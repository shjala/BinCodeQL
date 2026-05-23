## Summary: MATE, cclyzer++, ddisasm for LLM+MCP+Datalog

Date: 2026-03-13
Purpose: Extract reusable design principles for bin_datalog, with emphasis on fact schema design and Datalog rule-library strategy.

### 1) What each project contributes

MATE
- Uses a rich multi-layer code property graph (IR, machine-level, assembly, DWARF) with explicit cross-layer mapping.
- Emphasizes provenance: different graph components come from different analyses/tools, with explicit origin semantics.
- Represents interprocedural flow with explicit call and return binding constructs (example patterns: parameter binding and call-return connectors).
- Uses context-aware edges for callgraph/dataflow style relations.

cclyzer++
- Shows a scalable Souffle architecture for interprocedural points-to/dataflow.
- Core relations are clean and compositional (examples: var_points_to, ptr_points_to, callgraph_edge).
- Encodes context sensitivity as first-class data (records / callsite context), not hidden control logic.
- Uses modular Datalog components and project profiles for different execution modes.
- Handles external code via signatures (declarative modeling of unknown library behavior).
- Explicitly documents unsoundness sources, turning hidden risk into trackable engineering decisions.

Ddisasm
- Demonstrates production Datalog over binaries with staged facts then refinement.
- Exposes a predicate-level API with module boundaries (examples: cfg, basic_def_used, use_def_analysis).
- Uses focused, purpose-specific relations (example: def chains driven by memory-address relevance).
- Stores facts and outputs in structured channels and metadata stores, enabling reproducibility and downstream tooling.

### 2) Fact schema guidance for bin_datalog (Point 1)

Design principles
- Keep schema narrow-semantic and typed rather than one giant generic relation.
- Separate foundational facts from inferred facts.
- Encode context explicitly in tuple columns when relation meaning depends on call context.
- Attach provenance metadata to every derived relation family.
- Treat unsupported backend capabilities as explicit coverage gaps, not silent nulls.

Recommended schema layers
1. Identity and mapping layer
- Program, backend, binary, function, basic block, instruction, symbol, type, variable, memory object IDs.
- Cross-representation mapping relations where possible (source symbol to binary entity, block to function, instruction to block).

2. Structural control layer
- Function entry and exit, callsite, call edges, CFG edges, interprocedural edges.
- External target edges for unresolved call destinations.

3. Def-use and memory layer
- Def and Use facts over registers and abstract variables.
- MemoryRead and MemoryWrite facts.
- Address-computation relevance facts for pruning def-use expansion.

4. Interprocedural binding layer
- ActualToFormal and FormalToActual mapping by callsite and argument index.
- Return binding relation from callee returns to caller result uses.

5. Alias and object abstraction layer
- Memory object abstractions with optional subobject relation.
- MayAlias and MustAlias approximation relations.
- Optional heap allocation context relation when context cloning enabled.

6. Provenance and coverage layer
- FactProvenance(relation, tuple_id, backend, extractor, confidence, timestamp).
- CapabilityCoverage(predicate, backend, status, note).

Minimum v1 relation core for full interprocedural def-use trajectory
- Function, Block, Inst, InstInBlock, BlockInFunction.
- CFGEdge, CallEdge, ReturnEdge.
- Def, Use.
- MemoryRead, MemoryWrite.
- ActualToFormal, FormalToReturn.
- PointsToMay or AliasMay (single approximation relation for v1).
- FactProvenance, CapabilityCoverage.

### 3) Rule-library strategy guidance (Point 3)

Core strategy
- Curated rule library first, LLM-generated rules second.
- Rules grouped into stable modules with explicit inputs and outputs.
- Every module should have declared assumptions, expected precision, and known failure modes.

Recommended module stack
1. Core graph rules
- Reachability and dominance-like utilities over CFG and call graph.
- Context-aware call/return balanced traversal utilities.

2. Intra-procedural def-use rules
- Register/variable def-use chains.
- Address-relevant slicing helper rules for memory-centric queries.

3. Interprocedural dataflow rules
- Actual to formal propagation.
- Return to caller propagation.
- Summarization rules for repeated callees.

4. Memory abstraction rules
- Load/store transfer rules via alias approximation.
- Optional field or subobject transfer rules with bounded expansion.

5. External behavior signatures
- Declarative summary rules for common APIs and imported functions.
- Signature catalog versioned separately from core rules.

6. Query templates
- Reusable query-level entry points mapped from user intent classes.
- Example classes: taint-like reachability, source-to-sink feasibility under approximations, untrusted input to critical operation.

LLM-assisted rule generation policy
- LLM proposes only query-template instantiations first.
- Free-form new rule synthesis allowed only in sandbox mode.
- Validation gate before execution:
  - Allowed predicates whitelist.
  - Stratification and recursion-depth checks.
  - Cost guardrails (max joins and estimated relation fanout).
- Auto-fallback to nearest curated template on validation failure.

### 4) Practical lessons to adopt immediately

From MATE
- Multi-layer schema with explicit cross-layer mapping is powerful for explainability.
- Provenance is not optional if you want analyst trust.

From cclyzer++
- Treat context as data in schema.
- Maintain separate accuracy and performance modes via modular rule sets.
- Define and publish unsoundness list early.
- Use signatures to model external functions instead of ignoring them.

From ddisasm
- Prefer many small, focused predicate modules over monolithic rule files.
- Build from over-approximate structural facts and iteratively refine.
- Keep rule interfaces stable and documented to enable incremental growth.

### 5) Risks and controls for your project

Risk
- Dual backend mismatch (BN and Ghidra produce different granularity).
Control
- CapabilityCoverage relation plus backend-specific adapters to common schema.

Risk
- Full interprocedural def-use explosion.
Control
- Stage rollout: intraprocedural complete first, then call/return bindings, then alias sensitivity.

Risk
- LLM-generated Datalog fragility.
Control
- Strict validation and curated fallback path.

Risk
- Hidden unsoundness.
Control
- Maintain a living unsoundness document and expose it in reports.

### 6) Recommended decisions for next design iteration

1. Adopt a BN-first, dual-backend schema contract with explicit capability coverage.
2. Freeze v1 relation core and add module-level ownership for each rule family.
3. Start with curated templates for 5 query classes before enabling free-form generation.
4. Add external-function signature system in v1.1, not later.
5. Require provenance fields in all final user-facing findings.

### 7) Suggested v1 query classes

1. Untrusted input to memory write path.
2. Argument flows to dangerous API callsite.
3. Allocation without matching free on feasible paths.
4. Return value from risky callee reaches control-sensitive branch.
5. Potential out-of-bounds index influences memory access address.
