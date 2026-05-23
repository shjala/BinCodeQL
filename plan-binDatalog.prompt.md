## Plan: LLM+MCP+Datalog Binary Query Agent

Build a correctness-first, explainable analysis agent that answers non-trivial binary property queries by combining MCP fact extraction with Souffle Datalog solving. Use a backend abstraction to support both Binary Ninja and Ghidra, but implement BN first as the reference backend and add Ghidra through adapter parity checks.

**Steps**
1. Phase 1 - Problem framing and query contract
1. Define a strict query contract (supported property classes, query template language, expected outputs, error modes).
1. Define out-of-scope queries for v1 (e.g., symbolic-execution-level constraints, whole-program pointer alias precision beyond selected rules).
1. Decide canonical result model: relation rows + provenance explanation + confidence/coverage metadata.

2. Phase 2 - Backend abstraction and fact schema (blocks phase 3+)
1. Create a backend capability matrix for BN MCP vs Ghidra MCP: function listing, decompilation, xrefs, type queries, CFG/basic blocks, stack vars, imports/exports.
1. Define a backend-agnostic fact schema (Datalog relations) with normalized identifiers: function_id, block_id, instr_id, var_id, type_id.
1. Define relation families for full interprocedural def-use target, staged by confidence:
1. Core structural: Function, Calls, CFGEdge, Entry, Exit.
1. Dataflow seed: Def, Use, MemoryRead, MemoryWrite, ArgMap, RetMap.
1. Interprocedural links: ActualToFormal, FormalToReturn, HeapObjAliasApprox.
1. Add provenance fields on facts (source backend, extraction tool, timestamp, optional confidence) to support explainability.

3. Phase 3 - Fact extraction pipeline
1. Implement BN extractor first using isolated MCP sessions per worker and chunked parallel extraction.
1. Add deterministic fact serialization to CSV/TSV files per relation with stable sorting for reproducibility.
1. Implement extraction checkpoints and caching (per binary hash + backend + schema version).
1. Implement Ghidra adapter mapping into the same schema; unsupported capability should emit explicit partial-coverage metadata, not silent omission.

4. Phase 4 - Datalog rule system and generation
1. Build a curated rule library first (handwritten baseline rules) for call reachability, taint-ish flow approximation, and resource lifecycle checks.
1. Introduce LLM-assisted rule generation behind guardrails:
1. Generate candidate rules from user intent into a sandbox file.
1. Run static validation (allowed predicates, recursion limits, stratification constraints).
1. Fallback to nearest curated template if validation fails.
1. Keep user-facing query-to-rule mapping traceable (which template/rules executed).

5. Phase 5 - Souffle execution and result interpretation
1. Run Souffle via subprocess with timeout/memory controls and per-run temp workspace.
1. Parse structured outputs (prefer output-dir artifacts over stdout scraping).
1. Post-process result relations into:
1. Human markdown report (primary).
1. Optional JSON artifact (secondary, for future automation).
1. Add interpretation layer that explains why each result row exists using provenance edges and rule traces where available.

6. Phase 6 - Interactive loop and UX
1. Implement ask-refine loop: if answer confidence/coverage is low, propose concrete follow-up queries or narrower scope.
1. Show explicit backend coverage summary (BN vs Ghidra parity, missing predicates).
1. Support “direct MCP answer” shortcut for trivial questions where Datalog is unnecessary.

7. Phase 7 - Evaluation and hardening
1. Build a benchmark set of query tasks (structural, dataflow, vulnerability-oriented).
1. Measure correctness (manual oracle or known ground truth), latency, and failure classes (syntax, timeout, incomplete facts).
1. Add regression fixtures for schema evolution and backend parity.
1. Document threat model for prompt-injected rule abuse and subprocess safety.

**Relevant files**
- /media/sanjay/f574986f-8197-4e72-a69d-87ddf200a6a9/sanjay/research/tii/tii24/repos/dev-claude/bin_datalog/research.md — source concept and goals to refine into a formal architecture doc.
- /media/sanjay/f574986f-8197-4e72-a69d-87ddf200a6a9/sanjay/research/tii/tii24/repos/dev-claude/vuln_analysis_6step/agent.py — reusable MCP toolset isolation, async orchestration, staged agent pipeline patterns.
- /media/sanjay/f574986f-8197-4e72-a69d-87ddf200a6a9/sanjay/research/tii/tii24/repos/dev-claude/fuzz_harness_adv/agent.py — subprocess execution and timeout/error-handling patterns applicable to Souffle runs.

- /memories/session/datalog_references_summary.md — distilled patterns from MATE, cclyzer++, and ddisasm; canonical input for schema and rule-library design discussions.

**Verification**
1. Contract tests: same query over same binary with same schema version must produce byte-identical fact files and stable result ordering.
1. Backend parity tests: run a minimal predicate suite on BN and Ghidra; compare overlap and report deltas explicitly.
1. Rule validation tests: malformed/generated rules must fail safely and route to curated fallback.
1. Performance tests: enforce max extraction and solve time budgets for small/medium binaries.
1. End-to-end acceptance: at least 10 non-trivial queries (including interprocedural def-use) answered with markdown explanations and traceable provenance.

**Decisions**
- Included: dual-backend architecture with BN-first implementation and Ghidra compatibility path.
- Included: full interprocedural def-use as target capability, but delivered incrementally via staged relation families.
- Included: markdown as primary human output, JSON as optional secondary artifact.
- Excluded (v1): high-precision alias analysis, SMT-backed path feasibility, full symbolic execution.

**Further Considerations**
1. Souffle relation design choice: normalized wide schema (fewer predicates, more columns) vs narrow semantic schema (more predicates, easier rule readability). Recommendation: start narrow semantic schema for explainability and easier LLM rule control.
1. LLM rule generation policy: optional-by-default vs always-on. Recommendation: default to curated library and enable generation only when no template matches.
1. Backend strategy: strict parity vs graceful degradation. Recommendation: graceful degradation with explicit coverage reporting, then iterate toward parity on high-value predicates.
