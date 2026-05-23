# BinCodeQL: CodeQL for Binaries

**Project name:** BinCodeQL (working title)
**Date:** 2026-03-13
**Status:** Pre-implementation planning — consolidation of idea, prior plan, reference analysis, and critical review.

**One-liner:** A Datalog-powered query engine for compiled binaries — what CodeQL does for source code, we do for stripped executables, with an LLM agent that can compose and extend queries at runtime.

---

## Part A: Critique of the Existing Plan

This section captures why the v1 plan (plan-binDatalog.prompt.md) needs revision, so the reasoning is preserved alongside the new plan.

### A1. The Core Parsing Problem Was Missing (now resolved)

The hardest engineering problem — parsing unstructured text output from MCP tools into typed Datalog tuples — was completely absent from the v1 plan. MCP tools return text strings, not structured relations:
- BN `decompile_function` → HLIL-like C text with addresses
- BN `get_il(name, view, ssa)` → IL text in hlil/mlil/llil
- Ghidra `decompile_function` → C pseudocode text
- Ghidra `disassemble_function` → assembly text listing

However, **examination of real MLIL-SSA output reveals this is far less risky than initially assessed.** The MLIL-SSA format is highly structured with a regular grammar (see Phase 0 sample). Each line follows `<num> @ <addr>  <statement>` with ~6 distinguishable statement types. SSA versioning is explicit (`var#N`). A regex-based parser can handle ~90% of lines. This is now an engineering task, not a research risk.

### A2. BN's `get_il` with SSA Was Overlooked

BN MCP exposes `get_il(name_or_address, view, ssa)` which returns MLIL or LLIL in SSA form. This is the single most valuable tool for the project because MLIL-SSA gives:
- Explicit def-use chains via SSA variable numbering
- Explicit memory operations (load/store)
- Explicit call sites with argument mapping
- Explicit return value assignments

The entire extraction pipeline should be designed around MLIL-SSA parsing, not decompiled C or HLIL.

### A3. The Backend Gap Is Larger Than Acknowledged

BN MCP (~40 tools) and Ghidra MCP (193 tools) aren't "same API, different syntax." They have fundamentally different strengths:

| Capability | BN MCP | Ghidra MCP |
|---|---|---|
| Function listing | `list_methods` | `list_functions` (paginated), `list_functions_enhanced` (thunk/external flags) |
| Decompilation | `decompile_function` | `decompile_function`, `batch_decompile`, `force_decompile` |
| IL/SSA views | **`get_il` (hlil/mlil/llil, SSA)** — unique | Not available |
| Call graph (structured) | Not available | **`get_full_call_graph`, `get_function_callers`, `get_function_callees`** |
| Control flow analysis | Not available | **`analyze_control_flow`** (cyclomatic, loops) |
| Xrefs | `get_xrefs_to` (single address) | `get_xrefs_to`, `get_xrefs_from`, **`get_bulk_xrefs`** |
| Stack vars | `get_stack_frame_vars` | `get_function_variables` |
| Struct layout / field access | `get_user_defined_type`, `get_xrefs_to_field`, `get_xrefs_to_struct` | `get_struct_layout`, **`analyze_struct_field_usage`**, `get_field_access_context` |
| Function metrics | Not available | **`get_function_metrics`**, `analyze_function_completeness` |
| Inline script execution | Not available | **`run_script_inline`** — can run arbitrary Ghidra Java/Python |
| Batch operations | Not available | **`batch_decompile`**, `get_bulk_xrefs`, `batch_analyze_completeness` |
| Binary patching | `patch_bytes` | Not available (modification via rename/type/comment tools only) |
| Multi-binary | `list_binaries`, `select_binary` | `list_open_programs`, `switch_program` |
| Strings | `list_strings`, `list_all_strings`, `list_strings_filter` | `list_strings`, `search_memory_strings` |
| Imports/exports | `list_imports`, `list_exports` | `list_imports`, `list_exports`, `list_external_locations` |
| Memory raw access | `hexdump_address`, `hexdump_data`, `get_data_decl` | `inspect_memory_content`, `read_memory`, `analyze_data_region` |
| Type system | `get_user_defined_type`, `define_types`, `declare_c_type`, `list_local_types`, `search_types`, `get_type_info` | `list_data_types`, `search_data_types`, `get_struct_layout`, `create_struct`, `create_enum`, `create_union`, etc. |

Key takeaway for extraction design:
- **BN is better for def-use facts** (MLIL-SSA is unmatched)
- **Ghidra is better for structural/relational facts** (call graph, control flow, bulk xrefs)
- Ghidra's `run_script_inline` is a backdoor to any analysis Ghidra can compute — extremely powerful for custom extraction

### A4. MCP Roundtrip Cost for Bulk Extraction

For a 500-function binary, extracting facts via MCP means thousands of HTTP roundtrips (one per tool call). At ~50ms each, that's minutes just for extraction. The plan didn't address this.

Better approach: **hybrid extraction** —
1. **Bulk extraction** via a BN plugin script or Ghidra's `run_script_inline` that dumps all facts as CSV in one call
2. **Interactive MCP** only for targeted follow-up queries during the LLM analysis loop

### A5. Plan Was Over-Engineered for v1

7 phases, 6 schema layers, 6 rule module families, provenance on every fact, dual-backend from day one — this is too much investment before validating whether the core idea produces useful answers.

### A6. Missing: Competitor Framing

The plan didn't position the project against the right competitors:

- **Joern** is primarily a source-code analysis tool. It builds a Code Property Graph from source (C/C++, Java, JavaScript, etc.) and queries it via CPGQL. It has an experimental Ghidra-based binary frontend, but this is secondary — Joern's strength is source, not binaries. Joern is not a satisfactory answer for someone who only has a stripped binary and no source.
- **CodeQL** is the gold standard for Datalog-style querying over code. But it only works on source. There is no CodeQL for binaries.
- **ddisasm** uses Datalog for disassembly reconstruction, not for user-facing queries.
- **cclyzer++** does Datalog pointer analysis over LLVM IR, not over binary artifacts.

**The gap:** No tool currently provides a CodeQL-like declarative query experience over compiled binaries. That's the gap this project fills.

Our differentiators:
1. **Binary-native.** Works on stripped executables — no source required. This is the core proposition.
2. **Declarative Datalog queries** (Souffle) over binary facts — same paradigm as CodeQL but targeting disassembler output instead of compiler ASTs.
3. **LLM-composable rules.** Unlike CodeQL where analysts write QL by hand, the LLM can compose and extend Datalog rules at query time.
4. **Dual-backend extraction** (BN + Ghidra) with explicit coverage reporting.
5. **Souffle's fixed-point reasoning** enables transitive properties (pointer chains, resource lifecycles, interprocedural taint) that imperative scripts struggle with.

### A7. Missing: Grounding in Real User Queries

Neither the idea doc nor the plan contains concrete user scenarios with expected inputs/outputs. Who is the user? What question do they ask today that they can't answer? What does the ideal output look like?

---

## Part B: Revised Plan

### Vision: BinCodeQL

CodeQL lets you write declarative queries over source code databases. We build the same thing for compiled binaries:

1. **Database creation** — Extract structured facts from binaries via disassembler (BN / Ghidra) into a Datalog fact database (like CodeQL's `codeql database create`)
2. **Query execution** — Run Souffle Datalog queries over the fact database (like CodeQL's `codeql database analyze`)
3. **LLM augmentation** — An LLM agent interprets natural-language questions, selects/composes queries, and explains results (CodeQL doesn't have this)

**Why this matters:** Security researchers working on firmware, IoT devices, proprietary software, and malware rarely have source code. They have binaries. Today they write ad-hoc scripts in BN/Ghidra/IDA. BinCodeQL gives them the declarative query power that source-code analysts already enjoy via CodeQL.

**The CodeQL analogy drives the architecture:**

| CodeQL Concept | BinCodeQL Equivalent |
|---|---|
| Extractor (language-specific) | BN extractor (MLIL-SSA parser) / Ghidra extractor (Pcode/script) |
| CodeQL database (snapshot) | Fact directory: `facts/<binary_hash>/` with TSV per relation |
| QL standard library | Curated Souffle rule library (`rules/*.dl`) |
| QL query packs | Query modules (taint, lifecycle, reachability, etc.) |
| `codeql database analyze` | `run_souffle(program.dl, fact_dir, output_dir)` |
| SARIF output | Markdown report + optional JSON |
| Manual QL authoring | LLM composes/extends Datalog rules from natural language |

### Target Users & Example Queries

These ground the design. Each should be answerable by the v1 system:

1. **Vulnerability researcher:** "Does any user-controlled input reach the `memcpy` call in `parse_header`?"
   → Taint-like reachability from input-source functions to sink function argument.

2. **Vulnerability researcher:** "Show all allocation sites where the allocated buffer is freed on some paths but used on others."
   → Resource lifecycle with path-sensitivity approximation.

3. **Malware analyst:** "What data does `suspicious_func` exfiltrate? Trace backwards from its network send call."
   → Backward interprocedural slicing from a known sink.

4. **Reverse engineer:** "Which functions modify the `session->auth_level` field?"
   → Struct field def tracking across call boundaries.

5. **CTF player:** "What's the shortest call chain from `main` to `win_function`?"
   → Call graph reachability with path extraction.

### Architecture (CodeQL-inspired pipeline)

```
                    ┌─────────────────────────────────────────────┐
                    │           BinCodeQL Pipeline                │
                    │  (analogous to CodeQL's create → analyze)   │
                    └─────────────────────────────────────────────┘

User query (natural language)
        │
        ▼
┌──────────────────────┐
│   LLM Orchestrator   │  (Google ADK agent)
│  - interprets query  │
│  - picks strategy    │
│  - explains results  │
└────┬────┬────────────┘
     │    │
     │    ▼ (trivial queries: "list functions", "show xrefs")
     │  ┌──────────────┐
     │  │ Direct MCP   │ → answer immediately (no Datalog needed)
     │  │ shortcut     │
     │  └──────────────┘
     │
     ▼ (non-trivial queries: "does tainted input reach this sink?")
┌─────────────────────────────────────────┐
│  STEP 1: Database Creation              │  ← like `codeql database create`
│  (Fact Extraction)                      │
│                                         │
│  ┌─────────────┐    ┌────────────────┐  │
│  │ BN Extractor│    │Ghidra Extractor│  │
│  │ (MLIL-SSA   │    │(run_script_    │  │
│  │  parser)    │    │ inline / Pcode)│  │
│  └──────┬──────┘    └───────┬────────┘  │
│         └────────┬──────────┘           │
│                  ▼                      │
│    facts/<binary_hash>/                 │  ← like CodeQL database snapshot
│    ├── Function.tsv                     │
│    ├── Def.tsv, Use.tsv                 │
│    ├── Call.tsv, CFGEdge.tsv            │
│    ├── MemRead.tsv, MemWrite.tsv        │
│    └── ... (one TSV per relation)       │
│    [cached by binary hash + schema ver] │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│  STEP 2: Query Composition              │  ← like selecting CodeQL query packs
│  (Datalog Assembly)                     │
│                                         │
│  LLM selects from curated rule modules: │
│  ├── rules/core.dl     (reachability)   │
│  ├── rules/taint.dl    (source→sink)    │
│  ├── rules/lifecycle.dl (alloc/free)    │
│  └── rules/custom.dl   (LLM-composed)  │
│                                         │
│  Validates → assembles → program.dl     │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│  STEP 3: Query Execution                │  ← like `codeql database analyze`
│  (Souffle subprocess)                   │
│                                         │
│  souffle -F facts/ -D output/ program.dl│
│  [timeout + memory limits]              │
│  → output/*.tsv (result relations)      │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│  STEP 4: Result Interpretation          │  ← LLM advantage over CodeQL
│  (LLM reads output + facts)            │
│                                         │
│  → Markdown report with:               │
│    - findings (what was found)          │
│    - evidence chains (which functions,  │
│      variables, call paths)             │
│    - confidence (what's approximated)   │
│  → Optional: SARIF-like JSON            │
└─────────────────────────────────────────┘
```

### Tool Taxonomy

The agent has access to three distinct tool layers with very different cost profiles:

| Layer | Tools | Transport | Latency | When Used |
|---|---|---|---|---|
| **Disassembler (MCP)** | `get_il`, `decompile_function`, `list_methods`, `get_xrefs_to`, `get_stack_frame_vars`, `list_imports`, `list_exports` | MCP (HTTP to BN/Ghidra bridge) | ~50-200ms per call | Extraction phase; direct-answer shortcuts for simple queries |
| **Fact Engine (Python)** | `extract_facts()`, `load_cached_facts()`, `list_extracted_functions()` | In-process Python function call | <1ms | Before any Datalog query; cache lookup |
| **Query Engine (subprocess)** | `run_souffle()`, `validate_datalog()` | Python subprocess → Souffle binary | 1-30s depending on complexity | Answering relational/transitive questions |
| **File I/O (Python)** | Read/write TSVs, read rule `.dl` files, read session state | In-process | <1ms | Glue between layers |

**Design rule:** MCP calls are expensive. Batch them during extraction. During the analysis conversation loop, prefer local operations (fact engine + query engine) when facts are already cached. Only go back to MCP for targeted follow-up (e.g., decompile a specific function the Datalog results flagged).

### User Interface Strategy

**v1: Terminal / CLI.** The user runs the agent from a terminal (like existing `python agent.py` or `adk run .`). This is identical to the interaction model already working in vuln_analysis_6step. Zero UI development cost.

**Why not a BN sidebar plugin for v1:** Building a Qt/PySide plugin couples the project to BN's UI lifecycle and turns a 1-week Phase 4 into a multi-week effort. The agent's value is in the analysis engine, not the UI chrome.

**Important architectural note:** Once facts are extracted and cached, BN does NOT need to be running. The Datalog query engine works entirely on local TSV files. This matters for:
- Offline analysis (e.g., on an air-gapped machine)
- Sharing a fact database with a colleague who doesn't have BN
- CI/automation pipelines
- Re-querying a binary analyzed last week without re-launching BN

The extraction phase requires BN (via MCP). Everything after that is standalone.

**Future (Phase 7+):** A BN sidebar plugin that acts as a thin client, forwarding queries to the BinCodeQL agent process. BN's scripting console already supports Python, making this feasible later.

### Context Management Architecture

A conversation about a 500-function binary will exceed any LLM context window. The solution is **NOT traditional RAG** — Datalog is a strictly better retrieval engine for structured binary facts.

**Why not RAG:**
- Traditional RAG: embed documents → vector store → cosine similarity → inject approximate chunks into prompt.
- BinCodeQL: extract facts → TSV database → Datalog query → inject **exact** results into prompt.
- Datalog gives you `"all functions reachable from X that call malloc without calling free"` — precise, complete, deterministic. Vector similarity gives you `"functions sort-of-related to memory allocation"` — approximate, incomplete, non-deterministic.
- The structured fact database already IS the retrieval system. Adding a vector store on top would be redundant.

**Three-layer persistence model:**

| Layer | What | Keyed By | Lifetime | Invalidated By |
|---|---|---|---|---|
| **Fact cache** | Extracted TSVs in `facts/<hash>/` | `sha256(binary) + schema_version` | Permanent (until schema changes) | New schema version or explicit re-extraction |
| **Query result cache** | Souffle output TSVs in `cache/<query_hash>/` | `sha256(rules.dl content + fact_dir path)` | Per-session (or permanent for deterministic queries) | Fact or rule changes |
| **Session state** | Conversation summary, running findings list, user-selected candidates | Session ID (in-memory or JSON file) | Current conversation | User ends session |

**How context stays small regardless of binary size:**
1. Facts are NOT in the LLM context. They live in TSVs on disk.
2. For each query, the LLM sends a Datalog program to Souffle. Souffle returns only the relevant tuples (often <100 rows for a targeted query, even on a 2000-function binary).
3. The LLM sees: **user question + Souffle results + session findings summary**. Nothing else.
4. After each analysis step, the LLM produces a **condensed finding** (1-3 sentences) added to a running `session_findings` list that stays in the prompt. Full evidence remains in the TSVs for drill-down.
5. If the user asks for details about a previous finding, the agent re-reads the relevant cached Souffle output — no re-computation needed.

**Where you MIGHT want semantic search (v2+, not v1):**
- Over **previous analysis reports** across sessions: "What did I find in this binary last week?"
- Over **the string table** of very large binaries if there are 50K+ strings and the user asks a semantic question ("anything related to crypto?"). But `list_strings_filter` with regex is probably sufficient for v1.
- Over **rule module documentation** if the curated library grows to 50+ modules. For v1 with 3-5 modules, their descriptions fit in the prompt directly.


### Phase 0: End-to-End Spike (validate in 1-2 days)

**Goal:** Prove the pipeline works on one function, one query, before any infrastructure investment.

**MLIL-SSA sample 1** — floating point conversion (simple control flow):
```
0 @ 0040a924  cond:0#1 = val#0 > 3.4028234663852886e+38
1 @ 0040a92c  zmm1#1 = 0x7f7fffff
2 @ 0040a934  if (cond:0#1) then 3 else 4 @ 0x40a936
3 @ 0040a934  goto 7 @ 0x40a954
4 @ 0040a936  zmm2#1 = -0x3810000020000000
5 @ 0040a93e  zmm1#2 = 0xff7fffff
6 @ 0040a94a  if (zmm2#1 f> val#0) then 11 else 12 @ 0x40a94c
7 @ 0040a954  zmm1#5 = ϕ(zmm1#1, zmm1#2, zmm1#4)
8 @ 0040a954  zmm2#2 = ϕ(zmm2#0, zmm2#1)
9 @ 0040a954  val#1 = zmm1#5
10 @ 0040a957  return val#1:0.d
11 @ 0040a94a  goto 7 @ 0x40a954
12 @ 0040a94c  zmm1#3 = (zx.o(0)).q
13 @ 0040a950  zmm1#4:0.d = fconvert.s(val#0) @ zmm1#3
14 @ 0040a950  goto 7 @ 0x40a954
```

**MLIL-SSA sample 2** — TIFFVGetFieldDefaulted wrapper (calls, memory, stack canary):
```
0 @ 0040a86b  var_a8#1 = rdx#0
4 @ 0040a881  if (entry_rax#0 == 0) then 5 else 6 @ 0x40a883
5 @ 0040a881  goto 15 @ 0x40a8ba
12 @ 0040a8aa  var_28_1#1 = zmm6#0
14 @ 0040a8b2  goto 15 @ 0x40a8ba
15 @ 0040a8ba  var_88_1#2 = ϕ(var_88#0, var_88_1#1)
22 @ 0040a8ba  var_18_1#2 = ϕ(var_18#0, var_18_1#1)
23 @ 0040a8ba  rax#1 = [fsbase#0 + 0x28].q @ mem#0
24 @ 0040a8c3  var_c0#1 = rax#1
25 @ 0040a8d2  rdx_1#1 = &ap
26 @ 0040a8d5  ap:0.d @ mem#0 -> mem#1 = 0x10
27 @ 0040a8dc  var_d0#1 = &arg_8
28 @ 0040a8e6  ap:4.d @ mem#1 -> mem#2 = 0x30
29 @ 0040a8ee  var_c8#1 = &var_b8
30 @ 0040a8f3  result#2, mem#3 = TIFFVGetFieldDefaulted(tif: tif#0, tag: tag#0, ap: rdx_1#1) @ mem#2
31 @ 0040a8f8  rdx_2#2 = var_c0#1
32 @ 0040a8fd  temp0#1 = rdx_2#2
33 @ 0040a8fd  temp1#1 = [fsbase#0 + 0x28].q @ mem#3
34 @ 0040a8fd  rdx_3#3 = rdx_2#2 - [fsbase#0 + 0x28].q @ mem#3
35 @ 0040a906  if (temp0#1 != temp1#1) then 36 @ 0x40a910 else 38 @ 0x40a90f
36 @ 0040a910  mem#4 = __stack_chk_fail() @ mem#3
37 @ 0040a910  noreturn
{ Does not return }
38 @ 0040a90f  return result#2
```

**Complete grammar** (observed from both samples):
```
Line format:    <line_num> @ <hex_addr>  <statement>
(some lines may show non-contiguous numbers if intermediate lines were omitted)

Statement types — 10 forms, all distinguishable by keyword/pattern:
═══════════════════════════════════════════════════════════════════════════════

1. ASSIGNMENT:          var#ver = expr
   Examples:            var_a8#1 = rdx#0
                        cond:0#1 = val#0 > 3.4028234663852886e+38
                        temp0#1 = rdx_2#2

2. CONDITIONAL BRANCH:  if (expr) then <line> [@ addr] else <line> @ <addr>
   Variant A:           if (cond:0#1) then 3 else 4 @ 0x40a936        (then has no @)
   Variant B:           if (temp0#1 != temp1#1) then 36 @ 0x40a910 else 38 @ 0x40a90f

3. UNCONDITIONAL GOTO:  goto <line> @ <addr>
   Example:             goto 7 @ 0x40a954

4. PHI NODE:            var#ver = ϕ(var#ver, var#ver, ...)
   Example:             zmm1#5 = ϕ(zmm1#1, zmm1#2, zmm1#4)

5. RETURN:              return <expr>
   Example:             return result#2
                        return val#1:0.d

6. SUBFIELD ASSIGN:     var#ver:off.size = expr @ var
   Example:             zmm1#4:0.d = fconvert.s(val#0) @ zmm1#3

7. FUNCTION CALL:       [ret_var#ver, ] mem_out#ver = func_name(param: arg#ver, ...) @ mem_in#ver
   With return:         result#2, mem#3 = TIFFVGetFieldDefaulted(tif: tif#0, tag: tag#0, ap: rdx_1#1) @ mem#2
   Void/noreturn:       mem#4 = __stack_chk_fail() @ mem#3
   Note: args can be NAMED (param: var#ver) when BN has type info

8. MEMORY READ:         var#ver = [base#ver + offset].size @ mem#ver
   Example:             rax#1 = [fsbase#0 + 0x28].q @ mem#0
   Also in exprs:       rdx_3#3 = rdx_2#2 - [fsbase#0 + 0x28].q @ mem#3

9. MEMORY WRITE:        target:off.size @ mem_in#ver -> mem_out#ver = value
   Example:             ap:0.d @ mem#0 -> mem#1 = 0x10
                        ap:4.d @ mem#1 -> mem#2 = 0x30
   Key: the -> arrow distinguishes stores from loads

10. ADDRESS-OF:         var#ver = &symbol
    Example:            rdx_1#1 = &ap
                        var_d0#1 = &arg_8
                        var_c8#1 = &var_b8

Special markers:
  - noreturn            (follows void call to noreturn function)
  - { Does not return } (comment line, skip)

SSA variables:          name#version          (zmm1#3, val#0, mem#2, rax#1)
  - name can contain:   letters, digits, underscore, colon (cond:0, var_88_1)
  - version:            non-negative integer
Subfield access:        var#ver:offset.size   (val#1:0.d, zmm1#4:0.d, ap:0.d)
Memory SSA:             mem#ver tracks memory state through the function
  - loads read @ mem#N
  - stores transition mem#N -> mem#N+1
  - calls read @ mem#N and produce mem#N+1
```

**Steps:**
1. Pick a small binary with a known vulnerability (e.g., a CTF challenge or a libtiff function from your existing work).
2. Use BN MCP `get_il(function_name, "mlil", true)` to get MLIL-SSA output for 2-3 functions.
3. Parse the MLIL-SSA text into fact CSVs: `Def.csv`, `Use.csv`, `Call.csv`, `CFGEdge.csv` (regex parser or LLM-assisted).
4. Hand-write a Datalog rule: intraprocedural def-use chain + one interprocedural call binding.
5. Run Souffle on the .dl + fact CSVs.
6. See if the output answers "does input X reach operation Y?"
7. Have the LLM explain the result.

**Exit criteria:** Pipeline produces a correct, explainable answer → proceed to Phase 1. Given the observed MLIL-SSA structure, this is now expected to succeed.

**ADK validation checkpoint:** During the spike, pay attention to whether ADK's tool-calling loop handles the MCP→Python→subprocess flow smoothly. If the framework causes friction (silent errors, hard-to-debug tool dispatch, session state surprises), consider dropping to litellm + a hand-rolled 100-line tool dispatcher. The decision should be made before Phase 1 begins. ADK's value-add is conversation loop + tool dispatch + MCP bridge — the core logic (parser, Souffle runner, fact cache) is framework-independent.

### Phase 1: MLIL-SSA Parser + Core Fact Extraction

**Goal:** Reliably extract typed Datalog facts from BN MLIL-SSA output.

**Scope:** BN-only. Single binary. Focus on parsing quality.

**Risk level: LOW.** The MLIL-SSA sample above shows the format is highly regular. Not a research risk—this is engineering work.

**Steps:**

1.1. **Collect MLIL-SSA corpus.** Run `get_il(func, "mlil", true)` for 20+ functions across 3+ binaries. Catalog all statement types encountered. Two real samples (see Phase 0) already reveal 10 statement types. Additional types to look for:
  - Indirect calls: `var#N = [ptr#M](args)` — how BN represents vtable/function pointer calls
  - Switch/jump tables: may appear as multiple goto targets or explicit jump table syntax
  - Tail calls: may appear as `tailcall func(args)` or `goto func`
  - Try/catch/exception: if any structured exception handling is present
  - Intrinsics: BN-specific operations like `__builtin_*` or architecture-specific ops

1.2. **Build MLIL-SSA parser.** Two-strategy approach:

  **Strategy A: Regex-based parser (recommended for v1).** Line-by-line dispatch:
  ```
  Line regex:  r'^(\d+) @ ([0-9a-f]+)  (.+)$'

  Statement dispatch ORDER MATTERS (most specific first):

  1. Skip:         r'^noreturn$' or r'^\{.*\}$'               → skip
  2. Phi:          r'(\S+)#(\d+)\s*=\s*ϕ\((.+)\)'            → Def + PhiSource(s)
  3. MemWrite:     r'(.+)\s*@\s*mem#(\d+)\s*->\s*mem#(\d+)\s*=\s*(.+)'  → MemWrite + Def(mem)
  4. Goto:         r'goto\s+(\d+)\s*@\s*(0x[0-9a-f]+)'       → CFGEdge
  5. Conditional:  r'if\s*\((.+)\)\s*then\s+(\d+)(?:\s*@\s*(0x[0-9a-f]+))?\s+else\s+(\d+)\s*@\s*(0x[0-9a-f]+)'
                                                               → CFGEdge(×2) + Uses from cond
  6. Return:       r'return\s+(.+)'                            → ReturnVal + Uses
  7. Call:         r'((?:\S+#\d+,\s*)*\S+#\d+)\s*=\s*(\w+)\((.+)\)\s*@\s*mem#(\d+)'
                                                               → Call + Def(s) + ActualArg(s) + Use(mem)
     (handles: result#2, mem#3 = func(param: arg#0, ...) @ mem#2)
  8. VoidCall:     r'mem#(\d+)\s*=\s*(\w+)\((.*)\)\s*@\s*mem#(\d+)'
                                                               → Call + Def(mem) + ActualArg(s)
  9. AddressOf:    r'(\S+)#(\d+)\s*=\s*&(\w+)'               → Def + AddressOf
  10. MemRead:     presence of r'\[.+\]\.\w+\s*@\s*mem#\d+' in RHS
                                                               → MemRead + Use(mem) + Use(base)
  11. Assignment:  r'(.+)\s*=\s*(.+)'                          → Def + Uses from RHS (fallback)

  SSA var extraction (global, for Uses):
    r'(?<!\&)(\w+(?::\w+)?)#(\d+)'   applied to any expression/RHS
    (negative lookbehind for & avoids treating &symbol as a use)
  
  Named arg parsing (inside call args):
    r'(\w+):\s*(\w+(?::\w+)?)#(\d+)'  → ActualArg with param_name
  ```

  **Strategy B: LLM-assisted parsing (for edge cases).** For statement types the regex parser doesn't handle cleanly (deeply nested expressions, unknown intrinsics, indirect calls), send the line to an LLM with a structured extraction prompt. Use sparingly — only as fallback for <5% of lines.

  **Output per function:** List of typed fact tuples:
  ```python
  @dataclass
  class MLILFact:
      func: str
      line_num: int
      addr: int
      kind: Literal["def", "use", "call", "phi", "cfg_edge",
                     "mem_read", "mem_write", "return", "address_of"]
      var_name: str | None
      var_version: int | None
      # ... kind-specific fields
  ```

1.3. **Fact tuple generation.** Map parsed statements to Datalog relations:

  | MLIL-SSA Pattern | Datalog Fact(s) | Source |
  |---|---|---|
  | `var#N = expr` (LHS) | `Def(func, var, N, addr)` | any assignment |
  | `var#N` anywhere on RHS | `Use(func, var, N, addr)` | global SSA var scan |
  | `ret#N, mem#M = func(p: a#K, ...) @ mem#J` | `Call(func, callee, addr)` | sample 2 line 30 |
  |  | + `Def(func, ret, N, addr)` + `Def(func, mem, M, addr)` | |
  |  | + `ActualArg(addr, idx, param_name, a, K)` per arg | |
  |  | + `Use(func, mem, J, addr)` | |
  | `mem#M = func() @ mem#J` | `Call(func, callee, addr)` + `Def(func, mem, M)` | sample 2 line 36 |
  | `var#N = ϕ(x#1, x#2, x#3)` | `Def(func, var, N, addr)` | sample 1 line 7 |
  |  | + `PhiSource(func, var, N, x, 1)` + ... per source | |
  | `if (cond) then L1 else L2` | `CFGEdge(func, addr, addr_L1)` + `CFGEdge(func, addr, addr_L2)` | samples 1,2 |
  | `goto L @ target_addr` | `CFGEdge(func, addr, target_addr)` | both samples |
  | `return var#N` | `ReturnVal(func, var, N)` | sample 2 line 38 |
  | `var#N = [base#M + off].sz @ mem#K` | `MemRead(func, addr, base, M, offset)` + `Use(func, mem, K)` | sample 2 line 23 |
  | `tgt:off.sz @ mem#J -> mem#K = val` | `MemWrite(func, addr, tgt, off, val)` + `Def(func, mem, K)` + `Use(func, mem, J)` | sample 2 lines 26,28 |
  | `var#N = &symbol` | `Def(func, var, N, addr)` + `AddressOf(func, var, N, symbol)` | sample 2 lines 25,27,29 |
  | `noreturn` / `{ ... }` | `NoReturn(func, addr)` (or skip) | sample 2 line 37 |

1.4. **Build structural fact extractor.** Using MCP tools directly:
  - `list_methods` → `Function(func_name, addr)`
  - `get_xrefs_to` for each function → `CallEdge(caller_addr, callee_addr)`
  - `get_stack_frame_vars` → `StackVar(func, name, offset, size, type)`
  - `list_imports` → `Import(name, addr)`
  - `list_exports` → `Export(name, addr)`
  - `get_entry_points` → `EntryPoint(addr)`

1.5. **Fact serialization.** Write all facts to `facts/<binary_hash>/` directory as TSV files (one per relation). Stable sort order for reproducibility.

1.6. **Extraction caching.** Key on `sha256(binary) + schema_version`. Skip re-extraction if cache exists.

**Remaining risk (moderate, not critical):** Real-world binaries will have MLIL-SSA constructs not seen in the sample: memory dereferences with complex address computations, SIMD operations, tail calls, exception handling, switch tables. The regex parser should handle ~90% of lines; unclear lines can be logged and handled incrementally.

### Phase 2: Curated Datalog Rule Library

**Goal:** A small, correct, tested set of Datalog rules that answer the target query classes.

**Scope:** 3-5 rule modules, no LLM generation yet.

**Steps:**

2.1. **Core utility rules** (rules/core.dl)
  - Transitive call reachability: `Reaches(a, b) :- CallEdge(a, b). Reaches(a, c) :- Reaches(a, b), CallEdge(b, c).`
  - Intraprocedural def-use chain: `DefUseChain(func, def_var, def_ver, use_var, use_ver) :- Def(func, def_var, def_ver, addr1), Use(func, use_var, use_ver, addr2), def_var = use_var, def_ver = use_ver.` (SSA makes this trivial — same name+version means same def)
  - Interprocedural argument binding: connects actual arguments to formal parameters via CallEdge + ActualArg + function parameter position.

2.2. **Taint-like flow rules** (rules/taint.dl)
  - Source marking: `TaintSource(func, var, ver) :- Import(func_name, _), Call(_, func_name, site), ActualArg(site, _, var, ver).` (input from imported functions)
  - Flow propagation: through assignments (SSA edges), through call arguments, through returns.
  - Sink checking: `TaintedSink(func, sink_call, arg_idx) :- TaintFlow(_, var, ver, func, sink_call_addr), DangerousAPI(sink_func), Call(func, sink_func, sink_call_addr), ActualArg(sink_call_addr, arg_idx, var, ver).`

2.3. **Resource lifecycle rules** (rules/resource.dl)
  - Allocation tracking via known allocator calls (malloc, calloc, etc.)
  - Free tracking via known deallocator calls
  - Use-after-free detection: use of a variable after it flows through a free call on some path

2.4. **Dangerous API table** (data/dangerous_apis.csv)
  - Curated list: memcpy, strcpy, sprintf, system, exec*, free, etc.
  - Categorized by risk type (buffer, format, command injection, lifecycle)

2.5. **Tests for each rule module.**
  - Small hand-crafted fact files with known answers
  - Run Souffle, check output matches expected relations

### Phase 3: Souffle Execution Engine

**Goal:** Reliable subprocess execution with proper sandboxing.

**Steps:**

3.1. **Souffle runner module.** Python function: `run_souffle(dl_file, fact_dir, output_dir, timeout_sec=60, memory_mb=2048) → Dict[str, List[Tuple]]`
  - Writes assembled .dl file (includes + facts + rules + query output declarations)
  - Runs `souffle -F fact_dir -D output_dir program.dl` with subprocess timeout
  - Parses output TSV files into Python dicts keyed by relation name
  - Handles errors: syntax errors (return Souffle stderr), timeout (return partial + timeout flag), memory (catch OOM)

3.2. **Souffle interpreted mode investigation.** Test `-j` (interpreted/JIT) vs default (compile-to-C++) for latency on small programs. If interpreted mode is fast enough (<2s), prefer it for interactive use. Reserve compiled mode for large binaries.

3.3. **Temp workspace management.** Each run gets a temp directory. Clean up on success. Preserve on failure for debugging.

### Phase 4: LLM Orchestrator Agent

**Goal:** An ADK agent that ties extraction, rule selection, execution, and explanation together.

**Steps:**

4.1. **Agent architecture.** Single LlmAgent with MCP tools (BN or Ghidra) plus Python tool functions for:
  - `extract_facts(binary_path, backend="bn")` → path to fact directory
  - `load_cached_facts(binary_hash)` → path to cached fact directory (no BN needed)
  - `list_available_rules()` → list of rule module names and descriptions
  - `run_query(fact_dir, rule_modules, extra_rules_dl=None)` → query results as dict
  - `get_session_findings()` → running list of condensed findings from this session

4.2. **Query routing logic — interleaving, not either/or.** Real questions use both MCP and Datalog in the same conversation turn. The routing is a **loop**, not a switch:

  ```
  User: "Is parse_header vulnerable?"
    ↓
  [1] MCP: decompile parse_header → show code (direct answer)
    ↓
  [2] Agent notices memcpy call → needs taint analysis
    ↓
  [3] Fact Engine: load cached facts (or extract if first time)
    ↓
  [4] Query Engine: run taint.dl → "arg2 of memcpy at 0x4012ab is tainted from read() via parse_input()"
    ↓
  [5] MCP: decompile each function along the taint path for evidence
    ↓
  [6] Agent explains finding with code snippets + Datalog evidence
  ```

  The prompt should NOT say "if trivial use MCP, if complex use Datalog." Instead:
  - Always check if facts are cached first (`load_cached_facts`)
  - Use MCP for **entity lookup** (decompile, show xrefs, get IL for a specific function)
  - Use Datalog for **relational questions** (reachability, taint, lifecycle)
  - Use MCP again for **evidence gathering** after Datalog identifies interesting functions/paths
  - The agent naturally interleaves based on what the current sub-question needs

4.3. **Rule selection.** LLM selects which rule modules to include based on query intent. Prompt provides a catalog of available modules with input/output relation descriptions.

4.4. **LLM query template instantiation (guarded).** For queries not covered by curated rules:
  - LLM generates a query-level output rule (not new core rules) that composes existing derived relations.
  - Validation: check that all referenced predicates exist in curated rules or extracted facts.
  - If validation fails: explain to user what's missing and suggest a narrower query.

4.5. **Result explanation.** LLM reads Souffle output CSVs + original facts and generates a markdown explanation:
  - What the query found
  - The evidence chain (which functions, which variables, which call paths)
  - Confidence qualifiers (what the analysis covers, what it approximates)

4.6. **Session state management.** After each substantive analysis step:
  - Produce a **condensed finding** (1-3 sentences) summarizing what was learned
  - Append to `session_findings` list (kept in prompt at all times)
  - Full evidence stays in cached Souffle outputs for drill-down
  - This keeps the effective context = user question + session findings summary + current Souffle results — small regardless of binary size

### Phase 5: Ghidra Backend (parallel with Phase 4)

**Goal:** Add Ghidra as a second extraction backend.

**Steps:**

5.1. **Ghidra structured extraction via `run_script_inline`.** Write a Ghidra script (Java or Python) that extracts all facts in one execution:
  - Iterates functions, extracts Pcode/HLIL equivalent, builds fact tuples
  - Returns CSV-formatted text directly
  - One MCP call extracts all facts (avoids roundtrip problem)

5.2. **Alternative: Ghidra MCP tool-by-tool extraction.** Use `get_full_call_graph`, `get_function_callers`, `get_function_callees` for structural facts. Use `decompile_function` + LLM-assisted parsing for dataflow facts (less reliable than BN MLIL-SSA).

5.3. **Capability coverage metadata.** When Ghidra can't produce a fact that BN can (e.g., SSA-precise def-use), emit explicit `CapabilityCoverage("Def", "ghidra", "approximated", "no SSA; def-use from decompiled C heuristic")`.

5.4. **Backend parity test suite.** Run same queries on same binary with both backends. Report delta.

### Phase 6: Evaluation & Hardening

**Goal:** Measure whether the system actually works.

**Steps:**

6.1. **Benchmark queries.** The 5 target queries from the "Target Users" section above, plus 5 more from real analysis work.

6.2. **Correctness measurement.** For each query, compare output against manually verified ground truth.

6.3. **Latency budget.** Targets: extraction <30s for <200 functions, Souffle solve <5s for intraprocedural, <30s for interprocedural.

6.4. **Failure classification.** Track: parsing failures, Souffle syntax errors, timeouts, wrong answers, unhelpful explanations.

6.5. **Regression fixtures.** Saved fact files + expected outputs for CI-like testing.

---

## Part C: Fact Schema (v1 — intentionally minimal)

Only include what's needed for the 5 target queries. No provenance in v1. No coverage metadata in v1. Add them in Phase 5+.

### Extracted facts (from MCP)
Function(name: symbol, addr: address)
EntryPoint(addr: address)
Import(name: symbol, addr: address)
Export(name: symbol, addr: address)
StackVar(func: symbol, name: symbol, offset: number, size: number, type: symbol)


### Parsed from MLIL-SSA

Def(func: symbol, var: symbol, version: number, addr: address)
Use(func: symbol, var: symbol, version: number, addr: address)
Call(caller_func: symbol, callee_func: symbol, call_addr: address)
ActualArg(call_addr: address, arg_idx: number, param_name: symbol, var: symbol, version: number)
ReturnVal(func: symbol, var: symbol, version: number)
PhiSource(func: symbol, var: symbol, def_version: number, src_var: symbol, src_version: number)
MemRead(func: symbol, addr: address, base_var: symbol, base_version: number, offset: number)
MemWrite(func: symbol, addr: address, target: symbol, offset: number, mem_in: number, mem_out: number)
AddressOf(func: symbol, var: symbol, version: number, symbol_target: symbol)
CFGEdge(func: symbol, from_addr: address, to_addr: address)


### Derived by Datalog rules (not extracted)
Reaches(caller: symbol, callee: symbol)
DefUseChain(func: symbol, def_var: symbol, def_ver: number, use_addr: address)
TaintSource(func: symbol, var: symbol, version: number)
TaintFlow(src_func: symbol, src_var: symbol, dst_func: symbol, dst_var: symbol, dst_ver: number)
TaintedSink(func: symbol, call_addr: address, arg_idx: number, sink_func: symbol)
Alloc(func: symbol, var: symbol, version: number, call_addr: address)
Free(func: symbol, var: symbol, version: number, call_addr: address)
UseAfterFree(func: symbol, use_addr: address, free_addr: address, var: symbol)


---

## Part D: Comparison with Alternatives

### CodeQL (the model we're following)

| Aspect | CodeQL | BinCodeQL |
|---|---|---|
| Target | Source code (C/C++, Java, JS, Python, etc.) | Compiled binaries (stripped executables, firmware) |
| Input | Compiler AST / IR via language extractors | Disassembler IL (BN MLIL-SSA, Ghidra Pcode) via MCP |
| Query language | QL (Datalog variant, proprietary) | Souffle Datalog (open source, standard) |
| Database | CodeQL database (snapshot, opaque format) | Flat TSV fact files (inspectable, diffable) |
| Standard library | Extensive QL libraries per language | Curated rule modules (taint, lifecycle, reachability) |
| Query authoring | Manual QL by security researcher | Manual Datalog OR LLM-composed from natural language |
| Binary support | No (requires source + build system) | **Primary target** |
| LLM integration | None | Core feature — agent composes queries, explains results |
| Licensing | Proprietary (free for OSS only) | Open source |

**What we learn from CodeQL's architecture:**
- The extractor/database/query separation is the right abstraction. We adopt it.
- CodeQL's standard library is what makes it useful — users compose from library predicates, not raw AST nodes. Our curated rule library must serve the same role.
- CodeQL query packs (suites of queries for a vulnerability class) map to our rule modules.
- SARIF output format is useful for tool integration; we should support it eventually.

**What we do differently:**
- Binary-native: no source or build system required
- LLM-in-the-loop: natural language → Datalog composition → explanation
- Open Datalog: Souffle is standard, not proprietary QL
- Transparent fact database: TSV files anyone can inspect, not an opaque blob

### Joern (Code Property Graph)

| Aspect | Joern | BinCodeQL |
|---|---|---|
| Primary target | **Source code** (C/C++, Java, JS, PHP, etc.) | **Compiled binaries** |
| Binary support | Experimental (Ghidra frontend, limited) | Primary design target |
| Query language | CPGQL (Scala DSL, imperative traversals) | Souffle Datalog (declarative, fixed-point) |
| Analysis style | Graph traversal (imperative) | Relation computation (declarative) |
| LLM integration | Manual prompting | Agent with tool access, rule composition |
| Extensibility | Requires Scala/Java code | Declarative .dl files, LLM can write them |
| Maturity | Production-grade for source | Research prototype for binaries |

**Key distinction:** Joern is a source-code analysis platform that happens to have binary support. BinCodeQL is a binary analysis platform from the ground up. Joern's binary frontend uses Ghidra to lift to a CPG but doesn't expose the same depth of analysis (no SSA-precise def-use, limited interprocedural flow on binary CPGs). Our approach extracts richer facts from BN's MLIL-SSA and reasons over them with full Datalog power.

**Why not just use Joern's Ghidra frontend?**
1. Joern's binary CPG is a second-class citizen — most CPGQL queries and libraries assume source-level constructs (AST nodes, source lines, type annotations) that don't exist in binaries.
2. CPGQL is imperative graph traversal. Datalog is declarative relation computation. For transitive, recursive properties (reachability over arbitrary call depth, resource lifecycle across paths), Datalog is more natural and correct.
3. No LLM integration — you have to know CPGQL to use it.

### Direct LLM + MCP (existing vuln_analysis_6step)

| Aspect | Direct LLM Analysis | BinCodeQL |
|---|---|---|
| Reasoning | LLM token window, attention-limited | Datalog fixed-point, mathematically complete |
| Interprocedural | LLM must hold all functions in context | Datalog traverses arbitrary depth |
| Reproducibility | Non-deterministic | Deterministic (same facts + rules = same answer) |
| Explainability | LLM prose | Rule trace + fact evidence |
| Scalability | ~20-50 functions in context | Thousands of functions in fact database |
| Limitation | Context window caps complexity | Fact extraction quality caps correctness |

**Key insight:** BinCodeQL and vuln_analysis_6step are complementary. The 6-step agent is better for nuanced, ambiguous, human-judgment questions ("is this exploitable?"). BinCodeQL is better for precise, transitive, property-verification questions ("does tainted input reach this sink across any call path?"). They should eventually be combined: BinCodeQL finds candidates, the 6-step agent verifies exploitability.

### ddisasm / cclyzer++

| Aspect | ddisasm / cclyzer++ | BinCodeQL |
|---|---|---|
| Purpose | Disassembly reconstruction / LLVM pointer analysis | User-facing binary query engine |
| Input | ELF binary / LLVM bitcode | Disassembler output via MCP |
| User interface | Programmatic (C++ / research tool) | LLM agent (natural language) |
| Query flexibility | Fixed analysis pipeline | Open-ended Datalog queries |

**What we take from them:** Schema design patterns, rule modularity, unsoundness tracking (see datalog_references_summary.md). But they are not competitors — they solve different problems.

---

## Part E: Open Questions for Discussion

1. **MLIL-SSA parseability — ANSWERED.** Real MLIL-SSA output is highly structured (see Phase 0 sample). Format: `<num> @ <addr>  <statement>` with ~6 statement types, all distinguishable by keyword. SSA variables are explicit `name#version`. A regex parser can handle ~90% of lines. Remaining question: what edge cases appear in larger/more complex binaries (SIMD, exception handling, switch tables, indirect calls)? The Phase 0 spike will catalog these.

2. **Souffle interpreted vs compiled mode.** For interactive use, compilation latency matters. Need to benchmark Souffle's `-j` flag on representative workloads. Alternative: Soufflé's `--compile` with caching of compiled programs for repeated queries on the same fact database.

3. **Scope of v1 binaries.** Small binaries (<200 functions) only? Or should we handle medium (200-2000)? This affects extraction time budget and Souffle memory.

4. **Integration with existing vuln_analysis_6step.** Should this be a standalone agent or a tool/sub-agent callable from the existing pipeline? Recommendation: standalone first, integration later. Long-term: BinCodeQL finds candidates, 6-step agent verifies exploitability.

5. **Bulk extraction strategy.** MCP tool-by-tool vs custom plugin script. The spike will reveal whether MCP roundtrip cost is tolerable for small binaries; if not, prioritize the plugin script approach.

6. **Project naming and scope.** "BinCodeQL" positions the project clearly. But should v1 target the full CodeQL analogy (database create + analyze + query packs) or just the core pipeline (extract + query + explain)? Recommendation: core pipeline first, CodeQL-style CLI commands and query pack structure in v2.

7. **Incremental database updates.** CodeQL databases are snapshots — you re-create them when code changes. For binaries this is fine (binaries don't change during analysis). But should we support incremental fact addition (e.g., "also extract facts for this function I just discovered")? Probably yes for interactive use.

8. **Query pack marketplace.** CodeQL's power comes from community-contributed query packs. Should we design the rule module system to be shareable/distributable from the start? At minimum: each module in its own directory with metadata (name, description, required relations, known limitations).

9. **Context management — ANSWERED.** Datalog IS the retrieval engine. See "Context Management Architecture" section above. No RAG for v1. Three-layer persistence (fact cache + query result cache + session state). The LLM context stays small by design: user question + Souffle results + session findings summary.

10. **UI — ANSWERED.** Terminal/CLI for v1 (same as existing agent pattern). BN sidebar plugin is a Phase 7+ consideration. Key design constraint: extraction requires BN running, but querying works standalone on cached facts.

11. **Agent framework — ANSWERED (pending spike validation).** ADK is the current choice. Phase 0 spike includes an explicit ADK validation checkpoint. If ADK causes friction, fall back to litellm + manual tool dispatch. Core logic (parser, Souffle runner, fact cache) is framework-independent by design.

---

## Part F: Execution Order Summary

| Order | Phase | Depends On | Estimated Effort | Deliverable |
|---|---|---|---|---|
| 0 | Spike | Nothing | 1-2 days | Working manual pipeline for 1 query on 1 function |
| 1 | MLIL-SSA parser + fact extraction | Phase 0 success | 1-2 weeks | `extract_facts()` function producing fact CSVs |
| 2 | Curated rule library | Phase 1 (needs facts to test against) | 1 week | 3 rule modules with tests |
| 3 | Souffle execution engine | Nothing (can parallelize with 1-2) | 2-3 days | `run_souffle()` function |
| 4 | LLM orchestrator agent | Phases 1-3 | 1 week | Working agent answering 5 target queries |
| 5 | Ghidra backend | Phase 4 working with BN | 1-2 weeks | Second extractor, parity tests |
| 6 | Evaluation | Phase 4 | Ongoing | Benchmark results, failure taxonomy |

Phases 1+3 can run in parallel. Phase 2 needs Phase 1 output for testing but rule writing can start earlier using hand-crafted facts.