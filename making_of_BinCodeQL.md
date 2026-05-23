# The Making of BinCodeQL

*A Datalog-powered query engine for compiled binaries, built with Claude as co-author.*

---

## 1. Genesis: Why Datalog for Binary Analysis?

The core idea: apply **Datalog** — a declarative logic language used in source-code analysis tools like CodeQL and Doop — to **compiled binaries**. Instead of parsing source, we extract facts from Binary Ninja's MLIL-SSA (Medium-Level IL, Static Single Assignment form) and write Souffle Datalog rules over them.

**Why this matters:** Source-code analyzers can't analyze stripped binaries, firmware, or closed-source libraries. BinCodeQL brings the same declarative query power to the binary world.

**Architecture decision:** The system is an **LLM agent** (Google ADK) that interacts with Binary Ninja via MCP (Model Context Protocol), extracts Datalog facts, composes and runs Souffle queries, and interprets results. The LLM doesn't just use pre-built rules — it can compose custom Datalog queries on the fly for novel vulnerability patterns.

---

## 2. Phase 1: Core Fact Extraction (Foundations)

### The Fact Schema

We designed a relational schema that captures the essential semantics of MLIL-SSA:

| Relation | What it captures |
|----------|-----------------|
| **Def/Use** | SSA definitions and uses — the backbone of data flow |
| **Call/ActualArg/ReturnVal** | Interprocedural control and data flow |
| **PhiSource** | SSA phi nodes — where values merge at control flow joins |
| **MemRead/MemWrite** | Memory load/store operations |
| **FieldRead/FieldWrite** | Struct field access (BN's structured types) |
| **FormalParam** | Function parameter identification |
| **CFGEdge** | Control flow graph edges |
| **AddressOf** | Address-of operations (for alias analysis) |

**Design choice: SSA-level facts, not assembly.** We chose MLIL-SSA over raw assembly because:
- SSA gives us explicit def-use chains (no need to compute reaching definitions)
- Phi nodes make control flow merges explicit
- MLIL is architecture-independent (works on x86, ARM, MIPS, etc.)
- Memory SSA versioning tracks memory state changes

### Two Extraction Modes

1. **Interactive (MCP):** `mlil_parser.py` — regex-based parser for MLIL-SSA text from `get_il()`. Good for incremental exploration. The LLM calls BN MCP tools, gets IL text, passes it to the parser.

2. **Batch (headless):** `scripts/bn_extract_facts.py` — walks MLIL-SSA instruction objects directly via BN Python API. No regex, no MCP round-trips. Handles all instruction types. Also extracts `StackVar` (stack frame layout) which the text parser can't get.

**Design choice: dual extraction.** Interactive mode lets the LLM explore incrementally (examine one function, decide what to look at next). Batch mode is for production analysis (extract everything, run queries). Both produce identical fact schemas.

### The Empty Facts Problem

Early testing revealed Souffle crashes when a `.input` directive references a missing `.facts` file. Solution: after writing populated facts, both extractors create empty files for all 20+ schema relations. Simple but critical for robustness.

---

## 3. Phase 2: Alias Analysis and Structural Patterns

### Andersen-Style Points-To Analysis (`alias.dl`)

We implemented a flow-insensitive, Andersen-style points-to analysis:

```
PointsTo(f, v, ver, obj) :- AddressOf(f, v, ver, obj).
PointsTo(f, v, ver, obj) :- Flow(f, v2, ver2, v, ver), PointsTo(f, v2, ver2, obj).
```

**Design choice: under-approximate.** The analysis is deliberately conservative — it may miss some aliases (false negatives) but won't invent fake ones (no false positives). This is the right trade-off for a vulnerability-hunting tool: missing a taint path is acceptable, but reporting a fake one wastes analyst time.

### Two-Pass Pipeline

Alias analysis produces `PointsTo` facts that the taint analysis consumes. Since Souffle doesn't support inter-file dependencies natively, we built a **two-pass pipeline**:

1. Run `alias.dl` → produces `PointsTo.csv`
2. Copy `PointsTo.csv` → `PointsTo.facts`
3. Run `interproc.dl` → uses PointsTo as input

This is wrapped in `tool_run_taint_pipeline()` — one call runs both passes.

### Structural Patterns (`patterns.dl`)

Simple heuristic detectors that don't need full taint analysis:
- `UnsafeStringCopy`: strcpy/strcat to a stack buffer
- `UnsafeGets`: any call to gets()
- `UnsafeSprintf`: sprintf to a stack buffer

These require `StackVar` facts (stack layout info), which motivated the headless extractor.

---

## 4. Phase 3: Pointer-Mediated Taint and Buffer Writes

### The fread Problem

When analyzing `fread(buf, 1, n, fp)`, the naive taint model taints the pointer variable (`buf`), not the buffer contents. But the real vulnerability is in the *data* written to the buffer.

**Solution: `BufferWriteSource` relation.** Library functions like `fread`, `read`, `recv` are annotated as writing external data into a buffer argument:

```
BufferWriteSource("fread", 0).   // arg0 is the buffer being written
BufferWriteSource("read", 1).    // arg1 is the buffer
```

Then `interproc.dl` uses this with `PointsTo` to taint the heap object:

```
TaintedHeapObject(obj, "external") :-
    Call(caller, callee, call_addr),
    BufferWriteSource(callee, buf_idx),
    ActualArg(call_addr, buf_idx, _, buf_var, buf_ver),
    PointsTo(caller, buf_var, buf_ver, obj).
```

Any subsequent load from a tainted heap object taints the loaded variable. This correctly models `fread→buf→memcpy→strcpy` chains.

### Fallback Without Alias Analysis

When `PointsTo` is empty (alias.dl wasn't run), `interproc.dl` falls back to using `AddressOf` facts directly. Less precise, but ensures the system works even without the first pass.

---

## 5. Phase 4: Precision Improvements

### 1-CFA Context Sensitivity

Context-insensitive analysis merges taint from all call sites, causing false positives. We added **1-CFA** (1-level Call-site-sensitive Function Analysis): the `TaintedVar` relation carries a `ctx` column — the call-site address.

```
TaintedVar(f, v, ver, origin, ctx)
```

This means if function `parse()` is called from both a trusted and untrusted context, the taint stays separated. The LLM can examine the `ctx` column to distinguish call-site contexts when triaging results.

### Sanitizer Modeling (TaintKill)

Functions like `memset`, `bzero`, `explicit_bzero` kill taint on their buffer arguments. We model this with:

```
TaintKill("memset", 0).     // arg0 is sanitized
TaintKill("bzero", 0).
```

`SanitizedVar` facts are emitted and excluded from `TaintedSink` — eliminating false positives where a buffer is zeroed before use.

### Guard Detection

When the code checks bounds before a dangerous operation (`if (len < sizeof(buf))`), the analysis emits `GuardedSink` facts. These aren't suppressed outright — the LLM can decide whether the guard is sufficient — but they're flagged for triage prioritization.

**Design choice: guards are informational, not suppressive.** A bounds check doesn't necessarily prevent overflow (the check might be wrong, or check the wrong variable). So we flag rather than suppress.

---

## 6. Phase 5: BOIL Detection (2026-03-18)

### What is a BOIL?

A **Buffer Overflow Inducing Loop** is a loop that copies data byte-by-byte with incrementing src/dst pointers, terminating on **source data** (e.g., null byte) rather than **buffer size**. Classic examples: hand-rolled `strcpy`, null-terminated copy loops. These are a major source of buffer overflows in C code.

### The ArithOp Fact

To confirm pointer increment patterns, we added a new fact:

```
ArithOp(func, addr, dst, dst_ver, op, src, src_ver, operand)
```

Extracted from both the regex parser (`mlil_parser.py`) and the headless extractor (`bn_extract_facts.py`). Captures `var = var2 + const`, `var = var2 - const`, shifts, etc.

### Detection Strategy: Layered Datalog Rules

The BOIL detector is a pipeline of increasingly specific Datalog relations:

```
BackEdge          → identifies loops (CFGEdge where target <= source)
LoopIterVar       → phi self-reference (var#N = phi(..., var#M, ...))
IncrementingVar   → ArithOp confirms add-by-constant in the loop
LoopMemRead/Write → memory ops using the loop-iter var as address
DataDepTermination → loaded byte influences the Guard condition
BoundsGuardedLoop → loop-iter var has a size-based guard (FP suppression)
BOILCandidate     → final: read + write + data-dep term - bounds guard
```

Each layer narrows the candidates. The LLM performs final classification on the remaining candidates.

### Key Design Decisions and Iterations

#### 1. SSA Temp Variable Bridging

**Problem:** In SSA, the pointer increment goes through temp variables:
```
rdx_1#2 = var_18#2          (copy from phi)
rax_1#4 = rdx_1#2 + 1       (ArithOp — dst is temp, not the loop var)
var_18#3 = rax_1#4           (copy back)
```

The naive `IncrementingVar` rule required the ArithOp's dst and src to both be the loop-iter var. This matched only 5 out of 60 functions (where BN optimized away the temps).

**Solution:** Use the transitive `Flow` relation to bridge both sides:
```datalog
IncrementingVar(f, v, pv, uv, operand) :-
    LoopIterVar(f, v, pv, uv),
    ArithOp(f, _, adst, adv, "add", asrc, asv, operand),
    Flow(f, v, pv, asrc, asv),   // phi version flows to ArithOp source
    Flow(f, adst, adv, v, uv).   // ArithOp result flows to update version
```

This boosted detection from 5 to 52 high-confidence matches. **The insight: in SSA, you always need to account for copy chains.**

#### 2. Indirect Memory Access Matching

**Problem:** `LoopMemRead`/`LoopMemWrite` required the loop-iter var to be directly Used at the MemRead/MemWrite address. But BN typically assigns the pointer to a temp first:
```
rax_2#6 = var_10#2          (copy loop var to temp)
rdx_1#2 = [rax_2#6].b      (MemRead uses the temp, not the loop var)
```

**Solution:** Added indirect rules using `Flow`:
```datalog
LoopMemRead(f, a, v, pv) :-
    MemRead(f, a, _, _, _),
    Use(f, v2, v2ver, a),
    Flow(f, v, pv, v2, v2ver),
    LoopIterVar(f, v, pv, _), v2 != v.
```

#### 3. Excluding the Memory SSA Token

**Problem:** `mem` (the memory SSA state variable) is a LoopIterVar in every loop (it has phi nodes at loop headers). This caused `mem` to dominate all results — 559 LoopIterVar entries, most being `mem`.

**Solution:** Simple exclusion: `v != "mem"` in LoopIterVar. The memory SSA token is a bookkeeping variable, not a real pointer.

#### 4. Single-Pointer BOIL Patterns (`sp != dp` → `ra != wa`)

**Problem:** `boil_ptrdiff_24` uses a single loop variable (`src`) to compute both the read address (`*src`) and the write address (`dest[src - start]`). The original rule required `sp != dp` (different source and destination pointer variables), which excluded this pattern.

**Solution:** Replaced `sp != dp` with `ra != wa` (read address != write address). The real invariant is that the read and write happen at different IL addresses (different memory locations), not that they use different SSA variables. This is a **more general formulation** that catches:
- Two-pointer patterns (classic strcpy-like): different vars, different addrs
- Single-pointer patterns (ptrdiff, indexed copy): same var, different addrs
- But NOT read-modify-write (`*p = f(*p); p++`): same var, same concept (though different addrs — mitigated by DataDepTermination specificity)

#### 5. False Positive Suppression via BoundsGuardedLoop

**Problem:** 30 out of 50 safe (`sf_*`) functions were flagged. These functions have the same structural pattern (loop + copy + null check) but ALSO have a size-based bounds check (`i < size`). The Datalog detector couldn't distinguish "terminates only on data" from "terminates on data AND size."

**Solution: `BoundsGuardedLoop` relation.** Detects when a loop-iter var participates in a Guard comparison with a non-zero bound:

```datalog
BoundsGuardedLoop(f, v, ga) :-
    LoopIterVar(f, v, pv, _),
    Use(f, v, pv, ga),
    Guard(f, ga, _, _, _, bound),
    bound != "0".
```

Three sub-decisions within this:

**(a) Use-at-guard-address, not just guard-variable matching.** The naive approach checked if the loop-iter var was the Guard's LHS variable. But compilers can put the loop-iter var on either side of the comparison (`i < size` vs `size > i`). By checking `Use(f, v, pv, ga)` — "is the loop-iter var used at the Guard address?" — we catch both sides.

**(b) Excluding memory-loaded values.** A sentinel check like `*ptr != 0xFFFF` also has the loop-iter var (`ptr`) in its flow chain. But the guard is on the **loaded data**, not the **position**. We exclude derived vars that were defined at a MemRead address:
```datalog
Def(f, dv, dver, def_addr), !MemRead(f, def_addr, _, _, _).
```
This distinguishes "is the loop counter within bounds?" (position check) from "is the loaded byte a sentinel?" (data check).

**(c) Function-level suppression.** Two loop-iter vars may increment in lockstep (`var_10` for source offset, `var_18` for destination offset). A bounds check on either one bounds the entire loop. Rather than tracking which vars are in the same loop, we use function-level suppression: `!BoundsGuardedLoop(f, _, _)`. If ANY loop-iter var in the function has a bounds guard, all BOILCandidates are suppressed. This is safe for a pre-filter (the LLM does final classification).

#### 6. Confidence Tiers with Stratification

**Problem:** Souffle rejects self-referencing negation (`!BOILCandidate(...)` inside `BOILCandidate` rules) — it can't stratify the relation.

**Solution:** Separate intermediate relations: `BOILHigh`, `BOILMedium`, `BOILLow`, unified into `BOILCandidate`:
```datalog
BOILCandidate(f, sp, dp, ra, wa, "high")   :- BOILHigh(f, sp, dp, ra, wa).
BOILCandidate(f, sp, dp, ra, wa, "medium") :- BOILMedium(f, sp, dp, ra, wa).
BOILCandidate(f, sp, dp, ra, wa, "low")    :- BOILLow(f, sp, dp, ra, wa).
```

#### 7. Parser Fix: Bracketed Store Pattern

**Problem:** During BOIL testing, we discovered the regex parser (`mlil_parser.py`) didn't handle `[ptr].size = val @ mem#in -> mem#out` (pointer dereference stores). This is the most common MLIL-SSA store pattern — ALL MemWrite facts were missing.

**Solution:** Added `BRACKET_WRITE_RE` regex and handler. This was a pre-existing parser gap that BOIL testing exposed.

### Final Results (boil-examples binary)

| Metric | Result |
|--------|--------|
| True positives (boil_ detected) | 97 / 101 (96%) |
| High confidence | 91 |
| Low confidence | 6 |
| False negatives | 4 (inline asm, ifunc resolver, optimized-away, VLA index) |
| **False positives (sf_ flagged)** | **0 / 50 (0%)** |

---

## 7. Architecture Overview

### File Map (as of Phase 5)

```
bin_datalog/
├── agent.py              (851 lines)  — ADK agent, tools, instruction prompt
├── mlil_parser.py        (523 lines)  — Regex MLIL-SSA → Fact tuples
├── fact_writer.py        (196 lines)  — Fact → Souffle .facts TSV files
├── bn_utils.py           (117 lines)  — BN Python path resolution, subprocess
├── resolve_calls.py       (99 lines)  — Hex callee → function name resolution
├── scripts/
│   └── bn_extract_facts.py (581 lines) — Headless BN fact extraction
└── rules/
    ├── schema.dl         (84 lines)   — Type + relation declarations
    ├── interproc.dl     (308 lines)   — 1-CFA interprocedural taint
    ├── boil.dl          (221 lines)   — BOIL candidate detection
    ├── taint.dl         (160 lines)   — Intraprocedural taint
    ├── signatures.dl    (168 lines)   — Library function models
    ├── summary.dl       (135 lines)   — Function summaries
    ├── alias.dl         (121 lines)   — Andersen-style points-to
    ├── core.dl          (101 lines)   — Basic def-use, reachability
    └── patterns.dl       (47 lines)   — Structural heuristics
```

Total: ~3,700 lines (1,345 Datalog + 2,368 Python).

### Data Flow

```
Binary (ELF/PE/Mach-O)
    │
    ▼
Binary Ninja (MLIL-SSA)
    │
    ├── MCP (interactive) ──→ mlil_parser.py ──→ fact_writer.py
    │                                               │
    └── Headless (batch) ──→ bn_extract_facts.py ──┘
                                                    │
                                                    ▼
                                            .facts TSV files
                                                    │
                                    ┌───────────────┼───────────────┐
                                    ▼               ▼               ▼
                              alias.dl        interproc.dl      boil.dl
                              (pass 1)         (pass 2)       (standalone)
                                │                   │               │
                                ▼                   ▼               ▼
                          PointsTo.csv      TaintedSink.csv   BOILCandidate.csv
                                            SanitizedVar.csv  BoundsGuardedLoop.csv
                                            GuardedSink.csv   ...
                                                    │
                                                    ▼
                                            LLM Agent interprets
                                            results for the user
```

---

## 8. Design Principles

1. **Declarative over imperative.** Vulnerability patterns are expressed as Datalog rules, not Python code. This makes them composable, auditable, and extensible. The LLM can compose new rules on the fly.

2. **Under-approximate by default.** False negatives are acceptable; false positives waste analyst time. Every analysis (alias, taint, BOIL) errs on the side of precision.

3. **SSA-aware throughout.** Every fact carries SSA versions. This gives us def-use chains for free and makes Flow/taint tracking precise without computing reaching definitions.

4. **LLM as orchestrator and classifier.** Datalog finds structural candidates; the LLM classifies, triages, and explains. The BOIL detector is explicitly a "pre-filter" — the LLM examines decompiled code for final verdict.

5. **Stratified confidence.** Rather than binary yes/no, BOIL candidates get high/medium/low confidence. This helps the LLM prioritize and lets analysts tune their false-positive tolerance.

6. **Incremental development via testing.** Each feature was tested on real binaries immediately. The BOIL detector went through 7 design iterations in a single session, driven by actual results on the boil-examples binary (101 true positives, 50 true negatives).

---

## 9. Lessons Learned

### SSA Is Both a Blessing and a Curse
SSA gives you explicit def-use chains and phi nodes — but it also introduces temp variables everywhere. Nearly every Datalog rule needs a `Flow`-based indirect variant to bridge SSA copy chains. This pattern repeats: `IncrementingVar`, `LoopMemRead`, `LoopMemWrite`, `BoundsGuardedLoop`, `DataDepTermination` — all needed both direct and indirect (flow-bridged) rules.

### The Power of Negation (and Its Limits)
Souffle's stratified negation is essential for confidence tiers and FP suppression. But cyclic negation is forbidden — you can't have `BOILCandidate` rules that negate themselves. The solution (separate intermediate relations) is mechanical but must be planned upfront.

### Guard Semantics Are Subtle
A comparison `if (x != 0)` could be:
- A null-byte termination check (data-dependent → dangerous)
- A bounds check (position-dependent → safe)
- A sentinel check (`!= 0xFFFF` → data-dependent but non-zero)

Distinguishing these requires tracking whether the compared variable came from a MemRead (data) or is the loop counter itself (position). The `!MemRead(f, def_addr, ...)` exclusion in `BoundsGuardedLoop` was the key insight.

### Testing Against Known Ground Truth Is Essential
The boil-examples binary with 101 true-positive and 50 true-negative functions was invaluable. Without it, we would have shipped the missing-MemWrite parser bug, the `mem` pollution in LoopIterVar, and the 60% FP rate on safe functions.

---

## 10. What's Next

- **Testing on real-world binaries** — libarchive, libpng, curl. Does the FP/FN rate hold?
- **Loop nesting awareness** — `boil_nested_14` is detected at low confidence because the inner loop's DataDepTermination isn't linked to the outer loop's guard
- **VLA/indexed copy patterns** — `boil_vla_struct_51` and `boil_indexed_3` (index-based, not pointer-based) need the LoopMemRead to track array index → address computation
- **Integration with taint analysis** — combine BOIL detection with interprocedural taint to find BOILs reachable from external input
- **Custom LLM prompts per confidence tier** — high-confidence BOILs get a short confirmation prompt; low-confidence ones get a deeper analysis prompt

---

*BinCodeQL is a collaboration between Sanjay and Claude. The system was developed iteratively: Sanjay provides the vulnerability research domain expertise and test binaries; Claude provides the implementation, Datalog rule composition, and systematic testing. Both contribute to design decisions.*
