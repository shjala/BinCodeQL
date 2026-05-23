# BinCodeQL — Datalog Rules Manual

*A technical reference to every Souffle Datalog rule in `rules/`.*

---

## Preface

BinCodeQL expresses its binary-analysis logic as Souffle Datalog rules that consume a fact base
extracted from Binary Ninja's MLIL-SSA representation. This manual documents every relation
declared in `rules/*.dl` — what it computes, how it is derived, and which upstream facts or
downstream consumers tie it into the pipeline.

**Reading order.** Skim Part I if you are new to Datalog. Part II is a glossary of the base
facts the extractor emits (authoritative schema lives in the CLAUDE.md table; this manual annotates
usage). Part III is the rule-by-rule reference, grouped so that each layer only depends on the
layers above it.

**Per-rule convention.** Each rule entry shows the relation signature followed by a brief
"what / how / caveat" capped at five lines. Where a rule has multiple clauses that share the
same head, they are summarised collectively — the goal is the reader's mental model, not a
line-for-line reproduction of the source.

**How to keep this current.** When you add or rename a relation, update the entry here at the
same time you edit the `.dl` file. Both live under `rules/` and `docs/` in the same repo — no
diff drift excuse.

---

## Part I — Datalog primer (for Souffle / MLIL-SSA)

### Relations, facts, rules

A Datalog program is a set of **relations** (typed tuples). A **fact** is a ground instance of a
relation; a **rule** derives new facts from existing ones. Souffle's concrete syntax:

```datalog
.decl Call(caller: Sym, callee: Sym, addr: Addr)   // declare a relation
.input Call                                         // load facts from Call.facts (TSV)
.output Reaches                                     // emit derived facts to Reaches.csv

Reaches(a, b) :- Call(a, b, _).                     // base case
Reaches(a, c) :- Reaches(a, b), Call(b, c, _).      // recursive case
```

Read `:-` as "if" — the head (left of `:-`) is derived when all body atoms (right) match. An
underscore `_` is an anonymous variable (match anything). Negation is written `!Relation(...)`
and is stratified: Souffle must be able to compute the negated relation completely before
negating it.

### Key operators you will see

- `A, B` — conjunction (both must hold).
- `(A ; B)` — disjunction inside a rule body.
- `X != Y`, `X = "foo"`, `X < Y` — arithmetic / string comparisons.
- `cat(a, b)`, `to_string(n)`, `substr`, `contains` — Souffle built-ins used for synthesising
  detail strings or normalising addresses.
- `count : { Pattern }` — aggregate (counts matching tuples) used in `FuncDefCount`.

### How our pipeline uses `.dl` files

Each `.dl` file is compiled independently by Souffle (`souffle -F facts -D output file.dl`).
Files cannot share relation definitions across runs — they communicate by **file staging**:
a rule's `.output` CSV is copied into the next rule's facts dir, where it is declared `.input`.
`tool_run_bn_extra_rules` in `agent.py` orchestrates this staging for the Bn* pass chain.
This isolation is why you will see the same `.decl Def / .input Def` block at the top of
almost every file — each rule file re-declares the inputs it consumes.

### MLIL-SSA facts, in one paragraph

Binary Ninja's MLIL-SSA form names every variable with an SSA version so each definition is
unique (e.g. `rbp_2#3`). The extractor walks this form and emits tuples: `Def/Use` at each
instruction, `PhiSource` at phi merges, `Call` + `ActualArg` at call sites, `Cast` / `ArithOp`
for the semantic operators, `Guard` from IF conditions, and structural facts like `CFGEdge` and
`FormalParam`. Rules then compose these into flow, aliasing, taint, and vulnerability patterns.
The SSA version (`ver`) is load-bearing — it's how we distinguish the pre- and post-loop value
of a counter, for example.

---

## Part II — Fact schema reference

The authoritative schema (column names and types for every base fact) lives in the CLAUDE.md
table at the project root. This section is an annotated index — use it to jump from a rule body
back to the fact that grounds it. `schema.dl` is the canonical `.decl`/`.input` block; including
it into ad-hoc queries is shorthand for pulling in the whole extractor's emit set.

- **Def / Use** — where an SSA variable is defined / used at an address.
- **Call / ActualArg / ReturnVal** — call sites and their argument bindings.
- **PhiSource / FormalParam** — SSA phi merges and parameter introduction.
- **MemRead / MemWrite / MemWriteSize / MemWriteValue** — memory operations. `MemWriteValue`
  separates the stored-value expression from the destination-address expression (both contribute
  to the generic `Use` at the same address, which is why width-mismatch rules join on
  `MemWriteValue` rather than `Use`).
- **FieldRead / FieldWrite / AddressOf / CallAddrArg / CallArgConst** — struct access, pointer
  creation, and literal argument values (e.g. the `-1` in `memset(buf, -1, n)`).
- **CFGEdge / Jump / StackVar** — control-flow and stack layout.
- **Guard** — an IF-condition comparison. Canonicalised so the guarded variable is always on the
  left (`var OP bound`). `bound_type` is `"var"` or `"const"`.
- **ArithOp / Cast / VarWidth / VarSign** — arithmetic, sign/zero-extend/truncate, bit-width,
  and ground-truth signedness (from DWARF — empty on stripped binaries).
- **AllocSite** — heap allocation call site with inferred element width (e.g. `elem_width=2`
  for `calloc(n, sizeof(uint16_t))`).
- **Annotations** (`.facts` tables the caller configures): `TaintSourceFunc`, `DangerousSink`,
  `EntryTaint`.
- **Signature tables** (defined in `signatures.dl`): `TaintTransfer`, `BufferWriteSource`,
  `TaintKill`.

---

## Part III — Rules, by layer

Layers are ordered so each one only consumes facts and derived relations from earlier layers:

1. Core / utilities
2. Taint analysis
3. BOIL (Buffer Overflow Inducing Loops)
4. Structural patterns
5. Integer / type confusion
6. Bn* rule set (NeuroLog port)
7. Bn* aggregation

---

### 1. Core / utilities

#### `schema.dl`

Declaration-only file. Defines the canonical `.decl Type` aliases (`Addr`, `Sym`, `Ver`, `Idx`)
and `.decl`/`.input` blocks for every base fact the extractor emits. Include via comment
(`#include "schema.dl"` is not a Souffle directive — `schema.dl` is kept as a reference copy
for ad-hoc queries). Has no rule bodies.

#### `core.dl`

Basic def-use, reachability, and data-flow utilities. Feeds most downstream analyses that don't
need Phase 4's 1-CFA context sensitivity.

- **`DefUsePair(func, var, ver, def_addr, use_addr)`** — an SSA variable's definition and a
  distinct-address use. Derived as `Def ∧ Use` at the same `(func, var, ver)` but different
  addresses. Trivial in SSA because version match is equivalent to reaching-def.

- **`Reaches(caller, callee)`** — transitive call-graph reachability. Base: any `Call` edge;
  recursive: composition. Used by coarse "can A eventually invoke B" queries; has no context
  sensitivity.

- **`PhiFlow(func, from_var, from_ver, to_var, to_ver)`** — one-step flow across a phi node.
  Directly unfolds `PhiSource`. Useful when a rule wants to reason about phi merges without
  recomputing transitive flow.

- **`IntraFlow(func, src, src_ver, dst, dst_ver)`** — intra-procedural transitive data flow.
  Three clauses: same-address use→def, phi merge, transitive closure. Self-edges are included
  implicitly via SSA version equality. See `summary.dl:Flow` / `interproc.dl:Flow` for local
  copies used to avoid cross-file staging.

- **`CallWithArg(caller, callee, call_addr, arg_idx, var, ver)`** — joins `Call` with
  `ActualArg` into one tuple for convenience.

- **`FieldAccess(func, addr, base, field, kind)`** — unifies `FieldRead` and `FieldWrite` into
  one relation with `kind ∈ {"read", "write"}`. Sugar for structure-level queries.

#### `summary.dl`

Classic parameter-summarisation pass: "which callee returns / call-args depend on which formal
parameter?" Stand-alone; duplicates `Flow` so it can run without core.dl in the facts dir.

- **`IsParam(func, var)`** — heuristic formal-parameter detection: any SSA v0 that is used but
  never defined inside the function. Excludes `mem` (the memory SSA token). Predates
  `FormalParam` and is kept as a fallback for extractor configurations that don't emit it.

- **`Flow(func, src, src_ver, dst, dst_ver)`** — local copy of `IntraFlow`: direct same-addr
  def-use, phi merge, transitive closure. `"mem"` is excluded so memory versions don't
  over-connect the graph.

- **`ReturnDependsOnParam(func, ret_var, param)`** — transitive dependence of a return
  variable on a formal parameter, computed via `Flow(param#0, ret_var#ret_ver)`. Two clauses
  handle the direct same-address def-use case explicitly.

- **`CallArgDependsOnParam(func, call_addr, callee, arg_idx, param)`** — same idea at
  call-argument granularity: which arg at which site traces back to which caller parameter.

- **`FuncSummary(func, output_kind, depends_on_param)`** — compact per-function summary. The
  `output_kind` is either `"return"` or `"argK_to_<callee>"` (string-synthesised). This is
  the callable-level artifact downstream triage uses.

#### `signatures.dl`

Library-function models. No rule bodies — just fact tables. These are the "trust boundary" of
the analyser: anything declared here is taken as-is, not re-analysed.

- **`TaintTransfer(func, out_arg, in_arg)`** — "when `in_arg` is tainted, `out_arg` becomes
  tainted" for an external function. `arg0..arg5` / `return` / `external` as sentinels. Covers
  memcpy / strcpy / strcat / printf family / sscanf / read-like I/O / libxml2 wrappers / a few
  libpng-specific shims.

- **`BufferWriteSource(func, arg_idx)`** — functions that write external data **into** the
  buffer at `arg_idx` (rather than returning a tainted value). Used by `interproc.dl` Rule 7
  to taint the heap object a tainted buffer points to.

- **`TaintKill(func, arg_idx)`** — sanitizers: `memset`, `bzero`, `explicit_bzero`, `memset_s`
  and their compiler-builtin variants. Consumed by `interproc.dl:SanitizedVar` which blocks
  `TaintedSink` matches on sanitized versions.

---

### 2. Taint analysis

#### `taint.dl`

The original (Phase 2) intraprocedural taint pass. Still used for simple queries; superseded by
`interproc.dl` for serious work. Has its own `TaintSourceFunc` / `DangerousSink` facts table
inline.

- **`TaintVar(func, var, ver, reason)`** — tainted SSA variable. Propagates via direct
  same-addr def-use, phi, field-taint round-trip, and AddressOf. Seeded by arguments to
  taint-source calls and by their return values. Four-column form (no `ctx`) — the
  context-sensitive successor is `interproc.dl:TaintedVar`.

- **`TaintedBuffer(func, buffer, reason)`** — symbolic buffer (a target of `AddressOf`) whose
  memory is tainted. Reading from a tainted buffer via `MemRead` re-taints the destination
  variable.

- **`TaintedField(func, base, field, reason)`** — a tainted value was stored into
  `base.field`. Subsequent `FieldRead` at the same pair re-taints the destination.

- **`TaintedSink(caller, callee, call_addr, arg_idx, tainted_var, tainted_ver, risk, reason)`**
  — tainted SSA variable appears at a `DangerousSink` argument slot. No sanitizer / guard
  awareness — use `interproc.dl:TaintedSink` if you need those.

- **`TaintSummary(func, var, ver, reason)`** — alias for `TaintVar` emitted as a separate
  output for grouped-per-function reporting.

#### `alias.dl`

Andersen-style flow-insensitive points-to and an alias-aware taint variant. Underapproximate
(false negatives only) — safe to run alongside `interproc.dl`.

- **`PointsTo(func, var, ver, obj)`** — an SSA variable may point to a named abstract object.
  Five rules: (1) `AddressOf(var) ↦ PointsTo(var, target)`; (2) same-address assignment; (3)
  phi merge; (4) load through a pointer whose pointee was stored into; (5) heap alloc returns
  point to a fresh `heap_<call_addr>` object.

- **`HeapAlloc(func, var, ver, call_addr)`** — the SSA variable that captures a
  `malloc`/`calloc`/`realloc` return value. Used to synthesise the fresh `heap_...` object
  label in `PointsTo`.

- **`AliasTaintedVar(func, var, ver, origin)`** — taint variant that propagates through
  alias-mediated stores and loads (`*p = tainted; ... x = *q` where `p`, `q` alias). Complements
  — does not replace — `interproc.dl:TaintedVar`, which tracks identity-based flow.

#### `interproc.dl`

The production taint engine. 1-CFA context-sensitive (`ctx` column = call site that introduced
the taint), sanitizer-aware, guard-aware, interprocedural-field-sensitive. Consumes
`signatures.dl`, `alias.dl:PointsTo`, and optionally `EntryTaint` from user configuration.

- **`IsParam(func, var)`** — backward-compat view derived from `FormalParam`, so rules written
  against the older `summary.dl` interface keep working.

- **`Flow(func, src, src_ver, dst, dst_ver)`** — same transitive intra-flow as `core.dl` /
  `summary.dl`, re-declared locally so the file is standalone-runnable.

- **`TaintedVar(func, var, ver, origin, ctx)`** — the 1-CFA taint relation. Seven seeding /
  propagation clauses: `EntryTaint` entry seeding; `TaintTransfer` external-source args /
  returns; intra-flow; pointer-to-buffer; library transfer at arg→arg and arg→return; caller
  →callee parameter mapping at call sites; callee→caller return propagation. `ctx=0` means
  top-level external, else the call-site address that carried taint into this function.

- **`TaintedBuffer(func, buffer, origin, ctx)`** — abstract buffer whose memory is tainted.
  Seeded by `AddressOf` from a tainted var and by output-parameter patterns (e.g. `sscanf`
  writes through a `&var` argument). Loads from a `TaintedBuffer` re-taint the destination var.

- **`TaintedField(func, base, field, origin, ctx)`** — field-level taint. Propagates
  interprocedurally: passing a struct-pointer arg forwards the field taint into the callee's
  formal param; returning modifies the caller's view symmetrically.

- **`TaintedHeapObject(obj, origin)`** — heap object (from `alias.dl:PointsTo`) whose contents
  are tainted, seeded by `BufferWriteSource` calls on pointers that point to `obj`. Loads
  through any pointer to `obj` re-taint the loaded value.

- **`SanitizedVar(func, var, ver, kill_func, kill_addr)`** — an SSA version passed to a
  `TaintKill` sink; excluded from the `TaintedSink` negation.

- **`GuardedSink(caller, callee, call_addr, guard_var, guard_op, guard_bound)`** — a tainted
  sink whose tainted var (or an upstream flow source) was compared in a `Guard`. Not used to
  suppress findings — emitted as a *separate* triage relation (see the feedback memory).

- **`TaintedSink(caller, callee, call_addr, arg_idx, tainted_var, risk, origin)`** — the
  actionable relation: tainted variable reaches a `DangerousSink` slot and is **not** in
  `SanitizedVar`. Use `BnUnguardedTaintedSink` (bn_unguarded_sink.dl) when you want the
  structural "no guard at all" subset.

- **`ArgStr(idx, str)`** — helper mapping `0 ↔ "arg0"`, etc., so `TaintTransfer`'s string-valued
  columns can join with numeric `ActualArg.arg_idx`.

---

### 3. BOIL — Buffer Overflow Inducing Loops

#### `boil.dl`

Structural loop-shape detector: byte-by-byte copy with incrementing src/dst and data-dependent
termination (e.g. null-byte). Stratified into high/medium/low confidence with a bounds-guard
false-positive filter.

- **`BackEdge(func, tail, head)`** — a CFG edge that goes "backwards" (`head <= tail`). Cheap
  surrogate for "this instruction is inside a loop".

- **`LoopIterVar(func, var, phi_ver, update_ver)`** — a variable whose phi node includes itself
  as a source — i.e. loop-carried. Excludes `mem`.

- **`IncrementingVar / DecrementingVar(func, var, phi_ver, update_ver[, step])`** — loop
  variable whose update is `+` / `-` on itself. Has two derivations each: direct (single
  ArithOp) and via intermediate copies bridged through `Flow`.

- **`LoopIterVarUnconfirmed(func, var, phi_ver)`** — `LoopIterVar` that did not match
  `IncrementingVar`. Weaker signal, retained for reporting.

- **`LoopMemRead / LoopMemWrite(func, addr, ptr_var, ptr_ver)`** — memory operation whose
  address register is a loop-iterating variable (directly, or via intermediate copy). Needed
  because MLIL-SSA often inserts temps between the iteration var and its use.

- **`DataDepTermination(func, read_addr, guard_addr)`** — the byte loaded at `read_addr` flows
  (direct or transitive) into a `Guard` at `guard_addr`. "The loop checks data it just read."

- **`BoundsGuardedLoop(func, var, guard_addr)`** — the loop-iter var (either phi or update
  version, direct or flow-lifted, but NOT via a memory load) is compared against a non-zero
  bound. A decrementing counter compared to `0` also counts. Purpose: filter out legit
  size-guarded loops that are NOT BOILs.

- **`BOILCandidate(func, src, dst, read_addr, write_addr, confidence)`** — unified three-tier
  result: `high` = both pointers incrementing + data-dep termination + no bounds guard;
  `medium` = weaker (loop-iter but arith not confirmed); `low` = structural only.

- **`BOILParamInvolvement(func, ptr_var, param_idx, role)`** — links the BOIL's src/dst back
  to formal parameters (direct and flow-indirect). Used by external-facing reports.

#### `boil_taint.dl`

Joins BOIL candidates with `interproc.dl:TaintedVar` and the user's `EntryTaint` specification.

- **`TaintedBOIL(func, src, dst, read_addr, write_addr, confidence, origin, role)`** — a BOIL
  whose src or dst pointer is tainted (direct match or via `Flow`). `role ∈ {src_tainted,
  dst_tainted}`.

- **`TaintedBOILEntry(boil_func, src, dst, confidence, role, entry_func, param_idx)`** —
  same BOIL, but matched to a specific entry-taint origin so the report shows "param N of
  entry function X reaches this BOIL". The match is by origin-string equality (`entry:<f>:argN`).

---

### 4. Structural patterns

#### `patterns.dl`

Heuristic, no-taint patterns. Three "almost always wrong" shapes.

- **`UnsafeStringCopy(func, call_addr, callee, dst_var, buf_var, buf_size)`** — `strcpy` /
  `strcat` whose destination is `&stack_buf` (via `AddressOf` + `StackVar`). Any size is unsafe;
  `buf_size` is shown for triage.

- **`UnsafeGets(func, call_addr)`** — any call to `gets`. No further conditions — it's always
  unsafe.

- **`UnsafeSprintf(func, call_addr, buf_var, buf_size)`** — `sprintf` whose dst is a stack
  buffer. Size is shown for triage, but the pattern fires unconditionally.

#### `patterns_mem.dl`

CodeQL-style memory-safety patterns, intraprocedural. Stand-alone `Flow` clause.

- **`Flow(...)`** — local transitive def-use / phi / identity closure (same definition as the
  other local flow copies).

- **`UseAfterFree(func, free_addr, use_addr, var)`** — `free(v)` then a later `Use(v, _, ua)`
  where `ua > fa` and `ua` is not another `free` call. Address-ordering is the sequencing proxy
  (SSA version alone isn't enough since freed-pointer uses often keep the same version).

- **`DoubleFree(func, free1_addr, free2_addr, var)`** — the same SSA variable appears as arg 0
  of two different `free` calls with `fa1 < fa2`.

- **`UncheckedMalloc(func, call_addr, var)`** — `malloc`/`calloc`/`realloc` whose return is
  used but never compared against 0 in a `Guard` (neither `eq 0` nor `ne 0`). False positives
  on style where the NULL check is inlined into an operator; triage per match.

- **`FormatStringSink(callee, fmt_arg)`** — fact table of printf-family sink positions
  (`printf`=0, `fprintf`=1, `sprintf`=1, `snprintf`=2, `syslog`=1, `dprintf`=1,
  `__printf_chk`=1).

- **`FormatStringVuln(func, call_addr, callee, fmt_var)`** — a formal parameter flows (direct
  or transitively) into a `FormatStringSink` format argument. Two clauses: direct param use,
  and param → flow → fmt arg.

#### `patterns_mem_interproc.dl`

Interprocedural counterpart of `patterns_mem.dl`. Three detection strategies composed together.

- **`Flow(...)`** — standard local transitive-closure definition.

- **Strategy 1: Parameter-based summaries.**
  - **`FreesParam(func, param_idx)`** — callable summary: "calling `func` with a pointer at
    `param_idx` will cause that pointer to be `free`'d". Base: param flows to `free(arg0)`.
    Transitive: param flows to a call whose callee has `FreesParam` at that index.
    Self-recursion gated.
  - **`UsesAfterFreeParam(func, param_idx, free_addr, use_addr)`** — the callee frees its
    param and then uses it (or a derived value) after the free.

- **Strategy 1 results:**
  - **`InterDoubleFree(caller, callee1, call1, callee2, call2, var)`** — four cases: two
    free-summary calls, free-summary + direct free, free-summary + flow + free-summary,
    and variants thereof; ordering `ca1 < ca2`.
  - **`InterUseAfterFree(caller, callee, free_call, use_addr, var)`** — three cases:
    summary-free + caller use, summary-free + subsequent non-free call-site use, summary-free
    + flow + use.

- **Strategy 2: Global-mediated.**
  - **`NormalizedGlobal(raw_base, norm)`** — equivalence-class the various string forms a
    global address can take (e.g. `"0x404020"` vs `"rdx_2#2 + 0x404020"`). Three clauses:
    exact hex-address match, computed-address-contains-simple-hex, and identity fallback.
  - **`GlobalFreeSite(func, free_addr, global_addr)`** — a MemRead from a global's offset 0,
    flowed to a direct `free` arg (or to a callee with `FreesParam`).
  - **`GlobalUseSite(func, use_addr, global_addr, var)`** — MemRead from a global, flowed to
    a subsequent use that is not itself a `free` call.
  - **`GlobalDoubleFree(f1, fa1, f2, fa2, global_addr)`** — cross-function pair of
    `GlobalFreeSite` rows on the same normalised global. Same-function clause also included.
  - **`GlobalUseAfterFree(free_func, free_addr, use_func, use_addr, global_addr, use_var)`**
    — free-site in one function paired with a use-site in any function on the same normalised
    global. Same-function case enforces ordering.

- **Strategy 3: Return-value propagation.**
  - **`ReturnsFreedPtr(func, param_idx)`** — callee frees its param then returns the
    (possibly flow-related) same variable. Caller receives a dangling pointer.
  - **`ReturnedDanglingPtr(caller, callee, call_addr, dangling_var, use_addr)`** — the caller
    then uses the return value.

- **Intra duplicates.** `UseAfterFree`, `DoubleFree`, `UncheckedMalloc`, `FormatStringVuln`,
  `FormatStringSink` are re-declared with the same bodies as in `patterns_mem.dl` so this file
  is standalone-runnable if the intra variant is not in the pipeline.

---

### 5. Integer / type confusion

#### `inttype.dl`

Four integer-abuse patterns at size-sensitive sinks, plus guard-flagging variants. Stand-alone.

- **`Flow(...)`** — local transitive closure (same definition as elsewhere).

- **`SizeSensitiveSink(func, arg_idx)`** — fact table of callees whose listed arg is a
  byte-count / element-count. Covers libc malloc/copy family. See `bn_arith_overflow.dl`'s
  `BnSizeSensitiveSink` for the extended list that includes FFmpeg / glib / kernel / Windows
  allocators.

- **`SignedToUnsignedConfusion(func, cast_addr, dst, dst_ver, callee, call_addr, arg_idx)`**
  — `Cast(kind="sx", sw<dw)` whose output flows to a size-sensitive sink arg. Negative input
  becomes a huge unsigned size after sign-extension.

- **`IntegerTruncation(func, cast_addr, dst, dst_ver, src_width, dst_width, callee,
  call_addr, arg_idx)`** — `Cast(kind="trunc", sw>dw)` into a size-sensitive sink. Wide value
  truncated, high bits silently dropped.

- **`WideningAfterOverflow(func, arith_addr, op, arith_width, cast_addr, callee, call_addr)`**
  — narrow `add`/`mul`/`lsl` on ≤4-byte signed value then `zx` widened and fed into a
  size-sensitive sink. Two forms: explicit `Cast(zx)` (`cast_addr > 0`) and implicit (x86-64
  auto-zero-extend, `cast_addr = 0`).

- **`SignExtNegativeToSize(func, arith_addr, cast_addr, callee, call_addr)`** — narrow
  arithmetic result (any op) sign-extended then used as an unsigned size. The
  arith-before-sx-to-size chain behind several glibc CVEs.

- **`GuardedIntIssue(func, cast_or_arith_addr, guard_addr, guard_op, guard_bound)`** — PRESENCE
  of a `Guard` anywhere on the cast output, cast source, arith source, or a flow-connected
  predecessor. Five clauses enumerating the positions. Emitted as a triage context — does NOT
  suppress `SignedToUnsignedConfusion` etc.

- **`CalleeGuardsParam(func, param_idx, guard_op, guard_bound)`** — the callee itself validates
  its `param_idx` (direct `Guard` on `param#0` or on a `Flow`-descendant).

- **`CalleeGuardedIntIssue(func, cast_addr, callee, call_addr, param_idx, guard_op,
  guard_bound)`** — integer-issue whose sink's callee guards the relevant param. Additional
  triage context.

#### `inttype_taint.dl`

The four-class detector re-run with tainted-source gating. Requires `TaintedVar.facts` from
`interproc.dl`. All four shapes repeat, now additionally predicated on `TaintedVar(f, csrc,
csv, origin, _)`.

- **`Flow(...)`, `SizeSensitiveSink(...)`** — local copies, same shape as `inttype.dl`.

- **`TaintedIntVuln(func, vuln_type, cast_addr, callee, sink_addr, origin)`** — unified output
  for all four patterns: `signed_to_unsigned`, `truncation`, `widening_after_overflow` (explicit
  + implicit variants: `widening_after_overflow_implicit` with `cast_addr=0`),
  `signext_negative_to_size`. `origin` is the `TaintedVar` origin tag.

- **`GuardedTaintedIntVuln(func, cast_or_arith_addr, guard_addr, guard_op, guard_bound)`** —
  mirrors `GuardedIntIssue` for tainted findings. Triage-only.

- **`CalleeGuardsParam(...)`, `CalleeGuardedTaintedIntVuln(...)`** — same roles as in the
  non-tainted file, with the tainted variant wired to `TaintedIntVuln`.

---

### 6. Bn* rule set (NeuroLog port)

The Bn* family ports NeuroLog's source-level vulnerability rules to MLIL-SSA. They run after
`interproc.dl` and share a precomputed `BnFlow` to amortise the transitive closure cost.
File order reflects the `tool_run_bn_extra_rules` pipeline — each file's outputs are staged
as facts before the next file runs.

#### `bn_flow.dl`

Shared intraprocedural data-flow transitive closure. Two-tier size-gated (V3 design, 2026-04-20).

- **`FuncDefCount(func, n)`** — number of `Def` rows per function. Built via the
  `count : { ... }` aggregate.

- **`FuncIsLarge(func)`** — functions above `FUNC_SIZE_GATE` (default 2000 defs) — flagged so
  the hop-counted closure skips them. Adjustable via `-DFUNC_SIZE_GATE=N` preprocessor flag.

- **`BnFlow1(func, src, src_ver, dst, dst_ver)`** — one-hop flow. Derived from same-address
  use→def (direct assignments) and `PhiSource`. Always computed, O(|Use| × |Def|) but cheap
  because of index sharing.

- **`BnFlowH(func, src, src_ver, dst, dst_ver, hops)`** — hop-counted transitive closure up
  to `MAX_HOPS` (default 10). Gated on `!FuncIsLarge` — only materialised for tractable
  functions. Built by extending `BnFlow1` one hop at a time.

- **`BnFlow(func, src, src_ver, dst, dst_ver)`** — unified projection: identity for every
  `Def`, plus `BnFlowH` (for small/medium funcs) or just `BnFlow1` (for large funcs). Shape
  is stable across the V1/V2/V3 iterations so downstream rules don't need to change.

#### `bn_signed_infer.dl`

Signedness inference used as input to `bn_arith_overflow.dl`. Precision-biased: downstream
rules gate on `"signed"` only.

- **`BnInferredSigned(func, var, ver, evidence)`** — raw signed signals: VarSign="signed"
  ground-truth (strongest), `sx` cast source or destination, signed comparison guards
  (`slt`, `sle`, `sgt`, `sge`). Each clause carries an `evidence` tag.

- **`BnInferredUnsigned(func, var, ver, evidence)`** — dual: VarSign="unsigned", `zx` cast,
  unsigned comparison guards (`ult`, `ule`, `ugt`, `uge`).

- **`BnSignedness(func, var, ver, sign)`** — resolved result. `sign ∈ {signed, unsigned,
  conflict, unknown}`. `signed` and `unsigned` fire only on purely-one-sided evidence;
  conflict sends both; unknown anchors to a `VarWidth` row so only known variables are
  emitted. Downstream rules filter on `"signed"`.

#### `bn_counter_oob.dl`

Unbounded-counter / counter-as-index detection — the core FFmpeg H.264 slice-counter shape.

- **`BnLoopIterVar(func, var)`** — loop-carried variable (phi with self-edge). Gating filter
  to prevent straight-line `p = q + 1` from exploding the candidate set.

- **`BnDangerousSink(func, arg_idx, risk)`** — fact table of size-sensitive sinks (`malloc`,
  `memcpy`, `read`, ...) + libxml2 wrappers. Similar in spirit to `BnSizeSensitiveSink` in
  `bn_arith_overflow.dl` but carries a `risk` column.

- **`BnHasUpperBound(func, var, ver)`** — proper upper-bound guard ops only: `slt`, `sle`,
  `ult`, `ule`. `eq` / `ne` are **not** upper bounds (the crux of the FFmpeg sentinel case).
  Flow-lifted in both directions to cover guards positioned before or after the increment.

- **`BnUnboundedCounter(func, var, ver, incr_addr)`** — an `ArithOp("add")` whose destination
  has no `BnHasUpperBound` anywhere on its SSA-connected versions.

- **`BnCounterUsedAsIndex(func, var, ver, incr_addr, use_addr, kind)`** — an unbounded counter
  reaches a memory operation. Four kinds: `mem_read_use`, `mem_write_use`, `ptr_arith`,
  `sink_arg`. All clauses gate on `BnLoopIterVar`.

- **`BnTaintedUnboundedCounter(func, var, ver, incr_addr, origin)`** — unbounded counter that
  is also `TaintedVar` (directly or via any SSA-connected version).

- **`BnTaintedCounterAsIndex(func, var, ver, incr_addr, use_addr, kind, origin)`** — the
  exploitable intersection: `BnCounterUsedAsIndex ∧ BnTaintedUnboundedCounter`.

#### `bn_alloc_copy.dl`

Classic heap-overflow pattern: `buf = alloc(A); copy(buf, src, B)` with `A ≠ B` or unbounded
copy into an alloc'd buffer.

- **`BnAllocFunc(callee, size_arg)`** — fact table of allocator callees and which arg is the
  size. Extensive FFmpeg / glib / Linux-kernel / Windows / libc coverage. Kept in sync with
  `_ALLOC_CALLEES` in `scripts/bn_extract_facts.py` and with `BnSizeSensitiveSink` in
  `bn_arith_overflow.dl`.

- **`BnCopyFunc(callee, dst_arg, size_arg)`** / **`BnUnboundedCopyFunc(callee, dst_arg)`** —
  bounded and unbounded copy sigs respectively. Includes libxml2 wrappers and glibc FORTIFY
  `__memcpy_chk` variants.

- **`BnAllocSite(func, call_addr, buf, buf_ver, size_var, size_ver, alloc_func)`** — the SSA
  variable that captures an allocator return. Filters out `buf = "mem"`.

- **`BnCopySite(func, call_addr, dst, dst_ver, size_var, size_ver, copy_func)`** — destination
  + size binding for bounded copy calls.

- **`BnAllocCopyMismatch(func, alloc_addr, copy_addr, buf, alloc_size, copy_size, alloc_func,
  copy_func, pattern, alloc_origin, copy_origin)`** — `BnAllocSite.buf → BnFlow → BnCopySite.dst`
  with `alloc_size ≠ copy_size`. Two patterns: `both_tainted_diff` (asz and csz tainted from
  different origins) and `untainted_alloc_tainted_copy` (attacker controls copy length only).

- **`BnAllocThenUnboundedCopy(func, alloc_addr, copy_addr, buf, alloc_size, alloc_func,
  copy_func, origin)`** — tainted-alloc-size followed by `strcpy`/`strcat`/`sprintf` on the
  allocated buffer. The allocation size is attacker-controlled so the unbounded copy can
  always overflow.

#### `bn_unguarded_sink.dl`

One-rule structural consolidation.

- **`BnUnguardedTaintedSink(caller, callee, call_addr, arg_idx, tainted_var, risk, origin)`**
  — `TaintedSink` minus any `GuardedSink` at the same call site. Per the team's feedback,
  guards do NOT suppress `TaintedSink` inside `interproc.dl`; this rule surfaces the
  structural subset for triage.

#### `bn_loop_bound.dl`

Tainted-loop-bound detection — complements BOIL.

- **`BnTaintedLoopBound(func, guard_addr, loop_var, loop_ver, bound_var, bound_ver, op,
  origin, taint_side)`** — a Guard with a loop-continuation op (`slt`, `sle`, `ult`, `ule`,
  `ne` — NOT `eq`). Three clauses: `bound_tainted` (bound is a tainted var), `loop_var_tainted`
  (direct), `loop_var_tainted_flow` (via `BnFlow`). `eq` is excluded because it's a sentinel
  check, not a loop continuation predicate.

#### `bn_unguarded_cast.dl`

Absence-of-guard dual to `inttype.dl:GuardedIntIssue`. Detects a narrowing or sign-extending
cast with no CFG-reaching guard on the cast source.

- **`BnCFGReach(func, from_addr, to_addr)`** — transitive `CFGEdge` closure. Local copy so
  the file is standalone-runnable.

- **`BnGuardedBeforeCast(func, cast_addr, src, src_ver)`** — a guard on the cast source
  (direct SSA match or flow-connected predecessor) that reaches the cast address on the CFG.

- **`BnUnguardedDangerousCast(func, cast_addr, src, src_ver, dst, dst_ver, kind, src_width,
  dst_width)`** — `Cast(kind="trunc", sw>dw)` or `Cast(kind="sx")` with no
  `BnGuardedBeforeCast`. These are the casts that warrant inspection because nothing visible
  on the CFG has checked the value yet.

#### `bn_arith_overflow.dl`

Narrow signed arithmetic overflow, with optional flow into a size-sensitive sink. The
recently-expanded `BnSizeSensitiveSink` list is the bridge to size-taking callees.

- **`BnCFGReach(func, from_addr, to_addr)`** — local CFG closure (same as `bn_unguarded_cast.dl`).

- **`BnSizeSensitiveSink(callee, arg_idx)`** — fact table covering libc / glib / kernel / FFmpeg
  (`av_*`) / Windows / libxml2 / `snprintf` / `vsnprintf`. Must be kept in sync with
  `bn_alloc_copy.dl:BnAllocFunc`.

- **`BnEffectiveGuardForArith(func, arith_addr, var, ver)`** — a guard on the arith dst (or a
  flow-connected predecessor) that reaches the arith address (pre-check) OR is reachable from
  it (post-check). Pre- and post-check accounting lets the rule match both `if (i < N) i += x`
  and `i += x; if (i < N)` shapes.

- **`BnPotentialArithOverflow(func, addr, var, ver, op, width)`** — `ArithOp` with
  `op ∈ {add, mul, lsl}`, `VarWidth ≤ 4`, `BnSignedness = "signed"`, and
  `!BnEffectiveGuardForArith`. Conservative on signedness: `"conflict"` / `"unknown"` are
  never fired.

- **`BnOverflowAtSink(func, arith_addr, sink_addr, var, callee, arg_idx)`** — potential
  overflow whose destination flows (via `BnFlow`) to a `BnSizeSensitiveSink` argument slot.
  The "this overflow actually matters for memory safety" refinement.

- **`BnTaintedOverflowAtSink(func, arith_addr, sink_addr, var, callee, arg_idx, origin)`** —
  `BnOverflowAtSink` + `TaintedVar` on either the overflow destination (direct pattern) or
  an arith source operand (indirect pattern: the overflow arises from tainted input value).
  High-severity feeder for `BnFinding`.

#### `bn_width_mismatch.dl`

Implicit truncation on a memory store — a wide SSA value stored into a narrower heap slot.
The root-cause shape behind several CVEs including the FFmpeg H.264 slice_table.

- **`BnNarrowStore(func, addr, val_var, val_ver, store_size, val_width)`** — a `MemWriteSize`
  of `S ≤ 4` bytes whose `MemWriteValue` is a var with `VarWidth > S` (and ≤ 8). Joins on
  `MemWriteValue` — NOT `Use` — so address-component pointer-width vars don't false-positive.

- **`BnWidthMismatchStore(func, addr, val_var, val_ver, store_size, val_width, alloc_addr,
  elem_width)`** — `BnNarrowStore` whose destination base traces (via `BnFlow`) back to a
  `BnAllocSite` with `elem_width < val_width`. The "32-bit counter into uint16_t[] slot"
  pattern.

- **`BnWidthMismatchCounter(func, addr, val_var, val_ver, store_size, val_width, alloc_addr,
  elem_width, incr_addr)`** — `BnWidthMismatchStore` AND the stored value is itself a
  `BnUnboundedCounter`. This is the exploitable intersection — counter can reach a value that
  doesn't fit the element, producing a silent truncation.

#### `bn_sentinel_init.dl`

The H.264 slice_table pattern: memset sentinel meets unbounded counter on a narrow-element
heap buffer.

- **`BnSentinelValue(value)`** — literal values that broadcast to a max-value sentinel: `"-1"`
  (signed form) plus `UINT8/16/32/64_MAX` in decimal and `0x..`/`0x..` hex serialisations.

- **`BnMemsetFunc(callee)`** — memset family: libc, FORTIFY, compiler builtins, wchar,
  Windows zeroing primitives.

- **`BnSentinelInit(func, init_addr, buf, buf_ver, sentinel_val)`** — `memset(buf, K, n)` with
  `K ∈ BnSentinelValue`. Primary clause binds the real SSA buffer via `ActualArg(ca, 0, ...)`.
  Fallback clause emits `buf="_unbound", buf_ver=0` when the extractor's register fallback
  recovers the fill constant but not the buffer SSA identity — keeps downstream signals alive
  without synthetic flow propagation.

- **`BnSentinelBuf(func, buf, buf_ver, sentinel_val, init_addr)`** — any SSA version reachable
  from a sentinel-initialised buffer via `BnFlow`. Skips `"_unbound"` rows since there's no
  real identity to propagate.

- **`BnSentinelNarrowAlloc(func, init_addr, alloc_addr, buf, buf_ver, sentinel_val,
  elem_width)`** — the sentinel buffer is linked (via `BnFlow` back to `BnAllocSite`) to an
  `AllocSite` with `1 ≤ elem_width ≤ 2`. Narrow elements make the sentinel collide with a
  reachable counter value.

- **`BnSentinelCollisionRisk(func, init_addr, cmp_addr, buf, counter, counter_ver,
  sentinel_val, origin, tier)`** — co-occurrence of a sentinel init and an unbounded counter
  in the same function. Three tiers: `eq_guarded_tainted` (A: `cmp_e`/`cmp_ne` on counter +
  tainted), `eq_guarded` (B: same guard + any counter), `structural` (C: bare co-occurrence).
  The tier names what the evidence supports — downstream reports key off this.

---

### 7. Bn* aggregation

#### `bn_findings.dl`

Unified output relation for the Bn* family. Runs last in the pipeline.

- **`BnFinding(func, addr, severity, category, var, detail)`** — one row per detected
  issue. Populated from each Bn* rule's output via a dedicated clause that synthesises a
  human-readable `detail` string via `cat`/`to_string`. Twelve categories cover:
  `tainted_unbounded_counter`, `tainted_counter_as_index`, `unbounded_counter`,
  `alloc_copy_<pattern>`, `alloc_then_unbounded_copy`, `unguarded_tainted_sink`,
  `tainted_overflow_at_sink`, `unguarded_cast_<kind>`, `tainted_loop_bound`,
  `width_mismatch_counter`, `width_mismatch_store`, `sentinel_collision[/_structural]`.
  Severity tiers — `high`, `medium`, `low` — map from the underlying tier columns (e.g.
  `BnSentinelCollisionRisk.tier` cascades to severity).

---

## Appendix A — Running the rules

**Full pipeline:**

```python
# inside the agent:
tool_run_taint_pipeline()          # alias.dl → interproc.dl (stages PointsTo, TaintedVar, ...)
tool_run_bn_extra_rules()          # bn_flow → bn_signed_infer → ... → bn_findings
```

**Ad-hoc single rule:**

```python
tool_run_souffle(rule_file="bn_sentinel_init.dl")
```

**Hand-invocation (debugging):**

```bash
souffle -F facts -D output rules/bn_arith_overflow.dl
# -p <dir>  : enable profile logs
# -c        : compile to C++ before running (10–100× faster on big TCs)
# -j auto   : parallelism (default via _souffle_cmd helper in agent.py)
```

Environment knobs (read by `_souffle_cmd` in `agent.py`):
- `SOUFFLE_JOBS` — parallelism (passed as `-j`). Default `auto`.
- `SOUFFLE_COMPILE` — set to `1` to pass `-c`.

## Appendix B — Extending the rule set

1. **Pick a layer.** New flow utility → `core.dl` or a local copy. New vulnerability pattern →
   its own `<topic>.dl` file. New Bn* rule → `bn_<topic>.dl` + wire into `tool_run_bn_extra_rules`
   `rule_files` list + `stage_after` map + (if surfaced) `bn_findings.dl`.

2. **Declare inputs, not includes.** Souffle runs each file independently; always `.decl` and
   `.input` every base fact you need. Don't rely on cross-file sharing except through staged
   `.csv → .facts` copy.

3. **Keep allocator / sink lists in sync.** `BnAllocFunc` (`bn_alloc_copy.dl`),
   `BnSizeSensitiveSink` (`bn_arith_overflow.dl`), `BnDangerousSink` (`bn_counter_oob.dl`),
   and `_ALLOC_CALLEES` (`scripts/bn_extract_facts.py`) all enumerate allocators. Drift is a
   real bug source — grep before adding a new callee.

4. **Emit, don't suppress.** Guard-aware findings are surfaced as separate triage relations
   (e.g. `GuardedSink`, `CalleeGuardedIntIssue`). The unguarded / exploitable core relation
   should not apply a `!Guard(...)` negation by default (team preference — see the no-suppression
   feedback memory).

5. **Add to this manual.** One entry per relation, ≤5 lines, in the matching section above.

## Appendix C — Common Souffle gotchas

- **Stratified negation.** `!R(...)` requires `R` to be fully computed first. You cannot write
  `A(x) :- !A(x), ...`. Split into auxiliary relations.
- **Recursive aggregates.** `n = count : { Def(f, _, _, _) }` inside a recursive rule is a
  compile error. Compute counts in a non-recursive step first.
- **`_` in the head.** Every head variable must appear in the body. Use fresh names, not `_`.
- **Identity self-loops.** Adding `BnFlow(f, v, ver, v, ver)` forces every rule that joins
  via BnFlow to also match same-variable same-version. Usually desired — double-check.
- **`Def("mem", ...)`** — the memory SSA token is a `Def` just like any variable. Most rules
  filter with `var != "mem"`. Forgetting this floods results.
- **String keys in joins.** Souffle indexes symbol columns, but a wildcard on a symbol column
  can still be expensive when the domain is large. Bind the most-selective column first.

---

*Last updated: 2026-04-22. Update this file whenever you add, rename, or materially change a
relation under `rules/`.*
