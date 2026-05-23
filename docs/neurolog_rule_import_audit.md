# NeuroLog → BinCodeQL Rule Import Audit

**Date:** 2026-05-21
**Source repo:** `../neurolog-cli/neurolog/rules/` (31 `.dl` files, 7,093 LOC)
**Target repo:** `bin_datalog/rules/` (MLIL-SSA fact base)
**Scope:** *Audit only.* No rules are ported in this document — verdicts must be reviewed and approved before any porting work begins.
**Bias:** Conservative. Per user direction: it is OK to skip a rule; it is NOT OK to port a wrong rule.

---

## 1. Schema delta — what bin_datalog has vs. what NeuroLog uses

Most of the core fact schema is **shared** (Def/Use/Call/ActualArg/PhiSource/MemRead/MemWrite/FieldRead/FieldWrite/AddressOf/CFGEdge/Guard/ArithOp/Cast/AllocSite). Where they diverge matters for portability.

### Facts NeuroLog has that we LACK (or have weakly)

| NeuroLog fact | Used for | bin_datalog status | Portability impact |
|---|---|---|---|
| `VarType(func, var, type_name, width, signedness)` | Signedness + canonical type per var | We have `VarSign(...)` (DWARF, signedness only) and `VarWidth(...)` (width only) | **Partial**: combine `VarSign + VarWidth` for signedness+width; type-name **strings** are unavailable on stripped binaries |
| `Cast.src_type / Cast.dst_type` (declared type names) | IncompatibleStructCast, VoidPtrLaundering, FuncPtrCastMismatch | Our `Cast` has widths only | **Blocking** for type-name-based confusion rules; partial workaround via BN type metadata if present |
| `ActualArgVarRef`, `ActualArgFieldPath` (compound-expr decomposition) | Source expression → constituent vars / field paths | SSA `ActualArg.(var,ver)` is the equivalent for atom args; **no** decomposition for compound expressions because in MLIL-SSA compounds are already broken into intermediate SSA temps | **Mostly subsumed** by SSA — we read intermediate vars directly. Edge case: dst expression that contains `+` (offset copy) is detectable from `ArithOp` feeding `ActualArg` |
| `FieldBaseRoot`, `FieldChainStep`, `ObjFieldPointsTo` (Phase 2a) | Nested field path resolution, heap-object-keyed field points-to | Not emitted; our `alias.dl` is Andersen but flow-insensitive without field chain | **Blocking** for rules that key field taint on heap-object identity. Infrastructure addition possible (extractor + alias extension); non-trivial |
| `MemcpyAlias`, `HeapFieldFuncPtr`, `IndirectFieldCall`, `FuncPtrAssign`, `IndirectCallSite` | Indirect-call / struct-copy alias | We have global-pointer indirect-call resolution; no struct-copy alias | **Adaptable**: extractor can emit these; non-trivial |
| `ConstTableLookup` | Recognize values constrained by source const-table lookup | None | **Blocking** for guard-quality rules that lean on it; can be approximated for binary using read-from-rodata patterns (lossy) |
| `GuardEarlyReturn`, `BoundedField`, `ValidatingCast`, `IsValidator` (smell-pass relations) | Source-side LLM-extracted guard-quality annotations | None | **Adaptable**: GuardEarlyReturn = `Guard at A` + `ReturnVal` close in CFG. ValidatingCast = `Cast at A` + `Guard(!=, _)` co-located in CFG. Both derivable from facts we already have |
| `ReturnSite(func, addr)` (per-return-instruction addr) | LeakyExitPath, GuardEarlyReturn | We have `ReturnVal(func, var, ver)` but no return-instruction address | **Easy add** — emit return-instruction addrs from MLIL-SSA |
| `BlockHead`, `CFGBlockEdge`, `FuncBlockCount` (block-level CFG) | Path-sensitive dominance (`EffectiveGuardDom`) | We have edge-level `CFGEdge`; `bn_guard_dominates.dl` already does reach-skipping dominance | **Subsumed**: our `bn_guard_dominates` is the equivalent of `source_dominance.dl`'s `EffectiveGuardDom`. No port needed |
| `LoopCounter` (LLM-emitted loop-IV) | BOIL loop-bound origin | Our `bn_counter_oob.dl` uses `PhiSource` self-ref instead | **Subsumed** (different mechanism, same role) |
| Project-signature relations: `AllocFamily`, `FreeFamily`, `ResourceSlot`, `CleanupFunc`, `StateField`, `FlagStateBit`, `KnownLookupCallee`, `SwitchKey`, `DeferredHandoff`, `SyncJoin` | All project-specific (curl/ffmpeg/etc.) | None | **Add as user-supplied input relations**. They are declarations, not derivations — extending the schema costs almost nothing; the work is at the analyst's end to populate them |

### Facts bin_datalog has that NeuroLog does NOT

These are binary-specific and *strengthen* portable rules:

- `CallArgConst(call_addr, arg_idx, value)` — literal int args (subsumes `SizeIsLiteral`/`SizeIsSizeof` for memset/etc.).
- `CallAddrArg(call_addr, arg_idx, target)` — &local args directly.
- `AllocSite(call_addr, func, size_var, size_const, elem_width)` — richer than NeuroLog's pattern-matched `AllocCallee`.
- `MemWriteSize`, `MemWriteValue`, `FieldWriteValue` — distinguish address vs. value at stores (precision win).
- `VarSign` — DWARF-grounded signedness when available (better than name-based heuristics).

---

## 2. Per-rule verdicts

**Verdict legend:**
- 🟢 **PORT** — directly portable; logic transfers cleanly to SSA facts.
- 🟡 **ADAPT** — portable with extractor or auxiliary-rule work; clearly defined gap.
- 🔵 **PARTIAL** — only a subset of the rule's sub-patterns is portable; the rest depend on source-only facts.
- 🔴 **SKIP** — depends on source-only constructs with no reasonable binary equivalent; or already covered by an existing bin_datalog rule.

Where a rule is **already covered**, the bin_datalog equivalent is named.

### Group A — `source_*.dl` (source-specific reaching-defs / type-string / tree-sitter)

| File | Verdict | Reason | Already covered by |
|---|---|---|---|
| `source_core.dl` | 🔴 SKIP | CFG-based reaching-defs reimplement what MLIL-SSA gives us structurally. Source `(var, def_line)` ≠ SSA `(var, ver)`. | `core.dl` |
| `source_taint.dl` | 🔴 SKIP | Source-style intraprocedural taint. SSA version is `taint.dl`. | `taint.dl` |
| `source_interproc.dl` (1,168 LOC) | 🔴 SKIP **except** sub-ideas | The bulk is reaching-defs + field-sensitive alias + LLM-smell-pass dependencies. The 1-CFA core, sanitizer kill, guarded-sink, and `InheritedParamBound`-style transfer are already in our `interproc.dl`. **Sub-ideas worth lifting** (see §3 below): G7 (derived-from-bounded transitive inheritance), heap-object-keyed taint, FuncModifiesParam side-effect reflection. | `interproc.dl` |
| `source_memsafety.dl` (711 LOC) | 🔴 SKIP **except** sub-ideas | Most outputs already have Bn* equivalents (UAF/double-free/UncheckedMalloc/BOIL). **Sub-ideas worth lifting**: `AllocCopyMismatch` joint-tainted variant (already partial in `bn_alloc_copy`), `ReinitBetweenFreeAndUse` UAF refinement, `SafeWriteAfterFreeAndNull` UAF refinement. | `bn_alloc_copy`, `patterns_mem`, `boil_taint` |
| `source_type_safety.dl` (748 LOC) | 🔴 SKIP **except** sub-ideas | Most patterns depend on `VarType.type_name` + `Cast.src_type`/`dst_type` strings we don't have. **Already covered**: TruncationCast→`bn_unguarded_cast`, NarrowArithAtSink→`bn_arith_overflow`, UnboundedCounter→`bn_counter_oob`, WidthMismatchAtSink→`bn_width_mismatch`. **Worth lifting**: `ValidatingCast` (Cast + nearby `!=` guard) and `FieldBoundedVar` (G8) as FP-suppression refinements. | `bn_unguarded_cast`, `bn_arith_overflow`, `bn_counter_oob`, `bn_width_mismatch` |
| `source_dominance.dl` | 🔴 SKIP | Block-level dominance for source CFGs. Our `bn_guard_dominates.dl` already implements reach-skipping dominance on edge-level `CFGEdge`. | `bn_guard_dominates.dl` |
| `source_sink_pass.dl` | 🔴 SKIP | Re-fires `TaintedSink` from recycled outputs to handle Souffle fixpoint quirks. Our pipeline runs `interproc.dl` in a single pass; not needed. | n/a |
| `source_arith_sink_bridge.dl` | 🔴 SKIP (mechanism) / 🟡 ADAPT (intent) | Bridges inlined `ArithOp` to `Call(alloc)` when args are expressions, not temps. In SSA this is always a temp — `Def(temp) ← ArithOp` then `ActualArg(call, idx, temp)` — so the bridge becomes trivial. Worth wrapping a tiny rule that materializes the same finding shape if we want a dedicated "alloc-with-derived-size" relation for triage. | implicit in `interproc.dl` |

### Group B — novel bug classes (highest interest)

#### 🟢 `allocator_mismatch.dl` — malloc-family vs free-family mismatch (92 LOC)

- **Detects:** `xmlMalloc(...)` then `free(...)`, or `av_malloc(...)` then `g_free(...)`. **NOT** size mismatch — *family* mismatch. Different from our existing `bn_alloc_copy.dl`.
- **Facts needed:** `Call`, `Def`, `ActualArg`, plus user-supplied `AllocFamily(callee, family)` and `FreeFamily(callee, family)`. DefReachesUse maps to SSA def-use via `Flow` (we have it via `bn_flow.dl`).
- **What's lost:** NeuroLog notes a precision caveat in curl (`#define free Curl_cfree` makes the extractor see `free` instead of `Curl_cfree`). In binary we see the **post-link** symbol — usually *less* ambiguous than source. **Precision likely improves in binary.**
- **Adaptation:** add `.decl AllocFamily(callee, family)` + `FreeFamily(callee, family)` to `schema.dl` as user-supplied; write `rules/bn_allocator_mismatch.dl` joining `Call → Flow → Call`.
- **Verdict:** 🟢 **PORT** as `rules/bn_allocator_mismatch.dl`. High-confidence; low-effort.

#### 🟡 `lifecycle_audit.dl` — leaky-exit-path + missing-field-release (216 LOC)

- **LeakyExitPath**: alloc → return without intervening free on any path.
  - Facts: `Call` (AllocFamily), `Def`, `CFGEdge`, `ReturnSite` (need to emit return-instruction addresses).
  - **Adaptation:** emit `ReturnSite(func, addr)` from MLIL-SSA (one extractor line). Then port directly. Free-path detection needs Flow + `Call(FreeFamily)` along all CFG paths from alloc to return — Souffle can express this.
  - **Lost in translation:** v0 doesn't model ownership transfer (`*out_ptr = buf; return 0`) or tail-call free wrappers — same FP class in source and binary.
  - **Verdict:** 🟡 **ADAPT** — port LeakyExitPath as `rules/bn_leaky_exit.dl` after emitting `ReturnSite`. Good FFmpeg/libxml2 candidate.

- **MissingFieldRelease**: cleanup function reads `obj->field` but doesn't free it.
  - Facts: `FieldRead`, `FieldWrite`, name heuristic for cleanup (`*_free`/`*_cleanup`/`*_destroy`), plus user-supplied `ResourceSlot(struct, field)`.
  - **What's lost:** binary may not preserve struct field names if stripped. With DWARF/BN-types we get them. Without, this rule is unusable.
  - **Verdict:** 🟡 **ADAPT** — port only when binary has type info (gate on field-name availability). Otherwise skip per-binary.

#### 🔵 `type_confusion.dl` — five sub-patterns (211 LOC)

Decompose:

| Sub-pattern | Needs | Verdict |
|---|---|---|
| `IncompatibleStructCast(T → U)` | `Cast.src_type` + `Cast.dst_type` strings | 🔴 SKIP (no type-name strings on stripped binaries) |
| `VoidPtrLaundering` (T → void* → U) | Same | 🔴 SKIP |
| `PtrIntTruncation` (ptr8 → int<8 → ptr) | `Cast.src_width` + `Cast.dst_width` + `Cast.kind="truncate"` | 🟢 **PORT** — widths only; we have all of this. Detect: `Cast(_, dst1, 8, w<8)` then `Cast(_, dst2, w<8, 8)` where same `dst1` SSA flows to `dst2`'s `src`. Real bug class on 32→64 ports. |
| `FuncPtrCastMismatch` | Function-pointer type signatures | 🟡 **ADAPT** when BN type info available (function prototypes are accessible). Otherwise skip. |
| `AllocCastChannel` (malloc at A, cast at A±5 lines) | `Call(alloc)` + `Cast` nearby | 🟢 **PORT** — addr-proximity is well-defined; we already detect alloc → arith → use chains. Lower value than NeuroLog version since binary doesn't show "cast from void*"; would surface "alloc result reinterpreted with non-trivial width change". Possibly weaker than source. |
| `TaintedTypeConfusion` (any of above + `TaintedVar`) | `TaintedVar` | Inherits subset of above. |

**Overall verdict:** 🔵 **PARTIAL** — port `PtrIntTruncation` (clear win) and optionally `FuncPtrCastMismatch` when type info is present. Skip the rest. New file: `rules/bn_type_confusion.dl`.

#### 🔴 `type_knowledge.dl` (202 LOC)

- **Detects:** validates `VarType` claims against a hardcoded LP64 type KB.
- **Verdict:** 🔴 **SKIP** — entirely source-type-KB. We don't ingest type-name strings, so there's nothing to validate. Our `VarSign` from DWARF is the ground-truth equivalent; we already trust it.

#### 🟢 `joint_buffer_bound.dl` — joint offset+size bound check (114 LOC)

- **Detects:** `strcpy(buf+offset, src)` where `offset` and `strlen(src)` are *separately* bounded but no *joint* bound. This is the **curl CVE-2023-38545** pattern.
- **Facts:** `Call`, `ActualArg`, `Guard` (with bound as `Sym` — we have this), `VarType`-signedness (we have `VarSign`).
- **Adaptation:** detect offset-copy form via `ArithOp(off, "add", base, _)` feeding `ActualArg(call_addr, 0, _, off_result, _)`. The "guard mentions BOTH off_var AND sz_var" check translates to two `Guard` rows whose `bound` field contains the names of both variables; in binary this only works when the comparison is *symbolic* (e.g., `Guard(_, _, off, _, "<", "sz - base")` keeps `sz` in the bound string).
- **What's lost:** in binary, guards often appear as `Guard(_, _, off, _, "<", "0x100")` (concrete constant) — the symbolic relation between off and sz that source had is gone. **The "no joint guard" detection becomes less precise.** Acceptable: we'd be flagging *candidates* anyway and dispatching to triage.
- **Verdict:** 🟢 **PORT** as `rules/bn_joint_buffer_bound.dl`. Loss-of-precision is documented; finding shape is still actionable.

#### 🟡 `state_machine_invariants.dl` — flag-union misuse + stale-state (250 LOC)

- **Detects two:** (a) flag-bitmap used as lookup key without masking state bits; (b) state field read after a call that may have modified it.
- **Facts:** `Guard`, `Call`, `ActualArg`, `SwitchKey`, `FieldRead`, `FieldWrite`, `ArithOp`, `FormalParam`, plus user-supplied `StateField(field)`, `FlagStateBit(struct, field, bit)`, `KnownLookupCallee(callee)`.
- **Adaptation:**
  - SwitchKey: emit from BN's MLIL_JUMP_TO / jump-table metadata.
  - All signatures: user-supplied — add to schema.
  - The pattern logic (mask-before-use via `ArithOp("and", ~bit)`, etc.) ports cleanly.
- **What's lost:** zero on the pattern side; full loss on the bottom-half (FlagStateBit declarations) without source. But that's also true in source — these are *project-supplied* signatures.
- **Verdict:** 🟡 **ADAPT** — port the framework as `rules/bn_state_machine.dl`. Will be dormant until per-binary signatures are supplied. Document this clearly.

#### 🟡 `unbounded_server_write.dl` — guard exists but no early-return (80 LOC)

- **Detects:** `memcpy(dst+off, src, sz)` where `Guard(sz)` exists but doesn't terminate the function. **CVE-2023-38545** companion to `joint_buffer_bound`.
- **Facts:** `Call`, `ActualArg`, `Guard`, plus derived `GuardEarlyReturn`.
- **Adaptation:** derive `GuardEarlyReturn(func, guard_addr)` from `Guard(func, guard_addr, ...)` + reach-to-`ReturnSite` within ≤K basic blocks via `CFGEdge`. One small auxiliary rule. Once that's emitted, the main rule ports directly.
- **What's lost:** the "early return" definition is fuzzier in binary (heuristic K); calibrate per-binary.
- **Verdict:** 🟡 **ADAPT** — port as `rules/bn_unbounded_server_write.dl` after adding the `GuardEarlyReturn` derivation auxiliary.

#### 🟢 `unbounded_sink_audit.dl` — sink-first triage (151 LOC)

- **Detects:** *all* dangerous-function calls whose size arg is not provably bounded (sink-first, opposite of source-first taint).
- **Facts:** `Call`, `ActualArg`, `Guard`, `DangerousSink` (we have it), `FormalParam` (we have it), plus optionally `ConstTableLookup`.
- **Adaptation:**
  - `SizeArgIndex` table (memcpy→2, malloc→0, etc.) ports verbatim.
  - `SizeIsLiteral`: subsumed by **our** `CallArgConst` (cleaner than NeuroLog's source check).
  - `SizeIsSizeof`: in binary, `sizeof(T)` is already a literal — covered by `CallArgConst`.
  - `SizeFromConstTable`: skip — niche; replaceable later with a rodata-read heuristic.
- **What's lost:** `ConstTableLookup` provenance check. Acceptable; remaining checks already catch most cases.
- **Verdict:** 🟢 **PORT** as `rules/bn_unbounded_sink_audit.dl`. **High value as a triage hook** — surfaces sink candidates for the agent's `/triage` flow.

#### 🟡 `uninit_var_use.dl` — read-before-write (80 LOC)

- **Detects:** strict uninit: `Use(var)` with no `Def`, `FormalParam`, or `AddressOf`.
- **Facts:** SSA `Def`/`Use`/`FormalParam`/`AddressOf` — we have all of these.
- **Adaptation:** in MLIL-SSA, an uninit read shows up as a use of a version not defined by any IR statement (BN typically marks this; some versions become phi-with-undef-source). Need to surface these as a fact, e.g., `UninitDef(func, var, ver)`.
- **What's lost:** NeuroLog comments: "source advantage — declared locals vs parameters are syntactically distinct". In binary, stack-locals come from `StackVar`, parameters from `FormalParam` — *we can distinguish them*. So no real loss; the rule may even be cleaner in binary.
- **Verdict:** 🟡 **ADAPT** — port as `rules/bn_uninit_use.dl` after the extractor emits `UninitDef` (or we infer it from "phi source with no upstream Def reaching from entry").

#### 🟡 `concurrent_uaf.dl` — handoff-to-deferred-then-free without sync (139 LOC)

- **Detects:** pointer handed to a deferred callback (e.g., timer, work queue) and freed before a join.
- **Facts:** `Call`, `ActualArg`, `Def`, `Use`, `CFGEdge`, plus user-supplied `DeferredHandoff(callee, idx)`, `SyncJoin(callee)`, `FreeFamily(callee, family)`.
- **What's lost:** zero on the pattern. All loss is in *populating* the signatures. NeuroLog calls this "PROBABILISTIC by construction" — surfaces candidates for human/LLM review.
- **Verdict:** 🟡 **ADAPT** — port as `rules/bn_concurrent_uaf.dl`. Same calibration cost as in source.

#### 🟡 `nondestructive_peek_in_loop.dl` — CPU-busy spin (109 LOC)

- **Detects:** loop with a `peek`-class call and a transient-error guard (EAGAIN/CURLE_AGAIN/EWOULDBLOCK) co-cyclic with no state advance.
- **Facts:** `Call`, `Guard`, `CFGEdge` — all available.
- **Adaptation:**
  - `peek` callee detection — works on binary symbols when present.
  - "Guard bound contains 'EAGAIN'" — in binary, EAGAIN is a numeric constant (11 on Linux). We'd need to match against numeric ground-truth: `Guard(_, _, _, _, "==", "11", "const")` for EAGAIN, similarly for EWOULDBLOCK and project-specific codes. **More verbose than source, equivalent semantically.**
- **What's lost:** if the binary error code differs from the platform default (rare), false negative. Calibrate per-target.
- **Verdict:** 🟡 **ADAPT** — port as `rules/bn_peek_in_loop.dl` with a numeric error-code lookup table.

#### 🟡 `single_writer_security_field.dl` — single-write security field (168 LOC)

- **Detects:** struct field written exactly once, reused as a key/mask/nonce. Underlies **CVE-2025-10148** (WebSocket per-frame key rotation).
- **Facts:** `FieldRead`, `FieldWrite`, `ArithOp` (xor), plus `PointsTo`, `ObjFieldPointsTo`, `FieldChainStep`, `BufferWriteSource`, `ActualArgFieldPath`.
- **Blocking dependency:** `ObjFieldPointsTo` (heap-object-keyed field points-to) — Phase 2a alias work we have **not** done. Without it, "single write to *this object's* field" collapses to "single write to *any* `base->field`" and false positives explode.
- **Adaptation:** would require extending `alias.dl` with heap-object-keyed field points-to. Real work — not a trivial port.
- **What's lost:** field names: requires DWARF/BN-types. Without them, the rule fires on numeric offsets and the SecuritySensitiveFieldName heuristic (mask/key/iv/nonce/secret substring match) doesn't work.
- **Verdict:** 🟡 **ADAPT** but **defer**. Add to Phase 3 backlog as "field-sensitive alias + security-field rule" — multi-week effort. **Do not port now.**

#### 🔴 `debug_sink.dl` — debugging only

- **Verdict:** 🔴 **SKIP**. Not production code.

### Group C — overlap with existing bin_datalog rules

| File | Verdict | Reason | Already covered by |
|---|---|---|---|
| `schema.dl` | 🔴 SKIP (use ours) | Our schema is a superset (CallArgConst, AllocSite, MemWriteValue, FieldWriteValue, VarSign). Some NeuroLog-only annotation relations (`AllocFamily`, `FreeFamily`, `DangerousSink` augmentations) are worth **importing as decls** for the rules above. | `schema.dl` |
| `alias.dl` (402 LOC) | 🔵 PARTIAL | Core Andersen rules subsumed by our `alias.dl`. The Phase 2a field-sensitive extensions (FieldChainStep, ObjFieldPointsTo, MemcpyAlias, HeapFieldFuncPtr, IndirectFieldCall) are not in ours and are required by `single_writer_security_field` and parts of `state_machine_invariants`. **Lift the field-sensitive sub-pass** in Phase 3 — bundled with single_writer rule. | `alias.dl` (partial) |
| `signatures.dl` | 🔴 SKIP | Our `signatures.dl` already declares the same TaintTransfer / BufferWriteSource / TaintKill triples. Worth sanity-diffing the signature tables once to pull in any new library models NeuroLog added that we lack. | `signatures.dl` |
| `taint.dl` | 🔴 SKIP | SSA equivalent in our `taint.dl`. | `taint.dl` |
| `core.dl` | 🔴 SKIP | SSA equivalent in our `core.dl`. | `core.dl` |
| `summary.dl` | 🔴 SKIP | SSA equivalent in our `summary.dl`. | `summary.dl` |
| `interproc.dl` (binary version — 318 LOC, NOT the 1168-LOC source one) | 🔴 SKIP | This appears to be NeuroLog's binary-side experimental copy. Their `interproc.dl` columns match ours `(func, var, ver, origin, ctx)` exactly. Our `interproc.dl` is more mature (size-gated Flow TC for performance, 1-CFA tested on FFmpeg). | `interproc.dl` |
| `patterns.dl` | 🔴 SKIP | Our `patterns.dl` covers the same structural patterns. | `patterns.dl` |
| `patterns_mem.dl` | 🔴 SKIP | Our `patterns_mem.dl` + `patterns_mem_interproc.dl` cover UAF/double-free/UncheckedMalloc/format-string. | `patterns_mem.dl`, `patterns_mem_interproc.dl` |
| `triage_ranker.dl` (226 LOC) | 🟡 ADAPT | Evidence-driven risk scorer (loop count, MemRead/MemWrite, ArithOp, Cast, Guard counts → FuncRiskScore). We have `bn_findings_rank.dl` for findings-level ranking but no **function-level pre-extraction risk scoring**. Worth porting as `rules/bn_func_risk.dl` for triage pre-filtering. Type-based weights (signedness flips, narrow casts) port directly via our `VarSign`+`VarWidth`+`Cast` facts. | partially `bn_findings_rank.dl` |

---

## 3. Sub-ideas worth lifting from `source_*.dl` (without porting the whole file)

These are individual rules buried in `source_interproc.dl` / `source_memsafety.dl` / `source_type_safety.dl` that are useful even though the bulk of the file is source-only.

| Sub-rule | From | What it adds | Adaptation |
|---|---|---|---|
| **G7 — Derived-from-bounded inheritance** | `source_interproc.dl` (InheritedParamBound) | If a param is guarded by the caller and a callee computes `y = x + k`, `y` inherits boundedness — suppresses spurious unguarded-sink findings | Already partially in our `interproc.dl` 1-CFA — verify; if missing, lift as a single extra rule |
| **FuncModifiesParam** side-effect reflection | `source_interproc.dl` | When `f(&out)` is called and `f` writes `*out`, reflect the write into the caller's view | Worth a future expressiveness uplift; not urgent |
| **ReinitBetweenFreeAndUse** UAF refinement | `source_memsafety.dl` | UAF gated on: free; reassign; use — suppresses 2-step FPs where the var is reinitialized between free and use | Port; uses pure SSA facts |
| **SafeWriteAfterFreeAndNull** UAF refinement | `source_memsafety.dl` | Suppresses `free(p); p = NULL; ... if (p) use(p)` patterns | Port; pure SSA facts |
| **ValidatingCast (G4)** FP-suppressor | `source_type_safety.dl` | A `Cast` whose result is immediately checked against a sentinel (`!=`) and returned-on-mismatch — suppresses `bn_unguarded_cast` FPs | Port as auxiliary `rules/bn_validating_cast.dl`; consumed by `bn_unguarded_cast` as a kill set |
| **FieldBoundedVar (G8)** FP-suppressor | `source_type_safety.dl` | A var sourced from a `BoundedField` read (e.g., struct field with known small range) — suppresses upstream unguarded-sink/cast findings | Requires `BoundedField` user-supplied annotation; nice-to-have |

These ride alongside the main rule ports — many will reduce existing bin_datalog FP rates.

---

## 4. Recommended import set (proposed)

Priority order — **for your review**. Nothing ports until you sign off.

### Tier 1 — port now, high confidence, low effort

1. **`bn_allocator_mismatch.dl`** ← `allocator_mismatch.dl` 🟢
2. **`bn_unbounded_sink_audit.dl`** ← `unbounded_sink_audit.dl` 🟢
3. **`bn_type_confusion.dl`** (PtrIntTruncation only initially) ← `type_confusion.dl` 🔵
4. **`bn_joint_buffer_bound.dl`** ← `joint_buffer_bound.dl` 🟢

### Tier 2 — port after adding small extractor facts

5. **`bn_leaky_exit.dl`** ← `lifecycle_audit.dl::LeakyExitPath` 🟡 *(needs `ReturnSite` fact)*
6. **`bn_unbounded_server_write.dl`** ← `unbounded_server_write.dl` 🟡 *(needs derived `GuardEarlyReturn`)*
7. **`bn_uninit_use.dl`** ← `uninit_var_use.dl` 🟡 *(needs `UninitDef` fact)*
8. **`bn_func_risk.dl`** ← `triage_ranker.dl` 🟡 *(pure rule, no new facts)*

### Tier 3 — port behind a user-supplied signature schema

9. **`bn_state_machine.dl`** ← `state_machine_invariants.dl` 🟡
10. **`bn_concurrent_uaf.dl`** ← `concurrent_uaf.dl` 🟡
11. **`bn_peek_in_loop.dl`** ← `nondestructive_peek_in_loop.dl` 🟡

### Tier 4 — FP-suppression sub-rules (small, high ROI)

12. **`bn_validating_cast.dl`** ← `source_type_safety.dl::ValidatingCast` 🟡
13. **UAF refinements** (`ReinitBetweenFreeAndUse`, `SafeWriteAfterFreeAndNull`) — fold into `patterns_mem.dl`

### Deferred to Phase 3 backlog — multi-week effort

14. **Field-sensitive alias** (FieldChainStep, ObjFieldPointsTo, MemcpyAlias) — required for `bn_single_writer_security.dl` and stronger `bn_state_machine.dl`
15. **`bn_missing_field_release.dl`** ← `lifecycle_audit.dl::MissingFieldRelease` (needs field-name availability + ResourceSlot signatures)

### Explicit non-ports

- All `source_*.dl` mechanisms (Group A): use SSA equivalents we already have.
- `schema.dl`, `alias.dl` (core), `signatures.dl`, `taint.dl`, `core.dl`, `summary.dl`, `interproc.dl`, `patterns.dl`, `patterns_mem.dl`: subsumed by our existing rules.
- `type_knowledge.dl`: source-type-KB; binary uses `VarSign` from DWARF instead.
- `debug_sink.dl`: debug only.
- `type_confusion.dl::IncompatibleStructCast` / `VoidPtrLaundering`: type-name strings unavailable on stripped binaries.

---

## 5. Decision points for you

Before any porting work begins:

1. **Are the four Tier-1 ports the right starting set?** (Highest confidence, smallest blast radius.)
2. **Are you OK adding `AllocFamily` / `FreeFamily` / `DangerousSink` extensions / `StateField` / `FlagStateBit` / etc. as user-supplied input relations?** These are decls only; the work of populating them is per-target.
3. **Is the small extractor work (emit `ReturnSite`, derive `GuardEarlyReturn`, emit `UninitDef`) worth doing now, or defer Tier 2?**
4. **Do we want field-sensitive alias in Phase 3 at all** — given the cost — or do we treat `single_writer_security_field`-class rules as out-of-scope until source-level NeuroLog catches those for us?
5. **Should I diff `signatures.dl` between the two repos and report any new library models NeuroLog has added that we lack?** (Separate, smaller follow-up task.)

Once you choose a Tier-1 subset, the next step is to write the four `.dl` files + one schema extension + a smoke run on the libxml2 corpus we already trust.
