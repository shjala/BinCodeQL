# Scaling roadmap — bin_datalog on arbitrary binaries

Date: 2026-05-22
Status: spec approved 2026-05-22 — implementation in progress (sprint scope in §7)
Driver: FFmpeg 8.0.1 eval triggered a `systemd-oomd` kill of the entire
terminal scope at 17:36 on 2026-05-21 (78% user-slice memory pressure
for >20s with reclaim activity). Souffle RSS climbed past 22 GB during
`bn_guard_dominates.dl` on 1.29 GB BnFlow + heavy CFG facts.

## 1. What we measured on FFmpeg 8.0.1 (224 / 299 funcs extracted)

| Relation | Rows | CSV size | Notes |
|---|---:|---:|---|
| `Def` | 162,102 | 6.5 MB | one-hop endpoint universe |
| `Use` | 319,456 | 12.6 MB | |
| `PhiSource` | 164,718 | 6.8 MB | |
| `BnFlow1` (1-hop) | 5,599,593 | 232 MB | 34× Def |
| **`BnFlow` (TC, hop-capped)** | **32,050,034** | **1.29 GB** | **200× Def** |
| `TaintedVar` | 643,854 | 49 MB | |
| `BnTaintedLoopBound` | 57,650 | 6.6 MB | overlooked blowup, see §4 |
| `BnPotentialArithOverflow` | 5,361 | 261 KB | |
| `Guard` | 11,229 | 611 KB | |
| `AllocSite` | 136 | 4 KB | |
| `ArithOp` | 15,747 | 976 KB | |
| `Cast` | 2,528 | 144 KB | |
| `ActualArg` | 9,853 | 219 KB | |

**Relevant-endpoint union (distinct `(func, var, ver)` tuples):**

| Source | Distinct endpoints |
|---|---:|
| `Guard.var` | 9,057 |
| `ArithOp.dst` ∪ `ArithOp.src` | ~22,000 |
| `Cast.dst` ∪ `Cast.src` | ~4,500 |
| `ActualArg.var` | 7,148 |
| `FormalParam.var` | 5,537 |
| `MemWriteSize.target` | 393 |
| `AllocSite.{size,result}` | 30 |
| **Union (estimated, ≤ sum)** | **~50,000** |
| Total Def universe | 162,102 |

→ Relevant fraction ≈ **31%** of Defs. Both src AND dst must be relevant
in `BnFlowRelevant`, so expected row reduction ≈ **0.3 × 0.3 ≈ 10×**
linear, with super-linear gain from TC fan-out collapse on irrelevant
intermediates.

## 2. Headline problem

`BnFlow` is materialized once (~1.29 GB) and then **re-loaded into RAM
by every one of the 13 Bn\* consumers**. That single relation, plus
each rule's own intermediate joins on it, is the dominant memory cost.
Souffle stores it as a btree with per-column indexes — measured RSS
~22 GB on bn_guard_dominates with full BnFlow.

### 2.1 Why scope alone doesn't fix this — architecture vs. slicing

Two independent dimensions drive memory cost:

| Dimension | Effect | Fix |
|---|---|---|
| **Architectural** — every rule re-loads full `BnFlow`; TC fanout through irrelevant intermediates | Dominant — doesn't shrink with smaller scope | `BnFlowRelevant` (§3) |
| **Scope** — total function count under analysis | Linear: 224 funcs vs 20 funcs ≈ 11× rows | per-subsystem sharding (§3.5) |

The architectural ceiling kicks in regardless of scope: even a 20-
function H.264-only run would still have every Bn* consumer re-loading
the (smaller but still re-loaded 13×) `BnFlow`. The architectural fix
addresses the *constant-multiplier* on every run; sharding addresses
the *absolute size* of any one run. They stack.

**`BnFlowRelevant` is the load-bearing change.** Sharding is a
complementary optimization the user can apply on top per-run when they
know what subsystem to focus on.

## 3. Tactical fix — `BnFlowRelevant` (anchored TC)

### 3.1 Definition

```souffle
// rules/bn_flow.dl

// New: union of every (func, var, ver) that any Bn* rule ever joins
// against BnFlow as either an LHS or RHS endpoint.
.decl RelevantEndpoint(func: Sym, var: Sym, ver: Ver)

// LHS roles (sources of flow we care about)
RelevantEndpoint(f, v, ver) :- Guard(f, _, v, ver, _, _, _).
RelevantEndpoint(f, v, ver) :- AllocSite(_, f, v, _, _, _, _).            // result ptr lives in Def(f, v, ver, _) implicitly
RelevantEndpoint(f, v, ver) :- Cast(f, _, v, ver, _, _, _, _, _).         // Cast.dst
RelevantEndpoint(f, v, ver) :- ArithOp(f, _, v, ver, _, _, _, _).         // ArithOp.dst
RelevantEndpoint(f, v, ver) :- FormalParam(f, v, _), Def(f, v, ver, _).   // pin to actual ver
RelevantEndpoint(f, v, ver) :- TaintedVar(f, v, ver, _, _).               // (only present once taint has run)

// RHS roles (destinations of flow we care about)
RelevantEndpoint(f, v, ver) :- Cast(f, _, _, _, v, ver, _, _, _).         // Cast.src
RelevantEndpoint(f, v, ver) :- ArithOp(f, _, _, _, _, v, ver, _).         // ArithOp.src
RelevantEndpoint(f, v, ver) :- ActualArg(ca, _, _, v, ver), Call(f, _, ca).
RelevantEndpoint(f, v, ver) :- MemWriteSize(f, a, _), Def(f, v, ver, a).
RelevantEndpoint(f, v, ver) :- AllocSite(_, f, _, _, v, ver, _).          // size_var

// Safety-net inclusions — captured by §3.4 audit pass, listed here
// so the relation is sound on day one.
// MemWrite.target (e.g. bn_sentinel_init RHS — distinct from MemWriteSize.target)
RelevantEndpoint(f, v, ver) :- MemWrite(f, _, v, _, _), Def(f, v, ver, _).
// AddressOf endpoints (for &var → ptr chains; used by alias-derived UAF rules)
RelevantEndpoint(f, v, ver) :- AddressOf(f, v, ver, _).
RelevantEndpoint(f, v, ver) :- AddressOf(f, _, _, v), Def(f, v, ver, _).
// Jump operands — covers bn_loop_bound RHS where the loop-bound var
// is whatever appears in a Jump's compare expression. Conservative
// (any Use at a Jump-bearing addr) so chains aren't lost.
RelevantEndpoint(f, v, ver) :- Jump(f, a, _), Use(f, v, ver, a).
// TaintedSink.tainted_var (subset of TaintedVar but make the role explicit)
RelevantEndpoint(f, v, ver) :- TaintedSink(f, _, _, _, v, _, _),
                               Def(f, v, ver, _).

// Anchored hop-counted TC: start only from relevant sources, but allow
// transit through irrelevant intermediates (because real chains often
// hop through copies). Final projection prunes to relevant→relevant.

.decl BnFlowH_anchored(func: Sym, src_var: Sym, src_ver: Ver,
                       dst_var: Sym, dst_ver: Ver, hops: Hops)

BnFlowH_anchored(f, sv, sver, dv, dver, 1) :-
    BnFlow1(f, sv, sver, dv, dver),
    RelevantEndpoint(f, sv, sver),
    !FuncIsLarge(f).

BnFlowH_anchored(f, sv, sver, dv, dver, h2) :-
    BnFlowH_anchored(f, sv, sver, mid, mver, h1),
    h1 < MAX_HOPS,
    BnFlow1(f, mid, mver, dv, dver),
    h2 = h1 + 1,
    (sv != dv ; sver != dver).

.decl BnFlowRelevant(func: Sym, src_var: Sym, src_ver: Ver,
                     dst_var: Sym, dst_ver: Ver)
.output BnFlowRelevant

// Identity for relevant endpoints (matches uniform pattern).
BnFlowRelevant(f, v, ver, v, ver) :- RelevantEndpoint(f, v, ver).

// Multi-hop, both endpoints relevant.
BnFlowRelevant(f, sv, sver, dv, dver) :-
    BnFlowH_anchored(f, sv, sver, dv, dver, _),
    RelevantEndpoint(f, dv, dver).

// One-hop for large functions (parallel structure to current BnFlow).
BnFlowRelevant(f, sv, sver, dv, dver) :-
    BnFlow1(f, sv, sver, dv, dver),
    FuncIsLarge(f),
    RelevantEndpoint(f, sv, sver),
    RelevantEndpoint(f, dv, dver).
```

### 3.2 Consumer switchover (13 rule files)

In every Bn* consumer:
- Replace `.input BnFlow` with `.input BnFlowRelevant`
- Rename in-rule join from `BnFlow(...)` → `BnFlowRelevant(...)`

The semantics are preserved **only if every join endpoint is in
`RelevantEndpoint`**. I verified this for all 13 consumers:

| Rule | LHS bind | RHS bind | Both endpoints in `RelevantEndpoint`? |
|---|---|---|---|
| `bn_alloc_copy` | AllocSite result | ActualArg / MemWrite target | ✅ |
| `bn_arith_overflow` | Guard / ArithOp.dst | ArithOp.src / ActualArg | ✅ |
| `bn_counter_oob` | ArithOp.dst (counter) | ActualArg (sink arg) | ✅ |
| `bn_loop_bound` | TaintedVar | Jump cmp operand (`Guard.var` proxy) | ⚠️ need to add Jump operands to relevant set if loop-bound is jump-keyed |
| `bn_unguarded_cast` | Guard | Cast.src | ✅ |
| `bn_width_mismatch` | AllocSite | MemWriteSize target | ✅ |
| `bn_sentinel_init` | AllocSite | MemWrite target | ✅ |
| `bn_allocator_mismatch` | AllocSite result | FreeCall arg (= ActualArg) | ✅ |
| `bn_unbounded_sink_audit` | FormalParam | ActualArg into dangerous sink | ✅ |
| `bn_joint_buffer_bound` | Guard | AllocSite.size_var / sink size arg | ✅ |
| `bn_type_confusion` | Cast.dst | Cast.src | ✅ |
| `bn_guard_dominates` | Guard | TaintedSink.tainted_var | ✅ (TaintedSink ⊂ TaintedVar) |
| `bn_findings` | Guard | rule output vars | ✅ |

One open question is `bn_loop_bound` (it joins onto whatever variable
the Jump's compare uses). Add a precaution to the relevant set:

```souffle
// loop-bound destinations
RelevantEndpoint(f, v, ver) :- Jump(f, _, _), Use(f, v, ver, _).
```

This is conservative — slightly inflates the relevant set, but
guarantees no flow chains are lost.

### 3.3 Two-tier rollout

**Phase 1 (1–2 days):** Add `RelevantEndpoint` + `BnFlowRelevant` to
`bn_flow.dl` as an **additive** output. Keep `BnFlow` in place. Stage
both into facts/. This lets us A/B compare on FFmpeg without breaking
any consumer.

**Phase 2 (1 day):** Switch all 13 consumers to `BnFlowRelevant`.
Re-run on FFmpeg, libxml2, libtiff to confirm finding-set parity
(row-count delta within ±5% per Bn* output). If parity holds, retire
`BnFlow` and `BnFlow1` from `.output` (still computed in-rule, not
staged to disk).

### 3.4 False-negative defenses

`BnFlowRelevant` is conservative *only if every endpoint role a Bn\*
rule ever joins against is in `RelevantEndpoint`*. The TC itself is
not lossy — `BnFlowH_anchored` transits through irrelevant
intermediates without filtering them, so chains like `Guard.var →
tmp1 → tmp2 → ActualArg` complete even when `tmp1`/`tmp2` aren't
relevant. **All FN risk comes from missing endpoint roles**, not from
the anchored TC.

Three layered defenses:

**D1 — endpoint coverage audit (mechanical).**
Add `scripts/audit_bnflow_coverage.py` (runs as a `pytest` check):

  1. Walk every `rules/bn_*.dl` file.
  2. Parse every `BnFlow(...)` / `BnFlowRelevant(...)` literal, extract
     the bound variables in positions 2,3 (src) and 4,5 (dst).
  3. Trace each bound variable back through other join atoms in the
     same clause head to find the *source fact* it derives from
     (e.g., `Guard(f, _, v, ver, _, _, _)` → role = `Guard.var`).
  4. Assert each role appears in `RelevantEndpoint`'s definition body.
  5. Fail the build if any role is uncovered.

This catches both today's gaps and any future rule that joins against
an unannounced endpoint role.

**D2 — A/B parity gate (empirical).**
During the additive rollout (§3.5 sequencing), every Bn\* rule runs
twice — once over `BnFlow` and once over `BnFlowRelevant` — and a
harness asserts:

```
|out_via_BnFlowRelevant - out_via_BnFlow| / |out_via_BnFlow| < 0.05
```

Run on FFmpeg + libxml2 + libtiff. The switchover only lands if every
rule's parity check passes. If a rule's count drops more than 5%, the
delta is dumped (set difference of finding tuples), the missing
endpoint role is identified, and `RelevantEndpoint` is extended.

**D3 — backward compatibility window.**
`BnFlow` stays staged for one full sprint after the switchover. If a
production scan misses a known-good finding, a one-line per-rule
override flips it back to `.input BnFlow` until the underlying gap is
fixed.

### 3.5 Complementary: per-subsystem sharding

Independent of `BnFlowRelevant`. Run the pipeline N times over disjoint
function subsets (one per subsystem), union the findings. Both fixes
stack.

**Why this works for our pipeline specifically:**
- Every fact relation is keyed by `func` as its first column.
- Every Bn\* rule joins are intraprocedural (the `func` column flows
  through every body atom).
- `BnFlow` is intraprocedural by construction.
- Findings are emitted per-(func, addr) — union across shards is a
  cat without conflict.

**Implementation:**
- `scripts/shard_targets.py` partitions `targets.txt` into subsystem
  shards by name prefix (heuristic that works for FFmpeg's
  prefix-naming convention):

  ```
  mov_*, mp4_*, mxf_*       → shard "container_iso"
  mpegts_*, asf_*, flv_*    → shard "container_streaming"
  ff_h264_*, h264_*         → shard "h264"
  ff_hevc_*, hevc_*         → shard "hevc"
  matroska_*, mkv_*         → shard "matroska"
  ff_aac_*, ff_ac3_*, ff_dca_*, ff_opus_*, ff_flac_*, ff_vorbis_* → shard "audio"
  *                          → shard "misc"
  ```

- `scan.py --shard <name>` extracts facts + runs pipeline against the
  shard's function subset.
- Findings union: `cat shards/*/output/BnFinding.csv | sort -u`.

**Expected per-shard scale on FFmpeg:**

| Shard | Func count | Projected BnFlow rows | Peak RSS (with BnFlowRelevant) |
|---|---:|---:|---:|
| `mov_*`    | ~40 | ~5M | < 2 GB |
| `mpegts_*` | ~10 | ~1M | < 1 GB |
| `h264_*`   | ~20 | ~3M | < 2 GB |
| `hevc_*`   | ~10 | ~1M | < 1 GB |
| `audio_*`  | ~30 | ~3M | < 2 GB |
| `misc`     | ~80 | ~8M | < 3 GB |

Each shard finishes in 3–5 min. Total pipeline (run serially) ~20 min,
or fully parallel ~5 min if disk I/O cooperates.

**When to use:** for an arbitrary, unfamiliar binary, run the full
pipeline once over the whole target set after `BnFlowRelevant` is
deployed. Use sharding when (a) the binary is very large, (b) only
one subsystem is interesting, or (c) memory budget is tight (laptop /
shared dev box).

### 3.6 Expected wins (combined)

| Metric | Current | After §3.1–§3.4 (`BnFlowRelevant`) | After §3.5 (+ sharding by 5–6 ways) |
|---|---:|---:|---:|
| BnFlow*.facts on disk (per run) | 1.29 GB | 100–150 MB | 20–30 MB per shard |
| Peak Souffle RSS (`bn_guard_dominates`) | 22 GB | 3–5 GB | < 2 GB per shard |
| Wall-time, `bn_flow.dl` | ~20 min | 5–8 min | 1–2 min per shard |
| Wall-time, downstream Bn* rules | 6 min total | 1–2 min total | ~30 s per shard |
| End-to-end pipeline (after taint) | ~28 min, OOM-prone | 10–15 min, stable | 5–8 min wall, fully parallel |

## 4. Other scaling concerns surfaced during this audit

These are **deferred** (logged here so they're not forgotten):

### 4.1 `BnTaintedLoopBound` blowup (57K rows / 6.6 MB)

For 412 TaintedSinks we emit 57K loop-bound joinings — ~140× row
amplification. Likely a missing distinct-projection in `bn_loop_bound.dl`.
**Action**: add a `BnTaintedLoopBoundSite` compact projection
(func, addr, loop_bound_var) so downstream consumes the de-duplicated
form. Pattern mirrors the `BnJointBufferBoundSite` fix from 2026-05-21.

### 4.2 Interproc.dl TC sizing

The `TaintedVar` relation reaches 643,854 rows on FFmpeg (with
1-CFA context tag). That's heavy but not catastrophic — the
size-gated two-tier from 2026-04-27 (`project_interproc_scaling`) is
working. Memory hot spot inside taint pipeline is `Pass2` — currently
runs in interpreter mode at 2400s on FFmpeg. **Action**: add
`TaintedVar` early-prune via the same `RelevantEndpoint` set —
only need TaintedVar for vars that hit a sink/cast/arith. Could
prune ~80% of taint rows.

### 4.3 Per-pass timeout policy

Current per-pass timeout is 1800s in `run_bn_extra_rules`. On large
binaries, bn_guard_dominates can exceed that. **Action**: make the
timeout adaptive — pass-specific defaults, with one-line override
in the rule list (e.g. `("bn_guard_dominates.dl", 3600)`).

### 4.4 `jobs=auto` is wrong for memory-bound passes — LANDING IN THIS SPRINT

Souffle's parallel evaluation duplicates per-stratum caches across
threads. For memory-heavy passes (`bn_guard_dominates`, `bn_flow`,
`interproc`) the parallel speedup is <2× while peak RSS multiplies by
N_threads. **Action**: per-rule `jobs` policy:

```python
_BN_RULE_JOBS = {
    "bn_flow.dl":             "auto",   # CPU-bound TC, parallelizes well
    "bn_guard_dominates.dl":  "1",      # memory-bound, parallel = OOM
    "bn_findings.dl":         "auto",
    # default: auto
}
```

### 4.5 Staging copy cost — LANDING IN THIS SPRINT

`run_bn_extra_rules` copies every Bn* output CSV back to
`facts_dir/*.facts` between passes via `Path.write_text(Path.read_text())`.
For BnFlow's 1.29 GB this is a full read+write — ~5–10 seconds + memory
spike. **Action**: hard-link or `os.symlink` instead of copy. Souffle
treats `.facts` as read-only input, so symlinks are safe.

### 4.6 Extractor scalability — separate sprint

Not in scope of this doc but flagged: `bn_extract_facts.py` walks every
function in series under a single BN headless process. For FFmpeg
(>10K functions in the full binary) this is the long pole. Two paths:

- **Per-function batching with worker pool** — extract N functions
  per BN subprocess, parallelize across cores. Likely 4–6× speedup.
- **Incremental extraction with .bndb caching** — re-use BN's analysis
  database; only re-extract functions whose code or signatures changed.
  Useful for iterative scan workflows.

## 5. Verification plan

After Phase 1 lands (additive `BnFlowRelevant`):

1. **Row-parity smoke** on FFmpeg-vuln-eval: for every Bn* output,
   verify `|output(via BnFlow)| - |output(via BnFlowRelevant)| / |output| < 5%`.
2. **Memory smoke**: run `bn_guard_dominates.dl` with `BnFlowRelevant`,
   confirm peak Souffle RSS < 6 GB on FFmpeg.
3. **Wall-time smoke**: total Bn* pipeline finishes < 10 min on
   FFmpeg (vs the 6 min for Tier-1 only + uncompleted bn_guard_dominates
   at 14+ min OOM-killed).
4. **Cross-binary**: re-run libxml2-vuln + libtiff regression set,
   confirm finding-set parity with 2026-05-03 audit results.

## 6. Decision gates

| Gate | Decision needed | Decision |
|---|---|---|
| G1 | Approve `RelevantEndpoint` definition in §3.1 (incl. safety-net additions for MemWrite, AddressOf, Jump, TaintedSink) | **APPROVED** 2026-05-22 |
| G2 | Rollout: additive A/B vs hard switch | **A/B** (§3.4 D2 parity gate enforces ≤5% delta) |
| G3 | Fold §4.2 (`TaintedVar` prune via RelevantEndpoint) into this sprint | **DEFERRED** — separate spike |
| G4 | Per-rule `jobs` policy (§4.4) | **IN THIS SPRINT** |
| G5 | Symlink staging (§4.5) | **IN THIS SPRINT** |
| G6 | §3.5 per-subsystem sharding | **IN THIS SPRINT** (sharding harness; not mandatory for FFmpeg eval once `BnFlowRelevant` lands) |
| G7 | §3.4 D1 coverage audit script | **IN THIS SPRINT** as pytest check |

## 7. Sprint scope (this implementation)

In scope:
- §3.1–§3.3 — `BnFlowRelevant` + 13-consumer A/B switchover
- §3.4 D1 — `scripts/audit_bnflow_coverage.py` + pytest hook
- §3.4 D2 — A/B parity harness (`scripts/bnflow_parity_check.py`)
- §3.5 — `scripts/shard_targets.py` and `scan.py --shard <name>` flag
- §4.4 — `_BN_RULE_JOBS` per-rule jobs policy in `pipeline.py`
- §4.5 — symlink-based staging in `run_bn_extra_rules`

Out of scope (deferred):
- §4.1 (`BnTaintedLoopBound` Site projection)
- §4.2 (TaintedVar prune)
- §4.3 (adaptive timeouts)
- §4.6 (extractor parallelism)
