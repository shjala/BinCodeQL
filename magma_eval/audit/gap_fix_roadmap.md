# Gap 1 + Gap 2 Fix Roadmap

**Context:** the libxml2 maintainer interaction (2026-05-04, GitLab
issue 1112) plus the entry-taint experiment
(`entry_taint_experiment.md`) decompose the methodological mistake
into two distinct, generic gaps. Both are addressable; their
complexity differs significantly.

## Gap 1 — Entry-point seeding

### Status today

`EntryTaint.facts` is empty in shipped runs; taint is seeded only by
`signatures.dl`'s libc-source heuristic. The libc heuristic is
correct (paths it reports are real) but origin labels are imprecise
(`external_via_fread` rather than `entry:main:arg1`).

### Generic fix: rule-based candidate enumeration + LLM refinement

**Step 1 (deterministic, shipped 2026-05-04):**
`rules/entry_candidates.dl` enumerates `EntryCandidate(func, idx, reason)`
where `reason` ∈ {`libc_input_caller`, `named_main`, `named_libfuzzer`,
`named_parser_api`}.

Empirical candidate counts:

| Binary | Total functions | Candidates | Rate |
|---|---:|---:|---:|
| xmllint (libxml2) | 3084 | 37 | 1.2% |
| tiffcp (libtiff)  | 1043 | 11 | 1.1% |

Tractable per-binary cost.

**Step 2 (LLM refinement, prompt template in
`prompts/entry_select.md`):** for each candidate, an agent reads the
function's HLIL plus its caller/callee context (other candidates) and
classifies it as `entry` / `internal` / `init-only` / `unreachable`.

The agent's job is the call-graph reasoning that picks the *root*
candidates: for a CLI binary like xmllint, only `main` is a true entry;
the public API (`xmlReadFile` etc.) is `internal` because main calls it.
For a library binary, every export with no internal candidate caller
is an `entry`.

**Step 3 (aggregation):** agent decisions become `EntryTaint.facts`
rows. Re-run taint pipeline. Origin labels are now properly
attributed.

### Cost per binary

- Datalog enumeration: seconds.
- Agent loop: ~37 candidates × ~3 KB context × DeepSeek pricing ≈ a few
  cents per binary. Parallelizable.
- Total wall: 5–15 minutes for a libxml2-scale binary.

### Validation

- Sanity check: post-EntryTaint reach percentage. If `entry:*`
  origins propagate to >50% of binary functions, the entry selection
  is too broad — fall back to a stricter subset (just `main`).
- Spot check: known-good entry chain (`main → xmlReadFile → parser`)
  should be reflected as `entry:main:arg1` propagation reaching the
  parser surface. The 2026-05-04 hand-picked experiment confirms this
  is the case for libxml2-vuln.

### Open questions

- How to handle stripped binaries (no `main` symbol)?
  Current fallback: leave EntryTaint empty and rely on libc-source
  heuristic — same noise floor as today.
- Library mode (libxml2.so without a wrapping CLI): every exported
  function is potentially an entry. Need an `Export.facts` relation
  from the extractor. Currently not emitted.
- Multi-tool binaries (e.g., a single ELF that's both `xmllint` and
  `xmlcatalog`): probably one EntryTaint set per tool, joined.

## Gap 2 — Constraint propagation

### Status today

Taint analysis is binary (yes/no on data flow). Length caps applied
along the flow path are not modeled. Per the libxml2 case, this is
the *dominant* missing piece for that bug class — Nick's correction
was at the constraint level, not the data-flow-path level.

### Sub-cases

**G2.a — Within-function or one-hop guards.** Shipped 2026-05-05 as
`rules/bn_guard_dominates.dl`. Block-level CFG dominance via
reach-skip characterisation, size-gated to <2000 edges/function.
Required fixing the legacy `CFGEdge` schema (it mixed instruction
addresses on the `from` side with basic-block *indices* on the `to`
side, making transitive closure incorrect): the extractor now also
emits `CFGBlockEdge(func, src_block_addr, dst_block_addr)` and
`BlockHead(func, instr_addr, block_addr)`, both with real
addresses.

Validated end-to-end on libxml2-vuln (xmllint, ~3K functions, full
extract → taint → Bn* pipeline, EntryTaint from the deterministic
entry-select run). On the documented `xmlSaveCtxtInit` FP, the loop
guard `i slt rax_19` at `0x55619f` correctly appears in
`GuardDominates` covering 27 downstream instructions (including the
post-loop write). Distinct call-site counts at MLIL addresses:

| Relation | Distinct (caller,callee,call_addr) |
|---|---:|
| `TaintedSink` (universe) | 83 |
| `GuardedSink` (legacy in-scope guard) | 81 |
| `BnGuardSubsumedSink` (CFG-dominance) | 77 |
| `BnUnguardedTaintedSink` (legacy unguarded) | 2 |
| `BnUnguardedDom` (dominance-aware unguarded) | 6 |

Net: dominance promotes 4 sites that the legacy in-scope check
suppressed but no guard *path-dominates*: `xmlBufferResize → memmove`,
`xmlBufResize → memmove`, `xmlRelaxNGCopyValidState → memcpy`,
`xmlSchemaDupVal → memcpy`. These are recovered findings that the
loose check was over-suppressing.

Outputs `Dominates`, `GuardDominates`, `BnGuardSubsumedSink`
(refined GuardedSink) and `BnUnguardedDom` (refined unguarded-sink).
Wired into the Bn* pipeline after `bn_null_deref.dl`. The
`GuardDominates` relation is also usable directly by the triage
agent for non-`TaintedSink` findings (e.g. `tainted_loop_bound`
suppression, the actual class the `xmlSaveCtxtInit` FP belongs to).

**G2.b — Multi-hop parser-side caps.** The libxml2
`xmlAutomataNewNegTrans` case: parser bounds string lengths 3–5 hops
upstream, on a different SSA variable. Requires either:

- (option B1) Pure-Datalog `EffectiveBound(unsafe_addr, var, op,
  bound)` derived by transitive `Flow × Guard` composition with
  cross-function stratification. Months of work; risk of blowup.
- (option B2) `ValueRange(f, v, ver, lo, hi)` with abstract-
  interpretation interval semantics. What CodeQL / Coverity do.
  Substantial engineering.
- (option B3) **LLM as constraint reasoner on demand**. Agent
  receives the data-flow chain plus all `Guard` rows in scope, asks:
  "is the unsafe op's operand bounded by any guard along this path?
  If so, by how much? Is the bound tight enough to prevent the
  structural overflow?" Per-finding cost, not at-scale. Fits the
  bootstrap-plus-reasoner architecture. **Recommended.**

### Recommended sequencing

| When | What | Effort | Effect |
|---|---|---|---|
| Now | G1 step 1 (Datalog enumeration) — done | half day | candidate lists generated for libxml2/libtiff |
| Now | G1 step 2 (agent prompt) — drafted | half day | spec ready to drive |
| Pre-paper | G1 step 3 (driver script + EntryTaint generation) | 1–2 days | proper origin labels in §6 figures |
| Pre-paper | G2.a `GuardDominates` within-function | 1–2 weeks | cross-validated FPs closed |
| Post-paper | G2.b option B3 (LLM constraint reasoner) | 1–2 weeks | libxml2-class cases handled |
| Post-paper | G2.b option B1/B2 (pure Datalog or AbsInt) | months | research contribution |

## Files in this iteration

- `rules/entry_candidates.dl` — Datalog candidate enumeration.
- `prompts/entry_select.md` — agent prompt template for per-candidate
  classification.
- `magma_eval/runs/<target>/entry_select/EntryCandidate.csv` — output
  of the Datalog rule, per-binary candidate list.

## What is *not* yet built

- ~~Driver script wiring `entry_candidates.dl` → agent loop →
  `EntryTaint.facts`.~~ **Built and run end-to-end (2026-05-04→05),
  results below.**
- `Export.facts` extraction from BN, for library-mode entry detection.
- `ValueRange` abstract-interpretation layer (G2.b option B2).

## End-to-end validation (2026-05-05)

We built and ran the driver against libxml2-vuln. Results:

**Driver components shipped:**
- `entry_select.py` — LLM-driven driver. Loads `EntryCandidate.csv`,
  fetches HLIL via `scripts/bn_decompile_funcs.py`, classifies each
  candidate via litellm → JSON, aggregates entries to
  `EntryTaint.facts`. Supports `--resume-from` for partial reruns.
- `entry_select_deterministic.py` — deterministic kernel of the same
  rules (named-main → entry, named-parser-API without candidate
  caller → entry, candidate-caller-exists → internal). Runs in
  seconds, no API calls. Optional `--llm-decisions` flag merges
  any prior LLM verdicts on `review`-flagged ambiguous cases.

**LLM run outcome:** of 37 candidates, 9 successfully classified
(all internal/init-only) before NVIDIA's free-tier endpoint began
persistently timing out (28/37 errors over a multi-hour retry
window). The 9 successful classifications matched the deterministic
rules exactly, confirming the driver's logic but blocked by provider
availability for completion. A paid endpoint (e.g., DeepSeek) or
parallel-batch mode would close the gap.

**Deterministic-only outcome:** 10 entries, 17 internal, 1
init-only, 9 review (ambiguous, would normally go to LLM):

```
EntryTaint.facts (10 rows, deterministic):
  main                    1
  xmlCtxtReadDoc          1
  xmlCtxtReadFd           1
  xmlParseMemory          0
  xmlReadDoc              0
  xmlReaderForDoc         0
  xmlReaderForFd          0
  xmlReaderForIO          0
  xmlSAXUserParseFile     2
  xmlSAXUserParseMemory   2
```

**Reach equivalence with the hand-picked baseline.** Re-running
`interproc.dl` with this auto-derived `EntryTaint` produces the
**identical 264 SSA instances** reached at `xmlAutomataNewNegTrans`,
just under different entry-attribution labels. Every entry origin
(`entry:main:arg1`, `entry:xmlReadDoc:arg0`,
`entry:xmlSAXUserParseFile:arg2`, …) propagates to the same 264
`(variable, SSA-version)` tuples that the hand-picked baseline
reached via its 7 origin labels. This is the empirical confirmation
that automated entry-selection reproduces the manual setup.

**Key insight from the deterministic run:** for a CLI binary like
xmllint, several public parser APIs (`xmlReadFile`, `xmlReadMemory`,
`xmlReadFd`, `xmlReadIO`, `xmlCtxtReadFile`) get classified as
`internal` because xmllint's own `parseAndPrintFile` calls them.
This is "binary-mode" reasoning — taint will propagate from
`main:argv` through `parseAndPrintFile` into them anyway, so
seeding at the API too would only duplicate origin labels (which the
empirical run confirms: identical 264 SSA instances). For
library-mode analysis (no main-rooted call graph), the same
deterministic rule with `pick_input_param` would treat them all as
entries.

**What this validates for §6.3 / §7:**
- The "Gap 1 is real but methodologically secondary" framing in the
  paper now has a stronger empirical leg: an automated entry
  selection produces the same reach as the hand-picked one, so the
  reachability *path* finding is a robust property of the call
  graph, not a quirk of the seeding choice. The remaining
  precision-decisive question is constraint propagation along the
  path (Gap 2).
- The artifact pipeline (`entry_candidates.dl` →
  `entry_select.py` / `entry_select_deterministic.py`) is
  reproducible and shipped. The LLM-driven version is provider-
  bottlenecked today but its driver is real and tested.
