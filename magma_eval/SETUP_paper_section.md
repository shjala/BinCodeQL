# BinCodeQL — Magma evaluation setup (paper §6.1)

This section documents the dataset, target selection, and evaluation
configurations behind the results in §6.2 (`RESULTS_paper_section.md`).

## 6.1.1 Why Magma?

Magma [Hazimeh et al., USENIX Security '21] is a fuzzing benchmark
that re-introduces *known* CVE-class memory-safety bugs into modern
versions of widely-used C/C++ libraries. We chose Magma over alternative
benchmarks (Juliet, Lava-M, OSS-Fuzz corpus) for four reasons that
directly map to the requirements of static binary analysis:

1. **Two-variant ground truth.** Each bug ships with a *vuln* binary
   (canary inserted) and a *patched* binary (upstream fix applied).
   This dual-build structure lets us measure not just recall on
   known-buggy functions but also *patch sensitivity* — does the
   pipeline distinguish a vulnerable build from its fixed counterpart?
   Other binary-bug benchmarks (LAVA-M, Juliet) provide only the
   buggy variant, making patch-aware ablation impossible.

2. **Reachability ground truth.** Magma's canaries are
   `MAGMA_LOG("%MAGMA_BUG%", <trigger_condition>)` calls embedded at
   the bug-trigger site. The trigger condition is a Boolean expression
   over function-local state that *must* hold for the bug to fire.
   This is the closest the literature gets to a checkable
   reachability oracle for binary static analysis: the ground truth
   describes not just "function X has a bug" but the precise local
   precondition under which that bug becomes reachable. We use the
   trigger conditions to verify that our pipeline's "confirmed"
   verdicts cite reasoning that's at least *consistent* with the
   intended trigger (not a different defect in the same function).

3. **Bug context the static analyzer can't observe.** Unlike fuzzing,
   static analysis can't observe a crash. A vulnerability detector
   has to *predict* whether a sink is unsafe — and that prediction
   needs the *same* triggering context the fuzzer would otherwise
   expose. Magma documents that context (in `bugs.json` and the
   inserted canary), letting us assess whether the pipeline's
   reasoning aligns with what an actual exploit input would do.

4. **Real-world scale and recognition.** The Magma targets are real
   maintained codebases (libtiff, libxml2, libpng, openssl, php,
   sqlite3, poppler, lua) with large, irregular control flow,
   non-trivial heap management, and indirect dispatch through
   function pointers — the same structural traits that defeat
   simpler benchmarks. Magma is the de-facto standard for fuzzer
   evaluation, which makes a binary-static-analysis result on the
   same dataset directly comparable to the fuzzing literature.

We use the released magma commit pinned in our `bugs.json`
manifest. The ground-truth function locations (start address,
end address, size) and the bug-id lists are produced by our
`magma_eval/build_manifest.py` from a clean build of each target;
we have separately verified (`verify_ground_truth.py`) that the
manifest's function set matches the symbols in the compiled binary
for all 31 catalogued bugs across libtiff and libxml2.

## 6.1.2 Target selection: libtiff and libxml2

We evaluate on two targets — **libtiff** (binary image format) and
**libxml2** (text-based markup parser). The pair is deliberate:

- **libtiff** exercises the binary-parsing failure modes: integer
  overflows in size computations (TIF001), unsigned-narrowed counters
  in pixel decoders (TIF002–TIF014), missing-bound checks on
  attacker-controlled tag arrays. This is where Bn*'s
  `unbounded_counter` / `width_mismatch_counter` /
  `tainted_counter_as_index` rules earn their keep.

- **libxml2** exercises text-parsing failure modes: tainted-loop-bound
  buffer overruns in entity decoders, unguarded sign-extensions of
  signed-int return codes, alloc-then-copy mismatches in
  `xmlStrncat`/`xmlStrncatNew`. The structural shapes are different
  enough from libtiff's that the same Bn* rules must generalize, not
  just memorize one binary's idioms.

The two targets share the property of being **large, complex,
real-world codebases** (libtiff: 1043 functions extracted, ~440k
facts; libxml2: 2977 functions, ~1.5M facts) with active CVE
histories. This makes them representative of the production-scale
binaries that motivated this work, while keeping the corpus small
enough to triage exhaustively under our budget.

### Limitations: why only two targets

The Magma benchmark covers eight targets. We restricted to two for
two reasons:

- **Hardware**: Souffle's interprocedural taint pipeline (`interproc.dl`
  Pass 2) materializes a transitive closure that scales as
  ~O(|Use|·|Def|·k) per function. On libxml2 (the larger of our two
  targets) this consumes ~10 GB RAM and ~21 minutes of wall time on
  a 2-core souffle invocation. The remaining Magma targets
  (openssl, php, sqlite3, poppler, lua) are larger still; we estimate
  4–8× the per-binary cost. We did not have access to a machine with
  the headroom to run all eight in our evaluation window.

- **API budget**: Each Datalog+LLM triage candidate consumes ~$0.012
  on DeepSeek v4-flash. Across the full 8-target Magma suite the
  per-binary candidate count grows roughly linearly with function
  count (libxml2-vuln: 133 deduped candidates on ~3000 fns), so the
  full 8-target sweep would be ~5–10× our 4-binary cost (~$25–60).
  This was not a hard ceiling but a discretionary one — given that
  the result on two complementary targets already supports the
  paper's headline claim, we prioritized depth (per-fn analysis,
  vuln-vs-patched diff, LLM-only ablation) over breadth.

The two targets are sufficient to demonstrate the +53pp recall delta
from §6.2; we believe the result generalizes but explicitly do not
claim it does without the missing measurements. Replicating the
remaining six targets is a near-term follow-up.

## 6.1.3 Evaluation configurations

We compare two pipelines, both using the same model and the same
50-function eval set per binary. The eval set is sampled from each
target's bugs.json: all functions with ≥1 catalogued bug
(`buggy_present`), padded to 50 with same-binary functions that have
no canary (`negatives`).

### Configuration A — Datalog+LLM (this work)

**Phase 1: Fact extraction.** Headless Binary Ninja runs over the
target binary and emits ~15 fact relations (Def, Use, Call,
ActualArg, MemRead, MemWrite, ArithOp, Cast, Guard, AllocSite,
PointsTo seed, …) into `.facts` files. We extract for *all*
functions in the binary (extract-all mode), so taint can propagate
from libc sources at the entry-point through the full call graph.

**Phase 2: Library signature staging.** A small Souffle program
(`signatures.dl`) declares ~110 `TaintTransfer` rules for libc and
target-specific functions (memcpy, fread, mmap, getopt,
xmlStrncat, png_read_data, …) plus 13 `BufferWriteSource` and 6
`TaintKill` (sanitizer) entries. The output is staged as `.facts`
so downstream Datalog can read it via `.input`. This step was
overlooked in earlier scan-mode runs and was the single largest
correctness fix in the project; without it `TaintedVar = ∅` because
no taint can be seeded from libc reads.

**Phase 3: Taint pipeline.** `alias.dl` (Andersen-style points-to)
followed by `interproc.dl` (1-CFA context-sensitive interprocedural
taint with TaintKill modeling and Guard detection). On libtiff this
produces 211k `TaintedVar` rows; on libxml2 ~10.5M. The 1-CFA
context blowup on libxml2 is the bottleneck of the entire pipeline.

**Phase 4: Bn\* vulnerability rules.** 11 Souffle rule files
(`bn_*.dl`) ported from NeuroLog's source-level rule set
(unbounded counter / counter-as-index / alloc-copy mismatch /
unguarded sink / unguarded cast / narrow-arith overflow /
width-mismatch store / sentinel collision / null deref) emit
candidate findings as `BnFinding(func, addr, severity, category,
var, detail)`.

**Phase 5: Triage agent.** For each `(func, category)` candidate
(deduped to the lowest-addr representative per class), an ADK
agent loads the function's MLIL-SSA and a bounded slice of the
fact tables relevant to the category, then composes ad-hoc
Souffle queries to verify the candidate. The agent has tools to:
read fact rows, run Datalog snippets against the staged facts,
trace TaintedVar back to its source, and read decompilation. The
agent emits a JSON verdict: `{verdict, confidence, reasoning,
evidence_cited[]}`.

The triage prompt instructs the agent to cite specific
fact rows for every claim and to mark a finding `false_positive`
unless it can construct a concrete reachability chain from an
external input source (mmap/read/argv/fread/getopt) to the
unsafe operation. The full prompt is in `magma_eval/triage_*.md`.

### Configuration B — LLM-only baseline (no Datalog)

To isolate the contribution of the Datalog scaffolding, we run an
LLM-only ablation using the *same model* (DeepSeek v4-flash), the
*same eval set* (50 fns per binary), and a *structurally similar*
prompt — but with no Datalog candidates and no Datalog tools. For
each function we feed:

- Binary Ninja HLIL pretty-print of the function body
- Caller list (incl. function-pointer xrefs from BN's
  `get_code_refs`)
- Direct callee list (from BN's `function.callees`)
- A single text instruction:

> *"You are a binary security analyst. Identify any
> memory-safety bugs in this function (buffer overflow, OOB,
> UAF, integer overflow, missing null/bound check, …) that
> are reachable from external input. Reachability rule: a bug
> is reachable only if you can identify a plausible chain
> from an external source (file content, network, argv) to
> the unsafe operation. If you cannot construct a concrete
> chain, say "false_positive" — do not speculate."*

The output schema mirrors Configuration A's verdict
(verdict / confidence / bug_type / reasoning / reachability_chain).
This is exactly the workflow that an analyst using a frontier LLM
"as a bug-finder" would use today; it represents the strongest
plausible LLM-only baseline available without re-architecting the
pipeline. The driver is `magma_eval/triage_no_datalog.py`.

### Why the prompts are not identical

We deliberately do *not* try to match the Datalog+LLM prompt
verbatim in the LLM-only run. The Datalog+LLM prompt references
specific Bn* candidates and Datalog evidence ("evidence_cited
must include `TaintedVar` and `Guard` rows from the staged facts");
those references are meaningless without the underlying
infrastructure, so handing them to the LLM-only baseline would
either (a) cause the model to hallucinate fact rows or (b) require
us to install the Datalog runtime alongside the LLM-only baseline
— at which point it's no longer "LLM-only."

The two prompts share the same *contract* — single JSON verdict,
explicit reachability requirement, conservative `false_positive`
default — but each instantiates that contract against the
infrastructure available to it. The +53pp recall delta is therefore
a faithful comparison of "LLM with Datalog scaffolding" vs "LLM
alone," not a comparison of two different prompt-engineering
strategies.

## 6.1.4 Verdict scoring

We score at the **function granularity**, not the candidate
granularity, because magma's ground truth is per-function (each
bug entry in `bugs.json` names a function and a single trigger
location). A buggy function counts as a true positive if the
pipeline produces *at least one* `confirmed` verdict on any
candidate within that function. This is consistent with the
"first hit wins" interpretation used in CodeQL/Joern evaluations
and avoids penalizing the Datalog+LLM pipeline for its multiple
categories per function (the agent triages each category
independently; one confirm anywhere in the function is sufficient).

For precision we report `confirmed-on-eval-set-negatives`: the
count of functions in the `negatives` bucket (`bug_ids = []`) that
received at least one `confirmed` verdict. This is an upper bound
on FP rate — some of those negatives are likely real-but-uncatalogued
bugs (Magma's bugs.json is not exhaustive); the cross-validation
between Datalog+LLM and the LLM-only baseline (§6.2 "novel-finding
candidates") provides one way to disambiguate.

## 6.1.5 Reproducibility

All artifacts are persisted on disk:

- Per-candidate verdicts: `magma_eval/runs/<binary>/verdicts/*.json`
  (Datalog+LLM) and `verdicts_no_datalog/*.json` (LLM-only).
- Each verdict file includes the full agent reasoning, the prompt
  hash, the cited evidence rows, and wall-time / token usage.
- The fact extraction is fully deterministic given the binary and
  the BN version pinned in `bn_utils.py`.
- The Datalog rule files are committed; Souffle is deterministic
  on a fixed input.
- The model is non-deterministic (the agent's verdict can vary
  across runs); we report single-shot results and mark the
  vuln-vs-patched verdict-pair diff as containing single-shot
  variance (§6.2.5). Multi-run voting is a near-term follow-up.

The full pipeline can be re-run from a clean checkout via:

```
# Datalog+LLM
python3 magma_eval/eval_one.py <target> <variant> \
    --profile deepseek --extract-all --triage-concurrency 4

# LLM-only baseline
python3 magma_eval/triage_no_datalog.py <target> <variant> \
    --profile deepseek --concurrency 4
```

See `RESULTS_paper_section.md` for §6.2 numerical results.
