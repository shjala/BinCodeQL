# Score-7 Triage Results — libxml2-vuln (xmllint)

**Date:** 2026-05-06
**Run dir:** `magma_eval/runs/libxml2-vuln-dom/` (uncommitted; per-run pattern)
**Pipeline:** full extract → taint → Bn* → bn_guard_dominates → bn_findings → bn_findings_rank
**Triage profile:** `magma_eval/.env.eval.deepseek` (v4-flash, no thinking, concurrency 8)
**Candidate set:** 121 cluster heads with `BnFindingScore.score >= 7` (top
sink-coupled tainted findings; see `bn_findings_rank.dl`).

## Verdict distribution

| Verdict | n | % |
|---|---:|---:|
| Confirmed | 60 | 52% |
| False-positive | 54 | 47% |
| Needs more info | 1 | 1% |
| **Total** | 115 | (6 timed out / no_verdict) |

Confidence: 95 high, 20 medium.

## Per-category yield

| Category | TP-rate | n | dom-cited |
|---|---:|---:|---:|
| `unguarded_tainted_sink` | 100% | 2 | 0% |
| `tainted_unbounded_counter` | 86% | 14 | 43% |
| `tainted_overflow_at_sink` | 51% | 57 | 9% |
| `tainted_counter_as_index` | 40% | 42 | 67% |

The `tainted_counter_as_index` line is striking: the lowest TP-rate
class is also the highest dom-cited class — meaning step 4a's
dom-guard signal is doing the most work where it's most needed
(refuting array-index findings whose loop bound dominates the index
op).

## Step 4a (CFG-dominating guard) impact

- 39/115 verdicts (34%) cited `BnFindingDomGuarded` / `GuardDominates`.
- 23 of those 39 → `false_positive` (59% — strong refutation signal).
- 15 of those 39 → `confirmed` (LLM correctly judged the
  dominating guard was loose / symbolic — the methodology's intended
  caveat-handling).
- 1 → `needs_more_info`.

Validates step 4a's design: the dom-guard relation is *evidence*, not
a hard suppressor. The LLM judges whether the bound is tight enough
for the bug class.

## Cost & wall-time per verdict

- Mean elapsed: **1,374s** (~23 min) per verdict (multi-turn agent).
- Median: 1,285s; p90: 2,271s; max: 3,312s.
- Total worker-time: **43.5 h** (5.5 h wall at concurrency 8).
- 6 verdicts hit the per-call timeout and produced no_verdict.

This is the cost ceiling: full agentic triage with tool-use loop.
Each finding burns 30-100K input tokens and 5-20K output tokens
across an average of ~10 tool turns.

## Implication for production deployment

This run is the **evaluation cost** — used to validate the rule set
+ step 4a methodology end-to-end. **Not the per-binary deployment
cost.** No realistic security-tool budget runs 5-6 hours and ~$10
per binary on every scan.

Practical deployment requires a tier above the agent:

- **Tier 0** — Auto-classify in pure Datalog (definitive FP for
  tight-bound dom-guards covering type range; definitive
  TP-likely for sink-coupled tainted with no guard).
- **Tier 1** — Single-shot LLM verdict on pre-packaged evidence.
  No tool loop. ~10-30s, ~$0.001/finding. Validate against this
  agentic baseline.
- **Tier 2** — Agentic deep-dive only on Tier 1 escalations or
  auditor-flagged findings. Bounded by user attention.

The agentic mode (this run) becomes the reference implementation
the cheaper tiers calibrate against. The 115-verdict dataset here
is the labeled set for that calibration.

## Files (uncommitted, per-run)

- `verdicts/*.json` — 115 verdict records with `evidence_cited`
- `triage_summary.json` — per-finding status + elapsed
- `triage_full.log` — driver output
- `candidates.json` — score-7 input set (= `candidates_score7.json`)
