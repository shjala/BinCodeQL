#!/usr/bin/env python3
"""Tier-1 single-shot triage — bypasses the ADK agent loop.

Pre-packages all relevant evidence in Python and asks the LLM for one
structured verdict per finding. ~30s and ~$0.001 per finding on
DeepSeek flash, vs ~23min and ~$0.05 with the agentic triage_agent.

Design (per the 2026-05-06 evaluation roadmap):
- Tier 0 (auto-classify in pure Datalog) — separate rule, not here.
- Tier 1 (this script) — single LLM call per finding.
- Tier 2 (existing triage_agent.py) — agentic deep-dive on Tier 1
  escalations and auditor-flagged findings.

Inputs match triage.py:
    --scan-out  scan output dir with candidates.json + facts/ + souffle_out/
    --limit     N — triage first N findings (smoke testing)
    --concurrency / -j  parallel LLM calls (default 8)
    --candidate-id  triage one specific finding

Output: <scan-out>/verdicts_oneshot/<id-slug>.json — same schema as
triage_agent verdicts so head-to-head comparison is trivial.

Cost model assumes flash; tune MODEL_NAME via the same .env profiles
that triage.py honours (BINCODEQL_PROFILE_ENV).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).parent.resolve()
load_dotenv(ROOT / ".env", override=True)
_profile = os.getenv("BINCODEQL_PROFILE_ENV")
if _profile and Path(_profile).is_file():
    load_dotenv(_profile, override=True)

import litellm  # noqa: E402

import evidence  # noqa: E402

DEFAULT_CONCURRENCY = 8
RELATION_HINTS_BY_CATEGORY = {
    "tainted_unbounded_counter":  ["ArithOp", "Guard", "VarWidth", "PhiSource"],
    "unbounded_counter":          ["ArithOp", "Guard", "VarWidth", "PhiSource"],
    "tainted_counter_as_index":   ["ArithOp", "Guard", "MemRead", "MemWrite", "Cast"],
    "alloc_copy_both_tainted_diff": ["AllocSite", "MemWriteSize", "MemWrite", "ArithOp", "Call", "ActualArg"],
    "alloc_then_unbounded_copy":  ["AllocSite", "MemWriteSize", "MemWrite", "ArithOp", "Call", "ActualArg"],
    "unguarded_tainted_sink":     ["Call", "ActualArg", "Guard"],
    "tainted_overflow_at_sink":   ["ArithOp", "Cast", "VarWidth", "Guard", "Call", "ActualArg"],
    "unguarded_cast_sx":          ["Cast", "VarWidth", "VarSign", "Guard"],
    "unguarded_cast_trunc":       ["Cast", "VarWidth", "VarSign", "Guard"],
    "tainted_loop_bound":         ["Guard", "CFGEdge", "ArithOp", "Use"],
    "width_mismatch_counter":     ["ArithOp", "MemWriteSize", "MemWriteValue", "Cast", "VarWidth"],
    "width_mismatch_store":       ["ArithOp", "MemWriteSize", "MemWriteValue", "Cast", "VarWidth"],
    "sentinel_collision":         ["AllocSite", "CallArgConst", "MemWrite", "ArithOp", "Guard"],
    "sentinel_collision_structural": ["AllocSite", "CallArgConst", "MemWrite", "ArithOp", "Guard"],
    "null_deref_alloc":           ["AllocSite", "MemRead", "Guard", "PhiSource"],
}
DEFAULT_RELATIONS = ["ArithOp", "Guard", "Call", "ActualArg", "Cast", "VarWidth"]
MAX_ROWS_PER_RELATION = 60

# DeepSeek (and most non-OpenAI providers) accept only the simple
# json_object form, not json_schema. The required shape is enforced
# via the system prompt + post-call validation.
VERDICT_RESPONSE_FORMAT = {"type": "json_object"}

REQUIRED_FIELDS = ("verdict", "confidence", "reasoning", "evidence_cited")
ALLOWED_VERDICTS = {"confirmed", "false_positive", "needs_more_info"}
ALLOWED_CONFIDENCE = {"high", "medium", "low"}


def _validate_verdict(v: dict) -> str | None:
    """Return None if `v` is well-formed, else an error message."""
    for f in REQUIRED_FIELDS:
        if f not in v:
            return f"missing field: {f}"
    if v["verdict"] not in ALLOWED_VERDICTS:
        return f"invalid verdict: {v['verdict']!r}"
    if v["confidence"] not in ALLOWED_CONFIDENCE:
        return f"invalid confidence: {v['confidence']!r}"
    if not isinstance(v["evidence_cited"], list):
        return "evidence_cited must be a list"
    return None


def _slug(finding_id: str) -> str:
    return finding_id.replace(":", "_").replace("/", "_")


def _trim(rows: list[list[str]], cap: int = MAX_ROWS_PER_RELATION) -> list[list[str]]:
    return rows[:cap] if len(rows) > cap else rows


def _read_dom_guard_rows(facts: Path, func: str, addr: str, category: str) -> dict[str, list[list[str]]]:
    """Return BnFindingDomGuarded* and BnFindingDomUnguarded rows for the
    finding key (func, addr, category). These are the step 4a evidence
    rows."""
    out = {}
    for rel in ("BnFindingDomGuarded", "BnFindingDomGuardedTight",
                "BnFindingDomGuardedLoose", "BnFindingDomUnguarded"):
        rows = evidence.read_facts_relation(facts, rel)
        if rel.startswith("BnFindingDomGuarded"):
            out[rel] = [r for r in rows if len(r) >= 3 and r[0] == func and r[1] == addr and r[2] == category]
        else:
            out[rel] = [r for r in rows if len(r) >= 4 and r[0] == func and r[1] == addr and r[3] == category]
    return out


def build_evidence_pack(finding: dict, scan_out: Path) -> str:
    """Render the prompt evidence section for one finding."""
    facts = scan_out / "facts"
    souffle = scan_out / "souffle_out"
    func = finding["func"]
    addr = finding["addr"]
    cat = finding["category"]
    var = finding.get("var", "")

    rels = RELATION_HINTS_BY_CATEGORY.get(cat, DEFAULT_RELATIONS)
    func_facts = evidence.read_function_facts(facts, func, rels)

    # Step-4a: dom-guard rows for this exact finding key.
    dom_rows = _read_dom_guard_rows(facts, func, addr, cat)

    # Taint chain (origins reaching this function).
    origin = ""
    if "origin=" in finding.get("detail", ""):
        origin = finding["detail"].split("origin=")[-1].split()[0]
    taint_rows = []
    if origin:
        taint_rows = evidence.read_taint_chain(souffle, origin, func, var)
        taint_rows = _trim(taint_rows, 30)

    parts = [
        "## Finding",
        f"id:        {finding['id']}",
        f"function:  {func}",
        f"addr:      {addr}",
        f"category:  {cat}",
        f"severity:  {finding.get('severity','?')}",
        f"var:       {var}",
        f"detail:    {finding.get('detail','')}",
    ]
    if "rank_score" in finding:
        parts.append(f"score:     {finding['rank_score']}")

    parts.append("\n## Step 4a — Path-dominating guard evidence")
    n_dom = sum(len(v) for v in dom_rows.values())
    if n_dom == 0:
        parts.append("(No BnFindingDomGuarded* / BnFindingDomUnguarded rows for this finding key. "
                     "Step 4a does not refute. Continue with structural evidence below.)")
    else:
        for rel, rows in dom_rows.items():
            if rows:
                parts.append(f"\n### {rel} ({len(rows)} rows):")
                for r in rows[:20]:
                    parts.append("  " + "\t".join(r))

    parts.append("\n## Function facts (filtered to this function)")
    for rel, rows in func_facts.items():
        if rows:
            parts.append(f"\n### {rel} ({len(rows)} rows):")
            for r in _trim(rows):
                parts.append("  " + "\t".join(r))

    if taint_rows:
        parts.append(f"\n## TaintedVar rows reaching {func} (origin={origin})")
        for r in taint_rows:
            parts.append("  " + "\t".join(r))

    return "\n".join(parts)


SYSTEM_PROMPT = """\
You are a binary-vulnerability triage analyst for BinCodeQL. You will
receive ONE finding plus a pre-packaged evidence bundle, and you must
return a single JSON verdict.

## Verdicts
- confirmed         — facts directly demonstrate an unsafe condition is
                       reachable along the data-flow / control-flow path
                       implied by the finding.
- false_positive    — facts show a guard, sanitizer, or structural
                       property that refutes the finding.
- needs_more_info   — only when the evidence genuinely cannot decide.
                       Do NOT use as a generic escape hatch.

## Reasoning discipline (3-5 sentences max)
- Cite specific fact rows in `evidence_cited` — these are the verifiable
  spine of the verdict. Each row is `{relation, row: [columns...]}`.
- For `tainted_*` categories, the data-flow axis (taint origin → sink
  variable) MUST be addressed.
- A path-dominating guard (the BnFindingDomGuarded* section) is strong
  refutation evidence ONLY when the bound is tight enough to rule out
  the unsafe condition. A loose bound (>= 0x10000), a variable bound,
  or an expression bound does NOT exonerate.
- A Datalog miss (rule didn't fire elsewhere) is NEVER exonerating
  evidence. Refute only with positive evidence.

## Output format
Return ONLY a JSON object with EXACTLY these fields:
{
  "verdict": "confirmed" | "false_positive" | "needs_more_info",
  "confidence": "high" | "medium" | "low",
  "reasoning": "3-5 sentences explaining the call",
  "evidence_cited": [{"relation": "<RelName>", "row": ["col1","col2",...]}, ...]
}
No prose outside the JSON. No code fences.

## Reachability axes (state explicitly when relevant)
A `confirmed` verdict is a STRUCTURAL claim. If you assert runtime
reachability (e.g. "exploitable via parser API"), separately address:
(a) library-internal data-flow, (b) direct C-API misuse,
(c) downstream wrapper exposure, (d) version-specific flag semantics.

Output the JSON verdict. No prose outside the JSON.
"""


def model_kwargs() -> dict:
    """Resolve litellm kwargs from .env, mirroring agent_factory."""
    name = os.getenv("MODEL_NAME") or "openai/deepseek-v4-flash"
    base = os.getenv("MODEL_BASE_URL")
    key_env = os.getenv("MODEL_API_KEY_ENV")
    api_key = os.getenv(key_env) if key_env else None
    timeout = int(os.getenv("MODEL_TIMEOUT") or "120")
    kw = {"model": name, "timeout": timeout}
    if base:
        kw["api_base"] = base
    if api_key:
        kw["api_key"] = api_key
    temp = os.getenv("MODEL_TEMPERATURE")
    if temp:
        kw["temperature"] = float(temp)
    return kw


async def triage_one(finding: dict, scan_out: Path, sem: asyncio.Semaphore) -> dict:
    fid = finding["id"]
    out_dir = scan_out / "verdicts_oneshot"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{_slug(fid)}.json"

    async with sem:
        t0 = time.time()
        try:
            evi = build_evidence_pack(finding, scan_out)
            user_msg = (
                f"Triage this finding and return a JSON verdict.\n\n{evi}"
            )
            kw = model_kwargs()
            resp = await litellm.acompletion(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                response_format=VERDICT_RESPONSE_FORMAT,
                **kw,
            )
            content = (resp.choices[0].message.content or "{}").strip()
            # Strip code-fence wrappers if the model emits them.
            if content.startswith("```"):
                content = content.split("\n", 1)[1] if "\n" in content else content
                if content.endswith("```"):
                    content = content.rsplit("\n", 1)[0]
                content = content.strip()
            v = json.loads(content)
            err = _validate_verdict(v)
            if err:
                return {"id": fid, "status": "invalid", "error": err,
                        "elapsed": round(time.time() - t0, 1)}
            v["id"] = fid
            v["source"] = finding.get("source", "")
            v["func"] = finding["func"]
            v["addr"] = finding["addr"]
            v["category"] = finding["category"]
            v["severity"] = finding.get("severity", "")
            v["elapsed"] = round(time.time() - t0, 1)
            out_path.write_text(json.dumps(v, indent=2))
            return {"id": fid, "status": "ok", "verdict": v.get("verdict"),
                    "confidence": v.get("confidence"), "elapsed": v["elapsed"]}
        except Exception as e:
            return {"id": fid, "status": "error", "error": str(e)[:200],
                    "elapsed": round(time.time() - t0, 1)}


async def main_async(args) -> int:
    scan_out = Path(args.scan_out)
    cand_path = scan_out / "candidates.json"
    candidates = json.loads(cand_path.read_text())["candidates"]
    if args.severity:
        candidates = [c for c in candidates if c.get("severity") == args.severity]
    if args.candidate_id:
        candidates = [c for c in candidates if c["id"] == args.candidate_id]
    if args.limit:
        candidates = candidates[:args.limit]
    if not args.force:
        done = {p.stem for p in (scan_out / "verdicts_oneshot").glob("*.json")} \
            if (scan_out / "verdicts_oneshot").exists() else set()
        candidates = [c for c in candidates if _slug(c["id"]) not in done]

    print(f"[triage_oneshot] {len(candidates)} candidates "
          f"(concurrency={args.concurrency}, model={os.getenv('MODEL_NAME')})...")
    sem = asyncio.Semaphore(args.concurrency)
    results = await asyncio.gather(*[triage_one(c, scan_out, sem) for c in candidates])

    by_v = {}
    by_s = {}
    for r in results:
        by_s[r["status"]] = by_s.get(r["status"], 0) + 1
        if r["status"] == "ok":
            by_v[r["verdict"]] = by_v.get(r["verdict"], 0) + 1
        print(f"  [{_slug(r['id'])}] {r['status']} "
              f"{r.get('verdict','')} ({r.get('elapsed','?')}s)"
              + (f" — {r.get('error','')}" if r['status'] == 'error' else ''))

    summary = {"by_status": by_s, "by_verdict": by_v, "results": results}
    (scan_out / "triage_oneshot_summary.json").write_text(json.dumps(summary, indent=2))
    print("\n--- Summary ---")
    print("  by_status:", by_s)
    print("  by_verdict:", by_v)
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--scan-out", required=True)
    p.add_argument("-j", "--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("--limit", type=int)
    p.add_argument("--force", action="store_true")
    p.add_argument("--severity", choices=["high", "medium", "low"])
    p.add_argument("--candidate-id")
    return p.parse_args()


def main() -> int:
    return asyncio.run(main_async(parse_args()))


if __name__ == "__main__":
    sys.exit(main())
