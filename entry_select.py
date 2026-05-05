#!/usr/bin/env python3
"""entry_select.py — LLM-driven entry-point selection.

Reads `EntryCandidate.csv` produced by `rules/entry_candidates.dl`, fetches
HLIL for each candidate via `scripts/bn_decompile_funcs.py`, and asks the
LLM to classify each as `entry` / `internal` / `init-only` / `unreachable`,
emitting `EntryTaint.facts` with the selected (func, param_idx) rows.

Usage:
    python3 entry_select.py \\
        --facts magma_eval/runs/libxml2-vuln/facts \\
        --binary /home/.../farah-magma/libxml2-vuln/xmllint \\
        --output magma_eval/runs/libxml2-vuln-llm-entry/facts \\
        --prompt prompts/entry_select.md
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

# Load .env early so MODEL_NAME / api keys are visible to litellm
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

import litellm  # type: ignore


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--facts", required=True, help="facts dir containing existing facts and EntryCandidate.csv")
    p.add_argument("--binary", required=True, help="binary path for decomp")
    p.add_argument("--output", required=True, help="output facts dir (copy of --facts with new EntryTaint.facts)")
    p.add_argument("--prompt", default="prompts/entry_select.md", help="path to system prompt template")
    p.add_argument("--candidates", default=None,
                   help="path to EntryCandidate.csv (default: <facts>/../entry_select/EntryCandidate.csv)")
    p.add_argument("--model", default=os.environ.get("MODEL_NAME", "openai/z-ai/glm-5.1"))
    p.add_argument("--decomp-cache", default=None,
                   help="dir to cache HLIL dumps (default: <output>/../entry_decomp)")
    p.add_argument("--max-functions", type=int, default=None,
                   help="cap candidates analyzed (debug)")
    p.add_argument("--per-request-delay", type=float, default=2.0,
                   help="seconds between LLM calls (rate-limit politeness)")
    p.add_argument("--resume-from", default=None,
                   help="path to a prior entry_decisions.json — keep its successes, retry only errors")
    return p.parse_args()


def load_candidates(candidates_csv: Path) -> dict[str, set[int]]:
    """Returns {func_name: {param_idx, ...}} from EntryCandidate.csv."""
    by_func: dict[str, set[int]] = defaultdict(set)
    with open(candidates_csv) as f:
        for row in csv.reader(f, delimiter='\t'):
            if len(row) >= 2:
                func, idx = row[0], int(row[1])
                by_func[func].add(idx)
    return dict(by_func)


def load_call_facts(facts_dir: Path) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Returns (callers_of, callees_of) maps. Both are dict[func, list[func]] (no addresses)."""
    callers_of: dict[str, set[str]] = defaultdict(set)
    callees_of: dict[str, set[str]] = defaultdict(set)
    with open(facts_dir / "Call.facts") as f:
        for row in csv.reader(f, delimiter='\t'):
            if len(row) >= 2:
                caller, callee = row[0], row[1]
                callers_of[callee].add(caller)
                callees_of[caller].add(callee)
    return ({k: sorted(v) for k, v in callers_of.items()},
            {k: sorted(v) for k, v in callees_of.items()})


def load_formal_params(facts_dir: Path) -> dict[str, list[tuple[str, int]]]:
    """Returns {func: [(var_name, idx), ...]}."""
    by_func: dict[str, list[tuple[str, int]]] = defaultdict(list)
    with open(facts_dir / "FormalParam.facts") as f:
        for row in csv.reader(f, delimiter='\t'):
            if len(row) >= 3:
                func, var, idx = row[0], row[1], int(row[2])
                by_func[func].append((var, idx))
    return {k: sorted(v, key=lambda x: x[1]) for k, v in by_func.items()}


def decompile_candidates(binary: str, funcs: list[str], cache_dir: Path) -> dict[str, str]:
    """Use bn_decompile_funcs.py to dump HLIL for each candidate. Cached on disk."""
    from bn_utils import get_bn_python
    cache_dir.mkdir(parents=True, exist_ok=True)
    needed = [f for f in funcs if not (cache_dir / f"{f}.txt").exists()]
    if needed:
        py, env = get_bn_python()
        cmd = [py, "scripts/bn_decompile_funcs.py", binary,
               "-f", ",".join(needed), "-o", str(cache_dir)]
        print(f"[decomp] running BN on {len(needed)} candidates...", flush=True)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900, env=env)
        if r.returncode != 0:
            print(f"[decomp] WARNING: rc={r.returncode}\nstderr: {r.stderr[-500:]}", file=sys.stderr)
    out: dict[str, str] = {}
    for f in funcs:
        p = cache_dir / f"{f}.txt"
        out[f] = p.read_text() if p.exists() else "(decomp unavailable)"
    return out


def build_user_prompt(func: str, params: list[tuple[str, int]],
                      candidate_callers: list[str], candidate_callees: list[str],
                      reasons: list[str], hlil: str) -> str:
    params_lines = "\n".join(f"  - param {idx}: {var}" for var, idx in params) or "  (none)"
    callers_lines = "\n".join(f"  - {c}" for c in candidate_callers[:20]) or "  (none in candidate set)"
    callees_lines = "\n".join(f"  - {c}" for c in candidate_callees[:20]) or "  (none in candidate set)"
    reasons_str = ", ".join(sorted(set(reasons)))
    # Cap HLIL aggressively — we only need a few hundred lines for classification
    hlil_capped = "\n".join(hlil.split("\n")[:80])
    return f"""Classify the entry-point status of function `{func}`.

Candidate reasons (why it was flagged): {reasons_str}

Parameters:
{params_lines}

Callers IN the candidate set ({len(candidate_callers)} total, top 20 shown):
{callers_lines}

Callees IN the candidate set ({len(candidate_callees)} total, top 20 shown):
{callees_lines}

HLIL (first 80 lines):
```
{hlil_capped}
```

Return JSON only, matching the schema in the system prompt."""


def parse_json_response(content: str) -> dict | None:
    """Extract first JSON object from response. LLMs sometimes prepend prose."""
    # Try direct parse first
    try:
        return json.loads(content.strip())
    except Exception:
        pass
    # Try to extract a ```json ... ``` block
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    # Fallback: first {...} substring
    m = re.search(r"\{.*\}", content, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return None


def classify_one(model: str, system_prompt: str, user_prompt: str,
                 timeout: int = 90, max_retries: int = 3) -> tuple[dict | None, str]:
    """Returns (parsed_json_or_None, raw_content). With retries on timeout."""
    import time as _time
    kwargs: dict = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.0,
        "timeout": timeout,
        "num_retries": max_retries,
    }
    base = os.environ.get("MODEL_BASE_URL")
    key_env = os.environ.get("MODEL_API_KEY_ENV")
    if base:
        kwargs["api_base"] = base
    if key_env and os.environ.get(key_env):
        kwargs["api_key"] = os.environ[key_env]
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            r = litellm.completion(**kwargs)
            content = r["choices"][0]["message"]["content"] or ""
            parsed = parse_json_response(content)
            return parsed, content
        except Exception as e:
            last_exc = e
            backoff = min(30, 2 ** attempt + (attempt * 2))
            if attempt < max_retries:
                _time.sleep(backoff)
    raise last_exc if last_exc else RuntimeError("classify_one: unknown failure")


def main() -> int:
    args = parse_args()
    facts_in = Path(args.facts).resolve()
    facts_out = Path(args.output).resolve()
    cands_csv = Path(args.candidates) if args.candidates else \
                facts_in.parent / "entry_select" / "EntryCandidate.csv"
    decomp_cache = Path(args.decomp_cache) if args.decomp_cache else \
                   facts_out.parent / "entry_decomp"

    if not cands_csv.exists():
        print(f"ERROR: {cands_csv} not found. Run rules/entry_candidates.dl first.", file=sys.stderr)
        return 2

    system_prompt = Path(args.prompt).read_text()

    # Load candidates and context
    cand_params = load_candidates(cands_csv)
    callers_of, callees_of = load_call_facts(facts_in)
    formal = load_formal_params(facts_in)

    # Group candidates by function (for reasons)
    reasons_by_func: dict[str, list[str]] = defaultdict(list)
    with open(cands_csv) as f:
        for row in csv.reader(f, delimiter='\t'):
            if len(row) >= 3:
                reasons_by_func[row[0]].append(row[2])

    cand_funcs = sorted(cand_params.keys())
    if args.max_functions:
        cand_funcs = cand_funcs[:args.max_functions]
    cand_set = set(cand_funcs)

    print(f"[entry_select] {len(cand_funcs)} candidate functions", flush=True)

    # Decompile all in one BN invocation
    hlil_by_func = decompile_candidates(args.binary, cand_funcs, decomp_cache)

    # Resume support: keep prior good decisions, retry only errors
    prior_good: dict[str, dict] = {}
    if args.resume_from and Path(args.resume_from).exists():
        prior = json.load(open(args.resume_from))
        for d in prior.get("decisions", []):
            if "error" not in d and d.get("function"):
                prior_good[d["function"]] = d
        print(f"[resume] keeping {len(prior_good)} prior successful decisions", flush=True)

    # Classify each
    decisions: list[dict] = []
    entry_taint_rows: list[tuple[str, int]] = []
    for i, func in enumerate(cand_funcs, 1):
        if func in prior_good:
            d = prior_good[func]
            print(f"  [{i}/{len(cand_funcs)}] {func}: {d['decision']} {d.get('tainted_params', [])} (cached)", flush=True)
            decisions.append(d)
            if d.get("decision") == "entry":
                for idx in d.get("tainted_params", []) or []:
                    if isinstance(idx, int):
                        entry_taint_rows.append((func, idx))
            continue
        if i > 1:
            time.sleep(args.per_request_delay)
        params = formal.get(func, [])
        cand_callers = sorted([c for c in callers_of.get(func, []) if c in cand_set])
        cand_callees = sorted([c for c in callees_of.get(func, []) if c in cand_set])
        user = build_user_prompt(func, params, cand_callers, cand_callees,
                                 reasons_by_func[func], hlil_by_func.get(func, ""))
        try:
            parsed, raw = classify_one(args.model, system_prompt, user)
        except Exception as e:
            print(f"  [{i}/{len(cand_funcs)}] {func}: ERROR {e}", flush=True)
            decisions.append({"function": func, "error": str(e)})
            continue
        if not parsed:
            print(f"  [{i}/{len(cand_funcs)}] {func}: parse-failed", flush=True)
            decisions.append({"function": func, "error": "parse-failed", "raw": raw[:500]})
            continue
        d = parsed.get("decision", "?")
        tps = parsed.get("tainted_params", []) or []
        print(f"  [{i}/{len(cand_funcs)}] {func}: {d} {tps}", flush=True)
        decisions.append(parsed)
        if d == "entry" and isinstance(tps, list):
            for idx in tps:
                if isinstance(idx, int):
                    entry_taint_rows.append((func, idx))

    # Stage output dir: hardlink the input facts, overwrite EntryTaint.facts
    facts_out.mkdir(parents=True, exist_ok=True)
    for f in facts_in.iterdir():
        dst = facts_out / f.name
        if dst.exists():
            continue
        try:
            os.link(f, dst)
        except Exception:
            shutil.copy2(f, dst)
    et_path = facts_out / "EntryTaint.facts"
    if et_path.exists() and et_path.stat().st_nlink > 1:
        et_path.unlink()
    with open(et_path, "w") as f:
        for func, idx in sorted(set(entry_taint_rows)):
            f.write(f"{func}\t{idx}\n")
    print(f"\n[entry_select] EntryTaint.facts: {len(set(entry_taint_rows))} rows -> {et_path}", flush=True)

    # Save decisions log
    log_path = facts_out.parent / "entry_decisions.json"
    with open(log_path, "w") as f:
        json.dump({
            "model": args.model,
            "candidates": len(cand_funcs),
            "entry_count": sum(1 for d in decisions if d.get("decision") == "entry"),
            "internal_count": sum(1 for d in decisions if d.get("decision") == "internal"),
            "init_only_count": sum(1 for d in decisions if d.get("decision") == "init-only"),
            "unreachable_count": sum(1 for d in decisions if d.get("decision") == "unreachable"),
            "errors": sum(1 for d in decisions if "error" in d),
            "decisions": decisions,
        }, f, indent=2)
    print(f"[entry_select] decisions log: {log_path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
