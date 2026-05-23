#!/usr/bin/env python3
"""LLM-only baseline: per-function bug-finder, no Datalog scaffolding.

Companion ablation to the Datalog+LLM pipeline. For each eval-set
function:
  1. Headless BN dumps HLIL to `<run_dir>/decomp/<func>.txt` (cached).
  2. Pull caller/callee lists from `<run_dir>/facts/Call.facts`.
  3. Single litellm call: "find any memory-safety bugs in this function;
     reason about whether external input can reach them."
  4. Persist verdict to `<run_dir>/verdicts_no_datalog/<func>.json`.

This is the "LLM as bug-finder" baseline — what people get without
Datalog precondition. Compared head-to-head against the Datalog+LLM
verdicts to quantify what Datalog actually contributes.

Usage:
    triage_no_datalog.py <target> <variant> [--profile deepseek]
        [--limit N] [--concurrency N] [--force]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
REPO_ROOT = ROOT.parent
EVAL_SET = ROOT / "eval_set.json"
RUNS_DIR = ROOT / "runs"
FARAH = Path("/home/sanjay/san-home/research/tii/tii24/tmp/farah-magma")
PRIMARY = {"libtiff": "tiffcp", "libxml2": "xmllint"}
ADK_PY = os.environ.get(
    "ADK_PYTHON",
    "/home/sanjay/san-home/research/tii/tii24/phoenix/google-adk/.venv/bin/python3",
)
BN_PY = os.environ.get(
    "BN_PYTHON",
    os.environ.get("BN_PYTHON_PATH",
                   "/home/sanjay/san-home/research/tii/tii24/phoenix/google-adk/.venv/bin/python3"),
)


PROMPT_TEMPLATE = """You are a binary security analyst.

I'll show you a single function decompiled by Binary Ninja (HLIL pretty-print).
Your task: identify whether this function contains any **memory-safety bugs**
(buffer overflow, OOB read/write, use-after-free, integer overflow leading to
oversized allocation, missing null/bound check, format-string, etc.) that are
**reachable from external input** (file content, network, argv).

Reachability rule: a bug is "reachable" only if you can identify a plausible
chain from an external input source (file read, mmap, argv, network) to the
unsafe operation. If the function only operates on internal/constant data
that can't be influenced by an attacker, the bug is NOT reachable.

You are given:
- Decompiled function text (HLIL)
- Callers (functions that call this one) — to gauge how external data reaches it
- Callees (functions this one calls) — to recognise sinks (memcpy, strcpy, etc.)

Be conservative. If you cannot construct a concrete reachability chain, say
"false_positive" — do not speculate. If the bug is real and reachable, say
"confirmed".

Output a single JSON object, nothing else, with these fields:
- verdict: "confirmed" | "false_positive" | "needs_more_info"
- confidence: "high" | "medium" | "low"
- bug_type: short label (e.g. "OOB write", "integer overflow", "missing null check"); empty if none
- reasoning: 2-5 sentences. Cite specific HLIL line/var names.
- reachability_chain: brief description of how external input reaches the bug (or "n/a" if false_positive)

==== FUNCTION: {func_name} ====
{decomp}

==== CALLERS ({n_callers}) ====
{callers}

==== CALLEES ({n_callees}) ====
{callees}
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="LLM-only per-function bug-finder baseline (no Datalog)."
    )
    p.add_argument("target", choices=("libtiff", "libxml2"))
    p.add_argument("variant", choices=("vuln", "patched"))
    p.add_argument("--profile", default="deepseek")
    p.add_argument("--functions",
                   help="Comma-separated function names; default: full eval set.")
    p.add_argument("--limit", type=int,
                   help="Smoke test: limit to first N fns.")
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--force", action="store_true",
                   help="Re-run even if verdict already exists.")
    p.add_argument("--skip-decomp", action="store_true",
                   help="Reuse existing decomp/ files (default if present).")
    return p.parse_args()


def function_list(target: str) -> list[str]:
    payload = json.loads(EVAL_SET.read_text())
    bucket = payload["targets"][target]
    names = [f["name"] for f in bucket["buggy_present"]]
    names += [f["name"] for f in bucket["negatives"]]
    return names


def decompile_all(binary: Path, funcs: list[str], decomp_dir: Path) -> int:
    """Run headless BN to dump HLIL for the given functions.

    Uses the same Python+env resolver as bn_utils.run_bn_script so
    BN_PYTHON_PATH (PYTHONPATH inject) works the same way as fact
    extraction does.
    """
    decomp_dir.mkdir(parents=True, exist_ok=True)
    script = REPO_ROOT / "scripts" / "bn_decompile_funcs.py"

    # Reuse the existing resolver so BN_PYTHON_PATH semantics match.
    sys.path.insert(0, str(REPO_ROOT))
    try:
        from bn_utils import get_bn_python
        bn_py, bn_env = get_bn_python()
    finally:
        sys.path.pop(0)

    cmd = [
        bn_py, str(script), str(binary),
        "-f", ",".join(funcs),
        "-o", str(decomp_dir),
    ]
    print(f"[no-datalog] Decompiling {len(funcs)} fns via {script.name}…",
          flush=True)
    rc = subprocess.call(cmd, env=bn_env)
    if rc != 0:
        print(f"[no-datalog] Decompile FAILED rc={rc}", file=sys.stderr)
    return rc


def callgraph_index(facts_dir: Path) -> tuple[dict, dict]:
    """Build caller/callee maps from Call.facts."""
    callers: dict[str, set] = {}
    callees: dict[str, set] = {}
    p = facts_dir / "Call.facts"
    if not p.exists():
        return callers, callees
    for line in p.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        caller, callee, _addr = parts[0], parts[1], parts[2]
        callees.setdefault(caller, set()).add(callee)
        callers.setdefault(callee, set()).add(caller)
    return callers, callees


def build_prompt(func: str, decomp_dir: Path,
                 callers: set, callees: set) -> str | None:
    decomp_path = decomp_dir / f"{func}.txt"
    if not decomp_path.exists():
        return None
    decomp = decomp_path.read_text()
    if len(decomp) > 60000:
        decomp = decomp[:60000] + "\n... (truncated; original was longer)"
    return PROMPT_TEMPLATE.format(
        func_name=func,
        decomp=decomp,
        n_callers=len(callers),
        callers="\n".join(f"  - {c}" for c in sorted(callers)) if callers else "  (none)",
        n_callees=len(callees),
        callees="\n".join(f"  - {c}" for c in sorted(callees)) if callees else "  (none)",
    )


def llm_call(prompt: str, profile_path: Path) -> tuple[str, dict]:
    """Run the prompt via litellm. Returns (raw_text, parsed_json or {})."""
    from dotenv import load_dotenv
    # Load default .env then profile override
    load_dotenv(REPO_ROOT / ".env", override=False)
    load_dotenv(profile_path, override=True)

    import litellm
    litellm.drop_params = True

    api_key_env = os.environ.get("MODEL_API_KEY_ENV", "OPENAI_API_KEY")
    api_key = os.environ.get(api_key_env)

    extra: dict = {}
    extra_body = os.environ.get("MODEL_EXTRA_BODY")
    if extra_body:
        try:
            extra["extra_body"] = json.loads(extra_body)
        except Exception:
            pass

    temperature = os.environ.get("MODEL_TEMPERATURE")
    top_p = os.environ.get("MODEL_TOP_P")
    if temperature:
        extra["temperature"] = float(temperature)
    if top_p:
        extra["top_p"] = float(top_p)

    timeout = int(os.environ.get("MODEL_TIMEOUT", "180"))
    retries = int(os.environ.get("MODEL_NUM_RETRIES", "2"))

    resp = litellm.completion(
        model=os.environ.get("MODEL_NAME", "openai/deepseek-v4-flash"),
        api_base=os.environ.get("MODEL_BASE_URL"),
        api_key=api_key,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=2048,
        timeout=timeout,
        num_retries=retries,
        **extra,
    )

    raw = resp.choices[0].message.content or ""
    parsed: dict = {}
    # Strip ```json fences if present
    txt = raw.strip()
    if txt.startswith("```"):
        txt = txt.strip("`")
        if txt.lstrip().startswith("json"):
            txt = txt.lstrip()[4:].lstrip()
    # Find first { ... last }
    s = txt.find("{")
    e = txt.rfind("}")
    if s != -1 and e != -1 and e > s:
        try:
            parsed = json.loads(txt[s:e+1])
        except Exception:
            parsed = {}
    return raw, parsed


def main() -> int:
    args = parse_args()
    binary = FARAH / f"{args.target}-{args.variant}" / PRIMARY[args.target]
    if not binary.is_file():
        print(f"ERROR: binary not found at {binary}", file=sys.stderr)
        return 2

    profile_path = ROOT / f".env.eval.{args.profile}"
    if not profile_path.is_file():
        print(f"ERROR: profile {profile_path} not found", file=sys.stderr)
        return 4

    funcs = ([f.strip() for f in args.functions.split(",")]
             if args.functions else function_list(args.target))
    if args.limit:
        funcs = funcs[:args.limit]

    run_dir = RUNS_DIR / f"{args.target}-{args.variant}"
    decomp_dir = run_dir / "decomp"
    verdicts_dir = run_dir / "verdicts_no_datalog"
    verdicts_dir.mkdir(parents=True, exist_ok=True)
    facts_dir = run_dir / "facts"

    # Decompile (cached unless missing)
    needed = [f for f in funcs if not (decomp_dir / f"{f}.txt").exists()]
    if needed and not args.skip_decomp:
        rc = decompile_all(binary, needed, decomp_dir)
        if rc != 0:
            print(f"[no-datalog] Decompile failed rc={rc}", file=sys.stderr)
            return rc

    # Callgraph index from existing facts
    callers_idx, callees_idx = callgraph_index(facts_dir)

    # Filter todo: skip those with existing verdicts unless --force
    todo = []
    for f in funcs:
        v = verdicts_dir / f"{f}.json"
        if not args.force and v.exists():
            continue
        if not (decomp_dir / f"{f}.txt").exists():
            print(f"[no-datalog] WARN: no decomp for {f}, skipping",
                  file=sys.stderr)
            continue
        todo.append(f)

    print(f"[no-datalog] {args.target}-{args.variant}: "
          f"triaging {len(todo)} of {len(funcs)} fns @ concurrency={args.concurrency}",
          flush=True)

    def _run_one(func: str) -> tuple[str, str, float]:
        t0 = time.time()
        prompt = build_prompt(func, decomp_dir,
                              callers_idx.get(func, set()),
                              callees_idx.get(func, set()))
        if prompt is None:
            return func, "no_decomp", time.time() - t0
        try:
            raw, parsed = llm_call(prompt, profile_path)
            verdict = parsed.get("verdict", "no_verdict") if parsed else "no_verdict"
            payload = {
                "func": func,
                "target": args.target,
                "variant": args.variant,
                "verdict": verdict,
                "confidence": parsed.get("confidence", ""),
                "bug_type": parsed.get("bug_type", ""),
                "reasoning": parsed.get("reasoning", ""),
                "reachability_chain": parsed.get("reachability_chain", ""),
                "raw": raw,
                "elapsed_s": round(time.time() - t0, 1),
            }
            (verdicts_dir / f"{func}.json").write_text(json.dumps(payload, indent=2))
            return func, verdict, time.time() - t0
        except Exception as e:
            payload = {
                "func": func,
                "target": args.target,
                "variant": args.variant,
                "verdict": "error",
                "error": f"{type(e).__name__}: {e}",
                "elapsed_s": round(time.time() - t0, 1),
            }
            (verdicts_dir / f"{func}.json").write_text(json.dumps(payload, indent=2))
            return func, "error", time.time() - t0

    counts = {"confirmed": 0, "false_positive": 0, "needs_more_info": 0,
              "no_verdict": 0, "error": 0, "no_decomp": 0}
    t_start = time.time()
    completed = 0
    total = len(todo)
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {ex.submit(_run_one, f): f for f in todo}
        for fut in as_completed(futures):
            func, verdict, elapsed = fut.result()
            completed += 1
            counts[verdict] = counts.get(verdict, 0) + 1
            print(f"[no-datalog] [{completed}/{total}] [{verdict}] {func}  "
                  f"({elapsed:.0f}s)", flush=True)

    total_t = time.time() - t_start
    print(f"\n[no-datalog] DONE — {counts}  ({total_t/60:.1f} min)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
