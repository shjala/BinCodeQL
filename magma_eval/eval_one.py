#!/usr/bin/env python3
# eval_one.py <target> <variant>
#
# End-to-end BinCodeQL evaluation on one (target, variant) magma binary:
#   1. Read magma_eval/eval_set.json for the function list
#   2. Run scan.py (extract → taint → Bn* rules) restricted to those funcs
#   3. Run triage.py (per-finding LLM verdicts) over candidates.json
#   4. Print summary; verdicts persisted under runs/<target>-<variant>/verdicts/
#
# CPU-throttled by default (SOUFFLE_JOBS=2, OMP_NUM_THREADS=2). Override
# with --jobs N or env. Triage concurrency defaults to 4 (API-bound).

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
REPO_ROOT = ROOT.parent
EVAL_SET = ROOT / "eval_set.json"
RUNS_DIR = ROOT / "runs"
FARAH = Path("/home/sanjay/san-home/research/tii/tii24/tmp/farah-magma")
PRIMARY = {
    "libtiff": "tiffcp",
    "libxml2": "xmllint",
}
# triage.py imports google.adk + litellm, which live in the ADK venv,
# not /usr/bin/python3. scan.py only needs subprocess + souffle, so it
# can use either; we use ADK venv for both for consistency.
ADK_PY = os.environ.get(
    "ADK_PYTHON",
    "/home/sanjay/san-home/research/tii/tii24/phoenix/google-adk/.venv/bin/python3",
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="End-to-end BinCodeQL eval for one (target, variant)."
    )
    p.add_argument("target", choices=("libtiff", "libxml2"))
    p.add_argument("variant", choices=("vuln", "patched"))
    p.add_argument("--profile", choices=("claude", "deepseek", "deepseek-pro"),
                   default="claude",
                   help="Model profile (loads magma_eval/.env.eval.<profile>); "
                        "Claude is the paper main arm, DeepSeek is the OSS arm.")
    p.add_argument("--jobs", type=int, default=2,
                   help="SOUFFLE_JOBS (default 2; safe for shared box).")
    p.add_argument("--extract-all", action="store_true",
                   help="Extract facts for ALL functions in the binary "
                        "(reachability-aware mode). Without this flag, "
                        "extraction is restricted to the 50-fn eval set, "
                        "which prevents the taint pipeline from seeding "
                        "from libc sources like read/mmap/getopt.")
    p.add_argument("--triage-concurrency", type=int, default=4,
                   help="Parallel triage sessions (API-bound, default 4).")
    p.add_argument("--severity", choices=("high", "medium", "low"),
                   help="Triage only candidates of this severity.")
    p.add_argument("--limit", type=int,
                   help="Triage only the first N candidates (smoke test).")
    p.add_argument("--skip-scan", action="store_true",
                   help="Reuse existing scan_out if present (skip extraction "
                        "and rule runs).")
    p.add_argument("--skip-triage", action="store_true",
                   help="Stop after scan; don't invoke triage.py.")
    p.add_argument("--force-triage", action="store_true",
                   help="Re-triage findings whose verdict files exist.")
    return p.parse_args()


def function_list(target: str, variant: str) -> list[str]:
    payload = json.loads(EVAL_SET.read_text())
    bucket = payload["targets"][target]
    names = [f["name"] for f in bucket["buggy_present"]]
    names += [f["name"] for f in bucket["negatives"]]
    return names


def run(cmd: list[str], env_extra: dict[str, str] | None = None) -> int:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    print(f"[eval_one] $ {' '.join(cmd)}", flush=True)
    return subprocess.call(cmd, cwd=str(REPO_ROOT), env=env)


def main() -> int:
    args = parse_args()
    binary = FARAH / f"{args.target}-{args.variant}" / PRIMARY[args.target]
    if not binary.is_file():
        print(f"ERROR: binary not found at {binary}", file=sys.stderr)
        return 2

    funcs = function_list(args.target, args.variant)
    if not funcs:
        print(f"ERROR: empty function list for {args.target}", file=sys.stderr)
        return 3

    run_dir = RUNS_DIR / f"{args.target}-{args.variant}"
    run_dir.mkdir(parents=True, exist_ok=True)

    profile_path = ROOT / f".env.eval.{args.profile}"
    if not profile_path.is_file():
        example = profile_path.with_suffix(profile_path.suffix + ".example")
        print(f"ERROR: profile {profile_path} not found; copy from "
              f"{example.name} and fill in the API key.", file=sys.stderr)
        return 4

    cpu_env = {
        "SOUFFLE_JOBS": str(args.jobs),
        "OMP_NUM_THREADS": str(args.jobs),
        # scan.py / triage.py see this and load the profile AFTER the
        # default .env, overriding MODEL_* and the API-key vars.
        "BINCODEQL_PROFILE_ENV": str(profile_path),
    }
    print(f"[eval_one] profile: {args.profile} ({profile_path})")

    # ── scan.py ───────────────────────────────────────────────────────────
    # Reachability-aware mode: extract ALL functions in the binary so the
    # taint pipeline can propagate from libc sources (read/mmap/getopt)
    # through the call graph to candidate functions. We still SCORE only
    # against the 50-function eval set — extra extraction is for taint,
    # not for additional candidates. Filter findings post-scan.
    cand_path = run_dir / "candidates.json"
    eval_funcs = set(funcs)
    if args.skip_scan and cand_path.exists():
        print(f"[eval_one] reusing scan_out at {run_dir}")
    else:
        scan_cmd = [
            ADK_PY, str(REPO_ROOT / "scan.py"),
            "--binary", str(binary),
            "-o", str(run_dir),
        ]
        if args.extract_all:
            scan_cmd.append("-a")
        else:
            scan_cmd += ["-f", ",".join(funcs)]
        rc = run(scan_cmd, env_extra=cpu_env)
        if rc != 0:
            print(f"[eval_one] scan.py failed (rc={rc})", file=sys.stderr)
            return rc

    if not cand_path.exists():
        print(f"[eval_one] WARN: scan produced no candidates.json at {cand_path}")
        return 0

    summary = json.loads(cand_path.read_text())
    pre_filter_total = summary.get("candidate_count", 0)
    print(f"[eval_one] {pre_filter_total} candidates (pre eval-set filter)")

    # Filter to eval-set functions when --extract-all was used. This keeps
    # triage scoped to the 50 candidates we sampled while still letting
    # taint reach them from extracted callers.
    deduped_path = run_dir / "candidates.json"
    if not args.skip_scan or not (run_dir / ".deduped").exists():
        cands = summary.get("candidates", [])
        if args.extract_all:
            in_set = [c for c in cands if c.get("func", "") in eval_funcs]
            print(f"[eval_one] filtered {len(cands)} → {len(in_set)} "
                  f"to eval-set ({len(eval_funcs)} functions)")
            cands = in_set

        # Dedup per (func, category): keep the lowest-addr representative
        # of each class. The triage verdict on one representative applies
        # to the whole class for that function.
        seen: dict[tuple[str, str], dict] = {}
        for c in cands:
            key = (c.get("func", ""), c.get("category", ""))
            if key not in seen or c.get("addr", "") < seen[key].get("addr", ""):
                seen[key] = c
        deduped = list(seen.values())
        deduped.sort(key=lambda c: (c.get("severity", ""), c.get("func", ""),
                                    c.get("addr", "")))
        new_summary = dict(summary)
        new_summary["candidates"] = deduped
        new_summary["candidate_count"] = len(deduped)
        new_summary["pre_dedup_count"] = len(cands)
        new_summary["pre_filter_count"] = pre_filter_total
        deduped_path.write_text(json.dumps(new_summary, indent=2))
        (run_dir / ".deduped").touch()
        print(f"[eval_one] deduped {len(cands)} → {len(deduped)} "
              f"by (func, category)")

    if args.skip_triage:
        return 0

    # ── triage: one subprocess per candidate ──────────────────────────────
    # Long-running triage.py with many candidates leaks asyncio/httpx
    # state across iterations (LiteLLM "Event loop is closed" pattern,
    # half-closed connection pool). Per-candidate subprocesses give
    # bulletproof state isolation at the cost of process-startup
    # overhead (~1.5s per candidate, dwarfed by the ~150s API time).
    cands = json.loads(cand_path.read_text()).get("candidates", [])
    if args.severity:
        cands = [c for c in cands if c.get("severity") == args.severity]
    if args.limit:
        cands = cands[:args.limit]

    verdicts_dir = run_dir / "verdicts"
    verdicts_dir.mkdir(parents=True, exist_ok=True)

    def _slug(fid: str) -> str:
        return fid.replace(":", "_").replace("/", "_")

    todo = []
    for c in cands:
        fid = c.get("id", "")
        vpath = verdicts_dir / f"{_slug(fid)}.json"
        if not args.force_triage and vpath.exists():
            continue
        todo.append(fid)

    print(f"[eval_one] triaging {len(todo)} of {len(cands)} candidates "
          f"(per-candidate subprocesses, concurrency={args.triage_concurrency})")

    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed
    t_start = time.time()
    n_ok = n_err = n_no = 0
    completed = 0
    lock_total = len(todo)

    def _run_one(fid: str) -> tuple[str, int, float]:
        t0 = time.time()
        cmd = [
            ADK_PY, str(REPO_ROOT / "triage.py"),
            "--scan-out", str(run_dir),
            "-j", "1",
            "--candidate-id", fid,
        ]
        if args.force_triage:
            cmd.append("--force")
        # Run silently (don't echo each subprocess command line — too noisy
        # with concurrent workers). Pass cpu_env so souffle stays bounded
        # if the agent calls tool_compose_datalog.
        env = os.environ.copy()
        env.update(cpu_env)
        with open(os.devnull, "w") as devnull:
            rc = subprocess.call(cmd, cwd=str(REPO_ROOT), env=env,
                                 stdout=devnull, stderr=devnull)
        return fid, rc, time.time() - t0

    with ThreadPoolExecutor(max_workers=args.triage_concurrency) as ex:
        futures = {ex.submit(_run_one, fid): fid for fid in todo}
        for fut in as_completed(futures):
            fid, rc, elapsed = fut.result()
            completed += 1
            vpath = verdicts_dir / f"{_slug(fid)}.json"
            if vpath.exists():
                try:
                    v = json.loads(vpath.read_text()).get("verdict", "?")
                except Exception:
                    v = "?"
                n_ok += 1
                tag = f"[OK {v}]"
            elif rc != 0:
                n_err += 1
                tag = "[ER]"
            else:
                n_no += 1
                tag = "[NO_VERDICT]"
            print(f"[eval_one] [{completed}/{lock_total}] {tag} {fid}  "
                  f"({elapsed:.0f}s)", flush=True)

    total = time.time() - t_start
    print(f"\n[eval_one] DONE — ok={n_ok} no_verdict={n_no} err={n_err} "
          f"({total/60:.1f} min total)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
