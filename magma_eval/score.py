#!/usr/bin/env python3
# score.py
#
# Score BinCodeQL eval runs against the magma ground truth.
#
# Inputs:
#   * magma_eval/bugs.json       — ground truth (bug_id, target, file, function)
#   * magma_eval/eval_set.json   — function set (buggy + negative-control)
#   * magma_eval/runs/<target>-<variant>/candidates.json
#   * magma_eval/runs/<target>-<variant>/verdicts/*.json
#
# Outputs:
#   * magma_eval/scores/<target>-<variant>.csv      — per-function rollup
#   * magma_eval/scores/<target>-<variant>.summary  — counts + recall/precision
#   * magma_eval/scores/all_summary.csv             — cross-binary table
#
# Scoring rules:
#   - A finding is a "hit" on a buggy function iff the agent's verdict is
#     in {real, guarded} AND the function name matches a buggy entry.
#   - A finding on a negative-control function with verdict in {real,
#     guarded} is a false positive.
#   - A buggy function for which NO finding fires (or all findings come
#     back FP/UNDETERMINED) is a false negative for every bug ID it
#     anchors.
#   - Variant comparison: the "patched" run should ideally see fewer
#     real verdicts on the buggy functions; we report Δ between vuln
#     and patched as paper-evidence of patch sensitivity.

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
RUNS_DIR = ROOT / "runs"
SCORES_DIR = ROOT / "scores"

POSITIVE_VERDICTS = {"real", "guarded", "confirmed", "true_positive", "tp"}
NEGATIVE_VERDICTS = {"fp", "false_positive", "not_a_bug", "benign"}
INDETERMINATE = {"undetermined", "unknown"}


def normalize_verdict(v: str | None) -> str:
    if not v:
        return "missing"
    s = v.strip().lower()
    if s in POSITIVE_VERDICTS:
        return "real"
    if s in NEGATIVE_VERDICTS:
        return "fp"
    if s in INDETERMINATE:
        return "undetermined"
    return s


def load_eval_set(path: Path, target: str) -> tuple[set[str], dict[str, list[str]]]:
    """Return (negatives_names, buggy_name_to_bug_ids)."""
    payload = json.loads(path.read_text())
    bucket = payload["targets"][target]
    buggy: dict[str, list[str]] = {}
    for f in bucket["buggy_present"]:
        buggy.setdefault(f["name"], []).extend(f.get("bug_ids", []))
    for k in list(buggy):
        buggy[k] = sorted(set(buggy[k]))
    negs = {f["name"] for f in bucket["negatives"]}
    return negs, buggy


def collect_verdicts(run_dir: Path) -> list[dict]:
    """Return list of {id, func, addr, category, verdict, confidence}."""
    cand_path = run_dir / "candidates.json"
    verdicts_dir = run_dir / "verdicts"
    if not cand_path.exists():
        return []
    summary = json.loads(cand_path.read_text())
    cands = {c["id"]: c for c in summary.get("candidates", [])}

    out: list[dict] = []
    if verdicts_dir.exists():
        for vp in sorted(verdicts_dir.glob("*.json")):
            try:
                v = json.loads(vp.read_text())
            except Exception:
                continue
            fid = v.get("id") or vp.stem.replace("_", ":", 3)
            cand = cands.get(fid, {})
            out.append({
                "id": fid,
                "func": v.get("func") or cand.get("func", ""),
                "addr": v.get("addr") or cand.get("addr", ""),
                "category": cand.get("category", ""),
                "verdict_raw": v.get("verdict", ""),
                "verdict": normalize_verdict(v.get("verdict")),
                "confidence": v.get("confidence", ""),
            })
    # Also surface candidates that were never triaged (so we can see
    # missing-coverage directly).
    triaged_ids = {r["id"] for r in out}
    for cid, c in cands.items():
        if cid not in triaged_ids:
            out.append({
                "id": cid,
                "func": c.get("func", ""),
                "addr": c.get("addr", ""),
                "category": c.get("category", ""),
                "verdict_raw": "",
                "verdict": "missing",
                "confidence": "",
            })
    return out


def score_target(target: str, variant: str) -> dict | None:
    run_dir = RUNS_DIR / f"{target}-{variant}"
    if not run_dir.is_dir():
        print(f"[score] no run dir for {target}-{variant}", file=sys.stderr)
        return None

    negatives, buggy = load_eval_set(ROOT / "eval_set.json", target)
    findings = collect_verdicts(run_dir)

    # Per-function rollup
    per_func: dict[str, dict] = {}
    for fn in list(buggy) + sorted(negatives):
        per_func[fn] = {
            "name": fn,
            "role": "buggy" if fn in buggy else "negative",
            "bug_ids": ",".join(buggy.get(fn, [])),
            "n_findings": 0,
            "n_real": 0,
            "n_fp": 0,
            "n_undetermined": 0,
            "n_missing": 0,
        }

    for f in findings:
        fn = f["func"]
        if fn not in per_func:
            per_func[fn] = {
                "name": fn, "role": "other", "bug_ids": "",
                "n_findings": 0, "n_real": 0, "n_fp": 0,
                "n_undetermined": 0, "n_missing": 0,
            }
        per_func[fn]["n_findings"] += 1
        v = f["verdict"]
        if v == "real":
            per_func[fn]["n_real"] += 1
        elif v == "fp":
            per_func[fn]["n_fp"] += 1
        elif v == "undetermined":
            per_func[fn]["n_undetermined"] += 1
        else:
            per_func[fn]["n_missing"] += 1

    # Bug-level TP/FN
    bug_tp: set[str] = set()
    bug_fn: set[str] = set()
    for fn, bids in buggy.items():
        if per_func[fn]["n_real"] > 0:
            for bid in bids:
                bug_tp.add(bid)
        else:
            for bid in bids:
                bug_fn.add(bid)

    # Function-level FP: any negative-control with at least one "real"
    fp_funcs = sum(1 for fn in negatives if per_func[fn]["n_real"] > 0)

    # Persist CSV
    SCORES_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = SCORES_DIR / f"{target}-{variant}.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["function", "role", "bug_ids", "n_findings",
                    "n_real", "n_fp", "n_undetermined", "n_missing"])
        for fn in sorted(per_func, key=lambda k: (per_func[k]["role"] != "buggy", k)):
            r = per_func[fn]
            w.writerow([r["name"], r["role"], r["bug_ids"], r["n_findings"],
                        r["n_real"], r["n_fp"], r["n_undetermined"], r["n_missing"]])

    n_buggy = len(buggy)
    n_neg = len(negatives)
    n_bugs = sum(len(v) for v in buggy.values())
    summary = {
        "target": target,
        "variant": variant,
        "n_buggy_functions": n_buggy,
        "n_negative_functions": n_neg,
        "n_bugs": n_bugs,
        "bug_tp": len(bug_tp),
        "bug_fn": len(bug_fn),
        "function_fp": fp_funcs,
        "recall_bug": round(len(bug_tp) / n_bugs, 3) if n_bugs else 0.0,
        "precision_func": (
            round(len([fn for fn in buggy if per_func[fn]["n_real"] > 0]) /
                  max(1, len([fn for fn in buggy if per_func[fn]["n_real"] > 0])
                      + fp_funcs), 3)
        ),
        "csv": str(csv_path.relative_to(ROOT)),
        "tp_bug_ids": sorted(bug_tp),
        "fn_bug_ids": sorted(bug_fn),
    }
    (SCORES_DIR / f"{target}-{variant}.summary").write_text(
        json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", choices=("libtiff", "libxml2", "all"),
                    default="all")
    ap.add_argument("--variant", choices=("vuln", "patched", "both"),
                    default="both")
    args = ap.parse_args()

    targets = (("libtiff", "libxml2") if args.target == "all"
               else (args.target,))
    variants = (("vuln", "patched") if args.variant == "both"
                else (args.variant,))

    summaries: list[dict] = []
    for t in targets:
        for v in variants:
            s = score_target(t, v)
            if s:
                summaries.append(s)

    if not summaries:
        print("[score] no runs found", file=sys.stderr)
        return 1

    SCORES_DIR.mkdir(parents=True, exist_ok=True)
    with open(SCORES_DIR / "all_summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["target", "variant", "n_bugs", "bug_tp", "bug_fn",
                    "function_fp", "recall_bug", "precision_func"])
        for s in summaries:
            w.writerow([s["target"], s["variant"], s["n_bugs"], s["bug_tp"],
                        s["bug_fn"], s["function_fp"],
                        s["recall_bug"], s["precision_func"]])

    print()
    print(f"{'target':10s} {'variant':8s} bugs  TP  FN  FP-fn  recall   prec")
    print("-" * 60)
    for s in summaries:
        print(f"{s['target']:10s} {s['variant']:8s} "
              f"{s['n_bugs']:4d} {s['bug_tp']:3d} {s['bug_fn']:3d} "
              f"{s['function_fp']:5d} "
              f"  {s['recall_bug']:.2f}   {s['precision_func']:.2f}")
    print()

    # Variant Δ (vuln vs patched): real findings on buggy functions
    # should drop in patched. Surface as a separate small table.
    by_target: dict[str, dict[str, dict]] = defaultdict(dict)
    for s in summaries:
        by_target[s["target"]][s["variant"]] = s
    pairs = [(t, vs) for t, vs in by_target.items()
             if "vuln" in vs and "patched" in vs]
    if pairs:
        print("Patch sensitivity (vuln→patched, lower TP on patched is good):")
        for t, vs in pairs:
            d = vs["vuln"]["bug_tp"] - vs["patched"]["bug_tp"]
            print(f"  {t:10s} TP_vuln={vs['vuln']['bug_tp']:3d}  "
                  f"TP_patched={vs['patched']['bug_tp']:3d}  Δ={d:+d}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
