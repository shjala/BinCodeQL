#!/usr/bin/env python3
"""scan.py — headless whole-binary BinCodeQL scan.

Drives the full extraction → taint pipeline → Bn* extra-rule pipeline
end-to-end with no LLM in the loop. Aggregates the resulting BnFinding
and TaintedSink rows into a single ranked candidates.json on disk,
ready for downstream per-finding triage sessions (step 2 of the
scan-mode refactor).

This is the "scan mode" entry-point. For interactive exploration
("look at function X"), keep using `agent.py`.

Usage:
    python scan.py --binary /path/to/target            -a
    python scan.py --binary /path/to/target.bndb       -f f1,f2,f3
    python scan.py --binary /path/to/target -o run/2026-04-27 -a
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path

PROJECT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_DIR))

from dotenv import load_dotenv  # noqa: E402

import pipeline  # noqa: E402
from bn_utils import extract_facts_batch  # noqa: E402

load_dotenv(override=True)

DEFAULT_RULES_DIR = PROJECT_DIR / "rules"

# Severity rank for ordering. Lower = more urgent.
_SEV_RANK = {"high": 0, "medium": 1, "low": 2, "": 3}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--binary", required=True,
                   help="Path to binary or .bndb database to analyze.")
    sel = p.add_mutually_exclusive_group(required=True)
    sel.add_argument("-a", "--all", action="store_true",
                     help="Extract facts for all functions in the binary.")
    sel.add_argument("-f", "--functions",
                     help="Comma-separated list of function names to extract.")
    p.add_argument("-o", "--output-dir",
                   default=str(PROJECT_DIR / "scan_out"),
                   help="Directory for facts + souffle outputs + candidates.json. "
                        "Will be created if missing.")
    p.add_argument("--taint-timeout", type=int, default=300,
                   help="Per-pass timeout for alias.dl / interproc.dl (default 300s).")
    p.add_argument("--bn-timeout", type=int, default=300,
                   help="Per-pass timeout for each bn_*.dl rule (default 300s).")
    p.add_argument("--skip-extract", action="store_true",
                   help="Skip extraction (assume facts/ in --output-dir is current).")
    return p.parse_args()


def aggregate_candidates(souffle_out: Path) -> list[dict]:
    """Aggregate BnFinding + TaintedSink rows into a uniform candidate list.

    Each candidate carries a stable id (source:func:addr:category) so a
    downstream triage step can address it deterministically. The
    candidate dict preserves the source-relation columns verbatim — the
    triage agent will consult these alongside the function's facts.
    """
    candidates: list[dict] = []

    bnf = souffle_out / "BnFinding.csv"
    if bnf.exists():
        with open(bnf, newline="") as f:
            for row in csv.reader(f, delimiter="\t"):
                if len(row) < 6:
                    continue
                func, addr, severity, category, var, detail = row[:6]
                candidates.append({
                    "id": f"BnFinding:{func}:{addr}:{category}",
                    "source": "BnFinding",
                    "func": func,
                    "addr": addr,
                    "severity": severity,
                    "category": category,
                    "var": var,
                    "detail": detail,
                })

    ts = souffle_out / "TaintedSink.csv"
    if ts.exists():
        with open(ts, newline="") as f:
            for row in csv.reader(f, delimiter="\t"):
                if len(row) < 7:
                    continue
                caller, callee, call_addr, arg_idx, tvar, risk, origin = row[:7]
                # Sinks already covered by BnFinding's `unguarded_tainted_sink`
                # category will appear twice — keep both for now; the triage
                # step dedups by (func, addr) when grouping per function.
                candidates.append({
                    "id": f"TaintedSink:{caller}:{call_addr}:{callee}:{arg_idx}",
                    "source": "TaintedSink",
                    "func": caller,
                    "addr": call_addr,
                    "severity": "medium",  # default — risk field is descriptive
                    "category": f"tainted_sink_{risk}" if risk else "tainted_sink",
                    "var": tvar,
                    "detail": f"callee={callee} arg_idx={arg_idx} origin={origin}",
                    "callee": callee,
                    "arg_idx": arg_idx,
                    "risk": risk,
                    "origin": origin,
                })

    candidates.sort(key=lambda c: (
        _SEV_RANK.get(c.get("severity", ""), 99),
        c.get("source", ""),
        c.get("func", ""),
        c.get("addr", ""),
    ))
    return candidates


def main() -> int:
    args = parse_args()
    out_dir = Path(args.output_dir).resolve()
    facts_dir = out_dir / "facts"
    souffle_out = out_dir / "souffle_out"
    facts_dir.mkdir(parents=True, exist_ok=True)
    souffle_out.mkdir(parents=True, exist_ok=True)

    jobs = os.getenv("SOUFFLE_JOBS", "auto")
    compile_mode = os.getenv("SOUFFLE_COMPILE", "0") not in ("0", "", "false", "False")

    # ── Phase 1: extraction ───────────────────────────────────────────────
    if args.skip_extract:
        print(f"[1/4] Extraction: SKIPPED (reusing {facts_dir})")
    else:
        t0 = time.time()
        if args.all:
            ex = extract_facts_batch(args.binary, None, str(facts_dir), extract_all=True)
        else:
            funcs = [f.strip() for f in args.functions.split(",") if f.strip()]
            ex = extract_facts_batch(args.binary, funcs, str(facts_dir), extract_all=False)
        if "error" in ex:
            print(f"[1/4] Extraction FAILED: {ex['error']}", file=sys.stderr)
            return 1
        print(f"[1/4] Extraction OK ({time.time()-t0:.1f}s) — "
              f"{ex.get('functions_processed', '?')} fns, "
              f"{ex.get('total_facts', '?')} facts")

    # ── Phase 2: taint pipeline (alias.dl → interproc.dl) ─────────────────
    t0 = time.time()
    tr = pipeline.run_taint_pipeline(
        facts_dir, souffle_out, DEFAULT_RULES_DIR,
        timeout_seconds=args.taint_timeout,
        jobs=jobs, compile_mode=compile_mode,
    )
    if "error" in tr:
        print(f"[2/4] Taint pipeline ERROR ({time.time()-t0:.1f}s): {tr['error']}",
              file=sys.stderr)
        # Continue — Bn* structural tiers still fire on partial taint output.
    else:
        n_outputs = len(tr.get("outputs", {}))
        print(f"[2/4] Taint pipeline OK ({time.time()-t0:.1f}s) — "
              f"{n_outputs} non-empty relations")

    # ── Phase 3: Bn* extra rules ──────────────────────────────────────────
    t0 = time.time()
    br = pipeline.run_bn_extra_rules(
        facts_dir, souffle_out, DEFAULT_RULES_DIR,
        timeout_seconds=args.bn_timeout,
        jobs=jobs, compile_mode=compile_mode,
    )
    if "error" in br:
        print(f"[3/4] Bn* rules ERROR ({time.time()-t0:.1f}s): {br['error']}",
              file=sys.stderr)
    else:
        non_empty = sum(1 for v in br.get("outputs", {}).values()
                        if v.get("rows", 0) > 0)
        print(f"[3/4] Bn* rules OK ({time.time()-t0:.1f}s) — "
              f"{non_empty} non-empty Bn* relations")

    # ── Phase 4: aggregate candidates ─────────────────────────────────────
    candidates = aggregate_candidates(souffle_out)
    cand_path = out_dir / "candidates.json"
    summary = {
        "binary": args.binary,
        "facts_dir": str(facts_dir),
        "souffle_out": str(souffle_out),
        "candidate_count": len(candidates),
        "by_severity": _count_by(candidates, "severity"),
        "by_source": _count_by(candidates, "source"),
        "by_category": _count_by(candidates, "category"),
        "candidates": candidates,
    }
    cand_path.write_text(json.dumps(summary, indent=2))

    print(f"[4/4] Aggregation OK — {len(candidates)} candidates → {cand_path}")
    print(f"      by severity: {summary['by_severity']}")
    print(f"      by source:   {summary['by_source']}")
    return 0


def _count_by(items: list[dict], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        out[it.get(key, "")] = out.get(it.get(key, ""), 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


if __name__ == "__main__":
    sys.exit(main())
