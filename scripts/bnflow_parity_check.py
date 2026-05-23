#!/usr/bin/env python3
"""A/B parity harness for `BnFlow` vs `BnFlowRelevant`.

This is the D2 false-negative defense from `docs/scaling_roadmap.md`.
For an already-extracted facts directory (taint pipeline + bn_flow.dl
must already have run, producing both BnFlow.csv and BnFlowRelevant.csv
in the output dir), runs every Bn* consumer rule TWICE:

    A:  BnFlowRelevant.facts  symlinked from BnFlow.csv         (full — reference)
    B:  BnFlowRelevant.facts  symlinked from BnFlowRelevant.csv (pruned — new default)

All consumers use `.input BnFlowRelevant` (Phase 2 switchover complete as of
2026-05-22). Run A feeds the *full* BnFlow as a reference so we can detect
any findings that the pruned version drops. The delta must stay within
tolerance (default 5%) before relying on BnFlowRelevant in production.

Usage:
    python scripts/bnflow_parity_check.py FACTS_DIR OUTPUT_DIR [--tol 0.05]

The script does NOT re-run bn_flow.dl — that step is assumed already
complete with both relations staged. It only runs the 13 downstream
Bn* consumers under each variant and compares.

Exit codes:
    0 — every consumer's output row count within tolerance, switchover safe
    1 — at least one consumer regressed beyond tolerance; details printed
    2 — setup error (missing facts/output/relations)
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
import pipeline  # noqa: E402

# Consumers that join against BnFlow. Order matches `pipeline._BN_RULE_FILES`
# minus bn_flow.dl itself. We re-run only the rules that consume BnFlow;
# bn_signed_infer.dl and bn_null_deref.dl don't, so they're skipped.
BN_CONSUMERS = [
    "bn_counter_oob.dl",
    "bn_alloc_copy.dl",
    "bn_unguarded_sink.dl",
    "bn_loop_bound.dl",
    "bn_unguarded_cast.dl",
    "bn_arith_overflow.dl",
    "bn_width_mismatch.dl",
    "bn_sentinel_init.dl",
    "bn_allocator_mismatch.dl",
    "bn_unbounded_sink_audit.dl",
    "bn_joint_buffer_bound.dl",
    "bn_type_confusion.dl",
    "bn_guard_dominates.dl",
    "bn_findings.dl",
]


def _row_count(p: Path) -> int:
    if not p.exists():
        return 0
    content = p.read_text().strip()
    return content.count("\n") + 1 if content else 0


def _snapshot(odir: Path) -> dict[str, int]:
    """Snapshot row counts for every `Bn*.csv` in odir."""
    return {f.name: _row_count(f) for f in sorted(odir.glob("Bn*.csv"))}


def _run_consumers(
    facts_dir: Path,
    output_dir: Path,
    rules_dir: Path,
    timeout_s: int,
) -> None:
    """Run every consumer once against the current BnFlow.facts."""
    for rf in BN_CONSUMERS:
        rule_jobs = pipeline._BN_RULE_JOBS.get(rf, "auto")
        rf_path = rules_dir / rf
        r = subprocess.run(
            pipeline.souffle_cmd(rf_path, facts_dir, output_dir, rule_jobs, False),
            capture_output=True, text=True, timeout=timeout_s,
        )
        if r.returncode != 0:
            print(f"  [warn] {rf} exited {r.returncode}", file=sys.stderr)
            if r.stderr:
                print(f"  stderr (first 500): {r.stderr[:500]}", file=sys.stderr)
        # Stage outputs so subsequent rules see them.
        for csv_name, facts_name in pipeline._BN_STAGE_AFTER.get(rf, []):
            src = output_dir / csv_name
            dst = facts_dir / facts_name
            if src.exists():
                pipeline._stage(src, dst)


def _swap_bnflowrelevant_facts(facts_dir: Path, source_csv: Path) -> None:
    """Repoint `BnFlowRelevant.facts` symlink to `source_csv`."""
    facts_path = facts_dir / "BnFlowRelevant.facts"
    if facts_path.is_symlink() or facts_path.exists():
        facts_path.unlink()
    os.symlink(source_csv.resolve(), facts_path)


def parity_check(
    facts_dir: Path, output_dir: Path, tol: float, timeout_s: int
) -> int:
    rules_dir = REPO_ROOT / "rules"

    bnflow_csv = output_dir / "BnFlow.csv"
    bnflow_rel_csv = output_dir / "BnFlowRelevant.csv"
    if not bnflow_csv.exists():
        print(f"FATAL: {bnflow_csv} missing — run bn_flow.dl first", file=sys.stderr)
        return 2
    if not bnflow_rel_csv.exists():
        print(f"FATAL: {bnflow_rel_csv} missing — run updated bn_flow.dl first", file=sys.stderr)
        return 2

    print(f"BnFlow.csv         : {_row_count(bnflow_csv):>10d} rows")
    print(f"BnFlowRelevant.csv : {_row_count(bnflow_rel_csv):>10d} rows")
    print(f"  shrink ratio: {_row_count(bnflow_rel_csv) / max(_row_count(bnflow_csv), 1):.3f}")
    print()

    # ── Run A (full BnFlow as reference) ───────────────────────────
    # Temporarily feed the full BnFlow.csv into BnFlowRelevant.facts so
    # consumers (which now .input BnFlowRelevant) see the complete TC.
    # This is the "maximally sound" reference run.
    print("[A] Running consumers against BnFlowRelevant.facts ← BnFlow.csv (full reference)")
    _swap_bnflowrelevant_facts(facts_dir, bnflow_csv)
    out_a = output_dir.parent / (output_dir.name + "_parityA")
    out_a.mkdir(parents=True, exist_ok=True)
    for csv in output_dir.glob("*.csv"):
        if not csv.name.startswith("Bn") or csv.name in (
            "BnFlow.csv", "BnFlow1.csv", "BnFlowRelevant.csv",
            "RelevantEndpoint.csv",
        ):
            shutil.copy(csv, out_a / csv.name)
    _run_consumers(facts_dir, out_a, rules_dir, timeout_s)
    snap_a = _snapshot(out_a)

    # ── Run B (pruned BnFlowRelevant — new default) ─────────────────
    print("[B] Running consumers against BnFlowRelevant.facts ← BnFlowRelevant.csv (pruned)")
    _swap_bnflowrelevant_facts(facts_dir, bnflow_rel_csv)
    out_b = output_dir.parent / (output_dir.name + "_parityB")
    out_b.mkdir(parents=True, exist_ok=True)
    for csv in output_dir.glob("*.csv"):
        if not csv.name.startswith("Bn") or csv.name in (
            "BnFlow.csv", "BnFlow1.csv", "BnFlowRelevant.csv",
            "RelevantEndpoint.csv",
        ):
            shutil.copy(csv, out_b / csv.name)
    _run_consumers(facts_dir, out_b, rules_dir, timeout_s)
    snap_b = _snapshot(out_b)

    # Restore BnFlowRelevant.facts to the correct pruned default.
    _swap_bnflowrelevant_facts(facts_dir, bnflow_rel_csv)

    # ── Diff ────────────────────────────────────────────────────────
    all_names = sorted(set(snap_a) | set(snap_b))
    regressions: list[tuple[str, int, int, float]] = []
    print()
    print(f"{'Output':<45} {'A rows':>10} {'B rows':>10} {'Δ':>10} {'Δ%':>8}")
    print("-" * 90)
    for name in all_names:
        a = snap_a.get(name, 0)
        b = snap_b.get(name, 0)
        delta = b - a
        denom = max(a, 1)
        pct = delta / denom
        flag = ""
        if a > 0 and abs(pct) > tol:
            flag = "  *FAIL*"
            regressions.append((name, a, b, pct))
        print(f"{name:<45} {a:>10d} {b:>10d} {delta:>+10d} {pct*100:>+7.1f}%{flag}")

    print()
    if regressions:
        print(f"PARITY FAILED: {len(regressions)} output(s) exceeded tolerance {tol*100:.0f}%")
        for name, a, b, pct in regressions:
            print(f"  {name}: A={a}, B={b}, Δ={pct*100:+.1f}%")
        return 1
    print(f"PARITY OK: all {len(all_names)} outputs within ±{tol*100:.0f}%")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("facts_dir", type=Path)
    ap.add_argument("output_dir", type=Path)
    ap.add_argument("--tol", type=float, default=0.05,
                    help="Tolerance for relative row-count delta (default 0.05 = 5%%)")
    ap.add_argument("--timeout", type=int, default=1800,
                    help="Per-rule timeout in seconds (default 1800)")
    args = ap.parse_args()
    return parity_check(args.facts_dir, args.output_dir, args.tol, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
