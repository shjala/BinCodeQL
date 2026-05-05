"""BinCodeQL Souffle pipeline driver — headless, no LLM/agent dependencies.

Pure-Python wrappers around the Souffle subprocess invocations and
multi-pass staging logic that previously lived inline in `agent.py`'s
`tool_run_taint_pipeline` and `tool_run_bn_extra_rules`. Lifting them
into a standalone module lets both the interactive agent and the
forthcoming `scan.py` CLI share a single execution path — preserving
verifiable, fact-driven results regardless of entry-point.

Each function takes explicit paths and knobs; no reliance on agent.py
module-level state. Behavior is identical to the original tool bodies.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional


def souffle_cmd(
    rule_path: str | Path,
    facts_dir: str | Path,
    output_dir: str | Path,
    jobs: str = "auto",
    compile_mode: bool = False,
) -> list[str]:
    """Build the souffle subprocess argv with the given evaluation knobs.

    Centralized so every caller — interactive tools, scan CLI, future
    triage harness — uses the same evaluation mode without duplicating
    flag logic.

    Args:
        rule_path: Path to the .dl rule file.
        facts_dir: Directory holding input .facts files.
        output_dir: Directory where Souffle should write .csv outputs.
        jobs: `-j` argument. "auto" enables multi-core; "1" disables;
              any other string is passed through.
        compile_mode: If True, append `-c` to compile the .dl to C++
                      then execute (faster on large fact sets, ~1–2 min
                      compile overhead per rule file on first run).

    Returns:
        argv list ready for `subprocess.run`.
    """
    cmd = ["souffle", "-F", str(facts_dir), "-D", str(output_dir)]
    if jobs and jobs != "1":
        cmd.extend(["-j", str(jobs)])
    if compile_mode:
        cmd.append("-c")
    cmd.append(str(rule_path))
    return cmd


def stage_signature_facts(
    facts_dir: str | Path,
    output_dir: str | Path,
    rules_dir: str | Path,
    timeout_seconds: int = 30,
    jobs: str = "1",
    compile_mode: bool = False,
) -> dict:
    """Run signatures.dl to materialize TaintTransfer/BufferWriteSource/TaintKill.

    signatures.dl declares these relations as constants (`TaintTransfer("read",
    "arg1", "external").` etc.) and emits them via `.output`. Downstream
    interproc.dl/taint.dl declare the same relations with `.input`, expecting
    facts files. This staging step bridges the two: runs signatures.dl, then
    copies the resulting CSVs into facts_dir as .facts so interproc.dl can
    seed taint from libc sources (read/mmap/getopt/etc.).

    Without this step, TaintTransfer.facts is empty and TaintedVar = ∅.

    Args:
        facts_dir: Directory where `*.facts` will be written.
        output_dir: Souffle CSV output directory (signatures.dl will write
                    TaintTransfer.csv etc. here).
        rules_dir: Directory containing signatures.dl.
        timeout_seconds: Souffle timeout (signatures.dl is small — 30s ample).

    Returns:
        Dict with row counts of each staged signature relation.
    """
    fdir = Path(facts_dir)
    odir = Path(output_dir)
    rdir = Path(rules_dir)
    fdir.mkdir(parents=True, exist_ok=True)
    odir.mkdir(parents=True, exist_ok=True)

    sig_dl = rdir / "signatures.dl"
    if not sig_dl.exists():
        return {"error": f"Rule file not found: {sig_dl}"}

    try:
        r = subprocess.run(
            souffle_cmd(sig_dl, fdir, odir, jobs, compile_mode),
            capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"signatures.dl timed out after {timeout_seconds}s"}

    result: dict = {"return_code": r.returncode}
    if r.returncode != 0:
        result["stderr"] = r.stderr.strip()
        return result

    for rel in ("TaintTransfer", "BufferWriteSource", "TaintKill"):
        src = odir / f"{rel}.csv"
        dst = fdir / f"{rel}.facts"
        if src.exists():
            content = src.read_text()
            dst.write_text(content)
            stripped = content.strip()
            result[rel] = stripped.count("\n") + 1 if stripped else 0
        else:
            dst.touch()
            result[rel] = 0

    return result


def run_taint_pipeline(
    facts_dir: str | Path,
    output_dir: str | Path,
    rules_dir: str | Path,
    timeout_seconds: int = 60,
    jobs: str = "auto",
    compile_mode: bool = False,
) -> dict:
    """Run alias.dl → interproc.dl with PointsTo staging in between.

    Pass 1: alias.dl computes PointsTo. Pass 2: copies PointsTo.csv into
    facts_dir as PointsTo.facts, then runs interproc.dl with
    alias-enhanced taint.

    Args:
        facts_dir: Directory with .facts inputs (PointsTo.facts will be
                   written here between passes).
        output_dir: Directory for .csv outputs. Stale CSVs are cleared
                    before each pass.
        rules_dir: Directory containing alias.dl and interproc.dl.
        timeout_seconds: Per-pass timeout.
        jobs / compile_mode: Forwarded to `souffle_cmd`.

    Returns:
        Dict with pass1_alias / pass2_interproc status and outputs.
    """
    fdir = Path(facts_dir)
    odir = Path(output_dir)
    rdir = Path(rules_dir)
    odir.mkdir(parents=True, exist_ok=True)

    results: dict = {"pass1_alias": {}, "pass2_interproc": {}, "outputs": {}}

    alias_dl = rdir / "alias.dl"
    if not alias_dl.exists():
        return {"error": f"Rule file not found: {alias_dl}"}

    for stale in odir.glob("*.csv"):
        stale.unlink()

    try:
        r1 = subprocess.run(
            souffle_cmd(alias_dl, fdir, odir, jobs, compile_mode),
            capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Pass 1 (alias.dl) timed out after {timeout_seconds}s"}

    if r1.returncode != 0:
        results["pass1_alias"]["error"] = r1.stderr.strip()
        # Continue anyway — interproc.dl has fallback rules for empty PointsTo.
    else:
        results["pass1_alias"]["return_code"] = r1.returncode

    for f in sorted(odir.glob("*.csv")):
        content = f.read_text().strip()
        if content:
            lines = content.split('\n')
            results["pass1_alias"][f.name] = len(lines)

    pts_src = odir / "PointsTo.csv"
    pts_dst = fdir / "PointsTo.facts"
    if pts_src.exists():
        pts_content = pts_src.read_text().strip()
        if pts_content:
            pts_dst.write_text(pts_content + '\n')
            results["points_to_facts"] = pts_content.count('\n') + 1
        else:
            pts_dst.touch()
            results["points_to_facts"] = 0
    else:
        pts_dst.touch()
        results["points_to_facts"] = 0

    interproc_dl = rdir / "interproc.dl"
    if not interproc_dl.exists():
        return {"error": f"Rule file not found: {interproc_dl}"}

    for stale in odir.glob("*.csv"):
        stale.unlink()

    try:
        r2 = subprocess.run(
            souffle_cmd(interproc_dl, fdir, odir, jobs, compile_mode),
            capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Pass 2 (interproc.dl) timed out after {timeout_seconds}s"}

    results["pass2_interproc"]["return_code"] = r2.returncode
    if r2.returncode != 0:
        results["pass2_interproc"]["stderr"] = r2.stderr.strip()

    for f in sorted(odir.glob("*.csv")):
        content = f.read_text().strip()
        if content:
            lines = content.split('\n')
            results["outputs"][f.name] = {
                "rows": len(lines),
                "preview": lines[:20],
            }

    return results


# Output relations from interproc.dl that downstream Bn* rules consume.
# Staged as .facts before bn_flow.dl runs; empty placeholders are written
# when an upstream pass failed, so structural Bn* tiers still fire.
_TAINT_OUTPUTS = [
    "TaintedVar", "PointsTo", "TaintedSink", "GuardedSink",
    "TaintedBuffer", "TaintedField", "SanitizedVar",
    "TaintedHeapObject",
]

# Per-rule CSV → facts staging table. After each Bn* rule runs, these
# CSVs from output_dir are copied into facts_dir so subsequent rules
# can read them via .input. Order matters: bn_flow.dl produces BnFlow
# which everything downstream consumes.
_BN_STAGE_AFTER: dict[str, list[tuple[str, str]]] = {
    "bn_flow.dl":           [("BnFlow.csv",                   "BnFlow.facts")],
    "bn_signed_infer.dl":   [("BnSignedness.csv",             "BnSignedness.facts")],
    "bn_counter_oob.dl":    [("BnUnboundedCounter.csv",       "BnUnboundedCounter.facts"),
                             ("BnTaintedUnboundedCounter.csv","BnTaintedUnboundedCounter.facts"),
                             ("BnCounterUsedAsIndex.csv",     "BnCounterUsedAsIndex.facts"),
                             ("BnTaintedCounterAsIndex.csv",  "BnTaintedCounterAsIndex.facts")],
    "bn_alloc_copy.dl":     [("BnAllocCopyMismatch.csv",      "BnAllocCopyMismatch.facts"),
                             ("BnAllocThenUnboundedCopy.csv", "BnAllocThenUnboundedCopy.facts"),
                             ("BnAllocSite.csv",              "BnAllocSite.facts")],
    "bn_unguarded_sink.dl": [("BnUnguardedTaintedSink.csv",   "BnUnguardedTaintedSink.facts")],
    "bn_loop_bound.dl":     [("BnTaintedLoopBound.csv",       "BnTaintedLoopBound.facts")],
    "bn_unguarded_cast.dl": [("BnUnguardedDangerousCast.csv", "BnUnguardedDangerousCast.facts")],
    "bn_arith_overflow.dl": [("BnTaintedOverflowAtSink.csv",  "BnTaintedOverflowAtSink.facts")],
    "bn_width_mismatch.dl": [("BnNarrowStore.csv",            "BnNarrowStore.facts"),
                             ("BnWidthMismatchStore.csv",     "BnWidthMismatchStore.facts"),
                             ("BnWidthMismatchCounter.csv",   "BnWidthMismatchCounter.facts")],
    "bn_sentinel_init.dl":  [("BnSentinelInit.csv",           "BnSentinelInit.facts"),
                             ("BnSentinelBuf.csv",            "BnSentinelBuf.facts"),
                             ("BnSentinelNarrowAlloc.csv",    "BnSentinelNarrowAlloc.facts"),
                             ("BnSentinelCollisionRisk.csv",  "BnSentinelCollisionRisk.facts")],
    "bn_null_deref.dl":     [("BnNullDeref.csv",              "BnNullDeref.facts")],
    "bn_guard_dominates.dl": [("GuardDominates.csv",           "GuardDominates.facts"),
                              ("BnGuardSubsumedSink.csv",      "BnGuardSubsumedSink.facts"),
                              ("BnUnguardedDom.csv",           "BnUnguardedDom.facts"),
                              ("Dominates.csv",                "Dominates.facts")],
    "bn_findings.dl":        [("BnFinding.csv",                "BnFinding.facts"),
                              ("BnFindingDomGuarded.csv",      "BnFindingDomGuarded.facts"),
                              ("BnFindingDomUnguarded.csv",    "BnFindingDomUnguarded.facts")],
    "bn_findings_rank.dl":   [("BnFindingCluster.csv",         "BnFindingCluster.facts"),
                              ("BnFindingScore.csv",           "BnFindingScore.facts"),
                              ("BnFindingRanked.csv",          "BnFindingRanked.facts"),
                              ("BnFindingDomGuardedTight.csv", "BnFindingDomGuardedTight.facts"),
                              ("BnFindingDomGuardedLoose.csv", "BnFindingDomGuardedLoose.facts"),
                              ("BnGuardBoundTight.csv",        "BnGuardBoundTight.facts")],
    # Stage buffer-attribution evidence so triage's ad-hoc Datalog
    # queries can `.input` these relations from the facts dir.
    # Both the strict (single-hop) and transitive (multi-hop)
    # variants are staged — triage prefers the *T variants by default
    # but can opt into the strict ones if the multi-hop closure
    # introduces too much over-approximation for a particular case.
    "buffer_attribution.dl": [
        ("AllocFieldStash.csv",                 "AllocFieldStash.facts"),
        ("ConsumerFieldLoad.csv",               "ConsumerFieldLoad.facts"),
        ("BufferReachesConsumer.csv",           "BufferReachesConsumer.facts"),
        ("Uint16TruncStoreOnAllocBuffer.csv",   "Uint16TruncStoreOnAllocBuffer.facts"),
        ("AllocFieldStashTransitive.csv",       "AllocFieldStashTransitive.facts"),
        ("BufferReachesConsumerT.csv",          "BufferReachesConsumerT.facts"),
        ("Uint16TruncStoreOnAllocBufferT.csv",  "Uint16TruncStoreOnAllocBufferT.facts"),
        ("TruncDerived.csv",                    "TruncDerived.facts"),
    ],
}

_BN_RULE_FILES = [
    "bn_flow.dl",
    "bn_signed_infer.dl",
    "bn_counter_oob.dl",
    "bn_alloc_copy.dl",
    "bn_unguarded_sink.dl",
    "bn_loop_bound.dl",
    "bn_unguarded_cast.dl",
    "bn_arith_overflow.dl",
    "bn_width_mismatch.dl",
    "bn_sentinel_init.dl",
    "bn_null_deref.dl",
    # Path-sensitive guard subsumption (CFG-dominance refinement of
    # GuardedSink). Requires CFGBlockEdge + BlockHead from the
    # extractor. Runs after structural Bn* rules so its outputs
    # (BnGuardSubsumedSink, BnUnguardedDom) can refine downstream
    # triage without affecting earlier passes.
    "bn_guard_dominates.dl",
    "bn_findings.dl",
    # Cluster + rank BnFinding into a triage-ready Top-K. Refines
    # dom-guards into tight (constant, constraining) vs loose (symbolic
    # or large-constant) and emits BnFindingScore / BnFindingRanked
    # so triage can focus on the ~100-200 highest-priority cluster
    # heads instead of all ~30K raw findings.
    "bn_findings_rank.dl",
    # Cross-function buffer-attribution evidence chain — derives
    # AllocFieldStash, ConsumerFieldLoad, BufferReachesConsumer,
    # Uint16TruncStoreOnAllocBuffer. Not a finding-producing rule;
    # consumed by the triage agent as cross-function evidence for
    # sentinel_collision*, alloc_copy_*, and width_mismatch_counter.
    "buffer_attribution.dl",
]


def run_bn_extra_rules(
    facts_dir: str | Path,
    output_dir: str | Path,
    rules_dir: str | Path,
    timeout_seconds: int = 120,
    jobs: str = "auto",
    compile_mode: bool = False,
) -> dict:
    """Run the Bn* extra-rule pipeline (ported from NeuroLog).

    Additive — does NOT clear non-Bn* CSVs in output_dir. Stages
    intermediate CSVs back to facts_dir between passes so downstream
    rules can consume them via .input. Auto-stages TaintedVar /
    PointsTo / TaintedSink / GuardedSink etc. from a prior taint
    pipeline run; missing inputs become empty placeholders so
    structural tiers still fire even on partial taint runs.

    Args:
        facts_dir: Directory with .facts files (also used for staging).
        output_dir: Directory for .csv outputs.
        rules_dir: Directory containing bn_*.dl rule files.
        timeout_seconds: Per-pass timeout.
        jobs / compile_mode: Forwarded to `souffle_cmd`.

    Returns:
        Dict with per-pass status + row counts of Bn* outputs.
    """
    fdir = Path(facts_dir)
    odir = Path(output_dir)
    rdir = Path(rules_dir)
    odir.mkdir(parents=True, exist_ok=True)

    # Auto-stage upstream taint outputs as .facts. Empty placeholders
    # keep structural Bn* tiers firing when the taint pipeline failed
    # mid-pass — without masking the upstream failure (caller still
    # sees pass2_interproc.stderr from run_taint_pipeline).
    for rel in _TAINT_OUTPUTS:
        csv = odir / f"{rel}.csv"
        facts = fdir / f"{rel}.facts"
        if csv.exists():
            facts.write_text(csv.read_text())
        elif not facts.exists():
            facts.touch()

    results: dict = {"passes": {}, "outputs": {}}

    for rf in _BN_RULE_FILES:
        rf_path = rdir / rf
        if not rf_path.exists():
            return {"error": f"Rule file not found: {rf_path}"}

        try:
            r = subprocess.run(
                souffle_cmd(rf_path, fdir, odir, jobs, compile_mode),
                capture_output=True, text=True, timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            results["passes"][rf] = {"error": f"timed out after {timeout_seconds}s"}
            return results

        results["passes"][rf] = {"return_code": r.returncode}
        if r.returncode != 0:
            results["passes"][rf]["stderr"] = r.stderr.strip()

        for csv_name, facts_name in _BN_STAGE_AFTER.get(rf, []):
            src = odir / csv_name
            dst = fdir / facts_name
            if src.exists():
                content = src.read_text().strip()
                dst.write_text(content + "\n" if content else "")

    for f in sorted(odir.glob("Bn*.csv")):
        content = f.read_text().strip()
        rows = len(content.split("\n")) if content else 0
        results["outputs"][f.name] = {
            "rows": rows,
            "preview": content.split("\n")[:10] if content else [],
        }

    return results
