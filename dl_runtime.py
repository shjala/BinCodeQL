"""On-demand Datalog runtime — execute LLM-authored rules at triage time.

Companion to `pipeline.py`, which runs the precomputed pipeline rule
files. This module accepts arbitrary Datalog source from the triage
agent, runs it via souffle against an existing facts directory, and
returns either parsed output relations OR a structured error record
the agent can use to fix its rule and retry.

The error-feedback loop is the whole point of having this. LLM-
authored Datalog will frequently miss arity, types, or .input
declarations on the first try; the agent reads `souffle_stderr` plus
the line-numbered source we hand back, fixes it, and resubmits.

Design choices:
  * `souffle_stderr` is passed through verbatim (capped at 16KB only
    as a safety against runaway error cascades; truncation is signaled
    in the response).
  * The submitted rule text is returned with `<line> | ` markers so the
    agent can match `<file>:<line>:<col>` errors directly to its source
    without having to re-count.
  * Output rows per relation are capped at 500 to avoid blowing the
    LLM's context with a runaway query — `truncated=true` flags this
    so the agent can re-run with a tighter filter.
"""

from __future__ import annotations

import csv
import subprocess
import tempfile
import time
from pathlib import Path

import pipeline


_STDERR_CAP_BYTES = 16 * 1024
_STDOUT_CAP_BYTES = 8 * 1024
_OUTPUT_ROW_CAP = 500


def _line_number_source(text: str) -> str:
    """Prepend `<line> | ` markers so souffle's <file>:<line>:<col>
    error messages align with what the agent sees."""
    lines = text.splitlines() or [""]
    width = len(str(len(lines)))
    return "\n".join(
        f"{i + 1:>{width}} | {line}" for i, line in enumerate(lines)
    )


def _read_csv(p: Path) -> list[list[str]]:
    if not p.exists() or p.stat().st_size == 0:
        return []
    with open(p, newline="") as f:
        return [row for row in csv.reader(f, delimiter="\t") if row]


def _cap(s: str, n: int) -> tuple[str, bool]:
    """Cap string at n bytes (UTF-8). Returns (capped, was_truncated)."""
    if len(s) <= n:
        return s, False
    return s[:n] + f"\n[...truncated {len(s) - n} more bytes]", True


def compose_and_run(
    rule_text: str,
    facts_dir: str | Path,
    output_relations: list[str],
    timeout_seconds: int = 60,
    jobs: str = "auto",
) -> dict:
    """Author + execute Datalog `rule_text` against `facts_dir`.

    Args:
        rule_text: Full .dl source. The author MUST declare every
                   input relation it consumes via `.decl X(...)`
                   followed by `.input X` — souffle does not auto-bind
                   to facts/. Likewise, every relation listed in
                   `output_relations` must have a corresponding
                   `.output Foo` directive.
        facts_dir: Directory containing the existing .facts files.
        output_relations: Names of derived relations to read back.
        timeout_seconds: Per-query timeout (default 60s — small,
                         because triage queries should be narrowly
                         scoped).
        jobs: Souffle `-j` argument (default "auto").

    Returns one of these structured dicts (always includes the
    `status` key):

      * status="ok":
          {"status": "ok",
           "outputs": {rel: {"rows": [[...]], "row_count": N,
                             "truncated": bool}, ...},
           "elapsed_seconds": float}

      * status="error":
          {"status": "error",
           "souffle_stderr": str,            # full stderr (capped)
           "souffle_stdout": str,            # may also be informative
           "rule_text_with_line_numbers": str,  # `1 | .decl ...`
           "elapsed_seconds": float,
           "stderr_truncated": bool}         # absent if not truncated

      * status="timeout":
          {"status": "timeout",
           "timeout_seconds": int,
           "elapsed_seconds": float}

      * status="no_outputs":  (souffle ran cleanly but produced no
        non-empty CSVs for the requested output relations — usually a
        sign the rule body never matched any facts)
          {"status": "no_outputs",
           "souffle_stderr": str,
           "elapsed_seconds": float}
    """
    fdir = Path(facts_dir)
    t0 = time.time()

    with tempfile.TemporaryDirectory(prefix="dl_runtime_") as td:
        td_p = Path(td)
        rule_file = td_p / "query.dl"
        rule_file.write_text(rule_text)
        out_dir = td_p / "out"
        out_dir.mkdir()

        cmd = pipeline.souffle_cmd(rule_file, fdir, out_dir,
                                   jobs=jobs, compile_mode=False)

        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "timeout_seconds": timeout_seconds,
                "elapsed_seconds": time.time() - t0,
            }

        elapsed = time.time() - t0
        stderr_capped, stderr_trunc = _cap(r.stderr or "", _STDERR_CAP_BYTES)
        stdout_capped, _ = _cap(r.stdout or "", _STDOUT_CAP_BYTES)

        if r.returncode != 0:
            result = {
                "status": "error",
                "souffle_stderr": stderr_capped,
                "souffle_stdout": stdout_capped,
                "rule_text_with_line_numbers": _line_number_source(rule_text),
                "elapsed_seconds": elapsed,
            }
            if stderr_trunc:
                result["stderr_truncated"] = True
            return result

        outputs: dict = {}
        any_nonempty = False
        for rel in output_relations:
            csv_path = out_dir / f"{rel}.csv"
            rows = _read_csv(csv_path)
            if rows:
                any_nonempty = True
            truncated = len(rows) > _OUTPUT_ROW_CAP
            if truncated:
                rows = rows[:_OUTPUT_ROW_CAP]
            outputs[rel] = {
                "rows": rows,
                "row_count": len(rows),
                "truncated": truncated,
            }

        if not any_nonempty:
            return {
                "status": "no_outputs",
                "souffle_stderr": stderr_capped,
                "elapsed_seconds": elapsed,
                # Still return the empty outputs dict so the agent
                # can confirm its rule was syntactically accepted.
                "outputs": outputs,
            }

        return {
            "status": "ok",
            "outputs": outputs,
            "elapsed_seconds": elapsed,
        }
