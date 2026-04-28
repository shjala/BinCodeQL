#!/usr/bin/env python3
"""Parallel per-finding triage orchestrator.

Reads `<scan_out>/candidates.json`, spawns up to N concurrent ADK
triage sessions (one per finding) using triage_agent.create_triage_agent,
and writes per-finding verdicts to `<scan_out>/verdicts/<id-slug>.json`.

Resumable: skips findings whose verdict file already exists; pass
--force to re-triage. Failures in one session don't stop others —
each finding's outcome is recorded in the summary.

Usage:
    python triage.py --scan-out scan_out/run-X
    python triage.py --scan-out scan_out/run-X -j 4 --severity high
    python triage.py --scan-out scan_out/run-X --limit 5    # smoke test
    python triage.py --scan-out scan_out/run-X --force       # full re-run
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

PROJECT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_DIR))

from dotenv import load_dotenv  # noqa: E402

from google.adk.runners import Runner  # noqa: E402
from google.adk.sessions import InMemorySessionService  # noqa: E402
from google.genai import types  # noqa: E402

import triage_agent  # noqa: E402

load_dotenv(override=True)

DEFAULT_CONCURRENCY = 8
APP_NAME = "bincodeql_triage"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--scan-out", required=True,
                   help="Directory produced by scan.py "
                        "(must contain candidates.json + facts/ + souffle_out/).")
    p.add_argument("-j", "--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                   help=f"Max parallel triage sessions (default {DEFAULT_CONCURRENCY}).")
    p.add_argument("--limit", type=int,
                   help="Triage only the first N (post-filter) candidates. "
                        "Useful for smoke testing.")
    p.add_argument("--force", action="store_true",
                   help="Re-triage findings whose verdict files already exist.")
    p.add_argument("--severity", choices=["high", "medium", "low"],
                   help="Restrict to candidates of this severity.")
    p.add_argument("--source", choices=["BnFinding", "TaintedSink"],
                   help="Restrict to candidates from this Datalog relation.")
    return p.parse_args()


def _slug(finding_id: str) -> str:
    return finding_id.replace(":", "_").replace("/", "_")


async def _triage_one(
    finding: dict,
    scan_out: Path,
    sem: asyncio.Semaphore,
) -> dict:
    """Run one triage session. Returns a status dict — never raises."""
    fid = finding.get("id", "<no-id>")
    async with sem:
        t0 = time.time()
        try:
            agent = triage_agent.create_triage_agent(finding, scan_out)
            session_service = InMemorySessionService()
            session = await session_service.create_session(
                app_name=APP_NAME,
                user_id=f"triage-{_slug(fid)}",
            )
            runner = Runner(
                agent=agent,
                session_service=session_service,
                app_name=APP_NAME,
            )
            kickoff = (
                f"Triage finding id={fid!r}. Begin by calling "
                f"tool_get_finding to load the row, then proceed through the "
                f"6-step methodology described in your instructions, and end "
                f"with tool_write_verdict."
            )
            content = types.Content(
                role="user",
                parts=[types.Part.from_text(text=kickoff)],
            )

            # Drain events; the verdict is persisted to disk via the
            # agent's tool_write_verdict tool, not the event stream.
            async for _ in runner.run_async(
                user_id=session.user_id,
                session_id=session.id,
                new_message=content,
            ):
                pass

            verdict_path = scan_out / "verdicts" / f"{_slug(fid)}.json"
            if verdict_path.exists():
                v = json.loads(verdict_path.read_text())
                return {
                    "id": fid,
                    "status": "ok",
                    "verdict": v.get("verdict"),
                    "confidence": v.get("confidence"),
                    "elapsed": round(time.time() - t0, 1),
                }
            return {
                "id": fid,
                "status": "no_verdict",
                "elapsed": round(time.time() - t0, 1),
            }
        except Exception as e:  # noqa: BLE001 — surface but don't kill cohort
            return {
                "id": fid,
                "status": "error",
                "error": f"{type(e).__name__}: {e}"[:400],
                "elapsed": round(time.time() - t0, 1),
            }


async def _main_async() -> int:
    args = parse_args()
    scan_out = Path(args.scan_out).resolve()
    cand_path = scan_out / "candidates.json"
    if not cand_path.exists():
        print(f"ERROR: candidates.json not found at {cand_path}", file=sys.stderr)
        return 2

    candidates = json.loads(cand_path.read_text()).get("candidates", [])
    pre_count = len(candidates)

    if args.severity:
        candidates = [c for c in candidates if c.get("severity") == args.severity]
    if args.source:
        candidates = [c for c in candidates if c.get("source") == args.source]

    if not args.force:
        verdicts_dir = scan_out / "verdicts"
        candidates = [
            c for c in candidates
            if not (verdicts_dir / f"{_slug(c.get('id', ''))}.json").exists()
        ]

    if args.limit:
        candidates = candidates[:args.limit]

    if not candidates:
        print(f"Nothing to triage (pre-filter total: {pre_count}).")
        return 0

    print(f"Triaging {len(candidates)} of {pre_count} candidates "
          f"(concurrency={args.concurrency})...")

    sem = asyncio.Semaphore(args.concurrency)
    tasks = [_triage_one(c, scan_out, sem) for c in candidates]

    results: list[dict] = []
    completed = 0
    for coro in asyncio.as_completed(tasks):
        r = await coro
        completed += 1
        tag = {"ok": "[OK]", "no_verdict": "[??]", "error": "[ER]"}.get(
            r["status"], "[??]"
        )
        verdict = r.get("verdict") or "-"
        # Truncate long ids for log readability; full id is in the summary file.
        short_id = r["id"] if len(r["id"]) <= 80 else r["id"][:77] + "..."
        print(f"  [{completed}/{len(candidates)}] {tag} {short_id}  "
              f"({verdict}, {r['elapsed']}s)")
        results.append(r)

    by_status: dict[str, int] = {}
    by_verdict: dict[str, int] = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        if r.get("verdict"):
            by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1

    print("\n--- Summary ---")
    print(f"  by_status:  {by_status}")
    print(f"  by_verdict: {by_verdict}")

    summary_path = scan_out / "triage_summary.json"
    summary_path.write_text(json.dumps({
        "scan_out": str(scan_out),
        "total_triaged": len(results),
        "by_status": by_status,
        "by_verdict": by_verdict,
        "results": results,
    }, indent=2))
    print(f"  wrote {summary_path}")
    return 0


def main() -> int:
    return asyncio.run(_main_async())


if __name__ == "__main__":
    sys.exit(main())
