#!/usr/bin/env python3
# build_manifest.py
#
# Parse magma's per-bug patches into a JSON manifest the eval harness
# consumes. One row per (bug_id, file, function, hunk lines). Plus an
# enclosing-function lookup for hunk headers whose context line isn't
# the function header itself.
#
# Output: magma_eval/bugs.json

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

MAGMA_ROOT = Path("/home/sanjay/san-home/research/tii/tii24/repos/magma")
SRC_ROOTS = {
    "libtiff": Path("/home/sanjay/san-home/research/tii/tii24/tmp/libtiff-magma"),
    "libxml2": Path("/home/sanjay/san-home/research/tii/tii24/tmp/libxml2-magma"),
}
OUT_PATH = Path(__file__).parent / "bugs.json"

HUNK_HDR = re.compile(
    r"^@@\s+-(?P<old>\d+)(?:,(?P<old_n>\d+))?\s+\+(?P<new>\d+)(?:,(?P<new_n>\d+))?\s+@@\s*(?P<ctx>.*)$"
)
FUNC_FROM_CTX = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
# Conservative match for a top-level function header line in C source:
# starts in column 0 with an identifier, contains a '(' before any ';'.
FUNC_HDR = re.compile(r"^[A-Za-z_][A-Za-z0-9_ \t\*]*\([^;]*$")


def enclosing_func(src_file: Path, line_no: int) -> str | None:
    """Walk backward from line_no looking for the most recent function header."""
    if not src_file.is_file():
        return None
    text = src_file.read_text(errors="replace").splitlines()
    if line_no > len(text):
        line_no = len(text)
    for i in range(line_no - 1, -1, -1):
        ln = text[i]
        if FUNC_HDR.match(ln):
            m = FUNC_FROM_CTX.search(ln)
            if m:
                return m.group(1)
    return None


def parse_patch(patch_path: Path, target: str) -> list[dict]:
    """Return one entry per CANARY-bearing hunk.

    A magma bug is anchored at its `MAGMA_LOG("%MAGMA_BUG%", ...)` call.
    Other hunks in the same patch add `MAGMA_ENABLE_FIXES` guards in
    helper functions — those are related-fix sites, not bug sites, so
    we drop them.
    """
    src_root = SRC_ROOTS[target]
    bug_id = patch_path.stem
    rows: list[dict] = []

    cur_file: str | None = None
    cur_hunk: dict | None = None
    cur_added: list[str] = []

    def flush():
        if cur_hunk is None:
            return
        if not any("MAGMA_LOG" in ln for ln in cur_added):
            return
        rows.append(cur_hunk)

    for raw in patch_path.read_text(errors="replace").splitlines():
        if raw.startswith("+++ b/"):
            flush()
            cur_hunk = None
            cur_added = []
            cur_file = raw[len("+++ b/"):].strip()
            continue
        m = HUNK_HDR.match(raw)
        if m and cur_file is not None:
            flush()
            cur_added = []
            old_start = int(m.group("old"))
            old_n = int(m.group("old_n") or "1")
            ctx = m.group("ctx").strip()
            func = None
            if ctx:
                mf = FUNC_FROM_CTX.search(ctx)
                if mf:
                    func = mf.group(1)
            if not func:
                src_path = src_root / cur_file
                func = enclosing_func(src_path, old_start)
            cur_hunk = {
                "bug_id": bug_id,
                "target": target,
                "file": cur_file,
                "function": func or "?",
                "hunk_old_start": old_start,
                "hunk_old_count": old_n,
            }
            continue
        if cur_hunk is not None and raw.startswith("+") and not raw.startswith("+++"):
            cur_added.append(raw[1:])

    flush()
    return rows


def main() -> int:
    manifest: dict = {"bugs": [], "by_target": {}}
    for target in ("libtiff", "libxml2"):
        bugs_dir = MAGMA_ROOT / "targets" / target / "patches" / "bugs"
        if not bugs_dir.is_dir():
            print(f"[warn] no patches dir for {target} at {bugs_dir}", file=sys.stderr)
            continue
        target_rows: list[dict] = []
        for p in sorted(bugs_dir.glob("*.patch")):
            target_rows.extend(parse_patch(p, target))
        manifest["bugs"].extend(target_rows)
        # Per-target rollup: distinct (file, function) pairs
        funcs = sorted({(r["file"], r["function"]) for r in target_rows})
        manifest["by_target"][target] = {
            "bug_count": len({r["bug_id"] for r in target_rows}),
            "distinct_funcs": [{"file": f, "function": fn} for f, fn in funcs],
        }

    OUT_PATH.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"[+] wrote {OUT_PATH}")
    for target, info in manifest["by_target"].items():
        print(f"    {target}: {info['bug_count']} bugs, {len(info['distinct_funcs'])} distinct funcs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
