#!/usr/bin/env python3
# verify_ground_truth.py
#
# Sanity-check bugs.json against the magma source trees.
#
# For each (bug_id, target, file, function) row:
#   1. Open the magma source file at the magma-checked-out commit
#   2. Find every line containing `MAGMA_LOG("%MAGMA_BUG%"` (the canary)
#   3. For each canary line, walk back to find the enclosing function
#      using a balanced-brace approach (more robust than the regex-only
#      header-line scan in build_manifest.py)
#   4. Compare against the function name we recorded
#
# Reports:
#   * MATCH       — bugs.json and source agree
#   * MISMATCH    — different function name; investigate
#   * NO_CANARY   — file has no MAGMA_LOG line at the recorded location
#                   (suggests the patch wasn't applied to the source tree
#                   we have, or the line was different in this commit)

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
BUGS_JSON = ROOT / "bugs.json"
SRC_ROOTS = {
    "libtiff": Path("/home/sanjay/san-home/research/tii/tii24/tmp/libtiff-magma"),
    "libxml2": Path("/home/sanjay/san-home/research/tii/tii24/tmp/libxml2-magma"),
}
MAGMA_ROOT = Path("/home/sanjay/san-home/research/tii/tii24/repos/magma")
PATCH_DIRS = {
    t: MAGMA_ROOT / "targets" / t / "patches" / "bugs"
    for t in SRC_ROOTS
}
# Match build_clean.sh's pinned commits.
PINNED_COMMITS = {
    "libtiff": "c145a6c14978f73bb484c955eb9f84203efcb12e",
    "libxml2": "ec6e3efb06d7b15cf5a2328fabd3845acea4c815",
}
# Per-target pristine clones, populated lazily and cached.
_PRISTINE_CLONES: dict[str, Path] = {}


def pristine_clone(target: str) -> Path:
    """Clone the magma source repo at its pinned commit into a fresh
    temp directory. Cached per-target so we only clone once.
    """
    if target in _PRISTINE_CLONES:
        return _PRISTINE_CLONES[target]
    src = SRC_ROOTS[target]
    dst = Path(tempfile.mkdtemp(prefix=f"verify-pristine-{target}-"))
    subprocess.run(["git", "clone", "--quiet", str(src), str(dst)], check=True)
    subprocess.run(["git", "-C", str(dst), "checkout", "--quiet",
                    PINNED_COMMITS[target]], check=True)
    _PRISTINE_CLONES[target] = dst
    return dst


def staged_source_for_bug(bug_id: str, target: str) -> Path | None:
    """Apply ONLY this bug's patch to a temp copy of the source tree
    so we can verify the canary placement. Returns the staged source
    root, or None if the patch can't be applied.

    We cache by bug_id to avoid re-staging within one verifier run.
    """
    cache = staged_source_for_bug._cache  # type: ignore
    key = (target, bug_id)
    if key in cache:
        return cache[key]

    src_root = pristine_clone(target)
    patch_path = PATCH_DIRS[target] / f"{bug_id}.patch"
    if not patch_path.is_file():
        cache[key] = None
        return None

    # Copy the affected files into a fresh tmp dir, apply the bug's
    # patch there. We don't apply against the pristine clone directly
    # so that subsequent bugs in the same target see a clean baseline.
    tmp_root = Path(tempfile.mkdtemp(prefix=f"verify-{bug_id}-"))
    affected = set()
    for ln in patch_path.read_text().splitlines():
        if ln.startswith("+++ b/"):
            affected.add(ln[len("+++ b/"):].strip())
    for f in affected:
        src = src_root / f
        dst = tmp_root / f
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_file():
            shutil.copy2(src, dst)

    r = subprocess.run(
        ["patch", "-p1", "--input", str(patch_path), "--silent"],
        cwd=str(tmp_root), capture_output=True, text=True,
    )
    if r.returncode != 0:
        cache[key] = None
        return None

    cache[key] = tmp_root
    return tmp_root


staged_source_for_bug._cache = {}  # type: ignore

CANARY_RE = re.compile(r'MAGMA_LOG\s*\(\s*"%MAGMA_BUG%"')
# Conservative C function-header pattern: starts in column 0 with an
# identifier or pointer-modifier, contains '(' before any ';'.
FUNC_HDR_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_ \t\*]*)\(([^;]*)$")


def find_function_at_line(text: list[str], line_no: int) -> str | None:
    """Walk back from line_no until we cross a `}` at column 0
    (end of the previous function), then walk forward to the next
    function header. Falls back to last header before line_no.
    """
    # Cap line_no to file length.
    line_no = min(line_no, len(text))

    # Find the most recent line at column 0 that ends with `}` — that's
    # likely the previous function's closing brace.
    boundary = 0
    for i in range(line_no - 1, -1, -1):
        if text[i].rstrip() == "}":
            boundary = i + 1
            break

    # Now scan from boundary forward for the next function header.
    for i in range(boundary, line_no):
        ln = text[i]
        m = FUNC_HDR_RE.match(ln)
        if m:
            # Extract just the identifier before the paren
            sig = m.group(1).strip()
            # Strip type modifiers — last identifier is the function name
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", sig)
            if tokens:
                return tokens[-1]
    # Fallback: last header anywhere before line_no
    for i in range(line_no - 1, -1, -1):
        m = FUNC_HDR_RE.match(text[i])
        if m:
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", m.group(1))
            if tokens:
                return tokens[-1]
    return None


def verify_bug_set(bug_id: str, target: str, claimed_funcs: list[str]) -> dict:
    """Verify ALL bugs.json entries for a given bug_id at once.

    Apply the bug's patch, find every canary in the patched files,
    determine its enclosing function. Compare the SET of canary-
    bearing functions vs the SET of functions claimed by bugs.json.
    Set comparison sidesteps the line-shift problem you get when the
    patch inserts many canaries that shift downstream line numbers.
    """
    staged_root = staged_source_for_bug(bug_id, target)
    if staged_root is None:
        return {"bug_id": bug_id, "target": target,
                "status": "PATCH_APPLY_FAILED",
                "claimed": sorted(claimed_funcs)}

    # Walk every C source file in the staged tree.
    actual_funcs: list[str] = []
    canary_locations: list[dict] = []
    for src_file in staged_root.rglob("*.c"):
        rel = src_file.relative_to(staged_root)
        text = src_file.read_text(errors="replace").splitlines()
        for i, ln in enumerate(text):
            if CANARY_RE.search(ln):
                fn = find_function_at_line(text, i + 1)
                actual_funcs.append(fn or "?")
                canary_locations.append({
                    "file": str(rel),
                    "line": i + 1,
                    "function": fn,
                })

    claimed_set = sorted(set(claimed_funcs))
    actual_set = sorted(set(actual_funcs))
    missing = [f for f in claimed_set if f not in actual_set]   # in bugs.json, not in source
    extra = [f for f in actual_set if f not in claimed_set]     # in source, not in bugs.json

    status = "MATCH" if not missing and not extra else "MISMATCH"
    return {
        "bug_id": bug_id,
        "target": target,
        "status": status,
        "claimed": claimed_set,
        "actual": actual_set,
        "missing_from_source": missing,
        "extra_in_source": extra,
        "canary_locations": canary_locations,
    }


def main() -> int:
    bugs = json.loads(BUGS_JSON.read_text())["bugs"]

    # Group claimed functions per (bug_id, target)
    grouped: dict[tuple[str, str], list[str]] = {}
    for b in bugs:
        grouped.setdefault((b["bug_id"], b["target"]), []).append(b["function"])

    results = []
    for (bug_id, target), funcs in sorted(grouped.items()):
        results.append(verify_bug_set(bug_id, target, funcs))

    by_status: dict[str, int] = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1

    print("=== Ground-truth verification summary (per bug_id) ===")
    for s, n in sorted(by_status.items(), key=lambda kv: -kv[1]):
        print(f"  {n:3d}  {s}")
    print()

    bad = [r for r in results if r["status"] != "MATCH"]
    if bad:
        print("=== Disagreements ===")
        for r in bad:
            print(f"  {r['bug_id']:8s} {r['target']}")
            if r["status"] == "PATCH_APPLY_FAILED":
                print("    patch could not be applied to pristine clone")
            else:
                if r.get("missing_from_source"):
                    print(f"    in bugs.json but no canary in source: {r['missing_from_source']}")
                if r.get("extra_in_source"):
                    print(f"    canary in source but not in bugs.json: {r['extra_in_source']}")
            print()
    else:
        print("All bug-anchor functions match. Ground truth verified.")

    out_path = ROOT / "ground_truth_check.json"
    out_path.write_text(json.dumps({
        "by_status": by_status,
        "results": results,
    }, indent=2))
    print(f"\nWrote {out_path}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
