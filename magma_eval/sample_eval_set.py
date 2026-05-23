#!/usr/bin/env python3
# sample_eval_set.py
#
# Build the per-binary 50-function eval set:
#   * all buggy functions from bugs.json that exist in the binary
#   * random sibling negatives to top up to TARGET_TOTAL
#
# Negative-control sampling is size-stratified: we draw from functions
# whose size lies in the same range as the buggy set so the LLM doesn't
# get an "x marks the spot" leak by function-size alone.
#
# We pick ONE primary utility per target that links the broadest
# decoder/parser surface:
#   libtiff -> tiffcp     (covers PixarLog, OJPEG, LZW, NeXT, JBIG, ...)
#   libxml2 -> xmllint    (full parser/validator surface)
#
# Output:  magma_eval/eval_set.json  (the function lists the harness
#           feeds into BinCodeQL)

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
REPO_ROOT = ROOT.parent
BUGS_JSON = ROOT / "bugs.json"
OUT_JSON = ROOT / "eval_set.json"

FARAH = Path("/home/sanjay/san-home/research/tii/tii24/tmp/farah-magma")
PRIMARY = {
    "libtiff": "tiffcp",
    "libxml2": "xmllint",
}
TARGET_TOTAL = 50
SEED = 1729  # so the negative control set is reproducible


def enumerate_funcs(binary: Path) -> list[dict]:
    """Run enumerate_funcs.py via the project's BN runner."""
    sys.path.insert(0, str(REPO_ROOT))
    from bn_utils import run_bn_script

    r = run_bn_script(
        str(ROOT / "enumerate_funcs.py"),
        [str(binary)],
        timeout=300,
    )
    if r.returncode != 0:
        raise RuntimeError(f"enumerate_funcs failed for {binary}: {r.stderr[-500:]}")
    payload = json.loads(r.stdout)
    return payload["functions"]


def build_set_for_target(target: str, variant: str, bugs: list[dict]) -> dict:
    binary = FARAH / f"{target}-{variant}" / PRIMARY[target]
    if not binary.is_file():
        raise FileNotFoundError(binary)

    all_funcs = enumerate_funcs(binary)
    by_name = {f["name"]: f for f in all_funcs}

    # Buggy functions for this target. Note: a function may anchor
    # multiple bug IDs; collapse by name.
    buggy_names: dict[str, list[str]] = {}
    for b in bugs:
        if b["target"] != target:
            continue
        buggy_names.setdefault(b["function"], []).append(b["bug_id"])

    # Intersect with binary symbols. If a buggy function isn't present
    # (inlined, dead-code-eliminated, or symbol-stripped), record it
    # for the manifest but mark as MISSING.
    buggy_present = []
    buggy_missing = []
    for fn, bids in buggy_names.items():
        if fn in by_name:
            entry = dict(by_name[fn])
            entry["bug_ids"] = sorted(set(bids))
            entry["role"] = "buggy"
            buggy_present.append(entry)
        else:
            buggy_missing.append({"function": fn, "bug_ids": sorted(set(bids))})

    # Size envelope for negative-control sampling: take the inter-quartile
    # band of buggy-function sizes so negatives are comparable in scale.
    sizes = sorted(e["size"] for e in buggy_present)
    if sizes:
        lo = sizes[max(0, len(sizes) // 4)]
        hi = sizes[min(len(sizes) - 1, 3 * len(sizes) // 4)]
        # Widen a bit so we have enough candidates.
        lo = max(64, lo // 2)
        hi = max(hi * 2, 4096)
    else:
        lo, hi = 64, 4096

    rng = random.Random(SEED)
    pool = [
        f for f in all_funcs
        if f["name"] not in buggy_names
        and lo <= f["size"] <= hi
        and not f["name"].startswith(("_", "sub_"))
        and f["blocks"] >= 3
    ]
    rng.shuffle(pool)
    n_neg = max(0, TARGET_TOTAL - len(buggy_present))
    negatives = []
    for f in pool[:n_neg]:
        e = dict(f)
        e["bug_ids"] = []
        e["role"] = "negative"
        negatives.append(e)

    return {
        "target": target,
        "variant": variant,
        "binary": str(binary),
        "total_functions_in_binary": len(all_funcs),
        "buggy_present": buggy_present,
        "buggy_missing": buggy_missing,
        "negatives": negatives,
        "size_band": {"lo": lo, "hi": hi},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", default="vuln",
                    help="Which variant to sample against (vuln|patched). "
                         "Sampling is identical between variants — same names "
                         "should be used so we can compare verdicts.")
    args = ap.parse_args()

    bugs = json.loads(BUGS_JSON.read_text())["bugs"]

    out = {"variant": args.variant, "targets": {}}
    for target in ("libtiff", "libxml2"):
        out["targets"][target] = build_set_for_target(target, args.variant, bugs)

    OUT_JSON.write_text(json.dumps(out, indent=2) + "\n")
    print(f"[+] wrote {OUT_JSON}")
    for tname, t in out["targets"].items():
        print(f"    {tname}: {len(t['buggy_present'])} buggy + "
              f"{len(t['negatives'])} negatives = "
              f"{len(t['buggy_present']) + len(t['negatives'])} total "
              f"(missing={len(t['buggy_missing'])})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
