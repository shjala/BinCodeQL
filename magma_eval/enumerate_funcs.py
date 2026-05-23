#!/usr/bin/env python3
# enumerate_funcs.py <binary>
#
# Headless BN: list every function (name, start_addr, size_bytes,
# basic_block_count). One-shot per binary, run once before sampling
# negative controls. Output is JSON to stdout.

import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: enumerate_funcs.py <binary>", file=sys.stderr)
        return 2
    binpath = Path(argv[1])
    if not binpath.is_file():
        print(f"ERROR: {binpath} not found", file=sys.stderr)
        return 3

    import binaryninja as bn  # noqa: E402

    # Prefer existing .bndb sibling; otherwise load + analyze.
    bndb = binpath.with_suffix(binpath.suffix + ".bndb")
    if bndb.is_file():
        bv = bn.load(str(bndb))
    else:
        bv = bn.load(str(binpath))

    out = []
    for f in bv.functions:
        try:
            size = sum(b.length for b in f.basic_blocks)
            bb = len(list(f.basic_blocks))
        except Exception:
            size, bb = 0, 0
        out.append({
            "name": f.name,
            "start": f.start,
            "size": size,
            "blocks": bb,
        })

    json.dump({"binary": str(binpath), "count": len(out), "functions": out}, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
