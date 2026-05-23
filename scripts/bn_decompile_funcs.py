#!/usr/bin/env python3
"""Headless BN decompilation dump.

Emit HLIL pretty-prints for a list of functions into a directory of
`<func>.txt` files. Used by the LLM-only baseline (triage_no_datalog.py)
to feed function code to the model without going through the BN MCP.

Usage:
    BN_PYTHON_PATH=... python3 bn_decompile_funcs.py BIN -f f1,f2,... -o DIR
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import binaryninja as bn


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("binary")
    p.add_argument("-f", "--functions", required=True,
                   help="Comma-separated list of function names")
    p.add_argument("-o", "--output-dir", required=True)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    bv = bn.load(args.binary, update_analysis=True)
    if bv is None:
        print(f"ERROR: cannot load {args.binary}", file=sys.stderr)
        return 2

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    targets = [n.strip() for n in args.functions.split(",") if n.strip()]
    by_name = {f.name: f for f in bv.functions}

    summary: dict = {"binary": args.binary, "functions": {}}

    for name in targets:
        fn = by_name.get(name)
        if fn is None:
            summary["functions"][name] = {"error": "not found"}
            continue

        try:
            hlil = fn.hlil
            lines = []
            if hlil is not None:
                for il_block in hlil.basic_blocks:
                    for il in il_block:
                        lines.append(str(il))
            text = "\n".join(lines) if lines else "(empty HLIL)"
        except Exception as e:
            text = f"(HLIL extraction failed: {e})"

        # Cross-references: catches indirect calls (e.g. function-pointer
        # hooks like TIFFPredictor's setupdecode) that Call.facts (direct
        # calls only) misses.
        xref_callers: set[str] = set()
        try:
            for ref in bv.get_code_refs(fn.start):
                src_fn = ref.function
                if src_fn is not None and src_fn.name != name:
                    xref_callers.add(src_fn.name)
        except Exception:
            pass

        # Outgoing direct calls — useful when Call.facts isn't loaded
        callees: set[str] = set()
        try:
            for callee in fn.callees:
                if callee is not None and callee.name != name:
                    callees.add(callee.name)
        except Exception:
            pass

        # Add a header so the LLM has function metadata + xref summary
        header_parts = [
            f"// Function: {name}",
            f"// Address: 0x{fn.start:x}",
            f"// Size: {fn.total_bytes} bytes, "
            f"{len(list(fn.basic_blocks))} basic blocks",
            f"// Parameters: {len(fn.parameter_vars)}",
        ]
        if xref_callers:
            header_parts.append(f"// Callers (incl. via fn ptr): "
                                f"{', '.join(sorted(xref_callers))}")
        if callees:
            header_parts.append(f"// Direct callees: "
                                f"{', '.join(sorted(callees))}")
        header_parts.append("// HLIL pretty-print (Binary Ninja):")
        header = "\n".join(header_parts) + "\n"

        path = out / f"{name}.txt"
        path.write_text(header + text)
        summary["functions"][name] = {
            "addr": fn.start,
            "size": fn.total_bytes,
            "blocks": len(list(fn.basic_blocks)),
            "lines": len(lines),
            "path": str(path),
        }

    (out / "_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({"functions_processed": len(targets),
                      "output_dir": str(out)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
