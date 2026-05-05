#!/usr/bin/env python3
"""entry_select_deterministic.py — deterministic kernel of LLM-driven
entry-point selection.

Reads `EntryCandidate.csv` from `rules/entry_candidates.dl` and
applies deterministic rules to derive `EntryTaint.facts`:

  R1. Function named main / wmain / WinMain — entry, param 1 (argv).
  R2. Function in NamedParserAPI AND has no caller in candidate set —
      entry, param whose var name is in {filename, buffer, cur,
      fd, ioread, URL}.
  R3. Function in NamedParserAPI AND HAS caller in candidate set —
      internal (taint will propagate from the upstream entry).
  R4. Function flagged only `libc_input_caller` AND has caller in
      candidate set — internal.
  R5. Function flagged only `libc_input_caller` AND has no candidate
      caller AND HLIL evidence shows it's only init-time (e.g.,
      reads getenv only) — init-only.
      (Without LLM, conservative default: flag for review, leave
       out of EntryTaint.)
  R6. Anything else — flag for LLM follow-up (we report and skip).

The LLM-driven version (`entry_select.py`) is a strict superset
of these rules. When provider availability allows, it reclassifies
ambiguous R5/R6 cases.

Usage:
    python3 entry_select_deterministic.py \
        --facts magma_eval/runs/libxml2-vuln/facts \
        --output magma_eval/runs/libxml2-vuln-det-entry/facts \
        --candidates magma_eval/runs/libxml2-vuln/entry_select/EntryCandidate.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
from collections import defaultdict
from pathlib import Path

# Same lists as in rules/entry_candidates.dl, kept in sync by hand.
NAMED_MAIN = {"main", "wmain", "WinMain", "DllMain"}
NAMED_LIBFUZZER = {"LLVMFuzzerTestOneInput", "LLVMFuzzerInitialize", "AFL_INIT"}
NAMED_PARSER_API = {
    "xmlReadFile", "xmlReadMemory", "xmlReadFd", "xmlReadIO", "xmlReadDoc",
    "xmlCtxtReadFile", "xmlCtxtReadMemory", "xmlCtxtReadFd", "xmlCtxtReadIO",
    "xmlCtxtReadDoc",
    "xmlParseFile", "xmlParseMemory",
    "xmlSAXUserParseFile", "xmlSAXUserParseMemory",
    "xmlSAXParseFile", "xmlSAXParseMemory",
    "xmlReaderForFile", "xmlReaderForMemory", "xmlReaderForFd",
    "xmlReaderForIO", "xmlReaderForDoc",
    "TIFFOpen", "TIFFFdOpen", "TIFFClientOpen",
    "TIFFReadDirectory", "TIFFRGBAImageGet",
    "png_read_info", "png_read_image", "png_read_png", "png_init_io",
    "av_read_frame", "avformat_open_input", "avcodec_send_packet",
}

# Variable names that indicate the parameter carries attacker input.
# Order matters — first match wins per function.
INPUT_VAR_NAMES = ("filename", "buffer", "cur", "fd", "ioread", "URL")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--facts", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--candidates", required=True)
    p.add_argument("--llm-decisions", default=None,
                   help="optional entry_decisions.json from prior LLM run "
                        "(merged with deterministic results)")
    return p.parse_args()


def load_candidates(p: Path) -> tuple[set[str], dict[str, list[str]]]:
    """Returns (candidate_funcs, reasons_by_func)."""
    funcs: set[str] = set()
    reasons: dict[str, list[str]] = defaultdict(list)
    with open(p) as f:
        for row in csv.reader(f, delimiter='\t'):
            if len(row) >= 3:
                funcs.add(row[0])
                reasons[row[0]].append(row[2])
    return funcs, dict(reasons)


def load_callers(facts_dir: Path) -> dict[str, set[str]]:
    callers_of: dict[str, set[str]] = defaultdict(set)
    with open(facts_dir / "Call.facts") as f:
        for row in csv.reader(f, delimiter='\t'):
            if len(row) >= 2:
                callers_of[row[1]].add(row[0])
    return callers_of


def load_formal_params(facts_dir: Path) -> dict[str, list[tuple[str, int]]]:
    by_func: dict[str, list[tuple[str, int]]] = defaultdict(list)
    with open(facts_dir / "FormalParam.facts") as f:
        for row in csv.reader(f, delimiter='\t'):
            if len(row) >= 3:
                by_func[row[0]].append((row[1], int(row[2])))
    return {k: sorted(v, key=lambda x: x[1]) for k, v in by_func.items()}


def pick_input_param(params: list[tuple[str, int]]) -> int | None:
    """Pick the param whose name suggests it carries attacker input."""
    for want in INPUT_VAR_NAMES:
        for var, idx in params:
            if var == want:
                return idx
    return None


def classify(func: str, candidate_funcs: set[str], reasons: list[str],
             callers_of: dict[str, set[str]],
             params: list[tuple[str, int]]) -> tuple[str, list[int], str]:
    """Returns (decision, tainted_params, rationale)."""
    cand_callers = [c for c in callers_of.get(func, set()) if c in candidate_funcs]

    # R1
    if func in NAMED_MAIN:
        return "entry", [1], "named main; argv is param 1"

    # libfuzzer
    if func in NAMED_LIBFUZZER:
        return "entry", [0], "libfuzzer harness; data buffer is param 0"

    # R2 / R3
    if func in NAMED_PARSER_API:
        if cand_callers:
            return "internal", [], f"named parser API but called by candidate(s): {cand_callers[:3]}"
        idx = pick_input_param(params)
        if idx is not None:
            return "entry", [idx], f"named parser API, no candidate caller; input param at idx {idx}"
        return "review", [], "named parser API but no input-typed param matched"

    # R4
    if cand_callers:
        return "internal", [], f"called by candidate(s): {cand_callers[:3]}"

    # R5/R6: function calls libc input source but is not a named entry
    # and has no candidate caller — defer to LLM. Without LLM:
    return "review", [], "libc input caller, no candidate caller, not a named API; LLM follow-up needed"


def main() -> int:
    args = parse_args()
    facts_in = Path(args.facts)
    facts_out = Path(args.output)
    cand_csv = Path(args.candidates)

    cand_funcs, reasons = load_candidates(cand_csv)
    callers_of = load_callers(facts_in)
    formal = load_formal_params(facts_in)

    decisions: list[dict] = []
    entry_taint: list[tuple[str, int]] = []
    counts: dict[str, int] = defaultdict(int)

    # Optional: merge LLM decisions for cases the deterministic rules
    # mark as `review`.
    llm_overrides: dict[str, dict] = {}
    if args.llm_decisions and Path(args.llm_decisions).exists():
        prior = json.load(open(args.llm_decisions))
        for d in prior.get("decisions", []):
            if "error" not in d and d.get("function"):
                llm_overrides[d["function"]] = d

    for func in sorted(cand_funcs):
        params = formal.get(func, [])
        d, tps, why = classify(func, cand_funcs, reasons.get(func, []),
                               callers_of, params)
        # If deterministic was unsure but LLM had an answer, take it
        if d == "review" and func in llm_overrides:
            ov = llm_overrides[func]
            d = ov.get("decision", "review")
            tps = ov.get("tainted_params", []) or []
            why = f"LLM ({ov.get('rationale', '')[:80]})"
        counts[d] += 1
        decisions.append({"function": func, "decision": d,
                          "tainted_params": tps, "rationale": why})
        if d == "entry":
            for idx in tps:
                if isinstance(idx, int):
                    entry_taint.append((func, idx))

    # Stage output dir: hardlink input facts, overwrite EntryTaint.facts
    facts_out.mkdir(parents=True, exist_ok=True)
    for f in facts_in.iterdir():
        dst = facts_out / f.name
        if dst.exists():
            continue
        try:
            os.link(f, dst)
        except Exception:
            shutil.copy2(f, dst)
    et_path = facts_out / "EntryTaint.facts"
    if et_path.exists() and et_path.stat().st_nlink > 1:
        et_path.unlink()
    with open(et_path, "w") as f:
        for func, idx in sorted(set(entry_taint)):
            f.write(f"{func}\t{idx}\n")

    log_path = facts_out.parent / "entry_decisions_deterministic.json"
    with open(log_path, "w") as f:
        json.dump({"counts": dict(counts), "decisions": decisions}, f, indent=2)

    print(f"[deterministic] {len(cand_funcs)} candidates")
    for k in ("entry", "internal", "init-only", "review"):
        if k in counts:
            print(f"  {k:10s} {counts[k]}")
    print(f"\nEntryTaint.facts ({len(set(entry_taint))} rows):")
    for func, idx in sorted(set(entry_taint)):
        print(f"  {func}\t{idx}")
    print(f"\nDecisions log: {log_path}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
