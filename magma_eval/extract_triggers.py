#!/usr/bin/env python3
# extract_triggers.py
#
# For each magma bug, pull the second arg of every
# `MAGMA_LOG("%MAGMA_BUG%", <condition>)` call in the patch — the
# precise condition magma considers "bug-met". Classify into rough
# semantic buckets so we can map Bn* rule coverage to bug classes.
#
# Output: writes magma_eval/bug_triggers.json and prints a coverage
# table linking bug classes → which Bn* rule (if any) should match.

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
MAGMA_ROOT = Path("/home/sanjay/san-home/research/tii/tii24/repos/magma")

# Match MAGMA_LOG calls and capture the condition (second arg).
# Tolerates whitespace, multi-line formatting, MAGMA_OR/MAGMA_AND combinators.
LOG_RE = re.compile(
    r'MAGMA_LOG\s*\(\s*"%MAGMA_BUG%"\s*,\s*(.+?)\)\s*;\s*(?://.*)?$',
    re.DOTALL,
)


def extract_conditions(patch_text: str) -> list[str]:
    """Pull conditions from MAGMA_LOG calls, handling multi-line `\\`
    continuations and MAGMA_AND/MAGMA_OR combinators.
    """
    # First, glue together added lines and collapse `\\\n` continuations.
    added: list[str] = []
    for line in patch_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    blob = "\n".join(added)
    # Splice backslash-newline continuations
    blob = re.sub(r"\\\s*\n\s*", " ", blob)

    out: list[str] = []
    # Find every MAGMA_LOG call and bracket-balance to extract its second arg.
    i = 0
    while True:
        m = re.search(r'MAGMA_LOG\s*\(', blob[i:])
        if not m:
            break
        start = i + m.end()
        # Skip the first arg ("%MAGMA_BUG%") and its comma
        depth = 1
        j = start
        # Find the comma at depth==1 after the format string
        while j < len(blob) and not (blob[j] == "," and depth == 1):
            ch = blob[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= len(blob) or blob[j] != ",":
            i = start
            continue
        # j is the position of the comma; condition starts at j+1
        cond_start = j + 1
        depth = 1
        k = cond_start
        while k < len(blob) and depth > 0:
            ch = blob[k]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        cond = blob[cond_start:k].strip()
        # Drop trailing comments
        cond = re.sub(r"//.*", "", cond).strip()
        # Compress whitespace
        cond = re.sub(r"\s+", " ", cond)
        out.append(cond)
        i = k + 1
    return out


# Heuristic classifier. Maps to a small set of semantic categories
# we can correlate with our Bn* rules. Order matters — earlier
# patterns take priority.
CLASSIFIERS = [
    ("type_confusion",
     lambda c: c.strip() == "1"),
    ("modulo_alignment",
     lambda c: re.search(r"%\s*[\w*\s()]+\s*\)?!=\s*0", c) is not None),
    ("uninit_state_flag",
     lambda c: bool(re.search(r"->(decoder_ok|encoder_state|state\s*&|instate)\b", c))
               or "PARSER_EOF" in c
               or re.search(r"==\s*0\)", c) is not None and "->" in c),
    ("int_overflow_size",
     lambda c: "MAX_SIZE_T" in c or "(size +" in c or " - len -" in c),
    ("signed_negative_input",
     lambda c: re.search(r"\b(size|len|m_tmp)\s*<\s*0\b", c) is not None),
    ("buffer_size_mismatch",
     lambda c: re.search(r"(avail_out|decodedSize|nstrips|op_offset|tp\s*<=\s*op)", c) is not None),
    ("null_deref",
     lambda c: "== NULL" in c),
    ("range_inversion",
     lambda c: re.search(r"\bend\s*<\s*start\b", c) is not None),
    ("array_bounds_index",
     lambda c: "i ==" in c and "sizeof" in c),
    ("oob_index_check",
     lambda c: re.search(r">=\s*(scanline|input->end|->end)", c) is not None
               or re.search(r"in\s*>=\s*ctxt->input->end", c) is not None),
    ("parser_invariant",
     lambda c: ("BASE_PTR" in c) or ("input->base" in c) or "RAW !=" in c
               or "in->end - in->cur" in c),
    ("format_string_buffer",
     lambda c: "strlen(buf)" in c or ("- xmlStrlen" in c)),
]


def classify(condition: str) -> str:
    for name, pred in CLASSIFIERS:
        if pred(condition):
            return name
    return "other"


# Mapping from semantic class to Bn* rule(s) that *could* fire on it.
# This is the predicted-coverage view — what we'd hope to detect.
RULE_COVERAGE = {
    "buffer_size_mismatch":   ["bn_alloc_copy", "bn_unguarded_sink",
                                "unguarded_cast_sx", "unbounded_counter"],
    "int_overflow_size":      ["bn_arith_overflow", "bn_width_mismatch",
                                "unguarded_cast_sx"],
    "signed_negative_input":  ["bn_signed_infer", "bn_unguarded_cast",
                                "unguarded_cast_sx"],
    "modulo_alignment":       [],  # no current rule matches this pattern
    "uninit_state_flag":      [],  # no current rule (precondition gap)
    "type_confusion":         [],  # binary-only: type identity gone
    "null_deref":             [],  # no null-deref rule
    "range_inversion":        ["bn_unguarded_sink"],
    "array_bounds_index":     ["unbounded_counter"],
    "oob_index_check":        ["bn_unguarded_sink", "unguarded_cast_sx"],
    "parser_invariant":       [],  # state-machine bugs, no rule
    "format_string_buffer":   ["bn_alloc_copy", "bn_unguarded_sink"],
    "other":                  [],
}


def main() -> int:
    bugs_json = ROOT / "bugs.json"
    bugs = json.loads(bugs_json.read_text())

    triggers_per_bug: dict[str, list[dict]] = {}
    for target in ("libtiff", "libxml2"):
        bugs_dir = MAGMA_ROOT / "targets" / target / "patches" / "bugs"
        for patch_path in sorted(bugs_dir.glob("*.patch")):
            bid = patch_path.stem
            conditions = extract_conditions(patch_path.read_text())
            triggers_per_bug[bid] = []
            seen_classes = set()
            for c in conditions:
                cls = classify(c)
                triggers_per_bug[bid].append({
                    "condition": c,
                    "class": cls,
                })
                seen_classes.add(cls)

    # Augment bugs.json entries with trigger info
    for b in bugs["bugs"]:
        bid = b["bug_id"]
        b["triggers"] = triggers_per_bug.get(bid, [])
        b["primary_class"] = (
            triggers_per_bug[bid][0]["class"] if triggers_per_bug.get(bid) else "?"
        )

    # Per-bug primary class
    by_class: dict[str, list[str]] = {}
    for bid, trigs in triggers_per_bug.items():
        if not trigs:
            continue
        cls = trigs[0]["class"]
        by_class.setdefault(cls, []).append(bid)

    print("=== Bug class → matching Bn* rules ===")
    print(f"{'class':25s} {'#bugs':>5s}  {'expected_rules':40s}  bug_ids")
    print("-" * 100)
    for cls in sorted(by_class, key=lambda c: -len(by_class[c])):
        ids = by_class[cls]
        rules = RULE_COVERAGE.get(cls, [])
        rules_s = ", ".join(rules) if rules else "(none — coverage gap)"
        print(f"{cls:25s} {len(ids):5d}  {rules_s:40s}  {','.join(sorted(ids))}")

    # Save augmented manifest
    out_path = ROOT / "bugs_with_triggers.json"
    out_path.write_text(json.dumps(bugs, indent=2) + "\n")
    print(f"\nWrote {out_path}")

    # Also save per-bug-id summary
    summary_path = ROOT / "bug_triggers.json"
    summary_path.write_text(json.dumps({
        "by_bug_id": triggers_per_bug,
        "by_class": by_class,
        "rule_coverage": RULE_COVERAGE,
    }, indent=2) + "\n")
    print(f"Wrote {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
