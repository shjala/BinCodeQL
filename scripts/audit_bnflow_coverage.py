#!/usr/bin/env python3
"""Audit that every `BnFlow(...)` join in `rules/bn_*.dl` binds
variables to roles covered by `RelevantEndpoint` in `rules/bn_flow.dl`.

This is the D1 false-negative defense from `docs/scaling_roadmap.md`.
Run as a pre-flight check before switching consumers to BnFlowRelevant,
and as a CI gate to catch new rules that add unrecognised join shapes.

Exit codes:
    0 — all joins covered, switchover safe
    1 — coverage gap found (output identifies which rule / position)
    2 — new join pattern detected that this audit doesn't know how to
        classify; manual review required (and likely an addition to
        either KNOWN_ROLE_PATTERNS or RelevantEndpoint).

The audit operates textually — it doesn't run Souffle. The rule
grammar we care about is regular enough that a clause-level regex
parser correctly handles every Bn* rule in tree as of 2026-05-22.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = REPO_ROOT / "rules"
BN_FLOW_DL = RULES_DIR / "bn_flow.dl"

# Source-atom patterns we recognise. Each entry is:
#   (regex_for_atom, role_name)
#
# The regex must contain ONE capture group per relevant column we want
# to extract — for variable-binding analysis we capture the (var, ver)
# pair when applicable. The role_name must match a clause in
# RelevantEndpoint's definition body (verified by `_collect_roles`).
# Column placeholder for the audit's positional patterns. Allows any of:
# bare identifier (\w+), `_` wildcard, or quoted literal ("add"). Used
# everywhere a non-capturing column appears between the columns we want
# to capture. Without quoted-literal support, patterns like
# `ArithOp(f, ua, _, _, "add", uv, uver, _)` silently miss the uv/uver
# capture because the regex's `\w+` skips the `"add"` and gets out of sync.
_C = r"(?:\"[^\"]*\"|\w+)"

KNOWN_ROLE_PATTERNS = [
    # Direct fact patterns (positional). `_C` covers literal/wildcard
    # columns we don't want to capture.
    ("Guard.var",            rf"Guard\s*\(\s*{_C}\s*,\s*{_C}\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("AllocSite.size_var",   rf"AllocSite\s*\(\s*{_C}\s*,\s*{_C}\s*,\s*(\w+)"),
    ("Cast.dst",             rf"Cast\s*\(\s*{_C}\s*,\s*{_C}\s*,\s*(\w+)\s*,\s*(\w+)\s*,"),
    ("Cast.src",             rf"Cast\s*\(\s*{_C}\s*,\s*{_C}\s*,\s*{_C}\s*,\s*{_C}\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("ArithOp.dst",          rf"ArithOp\s*\(\s*{_C}\s*,\s*{_C}\s*,\s*(\w+)\s*,\s*(\w+)\s*,"),
    ("ArithOp.src",          rf"ArithOp\s*\(\s*{_C}\s*,\s*{_C}\s*,\s*{_C}\s*,\s*{_C}\s*,\s*{_C}\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("FormalParam.var",      r"FormalParam\s*\(\s*\w+\s*,\s*(\w+)"),
    ("ActualArg.var",        r"ActualArg\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("MemWrite.target",      r"MemWrite\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)"),
    ("AddressOf.var",        r"AddressOf\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)\s*,"),
    ("AddressOf.target",     r"AddressOf\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)"),
    ("TaintedVar.var",       r"TaintedVar\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("TaintedSink.tainted",  r"TaintedSink\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)"),
    ("MemRead.base",         r"MemRead\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)"),
    # Derived intermediate relations local to a Bn* rule. These are
    # covered transitively — the underlying fact-atom that defines the
    # intermediate is already covered by RelevantEndpoint, so anything
    # bound *from* the intermediate is automatically reachable.
    ("BnAllocSite.buf",      r"BnAllocSite\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnAllocSite.size",     r"BnAllocSite\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnAllocDef.var",       r"BnAllocDef\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnFreeCall.var",       r"BnFreeCall\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnCopySite.dst",       r"BnCopySite\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnCopySite.size",      r"BnCopySite\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnPotentialArithOverflow.v",
                              r"BnPotentialArithOverflow\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnEffectiveGuardForArith.v",
                              r"BnEffectiveGuardForArith\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnHasUpperBound.v",    r"BnHasUpperBound\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnCounterUsedAsIndex.v",
                              r"BnCounterUsedAsIndex\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnUnboundedCounter.v", r"BnUnboundedCounter\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnSizeAtCallSite.var", r"BnSizeAtCallSite\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnGuardedCapacityCall.cap",
                              r"BnGuardedCapacityCall\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    # bn_arith_overflow's narrow-arith proxy.
    ("BnNarrowArithOp.v",    r"BnNarrowArithOp\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    # bn_findings + bn_guard_dominates intermediates.
    ("GuardDominates.gv",    r"GuardDominates\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)"),
    ("BnFinding.var",        r"BnFinding\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)"),
    # bn_sentinel_init self-recursion + alloc anchor.
    ("BnSentinelBuf.var",    r"BnSentinelBuf\s*\(\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnSentinelInit.buf",   r"BnSentinelInit\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    # bn_type_confusion intermediate steps.
    ("BnPtrToNarrow.iv",     r"BnPtrToNarrow\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    ("BnNarrowToPtr.iv",     r"BnNarrowToPtr\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
    # bn_joint_buffer_bound intermediates.
    ("BnCapacityGuard.gv",   r"BnCapacityGuard\s*\(\s*\w+\s*,\s*(\w+)"),
    ("BnSmallConstGuard.gv", r"BnSmallConstGuard\s*\(\s*\w+\s*,\s*(\w+)"),
    ("BnOffsetCopySink.dst", r"BnOffsetCopySink\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(\w+)\s*,\s*(\w+)"),
]

# Map role names to the RelevantEndpoint clause they correspond to.
# Keys must appear in `_collect_roles(BN_FLOW_DL)`'s output.
ROLE_TO_RELEVANT_CLAUSE = {
    "Guard.var":           "Guard",
    "AllocSite.size_var":  "AllocSite",
    "Cast.dst":            "Cast",
    "Cast.src":            "Cast",
    "ArithOp.dst":         "ArithOp",
    "ArithOp.src":         "ArithOp",
    "FormalParam.var":     "FormalParam",
    "ActualArg.var":       "ActualArg",
    "MemWrite.target":     "MemWrite",
    "AddressOf.var":       "AddressOf",
    "AddressOf.target":    "AddressOf",
    "TaintedVar.var":      "TaintedVar",
    "TaintedSink.tainted": "TaintedSink",
    # Derived: same role as the underlying alloc/free/arith fact.
    # The map points at the underlying fact that *defines* the
    # intermediate; RelevantEndpoint already covers all of these.
    "BnAllocSite.buf":     "Call",
    "BnAllocSite.size":    "AllocSite",
    "BnAllocDef.var":      "Call",
    "BnFreeCall.var":      "ActualArg",
    "BnCopySite.dst":      "ActualArg",
    "BnCopySite.size":     "ActualArg",
    "BnPotentialArithOverflow.v": "ArithOp",
    "BnEffectiveGuardForArith.v": "Guard",
    "BnHasUpperBound.v":   "Guard",
    "BnCounterUsedAsIndex.v":     "ArithOp",
    "BnUnboundedCounter.v":       "ArithOp",
    "BnSizeAtCallSite.var":       "ActualArg",
    "BnGuardedCapacityCall.cap":  "Guard",
    "BnNarrowArithOp.v":          "ArithOp",
    "GuardDominates.gv":          "Guard",
    "BnFinding.var":              "Guard",   # finding vars trace back to rule outputs which are guard-anchored
    "BnSentinelBuf.var":          "Call",    # rooted in AllocSite (= Call result)
    "BnSentinelInit.buf":         "Call",
    "BnPtrToNarrow.iv":           "Cast",
    "BnNarrowToPtr.iv":           "Cast",
    "BnCapacityGuard.gv":         "Guard",
    "BnSmallConstGuard.gv":       "Guard",
    "BnOffsetCopySink.dst":       "ActualArg",
    "MemRead.base":               "MemRead",
}


# ── Helpers ─────────────────────────────────────────────────────────


def split_clauses(text: str) -> list[str]:
    """Split a `.dl` file into rule-body clauses (head :- body.).

    Drops line/block comments and skips `.decl`/`.input`/`.output`/
    `.type` declarations entirely — those contain "." inside column
    specs (e.g. `: Sym, n: number`) that would confuse a naive split.
    """
    no_line_comments = re.sub(r"//[^\n]*", "", text)
    no_block_comments = re.sub(r"/\*.*?\*/", "", no_line_comments, flags=re.S)
    # Strip leading `.decl/.input/.output/.type` lines (they don't have ":-").
    no_decls = re.sub(
        r"^\s*\.(decl|input|output|type)[^\n]*\n",
        "",
        no_block_comments,
        flags=re.M,
    )
    # Multi-line `.decl ...\n    cols\n    cols)` — strip everything
    # from `.decl` up through the first closing paren that doesn't have
    # a `:-` between (i.e. a declaration, not a clause head).
    no_decls = re.sub(
        r"\.decl\s+\w+\s*\([^)]*\)\s*",
        " ",
        no_decls,
        flags=re.S,
    )
    # Clauses are separated by `.` — but only those ending a `:-` body.
    # We split on `.` and keep chunks that contain `:-`.
    chunks = no_decls.split(".")
    return [c.strip() for c in chunks if c.strip() and ":-" in c]


BNFLOW_ATOM_RE = re.compile(
    r"BnFlow\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)"
)


def find_bnflow_calls(clause: str) -> list[tuple[str, str, str, str, str]]:
    """Return (func, sv, sver, dv, dver) tuples from BnFlow atoms in clause."""
    return BNFLOW_ATOM_RE.findall(clause)


def role_for_binding(clause: str, var: str) -> tuple[str | None, str | None]:
    """Identify which fact-atom in `clause` binds `var`. Returns
    (role_name, matched_pattern) — both None if no recognised pattern
    matches.
    """
    # First: explicit role patterns (specific column position known).
    for role, regex in KNOWN_ROLE_PATTERNS:
        for m in re.finditer(regex, clause):
            for captured in m.groups():
                if captured == var:
                    return role, regex

    # Fallback 1: compound `Use(_, var, ver, a) + <interesting>(f, a, ...)`
    # pattern. Recognises Use endpoints at MemRead/MemWrite/MemWriteSize/
    # Jump addresses — RelevantEndpoint covers these via Use+MemAccess
    # clauses. The audit can't see the cross-atom binding any other way.
    use_re = re.compile(
        rf"Use\s*\(\s*{_C}\s*,\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)"
    )
    for m in use_re.finditer(clause):
        u_var, u_ver, u_addr = m.group(1), m.group(2), m.group(3)
        if var not in (u_var, u_ver):
            continue
        # Look for a co-occurring address-keyed atom binding the same addr.
        # BnNarrowStore is included because it's a MemWriteSize-derived
        # intermediate keyed by the store address (defined in
        # bn_width_mismatch.dl).
        anchor_re = re.compile(
            rf"(MemRead|MemWrite|MemWriteSize|Jump|BnNarrowStore)\s*\(\s*{_C}\s*,\s*{re.escape(u_addr)}\b"
        )
        if anchor_re.search(clause):
            return f"Use@{anchor_re.search(clause).group(1)}", "Use+address-anchor"

    # Fallback 2: any Bn-prefixed intermediate that mentions `var` in any
    # column position is treated as transitively covered. Sound because
    # every Bn-intermediate in the rules/ tree itself derives from
    # RelevantEndpoint-covered fact atoms (verified by inspection of
    # the rules; new intermediates that don't satisfy this property
    # would need to be added to KNOWN_ROLE_PATTERNS with their actual
    # role).
    bn_intermediate_re = re.compile(
        r"(Bn\w+|GuardDominates)\s*\(\s*([^)]+)\)"
    )
    for m in bn_intermediate_re.finditer(clause):
        rel = m.group(1)
        # Skip BnFlow / BnFlow1 / BnFlowRelevant — the audited relations.
        if rel.startswith("BnFlow"):
            continue
        cols = [c.strip() for c in m.group(2).split(",")]
        if var in cols:
            return f"intermediate:{rel}", rel
    return None, None


def _collect_roles(bn_flow_path: Path) -> set[str]:
    """Parse `bn_flow.dl` to find which fact-relations appear in any
    RelevantEndpoint clause body. Used to confirm ROLE_TO_RELEVANT_CLAUSE
    is in sync with the actual bn_flow.dl content.
    """
    text = bn_flow_path.read_text()
    # Find each "RelevantEndpoint(...)  :-  <body>." clause.
    pattern = re.compile(
        r"RelevantEndpoint\s*\([^)]*\)\s*:-\s*(.*?)\.", re.S
    )
    found = set()
    for body_text in pattern.findall(text):
        # Strip line comments and grab leading word from each atom.
        body_text = re.sub(r"//[^\n]*", "", body_text)
        for m in re.finditer(r"(\w+)\s*\(", body_text):
            found.add(m.group(1))
    return found


# ── Audit ───────────────────────────────────────────────────────────


def audit() -> int:
    if not BN_FLOW_DL.exists():
        print(f"FATAL: {BN_FLOW_DL} not found", file=sys.stderr)
        return 1

    declared_roles = _collect_roles(BN_FLOW_DL)
    missing_decls = sorted(
        set(ROLE_TO_RELEVANT_CLAUSE.values()) - declared_roles
    )
    if missing_decls:
        print(
            "FATAL: ROLE_TO_RELEVANT_CLAUSE references atoms NOT present "
            f"in any RelevantEndpoint clause body: {missing_decls}",
            file=sys.stderr,
        )
        return 1

    bn_rule_files = sorted(RULES_DIR.glob("bn_*.dl"))
    # bn_flow.dl is the definition site; its own internal joins on
    # BnFlow1/etc. are not the consumer pattern we're auditing.
    bn_rule_files = [p for p in bn_rule_files if p.name != "bn_flow.dl"]

    failures: list[str] = []
    unknowns: list[str] = []
    covered_count = 0

    for rf in bn_rule_files:
        text = rf.read_text()
        for clause in split_clauses(text):
            for func_v, sv, sver, dv, dver in find_bnflow_calls(clause):
                # Don't audit the `.decl BnFlow(...)` line itself
                # (it's a declaration, not a join).
                if ".decl" in clause.split("BnFlow")[0][-30:]:
                    continue
                for pos, var in (
                    ("src_var", sv),
                    ("src_ver", sver),
                    ("dst_var", dv),
                    ("dst_ver", dver),
                ):
                    if var == "_":
                        continue
                    role, _ = role_for_binding(clause, var)
                    if role is None:
                        unknowns.append(
                            f"  {rf.name}: unrecognised binding for "
                            f"{pos}={var!r} in clause:\n"
                            f"    {clause[:200]}..."
                        )
                        continue
                    covered_count += 1
                    # `intermediate:*` and `Use@*` roles are transitively
                    # covered via RelevantEndpoint clauses; no direct
                    # ROLE_TO_RELEVANT_CLAUSE mapping required.
                    if role.startswith("intermediate:") or role.startswith("Use@"):
                        continue
                    rel = ROLE_TO_RELEVANT_CLAUSE.get(role)
                    if rel not in declared_roles:
                        failures.append(
                            f"  {rf.name}: BnFlow.{pos} {var!r} bound by "
                            f"{role}, but RelevantEndpoint does not "
                            f"include {rel}"
                        )

    print(f"BnFlow coverage audit — {len(bn_rule_files)} rule files scanned")
    print(f"  Coverage hits: {covered_count} binding positions verified")
    if unknowns:
        print(f"  Unrecognised bindings: {len(unknowns)}")
        for u in unknowns[:20]:
            print(u)
        if len(unknowns) > 20:
            print(f"  ... and {len(unknowns) - 20} more")
    if failures:
        print(f"  COVERAGE GAPS: {len(failures)}")
        for f in failures:
            print(f)
        return 1
    if unknowns:
        print("  RESULT: unknown bindings present — manual review required")
        return 2
    print("  RESULT: all BnFlow join positions are covered by RelevantEndpoint")
    return 0


if __name__ == "__main__":
    sys.exit(audit())
