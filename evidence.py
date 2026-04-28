"""Scoped evidence readers for the per-finding triage agent.

Pure-Python, no LLM / no Souffle / no Binary Ninja. Reads .facts and
.csv files from the scan output and returns subsets relevant to one
finding — function-filtered facts, taint chains, callgraph
neighborhood. The triage agent uses these as its only window into the
binary, which keeps each session's context bounded regardless of
total binary size.

Schema reference: CLAUDE.md → Fact Schema. Column 0 of every fact
relation that has a `func` field IS the function name, with the
exception of AllocSite (column 1). Relations keyed by `call_addr`
instead of `func` (ActualArg, CallArgConst, CallAddrArg) are joined
through Call.facts to recover the originating function.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Optional


# Maps each fact relation to the column index that holds the function
# name. None means the relation is keyed by call_addr and must be
# joined via Call.facts. Relations not listed here are not supported
# by `read_function_facts` (extend the table to add them).
_FUNC_COLUMN: dict[str, Optional[int]] = {
    # func at col 0
    "Def":               0,
    "Use":               0,
    "Call":              0,   # caller
    "ReturnVal":         0,
    "PhiSource":         0,
    "FormalParam":       0,
    "MemRead":           0,
    "MemWrite":          0,
    "MemWriteSize":      0,
    "MemWriteValue":     0,
    "FieldRead":         0,
    "FieldWrite":        0,
    "AddressOf":         0,
    "CFGEdge":           0,
    "Jump":              0,
    "StackVar":          0,
    "Guard":             0,
    "ArithOp":            0,
    "Cast":              0,
    "VarWidth":          0,
    "VarSign":           0,
    "EntryTaint":        0,
    "BufferWriteSource": 0,
    "TaintKill":         0,
    "PointsTo":          0,
    "TaintedVar":        0,
    "SanitizedVar":      0,
    # func at col 1 (AllocSite is keyed by call_addr but stores the
    # containing function in column 1)
    "AllocSite":         1,
    # call_addr-keyed: join via Call.facts
    "ActualArg":         None,
    "CallArgConst":      None,
    "CallAddrArg":       None,
}


def read_facts_relation(facts_dir: Path | str, relation: str) -> list[list[str]]:
    """Read a .facts TSV file. Returns [] if absent or empty.

    Souffle's .facts format is tab-separated, no header, no quoting.
    Empty lines are skipped.
    """
    p = Path(facts_dir) / f"{relation}.facts"
    if not p.exists() or p.stat().st_size == 0:
        return []
    with open(p, newline="") as f:
        return [row for row in csv.reader(f, delimiter="\t") if row]


def read_csv_relation(souffle_out: Path | str, relation: str) -> list[list[str]]:
    """Read a Souffle-output .csv file. Same TSV format as .facts."""
    p = Path(souffle_out) / f"{relation}.csv"
    if not p.exists() or p.stat().st_size == 0:
        return []
    with open(p, newline="") as f:
        return [row for row in csv.reader(f, delimiter="\t") if row]


def _call_addrs_originating_in(facts_dir: Path | str, func: str) -> set[str]:
    """Set of call_addrs of Call rows whose caller == func."""
    out: set[str] = set()
    for row in read_facts_relation(facts_dir, "Call"):
        if len(row) >= 3 and row[0] == func:
            out.add(row[2])
    return out


def read_function_facts(
    facts_dir: Path | str,
    func: str,
    relations: Optional[list[str]] = None,
) -> dict[str, list[list[str]]]:
    """Return facts filtered to function `func`.

    Args:
        facts_dir: Directory holding .facts files (e.g. scan_out/facts).
        func: Function name to filter by.
        relations: Subset of relation names to load. Defaults to all
                   relations declared in `_FUNC_COLUMN`.

    Returns:
        Dict mapping relation name → list of TSV rows. Order within
        each list matches the on-disk order. Missing or empty
        relations map to [].
    """
    fdir = Path(facts_dir)
    rels = list(_FUNC_COLUMN.keys()) if relations is None else relations

    # Pre-compute call_addrs originating in `func` only if we'll need
    # them — saves a Call.facts scan for callers that pass an explicit
    # `relations` subset that excludes call_addr-keyed relations.
    needs_call_join = any(
        r in ("ActualArg", "CallArgConst", "CallAddrArg") for r in rels
    )
    call_addrs = _call_addrs_originating_in(fdir, func) if needs_call_join else set()

    out: dict[str, list[list[str]]] = {}
    for rel in rels:
        col = _FUNC_COLUMN.get(rel)
        rows = read_facts_relation(fdir, rel)
        if col is None:
            # call_addr-keyed
            if rel in ("ActualArg", "CallArgConst", "CallAddrArg"):
                out[rel] = [r for r in rows if r and r[0] in call_addrs]
            else:
                out[rel] = []
        else:
            out[rel] = [r for r in rows if len(r) > col and r[col] == func]
    return out


def read_callers(facts_dir: Path | str, func: str) -> list[dict]:
    """Functions that call `func`, with their call_addrs."""
    callers = []
    for row in read_facts_relation(facts_dir, "Call"):
        if len(row) >= 3 and row[1] == func:
            callers.append({"caller": row[0], "callee": row[1], "addr": row[2]})
    return callers


def read_callees(facts_dir: Path | str, func: str) -> list[dict]:
    """Functions called from `func`, with their call_addrs."""
    callees = []
    for row in read_facts_relation(facts_dir, "Call"):
        if len(row) >= 3 and row[0] == func:
            callees.append({"caller": row[0], "callee": row[1], "addr": row[2]})
    return callees


def read_taint_chain(
    souffle_out: Path | str,
    origin: str,
    sink_func: str,
    sink_var: Optional[str] = None,
) -> list[list[str]]:
    """TaintedVar rows reaching `sink_func` with the given origin.

    TaintedVar schema (from interproc.dl): (func, var, ver, origin, ctx).
    Filter: rows where func == sink_func AND origin matches.
    Optionally narrow to a specific sink_var.

    Returns rows in on-disk order — which is rule-evaluation order, a
    reasonable proxy for propagation order for triage display.
    """
    rows = read_csv_relation(souffle_out, "TaintedVar")
    out = []
    for r in rows:
        if len(r) < 4:
            continue
        if r[0] != sink_func:
            continue
        if r[3] != origin:
            continue
        if sink_var is not None and r[1] != sink_var:
            continue
        out.append(r)
    return out


def read_candidate(candidates_json: Path | str, finding_id: str) -> Optional[dict]:
    """Load one candidate by its stable id from a candidates.json file."""
    p = Path(candidates_json)
    if not p.exists():
        return None
    data = json.loads(p.read_text())
    for c in data.get("candidates", []):
        if c.get("id") == finding_id:
            return c
    return None


def trace_var_to_alloc(
    facts_dir: Path | str,
    func: str,
    var: str,
    ver: int | str,
    max_depth: int = 8,
) -> list[dict]:
    """Walk Def + Use→Def + PhiSource backward from (var, ver) to find
    the AllocSite (or struct field) the variable's value originated from.

    Handles three common cases per BFS step:

      1. **Direct alloc**: the var was defined at an addr that is also
         an AllocSite call_addr (e.g. `rdi_2 = av_calloc(...)`). Returns
         the alloc info — done.
      2. **Copy / move**: the var was defined at a non-call addr; we
         look at *Use rows at the same addr* to find which other var
         was the source, and recurse into that var's Def. This is what
         catches register-to-register moves (`rdi_12 = r13`).
      3. **Field load**: the var was loaded from a struct field
         (FieldRead at the def addr). Returns the field info so the
         caller can search for a FieldWrite that wrote the field —
         typically the originating allocation lives in another
         function (`h->slice_table_base = av_calloc(...)`).
      4. **Phi**: the var has phi sources; each is enqueued.

    Args:
        facts_dir: Directory with .facts files.
        func: Function in which to do the trace.
        var, ver: Starting SSA variable.
        max_depth: BFS depth cap (defends against cycles + diverging
                   slices). Default 8 covers nearly all in-function
                   buffer-pointer chains.

    Returns:
        List of hits. Each hit dict has at least one of:
          - `alloc_call_addr` + `callee` + `elem_width` etc. (direct
            alloc), with `_alloc_resolved=True`
          - `from_field` + `field_load_addr` (field load — alloc lives
            elsewhere), with `_alloc_resolved=False`
        Plus `trace_depth` (steps from start) and `path` (visited
        (var, ver, addr) tuples). Empty list means the var did not
        originate from anything in-function we can trace (e.g. it
        comes from a function parameter, a global load, or beyond the
        depth cap).
    """
    fdir = Path(facts_dir)

    var_def: dict[tuple[str, str], str] = {}
    for row in read_facts_relation(fdir, "Def"):
        if len(row) >= 4 and row[0] == func:
            var_def[(row[1], row[2])] = row[3]

    addr_uses: dict[str, list[tuple[str, str]]] = {}
    for row in read_facts_relation(fdir, "Use"):
        if len(row) >= 4 and row[0] == func:
            addr_uses.setdefault(row[3], []).append((row[1], row[2]))

    allocs: dict[str, dict] = {}
    for row in read_facts_relation(fdir, "AllocSite"):
        if len(row) >= 5:
            allocs[row[0]] = {
                "callee": row[1],
                "size_var": row[2],
                "size_const": row[3],
                "elem_width": row[4],
            }

    phi: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for row in read_facts_relation(fdir, "PhiSource"):
        if len(row) >= 5 and row[0] == func:
            phi.setdefault((row[1], row[2]), []).append((row[3], row[4]))

    field_reads: dict[str, dict] = {}
    for row in read_facts_relation(fdir, "FieldRead"):
        if len(row) >= 4 and row[0] == func:
            field_reads[row[1]] = {"base": row[2], "field": row[3]}

    queue: list[tuple[str, str, int, list]] = [(var, str(ver), 0, [])]
    visited: set[tuple[str, str]] = set()
    found: list[dict] = []

    while queue:
        v, vr, depth, path = queue.pop(0)
        if (v, vr) in visited or depth > max_depth:
            continue
        visited.add((v, vr))

        addr = var_def.get((v, vr))
        if not addr:
            continue

        # Case 1: direct alloc
        if addr in allocs:
            found.append({
                "var": v,
                "ver": vr,
                "alloc_call_addr": addr,
                "_alloc_resolved": True,
                "trace_depth": depth,
                "path": path + [(v, vr, addr)],
                **allocs[addr],
            })
            continue

        # Case 3: field load — record and stop this branch (cross-function)
        if addr in field_reads:
            found.append({
                "var": v,
                "ver": vr,
                "from_field": field_reads[addr],
                "field_load_addr": addr,
                "_alloc_resolved": False,
                "trace_depth": depth,
                "path": path + [(v, vr, addr)],
            })
            continue

        # Case 2: copy/move — follow Uses at the same addr (excluding self)
        for (uv, uvr) in addr_uses.get(addr, []):
            if (uv, uvr) != (v, vr):
                queue.append((uv, uvr, depth + 1, path + [(v, vr, addr)]))

        # Case 4: phi
        for (sv, svr) in phi.get((v, vr), []):
            queue.append((sv, svr, depth + 1, path + [(v, vr, addr)]))

    return found


def function_evidence_summary(
    facts_dir: Path | str,
    func: str,
) -> dict:
    """Cheap summary of a function's evidence footprint — for sizing.

    Returns row counts per relation without loading all rows. Useful
    for the triage agent to decide whether to fall back to BB-scoped
    loading for a fat function (e.g., ff_h264_filter_mb).
    """
    fdir = Path(facts_dir)
    facts = read_function_facts(fdir, func)
    return {rel: len(rows) for rel, rows in facts.items() if rows}
