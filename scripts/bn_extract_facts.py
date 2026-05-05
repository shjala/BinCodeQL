#!/usr/bin/env python3
"""
BinCodeQL Headless Fact Extraction — Walk MLIL-SSA objects via Binary Ninja API.

Runs as a subprocess (no MCP). Emits Souffle-compatible .facts files directly
from BN's MLIL-SSA instruction objects, bypassing text regex parsing.

Usage:
    python3 bn_extract_facts.py /path/to/binary -f main,process_data -o facts/
    python3 bn_extract_facts.py /path/to/binary --all -o facts/
    python3 bn_extract_facts.py /path/to/binary -f main -o facts/ -v --json
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

try:
    import binaryninja
    from binaryninja import (
        MediumLevelILOperation as MLIL,
        MediumLevelILInstruction,
        RegisterValueType,
        VariableSourceType,
    )
except ImportError:
    print("[!] Error: Binary Ninja Python API not available", file=sys.stderr)
    print("    Set BN_PYTHON or BN_PYTHON_PATH env var", file=sys.stderr)
    sys.exit(1)

# Register-value types that carry a concrete integer we can emit as a
# CallArgConst. Excludes ranges, stack offsets, undetermined, etc.
_CONST_RV_TYPES = frozenset({
    RegisterValueType.ConstantValue,
    RegisterValueType.ConstantPointerValue,
    RegisterValueType.ImportedAddressValue,
})


def resolve_binary_path(binary_path: str, verbose: bool = False) -> tuple:
    """Resolve binary path, preferring .bndb sibling if it exists.

    Returns (resolved_path, is_bndb).

    Priority:
    1. If path ends with .bndb → use it directly
    2. If <path>.bndb exists → use .bndb (pre-analyzed, faster)
    3. Otherwise → use raw binary (BN will analyze from scratch)
    """
    if binary_path.lower().endswith('.bndb'):
        return binary_path, True

    bndb_sibling = binary_path + '.bndb'
    if Path(bndb_sibling).exists():
        if verbose:
            print(f"[*] Found .bndb database: {bndb_sibling}", file=sys.stderr)
        return bndb_sibling, True

    return binary_path, False


# ── Fact accumulator ──────────────────────────────────────────────────────────

class FactCollector:
    """Accumulates facts as tuples, keyed by relation name."""

    def __init__(self):
        self.facts = defaultdict(set)

    def add(self, relation: str, *columns):
        """Add a fact row. All columns are converted to strings."""
        self.facts[relation].add(tuple(str(c) for c in columns))

    # Canonical list of ALL .facts files that Souffle rules may expect.
    ALL_FACT_FILES = [
        "ActualArg.facts", "AddressOf.facts", "AllocSite.facts",
        "ArithOp.facts",
        "BlockHead.facts",
        "BufferWriteSource.facts", "CallAddrArg.facts", "CallArgConst.facts",
        "CFGBlockEdge.facts", "CFGEdge.facts", "Call.facts", "Cast.facts",
        "DangerousSink.facts", "Def.facts",
        "EntryTaint.facts",
        "FieldRead.facts", "FieldWrite.facts", "FieldWriteValue.facts",
        "FormalParam.facts",
        "Guard.facts", "Jump.facts", "MemRead.facts", "MemWrite.facts",
        "MemWriteSize.facts", "MemWriteValue.facts",
        "PhiSource.facts", "PointsTo.facts", "ReturnVal.facts",
        "StackVar.facts", "TaintKill.facts", "TaintSourceFunc.facts",
        "TaintTransfer.facts", "Use.facts", "VarSign.facts", "VarWidth.facts",
    ]

    def write_all(self, output_dir: Path):
        """Write all accumulated facts to .facts files (TSV)."""
        output_dir.mkdir(parents=True, exist_ok=True)
        stats = {}
        for relation, rows in sorted(self.facts.items()):
            path = output_dir / f"{relation}.facts"
            sorted_rows = sorted(rows)
            with open(path, 'w') as f:
                for row in sorted_rows:
                    f.write('\t'.join(row) + '\n')
            stats[f"{relation}.facts"] = len(sorted_rows)

        # Ensure all schema relations have a .facts file (empty if no data)
        for filename in self.ALL_FACT_FILES:
            filepath = output_dir / filename
            if not filepath.exists():
                filepath.touch()

        return stats

    def summary(self):
        return {name: len(rows) for name, rows in sorted(self.facts.items())}


# ── SSA variable helpers ──────────────────────────────────────────────────────

def ssa_var_name(var):
    """Get the name string of an SSA variable."""
    if hasattr(var, 'var'):
        return var.var.name
    if hasattr(var, 'name'):
        return var.name
    return str(var)


def ssa_var_version(var):
    """Get the version of an SSA variable."""
    if hasattr(var, 'version'):
        return var.version
    return 0


def ssa_str(var):
    """Return 'name' for an SSA var."""
    return ssa_var_name(var)


def decompose_load_addr(expr):
    """Split a load-address expression into (base, offset) strings.

    Recognizes the common shapes:
      - MLIL_VAR_SSA(v)                 → ("v#k",   "0")
      - MLIL_ADD(var, const)            → ("v#k",   "<const>")
      - MLIL_ADD(var_a, var_b)          → ("va#i",  "vb#j")
      - MLIL_ADD(ptr, MLIL_MUL(idx, N)) → ("ptr#k", "idx#j")     (scaled index)
      - MLIL_CONST_PTR                  → ("<const_ptr>", "0")
    Falls back to (str(expr), "0") otherwise. The output is used purely as
    string identifiers for Datalog joins — Use facts on the same addr already
    exist independently, so under-decomposition never loses a Use, it only
    reduces offset-column precision.
    """
    if expr is None:
        return ("", "0")
    op = expr.operation

    def var_str(v):
        name = ssa_var_name(v.src) if op_of(v) == MLIL.MLIL_VAR_SSA else None
        ver = ssa_var_version(v.src) if op_of(v) == MLIL.MLIL_VAR_SSA else None
        return f"{name}#{ver}" if name is not None else None

    def op_of(v):
        return v.operation if v is not None else None

    # Simple variable load
    if op == MLIL.MLIL_VAR_SSA:
        name = ssa_var_name(expr.src)
        ver = ssa_var_version(expr.src)
        return (f"{name}#{ver}", "0")

    # base + offset
    if op == MLIL.MLIL_ADD:
        left = expr.left
        right = expr.right
        lop = op_of(left)
        rop = op_of(right)

        # var + const
        if lop == MLIL.MLIL_VAR_SSA and rop in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
            vs = var_str(left)
            if vs:
                return (vs, str(right.constant))
        if rop == MLIL.MLIL_VAR_SSA and lop in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
            vs = var_str(right)
            if vs:
                return (vs, str(left.constant))

        # var + var  (heuristic: the pointer-like operand is the "base")
        if lop == MLIL.MLIL_VAR_SSA and rop == MLIL.MLIL_VAR_SSA:
            return (var_str(left) or str(left), var_str(right) or str(right))

        # var + (var * N)  — scaled-index pattern; treat the multiplicand as offset
        if lop == MLIL.MLIL_VAR_SSA and rop == MLIL.MLIL_MUL:
            inner = right.left if op_of(right.left) == MLIL.MLIL_VAR_SSA else right.right
            if op_of(inner) == MLIL.MLIL_VAR_SSA:
                return (var_str(left) or str(left), var_str(inner) or str(inner))
        if rop == MLIL.MLIL_VAR_SSA and lop == MLIL.MLIL_MUL:
            inner = left.left if op_of(left.left) == MLIL.MLIL_VAR_SSA else left.right
            if op_of(inner) == MLIL.MLIL_VAR_SSA:
                return (var_str(right) or str(right), var_str(inner) or str(inner))

    if op in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
        return (str(expr.constant), "0")

    # Fallback — keep the whole expression as base.
    return (str(expr), "0")


def emit_var_sign(fc, func_name, var_obj, name, ver):
    """Emit a VarSign fact when BN's type system indicates signedness.

    Ground truth for signedness when DWARF/type info is present — superior
    to the bn_signed_infer.dl heuristic. Missing type info (stripped binaries)
    → no fact emitted, downstream falls back to the heuristic.
    """
    try:
        t = var_obj.var.type
        sign_str = None
        # BN's integer types expose a .signed attribute
        if hasattr(t, 'signed'):
            sign_str = "signed" if t.signed else "unsigned"
        if sign_str:
            fc.add("VarSign", func_name, name, ver, sign_str)
    except (AttributeError, TypeError):
        pass


# ── Expression walkers ────────────────────────────────────────────────────────

def collect_uses(fc, func_name, expr, addr):
    """Recursively collect Use facts from an MLIL-SSA expression."""
    if expr is None:
        return
    op = expr.operation

    if op == MLIL.MLIL_VAR_SSA:
        name = ssa_var_name(expr.src)
        ver = ssa_var_version(expr.src)
        fc.add("Use", func_name, name, ver, addr)
        return

    if op == MLIL.MLIL_VAR_SSA_FIELD:
        name = ssa_var_name(expr.src)
        ver = ssa_var_version(expr.src)
        fc.add("Use", func_name, name, ver, addr)
        return

    if op == MLIL.MLIL_ADDRESS_OF:
        # &var — the var itself is not "used" in the data-flow sense
        return

    if op == MLIL.MLIL_ADDRESS_OF_FIELD:
        return

    # Recurse into sub-expressions via operands
    for operand in expr.operands:
        if isinstance(operand, MediumLevelILInstruction):
            collect_uses(fc, func_name, operand, addr)
        elif isinstance(operand, list):
            for item in operand:
                if isinstance(item, MediumLevelILInstruction):
                    collect_uses(fc, func_name, item, addr)


def collect_value_vars(fc, func_name, expr, addr, relation):
    """Like collect_uses, but emits to a caller-specified relation —
    used to record which SSA variables contribute to a specific position
    in an instruction (the stored value of a STORE, the return
    expression of a RETURN, etc.) distinct from uses contributed by the
    destination-address computation.

    Width-mismatch detection needs this separation: at a MLIL_STORE_SSA
    instruction the address computation uses pointer-width variables
    while the stored value may be narrower — a rule that matches on
    generic Use(addr) cannot tell them apart and produces false
    positives. Having MemWriteValue as a distinct relation cleanly
    resolves the class for any store pattern, not just width-mismatch.
    """
    if expr is None:
        return
    op = expr.operation

    if op in (MLIL.MLIL_VAR_SSA, MLIL.MLIL_VAR_SSA_FIELD):
        name = ssa_var_name(expr.src)
        ver = ssa_var_version(expr.src)
        fc.add(relation, func_name, addr, name, ver)
        return

    # Stop at ADDRESS_OF — the stored-value of `*p = &x` is the address
    # of x, not x's value. Rules that care about the taken-address form
    # can join with AddressOf separately.
    if op in (MLIL.MLIL_ADDRESS_OF, MLIL.MLIL_ADDRESS_OF_FIELD):
        return

    for operand in expr.operands:
        if isinstance(operand, MediumLevelILInstruction):
            collect_value_vars(fc, func_name, operand, addr, relation)
        elif isinstance(operand, list):
            for item in operand:
                if isinstance(item, MediumLevelILInstruction):
                    collect_value_vars(fc, func_name, item, addr, relation)


# ── Comparison operator mapping for Guard extraction ─────────────────────────

COMPARISON_OPS = {
    MLIL.MLIL_CMP_SLT, MLIL.MLIL_CMP_ULT,
    MLIL.MLIL_CMP_SLE, MLIL.MLIL_CMP_ULE,
    MLIL.MLIL_CMP_SGT, MLIL.MLIL_CMP_UGT,
    MLIL.MLIL_CMP_SGE, MLIL.MLIL_CMP_UGE,
    MLIL.MLIL_CMP_E, MLIL.MLIL_CMP_NE,
}

COMPARISON_OP_MAP = {
    MLIL.MLIL_CMP_SLT: "slt", MLIL.MLIL_CMP_ULT: "ult",
    MLIL.MLIL_CMP_SLE: "sle", MLIL.MLIL_CMP_ULE: "ule",
    MLIL.MLIL_CMP_SGT: "sgt", MLIL.MLIL_CMP_UGT: "ugt",
    MLIL.MLIL_CMP_SGE: "sge", MLIL.MLIL_CMP_UGE: "uge",
    MLIL.MLIL_CMP_E: "eq", MLIL.MLIL_CMP_NE: "ne",
}

# Flipped operators for const OP var → var FLIPPED_OP const
COMPARISON_FLIP_MAP = {
    MLIL.MLIL_CMP_SLT: "sgt", MLIL.MLIL_CMP_ULT: "ugt",
    MLIL.MLIL_CMP_SLE: "sge", MLIL.MLIL_CMP_ULE: "uge",
    MLIL.MLIL_CMP_SGT: "slt", MLIL.MLIL_CMP_UGT: "ult",
    MLIL.MLIL_CMP_SGE: "sle", MLIL.MLIL_CMP_UGE: "ule",
    MLIL.MLIL_CMP_E: "eq", MLIL.MLIL_CMP_NE: "ne",
}


def _resolve_const_addr(bv, target_addr):
    """Map a code/data constant address to its symbol name."""
    funcs = bv.get_functions_containing(target_addr)
    if funcs:
        return funcs[0].name
    sym = bv.get_symbol_at(target_addr)
    if sym:
        return sym.name
    return None


def _resolve_var_through_global_load(bv, mlil_func, ssa_var):
    """Trace an SSA call-target var back to a global function-pointer load.

    libxml2 / glib / SQLite / OpenSSL and similar libraries install allocators
    and I/O as globals:  xmlMallocFunc xmlMalloc = malloc;
    At binary level a `(*xmlMalloc)(size)` compiles to:
        rax = [<addr_of_xmlMalloc_global>]
        call rax
    i.e. `MLIL_CALL_SSA(dest=MLIL_VAR_SSA, ...)` where the var is defined by
    `MLIL_LOAD_SSA(MLIL_CONST_PTR)`. Returning the global's symbol name
    ("xmlMalloc") turns the call into a named one that every existing
    signature-matching rule picks up.
    """
    try:
        defn = mlil_func.get_ssa_var_definition(ssa_var)
    except Exception:
        return None
    if defn is None:
        return None

    # defn is an MLIL-SSA instruction. For MLIL_SET_VAR_SSA, src is the RHS.
    src = getattr(defn, "src", None)
    if src is None:
        return None

    if src.operation != MLIL.MLIL_LOAD_SSA:
        return None

    # The load address must be a const pointer, an import, or a symbol ref.
    # BN uses MLIL_IMPORT for imported globals (e.g. xmlRealloc resolved to
    # a GOT entry) and MLIL_CONST_PTR for data-section globals.
    load_addr_expr = src.src
    if load_addr_expr.operation in (MLIL.MLIL_CONST_PTR, MLIL.MLIL_CONST,
                                    MLIL.MLIL_IMPORT):
        global_addr = load_addr_expr.constant
        sym = bv.get_symbol_at(global_addr)
        if sym and sym.name:
            return sym.name
    return None


def resolve_callee(bv, insn):
    """Resolve the callee of a CALL instruction to a function name."""
    dest = insn.dest
    if dest.operation == MLIL.MLIL_CONST_PTR or dest.operation == MLIL.MLIL_CONST:
        target_addr = dest.constant
        name = _resolve_const_addr(bv, target_addr)
        return name if name is not None else hex(target_addr)
    if dest.operation == MLIL.MLIL_IMPORT:
        return dest.constant  # import address
    # Indirect through an SSA var — try to resolve through a global load.
    if dest.operation == MLIL.MLIL_VAR_SSA:
        try:
            name = _resolve_var_through_global_load(bv, insn.function, dest.src)
            if name:
                return name
        except Exception:
            pass
    return "<indirect>"


# ── AllocSite helper ──────────────────────────────────────────────────────────

# Allocator callees → (size_arg_idx, elem_size_arg_idx).
# elem_size_arg_idx = -1 means no explicit elem_size arg (malloc / xmlMalloc style).
# Kept in sync with BnAllocFunc in rules/bn_alloc_copy.dl; the superset here
# also covers Windows heap APIs, kernel allocators, and common C++ forms so
# AllocSite facts are emitted uniformly regardless of target platform.
_ALLOC_CALLEES = {
    # ── Standard libc ────────────────────────────────────────────────
    "malloc":               (0, -1),
    "xmalloc":              (0, -1),
    "calloc":               (0, 1),    # calloc(count, elem_size)
    "realloc":              (1, -1),   # realloc(ptr, size)
    "reallocarray":         (1, 2),    # reallocarray(ptr, count, elem_size)
    "aligned_alloc":        (1, -1),   # aligned_alloc(align, size)
    "memalign":             (1, -1),   # memalign(align, size)
    "posix_memalign":       (2, -1),   # posix_memalign(&ptr, align, size)
    "valloc":               (0, -1),
    "pvalloc":              (0, -1),
    "alloca":               (0, -1),
    "strdup":               (0, -1),   # size comes from strlen, treated as var
    "strndup":              (1, -1),
    # ── C++ operator new (mangled names emitted by BN) ───────────────
    "operator new":         (0, -1),
    "operator new[]":       (0, -1),
    "_Znwm":                (0, -1),   # operator new(size_t)
    "_Znam":                (0, -1),   # operator new[](size_t)
    "_Znwj":                (0, -1),   # 32-bit operator new
    "_Znaj":                (0, -1),   # 32-bit operator new[]
    # ── glib ─────────────────────────────────────────────────────────
    "g_malloc":             (0, -1),
    "g_malloc0":            (0, -1),
    "g_try_malloc":         (0, -1),
    "g_try_malloc0":        (0, -1),
    "g_realloc":            (1, -1),
    "g_try_realloc":        (1, -1),
    "g_new":                (0, -1),   # macro — may be inlined
    "g_new0":               (0, -1),
    # ── libxml2 ──────────────────────────────────────────────────────
    "xmlMalloc":            (0, -1),
    "xmlMallocAtomic":      (0, -1),
    "xmlMemMalloc":         (0, -1),
    "xmlRealloc":           (1, -1),
    "xmlMemRealloc":        (1, -1),
    # ── Windows heap APIs (size_arg_idx varies per API) ──────────────
    "HeapAlloc":            (2, -1),   # HeapAlloc(heap, flags, size)
    "HeapReAlloc":          (3, -1),   # HeapReAlloc(heap, flags, ptr, size)
    "LocalAlloc":           (1, -1),   # LocalAlloc(flags, size)
    "LocalReAlloc":         (1, -1),
    "GlobalAlloc":          (1, -1),
    "GlobalReAlloc":        (1, -1),
    "VirtualAlloc":         (1, -1),   # VirtualAlloc(addr, size, type, prot)
    "VirtualAllocEx":       (2, -1),
    "CoTaskMemAlloc":       (0, -1),
    "SysAllocString":       (0, -1),
    # ── Linux kernel / drivers ───────────────────────────────────────
    "kmalloc":              (0, -1),
    "kzalloc":              (0, -1),
    "kcalloc":              (0, 1),
    "krealloc":             (1, -1),
    "vmalloc":              (0, -1),
    "vzalloc":              (0, -1),
    "devm_kmalloc":         (1, -1),   # devm_kmalloc(dev, size, gfp)
    "devm_kzalloc":         (1, -1),
    "kmem_cache_alloc":     (0, -1),
    "kmem_cache_zalloc":    (0, -1),
    # ── FFmpeg / libav (very common in video/audio codecs) ───────────
    "av_malloc":            (0, -1),
    "av_mallocz":           (0, -1),
    "av_calloc":            (0, 1),     # av_calloc(nmemb, size)
    "av_malloc_array":      (0, 1),     # av_malloc_array(nmemb, size)
    "av_mallocz_array":     (0, 1),     # av_mallocz_array(nmemb, size)
    "av_realloc":           (1, -1),    # av_realloc(ptr, size)
    "av_realloc_f":         (1, 2),     # av_realloc_f(ptr, nmemb, size)
    "av_reallocp":          (1, -1),
    "av_reallocp_array":    (1, 2),
    "av_fast_malloc":       (1, -1),    # av_fast_malloc(&ptr, &size, min_size)
    "av_fast_mallocz":      (1, -1),
    "av_fast_realloc":      (1, -1),
    "av_strdup":            (0, -1),
    "av_strndup":            (1, -1),
    # ── Other common wrappers ────────────────────────────────────────
    "mem_alloc":            (0, -1),
    "reallocf":             (1, -1),
}


# Callees whose first argument is a destination buffer pointer that is
# typically loaded well upstream of the call (post-alloc, often in a
# different basic block). When the fact-extractor's register fallback
# recovers actual args for an unprototyped call, arg 0 of these
# callees is allowed to resolve via cross-BB reaching state — without
# this relaxation, the SSA identity of the buffer is lost and rules
# like bn_sentinel_init fall back to a synthetic "_unbound" buffer,
# which then can't be flow-linked to an AllocSite. Other arg indexes
# still go through the strict same-BB gate (they're typically fill
# values / sizes computed at the call site).
_STABLE_PTR_ARG0_CALLEES = frozenset({
    # memset family
    "memset", "memset_s", "__memset_chk", "__builtin_memset",
    "__builtin___memset_chk", "wmemset", "__builtin_wmemset",
    "RtlFillMemory", "FillMemory", "bzero", "explicit_bzero",
    # memcpy / memmove family
    "memcpy", "memmove", "memccpy",
    "__memcpy_chk", "__memmove_chk",
    "__builtin_memcpy", "__builtin_memmove",
    "__builtin___memcpy_chk", "__builtin___memmove_chk",
    # string copies
    "strcpy", "strncpy", "strcat", "strncat",
    "__strcpy_chk", "__strncpy_chk", "__strcat_chk", "__strncat_chk",
    # printf-to-buffer
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "__sprintf_chk", "__snprintf_chk", "__vsprintf_chk", "__vsnprintf_chk",
    # libxml2 wrappers (arg 0 is dst)
    "xmlStrcpy", "xmlStrcat", "xmlStrncpy", "xmlStrncat",
    "xmlMemcpy", "xmlMemmove",
})


def _arg_const(arg):
    """Return int value if arg is a literal constant, else None."""
    try:
        if arg.operation in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
            return int(arg.constant)
    except (AttributeError, TypeError):
        pass
    return None


def _arg_mul_const_factor(arg):
    """If arg is `n * K` or `K * n` with K a constant, return (var_side, K).
    Returns (None, None) otherwise."""
    try:
        if arg.operation != MLIL.MLIL_MUL:
            return (None, None)
        left, right = arg.left, arg.right
        lc = _arg_const(left)
        rc = _arg_const(right)
        if rc is not None and lc is None:
            return (left, rc)
        if lc is not None and rc is None:
            return (right, lc)
    except (AttributeError, TypeError):
        pass
    return (None, None)


def emit_alloc_site(fc, callee, call_addr, params):
    """Emit AllocSite(call_addr, callee, size_var, size_const, elem_width)
    when callee is a known heap allocator.

    - size_var:    the SSA name when size is a variable, else "_".
    - size_const:  the literal byte count when size is constant, else "0".
    - elem_width:  heuristic element width — the constant factor when the
                   size arg is `n * K` (e.g. malloc(n * 2) → 2), or the
                   calloc/reallocarray elem_size arg when present. 0 if
                   unknown.
    """
    spec = _ALLOC_CALLEES.get(callee)
    if spec is None:
        return
    size_idx, elem_idx = spec
    if size_idx >= len(params):
        return

    size_arg = params[size_idx]
    size_var = "_"
    size_const = "0"
    elem_width = 0

    # Case 1: calloc(count, elem_size) / reallocarray(ptr, count, elem_size)
    if elem_idx >= 0 and elem_idx < len(params):
        esz = _arg_const(params[elem_idx])
        if esz is not None and esz > 0:
            elem_width = esz
        # size_var / size_const from the count arg
        cnt_const = _arg_const(size_arg)
        if cnt_const is not None:
            size_const = str(cnt_const * (elem_width or 1))
        else:
            try:
                if size_arg.operation == MLIL.MLIL_VAR_SSA:
                    size_var = ssa_var_name(size_arg.src)
            except (AttributeError, TypeError):
                pass
    else:
        # Case 2: malloc-style — single size arg.
        # Recognize `n * K` patterns to recover elem_width.
        var_side, factor = _arg_mul_const_factor(size_arg)
        if var_side is not None:
            elem_width = factor
            try:
                if var_side.operation == MLIL.MLIL_VAR_SSA:
                    size_var = ssa_var_name(var_side.src)
            except (AttributeError, TypeError):
                pass
        else:
            c = _arg_const(size_arg)
            if c is not None:
                size_const = str(c)
            else:
                try:
                    if size_arg.operation == MLIL.MLIL_VAR_SSA:
                        size_var = ssa_var_name(size_arg.src)
                except (AttributeError, TypeError):
                    pass

    fc.add("AllocSite", call_addr, callee, size_var, size_const, elem_width)


# ── Register-ABI fallback for calls with unbound params ──────────────────────
#
# BN's MLIL-SSA sometimes renders a resolved call as `0x<addr>()` with an
# empty `insn.params` — this happens when the callee has no attached function
# prototype (common for libc symbols on stripped binaries, or for indirect
# call targets that were resolved via data-flow but aren't proper functions
# in BN's sense). The upstream extractor loop walks `insn.params` to emit
# CallArgConst / ActualArg / CallAddrArg, so when params is empty we never
# record the argument constants — which silently blocks any rule that
# reasons about call-arg literals (memset fill bytes, size constants, etc.).
#
# The fallback below uses BN's static register-value analysis
# (`func.get_reg_value_at`) combined with the calling convention's
# int_arg_regs list to recover constant args even when MLIL doesn't bind
# them. The ABI comes from BN itself — this works uniformly for x86-64
# SysV, Windows x64, AArch64 AAPCS, etc. without hardcoded register names.

def resolve_callee_cc(bv, caller_func, insn):
    """Return the CallingConvention that governs this call.

    Prefer the callee's declared CC (so an explicitly-typed import with a
    non-default CC wins); fall back to the caller's CC when the callee is
    unresolved, an import stub, or has no CC attached.
    """
    try:
        dest = insn.dest
        op = dest.operation
        if op in (MLIL.MLIL_CONST_PTR, MLIL.MLIL_CONST):
            callee_addr = dest.constant
            callee_func = bv.get_function_at(callee_addr)
            if callee_func is not None and callee_func.calling_convention is not None:
                return callee_func.calling_convention
    except (AttributeError, TypeError):
        pass
    return caller_func.calling_convention


def extract_reg_args_fallback(bv, caller_func, insn, call_addr, fc, func_name,
                              reg_state, callee=None):
    """When insn.params is empty, reconstruct actual args from the
    reaching register state at the call site.

    Two paths:
      1. Constant args → emit `CallArgConst(call_addr, arg_idx, value)`
         from BN's static register-value analysis.
      2. Non-constant args → emit `ActualArg(call_addr, arg_idx, "_",
         var, ver)` using the latest reg-backed SSA def from reg_state,
         FILTERED to defs within the same basic block as the call.

    The basic-block gate prevents spurious ActualArg emissions for
    args the callee doesn't actually take. Real calls set up their
    args in the same block (callers move values into the ABI registers
    immediately before CALL). A reg_state entry whose def lives in an
    earlier block is stale reaching state — we can't distinguish a
    "real arg" from "leftover register value" without a callee
    prototype, and unprototyped callees are precisely the case that
    drives this fallback.

    Exception — _STABLE_PTR_ARG0_CALLEES: for well-known stdlib and
    compiler-builtin functions whose first argument is a destination
    buffer pointer (memset, memcpy, strcpy, ...), the pointer is almost
    always loaded well upstream of the call (post-alloc in a different
    BB). Accepting cross-BB reg_state for arg 0 of these callees
    recovers the SSA identity of the buffer — upgrading e.g.
    BnSentinelCollisionRisk from Tier C (structural) to Tier A/B
    (flow-linked) on real targets like the FFmpeg H.264 slice_table
    CVE. Other args (size, fill value) still go through the strict
    same-BB gate.

    Path 2 is what makes summary-based interprocedural analysis work
    across this kind of call: actual→formal param mapping depends on
    ActualArg, and without (2) any rule that propagates through the
    callee (bn_sentinel_buf, bn_alloc_copy dest propagation, interproc
    taint on the buffer arg) silently drops calls whose args were
    register-passed without an attached prototype.

    `reg_state` entries are (var_name, var_ver, def_bb_start_idx). We
    compare against `call_bb_start_idx` for the same-block filter.
    """
    relax_bb_for_arg0 = callee in _STABLE_PTR_ARG0_CALLEES
    try:
        call_bb_start = insn.il_basic_block.start
    except AttributeError:
        call_bb_start = None
    cc = resolve_callee_cc(bv, caller_func, insn)
    if cc is None:
        return
    try:
        arg_regs = list(cc.int_arg_regs)
    except (AttributeError, TypeError):
        return

    for arg_idx, reg_name in enumerate(arg_regs):
        try:
            rv = caller_func.get_reg_value_at(call_addr, reg_name)
        except (AttributeError, KeyError, TypeError):
            rv = None

        # Path 1: constant arg — record its literal value
        if rv is not None and rv.type in _CONST_RV_TYPES:
            try:
                fc.add("CallArgConst", call_addr, arg_idx, str(rv.value))
                # A constant arg also gets ActualArg with a synthetic
                # "_const" var name; downstream rules that want the SSA
                # identity filter on var != "_const" / != "_unbound".
                fc.add("ActualArg", call_addr, arg_idx, "_", "_const", 0)
            except (AttributeError, TypeError):
                pass
            continue

        # Path 2: non-constant arg — look up the SSA var currently
        # bound to this register in the caller's reaching state.
        # Produces the actual→formal mapping that was lost when BN
        # rendered the call with empty insn.params.
        bound = reg_state.get(reg_name)
        if bound is not None:
            var_name, var_ver, def_bb_start = bound
            # Same-BB gate: skip stale reg_state entries whose def
            # lives in an earlier basic block (they're not real args).
            # Exception: for known stable-pointer-arg-0 callees, arg 0
            # comes from an upstream buffer load; keep cross-BB match.
            cross_bb = (call_bb_start is not None
                        and def_bb_start is not None
                        and def_bb_start != call_bb_start)
            if cross_bb and not (relax_bb_for_arg0 and arg_idx == 0):
                continue
            try:
                fc.add("ActualArg", call_addr, arg_idx, "_",
                       var_name, var_ver)
                # Also record the variable's Use at this address so
                # taint / data-flow rules treat the arg as a read site
                # (matches what the normal MLIL_VAR_SSA branch does).
                fc.add("Use", func_name, var_name, var_ver, call_addr)
            except (AttributeError, TypeError):
                pass


def _update_reg_state(insn, reg_state, bv):
    """After processing a defining instruction (SET_VAR_SSA or
    CALL_SSA), update `reg_state[reg_name] = (var_name, var_ver,
    def_bb_start_idx)` for each dest variable that is backed by a
    register. The bb_start_idx lets call-site fallbacks enforce a
    same-block filter (see extract_reg_args_fallback). Non-register
    destinations (stack-slot variables, flags, etc.) don't affect the
    reg map. Called from the extractor's main instruction loop to
    maintain a forward-walking reaching-def snapshot.
    """
    try:
        def_bb_start = insn.il_basic_block.start
    except AttributeError:
        def_bb_start = None
    op = insn.operation
    if op == MLIL.MLIL_SET_VAR_SSA:
        dests = [insn.dest]
    elif op == MLIL.MLIL_SET_VAR_SSA_FIELD:
        dests = [insn.dest]
    elif op == MLIL.MLIL_CALL_SSA:
        dests = list(getattr(insn, "output", []) or [])
    elif op == MLIL.MLIL_VAR_PHI:
        dests = [insn.dest]
    else:
        return

    for d in dests:
        try:
            underlying = d.var
            if underlying.source_type != VariableSourceType.RegisterVariableSourceType:
                continue
            reg_name = bv.arch.get_reg_name(underlying.storage)
            if not reg_name:
                continue
            reg_state[reg_name] = (ssa_var_name(d), ssa_var_version(d),
                                   def_bb_start)
        except (AttributeError, TypeError):
            continue


# ── Main extraction logic ─────────────────────────────────────────────────────

def find_function(bv, name):
    """Find a function by name in the binary view."""
    funcs = bv.get_functions_by_name(name)
    if funcs:
        return funcs[0]
    return None


CAST_OPS = {
    MLIL.MLIL_SX: "sx",
    MLIL.MLIL_ZX: "zx",
    MLIL.MLIL_LOW_PART: "trunc",
}


def extract_function_facts(bv, func, fc, verbose=False):
    """Extract all facts from a single function's MLIL-SSA."""
    func_name = func.name

    if func.mlil is None:
        if verbose:
            print(f"  [SKIP] {func_name}: no MLIL available", file=sys.stderr)
        return

    try:
        mlil = func.mlil.ssa_form
    except Exception as e:
        if verbose:
            print(f"  [SKIP] {func_name}: SSA form error: {e}", file=sys.stderr)
        return

    if mlil is None:
        if verbose:
            print(f"  [SKIP] {func_name}: no SSA form", file=sys.stderr)
        return

    # Block-level CFG: emit CFGBlockEdge(func, src_block_addr, dst_block_addr)
    # using real instruction addresses on both ends, plus
    # BlockHead(func, instr_addr, block_addr) so downstream rules can
    # look up the block of any instruction. Needed for proper CFG
    # transitive closure (the legacy CFGEdge mixes instr-addr `from`
    # with bb-index `to` and is therefore non-composing).
    try:
        for bb in mlil.basic_blocks:
            try:
                bb_start_addr = mlil[bb.start].address
            except Exception:
                continue
            for i in range(bb.start, bb.end):
                try:
                    fc.add("BlockHead", func_name, mlil[i].address, bb_start_addr)
                except Exception:
                    pass
            for edge in bb.outgoing_edges:
                try:
                    succ_start_addr = mlil[edge.target.start].address
                except Exception:
                    continue
                fc.add("CFGBlockEdge", func_name, bb_start_addr, succ_start_addr)
    except Exception as e:
        if verbose:
            print(f"  [WARN] {func_name}: block-CFG extraction: {e}", file=sys.stderr)

    # Track version-0 vars for FormalParam detection
    defined_v0 = set()
    used_v0 = {}  # var_name -> min_addr

    # Forward-walking reaching-def snapshot for register-backed SSA
    # variables. Consumed by extract_reg_args_fallback when a call has
    # empty insn.params — lets us recover actual-to-formal parameter
    # mapping for calls that BN didn't bind (e.g. prototypeless libc).
    reg_state: dict = {}
    prev_insn = None

    for insn in mlil.instructions:
        # Update reg_state from the previously-processed instruction
        # before handling the current one. This ensures that when we
        # reach a call with unbound params, reg_state reflects every
        # reaching def UP TO but not including the call itself —
        # semantically correct "reaching definitions at call site".
        if prev_insn is not None:
            _update_reg_state(prev_insn, reg_state, bv)
        prev_insn = insn

        addr = insn.address
        op = insn.operation

        # ── SET_VAR_SSA: var#ver = expr ──
        if op == MLIL.MLIL_SET_VAR_SSA:
            dst = insn.dest
            name = ssa_var_name(dst)
            ver = ssa_var_version(dst)
            fc.add("Def", func_name, name, ver, addr)
            if ver == 0:
                defined_v0.add(name)

            src = insn.src

            # Check for address-of
            if src.operation == MLIL.MLIL_ADDRESS_OF:
                target = src.src
                target_name = ssa_var_name(target) if hasattr(target, 'name') or hasattr(target, 'var') else str(target)
                fc.add("AddressOf", func_name, name, ver, target_name)
            elif src.operation == MLIL.MLIL_ADDRESS_OF_FIELD:
                target = src.src
                target_name = ssa_var_name(target) if hasattr(target, 'name') or hasattr(target, 'var') else str(target)
                fc.add("AddressOf", func_name, name, ver, target_name)

            # Check for arithmetic operation: var = var2 op const/var3
            ARITH_OPS = {
                MLIL.MLIL_ADD, MLIL.MLIL_SUB, MLIL.MLIL_MUL,
                MLIL.MLIL_LSL, MLIL.MLIL_LSR,
            }
            ARITH_OP_MAP = {
                MLIL.MLIL_ADD: "add", MLIL.MLIL_SUB: "sub",
                MLIL.MLIL_MUL: "mul", MLIL.MLIL_LSL: "lsl",
                MLIL.MLIL_LSR: "lsr",
            }
            if src.operation in ARITH_OPS:
                op_str = ARITH_OP_MAP[src.operation]
                left = src.left
                right = src.right
                if left.operation == MLIL.MLIL_VAR_SSA:
                    src_name = ssa_var_name(left.src)
                    src_ver = ssa_var_version(left.src)
                    if right.operation in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
                        operand = str(right.constant)
                    elif right.operation == MLIL.MLIL_VAR_SSA:
                        operand = ssa_var_name(right.src)
                    else:
                        operand = str(right)
                    fc.add("ArithOp", func_name, addr, name, ver,
                           op_str, src_name, src_ver, operand)
                elif right.operation == MLIL.MLIL_VAR_SSA:
                    # Commuted: const op var
                    src_name = ssa_var_name(right.src)
                    src_ver = ssa_var_version(right.src)
                    if left.operation in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
                        operand = str(left.constant)
                    else:
                        operand = str(left)
                    fc.add("ArithOp", func_name, addr, name, ver,
                           op_str, src_name, src_ver, operand)

            # Check for cast operation (sign-extend, zero-extend, truncation)
            if src.operation in CAST_OPS:
                cast_kind = CAST_OPS[src.operation]
                inner = src.src
                src_width = inner.size
                dst_width = src.size
                if inner.operation == MLIL.MLIL_VAR_SSA:
                    fc.add("Cast", func_name, addr, name, ver,
                           ssa_var_name(inner.src), ssa_var_version(inner.src),
                           cast_kind, src_width, dst_width)

            # Emit VarWidth for every defined variable
            try:
                fc.add("VarWidth", func_name, name, ver, dst.var.type.width)
            except (AttributeError, TypeError):
                # Fallback to expression size if type width unavailable
                try:
                    fc.add("VarWidth", func_name, name, ver, src.size)
                except (AttributeError, TypeError):
                    pass

            # Emit VarSign when BN type info carries signedness
            emit_var_sign(fc, func_name, dst, name, ver)

            # Check for memory read: var = [expr].size
            if src.operation == MLIL.MLIL_LOAD_SSA:
                load_src = src.src
                base, offset = decompose_load_addr(load_src)
                fc.add("MemRead", func_name, addr, base, offset, str(src.size))
                fc.add("Use", func_name, "mem", ssa_var_version(src.src_memory), addr)

            # Check for struct-field read: var = base->field
            #
            # Emits FieldRead(func, addr, base, field_off) so a Datalog
            # rule can connect a producer's FieldWrite of an alloc result
            # into a struct field with a consumer's FieldRead of the same
            # field — that's the buffer-attribution chain that lets
            # cross-function triage prove the producer-consumer linkage.
            if src.operation == MLIL.MLIL_LOAD_STRUCT_SSA:
                fc.add("FieldRead", func_name, addr, str(src.src), str(src.offset))
                fc.add("Use", func_name, "mem", ssa_var_version(src.src_memory), addr)

            # Collect uses from RHS
            collect_uses(fc, func_name, src, addr)
            continue

        # ── SET_VAR_SSA_FIELD: partial variable write ──
        if op == MLIL.MLIL_SET_VAR_SSA_FIELD:
            dst = insn.dest
            name = ssa_var_name(dst)
            ver = ssa_var_version(dst)
            fc.add("Def", func_name, name, ver, addr)
            if ver == 0:
                defined_v0.add(name)
            # Previous version is a use
            prev = insn.prev
            fc.add("Use", func_name, ssa_var_name(prev), ssa_var_version(prev), addr)
            collect_uses(fc, func_name, insn.src, addr)
            continue

        # ── VAR_PHI: var#N = phi(var#A, var#B, ...) ──
        if op == MLIL.MLIL_VAR_PHI:
            dst = insn.dest
            name = ssa_var_name(dst)
            ver = ssa_var_version(dst)
            fc.add("Def", func_name, name, ver, addr)
            if ver == 0:
                defined_v0.add(name)
            try:
                fc.add("VarWidth", func_name, name, ver, dst.var.type.width)
            except (AttributeError, TypeError):
                pass
            emit_var_sign(fc, func_name, dst, name, ver)

            for src in insn.src:
                src_name = ssa_var_name(src)
                src_ver = ssa_var_version(src)
                fc.add("PhiSource", func_name, name, ver, src_name, src_ver)
                fc.add("Use", func_name, src_name, src_ver, addr)
                if src_ver == 0:
                    if src_name not in used_v0 or addr < used_v0[src_name]:
                        used_v0[src_name] = addr
            continue

        # ── CALL_SSA: ret, mem = callee(args) @ mem ──
        if op == MLIL.MLIL_CALL_SSA:
            callee = resolve_callee(bv, insn)
            fc.add("Call", func_name, callee, addr)

            # AllocSite — record heap-allocation call sites with their size.
            # Used by bn_width_mismatch.dl / bn_sentinel_init.dl to recover
            # the element width of heap buffers (e.g. uint16_t[]).
            emit_alloc_site(fc, callee, addr, insn.params)

            # Output (return vars + mem)
            for out_var in insn.output:
                out_name = ssa_var_name(out_var)
                out_ver = ssa_var_version(out_var)
                fc.add("Def", func_name, out_name, out_ver, addr)
                if out_ver == 0:
                    defined_v0.add(out_name)
                try:
                    fc.add("VarWidth", func_name, out_name, out_ver,
                           out_var.var.type.width)
                except (AttributeError, TypeError):
                    pass
                emit_var_sign(fc, func_name, out_var, out_name, out_ver)

            # Memory SSA
            mem_out = insn.output_dest_memory
            mem_in = insn.src_memory
            fc.add("Def", func_name, "mem", mem_out, addr)
            fc.add("Use", func_name, "mem", mem_in, addr)

            # Arguments. When BN didn't bind params (empty list), fall back
            # to BN's register-value analysis (for constants) + the
            # reaching reg_state (for SSA-bound args) using the callee's
            # calling convention — recovers both sides of the
            # actual-to-formal mapping for calls that BN left unbound.
            if not insn.params:
                extract_reg_args_fallback(bv, func, insn, addr, fc,
                                          func_name, reg_state,
                                          callee=callee)
            for i, arg in enumerate(insn.params):
                if arg.operation == MLIL.MLIL_VAR_SSA:
                    arg_name = ssa_var_name(arg.src)
                    arg_ver = ssa_var_version(arg.src)
                    fc.add("ActualArg", addr, i, "_", arg_name, arg_ver)
                    fc.add("Use", func_name, arg_name, arg_ver, addr)
                    if arg_ver == 0:
                        if arg_name not in used_v0 or addr < used_v0[arg_name]:
                            used_v0[arg_name] = addr
                elif arg.operation in (MLIL.MLIL_ADDRESS_OF,
                                       MLIL.MLIL_ADDRESS_OF_FIELD):
                    # &var passed as call arg — output parameter pattern.
                    # Emit CallAddrArg so Datalog can bridge taint to the target.
                    target = arg.src
                    target_name = (ssa_var_name(target)
                                   if hasattr(target, 'var') or hasattr(target, 'name')
                                   else str(target))
                    fc.add("CallAddrArg", addr, i, target_name)
                elif arg.operation in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
                    # Literal argument — record its concrete value so rules
                    # can recognize sentinels (memset(buf, -1, n)) and magic
                    # constants (size == 65535).
                    try:
                        fc.add("CallArgConst", addr, i, str(arg.constant))
                    except (AttributeError, TypeError):
                        pass
                else:
                    # Expression argument — collect uses, emit with placeholder
                    collect_uses(fc, func_name, arg, addr)
            continue

        # ── STORE_SSA: [addr_expr] = value @ mem#in -> mem#out ──
        if op == MLIL.MLIL_STORE_SSA:
            dest_expr = insn.dest
            src_expr = insn.src
            mem_in = insn.src_memory
            mem_out = insn.dest_memory

            fc.add("MemWrite", func_name, addr, str(dest_expr), mem_in, mem_out)
            # Record store width in bytes so rules can detect implicit
            # truncation (e.g. storing a 32-bit value into a 16-bit slot).
            # MLIL's store-expression `.size` is the store width in bytes.
            store_size = 0
            for cand in (insn.src, insn.dest):
                sz = getattr(cand, "size", None)
                if isinstance(sz, int) and sz > 0:
                    store_size = sz
                    break
            if store_size > 0:
                fc.add("MemWriteSize", func_name, addr, store_size)
            fc.add("Def", func_name, "mem", mem_out, addr)
            fc.add("Use", func_name, "mem", mem_in, addr)
            collect_uses(fc, func_name, dest_expr, addr)
            collect_uses(fc, func_name, src_expr, addr)
            # MemWriteValue: SSA vars appearing specifically in the stored-
            # value expression (not in the destination-address computation).
            # Lets width-mismatch rules target the value source without
            # false-positives from pointer-width address components.
            collect_value_vars(fc, func_name, src_expr, addr, "MemWriteValue")
            continue

        # ── STORE_STRUCT_SSA: base->field = value ──
        if op == MLIL.MLIL_STORE_STRUCT_SSA:
            base_expr = insn.dest
            offset = insn.offset
            src_expr = insn.src
            mem_in = insn.src_memory
            mem_out = insn.dest_memory

            fc.add("FieldWrite", func_name, addr, str(base_expr),
                    str(offset), mem_in, mem_out)
            fc.add("Def", func_name, "mem", mem_out, addr)
            fc.add("Use", func_name, "mem", mem_in, addr)
            collect_uses(fc, func_name, base_expr, addr)
            collect_uses(fc, func_name, src_expr, addr)
            # FieldWriteValue captures which SSA variable is being stored
            # into the struct field — needed to link an AllocSite return
            # value to the field it's stored into. Mirrors MemWriteValue
            # for plain stores.
            collect_value_vars(fc, func_name, src_expr, addr, "FieldWriteValue")
            continue

        # ── IF: conditional branch ──
        if op == MLIL.MLIL_IF:
            cond = insn.condition
            collect_uses(fc, func_name, cond, addr)

            # CFG edges — true and false targets
            true_bb = insn.true
            false_bb = insn.false
            # `basic_blocks[i].start` is an MLIL instruction *index*; convert
            # to a real address via mlil[idx].address so CFGEdge composes for
            # transitive-closure rules (Reach, Dominates, BnCFGReach).
            if true_bb < len(mlil.basic_blocks):
                fc.add("CFGEdge", func_name, addr,
                       mlil[mlil.basic_blocks[true_bb].start].address)
            if false_bb < len(mlil.basic_blocks):
                fc.add("CFGEdge", func_name, addr,
                       mlil[mlil.basic_blocks[false_bb].start].address)

            # Guard extraction: if condition is a comparison, emit Guard fact
            # Guard schema: func, addr, var, ver, op, bound, bound_type
            #   bound_type: "const" if bound is a literal, "var" if bound is a variable
            if cond.operation in COMPARISON_OPS:
                left = cond.left
                right = cond.right
                op_str = COMPARISON_OP_MAP[cond.operation]
                if left.operation == MLIL.MLIL_VAR_SSA:
                    var_name = ssa_var_name(left.src)
                    var_ver = ssa_var_version(left.src)
                    if right.operation in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
                        bound = str(right.constant)
                        bound_type = "const"
                    elif right.operation == MLIL.MLIL_VAR_SSA:
                        bound = ssa_var_name(right.src)
                        bound_type = "var"
                    else:
                        bound = str(right)
                        bound_type = "expr"
                    fc.add("Guard", func_name, addr, var_name, var_ver, op_str, bound, bound_type)
                elif right.operation == MLIL.MLIL_VAR_SSA and left.operation in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
                    # Reverse case: const OP var → emit as var FLIPPED_OP const
                    var_name = ssa_var_name(right.src)
                    var_ver = ssa_var_version(right.src)
                    bound = str(left.constant)
                    flipped = COMPARISON_FLIP_MAP.get(cond.operation, op_str)
                    fc.add("Guard", func_name, addr, var_name, var_ver, flipped, bound, "const")
            continue

        # ── GOTO ──
        if op == MLIL.MLIL_GOTO:
            target_bb = insn.dest
            if target_bb < len(mlil.basic_blocks):
                fc.add("CFGEdge", func_name, addr,
                       mlil[mlil.basic_blocks[target_bb].start].address)
            continue

        # ── RET: return expr ──
        if op == MLIL.MLIL_RET:
            for src in insn.src:
                if isinstance(src, MediumLevelILInstruction):
                    if src.operation == MLIL.MLIL_VAR_SSA:
                        rv_name = ssa_var_name(src.src)
                        rv_ver = ssa_var_version(src.src)
                        fc.add("ReturnVal", func_name, rv_name, rv_ver)
                        fc.add("Use", func_name, rv_name, rv_ver, addr)
                    else:
                        collect_uses(fc, func_name, src, addr)
            continue

        # ── JUMP: indirect jump ──
        if op == MLIL.MLIL_JUMP or op == MLIL.MLIL_JUMP_TO:
            fc.add("Jump", func_name, addr, str(insn.dest))
            collect_uses(fc, func_name, insn.dest, addr)
            continue

        # ── TAILCALL_SSA ──
        if op == MLIL.MLIL_TAILCALL_SSA:
            callee = resolve_callee(bv, insn)
            fc.add("Call", func_name, callee, addr)
            for i, arg in enumerate(insn.params):
                if arg.operation == MLIL.MLIL_VAR_SSA:
                    arg_name = ssa_var_name(arg.src)
                    arg_ver = ssa_var_version(arg.src)
                    fc.add("ActualArg", addr, i, "_", arg_name, arg_ver)
                    fc.add("Use", func_name, arg_name, arg_ver, addr)
                else:
                    collect_uses(fc, func_name, arg, addr)
            continue

        # Other operations: collect any uses generically
        for operand in insn.operands:
            if isinstance(operand, MediumLevelILInstruction):
                collect_uses(fc, func_name, operand, addr)

    # ── Track version-0 uses from all collected Use facts ──
    for row in fc.facts.get("Use", set()):
        # row = (func, var, ver, addr)
        if row[0] == func_name and row[2] == "0":
            vname = row[1]
            vaddr = int(row[3])
            if vname not in used_v0 or vaddr < used_v0[vname]:
                used_v0[vname] = vaddr

    # ── Stack variable info ──
    for var in func.stack_layout:
        fc.add("StackVar", func_name, var.name, var.storage, var.type.width)

    # ── Formal parameters ──
    for i, param in enumerate(func.parameter_vars):
        fc.add("FormalParam", func_name, param.name, i)
        try:
            fc.add("VarWidth", func_name, param.name, 0, param.type.width)
        except (AttributeError, TypeError):
            pass

    # ── Fallback FormalParam: version-0 used but not defined ──
    # (Catches cases where BN doesn't explicitly list parameters)
    params_already = {row[1] for row in fc.facts.get("FormalParam", set())
                      if row[0] == func_name}
    fallback_params = []
    for vname, min_addr in used_v0.items():
        if vname not in defined_v0 and vname != "mem" and vname not in params_already:
            fallback_params.append((min_addr, vname))
    fallback_params.sort()
    next_idx = len(params_already)
    for _, vname in fallback_params:
        fc.add("FormalParam", func_name, vname, next_idx)
        next_idx += 1


def extract_facts(bv, function_names, output_dir, verbose=False, extract_all=False):
    """Extract facts for specified functions (or all) and write to output_dir."""
    fc = FactCollector()

    if extract_all:
        targets = list(bv.functions)
        if verbose:
            print(f"[*] Extracting facts for ALL {len(targets)} functions", file=sys.stderr)
    else:
        targets = []
        for name in function_names:
            func = find_function(bv, name)
            if func:
                targets.append(func)
            elif verbose:
                print(f"  [WARN] Function not found: {name}", file=sys.stderr)

    for i, func in enumerate(targets):
        if verbose and (i % 50 == 0 or i == len(targets) - 1):
            print(f"  [{i+1}/{len(targets)}] {func.name}", file=sys.stderr)
        extract_function_facts(bv, func, fc, verbose=verbose)

    out = Path(output_dir)
    stats = fc.write_all(out)

    return {
        "functions_processed": len(targets),
        "relations": stats,
        "total_facts": sum(stats.values()),
        "facts_dir": str(out),
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="BinCodeQL: Extract Datalog facts from a binary via Binary Ninja headless API"
    )
    parser.add_argument("binary", help="Path to binary or .bndb database (auto-detects .bndb sibling)")
    parser.add_argument("-f", "--functions",
                        help="Comma-separated function names to extract")
    parser.add_argument("--all", action="store_true",
                        help="Extract facts for ALL functions")
    parser.add_argument("-o", "--output", default="facts",
                        help="Output directory for .facts files (default: facts)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print progress to stderr")
    parser.add_argument("--json", action="store_true",
                        help="Print JSON summary to stdout")
    args = parser.parse_args()

    if not args.functions and not args.all:
        parser.error("Specify -f FUNC1,FUNC2 or --all")

    binary_path = args.binary
    if not Path(binary_path).exists():
        print(f"[!] Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    load_path, is_bndb = resolve_binary_path(binary_path, args.verbose)

    if args.verbose:
        print(f"[*] Loading {'database' if is_bndb else 'binary'}: {load_path}", file=sys.stderr)

    bv = binaryninja.load(load_path, update_analysis=not is_bndb)
    if bv is None:
        # Fallback: if .bndb failed, try raw binary
        if is_bndb and load_path != binary_path:
            if args.verbose:
                print(f"[*] .bndb load failed, falling back to raw binary", file=sys.stderr)
            bv = binaryninja.load(binary_path)
        if bv is None:
            print(f"[!] Failed to load: {binary_path}", file=sys.stderr)
            sys.exit(1)

    if args.verbose:
        mode = "database" if is_bndb else "binary"
        print(f"[*] Loaded {mode}: {len(bv.functions)} functions", file=sys.stderr)

    function_names = []
    if args.functions:
        function_names = [n.strip() for n in args.functions.split(",")]

    result = extract_facts(
        bv, function_names, args.output,
        verbose=args.verbose, extract_all=args.all,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Extracted {result['total_facts']} facts from "
              f"{result['functions_processed']} functions", file=sys.stderr)
        for name, count in sorted(result['relations'].items()):
            print(f"  {name:25s} {count} rows", file=sys.stderr)


if __name__ == "__main__":
    main()
