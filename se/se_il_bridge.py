"""Bridge between Datalog facts and angr's register/memory model.

Maps Datalog variable references (function name + arg index, or stack var
name + offset from BN MCP) to angr's register names and stack offsets.

This module does NOT import binaryninja — it works purely with:
  - angr's archinfo (calling conventions, register names)
  - Address/offset information provided by the BN MCP bridge as metadata

The BN MCP provides:
  - ``get_stack_frame_vars(func)`` → stack var names, offsets, sizes
  - ``decompile_function(func)``   → shows parameter/arg mapping
  - Calling convention info

This bridge translates that metadata into angr-compatible locations.
"""


# ---------------------------------------------------------------------------
# x86-64 SysV ABI (default for Linux ELFs)
# ---------------------------------------------------------------------------

SYSV_AMD64_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
SYSV_AMD64_RET_REG = "rax"
SYSV_AMD64_PTR_SIZE = 8


def arg_index_to_register(arg_idx: int, arch: str = "amd64") -> dict:
    """Map a 0-based argument index to its register or stack location.

    Uses the platform calling convention (SysV AMD64 by default).

    Returns::
        {"type": "register", "reg": "rdi", "arg_idx": 0}
        {"type": "stack", "offset": 8, "size": 8, "arg_idx": 6}
    """
    if arch == "amd64":
        regs = SYSV_AMD64_ARG_REGS
        ptr_size = SYSV_AMD64_PTR_SIZE
    else:
        return {"type": "unknown", "detail": f"Unsupported arch: {arch}"}

    if arg_idx < len(regs):
        return {
            "type": "register",
            "reg": regs[arg_idx],
            "arg_idx": arg_idx,
        }

    # Stack arguments (after return address)
    stack_offset = (arg_idx - len(regs)) * ptr_size
    return {
        "type": "stack",
        "offset": stack_offset,
        "size": ptr_size,
        "arg_idx": arg_idx,
    }


def arg_index_to_register_angr(proj, arg_idx: int) -> dict:
    """Map argument index using angr's own calling convention detection.

    Args:
        proj: angr.Project instance
        arg_idx: 0-based argument index

    Returns same format as ``arg_index_to_register``.
    """
    cc = proj.factory.cc()
    if arg_idx < len(cc.ARG_REGS):
        return {
            "type": "register",
            "reg": cc.ARG_REGS[arg_idx],
            "arg_idx": arg_idx,
        }

    stack_offset = (arg_idx - len(cc.ARG_REGS)) * proj.arch.bytes
    return {
        "type": "stack",
        "offset": stack_offset,
        "size": proj.arch.bytes,
        "arg_idx": arg_idx,
    }


def stack_var_to_angr_offset(rbp_offset: int, var_size: int) -> dict:
    """Convert a BN stack variable offset to angr memory reference info.

    BN reports stack offsets relative to the frame base (e.g., -0x40 for a
    local buffer).  angr can access these via ``state.memory.load(rbp + offset, size)``.

    Args:
        rbp_offset: Signed offset from RBP (e.g., -64 for ``rbp-0x40``)
        var_size: Size of the variable in bytes

    Returns::
        {"type": "stack", "rbp_offset": -64, "size": 8,
         "angr_expr": "state.memory.load(state.regs.rbp - 0x40, 8)"}
    """
    abs_offset = abs(rbp_offset)
    sign = "-" if rbp_offset < 0 else "+"
    return {
        "type": "stack",
        "rbp_offset": rbp_offset,
        "size": var_size,
        "angr_expr": (
            f"state.memory.load(state.regs.rbp {sign} {hex(abs_offset)}, "
            f"{var_size})"
        ),
    }


def map_datalog_var(var_info: dict) -> dict:
    """Map a Datalog variable reference to an angr-compatible location.

    Takes metadata from BN MCP (gathered separately) and returns angr
    location info. This is the main entry point for the agent.

    Args:
        var_info: Dict with keys from BN MCP:
            - "type": "argument" | "stack" | "register"
            - "index": arg index (for arguments)
            - "reg": register name (for registers)
            - "offset": stack offset (for stack vars)
            - "size": variable size in bytes

    Returns::
        {"type": "register", "reg": "rdi", "arg_idx": 0}
        {"type": "stack", "rbp_offset": -64, "size": 8, "angr_expr": "..."}
    """
    vtype = var_info.get("type", "unknown")

    if vtype == "argument":
        return arg_index_to_register(var_info.get("index", 0))

    if vtype == "register":
        return {
            "type": "register",
            "reg": var_info.get("reg", "unknown"),
        }

    if vtype == "stack":
        offset = var_info.get("offset", 0)
        size = var_info.get("size", 8)
        return stack_var_to_angr_offset(offset, size)

    return {"type": "unknown", "detail": f"Cannot map variable type: {vtype}"}
