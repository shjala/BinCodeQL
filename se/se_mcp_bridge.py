#!/usr/bin/env python3
"""angr Symbolic Execution MCP Bridge for BinCodeQL.

Runs as a standalone MCP server (stdio transport).  Exposes SE tools that
the BinCodeQL agent can call alongside its existing BN MCP and Datalog tools.

Uses angr for symbolic execution — no Binary Ninja dependency.  The binary
path is resolved automatically in this order:

  1. CLI argument:   ``python se_mcp_bridge.py /path/to/binary``
  2. Env var:        ``BINARY_PATH=/path/to/binary python se_mcp_bridge.py``
  3. Auto-discover from the running Binary Ninja HTTP server (localhost:9009)
     — queries ``GET /status`` and extracts the ``filename`` field.

Option 3 is the default when launched alongside the BN MCP bridge: the agent
never needs to pass the path explicitly.

This is a **separate process** from the main BN MCP bridge, designed to be
launched as a second MCPToolset in agent.py.
"""

import sys
import os
import json
import dataclasses
import traceback
from urllib.request import urlopen
from urllib.error import URLError

# ---------------------------------------------------------------------------
# Early error capture — keep stderr clean for MCP protocol
# ---------------------------------------------------------------------------

def _excepthook(exc_type, exc, tb):
    traceback.print_exception(exc_type, exc, tb, file=sys.stderr)

sys.excepthook = _excepthook

# Add our own directory to the path (se/ is not a Python package)
_se_dir = os.path.dirname(os.path.abspath(__file__))
if _se_dir not in sys.path:
    sys.path.insert(0, _se_dir)

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("angr-se-bridge")

# Binary Ninja HTTP server — used to auto-discover the loaded binary
BN_HTTP_URL = os.environ.get("BN_HTTP_URL", "http://localhost:9009")

# Lazy globals — initialized on first tool call
_binary_path = None
_backend = None


def _query_bn_binary_path() -> str | None:
    """Ask the running BN HTTP server for the active binary's path.

    Returns the absolute path string, or None if BN is unreachable.
    """
    try:
        with urlopen(f"{BN_HTTP_URL}/status", timeout=3) as resp:
            data = json.loads(resp.read())
            fn = data.get("filename") or data.get("path")
            if fn and os.path.exists(fn):
                return os.path.abspath(fn)
    except (URLError, OSError, json.JSONDecodeError, KeyError):
        pass
    return None


def _get_binary_path() -> str:
    """Resolve the binary path.  Priority:

    1. CLI argument  (``python se_mcp_bridge.py /path/to/binary``)
    2. ``BINARY_PATH`` environment variable
    3. Auto-discover from the running Binary Ninja HTTP server
    """
    global _binary_path
    if _binary_path is not None:
        return _binary_path

    # 1. Explicit CLI arg
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        _binary_path = os.path.abspath(sys.argv[1])
    # 2. Environment variable
    elif os.environ.get("BINARY_PATH") and os.path.exists(os.environ["BINARY_PATH"]):
        _binary_path = os.path.abspath(os.environ["BINARY_PATH"])
    else:
        # 3. Ask BN
        _binary_path = _query_bn_binary_path()

    if not _binary_path:
        raise RuntimeError(
            "No binary path available.  Provide via CLI arg, BINARY_PATH env var, "
            "or ensure Binary Ninja is running with an open binary."
        )

    print(f"Binary: {_binary_path}", file=sys.stderr)
    return _binary_path


def _get_backend():
    """Get or initialize the AngrBackend with heap-tracking stubs."""
    global _backend
    if _backend is not None:
        return _backend

    from se_backend import AngrBackend
    from se_stubs import HeapTracker, hook_project

    tracker = HeapTracker()
    _backend = AngrBackend(auto_load_libs=False, heap_tracker=tracker)

    # Pre-load project and install hooks
    binary = _get_binary_path()
    proj = _backend._get_project(binary)
    hook_project(proj, tracker)

    print(f"angr project loaded: {proj.filename}", file=sys.stderr)
    return _backend


def _serialize(result):
    """Convert a dataclass result to a JSON-serializable dict."""
    d = dataclasses.asdict(result)
    if d.get("concrete_input") is not None:
        d["concrete_input_hex"] = d["concrete_input"].hex()
        del d["concrete_input"]
    return d


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def se_explore(
    function_name: str,
    target_addr: str,
    avoid_addrs: str = "",
    max_steps: int = 50000,
    timeout_secs: int = 120,
    symbolic_args: str = "",
) -> dict:
    """Symbolically explore from function entry to target address.

    Checks if target_addr is reachable from the start of function_name.
    Returns SAT (with concrete input), UNSAT, TIMEOUT, or ERROR.

    Args:
        function_name: Name of the function to start from.
        target_addr: Hex address to reach (e.g., "0x401234").
        avoid_addrs: Comma-separated hex addresses to avoid.
        max_steps: Maximum simulation steps before giving up.
        timeout_secs: Wall-clock timeout in seconds.
        symbolic_args: Comma-separated "idx:size" pairs to make arguments symbolic
                       (e.g., "0:8,1:4" = arg0 is 8 bytes, arg1 is 4 bytes).
    """
    try:
        binary = _get_binary_path()
        backend = _get_backend()

        avoid = []
        if avoid_addrs.strip():
            avoid = [int(a.strip(), 16) for a in avoid_addrs.split(",")]

        sym_args = {}
        if symbolic_args.strip():
            for pair in symbolic_args.split(","):
                idx, sz = pair.split(":")
                sym_args[int(idx)] = int(sz)

        result = backend.explore(
            binary_path=binary,
            function_name=function_name,
            target_addr=int(target_addr, 16),
            avoid_addrs=avoid,
            max_steps=max_steps,
            timeout_secs=timeout_secs,
            symbolic_args=sym_args if sym_args else None,
        )
        return _serialize(result)
    except Exception as e:
        return {"status": "ERROR", "error_message": str(e)}


@mcp.tool()
def se_check_overflow(
    function_name: str,
    sink_addr: str,
    buffer_size: int,
    size_arg_index: int = -1,
    max_steps: int = 50000,
    timeout_secs: int = 120,
) -> dict:
    """Check if a buffer overflow at the given sink address is feasible.

    Explores from function entry to sink_addr. If reachable, adds the
    constraint that the write size exceeds buffer_size and checks SAT.

    Args:
        function_name: Name of the function containing the sink.
        sink_addr: Hex address of the dangerous call (e.g., "0x401234").
        buffer_size: Known size of the destination buffer in bytes.
        size_arg_index: 0-based index of the argument carrying the size
                        (-1 if unknown; will just check reachability).
    """
    try:
        binary = _get_binary_path()
        backend = _get_backend()
        result = backend.check_overflow_feasibility(
            binary_path=binary,
            function_name=function_name,
            sink_addr=int(sink_addr, 16),
            buffer_size=buffer_size,
            size_arg_index=size_arg_index,
            max_steps=max_steps,
            timeout_secs=timeout_secs,
        )
        return _serialize(result)
    except Exception as e:
        return {"status": "ERROR", "error_message": str(e)}


@mcp.tool()
def se_check_uaf(
    function_name: str,
    alloc_addr: str,
    free_addr: str,
    use_addr: str,
    max_steps: int = 50000,
    timeout_secs: int = 120,
) -> dict:
    """Check if a use-after-free sequence (alloc -> free -> use) is feasible.

    Explores sequentially: function entry -> alloc_addr -> free_addr -> use_addr.
    Each phase gets a third of the step/time budget.

    Args:
        function_name: Name of the function to analyze.
        alloc_addr: Hex address of the allocation (malloc/calloc call).
        free_addr: Hex address of the free call.
        use_addr: Hex address of the use-after-free site.
    """
    try:
        binary = _get_binary_path()
        backend = _get_backend()
        result = backend.check_uaf_feasibility(
            binary_path=binary,
            function_name=function_name,
            alloc_addr=int(alloc_addr, 16),
            free_addr=int(free_addr, 16),
            use_addr=int(use_addr, 16),
            max_steps=max_steps,
            timeout_secs=timeout_secs,
        )
        return _serialize(result)
    except Exception as e:
        return {"status": "ERROR", "error_message": str(e)}


@mcp.tool()
def se_get_constraints(
    function_name: str,
    target_addr: str,
    max_steps: int = 50000,
    timeout_secs: int = 120,
) -> dict:
    """Get the path constraints needed to reach target_addr from function entry.

    Returns human-readable constraint summaries and SMT-LIB2 format.

    Args:
        function_name: Name of the function.
        target_addr: Hex address to reach.
    """
    try:
        binary = _get_binary_path()
        backend = _get_backend()
        result = backend.get_path_constraints(
            binary_path=binary,
            function_name=function_name,
            target_addr=int(target_addr, 16),
            max_steps=max_steps,
            timeout_secs=timeout_secs,
        )
        return _serialize(result)
    except Exception as e:
        return {"status": "ERROR", "error_message": str(e)}


@mcp.tool()
def se_solve_input(
    function_name: str,
    target_addr: str,
    extra_constraints: str = "",
    max_steps: int = 50000,
    timeout_secs: int = 120,
) -> dict:
    """Generate a concrete input that reaches target_addr with extra constraints.

    Useful for crafting PoC inputs or fuzzer seeds.

    Args:
        function_name: Name of the function.
        target_addr: Hex address to reach.
        extra_constraints: Semicolon-separated constraint strings, e.g.,
                           "rdi > 0x100; rsi != 0".
    """
    try:
        binary = _get_binary_path()
        backend = _get_backend()
        constraints = []
        if extra_constraints.strip():
            constraints = [c.strip() for c in extra_constraints.split(";") if c.strip()]
        result = backend.solve_for_input(
            binary_path=binary,
            function_name=function_name,
            target_addr=int(target_addr, 16),
            extra_constraints=constraints if constraints else None,
            max_steps=max_steps,
            timeout_secs=timeout_secs,
        )
        return _serialize(result)
    except Exception as e:
        return {"status": "ERROR", "error_message": str(e)}


@mcp.tool()
def se_map_var(
    var_type: str,
    arg_index: int = -1,
    stack_offset: int = 0,
    var_size: int = 8,
    reg_name: str = "",
) -> dict:
    """Map a Datalog variable reference to its angr register/stack location.

    Translates BN MCP metadata about variables into angr-compatible locations.
    The agent calls BN MCP's get_stack_frame_vars first, then passes the
    metadata here.

    Args:
        var_type: One of "argument", "stack", "register".
        arg_index: For arguments, the 0-based parameter index.
        stack_offset: For stack variables, the RBP-relative offset.
        var_size: Size of the variable in bytes.
        reg_name: For register variables, the register name.
    """
    try:
        from se_il_bridge import map_datalog_var
        var_info = {"type": var_type, "size": var_size}
        if var_type == "argument":
            var_info["index"] = arg_index
        elif var_type == "stack":
            var_info["offset"] = stack_offset
        elif var_type == "register":
            var_info["reg"] = reg_name
        return map_datalog_var(var_info)
    except Exception as e:
        return {"type": "unknown", "detail": str(e)}


@mcp.tool()
def se_get_heap_state() -> dict:
    """Get the current heap tracker state: allocations, frees, and violations.

    Returns a summary of all tracked heap operations and any detected
    violations (double-free, use-after-free, heap overflow).
    """
    try:
        from se_stubs import get_heap_tracker
        tracker = get_heap_tracker()
        return {
            "total_allocations": len(tracker.allocations),
            "freed_count": sum(1 for a in tracker.allocations.values() if a.freed),
            "live_count": sum(1 for a in tracker.allocations.values() if not a.freed),
            "violations": tracker.violations,
            "allocations": [
                {
                    "ptr": hex(a.ptr),
                    "size": a.size,
                    "alloc_addr": hex(a.alloc_addr),
                    "freed": a.freed,
                    "free_addr": hex(a.free_addr) if a.free_addr else None,
                }
                for a in tracker.allocations.values()
            ],
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def se_unload() -> dict:
    """Unload the angr project to free memory.

    Call this between analysis sessions or when switching binaries.
    The project will be re-loaded lazily on the next tool call.
    """
    global _backend, _binary_path
    try:
        if _backend:
            _backend.unload()
            _backend = None
        _binary_path = None
        return {"status": "ok", "message": "angr project unloaded"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Starting angr SE MCP bridge...", file=sys.stderr)
    try:
        mcp.run()
    except Exception as e:
        _excepthook(type(e), e, e.__traceback__)
        raise
