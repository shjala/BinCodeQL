# SENinja Integration Plan v1

## Motivation

The BinCodeQL Datalog pipeline (alias.dl → interproc.dl) is a sound over-approximation:
it finds all *possible* taint paths but cannot determine which are *feasible*.
Symbolic execution (SE) is the natural complement — it under-approximates by exploring
concrete/symbolic paths, proving reachability or infeasibility of specific Datalog alerts.

**Core use case**: Datalog produces `TaintedSink` / `GuardedSink` alerts → SE validates
each alert by checking if a concrete input can reach the sink under the vulnerability
condition (overflow, UAF, etc.). This directly addresses the false-positive problem
identified in improvements_todo4.md (criticisms #3, #5).

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                     BinCodeQL Agent                      │
│                      (agent.py)                          │
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐ │
│  │ BN MCP      │  │ Datalog     │  │ SE MCP           │ │
│  │ Toolset     │  │ Tools       │  │ Toolset          │ │
│  │ (existing)  │  │ (existing)  │  │ (NEW)            │ │
│  └──────┬──────┘  └──────┬──────┘  └────────┬─────────┘ │
└─────────┼────────────────┼──────────────────┼────────────┘
          │                │                  │
          ▼                ▼                  ▼
  ┌──────────────┐  ┌───────────┐  ┌───────────────────┐
  │ binja_mcp_   │  │ Souffle   │  │ se_mcp_bridge.py  │
  │ bridge.py    │  │ engine    │  │ (NEW - separate   │
  │ (UNCHANGED)  │  │           │  │  MCP server)      │
  └──────┬───────┘  └───────────┘  └────────┬──────────┘
         │                                   │
         ▼                                   ▼
  ┌──────────────┐              ┌───────────────────────┐
  │ Binary Ninja │              │ se_backend.py (NEW)   │
  │ (GUI/headless│              │ ┌───────────────────┐ │
  │  with MCP)   │              │ │ SEBackend (ABC)   │ │
  │              │              │ ├───────────────────┤ │
  │              │◄─────────────│ │ SeninjaBackend    │ │
  │              │  BN Python   │ │ (default)         │ │
  │              │  API calls   │ ├───────────────────┤ │
  │              │              │ │ AngrBackend       │ │
  │              │              │ │ (future, optional)│ │
  │              │              │ └───────────────────┘ │
  │              │              └───────────────────────┘
  └──────────────┘
```

### Key design decisions

1. **Separate MCP bridge** (`se_mcp_bridge.py`) — does NOT modify the existing
   `binja_mcp_bridge.py`. Runs as its own stdio MCP server process.
2. **Swappable backend** — `se_backend.py` defines an `SEBackend` ABC. SENinja is
   the default implementation. angr or others can be swapped in later by implementing
   the same interface.
3. **SE bridge connects to BN** — The SE MCP bridge imports `binaryninja` and SENinja
   in the same process, getting direct access to `BinaryView`, types, and IL mappings.
   It does NOT go through the existing MCP bridge.
4. **Agent sees SE as just another toolset** — Added to `agent.py` as a second
   `MCPToolset` alongside the existing BN MCP toolset.

---

## Datalog → SE Workflow

The agent follows this pipeline when validating a Datalog alert:

```
Step 1: Datalog pipeline produces TaintedSink alerts
        ┌──────────────────────────────────────────────┐
        │ TaintedSink("parse_header", "strcpy",        │
        │             0x401234, 1, "buf#3",             │
        │             "buffer_overflow",                │
        │             "external_via_read")              │
        └───────────────────┬──────────────────────────┘
                            │
Step 2: Agent extracts validation parameters
        - function:    parse_header
        - sink_addr:   0x401234
        - buf_size:    64 (from StackVar.facts)
        - entry_addr:  function start (from BN MCP)
                            │
Step 3: Agent calls SE tool
        ┌──────────────────────────────────────────────┐
        │ se_check_overflow_feasibility(               │
        │   function_name="parse_header",              │
        │   sink_addr="0x401234",                      │
        │   buffer_size=64                             │
        │ )                                            │
        └───────────────────┬──────────────────────────┘
                            │
Step 4: SE returns verdict
        ┌──────────────────────────────────────────────┐
        │ { "status": "SAT",                           │
        │   "concrete_input_hex": "41414141...",       │
        │   "overflow_by": 8,                          │
        │   "path_constraints_summary": "len > 64",   │
        │   "steps_taken": 1247 }                      │
        └──────────────────────────────────────────────┘

Step 5: Agent combines Datalog + SE into final report
        - Confirmed: buffer overflow in parse_header @ 0x401234
        - PoC input available
        - OR: Infeasible (guarded by bounds check) → FP eliminated
```

---

## File Layout (new files only)

```
bin_datalog/
└── se/                         # NEW subdirectory for all SE code
    ├── __init__.py             # Package init
    ├── se_mcp_bridge.py        # MCP server exposing SE tools
    ├── se_backend.py           # SEBackend ABC + SeninjaBackend
    ├── se_stubs.py             # Libc function stubs for SENinja
    ├── se_il_bridge.py         # MLIL-SSA var → LLIL register/stack mapping
    └── tests/
        └── test_se_tools.py    # Unit tests for SE tool layer
```

No existing files are modified during the SE integration. The SE toolset is added
to the agent's tool list at integration time (Phase 4 below).

---

## Phase 1: SE Backend Abstraction (`se_backend.py`)

### SEBackend ABC

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

@dataclass
class ExploreResult:
    """Result of a symbolic exploration."""
    status: str                          # "SAT", "UNSAT", "TIMEOUT", "ERROR"
    steps_taken: int = 0
    concrete_input: Optional[bytes] = None
    constraints_summary: list[str] = None  # Human-readable constraint strings
    registers_at_target: dict = None       # {reg_name: value_or_symbolic}
    error_message: Optional[str] = None

@dataclass
class FeasibilityResult:
    """Result of a vulnerability feasibility check."""
    status: str                          # "FEASIBLE", "INFEASIBLE", "TIMEOUT", "ERROR"
    feasible: bool = False
    concrete_input: Optional[bytes] = None
    violation_detail: str = ""           # e.g., "write of 72 bytes into 64-byte buffer"
    blocking_guard: Optional[str] = None # e.g., "if (len < 64) at 0x401220"
    steps_taken: int = 0
    error_message: Optional[str] = None

@dataclass
class ConstraintsResult:
    """Path constraints to reach a target address."""
    reachable: bool = False
    constraints: list[str] = None        # Human-readable
    smt2_constraints: Optional[str] = None  # SMT-LIB2 format for external solvers
    steps_taken: int = 0


class SEBackend(ABC):
    """Abstract symbolic execution backend. Implementations wrap specific
    SE engines (SENinja, angr, etc.) behind a uniform interface."""

    @abstractmethod
    def explore(
        self,
        bv,                              # binaryninja.BinaryView
        function_name: str,
        target_addr: int,
        avoid_addrs: list[int] = None,
        max_steps: int = 50_000,
        timeout_secs: int = 120,
        symbolic_args: dict = None,      # {arg_idx: size_in_bytes}
    ) -> ExploreResult:
        """Explore from function entry to target_addr."""
        ...

    @abstractmethod
    def check_overflow_feasibility(
        self,
        bv,
        function_name: str,
        sink_addr: int,
        buffer_size: int,
        size_arg_index: int = -1,
        max_steps: int = 50_000,
        timeout_secs: int = 120,
    ) -> FeasibilityResult:
        """Check if a buffer overflow at sink_addr is feasible."""
        ...

    @abstractmethod
    def check_uaf_feasibility(
        self,
        bv,
        function_name: str,
        alloc_addr: int,
        free_addr: int,
        use_addr: int,
        max_steps: int = 50_000,
        timeout_secs: int = 120,
    ) -> FeasibilityResult:
        """Check if a use-after-free sequence is feasible."""
        ...

    @abstractmethod
    def get_path_constraints(
        self,
        bv,
        function_name: str,
        target_addr: int,
        max_steps: int = 50_000,
        timeout_secs: int = 120,
    ) -> ConstraintsResult:
        """Return path constraints for reaching target_addr."""
        ...

    @abstractmethod
    def solve_for_input(
        self,
        bv,
        function_name: str,
        target_addr: int,
        extra_constraints: list[str] = None,
        max_steps: int = 50_000,
        timeout_secs: int = 120,
    ) -> ExploreResult:
        """Find concrete input satisfying path + extra constraints."""
        ...
```

### SeninjaBackend implementation outline

```python
class SeninjaBackend(SEBackend):
    """SENinja-based symbolic execution backend.

    Operates on BN's LLIL via SENinja's SEState. Uses BN's IL mapping
    APIs to bridge between MLIL-SSA (Datalog facts) and LLIL (SENinja).
    """

    def __init__(self, stub_registry=None):
        self.stubs = stub_registry or default_stubs()

    def explore(self, bv, function_name, target_addr, avoid_addrs=None,
                max_steps=50_000, timeout_secs=120, symbolic_args=None):
        from seninja import SEState
        import time

        func = self._resolve_function(bv, function_name)
        state = SEState(bv, func.start)

        # Make function arguments symbolic
        if symbolic_args:
            self._symbolize_args(state, func, symbolic_args)

        avoid_set = set(avoid_addrs or [])
        start_time = time.time()
        steps = 0

        # BFS exploration with step + time budget
        worklist = [state]
        found_state = None

        while worklist and steps < max_steps:
            if time.time() - start_time > timeout_secs:
                return ExploreResult(status="TIMEOUT", steps_taken=steps)

            current = worklist.pop(0)
            ip = current.get_ip()

            if ip == target_addr:
                found_state = current
                break

            if ip in avoid_set:
                continue

            # Apply stubs if current instruction is a call to a modeled function
            # ... (stub application logic)

            # Step and fork
            successors = current.execute()  # SENinja step
            worklist.extend(successors)
            steps += 1

        if found_state:
            concrete = self._concretize_input(found_state)
            constraints = self._summarize_constraints(found_state)
            return ExploreResult(
                status="SAT", steps_taken=steps,
                concrete_input=concrete,
                constraints_summary=constraints,
            )

        return ExploreResult(status="UNSAT", steps_taken=steps)

    def _resolve_function(self, bv, name):
        """Resolve function name → binaryninja.Function object."""
        funcs = bv.get_functions_by_name(name)
        if not funcs:
            raise ValueError(f"Function '{name}' not found in BinaryView")
        return funcs[0]

    def _symbolize_args(self, state, func, symbolic_args):
        """Mark function arguments as symbolic bitvectors.
        Uses BN's calling convention to determine registers/stack slots."""
        cc = func.calling_convention
        for arg_idx, size_bytes in symbolic_args.items():
            if arg_idx < len(cc.int_arg_regs):
                reg = cc.int_arg_regs[arg_idx]
                state.set_symbolic(reg, size_bytes * 8)  # bits
            # else: stack argument handling

    def _concretize_input(self, state):
        """Extract one concrete satisfying input from the solved state."""
        # Ask Z3 for a model of the symbolic variables
        # Return as bytes
        ...

    def _summarize_constraints(self, state):
        """Produce human-readable constraint summaries from Z3 constraints."""
        # Convert Z3 AST to readable strings
        ...
```

---

## Phase 2: MLIL↔LLIL Bridge (`se_il_bridge.py`)

The Datalog facts reference MLIL-SSA variables (e.g., `buf#3`, `len#1`). SENinja
operates on LLIL (registers and stack offsets). This module bridges the gap.

### Key mappings needed

| Datalog/MLIL concept | LLIL/SENinja concept | BN API to bridge |
|---|---|---|
| `buf#3` (MLIL-SSA var) | `rbp-0x40` (stack slot) or `rdi` (register) | `func.mlil.ssa_form[idx].llils` → LLIL instr → operand |
| `StackVar(func, var, offset, size)` | Stack offset directly usable | Already extracted; pass offset to SENinja |
| `Call(caller, callee, 0x401234)` | LLIL call instruction at same address | Address-based lookup (trivial) |
| `FormalParam(func, arg0, 0)` | First int arg register (`rdi` on x86-64) | `func.calling_convention.int_arg_regs[0]` |
| `TaintedSink(... arg_idx=1 ...)` | Second arg register (`rsi` on x86-64) | `func.calling_convention.int_arg_regs[1]` |

### Implementation outline

```python
def mlil_var_to_location(bv, function_name: str, var_name: str, var_version: int):
    """Map an MLIL-SSA variable to its LLIL storage location.

    Returns one of:
      {"type": "register", "reg": "rdi"}
      {"type": "stack", "offset": -0x40, "size": 64}
      {"type": "unknown", "detail": "..."}
    """
    func = bv.get_functions_by_name(function_name)[0]
    mlil_ssa = func.mlil.ssa_form

    # Search MLIL-SSA for the variable definition
    for instr in mlil_ssa:
        # Match var name and SSA version
        # Get corresponding LLIL instruction via instr.llils
        # Extract register or stack reference from LLIL operand
        ...

def sink_arg_to_register(bv, function_name: str, call_addr: int, arg_idx: int):
    """Map a sink's argument index to the concrete register/location at call time.

    Uses the callee's calling convention (or the caller's if callee is external).
    """
    func = bv.get_functions_by_name(function_name)[0]
    cc = func.calling_convention
    if arg_idx < len(cc.int_arg_regs):
        return {"type": "register", "reg": cc.int_arg_regs[arg_idx].name}
    else:
        # Stack argument: compute offset from calling convention
        stack_offset = (arg_idx - len(cc.int_arg_regs)) * bv.address_size
        return {"type": "stack", "offset": stack_offset}
```

---

## Phase 3: MCP Bridge (`se_mcp_bridge.py`)

Separate MCP server process. Imports `binaryninja` + SENinja directly. Communicates
with the ADK agent via stdio (same pattern as existing `binja_mcp_bridge.py`).

### Tool surface

| MCP Tool | Purpose | Input | Output |
|---|---|---|---|
| `se_explore` | Reachability check: can execution reach target_addr? | `function_name`, `target_addr`, `avoid_addrs`, `max_steps`, `timeout_secs`, `symbolic_args` | `ExploreResult` as JSON |
| `se_check_overflow` | Validate buffer overflow feasibility | `function_name`, `sink_addr`, `buffer_size`, `size_arg_index` | `FeasibilityResult` as JSON |
| `se_check_uaf` | Validate use-after-free feasibility | `function_name`, `alloc_addr`, `free_addr`, `use_addr` | `FeasibilityResult` as JSON |
| `se_get_constraints` | Get path constraints to reach an address | `function_name`, `target_addr` | `ConstraintsResult` as JSON |
| `se_solve_input` | Generate concrete input reaching target with extra constraints | `function_name`, `target_addr`, `extra_constraints` | `ExploreResult` as JSON |
| `se_get_state_info` | Inspect symbolic state at an address (registers, memory) | `function_name`, `addr` | Register/memory snapshot |
| `se_map_mlil_var` | Map an MLIL-SSA var to its LLIL location (debugging/introspection) | `function_name`, `var_name`, `var_version` | Location dict |

### Server skeleton

```python
#!/usr/bin/env python3
"""SENinja Symbolic Execution MCP Bridge for BinCodeQL.

Runs as a standalone MCP server (stdio transport). Connects to Binary Ninja
and exposes SE tools via the MCP protocol.

Usage:
    python se_mcp_bridge.py            # Connects to running BN instance
    python se_mcp_bridge.py <bndb>     # Opens a BNDB in headless mode
"""

import sys
import json
from mcp.server import Server
from mcp.server.stdio import stdio_server

import binaryninja
from se.se_backend import SeninjaBackend
from se.se_il_bridge import mlil_var_to_location, sink_arg_to_register

server = Server("seninja-se-bridge")
backend = SeninjaBackend()


def get_bv():
    """Get the current BinaryView.
    If running headless, opens from sys.argv[1].
    If connected to GUI, uses binaryninja.get_current_binaryview() or similar.
    """
    # Implementation depends on headless vs GUI mode
    ...


@server.tool("se_explore")
async def se_explore(
    function_name: str,
    target_addr: str,
    avoid_addrs: list[str] = None,
    max_steps: int = 50000,
    timeout_secs: int = 120,
    symbolic_args: dict = None,
) -> dict:
    """Symbolically explore from function entry to target address.

    Returns reachability status, concrete input (if SAT), and path
    constraint summary.
    """
    bv = get_bv()
    result = backend.explore(
        bv=bv,
        function_name=function_name,
        target_addr=int(target_addr, 16),
        avoid_addrs=[int(a, 16) for a in (avoid_addrs or [])],
        max_steps=max_steps,
        timeout_secs=timeout_secs,
        symbolic_args={int(k): v for k, v in (symbolic_args or {}).items()},
    )
    return _serialize(result)


@server.tool("se_check_overflow")
async def se_check_overflow(
    function_name: str,
    sink_addr: str,
    buffer_size: int,
    size_arg_index: int = -1,
    max_steps: int = 50000,
    timeout_secs: int = 120,
) -> dict:
    """Check if a buffer overflow at the given sink address is feasible.

    Adds the constraint: written_size > buffer_size, then checks SAT.
    If SAT, returns a concrete input that triggers the overflow.
    If UNSAT, describes the blocking constraint (e.g., a bounds check).
    """
    bv = get_bv()
    result = backend.check_overflow_feasibility(
        bv=bv,
        function_name=function_name,
        sink_addr=int(sink_addr, 16),
        buffer_size=buffer_size,
        size_arg_index=size_arg_index,
        max_steps=max_steps,
        timeout_secs=timeout_secs,
    )
    return _serialize(result)


@server.tool("se_check_uaf")
async def se_check_uaf(
    function_name: str,
    alloc_addr: str,
    free_addr: str,
    use_addr: str,
    max_steps: int = 50000,
    timeout_secs: int = 120,
) -> dict:
    """Check if a use-after-free sequence (alloc → free → use) is feasible.

    Explores for a path that hits alloc, then free, then use on the same
    memory object.
    """
    bv = get_bv()
    result = backend.check_uaf_feasibility(
        bv=bv,
        function_name=function_name,
        alloc_addr=int(alloc_addr, 16),
        free_addr=int(free_addr, 16),
        use_addr=int(use_addr, 16),
        max_steps=max_steps,
        timeout_secs=timeout_secs,
    )
    return _serialize(result)


@server.tool("se_get_constraints")
async def se_get_constraints(
    function_name: str,
    target_addr: str,
    max_steps: int = 50000,
    timeout_secs: int = 120,
) -> dict:
    """Get the path constraints needed to reach target_addr from function entry.

    Useful for understanding conditional guards without running a full
    feasibility check. Returns both human-readable and SMT-LIB2 formats.
    """
    bv = get_bv()
    result = backend.get_path_constraints(
        bv=bv,
        function_name=function_name,
        target_addr=int(target_addr, 16),
        max_steps=max_steps,
        timeout_secs=timeout_secs,
    )
    return _serialize(result)


@server.tool("se_solve_input")
async def se_solve_input(
    function_name: str,
    target_addr: str,
    extra_constraints: list[str] = None,
    max_steps: int = 50000,
    timeout_secs: int = 120,
) -> dict:
    """Generate a concrete input that reaches target_addr and satisfies
    additional constraints.

    extra_constraints are strings like:
      "arg0 > 0x100"
      "mem[rdi+8] == 0"
    The backend parses these into Z3 expressions.
    """
    bv = get_bv()
    result = backend.solve_for_input(
        bv=bv,
        function_name=function_name,
        target_addr=int(target_addr, 16),
        extra_constraints=extra_constraints,
        max_steps=max_steps,
        timeout_secs=timeout_secs,
    )
    return _serialize(result)


@server.tool("se_map_mlil_var")
async def se_map_mlil_var(
    function_name: str,
    var_name: str,
    var_version: int = 0,
) -> dict:
    """Map an MLIL-SSA variable (from Datalog facts) to its LLIL storage location.

    Returns register name or stack offset. Useful for understanding what
    SENinja's symbolic state represents in terms of Datalog variables.
    """
    bv = get_bv()
    return mlil_var_to_location(bv, function_name, var_name, var_version)


@server.tool("se_get_state_info")
async def se_get_state_info(
    function_name: str,
    addr: str,
) -> dict:
    """Get symbolic state info at a given address (registers, memory, constraints).

    Explores from function entry to addr, then dumps the state.
    Useful for debugging SE behavior or understanding state at a specific point.
    """
    bv = get_bv()
    explore_result = backend.explore(
        bv=bv, function_name=function_name,
        target_addr=int(addr, 16), max_steps=50000, timeout_secs=60,
    )
    # Include register state in result if exploration succeeded
    return _serialize(explore_result)


def _serialize(result):
    """Convert dataclass result to JSON-friendly dict."""
    import dataclasses
    d = dataclasses.asdict(result)
    # Convert bytes to hex strings for JSON
    if d.get("concrete_input") is not None:
        d["concrete_input_hex"] = d["concrete_input"].hex()
        del d["concrete_input"]
    return d


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

---

## Phase 4: Agent Integration

### New config constants in `agent.py`

```python
SE_MCP_PYTHON_PATH = MCP_PYTHON_PATH  # Reuse same BN venv (has binaryninja + seninja)
SE_MCP_BRIDGE_PATH = str(PROJECT_DIR / "se" / "se_mcp_bridge.py")

def create_se_mcp_toolset():
    return MCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command=SE_MCP_PYTHON_PATH,
                args=[SE_MCP_BRIDGE_PATH],
            )
        )
    )
```

### Updated tool list (addition only)

```python
root_agent = LlmAgent(
    name="BinCodeQL",
    model=create_model(),
    instruction=AGENT_INSTRUCTION,
    tools=[
        # ... all existing tools unchanged ...
        FunctionTool(tool_clean_workspace),
        FunctionTool(tool_extract_facts),
        FunctionTool(tool_extract_facts_batch),
        FunctionTool(tool_resolve_calls),
        FunctionTool(tool_run_souffle),
        FunctionTool(tool_list_datalog_files),
        FunctionTool(tool_read_file),
        FunctionTool(tool_generate_signatures),
        FunctionTool(tool_generate_annotations),
        FunctionTool(tool_run_taint_pipeline),
        create_mcp_toolset(),          # Existing BN MCP
        create_se_mcp_toolset(),       # NEW: SE MCP
    ],
)
```

### Agent instruction additions (appended to AGENT_INSTRUCTION)

```
## Symbolic Execution Validation

When the Datalog pipeline produces TaintedSink alerts, validate them with SE:

1. For each TaintedSink, extract: function, sink_addr, buffer size (from StackVar),
   vulnerability type (from DangerousSink risk column).
2. Call the appropriate SE tool:
   - Buffer overflow → `se_check_overflow(function, sink_addr, buffer_size)`
   - Use-after-free → `se_check_uaf(function, alloc_addr, free_addr, use_addr)`
   - General reachability → `se_explore(function, target_addr)`
3. If SE returns FEASIBLE/SAT, report as CONFIRMED with the concrete input.
4. If SE returns INFEASIBLE/UNSAT, report as LIKELY FALSE POSITIVE with the
   blocking constraint (usually a bounds check / guard).
5. If SE returns TIMEOUT, report as UNCONFIRMED — the path may be too complex
   for SE; manual review needed.
6. If a sink already appears in GuardedSink output, still run SE to confirm
   the guard is sufficient (guards don't always prevent overflow).

Use `se_get_constraints` when you want to understand what conditions control
reachability without running a full feasibility check.

Use `se_solve_input` to generate fuzzer seed inputs that reach deep code paths.
```

---

## Phase 5: Libc Stubs (`se_stubs.py`)

SENinja has limited library function modeling. We provide stubs for the functions
most relevant to vulnerability analysis — specifically those that appear in
`DangerousSink.facts` and `TaintTransfer.facts`.

### Stub priority list

| Priority | Function | Stub behavior |
|---|---|---|
| P0 | `malloc(size)` | Return fresh symbolic pointer; track allocation metadata |
| P0 | `free(ptr)` | Mark allocation as freed (for UAF detection) |
| P0 | `memcpy(dst, src, n)` | Symbolic copy of n bytes; check dst bounds |
| P0 | `strcpy(dst, src)` | Copy until null; check dst bounds against src length |
| P0 | `strlen(s)` | Return symbolic length (constrained: 0 ≤ len < allocation_size) |
| P0 | `read(fd, buf, count)` | Write `count` symbolic bytes to `buf`; return symbolic ≤ count |
| P1 | `strncpy(dst, src, n)` | Bounded copy; still check dst size ≥ n |
| P1 | `memset(dst, val, n)` | Concrete fill (important for sanitizer detection) |
| P1 | `calloc(n, size)` | malloc(n*size) + memset(0) |
| P1 | `realloc(ptr, size)` | Free old, malloc new, copy min(old_size, new_size) |
| P2 | `sprintf(dst, fmt, ...)` | Estimate output length symbolically; check dst bounds |
| P2 | `fread(buf, size, n, fp)` | Write size*n symbolic bytes to buf |
| P2 | `fgets(buf, size, fp)` | Write up to size-1 symbolic bytes + null |

### Stub structure

```python
class StubRegistry:
    """Registry of symbolic function stubs."""

    def __init__(self):
        self._stubs = {}
        self._heap_tracker = HeapTracker()  # Tracks alloc/free for UAF detection

    def register(self, name, handler):
        self._stubs[name] = handler

    def has_stub(self, name):
        return name in self._stubs

    def apply(self, name, state, call_addr):
        return self._stubs[name](state, call_addr, self._heap_tracker)


class HeapTracker:
    """Track heap allocations and frees for UAF/double-free detection."""

    def __init__(self):
        self.allocations = {}    # ptr → {size, freed, alloc_addr, free_addr}

    def alloc(self, ptr, size, addr):
        self.allocations[ptr] = {"size": size, "freed": False,
                                  "alloc_addr": addr, "free_addr": None}

    def free(self, ptr, addr):
        if ptr in self.allocations:
            if self.allocations[ptr]["freed"]:
                return {"error": "double_free", "addr": addr,
                        "first_free": self.allocations[ptr]["free_addr"]}
            self.allocations[ptr]["freed"] = True
            self.allocations[ptr]["free_addr"] = addr
        return None

    def is_freed(self, ptr):
        return ptr in self.allocations and self.allocations[ptr]["freed"]


def default_stubs():
    registry = StubRegistry()

    def stub_malloc(state, call_addr, heap):
        # Get size argument (rdi on x86_64)
        size = state.regs.rdi
        # Allocate a fresh symbolic region
        ptr = state.mem.allocate(size)
        heap.alloc(ptr, size, call_addr)
        state.regs.rax = ptr  # Return value

    def stub_free(state, call_addr, heap):
        ptr = state.regs.rdi
        result = heap.free(ptr, call_addr)
        if result and result.get("error") == "double_free":
            state.add_violation("double_free", result)

    def stub_memcpy(state, call_addr, heap):
        dst = state.regs.rdi
        src = state.regs.rsi
        n = state.regs.rdx
        # Check: does n exceed dst's allocation size?
        # This is where we detect the overflow
        if heap.check_bounds(dst, n):
            state.add_violation("buffer_overflow", {
                "dst": dst, "size": n, "addr": call_addr
            })
        state.mem.copy(dst, src, n)
        state.regs.rax = dst

    # ... more stubs ...

    registry.register("malloc", stub_malloc)
    registry.register("free", stub_free)
    registry.register("memcpy", stub_memcpy)
    # etc.

    return registry
```

---

## Implementation Order

| Phase | Deliverable | Depends on | Estimated complexity |
|---|---|---|---|
| **1** | `se/se_backend.py` — ABC + SeninjaBackend skeleton | SENinja installed in BN venv | Medium |
| **2** | `se/se_il_bridge.py` — MLIL↔LLIL variable mapping | Phase 1 + BN Python API | Low-Medium |
| **3** | `se/se_stubs.py` — P0 stubs (malloc, free, memcpy, strcpy, strlen, read) | Phase 1 | Medium |
| **4** | `se/se_mcp_bridge.py` — MCP server with all 7 tools | Phases 1-3 | Medium |
| **5** | Agent integration — add `create_se_mcp_toolset()` + instructions | Phase 4 | Low |
| **6** | Testing — unit tests + validate on a known-vulnerable binary | Phase 5 | Medium |

### Phase 1-3 can be developed and tested independently (no MCP needed).
### Phase 4 wires everything into MCP.
### Phase 5 is a small config change in agent.py.
### Phase 6 validates the full Datalog→SE pipeline end-to-end.

---

## Prerequisites

1. **SENinja installed** in the BN Python environment:
   ```bash
   # In BN's plugin directory or installed via plugin manager
   # Verify: python3 -c "from seninja import SEState; print('ok')"
   # SENinja source is also importable from bin_datalog/se/ modules
   ```

2. **Z3 Python bindings** available:
   ```bash
   pip install z3-solver  # In BN's venv
   ```

3. **MCP Python SDK** (same as existing bridge uses):
   ```bash
   pip install mcp  # In BN's venv
   ```

4. **BN with an open binary** (GUI mode) or a `.bndb` path (headless mode).

---

## Future Extensions (out of scope for v1)

- **AngrBackend**: Drop-in replacement implementing `SEBackend` — useful if SENinja
  hits limits on interprocedural analysis or complex constraint solving.
- **Concolic execution**: Combine concrete fuzzer inputs (from fuzz_harness) with
  symbolic tracking to extend coverage beyond what pure SE achieves.
- **SE-guided Datalog refinement**: Feed SE's path constraints back as new Datalog
  facts (e.g., `InfeasiblePath(func, addr)`) to prune the Datalog analysis itself.
- **Parallel SE validation**: Run multiple `se_check_overflow` calls in parallel
  across different TaintedSink alerts (each gets its own BN headless + SENinja session).
- **Custom constraint language**: Parse user-written constraints like
  `"arg0.len > field(struct_header, size)"` into Z3, leveraging BN type info.
