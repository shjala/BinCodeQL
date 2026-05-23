"""SEBackend ABC and angr implementation.

Defines the abstract interface for symbolic execution backends and provides
a concrete implementation using angr for vulnerability validation.
"""

import re
import time
import logging
import dataclasses
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ExploreResult:
    """Result of a symbolic exploration."""
    status: str  # "SAT", "UNSAT", "TIMEOUT", "ERROR"
    steps_taken: int = 0
    concrete_input: Optional[bytes] = None
    constraints_summary: list = field(default_factory=list)
    registers_at_target: Optional[dict] = None
    error_message: Optional[str] = None


@dataclass
class FeasibilityResult:
    """Result of a vulnerability feasibility check."""
    status: str  # "FEASIBLE", "INFEASIBLE", "TIMEOUT", "ERROR"
    feasible: bool = False
    concrete_input: Optional[bytes] = None
    violation_detail: str = ""
    blocking_guard: Optional[str] = None
    steps_taken: int = 0
    error_message: Optional[str] = None


@dataclass
class ConstraintsResult:
    """Path constraints to reach a target address."""
    reachable: bool = False
    constraints: list = field(default_factory=list)
    smt2_constraints: Optional[str] = None
    steps_taken: int = 0


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class SEBackend(ABC):
    """Abstract symbolic execution backend.

    Implementations wrap specific SE engines (angr, SENinja, etc.) behind
    a uniform interface so the MCP tool layer is engine-agnostic.

    The ``binary_path`` parameter replaces ``bv`` (BinaryView) — angr opens
    the binary directly, no Binary Ninja required.
    """

    @abstractmethod
    def explore(
        self,
        binary_path: str,
        function_name: str,
        target_addr: int,
        avoid_addrs: list = None,
        max_steps: int = 50_000,
        timeout_secs: int = 120,
        symbolic_args: dict = None,
    ) -> ExploreResult:
        ...

    @abstractmethod
    def check_overflow_feasibility(
        self,
        binary_path: str,
        function_name: str,
        sink_addr: int,
        buffer_size: int,
        size_arg_index: int = -1,
        max_steps: int = 50_000,
        timeout_secs: int = 120,
    ) -> FeasibilityResult:
        ...

    @abstractmethod
    def check_uaf_feasibility(
        self,
        binary_path: str,
        function_name: str,
        alloc_addr: int,
        free_addr: int,
        use_addr: int,
        max_steps: int = 50_000,
        timeout_secs: int = 120,
    ) -> FeasibilityResult:
        ...

    @abstractmethod
    def get_path_constraints(
        self,
        binary_path: str,
        function_name: str,
        target_addr: int,
        max_steps: int = 50_000,
        timeout_secs: int = 120,
    ) -> ConstraintsResult:
        ...

    @abstractmethod
    def solve_for_input(
        self,
        binary_path: str,
        function_name: str,
        target_addr: int,
        extra_constraints: list = None,
        max_steps: int = 50_000,
        timeout_secs: int = 120,
    ) -> ExploreResult:
        ...


# ---------------------------------------------------------------------------
# angr backend
# ---------------------------------------------------------------------------

class AngrBackend(SEBackend):
    """angr-based symbolic execution backend.

    Loads the binary via ``angr.Project``, uses ``SimulationManager`` for
    path exploration, and Claripy for constraint solving.
    """

    def __init__(self, auto_load_libs: bool = False,
                 heap_tracker=None):
        """
        Args:
            auto_load_libs: Whether angr should load shared libraries.
                False (default) avoids bloated memory and focuses analysis
                on the target binary.  angr provides SimProcedures for
                common libc functions automatically.
            heap_tracker: Optional HeapTracker instance for vuln detection.
                If None, a fresh one is created per session.
        """
        self._auto_load_libs = auto_load_libs
        self._heap_tracker = heap_tracker
        self._project_cache = {}  # path → angr.Project (reuse across calls)

    def _get_project(self, binary_path: str):
        """Get or create an angr Project for the given binary."""
        if binary_path not in self._project_cache:
            import angr
            proj = angr.Project(
                binary_path,
                auto_load_libs=self._auto_load_libs,
                load_options={"main_opts": {"base_addr": 0}},
            )
            self._project_cache[binary_path] = proj
        return self._project_cache[binary_path]

    def unload(self, binary_path: str = None):
        """Drop cached Project(s) to free memory."""
        if binary_path:
            self._project_cache.pop(binary_path, None)
        else:
            self._project_cache.clear()

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _resolve_function_addr(proj, name: str) -> int:
        """Resolve a function name to its entry address."""
        sym = proj.loader.find_symbol(name)
        if sym is not None:
            return sym.rebased_addr
        # Fallback: check CFG knowledge base if available
        if proj.kb and hasattr(proj.kb, "functions"):
            for addr, func in proj.kb.functions.items():
                if func.name == name:
                    return addr
        raise ValueError(f"Function '{name}' not found in binary")

    def _create_state(self, proj, start_addr: int, symbolic_args: dict = None):
        """Create a call state at the given address with optional symbolic args."""
        import claripy

        if symbolic_args:
            # Build symbolic arguments in calling convention order
            cc = proj.factory.cc()
            args = []
            for idx in sorted(symbolic_args.keys()):
                size_bytes = symbolic_args[idx]
                sym = claripy.BVS(f"arg{idx}", size_bytes * 8)
                args.append(sym)
            state = proj.factory.call_state(
                start_addr,
                *args,
                add_options={
                    "SYMBOL_FILL_UNCONSTRAINED_MEMORY",
                    "SYMBOL_FILL_UNCONSTRAINED_REGISTERS",
                },
            )
        else:
            state = proj.factory.blank_state(
                addr=start_addr,
                add_options={
                    "SYMBOL_FILL_UNCONSTRAINED_MEMORY",
                    "SYMBOL_FILL_UNCONSTRAINED_REGISTERS",
                },
            )
        return state

    def _run_explore(self, proj, state, target_addr, avoid_addrs,
                     max_steps, timeout_secs):
        """Run SimulationManager.explore() with step + time budget.

        Returns ``(found_state_or_None, steps_taken, timed_out)``.
        """
        simgr = proj.factory.simgr(state)
        avoid = avoid_addrs or []
        start_time = time.monotonic()
        steps = 0

        while steps < max_steps:
            elapsed = time.monotonic() - start_time
            if elapsed > timeout_secs:
                return None, steps, True

            if not simgr.active:
                break

            simgr.step()
            steps += 1

            # Check for found states
            simgr.move(
                from_stash="active",
                to_stash="found",
                filter_func=lambda s: s.addr == target_addr,
            )
            if avoid:
                simgr.move(
                    from_stash="active",
                    to_stash="avoid",
                    filter_func=lambda s: s.addr in avoid,
                )

            if simgr.found:
                return simgr.found[0], steps, False

            # Limit active state count to prevent memory explosion
            if len(simgr.active) > 64:
                simgr.drop(stash="active", filter_func=lambda s: True)
                # Keep only the first 32 states (DFS-ish priority)
                kept = simgr.active[:32]
                simgr._stashes["active"] = kept

        timed_out = (time.monotonic() - start_time) > timeout_secs
        return None, steps, timed_out

    def _concretize_input(self, state):
        """Extract concrete bytes for all symbolic input in the state."""
        parts = []
        for act in state.history.actions:
            # Collect stdin reads if present
            pass

        # Try to concretize file input (stdin)
        try:
            stdin = state.posix.stdin
            data = stdin.concretize()
            if data:
                return bytes(data)
        except Exception:
            pass

        # Concretize symbolic args from registers
        try:
            for i in range(6):  # x86-64: rdi, rsi, rdx, rcx, r8, r9
                reg_name = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"][i]
                val = getattr(state.regs, reg_name)
                if val.symbolic:
                    concrete = state.solver.eval(val, cast_to=int)
                    parts.append(concrete.to_bytes(8, "little"))
        except Exception:
            pass

        return b"".join(parts) if parts else None

    def _summarize_constraints(self, state):
        """Return human-readable strings for path constraints."""
        summaries = []
        for c in state.solver.constraints:
            s = str(c)
            if len(s) > 200:
                s = s[:200] + "..."
            summaries.append(s)
        return summaries

    def _dump_registers(self, state):
        """Snapshot interesting registers from the state."""
        reg_names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                     "rsp", "rbp", "r8", "r9", "r10", "r11",
                     "r12", "r13", "r14", "r15"]
        result = {}
        for r in reg_names:
            try:
                val = getattr(state.regs, r)
                if val.symbolic:
                    result[r] = f"symbolic({val})"
                else:
                    result[r] = hex(state.solver.eval(val))
            except Exception:
                pass
        return result

    def _get_arg_bv(self, proj, state, arg_index: int):
        """Get the bitvector for argument at *arg_index* via calling convention."""
        cc = proj.factory.cc()
        if arg_index < len(cc.ARG_REGS):
            reg_name = cc.ARG_REGS[arg_index]
            return getattr(state.regs, reg_name)
        # Stack argument
        stack_offset = (arg_index - len(cc.ARG_REGS)) * proj.arch.bytes
        sp = state.regs.rsp
        return state.memory.load(sp + stack_offset, proj.arch.bytes,
                                 endness=proj.arch.memory_endness)

    # -- public API -------------------------------------------------------

    def explore(self, binary_path, function_name, target_addr,
                avoid_addrs=None, max_steps=50_000, timeout_secs=120,
                symbolic_args=None):
        try:
            proj = self._get_project(binary_path)
            func_addr = self._resolve_function_addr(proj, function_name)
            state = self._create_state(proj, func_addr, symbolic_args)

            found, steps, timed_out = self._run_explore(
                proj, state, target_addr, avoid_addrs, max_steps, timeout_secs)

            if found:
                concrete = self._concretize_input(found)
                constraints = self._summarize_constraints(found)
                regs = self._dump_registers(found)
                return ExploreResult(
                    status="SAT", steps_taken=steps,
                    concrete_input=concrete,
                    constraints_summary=constraints,
                    registers_at_target=regs,
                )
            if timed_out:
                return ExploreResult(status="TIMEOUT", steps_taken=steps)
            return ExploreResult(status="UNSAT", steps_taken=steps)

        except Exception as e:
            return ExploreResult(status="ERROR", error_message=str(e))

    def check_overflow_feasibility(self, binary_path, function_name,
                                   sink_addr, buffer_size,
                                   size_arg_index=-1,
                                   max_steps=50_000, timeout_secs=120):
        try:
            import claripy

            proj = self._get_project(binary_path)
            func_addr = self._resolve_function_addr(proj, function_name)
            state = self._create_state(proj, func_addr)

            found, steps, timed_out = self._run_explore(
                proj, state, sink_addr, [], max_steps, timeout_secs)

            if not found:
                if timed_out:
                    return FeasibilityResult(status="TIMEOUT", steps_taken=steps)
                return FeasibilityResult(
                    status="INFEASIBLE", feasible=False, steps_taken=steps,
                    blocking_guard="Path to sink is unreachable",
                )

            # At the sink, check if the size argument can exceed buffer_size
            if size_arg_index >= 0:
                size_bv = self._get_arg_bv(proj, found, size_arg_index)
                overflow_cond = claripy.UGT(
                    size_bv,
                    claripy.BVV(buffer_size, size_bv.size()),
                )
                if found.solver.satisfiable(extra_constraints=[overflow_cond]):
                    found.solver.add(overflow_cond)
                    eval_size = found.solver.eval(size_bv)
                    concrete = self._concretize_input(found)
                    return FeasibilityResult(
                        status="FEASIBLE", feasible=True,
                        concrete_input=concrete, steps_taken=steps,
                        violation_detail=(
                            f"write of {eval_size} bytes into "
                            f"{buffer_size}-byte buffer"
                        ),
                    )
                else:
                    constraints = self._summarize_constraints(found)
                    return FeasibilityResult(
                        status="INFEASIBLE", feasible=False,
                        steps_taken=steps,
                        blocking_guard=(
                            f"Size arg constrained to <= {buffer_size}; "
                            f"constraints: {constraints[:3]}"
                        ),
                    )

            # No specific size arg — just report reachability
            concrete = self._concretize_input(found)
            return FeasibilityResult(
                status="FEASIBLE", feasible=True,
                concrete_input=concrete, steps_taken=steps,
                violation_detail=f"Sink at {hex(sink_addr)} is reachable",
            )

        except Exception as e:
            return FeasibilityResult(status="ERROR", error_message=str(e))

    def check_uaf_feasibility(self, binary_path, function_name,
                              alloc_addr, free_addr, use_addr,
                              max_steps=50_000, timeout_secs=120):
        """Check alloc -> free -> use feasibility via chained exploration."""
        try:
            proj = self._get_project(binary_path)
            func_addr = self._resolve_function_addr(proj, function_name)
            state = self._create_state(proj, func_addr)

            third_steps = max_steps // 3
            third_time = timeout_secs // 3

            # Phase 1: reach alloc site
            found1, s1, t1 = self._run_explore(
                proj, state, alloc_addr, [], third_steps, third_time)
            if not found1:
                return FeasibilityResult(
                    status="TIMEOUT" if t1 else "INFEASIBLE",
                    steps_taken=s1,
                    blocking_guard="Cannot reach allocation site",
                )

            # Phase 2: from alloc, reach free site
            found2, s2, t2 = self._run_explore(
                proj, found1, free_addr, [], third_steps, third_time)
            if not found2:
                return FeasibilityResult(
                    status="TIMEOUT" if t2 else "INFEASIBLE",
                    steps_taken=s1 + s2,
                    blocking_guard="Cannot reach free after allocation",
                )

            # Phase 3: from free, reach use site
            found3, s3, t3 = self._run_explore(
                proj, found2, use_addr, [], third_steps, third_time)
            total = s1 + s2 + s3
            if not found3:
                return FeasibilityResult(
                    status="TIMEOUT" if t3 else "INFEASIBLE",
                    steps_taken=total,
                    blocking_guard="Cannot reach use-site after free",
                )

            concrete = self._concretize_input(found3)
            return FeasibilityResult(
                status="FEASIBLE", feasible=True,
                concrete_input=concrete, steps_taken=total,
                violation_detail=(
                    f"Use-after-free: alloc@{hex(alloc_addr)} -> "
                    f"free@{hex(free_addr)} -> use@{hex(use_addr)}"
                ),
            )

        except Exception as e:
            return FeasibilityResult(status="ERROR", error_message=str(e))

    def get_path_constraints(self, binary_path, function_name, target_addr,
                             max_steps=50_000, timeout_secs=120):
        try:
            proj = self._get_project(binary_path)
            func_addr = self._resolve_function_addr(proj, function_name)
            state = self._create_state(proj, func_addr)

            found, steps, timed_out = self._run_explore(
                proj, state, target_addr, [], max_steps, timeout_secs)

            if found:
                constraints = self._summarize_constraints(found)
                # Build SMT-LIB2 dump from Claripy solver
                smt2 = None
                try:
                    solver = found.solver._solver
                    smt2 = solver.to_smt2()
                except Exception:
                    pass
                return ConstraintsResult(
                    reachable=True, constraints=constraints,
                    smt2_constraints=smt2, steps_taken=steps,
                )
            return ConstraintsResult(reachable=False, steps_taken=steps)

        except Exception as e:
            return ConstraintsResult(
                reachable=False, steps_taken=0,
                constraints=[f"Error: {e}"],
            )

    def solve_for_input(self, binary_path, function_name, target_addr,
                        extra_constraints=None, max_steps=50_000,
                        timeout_secs=120):
        try:
            proj = self._get_project(binary_path)
            func_addr = self._resolve_function_addr(proj, function_name)
            state = self._create_state(proj, func_addr)

            found, steps, timed_out = self._run_explore(
                proj, state, target_addr, [], max_steps, timeout_secs)

            if not found:
                status = "TIMEOUT" if timed_out else "UNSAT"
                return ExploreResult(status=status, steps_taken=steps)

            # Apply extra constraints
            if extra_constraints:
                for ec_str in extra_constraints:
                    parsed = _parse_constraint(ec_str, found)
                    if parsed is not None:
                        found.solver.add(parsed)

                if not found.solver.satisfiable():
                    return ExploreResult(
                        status="UNSAT", steps_taken=steps,
                        constraints_summary=[
                            "Extra constraints made path infeasible"
                        ],
                    )

            concrete = self._concretize_input(found)
            constraints = self._summarize_constraints(found)
            regs = self._dump_registers(found)
            return ExploreResult(
                status="SAT", steps_taken=steps,
                concrete_input=concrete,
                constraints_summary=constraints,
                registers_at_target=regs,
            )

        except Exception as e:
            return ExploreResult(status="ERROR", error_message=str(e))


# ---------------------------------------------------------------------------
# Constraint string parser (lightweight, uses Claripy)
# ---------------------------------------------------------------------------

def _parse_constraint(expr_str: str, state):
    """Parse a simple constraint string into a Claripy Bool expression.

    Supports forms like:
        "rax > 0x100"
        "rdi == 0"
        "rsi != 0xff"
    """
    m = re.match(
        r"^\s*(\w+)\s*(==|!=|>|<|>=|<=)\s*(0x[0-9a-fA-F]+|\d+)\s*$",
        expr_str,
    )
    if not m:
        return None

    reg_name, op, val_str = m.group(1), m.group(2), m.group(3)
    val = int(val_str, 0)

    try:
        import claripy
        reg_bv = getattr(state.regs, reg_name)
        rhs = claripy.BVV(val, reg_bv.size())
    except (AttributeError, Exception):
        return None

    ops = {
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
        ">":  lambda a, b: claripy.UGT(a, b),
        "<":  lambda a, b: claripy.ULT(a, b),
        ">=": lambda a, b: claripy.UGE(a, b),
        "<=": lambda a, b: claripy.ULE(a, b),
    }
    return ops[op](reg_bv, rhs)
