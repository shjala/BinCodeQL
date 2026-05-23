"""Heap-tracking SimProcedures for vulnerability analysis with angr.

angr already provides SimProcedures for most libc functions (malloc, free,
memcpy, strlen, strcmp, etc.).  This module adds a **HeapTracker** that
observes allocation/free patterns and detects:
  - Double-free
  - Use-after-free
  - Heap buffer overflow (bounds checking)

It also provides custom SimProcedure subclasses that wrap angr's built-in
models and feed events to the HeapTracker.

Usage::

    from se_stubs import HeapTracker, hook_project
    tracker = HeapTracker()
    hook_project(project, tracker)
    # ... run exploration ...
    print(tracker.violations)
"""

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Heap tracker — correlates alloc / free for UAF & double-free detection
# ---------------------------------------------------------------------------

@dataclass
class HeapAllocation:
    ptr: int
    size: int
    alloc_addr: int
    freed: bool = False
    free_addr: Optional[int] = None


class HeapTracker:
    """Tracks symbolic heap allocations and frees.

    Records are keyed by the concrete pointer value returned by the
    allocator.  Violations (double-free, UAF) are appended to
    ``self.violations``.
    """

    def __init__(self):
        self.allocations: dict[int, HeapAllocation] = {}
        self.violations: list[dict] = []

    def record_alloc(self, ptr: int, size: int, alloc_addr: int):
        self.allocations[ptr] = HeapAllocation(
            ptr=ptr, size=size, alloc_addr=alloc_addr, freed=False,
        )

    def record_free(self, ptr: int, free_addr: int) -> Optional[dict]:
        """Returns a violation dict if double-free, else None."""
        if ptr not in self.allocations:
            return None
        alloc = self.allocations[ptr]
        if alloc.freed:
            violation = {
                "type": "double_free",
                "ptr": hex(ptr),
                "first_free": hex(alloc.free_addr),
                "second_free": hex(free_addr),
                "alloc_addr": hex(alloc.alloc_addr),
            }
            self.violations.append(violation)
            return violation
        alloc.freed = True
        alloc.free_addr = free_addr
        return None

    def is_freed(self, ptr: int) -> bool:
        return ptr in self.allocations and self.allocations[ptr].freed

    def get_alloc_size(self, ptr: int) -> Optional[int]:
        if ptr in self.allocations:
            return self.allocations[ptr].size
        return None

    def check_bounds(self, ptr: int, access_size: int) -> Optional[dict]:
        """Check if *access_size* bytes from *ptr* exceed the allocation."""
        for base, alloc in self.allocations.items():
            if base <= ptr < base + alloc.size:
                end = ptr + access_size
                if end > base + alloc.size:
                    violation = {
                        "type": "heap_buffer_overflow",
                        "ptr": hex(ptr),
                        "alloc_base": hex(base),
                        "alloc_size": alloc.size,
                        "access_end": hex(end),
                        "overflow_by": end - (base + alloc.size),
                    }
                    self.violations.append(violation)
                    return violation
                return None
        return None

    def check_use_after_free(self, ptr: int, use_addr: int) -> Optional[dict]:
        """Check if *ptr* was freed before this use."""
        for base, alloc in self.allocations.items():
            if base <= ptr < base + alloc.size:
                if alloc.freed:
                    violation = {
                        "type": "use_after_free",
                        "ptr": hex(ptr),
                        "alloc_addr": hex(alloc.alloc_addr),
                        "free_addr": hex(alloc.free_addr),
                        "use_addr": hex(use_addr),
                    }
                    self.violations.append(violation)
                    return violation
                return None
        return None


# ---------------------------------------------------------------------------
# Global tracker instance (shared across all stubs in one SE session)
# ---------------------------------------------------------------------------

_heap_tracker = HeapTracker()


def get_heap_tracker() -> HeapTracker:
    return _heap_tracker


def reset_heap_tracker():
    global _heap_tracker
    _heap_tracker = HeapTracker()


# ---------------------------------------------------------------------------
# angr SimProcedure wrappers with HeapTracker integration
# ---------------------------------------------------------------------------

def _make_tracked_malloc(tracker: HeapTracker):
    """Create a malloc SimProcedure class that feeds the HeapTracker."""
    import angr
    import claripy

    class TrackedMalloc(angr.SimProcedure):
        def run(self, size):
            # Concretize size if symbolic
            if self.state.solver.symbolic(size):
                concrete_size = self.state.solver.max(size)
                concrete_size = min(concrete_size, 0x100000)  # 1MB cap
            else:
                concrete_size = self.state.solver.eval(size)

            # Use angr's heap allocator
            ptr = self.state.heap.allocate(concrete_size)
            tracker.record_alloc(ptr, concrete_size, self.state.addr)
            return ptr

    return TrackedMalloc


def _make_tracked_calloc(tracker: HeapTracker):
    """Create a calloc SimProcedure that feeds the HeapTracker."""
    import angr
    import claripy

    class TrackedCalloc(angr.SimProcedure):
        def run(self, nmemb, size):
            if self.state.solver.symbolic(nmemb):
                n = self.state.solver.max(nmemb)
            else:
                n = self.state.solver.eval(nmemb)
            if self.state.solver.symbolic(size):
                sz = self.state.solver.max(size)
            else:
                sz = self.state.solver.eval(size)

            total = min(n * sz, 0x100000)
            ptr = self.state.heap.allocate(total)
            # Zero-initialize
            self.state.memory.store(
                ptr, claripy.BVV(0, total * 8),
            )
            tracker.record_alloc(ptr, total, self.state.addr)
            return ptr

    return TrackedCalloc


def _make_tracked_free(tracker: HeapTracker):
    """Create a free SimProcedure with double-free detection."""
    import angr

    class TrackedFree(angr.SimProcedure):
        def run(self, ptr):
            if self.state.solver.symbolic(ptr):
                ptr_val = self.state.solver.eval(ptr)
            else:
                ptr_val = self.state.solver.eval(ptr)

            if ptr_val == 0:
                return  # free(NULL) is a no-op

            violation = tracker.record_free(ptr_val, self.state.addr)
            if violation:
                # Store as state metadata for later retrieval
                if not hasattr(self.state, "se_violations"):
                    self.state.globals["se_violations"] = []
                self.state.globals["se_violations"].append(violation)

    return TrackedFree


def _make_tracked_realloc(tracker: HeapTracker):
    """Create a realloc SimProcedure with HeapTracker integration."""
    import angr
    import claripy

    class TrackedRealloc(angr.SimProcedure):
        def run(self, ptr, new_size):
            if self.state.solver.symbolic(new_size):
                new_sz = min(self.state.solver.max(new_size), 0x100000)
            else:
                new_sz = self.state.solver.eval(new_size)

            if self.state.solver.symbolic(ptr):
                ptr_val = self.state.solver.eval(ptr)
            else:
                ptr_val = self.state.solver.eval(ptr)

            # realloc(NULL, size) == malloc(size)
            if ptr_val == 0:
                new_ptr = self.state.heap.allocate(new_sz)
                tracker.record_alloc(new_ptr, new_sz, self.state.addr)
                return new_ptr

            old_size = tracker.get_alloc_size(ptr_val) or 0

            # Allocate new region
            new_ptr = self.state.heap.allocate(new_sz)
            tracker.record_alloc(new_ptr, new_sz, self.state.addr)

            # Copy old data
            copy_size = min(old_size, new_sz)
            if copy_size > 0:
                data = self.state.memory.load(ptr_val, copy_size)
                self.state.memory.store(new_ptr, data)

            # Free old
            tracker.record_free(ptr_val, self.state.addr)
            return new_ptr

    return TrackedRealloc


# ---------------------------------------------------------------------------
# Hook installer
# ---------------------------------------------------------------------------

def hook_project(proj, tracker: HeapTracker = None):
    """Install HeapTracker-aware SimProcedures on an angr Project.

    Replaces the default malloc/calloc/free/realloc with tracked versions.
    angr's built-in SimProcedures for memcpy, strlen, strcmp, etc. are
    left unchanged (they work fine for SE).

    Args:
        proj: angr.Project instance
        tracker: HeapTracker to use. If None, uses the global tracker.
    """
    if tracker is None:
        tracker = get_heap_tracker()

    # Hook by symbol name — angr resolves PLT/GOT automatically
    proj.hook_symbol("malloc", _make_tracked_malloc(tracker)())
    proj.hook_symbol("calloc", _make_tracked_calloc(tracker)())
    proj.hook_symbol("free", _make_tracked_free(tracker)())
    proj.hook_symbol("realloc", _make_tracked_realloc(tracker)())


def build_hook_registry(track_heap: bool = True) -> dict:
    """Return a dict of function names to angr SimProcedure classes.

    This is for programmatic inspection / testing.  For actual hooking,
    use ``hook_project()`` which handles symbol resolution.
    """
    reset_heap_tracker()
    tracker = get_heap_tracker()

    hooks = {
        "free": _make_tracked_free(tracker),
        "realloc": _make_tracked_realloc(tracker),
    }

    if track_heap:
        hooks["malloc"] = _make_tracked_malloc(tracker)
        hooks["calloc"] = _make_tracked_calloc(tracker)

    return hooks
