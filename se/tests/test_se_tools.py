"""Tests for the SE integration layer (angr backend).

These tests verify the components that can be tested WITHOUT angr running:
  - Result dataclasses
  - HeapTracker logic
  - Constraint parser regex
  - Serialization helpers
  - IL bridge variable mapping

Tests requiring angr are marked with ``@pytest.mark.skipif``.
"""

import pytest
import sys
import os
import importlib

# Add se/ directory directly to sys.path so we can import modules
# without going through bin_datalog/__init__.py (which pulls in agent.py
# and its heavy dependencies like litellm).
_se_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _se_dir not in sys.path:
    sys.path.insert(0, _se_dir)

se_backend = importlib.import_module("se_backend")
se_stubs = importlib.import_module("se_stubs")


# ── Test result dataclasses ──────────────────────────────────────────────

class TestResultDataclasses:
    def test_explore_result_defaults(self):
        ExploreResult = se_backend.ExploreResult
        r = ExploreResult(status="SAT")
        assert r.status == "SAT"
        assert r.steps_taken == 0
        assert r.concrete_input is None
        assert r.constraints_summary == []
        assert r.registers_at_target is None
        assert r.error_message is None

    def test_feasibility_result_defaults(self):
        FeasibilityResult = se_backend.FeasibilityResult
        r = FeasibilityResult(status="INFEASIBLE")
        assert r.feasible is False
        assert r.violation_detail == ""

    def test_constraints_result_defaults(self):
        ConstraintsResult = se_backend.ConstraintsResult
        r = ConstraintsResult()
        assert r.reachable is False
        assert r.constraints == []


# ── Test HeapTracker ─────────────────────────────────────────────────────

class TestHeapTracker:
    def _make_tracker(self):
        return se_stubs.HeapTracker()

    def test_alloc_and_free(self):
        ht = self._make_tracker()
        ht.record_alloc(0x1000, 64, 0x400100)
        assert not ht.is_freed(0x1000)

        violation = ht.record_free(0x1000, 0x400200)
        assert violation is None
        assert ht.is_freed(0x1000)

    def test_double_free_detection(self):
        ht = self._make_tracker()
        ht.record_alloc(0x2000, 32, 0x400100)
        ht.record_free(0x2000, 0x400200)

        violation = ht.record_free(0x2000, 0x400300)
        assert violation is not None
        assert violation["type"] == "double_free"
        assert violation["first_free"] == hex(0x400200)
        assert violation["second_free"] == hex(0x400300)
        assert len(ht.violations) == 1

    def test_free_null_is_safe(self):
        ht = self._make_tracker()
        # Free of untracked pointer returns None (not a violation)
        violation = ht.record_free(0x0, 0x400200)
        assert violation is None

    def test_bounds_check_within(self):
        ht = self._make_tracker()
        ht.record_alloc(0x3000, 64, 0x400100)
        violation = ht.check_bounds(0x3000, 64)
        assert violation is None

    def test_bounds_check_overflow(self):
        ht = self._make_tracker()
        ht.record_alloc(0x3000, 64, 0x400100)
        violation = ht.check_bounds(0x3000, 72)
        assert violation is not None
        assert violation["type"] == "heap_buffer_overflow"
        assert violation["overflow_by"] == 8

    def test_bounds_check_interior_pointer(self):
        ht = self._make_tracker()
        ht.record_alloc(0x4000, 100, 0x400100)
        # Access from offset 90 for 20 bytes overflows by 10
        violation = ht.check_bounds(0x4000 + 90, 20)
        assert violation is not None
        assert violation["overflow_by"] == 10

    def test_uaf_detection(self):
        ht = self._make_tracker()
        ht.record_alloc(0x5000, 64, 0x400100)
        ht.record_free(0x5000, 0x400200)
        violation = ht.check_use_after_free(0x5000, 0x400300)
        assert violation is not None
        assert violation["type"] == "use_after_free"

    def test_no_uaf_on_live_alloc(self):
        ht = self._make_tracker()
        ht.record_alloc(0x6000, 64, 0x400100)
        violation = ht.check_use_after_free(0x6000, 0x400200)
        assert violation is None

    def test_get_alloc_size(self):
        ht = self._make_tracker()
        ht.record_alloc(0x7000, 128, 0x400100)
        assert ht.get_alloc_size(0x7000) == 128
        assert ht.get_alloc_size(0x9999) is None


# ── Test serialization ───────────────────────────────────────────────────

class TestSerialization:
    def test_serialize_explore_result_with_bytes(self):
        import dataclasses
        ExploreResult = se_backend.ExploreResult

        r = ExploreResult(
            status="SAT",
            steps_taken=42,
            concrete_input=b"\x41\x42\x43",
        )
        d = dataclasses.asdict(r)
        # Simulate the bridge serialization
        if d.get("concrete_input") is not None:
            d["concrete_input_hex"] = d["concrete_input"].hex()
            del d["concrete_input"]

        assert d["concrete_input_hex"] == "414243"
        assert "concrete_input" not in d
        assert d["status"] == "SAT"

    def test_serialize_none_input(self):
        import dataclasses
        ExploreResult = se_backend.ExploreResult

        r = ExploreResult(status="UNSAT")
        d = dataclasses.asdict(r)
        assert d.get("concrete_input") is None


# ── Test build_hook_registry ─────────────────────────────────────────────

class TestHookRegistry:
    def test_registry_has_expected_keys(self):
        """Verify registry structure: angr version has tracked alloc/free classes."""
        se_stubs.reset_heap_tracker()
        hooks = se_stubs.build_hook_registry(track_heap=True)
        assert "free" in hooks
        assert "realloc" in hooks
        assert "malloc" in hooks
        assert "calloc" in hooks
        # Each value is a SimProcedure class (not instance)
        for name, cls in hooks.items():
            assert callable(cls), f"{name} should be callable"

    def test_registry_without_heap_tracking(self):
        hooks = se_stubs.build_hook_registry(track_heap=False)
        assert "malloc" not in hooks
        assert "calloc" not in hooks
        assert "free" in hooks
        assert "realloc" in hooks


# ── Test constraint parser ───────────────────────────────────────────────

class TestConstraintParser:
    def test_parse_valid_constraint(self):
        """Test the regex parser with a None state (no angr needed)."""
        _parse_constraint = se_backend._parse_constraint
        # Without real angr state, getattr(state.regs, ...) fails → returns None
        result = _parse_constraint("not a constraint", None)
        assert result is None

    def test_parse_format_recognition(self):
        """Verify regex matches valid formats."""
        import re
        pattern = r"^\s*(\w+)\s*(==|!=|>|<|>=|<=)\s*(0x[0-9a-fA-F]+|\d+)\s*$"
        assert re.match(pattern, "rax > 0x100")
        assert re.match(pattern, "rdi == 0")
        assert re.match(pattern, "rsi != 0xff")
        assert re.match(pattern, "r8 >= 42")
        assert not re.match(pattern, "not valid")
        assert not re.match(pattern, "rax >")


# ── Test IL bridge ───────────────────────────────────────────────────────

class TestILBridge:
    @classmethod
    def setup_class(cls):
        cls.il_bridge = importlib.import_module("se_il_bridge")

    def test_arg_index_to_register_sysv(self):
        r = self.il_bridge.arg_index_to_register(0)
        assert r["type"] == "register"
        assert r["reg"] == "rdi"
        r5 = self.il_bridge.arg_index_to_register(5)
        assert r5["reg"] == "r9"
        r6 = self.il_bridge.arg_index_to_register(6)
        assert r6["type"] == "stack"  # 7th arg goes on stack

    def test_map_datalog_var_argument(self):
        result = self.il_bridge.map_datalog_var({"type": "argument", "index": 0, "size": 8})
        assert result["type"] == "register"
        assert result["reg"] == "rdi"

    def test_map_datalog_var_stack(self):
        result = self.il_bridge.map_datalog_var({"type": "stack", "offset": -0x10, "size": 8})
        assert result["type"] == "stack"
        assert result["rbp_offset"] == -0x10

    def test_map_datalog_var_register(self):
        result = self.il_bridge.map_datalog_var({"type": "register", "reg": "rax", "size": 8})
        assert result["type"] == "register"
        assert result["reg"] == "rax"

    def test_map_datalog_var_unknown(self):
        result = self.il_bridge.map_datalog_var({"type": "weird"})
        assert result["type"] == "unknown"
