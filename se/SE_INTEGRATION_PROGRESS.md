# Symbolic Execution Integration — Progress & Design Decisions

> Session resume document. Captures *why* and *how* decisions were made,
> not the code itself. Read this to pick up where we left off.

**Last updated:** 17 March 2026  
**Status:** SE layer fully implemented, tested, **not yet wired into agent.py**

---

## 1. Goal

Add targeted symbolic execution (SE) to BinCodeQL so the agent can
**verify** vulnerability candidates found by Datalog queries + LLM analysis.
SE confirms whether a flagged path is actually reachable and whether
attacker-controlled input can trigger it.

---

## 2. Engine Choice: SENinja → angr

### Why SENinja was the first choice
- Native to Binary Ninja — operates directly on BN's LLIL/MLIL
- No IL translation needed (BN IL → VEX)
- Lighter than angr for targeted per-function exploration

### Why we abandoned SENinja
- **Python version blocker**: SENinja requires Python ≥ 3.11, but Binary
  Ninja 5.2.8 ships with system Python 3.10.12 (confirmed via BN console).
  The plugin manager install failed silently. No workaround short of
  replacing the system Python, which the user doesn't want.

### Why angr works
- Runs on Python 3.10 — no version conflict
- Installed cleanly in the ADK venv (`angr 9.2.205`, via `uv pip install angr`)
- **No BN dependency** for the SE process — angr loads the binary directly
  from disk (ELF/PE). It has its own loader (CLE) and lifter (VEX via PyVEX).
- Rich built-in SimProcedure library for libc functions
- Claripy solver (wraps Z3) for constraint generation/solving
- 32 GB RAM on the machine handles both BN + angr comfortably (~2 GB overhead)

### What we lose vs SENinja
- No direct BN IL correlation — angr works on addresses + VEX, not MLIL.
  We bridge this gap via calling conventions (register names, stack offsets)
  rather than IL-level variable mapping.
- angr is heavier on memory and startup than SENinja would have been.

---

## 3. Architecture Decision: Two Separate MCP Processes

```
Agent (ADK venv, Python 3.10)
├── BN MCP bridge    (system Python, BN API)  ← existing, unchanged
│   communicates with BN HTTP server on localhost:9009
└── SE MCP bridge    (ADK venv, angr)         ← NEW, in bin_datalog/se/
    loads binary directly from disk via angr
```

### Why two processes?
- BN MCP bridge runs under BN's system Python (3.10) with BN API imports.
  angr is installed in the ADK venv. Mixing them in one process would
  create import/dependency conflicts.
- Separate processes = separate failure domains. angr crashing doesn't
  kill the BN bridge.
- ADK's `MCPToolset` + `StdioServerParameters` already supports multiple
  MCP subprocesses — this is the standard ADK pattern.

### How binary path flows (key design decision)
The agent needs to tell angr *which* binary to analyze. Three resolution
strategies in priority order:

1. **CLI argument** — `python se_mcp_bridge.py /path/to/binary`
2. **`BINARY_PATH` env var**
3. **Auto-discover from BN** — the SE bridge queries
   `GET http://localhost:9009/status` (same HTTP server the BN MCP bridge
   uses) and extracts the `filename` field from the JSON response.

**We chose option 3 as the default path.** Rationale:
- The BN HTTP server is always running when the agent runs
- The agent already calls `get_binary_status()` from the BN MCP tools
- No extra configuration or agent-visible tool calls needed — fully automatic
- Supports binary switching: `se_unload()` clears the cached path, next
  tool call re-queries BN to pick up a newly loaded binary

The `BN_HTTP_URL` defaults to `http://localhost:9009` but is overridable
via env var for non-standard setups.

---

## 4. Module Structure — `bin_datalog/se/`

No `__init__.py` (intentional — avoids pytest pulling in `bin_datalog/agent.py`
and its heavy `litellm` dependency chain). Each module adds `se/` to
`sys.path` at import time.

| File | Lines | Purpose |
|------|-------|---------|
| `se_backend.py` | 598 | ABC (`SEBackend`) + `AngrBackend` implementation + result dataclasses |
| `se_stubs.py` | 299 | `HeapTracker` + angr `SimProcedure` factories for malloc/calloc/free/realloc |
| `se_il_bridge.py` | 147 | Maps Datalog variable references → angr register/stack locations (pure Python, no BN) |
| `se_mcp_bridge.py` | 427 | FastMCP server exposing 8 tools — the entry point launched by ADK |
| `tests/test_se_tools.py` | 240 | 23 unit tests (all pass) |
| `tests/conftest.py` | 9 | Adds `se/` to `sys.path` for test imports |
| `pytest.ini` | — | Anchors pytest rootdir to `se/` to avoid import chain |

---

## 5. Key Design Decisions Per Module

### se_backend.py — Why an ABC?
- Future-proofing: if SENinja becomes viable later (BN upgrades Python),
  we can add `SeninjaBackend` without changing the MCP layer.
- The ABC defines 5 operations: `explore`, `check_overflow_feasibility`,
  `check_uaf_feasibility`, `get_path_constraints`, `solve_for_input`.
- Result types are plain dataclasses (`ExploreResult`, `FeasibilityResult`,
  `ConstraintsResult`) — no angr-specific objects cross the boundary.

### se_backend.py — AngrBackend internals
- **Project caching**: `_get_project(binary_path)` caches `angr.Project`
  per path. `auto_load_libs=False` by default (faster, avoids pulling in
  system libc — we hook what we need via SimProcedures).
- **Exploration loop**: Manual `SimulationManager.step()` loop (not
  `simgr.explore()`) with step budget + wall-clock timeout + active state
  cap (64). This prevents state explosion from killing the process.
- **Function resolution**: Looks up function by name via `proj.loader.find_symbol()`,
  creates `call_state` at the function's entry address.
- **Symbolic arguments**: Caller specifies `{arg_idx: byte_size}` pairs.
  The backend creates `claripy.BVS` bitvectors and places them in the
  correct registers per calling convention.
- **Constraint parser**: `_parse_constraint("rdi > 0x100", state)` uses
  regex to parse register constraints, resolves to Claripy expressions.

### se_stubs.py — Why custom SimProcedures?
- angr has built-in malloc/free, but they don't track allocation metadata
  for vulnerability detection.
- `HeapTracker` is pure Python — records every alloc/free with address,
  size, call site. Detects double-free and UAF at the tracker level.
- We only hook 4 functions (malloc, calloc, free, realloc). angr's
  built-in SimProcedures for memcpy, strlen, strcmp, etc. are left as-is
  — they work correctly for SE and don't need tracking.
- Each hook is a factory function (`_make_tracked_malloc(tracker)`) that
  returns a SimProcedure *class* (not instance) — angr requires classes.
- Double-free violations are stored in `state.globals["se_violations"]`
  so they survive across simulation steps.

### se_il_bridge.py — Why pure Python?
- The original SENinja version imported `binaryninja` to resolve MLIL
  variables. angr doesn't use BN's IL at all.
- This module now uses hardcoded calling convention tables (SysV AMD64:
  rdi, rsi, rdx, rcx, r8, r9) to map argument indices → registers.
- For stack variables, it translates BN's RBP-relative offsets to angr
  memory expressions (`state.memory.load(state.regs.rbp - 0x40, 8)`).
- Also has `arg_index_to_register_angr(proj, idx)` that queries angr's
  own `proj.factory.cc().ARG_REGS` for the active binary's detected CC.
- `map_datalog_var(var_info)` is the main entry point — takes a dict
  with `type`, `index`/`offset`/`reg` keys from BN MCP metadata.

### se_mcp_bridge.py — Tool design philosophy
- **8 MCP tools** exposed: `se_explore`, `se_check_overflow`, `se_check_uaf`,
  `se_get_constraints`, `se_solve_input`, `se_map_var`, `se_get_heap_state`,
  `se_unload`.
- All hex addresses are passed as strings (`"0x401234"`) and parsed
  server-side — avoids JSON integer precision issues.
- Comma/semicolon-separated lists for multi-value params (avoid_addrs,
  extra_constraints) — keeps the MCP tool signatures flat and LLM-friendly.
- `_serialize()` converts dataclass results to JSON-safe dicts, turning
  `bytes` → hex strings.
- Lazy initialization: angr project isn't loaded until the first tool call.

---

## 6. Testing Strategy

Tests are designed to run **without angr, BN, or any external process**.
They verify:
- Result dataclass defaults and structure
- HeapTracker alloc/free/double-free/UAF/bounds-check logic (pure Python)
- Hook registry structure (correct keys, callable values)
- Constraint parser regex matching
- IL bridge register/stack/argument mapping

To run: `cd bin_datalog/se && <ADK_VENV>/bin/python -m pytest tests/ -v`

ADK venv: `/home/sanjay/san-home/research/tii/tii24/phoenix/google-adk/.venv/`

**23/23 tests pass** as of 17 March 2026.

---

## 7. What Remains — Integration into agent.py

The SE layer is complete and tested but **not wired into `agent.py` yet**
(user is still debugging existing system). When ready:

### Step 1: Add SE MCPToolset to agent.py
```python
SE_PYTHON_PATH = "/home/sanjay/san-home/research/tii/tii24/phoenix/google-adk/.venv/bin/python"
SE_BRIDGE_PATH = "<repo>/bin_datalog/se/se_mcp_bridge.py"

def create_se_toolset():
    return MCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command=SE_PYTHON_PATH,
                args=[SE_BRIDGE_PATH],
            )
        )
    )
```
Add `create_se_toolset()` to the agent's `tools=[]` list.

### Step 2: Update agent prompts
Add SE tool descriptions to the agent's system prompt so it knows
when to call `se_explore`, `se_check_overflow`, etc.  Typical flow:
1. Datalog query identifies a suspicious pattern (e.g., unchecked memcpy)
2. BN MCP decompiles the function, agent identifies sink address
3. Agent calls `se_check_overflow(func, sink_addr, buffer_size)` to
   confirm feasibility
4. If SAT, agent calls `se_get_constraints()` for the triggering path

### Step 3: Test end-to-end with a known vulnerable binary
Use a simple test binary with a known buffer overflow to verify the
full pipeline: Datalog facts → LLM triage → SE confirmation.

### Optional: Prompt-guided SE
The agent could learn to combine BN xref info with SE tools:
- Use `get_xrefs_to` to find callers of dangerous functions
- Use `se_explore` to check if those call sites are reachable
- Use `se_solve_input` to generate PoC inputs

---

## 8. Environment Reference

| Component | Path / Version |
|-----------|----------------|
| angr | 9.2.205 (in ADK venv) |
| ADK venv | `/home/sanjay/san-home/research/tii/tii24/phoenix/google-adk/.venv/` |
| BN | 5.2.8, system Python 3.10.12 |
| BN HTTP server | `http://localhost:9009` |
| BN MCP bridge | `/media/sanjay/.../phoenix/binary_ninja_mcp/bridge/binja_mcp_bridge.py` |
| SE code | `/media/sanjay/.../repos/dev-claude/bin_datalog/se/` |
| Original plan | `bin_datalog/SENinja_integration_plan_v1.md` (outdated — was for SENinja) |
