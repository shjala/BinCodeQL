# BinCodeQL

Datalog-powered query engine for compiled binaries. An LLM agent composes [Souffle](https://souffle-lang.github.io/) Datalog queries at runtime using facts extracted from [Binary Ninja](https://binary.ninja/) via MCP or headless API.

## Motivation

Source-level tools like CodeQL and Joern are powerful — but most real-world targets ship as stripped binaries with no source. BinCodeQL bridges that gap: it lifts Binary Ninja's MLIL-SSA intermediate representation into Datalog facts, then runs Souffle queries for taint analysis, pointer analysis, and vulnerability detection — all orchestrated by an LLM agent that can reason about results and compose custom queries on the fly.

## How It Works

```
User Query → LLM Agent (Google ADK)
  ├── Binary Ninja MCP   → interactive exploration + incremental extraction
  ├── Headless BN script  → batch fact extraction (bn_extract_facts.py)
  ├── mlil_parser.py      → parse MLIL-SSA text into typed fact tuples
  ├── fact_writer.py      → write Souffle-compatible .facts files
  ├── souffle              → execute Datalog rules → .csv results
  └── Agent interprets results → answer to user
```

Three extraction modes:
- **Database (.bndb) — fastest:** If you have a pre-analyzed `.bndb` file (from BN GUI), pass it directly. BN loads pre-computed results instantly — milliseconds vs minutes. Auto-detected if `<binary>.bndb` sibling exists.
- **Batch (recommended):** `tool_extract_facts_batch` runs a headless BN subprocess that walks MLIL-SSA objects directly — zero unparsed lines, auto-resolved calls, StackVar extraction. Requires `BN_PYTHON` or `BN_PYTHON_PATH` env var.
- **Interactive (MCP):** `tool_extract_facts` uses BN MCP `get_il()` + regex parser for incremental exploration.

## Fact Schema

Facts are extracted from MLIL-SSA (Medium-Level IL with Static Single Assignment) — a structured, register-free representation that makes def-use chains explicit.

| Relation | Columns | Description |
|----------|---------|-------------|
| `Def` | func, var, ver, addr | SSA variable definition |
| `Use` | func, var, ver, addr | SSA variable use |
| `Call` | caller, callee, addr | Function call |
| `ActualArg` | call_addr, arg_idx, param, var, ver | Argument passed at call site |
| `FormalParam` | func, var, idx | Function parameter (positional) |
| `ReturnVal` | func, var, ver | Return value variable |
| `PhiSource` | func, var, def_ver, src_var, src_ver | Phi node source |
| `FieldRead` | func, addr, base, field | Struct field read |
| `FieldWrite` | func, addr, base, field, mem_in, mem_out | Struct field write |
| `MemRead` | func, addr, base, offset, size | Memory read |
| `MemWrite` | func, addr, target, mem_in, mem_out | Memory write |
| `AddressOf` | func, var, ver, target | Address-of expression |
| `CFGEdge` | func, from_addr, to_addr | Control flow edge |
| `Guard` | func, addr, var, ver, op, bound | Branch condition comparison |
| `ArithOp` | func, addr, dst, dst_ver, op, src, src_ver, operand | Arithmetic operation (add, sub, mul, lsl, lsr) |
| `StackVar` | func, var, offset, size | Stack variable layout (from headless extraction) |
| `EntryTaint` | func, param_idx | User-specified attack surface (library API params) |

## Pre-built Rule Modules

| File | Purpose |
|------|---------|
| `rules/interproc.dl` | Interprocedural taint analysis with source-to-sink detection |
| `rules/alias.dl` | Andersen-style points-to analysis + alias-enhanced taint propagation |
| `rules/patterns.dl` | Structural vulnerability heuristics (unsafe strcpy/strcat, gets, sprintf into stack buffers) |
| `rules/taint.dl` | Intraprocedural taint tracking |
| `rules/summary.dl` | Function summary computation (param → return dependencies) |
| `rules/core.dl` | Basic def-use pairs, call reachability, field access |
| `rules/signatures.dl` | Library function taint transfer models (memcpy, read, recv, etc.) |
| `rules/boil.dl` | BOIL (Buffer Overflow Inducing Loop) detection — finds unbounded byte-copy loops |
| `rules/boil_taint.dl` | BOIL + taint integration — finds BOILs reachable from attacker-controlled input |
| `rules/schema.dl` | Reusable type and relation declarations |

## Agent Tools

The LLM agent has these tools available:

| Tool | Description |
|------|-------------|
| `tool_clean_workspace` | Remove stale .facts and .csv files before a fresh analysis |
| `tool_extract_facts_batch` | **Batch extraction** — headless BN subprocess, all facts in one call |
| `tool_extract_facts` | Parse MLIL-SSA text into .facts files (interactive MCP workflow) |
| `tool_resolve_calls` | Replace hex-address callees with resolved function names |
| `tool_run_souffle` | Execute a rule file or custom Datalog query |
| `tool_list_datalog_files` | List available rules and facts with schema info |
| `tool_read_file` | Read any rule, fact, or output file |
| `tool_generate_signatures` | Generate TaintTransfer.facts from signature rules |
| `tool_generate_annotations` | Generate DangerousSink.facts and TaintSourceFunc.facts |
| `tool_set_entry_taint` | Mark exported API params as attacker-controlled (library analysis) |
| `tool_run_taint_pipeline` | Two-pass pipeline: alias analysis → interprocedural taint |
| Binary Ninja MCP | Full suite of BN tools (decompile, get IL, xrefs, imports, etc.) |

## Quick Start

### Prerequisites

- Python 3.10+
- [Souffle](https://souffle-lang.github.io/install) Datalog compiler
- [Binary Ninja](https://binary.ninja/) with the [MCP bridge](https://github.com/binary-ninja-mcp) running
- [Google ADK](https://github.com/google/adk-python) (`pip install google-adk`)
--[BN MCP](https://github.com/fosdickio/binary_ninja_mcp) Binary Ninja MCP

### Configuration

All secrets and machine-specific paths live in a `.env` file (gitignored). Create one from the template:

```bash
cp .env.example .env
```

Then edit `.env` with your values:

| Variable | Required | Description |
|----------|----------|-------------|
| `MODEL_NAME` | Yes | LiteLLM model ID (e.g., `anthropic/claude-sonnet-4-6`, `openai/gpt-5`) |
| `ANTHROPIC_API_KEY` | If using Anthropic | Anthropic API key |
| `OPENAI_API_KEY` | If using OpenAI | OpenAI API key |
| `MCP_PYTHON_PATH` | Yes | Python interpreter inside the MCP bridge venv |
| `MCP_BRIDGE_PATH` | Yes | Path to the MCP bridge script (`binja_mcp_bridge.py`) |
| `BN_PYTHON_PATH` | For batch extraction | Path to Binary Ninja's Python package dir (e.g., `/path/to/binaryninja/python`) |
| `BN_PYTHON` | Alternative to above | Full path to a Python interpreter with `binaryninja` installed |
| `BNDB_PATH` | Optional | Pre-analyzed `.bndb` database path (default for `tool_extract_facts_batch`) |

### Running

```bash
# Interactive web UI
adk web .

# CLI mode
adk run .
```

### Example Session

```
You: Analyze the png_handle_iCCP function for taint vulnerabilities

Agent: [extracts MLIL-SSA for png_handle_iCCP and related functions]
       [resolves indirect call targets via function_at]
       [generates signatures and annotations]
       [runs interproc.dl + alias.dl + patterns.dl]

       Found TaintedSink: png_handle_iCCP calls memcpy at 0x41b3a0
       with tainted arg0 (buffer_overflow_dst).
       Origin: external_via_png_crc_read

       UnsafeStringCopy: copy_to_buffer calls strcpy at 0x401234
       into stack buffer var_28 (24 bytes).
       ...
```

## Architecture

```
bin_datalog/
├── agent.py                # ADK agent definition + tool functions
├── mlil_parser.py          # MLIL-SSA text → Fact tuples (regex-based)
├── fact_writer.py          # Fact tuples → .facts TSV files
├── bn_utils.py             # BN Python path resolution + subprocess helpers
├── resolve_calls.py        # Hex address → function name resolution
├── scripts/
│   └── bn_extract_facts.py # Headless BN fact extraction (walks MLIL-SSA objects)
├── rules/
│   ├── schema.dl           # Shared type + relation declarations
│   ├── interproc.dl        # Interprocedural taint analysis
│   ├── alias.dl            # Andersen-style points-to + alias-enhanced taint
│   ├── patterns.dl         # Structural vulnerability patterns
│   ├── taint.dl            # Intraprocedural taint tracking
│   ├── summary.dl          # Function summaries
│   ├── boil.dl             # BOIL detection (unbounded byte-copy loops)
│   ├── boil_taint.dl       # BOIL + taint integration
│   ├── core.dl             # Basic queries
│   └── signatures.dl       # Library function models
├── facts/                  # Extracted .facts files (gitignored)
├── output/                 # Souffle output CSVs (gitignored)
└── samples/                # Example MLIL-SSA text files
```

## Analysis Modules

### Taint Analysis (`interproc.dl`)
Interprocedural taint tracking from external sources (read, recv, fgets, etc.) to dangerous sinks (memcpy, strcpy, system, free, etc.). Uses function summaries, library signatures, and phi-node propagation.

### Alias Analysis (`alias.dl`)
Andersen-style flow-insensitive points-to analysis. Under-approximate: may miss aliases (false negatives) but never invents them (no false positives). Runs alongside taint analysis via `AliasTaintedVar` — catches taint propagation through aliased pointers that basic taint analysis misses.

### Structural Patterns (`patterns.dl`)
Heuristic vulnerability detection without taint analysis. Finds `strcpy`/`strcat` into stack buffers, `gets()` usage, `sprintf` into fixed-size buffers. Requires `StackVar` facts (from headless extraction).

### BOIL Detection (`boil.dl`)
Detects Buffer Overflow Inducing Loops — byte-copy loops that terminate on source data (e.g., null byte) rather than destination buffer size. Uses phi self-references to find loop-carried pointer variables, ArithOp to confirm pointer increments, and Guard analysis to suppress false positives from size-bounded loops. Reports candidates at high/medium/low confidence tiers.

### Library Attack Surface (`EntryTaint` + `boil_taint.dl`)

For library analysis where there are no calls to `read()`/`recv()` — the library's exported API IS the attack surface. Use `tool_set_entry_taint` to mark which params are attacker-controlled:

```python
# Mark parse_image's second argument as attacker-controlled
tool_set_entry_taint([{"func": "parse_image", "param_idx": 1}])
```

Then `interproc.dl` seeds `TaintedVar` from those params (origin: `entry:parse_image:arg1`), and `boil_taint.dl` joins taint results with BOIL candidates to find:
- **TaintedBOIL** — BOIL candidates where the source/destination pointer is tainted
- **TaintedBOILEntry** — traces back to the specific entry-point param that reaches the BOIL

## Query Classes

BinCodeQL is designed to answer these categories of vulnerability questions:

1. **Untrusted input → memory write path** — Does external data reach a buffer write?
2. **Argument flow → dangerous API** — Does a function argument reach memcpy/strcpy/system?
3. **Missing free on feasible paths** — Is an allocation freed on all paths?
4. **Risky return value → control branch** — Does an unchecked return value control a branch?
5. **OOB index → memory access** — Can an attacker-controlled index reach an array access?

## License

Research project — not yet licensed for redistribution.
