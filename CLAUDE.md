# CLAUDE.md

BinCodeQL — Datalog-powered query engine for compiled binaries. LLM agent composes Souffle Datalog queries at runtime using facts extracted from Binary Ninja via MCP or headless BN subprocess. Built with Google ADK.

## CLAUDE.md Maintenance Rules
- Keep this file under 150 lines. It loads into every session's context window.
- For detailed content, create a file under `.claude/docs/` and add a reference in "Reference Docs" below.
- Only universal instructions belong here: how to run, critical rules, key files, architecture overview.

## Status

Implemented: fact extraction (MCP + headless), taint analysis, alias analysis, structural patterns, buffer-write semantics (Phase 3), two-pass pipeline, 1-CFA context-sensitive taint, sanitizer/kill modeling, guard detection, interprocedural field sensitivity (Phase 4), integer/type confusion detection, CodeQL-style memory safety patterns (Phase 5), Bn* rule set ported from NeuroLog (unbounded-counter OOB, alloc/copy mismatch, unguarded cast/sink, narrow-arith overflow, loop-carried-var FP filter), VarSign ground-truth signedness from DWARF, global-pointer indirect-call resolution. Active development.

Run the Bn* pipeline end-to-end via `tool_run_bn_extra_rules` after the taint pipeline (`tool_run_taint_pipeline`). The agent prompt in `agent.py` documents the full 10-step workflow and the entry-taint heuristic.

## Architecture

```
User Query → LLM Agent (ADK)
  ├── Binary Ninja MCP → interactive exploration + incremental extraction
  ├── Headless BN subprocess (bn_extract_facts.py) → batch fact extraction
  ├── Generate Souffle .dl file (facts + rules)
  ├── Run `souffle` via subprocess → get results
  └── Interpret results → answer to user
```

## Key Files

| File | Purpose |
|------|---------|
| `agent.py` | ADK agent with tools: extract_facts, extract_facts_batch, run_souffle, etc. |
| `mlil_parser.py` | Regex-based MLIL-SSA text → Fact tuples (for MCP workflow) |
| `fact_writer.py` | Serializes Fact objects to Souffle-compatible .facts TSV files |
| `bn_utils.py` | BN Python path resolution, subprocess runner, batch extraction wrapper |
| `resolve_calls.py` | Resolves hex-address callees in Call.facts to function names |
| `scripts/bn_extract_facts.py` | Headless BN script — walks MLIL-SSA objects, emits .facts directly |

### Rule Files

| Rule File | Purpose |
|-----------|---------|
| `rules/schema.dl` | Reusable type + relation declarations (`.decl` + `.input`) |
| `rules/interproc.dl` | 1-CFA context-sensitive interprocedural taint with sanitizer kill, guard detection, interprocedural field taint |
| `rules/taint.dl` | Intraprocedural taint tracking |
| `rules/alias.dl` | Andersen-style points-to analysis + alias-enhanced taint |
| `rules/boil.dl` | BOIL (Buffer Overflow Inducing Loop) candidate detection |
| `rules/boil_taint.dl` | BOIL + taint integration: finds BOILs reachable from attacker input |
| `rules/patterns.dl` | Structural vulnerability heuristics (unsafe strcpy, gets, sprintf) |
| `rules/patterns_mem.dl` | Intraprocedural memory safety: UAF, double-free, unchecked malloc, format string |
| `rules/patterns_mem_interproc.dl` | Interprocedural memory safety: global-mediated + parameter-based UAF/double-free |
| `rules/inttype.dl` | Integer/type confusion: signed→unsigned, truncation, widening-after-overflow |
| `rules/inttype_taint.dl` | Taint-integrated integer vulnerability detection |
| `rules/summary.dl` | Function summary computation (param → return dependencies) |
| `rules/core.dl` | Basic def-use, reachability, field access queries |
| `rules/signatures.dl` | Library function taint transfer models + BufferWriteSource + TaintKill |
| `rules/bn_flow.dl` | Shared intraprocedural Flow transitive closure (consumed by other Bn* rules) |
| `rules/bn_signed_infer.dl` | Signedness inference (VarSign ground truth + sx/zx/Guard heuristic) |
| `rules/bn_counter_oob.dl` | Unbounded counter / counter-as-index detection (gated on loop-carried phi self-ref) |
| `rules/bn_alloc_copy.dl` | Alloc/copy size-mismatch detection (new bug class) |
| `rules/bn_unguarded_sink.dl` | `TaintedSink \ GuardedSink` — structural consolidation |
| `rules/bn_loop_bound.dl` | Tainted loop-bound detection (proper loop-continuation op set) |
| `rules/bn_unguarded_cast.dl` | Narrowing/sign-extend cast without CFG-reaching guard on source |
| `rules/bn_arith_overflow.dl` | Narrow signed arith overflow (≤4B add/mul/lsl) + sink coupling |
| `rules/bn_width_mismatch.dl` | Wide value stored into narrower slot (32-bit counter → 16-bit table element) |
| `rules/bn_sentinel_init.dl` | memset sentinel (-1/0xFF/0xFFFF) meets unbounded counter (H.264 slice_table class) |
| `rules/bn_findings.dl` | Unified BnFinding aggregation (primary reporting relation) |

## Fact Schema

| Relation | Columns |
|----------|---------|
| Def | func, var, ver, addr |
| Use | func, var, ver, addr |
| Call | caller, callee, addr |
| ActualArg | call_addr, arg_idx, param, var, ver |
| ReturnVal | func, var, ver |
| PhiSource | func, var, def_ver, src_var, src_ver |
| FormalParam | func, var, idx |
| MemRead | func, addr, base, offset, size |
| MemWrite | func, addr, target, mem_in, mem_out |
| FieldRead | func, addr, base, field |
| FieldWrite | func, addr, base, field, mem_in, mem_out |
| AddressOf | func, var, ver, target |
| CallAddrArg | call_addr, arg_idx, target (direct &var in call args) |
| CFGEdge | func, from_addr, to_addr |
| Jump | func, addr, expr |
| StackVar | func, var, offset, size |
| Guard | func, addr, var, ver, op, bound, bound_type |
| ArithOp | func, addr, dst, dst_ver, op, src, src_ver, operand |
| Cast | func, addr, dst, dst_ver, src, src_ver, kind, src_width, dst_width |
| VarWidth | func, var, ver, width |
| CallArgConst | call_addr, arg_idx, value (literal constant args, e.g. -1 in memset) |
| MemWriteSize | func, addr, size (store width in bytes, for truncation detection) |
| AllocSite | call_addr, func, size_var, size_const, elem_width |
| EntryTaint | func, param_idx (user-specified attack surface) |
| BufferWriteSource | func, arg_idx |
| TaintKill | func, arg_idx |
| PointsTo | func, var, ver, obj (derived from alias.dl) |
| TaintedVar | func, var, ver, origin, ctx (output, 1-CFA) |
| TaintedSink | caller, callee, call_addr, arg_idx, var, risk, origin |
| SanitizedVar | func, var, ver, kill_func, kill_addr |
| GuardedSink | caller, callee, call_addr, guard_var, guard_op, guard_bound |
| TaintedHeapObject | obj, origin (output from interproc.dl) |
| BOILCandidate | func, src_ptr, dst_ptr, read_addr, write_addr, confidence |
| TaintedBOIL | func, src_ptr, dst_ptr, read_addr, write_addr, confidence, origin, role |
| TaintedBOILEntry | boil_func, src_ptr, dst_ptr, confidence, role, entry_func, param_idx |
| SignedToUnsignedConfusion | func, cast_addr, dst, dst_ver, callee, call_addr, arg_idx |
| IntegerTruncation | func, cast_addr, dst, dst_ver, src_width, dst_width, callee, call_addr, arg_idx |
| WideningAfterOverflow | func, arith_addr, op, arith_width, cast_addr, callee, call_addr |
| SignExtNegativeToSize | func, arith_addr, cast_addr, callee, call_addr |
| TaintedIntVuln | func, vuln_type, cast_addr, callee, sink_addr, origin |
| CalleeGuardsParam | func, param_idx, guard_op, guard_bound |
| CalleeGuardedIntIssue | func, cast_addr, callee, call_addr, param_idx, guard_op, guard_bound |
| CalleeGuardedTaintedIntVuln | func, vuln_type, cast_addr, callee, sink_addr, origin, guard_op, guard_bound |
| UseAfterFree | func, free_addr, use_addr, var |
| DoubleFree | func, free1_addr, free2_addr, var |
| UncheckedMalloc | func, call_addr, var |
| FormatStringVuln | func, call_addr, callee, fmt_var |
| FreesParam | func, param_idx |
| InterDoubleFree | caller, callee1, call1, callee2, call2, var |
| InterUseAfterFree | caller, callee, free_call, use_addr, var |
| GlobalDoubleFree | func1, free1, func2, free2, global_addr |
| GlobalUseAfterFree | free_func, free_addr, use_func, use_addr, global_addr, use_var |
| UsesAfterFreeParam | func, param_idx, free_addr, use_addr |
| ReturnsFreedPtr | func, param_idx |
| ReturnedDanglingPtr | caller, callee, call_addr, dangling_var, use_addr |

## Extraction Modes

### Batch (recommended): `tool_extract_facts_batch`
Headless BN subprocess. One call extracts all facts for multiple functions. Emits StackVar + Guard. Auto-resolves callees. Requires `BN_PYTHON` or `BN_PYTHON_PATH` env var.

### Database (.bndb): fastest
Pass a .bndb path to `tool_extract_facts_batch`. BN loads pre-analyzed database — no re-analysis needed. Includes user-refined types and annotations. Auto-detected if `<binary>.bndb` sibling exists.

### Interactive (MCP): `tool_extract_facts`
Uses BN MCP `get_il()` + regex parser. Good for incremental exploration. No StackVar (text parser doesn't have stack layout info). Emits Guard from IF conditions.

## Critical MCP Tools

| Tool | Purpose |
|------|---------|
| `get_il(name, "mlil", ssa=True)` | MLIL-SSA with explicit def-use chains |
| `decompile_function` | HLIL-like C pseudocode |
| `list_methods` | Function enumeration |
| `search_functions_by_name` | Find specific functions |
| `get_xrefs_to` | Cross-reference analysis |
| `list_imports`, `list_exports` | Symbol information |

## Configuration

All configurable parameters live in `.env` (gitignored). Copy `.env.example` to get started:
```bash
cp .env.example .env
# Edit .env with your API keys and Binary Ninja paths
```

Key variables: `MODEL_NAME`, `MCP_PYTHON_PATH`, `MCP_BRIDGE_PATH`, `BN_PYTHON_PATH`, `BNDB_PATH`, API keys.

## Dependencies

- **Google ADK** — Agent framework
- **Binary Ninja** — Via MCP bridge + headless Python API
- **Souffle** — Datalog compiler, invoked via subprocess
- **LiteLLM** — Model abstraction layer

## Related Sibling Projects

- `../vuln_analysis_6step/agent.py` — MCP toolset isolation, async orchestration
- `../fuzz_harness_adv/agent.py` — Subprocess execution, timeout/error-handling

## Available Skills

- `/google-adk` — ADK documentation and examples
- `/datalog` — Souffle Datalog for binary analysis

## Reference Docs

See `.claude/skills/google-adk/SKILL.md` for full paths to local ADK docs, examples, and SDK source.
