# File: agent.py
# BinCodeQL — Datalog-powered binary analysis co-pilot
# Interactive agent with Binary Ninja MCP + Souffle Datalog tools

import os
import sys
import asyncio
import subprocess
import tempfile
import json
from pathlib import Path
from typing import Optional

# Ensure sibling-module imports work whether this file is loaded as a
# package submodule (ADK's `from . import agent`) or run as a script
# (`python agent.py`). Without this, `import pipeline` / `import
# agent_factory` fail under ADK's package loader because bin_datalog/
# is not automatically on sys.path.
_PKG_DIR = Path(__file__).parent.resolve()
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

from dotenv import load_dotenv  # noqa: E402

from google.adk.agents import LlmAgent  # noqa: E402
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioConnectionParams, StdioServerParameters  # noqa: E402
from google.adk.tools import FunctionTool  # noqa: E402
from google.adk.models.lite_llm import LiteLlm  # noqa: E402

import pipeline  # noqa: E402
from agent_factory import create_model  # noqa: E402

load_dotenv(_PKG_DIR / ".env", override=True)

# =============================================================================
# Configuration
# =============================================================================
MCP_PYTHON_PATH = os.getenv("MCP_PYTHON_PATH", "python3")
MCP_BRIDGE_PATH = os.getenv("MCP_BRIDGE_PATH", "")
BNDB_PATH = os.getenv("BNDB_PATH", "")

PROJECT_DIR = Path(__file__).parent
RULES_DIR = PROJECT_DIR / "rules"
FACTS_DIR = PROJECT_DIR / "facts"
OUTPUT_DIR = PROJECT_DIR / "output"

# Souffle execution knobs. `-j` adds multi-core parallelism to the Datalog
# evaluator (helps most on transitive-closure-heavy rules like bn_flow.dl
# and interproc.dl). `-c` compiles to C++ and then executes — much faster
# for large fact sets but adds ~1-2min compile overhead on the first run
# per rule file. Cached compilation output lives under TMPDIR.
SOUFFLE_JOBS = os.getenv("SOUFFLE_JOBS", "auto")
SOUFFLE_COMPILE = os.getenv("SOUFFLE_COMPILE", "0") not in ("0", "", "false", "False")


def _souffle_cmd(rule_path: str, facts_dir: str, output_dir: str) -> list:
    """Build the souffle subprocess argv with current knobs applied.

    Thin wrapper over `pipeline.souffle_cmd` that injects the project's
    env-var-driven knobs (SOUFFLE_JOBS / SOUFFLE_COMPILE).
    """
    return pipeline.souffle_cmd(
        rule_path, facts_dir, output_dir,
        jobs=SOUFFLE_JOBS, compile_mode=SOUFFLE_COMPILE,
    )


# Model configuration + factory live in agent_factory.py so the
# triage agent (scan mode) and any future agent entry-point share the
# same prompt-caching / retry / extended-thinking behavior.
# `create_model()` is imported above.


def create_mcp_toolset():
    if not MCP_BRIDGE_PATH:
        raise ValueError(
            "MCP_BRIDGE_PATH not set. Add it to .env (see .env.example)."
        )
    return MCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command=MCP_PYTHON_PATH,
                args=[MCP_BRIDGE_PATH],
            )
        )
    )


# =============================================================================
# Tool: Clean workspace (remove stale facts and output files)
# =============================================================================
def tool_clean_workspace(
    clean_facts: bool = True,
    clean_output: bool = True,
) -> dict:
    """Remove stale .facts and .csv files to start a fresh analysis.

    Call this before beginning a new analysis session to ensure no stale
    data from previous runs contaminates results.

    Args:
        clean_facts: If True, remove all .facts files from facts/ dir.
        clean_output: If True, remove all .csv files from output/ dir.

    Returns:
        Dict with counts of removed files.
    """
    removed = {"facts": 0, "output": 0}
    if clean_facts:
        for f in FACTS_DIR.glob("*.facts"):
            f.unlink()
            removed["facts"] += 1
    if clean_output:
        for f in OUTPUT_DIR.glob("*.csv"):
            f.unlink()
            removed["output"] += 1
    return removed


# =============================================================================
# Tool: Extract MLIL-SSA facts from a function
# =============================================================================
def tool_extract_facts(
    function_name: str,
    mlil_ssa_text: str,
    append: bool = True,
    facts_dir: str = "",
) -> dict:
    """Extract Datalog facts from MLIL-SSA text for a function.

    Call this AFTER using the BN MCP tool `get_il(function_name, "mlil", ssa=True)`
    to obtain the MLIL-SSA text. This tool parses that text into Souffle-compatible
    fact files (Def, Use, Call, ActualArg, PhiSource, FormalParam, etc.).

    By default, successive calls ACCUMULATE facts (append=True). Call
    `tool_clean_workspace` first to start fresh, then call this for each
    function to build up the fact database incrementally.

    Args:
        function_name: Name of the function being parsed.
        mlil_ssa_text: Raw MLIL-SSA text from Binary Ninja.
        append: If True (default), merge new facts with existing .facts files
                (deduplicated). If False, overwrite files.
        facts_dir: Directory to write .facts files. Defaults to project facts/ dir.

    Returns:
        Dict with parse stats: fact counts per relation, any unparsed lines,
        and `unresolved_callees` — list of hex-address callees that need
        resolution via `function_at` + `tool_resolve_calls`.
    """
    import sys
    sys.path.insert(0, str(PROJECT_DIR))
    from mlil_parser import parse_mlil_ssa, FactKind
    from fact_writer import write_facts

    target_dir = Path(facts_dir) if facts_dir else FACTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    facts = parse_mlil_ssa(function_name, mlil_ssa_text)

    # Check for unparsed lines by re-running and capturing stderr
    import io
    old_stdout = sys.stdout
    sys.stdout = capture = io.StringIO()
    _ = parse_mlil_ssa(function_name, mlil_ssa_text)
    sys.stdout = old_stdout
    unparsed = [l for l in capture.getvalue().split('\n') if 'UNPARSED' in l]

    stats = write_facts(facts, target_dir, append=append)

    # Scan for unresolved hex-address callees
    unresolved = sorted(set(
        f.fields["callee"]
        for f in facts
        if f.kind == FactKind.CALL and f.fields["callee"].startswith("0x")
    ))

    return {
        "function": function_name,
        "total_facts": len(facts),
        "relations": {k: v for k, v in sorted(stats.items())},
        "unparsed_lines": len(unparsed),
        "unparsed_samples": unparsed[:5] if unparsed else [],
        "facts_dir": str(target_dir),
        "unresolved_callees": unresolved,
    }


# =============================================================================
# Tool: Resolve hex call targets to function names
# =============================================================================
def tool_resolve_calls(
    address_map: dict,
    facts_dir: str = "",
) -> dict:
    """Resolve hex-address callees in Call.facts to function names.

    After extracting facts, Call.facts may contain hex addresses (e.g., "0x436600")
    instead of function names. Use the BN MCP `function_at` tool to discover what
    function lives at each address, then call this tool with the mapping.

    Args:
        address_map: Dict mapping hex addresses to function names,
                     e.g. {"0x436600": "memcpy", "0x41a2f0": "png_crc_read"}.
        facts_dir: Directory containing .facts files. Defaults to project facts/ dir.

    Returns:
        Dict with resolution stats.
    """
    import sys
    sys.path.insert(0, str(PROJECT_DIR))
    from resolve_calls import resolve_call_targets

    target_dir = str(Path(facts_dir) if facts_dir else FACTS_DIR)

    import io
    old_stdout = sys.stdout
    sys.stdout = capture = io.StringIO()
    resolve_call_targets(target_dir, address_map)
    sys.stdout = old_stdout

    return {"result": capture.getvalue().strip(), "facts_dir": target_dir}


# =============================================================================
# Tool: Run Souffle Datalog query
# =============================================================================
def tool_run_souffle(
    rule_file: str = "",
    custom_rules: str = "",
    facts_dir: str = "",
    output_dir: str = "",
    timeout_seconds: int = 30,
) -> dict:
    """Run a Souffle Datalog query against extracted facts.

    You can either:
    1. Run an existing rule file from the rules/ directory (e.g. "interproc.dl")
    2. Provide custom Datalog rules as a string (written to a temp file and run)

    The query reads .facts files from facts_dir and writes results to output_dir.

    Args:
        rule_file: Name of a rule file in rules/ dir (e.g., "interproc.dl", "taint.dl").
                   Ignored if custom_rules is provided.
        custom_rules: Custom Souffle Datalog program as a string. If provided,
                      this is written to a temp file and executed instead of rule_file.
        facts_dir: Directory containing .facts input files.
        output_dir: Directory for output CSV files.
        timeout_seconds: Max execution time (default 30s).

    Returns:
        Dict with stdout, stderr, return code, and list of output files with contents.
    """
    fdir = str(Path(facts_dir) if facts_dir else FACTS_DIR)
    odir = str(Path(output_dir) if output_dir else OUTPUT_DIR)
    Path(odir).mkdir(parents=True, exist_ok=True)

    # Clear stale output CSVs before running to avoid mixing old/new results
    for stale in Path(odir).glob("*.csv"):
        stale.unlink()

    # Determine the .dl file to run
    if custom_rules:
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.dl', delete=False,
                                          dir=str(PROJECT_DIR))
        tmp.write(custom_rules)
        tmp.close()
        dl_path = tmp.name
    elif rule_file:
        dl_path = str(RULES_DIR / rule_file)
        if not Path(dl_path).exists():
            return {"error": f"Rule file not found: {dl_path}"}
    else:
        return {"error": "Provide either rule_file or custom_rules"}

    try:
        result = subprocess.run(
            _souffle_cmd(dl_path, fdir, odir),
            capture_output=True, text=True, timeout=timeout_seconds,
        )

        # Collect output files
        outputs = {}
        for f in sorted(Path(odir).glob("*.csv")):
            content = f.read_text().strip()
            if content:
                lines = content.split('\n')
                outputs[f.name] = {
                    "rows": len(lines),
                    "preview": lines[:20],  # first 20 rows
                }

        return {
            "return_code": result.returncode,
            "stdout": result.stdout.strip() if result.stdout else "",
            "stderr": result.stderr.strip() if result.stderr else "",
            "output_files": outputs,
            "rule_file": dl_path,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Souffle timed out after {timeout_seconds}s"}
    finally:
        if custom_rules:
            Path(dl_path).unlink(missing_ok=True)


# =============================================================================
# Tool: List available rule files and fact files
# =============================================================================
def tool_list_datalog_files() -> dict:
    """List available Datalog rule files and fact files.

    Returns the rule files in rules/ and fact files in facts/ with their sizes
    and column schemas, so you know what's available to query.
    """
    import sys
    sys.path.insert(0, str(PROJECT_DIR))
    from fact_writer import SCHEMA_DOCS
    from mlil_parser import FactKind

    # Build filename→columns lookup from SCHEMA_DOCS
    from fact_writer import RELATION_SCHEMA
    file_columns = {}
    for kind, cols in SCHEMA_DOCS.items():
        schema = RELATION_SCHEMA.get(kind)
        if schema:
            file_columns[schema[0]] = cols

    rules = []
    for f in sorted(RULES_DIR.glob("*.dl")):
        rules.append({"name": f.name, "size_bytes": f.stat().st_size})

    facts = []
    for f in sorted(FACTS_DIR.glob("*.facts")):
        lines = f.read_text().strip().count('\n') + 1 if f.stat().st_size > 0 else 0
        entry = {"name": f.name, "rows": lines}
        if f.name in file_columns:
            entry["columns"] = file_columns[f.name]
        facts.append(entry)

    return {"rules": rules, "facts": facts}


# =============================================================================
# Tool: Read a rule or output file
# =============================================================================
def tool_read_file(file_path: str, max_bytes: int = 200_000) -> dict:
    """Read any text file on disk — rules, facts, CSV outputs, prior
    reports, decompilation scratchpads, READMEs, third-party advisory
    notes, etc.

    Use this whenever the user references prior work ("the report we
    wrote last week", "the LibXML2 advisory in docs/"), points at a
    GitLab/CVE writeup pasted into the repo, or otherwise asks you to
    build on something already on disk. Reading a prior report first
    avoids redoing the discovery+extraction phase from scratch — pull
    out the cited functions, addresses, and verdicts, then run only
    the additional facts/queries the follow-up question needs.

    Args:
        file_path: Project-relative path (e.g., "rules/interproc.dl",
            "output/TaintedSink.csv", "facts/Call.facts",
            "reports/<old_report>.md", "docs/foo.md") or an absolute
            path anywhere on disk.
        max_bytes: Truncation guard. Files larger than this are read
            up to the cap and `truncated: true` is set in the result;
            ask the user (or call again with a higher cap) if you
            need the rest. Default 200 KB — big enough for any single
            report or rule file, small enough to keep the context
            window healthy.
    """
    p = Path(file_path)
    if not p.is_absolute():
        p = PROJECT_DIR / p

    if not p.exists():
        return {"error": f"File not found: {p}"}

    size = p.stat().st_size
    truncated = size > max_bytes
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        content = fh.read(max_bytes)
    return {
        "path": str(p),
        "size_bytes": size,
        "bytes_read": len(content.encode("utf-8")),
        "truncated": truncated,
        "content": content,
    }


def tool_list_reports(
    name_filter: str = "",
    reports_dir: str = "",
    limit: int = 50,
) -> dict:
    """List prior analysis reports under `reports/` (newest first).

    Use this when the user mentions a prior analysis without giving
    the exact filename ("the FFmpeg sentinel report", "what did we
    say about libxml2 last month?"). Pick the most likely match by
    title/timestamp, then `tool_read_file` to load it.

    Args:
        name_filter: Optional substring filter on the filename
            (case-insensitive). E.g. "ffmpeg" or "sentinel".
        reports_dir: Optional override directory. Defaults to the
            repo's `reports/`.
        limit: Maximum number of entries to return (newest first).

    Returns:
        Dict with `reports`: list of {filename, path, size_bytes,
        mtime_iso} sorted newest first, plus `count` and `dir`.
    """
    from datetime import datetime, timezone
    target_dir = Path(reports_dir) if reports_dir else REPORTS_DIR
    if not target_dir.exists():
        return {"reports": [], "count": 0, "dir": str(target_dir),
                "note": "reports directory does not exist yet"}
    needle = name_filter.lower().strip()
    entries = []
    for p in target_dir.iterdir():
        if not p.is_file():
            continue
        if needle and needle not in p.name.lower():
            continue
        st = p.stat()
        entries.append({
            "filename": p.name,
            "path": str(p),
            "size_bytes": st.st_size,
            "mtime_iso": datetime.fromtimestamp(
                st.st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "_mtime": st.st_mtime,
        })
    entries.sort(key=lambda x: x["_mtime"], reverse=True)
    for e in entries:
        e.pop("_mtime", None)
    return {
        "reports": entries[:limit],
        "count": len(entries),
        "dir": str(target_dir),
        "filter": name_filter,
    }


# =============================================================================
# Tool: Generate TaintTransfer.facts from signatures
# =============================================================================
def tool_generate_signatures(
    extra_signatures: list[dict] = None,
) -> dict:
    """Generate TaintTransfer.facts from the signatures rule file.

    Runs rules/signatures.dl to produce TaintTransfer.csv, then copies it
    to facts/TaintTransfer.facts so interproc.dl can use it.

    Optionally add extra signatures (e.g., for newly discovered library functions).

    Args:
        extra_signatures: Optional list of dicts with keys:
            func (str), out_arg (str), in_arg (str).
            Example: [{"func": "png_crc_read", "out_arg": "arg1", "in_arg": "external"}]

    Returns:
        Dict with the number of TaintTransfer facts generated.
    """
    # If extra signatures provided, append to a temp copy of signatures.dl
    sig_file = RULES_DIR / "signatures.dl"
    dl_content = sig_file.read_text()

    if extra_signatures:
        # Insert before the .output line
        extra_lines = []
        for sig in extra_signatures:
            extra_lines.append(
                f'TaintTransfer("{sig["func"]}", "{sig["out_arg"]}", "{sig["in_arg"]}").'
            )
        dl_content = dl_content.replace(
            '.output TaintTransfer',
            '\n'.join(extra_lines) + '\n.output TaintTransfer'
        )

    # Write temp file and run
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.dl', delete=False)
    tmp.write(dl_content)
    tmp.close()

    try:
        result = subprocess.run(
            _souffle_cmd(tmp.name, str(FACTS_DIR), str(OUTPUT_DIR)),
            capture_output=True, text=True, timeout=15,
        )

        if result.returncode != 0:
            return {"error": result.stderr}

        # Copy output to facts dir
        result_info = {}
        src = OUTPUT_DIR / "TaintTransfer.csv"
        dst = FACTS_DIR / "TaintTransfer.facts"
        if src.exists():
            dst.write_text(src.read_text())
            content = src.read_text().strip()
            rows = content.count('\n') + 1 if content else 0
            result_info["taint_transfer_facts"] = rows
            result_info["taint_transfer_path"] = str(dst)
        else:
            return {"error": "TaintTransfer.csv not generated"}

        # Also copy BufferWriteSource if produced
        bws_src = OUTPUT_DIR / "BufferWriteSource.csv"
        bws_dst = FACTS_DIR / "BufferWriteSource.facts"
        if bws_src.exists():
            bws_dst.write_text(bws_src.read_text())
            content = bws_src.read_text().strip()
            bws_rows = content.count('\n') + 1 if content else 0
            result_info["buffer_write_source_facts"] = bws_rows
            result_info["buffer_write_source_path"] = str(bws_dst)

        # Also copy TaintKill if produced
        tk_src = OUTPUT_DIR / "TaintKill.csv"
        tk_dst = FACTS_DIR / "TaintKill.facts"
        if tk_src.exists():
            tk_dst.write_text(tk_src.read_text())
            content = tk_src.read_text().strip()
            tk_rows = content.count('\n') + 1 if content else 0
            result_info["taint_kill_facts"] = tk_rows
            result_info["taint_kill_path"] = str(tk_dst)

        return result_info
    finally:
        Path(tmp.name).unlink(missing_ok=True)


# =============================================================================
# Tool: Generate source/sink annotation fact files
# =============================================================================
# Built-in catalogs for dangerous sinks and taint source functions
_BUILTIN_SINKS = [
    ("memcpy", 0, "buffer_overflow_dst"),
    ("memcpy", 2, "buffer_overflow_size"),
    ("memmove", 0, "buffer_overflow_dst"),
    ("memmove", 2, "buffer_overflow_size"),
    ("strcpy", 0, "buffer_overflow_dst"),
    ("strncpy", 0, "buffer_overflow_dst"),
    ("strcat", 0, "buffer_overflow_dst"),
    ("sprintf", 0, "format_buffer_overflow"),
    ("snprintf", 0, "format_buffer_overflow"),
    ("system", 0, "command_injection"),
    ("execve", 0, "command_injection"),
    ("free", 0, "double_free"),
]

_BUILTIN_SOURCES = [
    ("read", "external"),
    ("recv", "external"),
    ("recvfrom", "external"),
    ("fread", "external"),
    ("fgets", "external"),
    ("gets", "external"),
    ("getenv", "external"),
    ("getline", "external"),
    ("scanf", "external"),
    ("recvmsg", "external"),
]


# =============================================================================
# Tool: Batch extract facts via headless Binary Ninja
# =============================================================================
def tool_extract_facts_batch(
    binary_path: str,
    function_names: list[str] = None,
    extract_all: bool = False,
) -> dict:
    """Extract Datalog facts from a binary or .bndb database using Binary Ninja.

    Accepts either a raw binary (ELF/PE/Mach-O) or a pre-analyzed .bndb
    database. Using .bndb is significantly faster — BN skips analysis and
    loads pre-computed MLIL-SSA directly.

    One call replaces the multi-step MCP extraction workflow (get_il → parse →
    write facts). Runs a headless BN subprocess that walks MLIL-SSA objects
    directly, producing .facts files including StackVar.

    Use this for batch extraction of multiple functions. For incremental,
    interactive exploration, continue using `tool_extract_facts` with MCP.

    Requires: BN_PYTHON or BN_PYTHON_PATH env var set, or BN on system path.

    Args:
        binary_path: Path to the binary or .bndb file to analyze.
        function_names: List of function names to extract.
        extract_all: If True, extract ALL functions (ignores function_names).

    Returns:
        Dict with extraction summary or error.
    """
    if not binary_path and BNDB_PATH:
        binary_path = BNDB_PATH

    import sys
    sys.path.insert(0, str(PROJECT_DIR))
    from bn_utils import extract_facts_batch

    return extract_facts_batch(binary_path, function_names, str(FACTS_DIR), extract_all)


# =============================================================================
# Tool: Find functions with loops (BOIL pre-filter)
# =============================================================================
def tool_find_loop_functions(
    binary_path: str = "",
    min_blocks: int = 2,
) -> dict:
    """Find all functions containing loops (back-edges) in a binary.

    This is a lightweight pre-filter for BOIL analysis. Scanning for back-edges
    is much faster than full fact extraction — use this first to identify
    loop-containing functions, then extract facts only for those functions
    before running boil.dl.

    Typical workflow for BOIL analysis on large binaries:
    1. tool_find_loop_functions(binary_path) → get list of loop functions
    2. tool_extract_facts_batch(binary_path, function_names=loop_funcs)
    3. tool_run_souffle(rule_file="boil.dl")

    Requires: BN_PYTHON or BN_PYTHON_PATH env var set, or BN on system path.

    Args:
        binary_path: Path to binary or .bndb database. Falls back to BNDB_PATH env var.
        min_blocks: Minimum basic blocks to consider (default: 2, skips trivial stubs).

    Returns:
        Dict with total_functions, loop_functions count, and list of function info
        (name, addr, blocks, loops) for each loop-containing function.
    """
    if not binary_path and BNDB_PATH:
        binary_path = BNDB_PATH

    if not binary_path:
        return {"error": "No binary_path provided and BNDB_PATH not set"}

    import sys
    sys.path.insert(0, str(PROJECT_DIR))
    from bn_utils import find_loop_functions

    return find_loop_functions(binary_path, min_blocks=min_blocks)


def tool_generate_annotations(
    extra_sources: list[dict] = None,
    extra_sinks: list[dict] = None,
    facts_dir: str = "",
) -> dict:
    """Generate DangerousSink.facts and TaintSourceFunc.facts from built-in catalogs.

    These fact files are loaded by interproc.dl via `.input` directives instead
    of being hardcoded in the rule file. You can extend the catalogs with
    extra entries for binary-specific functions.

    Args:
        extra_sources: Optional list of dicts with keys:
            func (str), category (str, e.g. "external").
            Example: [{"func": "png_read_data", "category": "external"}]
        extra_sinks: Optional list of dicts with keys:
            func (str), arg_idx (int), risk (str).
            Example: [{"func": "png_crc_read", "arg_idx": 1, "risk": "buffer_overflow"}]
        facts_dir: Directory for .facts files. Defaults to project facts/ dir.

    Returns:
        Dict with counts of sink and source facts written.
    """
    target_dir = Path(facts_dir) if facts_dir else FACTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    # Sinks
    sink_rows = set()
    for func, idx, risk in _BUILTIN_SINKS:
        sink_rows.add((func, str(idx), risk))
    if extra_sinks:
        for s in extra_sinks:
            sink_rows.add((s["func"], str(s["arg_idx"]), s["risk"]))
    sorted_sinks = sorted(sink_rows)
    sink_path = target_dir / "DangerousSink.facts"
    with open(sink_path, 'w') as fp:
        for row in sorted_sinks:
            fp.write('\t'.join(row) + '\n')

    # Sources
    source_rows = set()
    for func, cat in _BUILTIN_SOURCES:
        source_rows.add((func, cat))
    if extra_sources:
        for s in extra_sources:
            source_rows.add((s["func"], s["category"]))
    sorted_sources = sorted(source_rows)
    source_path = target_dir / "TaintSourceFunc.facts"
    with open(source_path, 'w') as fp:
        for row in sorted_sources:
            fp.write('\t'.join(row) + '\n')

    return {
        "sinks": len(sorted_sinks),
        "sources": len(sorted_sources),
        "sink_path": str(sink_path),
        "source_path": str(source_path),
    }


# =============================================================================
# Session token-usage accumulator
# =============================================================================
# Updated by `_record_usage` (registered as the LlmAgent's after_model
# callback). Read by `tool_session_usage` and embedded in every report
# so analyses carry their own cost ledger.

_USAGE_TOTALS: dict = {
    "turns": 0,
    "prompt_tokens": 0,
    "candidates_tokens": 0,   # output tokens
    "thoughts_tokens": 0,     # extended-thinking tokens (Anthropic)
    "cached_tokens": 0,       # cache-read tokens (Anthropic prompt cache)
    "tool_use_prompt_tokens": 0,
    "total_tokens": 0,
}


def _record_usage(callback_context, llm_response) -> None:
    """ADK after_model_callback — accumulate per-turn token usage."""
    um = getattr(llm_response, "usage_metadata", None)
    if um is None:
        return
    _USAGE_TOTALS["turns"] += 1
    for src, dst in (
        ("prompt_token_count", "prompt_tokens"),
        ("candidates_token_count", "candidates_tokens"),
        ("thoughts_token_count", "thoughts_tokens"),
        ("cached_content_token_count", "cached_tokens"),
        ("tool_use_prompt_token_count", "tool_use_prompt_tokens"),
        ("total_token_count", "total_tokens"),
    ):
        v = getattr(um, src, None)
        if v:
            _USAGE_TOTALS[dst] += int(v)


def tool_session_usage(reset: bool = False) -> dict:
    """Return cumulative LLM token usage for the current session.

    The agent SHOULD call this near the end of any non-trivial analysis
    and pass the result into `tool_write_analysis_report` (or rely on
    that tool's auto-embed of the same numbers). Use `reset=True` to
    clear counters at the start of a fresh analysis.

    Returned keys:
      turns                  — number of model calls
      prompt_tokens          — input tokens billed
      candidates_tokens      — output tokens billed
      thoughts_tokens        — extended-thinking tokens (anthropic/*)
      cached_tokens          — cache-read tokens (anthropic prompt cache)
      tool_use_prompt_tokens — tokens charged for tool-use scaffolding
      total_tokens           — provider-reported total
    """
    snapshot = dict(_USAGE_TOTALS)
    if reset:
        for k in _USAGE_TOTALS:
            _USAGE_TOTALS[k] = 0
    return snapshot


# =============================================================================
# Tool: Write analysis report to reports/
# =============================================================================
REPORTS_DIR = PROJECT_DIR / "reports"

_SEVERITY_BADGES = {
    "high": "[HIGH]",
    "medium": "[MEDIUM]",
    "low": "[LOW]",
    "info": "[INFO]",
}

_STATUS_BADGES = {
    "confirmed": "confirmed",
    "likely": "likely",
    "plausible-unverified": "plausible-unverified",
    "inconclusive": "inconclusive",
    "refuted": "refuted",
    "no_candidates": "no_candidates",
}


def _slugify(text: str) -> str:
    import re
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", text).strip("_").lower()
    return slug[:60] if len(slug) > 60 else slug


def tool_write_analysis_report(
    title: str,
    binary: str,
    findings: list[dict] = None,
    hypotheses: list[dict] = None,
    status: str = "",
    raw_markdown: str = "",
    filename: str = "",
    reports_dir: str = "",
) -> dict:
    """Persist an analysis report to the reports/ directory.

    Call this at the end of any non-trivial analysis session, AND whenever
    you conclude "not detected" / "inconclusive" so the hypothesis trace
    survives. The hybrid LLM+Datalog contract requires that reasoning
    (not just rule output) is preserved.

    Args:
        title: Short report title, e.g. "FFmpeg H.264 slice_table review".
        binary: Absolute or relative path to the binary analyzed.
        findings: List of finding dicts. Each should carry:
            - severity:   "high" | "medium" | "low" | "info"
            - category:   short tag (e.g. "sentinel_collision",
                          "tainted_counter_as_index")
            - function:   function name (optional)
            - addr:       hex or int address (optional)
            - evidence:   list[str] — each cites a CSV row, fact, or MCP
                          lookup. REQUIRED — findings without evidence
                          will be flagged in the output.
            - reasoning:  one-paragraph explanation tying the facts to
                          the exploitability claim.
            - confidence: "confirmed" | "likely" | "plausible-unverified"
        hypotheses: List of hypothesis dicts from the reflective loop:
            - name:          e.g. "sentinel collision at slice_table"
            - verdict:       "confirmed" | "likely" | "plausible-unverified"
                             | "refuted"
            - facts_checked: list[str] — specific CSV/fact rows examined.
            - mcp_checked:   list[str] — MCP calls made (e.g.
                             "decompile_function(h264_init)").
            - note:          one-line reasoning.
        status: Overall session verdict. Use "confirmed" when findings were
            proven exploitable; "inconclusive" when rules missed and
            reflective anomalies remain; "refuted" when the reported bug
            class was actively disproven; "no_candidates" only when no
            interesting sinks/loops exist at all. Empty string → omitted.
        raw_markdown: Optional free-form narrative appended at the end —
            use for multi-paragraph reasoning or code snippets that don't
            fit the structured schema.
        filename: Optional override. Defaults to
            reports/<slug(title)>_<YYYYMMDD_HHMMSS>.md.
        reports_dir: Optional override directory. Defaults to the repo's
            reports/ (gitignored).

    Returns:
        Dict with file path, bytes written, finding count, hypothesis count.
    """
    from datetime import datetime

    findings = findings or []
    hypotheses = hypotheses or []

    target_dir = Path(reports_dir) if reports_dir else REPORTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.utcnow()
    ts_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    ts_file = now.strftime("%Y%m%d_%H%M%S")

    if filename:
        fname = filename if filename.endswith(".md") else filename + ".md"
    else:
        fname = f"{_slugify(title) or 'analysis'}_{ts_file}.md"
    out_path = target_dir / fname

    lines: list[str] = []
    lines.append(f"# {title}\n")
    lines.append("## Metadata\n")
    lines.append(f"- **binary:** `{binary}`")
    lines.append(f"- **timestamp:** {ts_iso}")
    if status:
        badge = _STATUS_BADGES.get(status, status)
        lines.append(f"- **status:** {badge}")
    lines.append(f"- **finding_count:** {len(findings)}")
    lines.append(f"- **hypothesis_count:** {len(hypotheses)}")
    lines.append("")

    # Findings grouped by severity (high → medium → low → info → other)
    if findings:
        lines.append("## Findings\n")
        order = ["high", "medium", "low", "info"]
        bucketed: dict[str, list[dict]] = {}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            bucketed.setdefault(sev, []).append(f)
        # Stable order, with unknown severities last
        sev_keys = [s for s in order if s in bucketed] + [
            s for s in bucketed if s not in order
        ]
        for sev in sev_keys:
            badge = _SEVERITY_BADGES.get(sev, sev.upper())
            lines.append(f"### {badge}\n")
            for f in bucketed[sev]:
                cat = f.get("category", "uncategorized")
                func = f.get("function", "")
                addr = f.get("addr", "")
                header_bits = [f"**{cat}**"]
                if func:
                    header_bits.append(f"`{func}`")
                if addr not in (None, ""):
                    addr_str = hex(addr) if isinstance(addr, int) else str(addr)
                    header_bits.append(f"@ {addr_str}")
                lines.append("#### " + " ".join(header_bits))
                evidence = f.get("evidence") or []
                if not evidence:
                    lines.append("- _⚠️ no evidence cited — please add fact/CSV/MCP references_")
                else:
                    lines.append("**Evidence:**")
                    for e in evidence:
                        lines.append(f"- {e}")
                reasoning = f.get("reasoning", "").strip()
                if reasoning:
                    lines.append("")
                    lines.append(f"**Reasoning:** {reasoning}")
                conf = f.get("confidence", "")
                if conf:
                    badge_c = _STATUS_BADGES.get(conf, conf)
                    lines.append(f"**Confidence:** {badge_c}")
                lines.append("")

    # Hypotheses table
    if hypotheses:
        lines.append("## Hypotheses considered\n")
        lines.append("| # | Hypothesis | Verdict | Facts checked | MCP checked | Note |")
        lines.append("|---|---|---|---|---|---|")
        for i, h in enumerate(hypotheses, 1):
            name = h.get("name", "(unnamed)")
            verdict = h.get("verdict", "")
            badge_v = _STATUS_BADGES.get(verdict, verdict)
            facts = ", ".join(h.get("facts_checked") or []) or "—"
            mcp = ", ".join(h.get("mcp_checked") or []) or "—"
            note = (h.get("note") or "").replace("|", "\\|")
            lines.append(
                f"| {i} | {name} | {badge_v} | {facts} | {mcp} | {note} |"
            )
        lines.append("")

    if raw_markdown:
        lines.append("## Notes\n")
        lines.append(raw_markdown.rstrip())
        lines.append("")

    # Auto-embed session token usage so each report carries its own cost
    # ledger. Numbers come from the after_model_callback accumulator.
    usage = dict(_USAGE_TOTALS)
    if usage.get("turns", 0) > 0:
        lines.append("## Token usage\n")
        lines.append(f"- **turns:** {usage['turns']}")
        lines.append(f"- **prompt_tokens:** {usage['prompt_tokens']:,}")
        lines.append(f"- **candidates_tokens:** {usage['candidates_tokens']:,}")
        if usage.get("thoughts_tokens"):
            lines.append(f"- **thoughts_tokens:** {usage['thoughts_tokens']:,}")
        if usage.get("cached_tokens"):
            lines.append(f"- **cached_tokens:** {usage['cached_tokens']:,}")
        if usage.get("tool_use_prompt_tokens"):
            lines.append(
                f"- **tool_use_prompt_tokens:** {usage['tool_use_prompt_tokens']:,}"
            )
        lines.append(f"- **total_tokens:** {usage['total_tokens']:,}")
        lines.append("")

    content = "\n".join(lines)
    out_path.write_text(content, encoding="utf-8")

    return {
        "path": str(out_path),
        "bytes": len(content.encode("utf-8")),
        "finding_count": len(findings),
        "hypothesis_count": len(hypotheses),
        "status": status,
    }


# =============================================================================
# Tool: Set entry-point taint (attack surface specification)
# =============================================================================
def tool_set_entry_taint(
    entries: list[dict],
    facts_dir: str = "",
) -> dict:
    """Specify which exported API parameters are attacker-controlled.

    For library analysis where there are no calls to read()/recv() — the
    library's exported API IS the attack surface. Mark params as tainted
    and interproc.dl will seed TaintedVar from them.

    Args:
        entries: List of dicts with keys:
            func (str): Function name (e.g., "parse_image")
            param_idx (int): 0-based parameter index (e.g., 1 for arg2)
            Example: [{"func": "parse_image", "param_idx": 1},
                      {"func": "parse_image", "param_idx": 0}]
        facts_dir: Directory for .facts files. Defaults to project facts/ dir.

    Returns:
        Dict with count of entries written and file path.
    """
    target_dir = Path(facts_dir) if facts_dir else FACTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    rows = set()
    for e in entries:
        rows.add((e["func"], str(e["param_idx"])))
    sorted_rows = sorted(rows)

    path = target_dir / "EntryTaint.facts"
    with open(path, 'w') as fp:
        for row in sorted_rows:
            fp.write('\t'.join(row) + '\n')

    return {
        "entries": len(sorted_rows),
        "path": str(path),
        "description": f"Marked {len(sorted_rows)} params as attacker-controlled entry points",
    }


# =============================================================================
# Tool: Two-pass taint pipeline (alias → interproc)
# =============================================================================
def tool_run_taint_pipeline(
    facts_dir: str = "",
    output_dir: str = "",
    timeout_seconds: int = 60,
) -> dict:
    """Run the full taint analysis pipeline: alias analysis → interprocedural taint.

    Pass 1: Runs alias.dl to compute PointsTo facts.
    Pass 2: Copies PointsTo to facts dir, runs interproc.dl with alias-enhanced taint.

    This replaces manually running alias.dl then interproc.dl. It handles the
    intermediate PointsTo.csv → PointsTo.facts copy automatically.

    Args:
        facts_dir: Directory containing .facts input files. Defaults to project facts/ dir.
        output_dir: Directory for output CSV files. Defaults to project output/ dir.
        timeout_seconds: Max execution time per pass (default 60s).

    Returns:
        Dict with results from both passes and combined output files.
    """
    fdir = Path(facts_dir) if facts_dir else FACTS_DIR
    odir = Path(output_dir) if output_dir else OUTPUT_DIR
    return pipeline.run_taint_pipeline(
        fdir, odir, RULES_DIR,
        timeout_seconds=timeout_seconds,
        jobs=SOUFFLE_JOBS, compile_mode=SOUFFLE_COMPILE,
    )


def tool_run_bn_extra_rules(
    facts_dir: str = "",
    output_dir: str = "",
    timeout_seconds: int = 120,
) -> dict:
    """Run the Bn* extra-rule pipeline (ported from NeuroLog).

    Additive to existing outputs — does NOT clear non-Bn* CSVs.
    Pass order:
       1.  bn_flow.dl                — shared Flow transitive closure
       2.  bn_signed_infer.dl        — signedness heuristic
       3.  bn_counter_oob.dl         — unbounded-counter / counter-as-index
       4.  bn_alloc_copy.dl          — alloc/copy size-mismatch
       5.  bn_unguarded_sink.dl      — TaintedSink \\ GuardedSink
       6.  bn_loop_bound.dl          — tainted loop bound (BOIL refinement)
       7.  bn_unguarded_cast.dl      — narrowing/sign-extend cast without guard
       8.  bn_arith_overflow.dl      — narrow signed overflow + sink coupling
       9.  bn_width_mismatch.dl      — wide value stored into narrow slot
      10.  bn_sentinel_init.dl       — sentinel-initialized buffer + counter
      11.  bn_null_deref.dl          — null deref of allocator result
      12.  bn_allocator_mismatch.dl  — alloc-family ↔ free-family mismatch
      13.  bn_unbounded_sink_audit.dl — sink-first guard-presence audit
      14.  bn_joint_buffer_bound.dl  — joint offset+size bound (CVE-2023-38545 class)
      15.  bn_type_confusion.dl      — pointer↔int truncation round-trip
      16.  bn_guard_dominates.dl     — CFG-dominance refinement
      17.  bn_findings.dl            — unified BnFinding summary

    Staging between passes copies derived CSVs back to facts/ so downstream
    rules can consume them via .input.

    Requires TaintedVar.facts in the facts dir for the tainted variants.
    Run `tool_run_taint_pipeline` first, then copy output/TaintedVar.csv →
    facts/TaintedVar.facts manually (or via a script), then invoke this.

    Args:
        facts_dir: Directory with .facts files. Defaults to project facts/ dir.
        output_dir: Directory for output CSVs. Defaults to project output/ dir.
        timeout_seconds: Max per-pass timeout (default 120s).

    Returns:
        Dict with per-pass status and row counts of Bn* outputs.
    """
    fdir = Path(facts_dir) if facts_dir else FACTS_DIR
    odir = Path(output_dir) if output_dir else OUTPUT_DIR
    return pipeline.run_bn_extra_rules(
        fdir, odir, RULES_DIR,
        timeout_seconds=timeout_seconds,
        jobs=SOUFFLE_JOBS, compile_mode=SOUFFLE_COMPILE,
    )


# =============================================================================
# Agent instruction prompt
# =============================================================================
AGENT_INSTRUCTION = """You are **BinCodeQL**, an interactive binary analysis co-pilot.
You help vulnerability researchers analyze compiled binaries using Datalog queries
over facts extracted from Binary Ninja's MLIL-SSA intermediate representation.

## Operating principle: facts are ingredients, not verdicts

BinCodeQL is an **LLM + Datalog hybrid**. The Datalog layer gives you precise,
mechanical dataflow and structural facts. The LLM layer — you — is responsible
for the weird-machine reasoning the rules cannot encode: combining facts into
possible failure scenarios, noticing suspicious coincidences, and hypothesizing
value-range / semantic invariants the program may silently break.

Three operating rules follow from this:

1. **A Datalog miss is not evidence of absence.** When rules return nothing for
   a candidate bug, that means the rule set as written did not match, not that
   the bug is absent. Treat empty rule output as a cue to reason, not as a
   verdict.

2. **Run the "wait a minute…" moment after every fact-extraction or rule pass.**
   Skim the fresh facts/CSVs for anomalies worth being *curious* about — an
   unbounded increment, a `memset` with `-1`/`0xFF`, a cast to a narrower type,
   a comparison against a suspicious constant (`65535`, `0x7FFFFFFF`, `-1`),
   a loop bound that is itself tainted, an `AllocSite` with small `elem_width`
   next to wide writes. For each anomaly, actually verbalize the thought:
   *"wait, if this counter is unbounded and that buffer has 16-bit elements
   and memset wrote 0xFF everywhere… what happens when they meet?"*. That
   reflective, curiosity-driven skepticism is the core of the hybrid. Without
   it, you are just a Datalog shell.

3. **Sketch value reasoning from the facts you already have.** Combine
   `ArithOp.operand` (literal constants on arith RHS), `Cast.src_width` /
   `Cast.dst_width`, `VarWidth`, `Guard.bound`, `CallArgConst` (constant call
   args — e.g. the `-1` in `memset(buf, -1, …)`), `MemWriteSize` (store width),
   `AllocSite.elem_width` (heap-element width). Then validate with MCP
   (`decompile_function`, `get_il`, `hexdump_address`). When the facts alone
   are insufficient, compose a narrower custom Datalog query over `schema.dl`
   or read MLIL-SSA directly. **Never** conclude "not present" without either
   a confirmed refutation or an explicit `inconclusive` verdict written to
   the report via `tool_write_analysis_report`.

## Your capabilities

1. **Binary Ninja MCP tools** — decompile functions, get MLIL-SSA IL, list functions,
   search symbols, get cross-references, list imports/exports, etc.

2. **Fact extraction** — Parse MLIL-SSA into Datalog facts (Def, Use, Call, PhiSource,
   ActualArg, ReturnVal, AddressOf, FieldRead, FieldWrite, MemRead, FormalParam,
   Guard, etc.). **Prefer batch extraction** (`tool_extract_facts_batch`) — it runs a
   headless BN subprocess, auto-resolves callees, and emits StackVar + Guard facts.

3. **Souffle Datalog engine** — Run pre-built or custom Datalog queries:
   - `interproc.dl` — Full interprocedural taint analysis with 1-CFA context sensitivity,
     sanitizer modeling (TaintKill), guard detection (GuardedSink), and interprocedural
     field taint propagation. TaintedVar has 5 columns: (func, var, ver, origin, ctx).
   - `taint.dl` — Intraprocedural taint tracking
   - `summary.dl` — Function summary computation (param → return dependencies)
   - `core.dl` — Basic def-use, reachability, field access queries
   - `alias.dl` — Andersen-style points-to analysis + alias-enhanced taint
   - `boil.dl` — BOIL (Buffer Overflow Inducing Loop) candidate detection
   - `patterns.dl` — Structural vulnerability heuristics (unsafe strcpy, gets, sprintf)
   - `patterns_mem.dl` — Intraprocedural memory safety: UAF, double-free,
     unchecked malloc, format string vulnerabilities
   - `patterns_mem_interproc.dl` — Interprocedural memory safety: parameter-based
     (FreesParam → InterDoubleFree/InterUseAfterFree) + global-mediated
     (GlobalFreeSite → GlobalDoubleFree/GlobalUseAfterFree). Includes intraprocedural
     rules too — run this instead of patterns_mem.dl for comprehensive detection.
   - `inttype.dl` — Integer/type confusion: signed→unsigned, truncation,
     widening-after-overflow, sign-extend-negative-to-size at size-sensitive sinks
   - `inttype_taint.dl` — Taint-integrated integer vulns (requires TaintedVar from interproc.dl)
   - `schema.dl` — Reusable `.decl` + `.input` declarations (include in custom queries)
   - Custom `.dl` programs you compose on the fly

4. **Taint signatures** — Library function models (memcpy, strcpy, read, recv, etc.)
   that declare how taint transfers through external functions. Also includes TaintKill
   (sanitizers like memset, bzero) that kill taint on buffers.

5. **Annotations** — Source/sink fact files generated from built-in catalogs, extensible
   with binary-specific functions.

## Fact schema reference

| Relation | Columns | File |
|----------|---------|------|
| Def | func, var, ver, addr | Def.facts |
| Use | func, var, ver, addr | Use.facts |
| Call | caller, callee, addr | Call.facts |
| ActualArg | call_addr, arg_idx, param, var, ver | ActualArg.facts |
| ReturnVal | func, var, ver | ReturnVal.facts |
| PhiSource | func, var, def_ver, src_var, src_ver | PhiSource.facts |
| FormalParam | func, var, idx | FormalParam.facts |
| MemRead | func, addr, base, offset, size | MemRead.facts |
| MemWrite | func, addr, target, mem_in, mem_out | MemWrite.facts |
| FieldRead | func, addr, base, field | FieldRead.facts |
| FieldWrite | func, addr, base, field, mem_in, mem_out | FieldWrite.facts |
| AddressOf | func, var, ver, target | AddressOf.facts |
| CallAddrArg | call_addr, arg_idx, target | CallAddrArg.facts |
| CFGEdge | func, from_addr, to_addr | CFGEdge.facts |
| Jump | func, addr, expr | Jump.facts |
| StackVar | func, var, offset, size | StackVar.facts |
| Guard | func, addr, var, ver, op, bound | Guard.facts |
| ArithOp | func, addr, dst, dst_ver, op, src, src_ver, operand | ArithOp.facts |
| Cast | func, addr, dst, dst_ver, src, src_ver, kind, src_width, dst_width | Cast.facts |
| VarWidth | func, var, ver, width | VarWidth.facts |
| CallArgConst | call_addr, arg_idx, value | CallArgConst.facts |
| MemWriteSize | func, addr, size | MemWriteSize.facts |
| AllocSite | call_addr, func, size_var, size_const, elem_width | AllocSite.facts |
| DangerousSink | func, arg_idx, risk | DangerousSink.facts |
| TaintSourceFunc | name, category | TaintSourceFunc.facts |
| BufferWriteSource | func, arg_idx | BufferWriteSource.facts |
| TaintKill | func, arg_idx | TaintKill.facts |
| PointsTo | func, var, ver, obj | PointsTo.facts (derived from alias.dl) |

### Derived output relations (from interproc.dl)

| Relation | Columns | Description |
|----------|---------|-------------|
| TaintedVar | func, var, ver, origin, ctx | Context-sensitive tainted variables (ctx = call-site address) |
| TaintedSink | caller, callee, call_addr, arg_idx, tainted_var, risk, origin | Tainted data reaching dangerous sinks (excludes sanitized vars) |
| TaintedBuffer | func, buffer, origin, ctx | Buffers tainted via pointer aliasing |
| TaintedField | func, base, field, origin, ctx | Field-level taint (interprocedural) |
| TaintedHeapObject | obj, origin | Heap objects tainted via buffer-write sources |
| SanitizedVar | func, var, ver, kill_func, kill_addr | Variables sanitized by TaintKill functions |
| GuardedSink | caller, callee, call_addr, guard_var, guard_op, guard_bound | Sinks with bounds-check guards (for triage) |

### Derived output relations (from inttype.dl / inttype_taint.dl)

| Relation | Columns | Description |
|----------|---------|-------------|
| SignedToUnsignedConfusion | func, cast_addr, dst, dst_ver, callee, call_addr, arg_idx | Sign-extend output flows to size-sensitive sink |
| IntegerTruncation | func, cast_addr, dst, dst_ver, src_width, dst_width, callee, call_addr, arg_idx | Wide→narrow truncation before size arg |
| WideningAfterOverflow | func, arith_addr, op, arith_width, cast_addr, callee, call_addr | Narrow arith then zero-extend to wide |
| SignExtNegativeToSize | func, arith_addr, cast_addr, callee, call_addr | Arith result sign-extended, used as size |
| TaintedIntVuln | func, vuln_type, cast_addr, callee, sink_addr, origin | Taint-integrated integer bug (from inttype_taint.dl) |
| GuardedIntIssue | func, cast_addr, guard_addr, guard_op, guard_bound | Int issue with bounds check (lower confidence) |

### Derived output relations (from patterns_mem.dl)

| Relation | Columns | Description |
|----------|---------|-------------|
| UseAfterFree | func, free_addr, use_addr, var | Pointer used after free() |
| DoubleFree | func, free1_addr, free2_addr, var | Same pointer freed twice |
| UncheckedMalloc | func, call_addr, var | malloc/calloc/realloc return used without NULL check |
| FormatStringVuln | func, call_addr, callee, fmt_var | Function param used as format string |

### Derived output relations (from the Bn* rule set)

| Relation | Columns | Description |
|----------|---------|-------------|
| BnSignedness | func, var, ver, sign | Resolved signedness: "signed"/"unsigned"/"conflict"/"unknown" |
| BnFlow | func, src_var, src_ver, dst_var, dst_ver | Shared transitive Flow closure (consumed by downstream rules) |
| BnLoopIterVar | func, var | Loop-carried variables (phi self-reference) |
| BnHasUpperBound | func, var, ver | Variable has a proper upper-bound guard (slt/sle/ult/ule, Flow-lifted) |
| BnUnboundedCounter | func, var, ver, incr_addr | `add` op with no upper-bound guard on any SSA version |
| BnTaintedUnboundedCounter | func, var, ver, incr_addr, origin | Loop-carried unbounded counter tainted from attacker input |
| BnCounterUsedAsIndex | func, var, ver, incr_addr, use_addr, kind | Counter flows to mem_read_use / mem_write_use / ptr_arith / sink_arg |
| BnTaintedCounterAsIndex | func, var, ver, incr_addr, use_addr, kind, origin | Exploitable tainted counter-as-index |
| BnAllocSite / BnCopySite | — | Allocation / copy call pairs for mismatch detection |
| BnAllocCopyMismatch | func, alloc_addr, copy_addr, buf, alloc_size, copy_size, alloc_func, copy_func, pattern, a_origin, c_origin | Alloc size ≠ copy size (both tainted or tainted-copy with untainted-alloc) |
| BnAllocThenUnboundedCopy | func, alloc_addr, copy_addr, buf, alloc_size, alloc_func, copy_func, origin | malloc(tainted-size) → strcpy/strcat/sprintf |
| BnUnguardedTaintedSink | caller, callee, call_addr, arg_idx, tainted_var, risk, origin | `TaintedSink \\ GuardedSink` |
| BnTaintedLoopBound | func, guard_addr, loop_var, loop_ver, bound_var, bound_ver, op, origin, taint_side | Tainted loop-continuation predicate ({slt,sle,ult,ule,ne}) |
| BnUnguardedDangerousCast | func, cast_addr, src, src_ver, dst, dst_ver, kind, src_width, dst_width | trunc/sx without CFG-reaching guard on the source |
| BnPotentialArithOverflow | func, addr, var, ver, op, width | Narrow (≤4B) signed add/mul/lsl with no guard |
| BnOverflowAtSink | func, arith_addr, sink_addr, var, callee, arg_idx | Narrow-signed arith flows to size-sensitive sink |
| BnTaintedOverflowAtSink | func, arith_addr, sink_addr, var, callee, arg_idx, origin | Exploitable narrow-signed overflow |
| BnNarrowStore | func, addr, val_var, val_ver, store_size, val_width | Wide value stored into narrower memory slot (implicit truncation) |
| BnWidthMismatchStore | func, addr, val_var, val_ver, store_size, val_width, alloc_addr, elem_width | BnNarrowStore whose alias target is an AllocSite with `elem_width < val_width` |
| BnSentinelInit | func, addr, buf, sentinel_val | `memset(buf, K, …)` with K ∈ {-1, 0xFF, 0xFFFF, 255, 65535} |
| BnSentinelBuf | func, buf, sentinel_val | Lifted sentinel buffer through PointsTo / CallAddrArg |
| BnSentinelCollisionRisk | func, init_addr, use_addr, buf, cmp_var, cmp_ver, sentinel_val, origin | Sentinel buffer compared against unbounded (possibly tainted) counter |
| BnAllocatorMismatch | func, alloc_addr, alloc_callee, alloc_family, alloc_var, free_addr, free_callee, free_family | Pointer allocated by family X freed by family Y (requires user-supplied AllocFamily/FreeFamily) |
| BnUnboundedSinkCall / BnUnboundedSinkParamCall | caller, callee, call_addr, size_var, size_ver, risk | Sink-first audit: dangerous call with no in-function bound on the size arg |
| BnJointBufferBoundUnsafe | func, addr, sink, dst_var, off_var, sz_var, const_bound, cap_var, cap_term | strcpy/memcpy at base+off where off and sz are bounded separately but no joint guard exists (CVE-2023-38545 class) |
| BnPtrIntTruncation | func, in_addr, out_addr, ptr_var, int_var, ptr_width, int_width, subkind | Pointer cast to sub-pointer-width int and cast back — silent high-bit truncation |
| BnFinding | func, addr, severity, category, var, detail | Unified aggregation — primary output for reporting |

Severity levels in `BnFinding`: `high` (exploitable shape — tainted counter-as-index, alloc-copy mismatch, unguarded tainted sink, tainted overflow-at-sink), `medium` (structural — tainted loop bound, unguarded cast, unbounded counter without taint).

### Derived output relations (from patterns_mem_interproc.dl)

| Relation | Columns | Description |
|----------|---------|-------------|
| FreesParam | func, param_idx | Function summary: frees its Nth parameter |
| InterDoubleFree | caller, callee1, call1, callee2, call2, var | Same arg passed to two callees that both free it |
| InterUseAfterFree | caller, callee, free_call, use_addr, var | Arg passed to freeing callee, then used after call returns |
| GlobalFreeSite | func, free_addr, global_addr | Global pointer loaded and freed |
| GlobalDoubleFree | func1, free1, func2, free2, global_addr | Same global freed in two places |
| GlobalUseAfterFree | free_func, free_addr, use_func, use_addr, global_addr, use_var | Global freed, then used (same or different function) |
| UsesAfterFreeParam | func, param_idx, free_addr, use_addr | Function frees param then uses it (callee-side UAF summary) |
| ReturnsFreedPtr | func, param_idx | Function frees param then returns it (dangling pointer) |
| ReturnedDanglingPtr | caller, callee, call_addr, dangling_var, use_addr | Caller uses return value that was freed inside callee |

## Workflow for analyzing a binary

### Recommended end-to-end pipeline (Bn* rule set)

Run the following tools in order. Each step is self-contained — do NOT
invent your own shell invocations; use the provided tools.

**1. Clean workspace** — `tool_clean_workspace` removes stale facts/output.

**2. Pick target functions.** Use `search_functions_by_name`, `list_exports`,
or `list_imports` to find candidates. For a vuln-discovery task without a
specific target, prefer exported attack-surface functions (parsers,
decoders, I/O wrappers) that transitively reach dangerous sinks.

**3. Batch extract** — `tool_extract_facts_batch(binary_path, function_names=[...])`.
Headless BN subprocess; auto-resolves direct and global-pointer-mediated
indirect calls (xmlMalloc-style libraries); emits all facts including
Cast, VarWidth, VarSign (from DWARF when present), StackVar, Guard,
CallAddrArg, and decomposed MemRead offsets.
Prefer `.bndb` sidecar — it loads in ms and preserves user type refinements.
Requires `BN_PYTHON` or `BN_PYTHON_PATH` env.

**4. Generate signatures** — `tool_generate_signatures()` writes
TaintTransfer.facts / BufferWriteSource.facts / TaintKill.facts from
`rules/signatures.dl`. Must be rerun whenever that rule file changes.

**5. Generate annotations** — `tool_generate_annotations(facts_dir=...)`
writes DangerousSink.facts and TaintSourceFunc.facts from built-in
catalogs. Pass `extra_sinks`/`extra_sources` for binary-specific entries.

**6. Set entry taint** — `tool_set_entry_taint(entries=[...])` marks
function parameters as attacker-controlled. REQUIRED for libraries that
do not themselves call `read`/`recv`/etc. — without entry taint, the
tainted variants of every Bn* rule fire 0 times.

**Entry-taint heuristic when the user doesn't specify params:** look at
the target function's signature via `decompile_function` or type info, then:
  - Mark every `const char *` / `const xmlChar *` / `const uint8_t *` /
    `void *` pointer parameter that represents external data (skip
    parser-context structs like `xmlParserCtxtPtr` unless that's the
    only input).
  - Mark every `int` / `size_t` / `ssize_t` length parameter.
  - Skip output parameters (e.g., `out`, `result`), file descriptors,
    and function-pointer callbacks.
  - If the target is an event/SAX callback, taint the data arg and len.

Examples:
  - `xmlStrndup(const xmlChar *cur, int len)` → taint arg 0 (cur), arg 1 (len)
  - `parse_tlv(ctx, uint8_t *buf, size_t len)` → taint arg 1 (buf), arg 2 (len)
  - `png_read_row(png_structrp png_ptr, uint8_t *row, uint8_t *display)` →
    taint arg 0 (png_ptr — holds I/O state) only

**7. Run the taint pipeline** — `tool_run_taint_pipeline()`.
Two passes: alias.dl → interproc.dl. Produces PointsTo, TaintedVar,
TaintedSink, TaintedHeapObject, TaintedBuffer, SanitizedVar, GuardedSink.
PointsTo and TaintedVar are auto-staged for the next pipeline — no
manual copy needed.

**8. Run the Bn* extra-rule pipeline** — `tool_run_bn_extra_rules()`.
Passes are auto-ordered with inter-pass fact staging:
   1.  bn_flow.dl                — shared transitive-closure Flow (perf)
   2.  bn_signed_infer.dl        — signedness (VarSign ground truth + heuristic)
   3.  bn_counter_oob.dl         — unbounded counter / counter-as-index
                                   (gated on loop-carried phi self-reference
                                   to suppress straight-line FPs)
   4.  bn_alloc_copy.dl          — alloc/copy size mismatch
   5.  bn_unguarded_sink.dl      — TaintedSink \\ GuardedSink
   6.  bn_loop_bound.dl          — tainted loop bound (BOIL refinement)
   7.  bn_unguarded_cast.dl      — trunc/sx without CFG-reaching guard
   8.  bn_arith_overflow.dl      — narrow signed arith overflow + sink coupling
   9.  bn_width_mismatch.dl      — wide value stored into narrower slot
                                   (32-bit counter → 16-bit table element)
  10.  bn_sentinel_init.dl       — memset(buf, K, …) sentinel meets unbounded
                                   counter (H.264 slice_table class)
  11.  bn_null_deref.dl          — null deref of allocator result
  12.  bn_allocator_mismatch.dl  — alloc-family X then free-family Y
                                   (requires user-supplied AllocFamily.facts +
                                   FreeFamily.facts; empty files = no rows)
  13.  bn_unbounded_sink_audit.dl — sink-first guard-presence audit (triage
                                   floor; complement to source-first taint)
  14.  bn_joint_buffer_bound.dl  — offset+size with no joint guard
                                   (CVE-2023-38545 class)
  15.  bn_type_confusion.dl      — pointer↔int truncation round-trip
                                   (LP64 silent high-bit loss)
  16.  bn_guard_dominates.dl     — CFG-dominance refinement of guards
  17.  bn_findings.dl            — unified BnFinding aggregation

**9. Optionally run additional rule files** for orthogonal coverage:
  - `patterns.dl`, `patterns_mem_interproc.dl` (UAF, double-free, etc.)
  - `inttype.dl`, `inttype_taint.dl` (classic integer bugs — overlapping but
    distinct from bn_arith_overflow.dl)
  - `boil.dl`, `boil_taint.dl` (buffer-overflow-inducing loops)

**10. Interpret and report.** Read the relevant CSVs, pair findings with
`decompile_function` output, cite file_path:line_number when referencing
code, group by severity (BnFinding has a severity column). Prefer
`BnFinding.csv` as the single consolidated view — it unions all Bn*
outputs with a consistent (severity, category, var, detail) shape.

### Alternative: Interactive MCP extraction

Use only when batch extraction is unavailable. Steps 1/3 are replaced by
`tool_extract_facts` (MCP-based, text-parser); the rest is identical.
MCP extraction doesn't emit StackVar/VarWidth/Cast/VarSign and cannot
resolve indirect calls — expect reduced rule coverage.

### Alternative: Interactive MCP extraction
Use when you need to explore incrementally or BN headless is unavailable.
1. **Select binary** — Use `select_binary` if needed.
2. **Clean workspace** — Call `tool_clean_workspace`.
3. **Explore** — Use `list_methods`, `search_functions_by_name`, `list_imports`.
4. **Extract IL** — Use `get_il(func, "mlil", ssa=True)` for functions of interest.
5. **Parse facts** — Call `tool_extract_facts` with the MLIL-SSA text (facts accumulate).
   If `unresolved_callees` is non-empty, resolve via `function_at` + `tool_resolve_calls`.
6. **Generate annotations + signatures** — Same as batch workflow.
7. **Run analysis** — Same as batch workflow.

## Writing custom Datalog queries

When the user asks a question not covered by existing rules, **compose a custom Datalog
program on the fly**. You can `#include "schema.dl"` to get all type and relation
declarations, or declare only what you need. The program must:
- Declare types: `.type Addr <: unsigned`, `.type Sym <: symbol`, `.type Ver <: unsigned`, `.type Idx <: unsigned`
- Declare and `.input` the relations it needs (Def, Use, Call, etc.)
- Define derived relations with rules
- `.output` the result relations

### Common vulnerability query patterns

For patterns not covered by existing rule files, compose custom queries on the fly:

- **Use-after-free / Double-free / Unchecked malloc / Format string:** Run
  `patterns_mem_interproc.dl` for comprehensive detection — covers both intraprocedural
  patterns AND interprocedural ones (parameter-based FreesParam summaries + global-mediated
  tracking). Detects cross-function UAF/double-free via shared globals. Or run the lighter
  `patterns_mem.dl` for intraprocedural-only analysis.
- **Integer/type confusion:** Run `inttype.dl` to find signed→unsigned confusion,
  integer truncation, widening-after-overflow, and sign-extend-negative-to-size bugs.
  Requires Cast.facts and VarWidth.facts (emitted by batch extraction).
- **Tainted integer bugs:** After running interproc.dl, run `inttype_taint.dl` to find
  integer confusion bugs reachable from attacker-controlled input. Output: TaintedIntVuln.
- **BOIL detection:** For large binaries, first call `tool_find_loop_functions` to
  identify functions with loops (fast back-edge scan), then extract facts only for
  those functions via `tool_extract_facts_batch`. Then run `boil.dl` to find
  buffer-overflow-inducing loops. BOILCandidate(func, src_ptr, dst_ptr, read_addr,
  write_addr, confidence) shows loops that copy data with incrementing pointers.
  "high" confidence means ArithOp confirmed both pointers increment and termination
  depends on source data. Examine candidates with decompile_function for full analysis.
- **Library attack surface (entry-point taint):** For libraries without calls to
  read()/recv(), use `tool_set_entry_taint` to mark exported API params as
  attacker-controlled. Example: `[{"func": "parse_image", "param_idx": 1}]`.
  Then run interproc.dl — TaintedVar will propagate from those params.
  Origin strings use format `entry:func_name:argN` for traceability.
- **Tainted BOIL (end-to-end):** After setting entry taints and running both
  interproc.dl and boil.dl, run `boil_taint.dl` to find BOILs reachable from
  attacker input. TaintedBOIL shows which BOIL candidates have tainted src/dst
  pointers. TaintedBOILEntry traces back to the specific entry-point param.
- **Sentinel-collision (memset-initialized sentinel meets unbounded counter):**
  `bn_sentinel_init.dl` in the Bn* pipeline emits `BnSentinelInit` for every
  `memset(buf, K, …)` call with `K ∈ {-1, 0xFF, 0xFFFF, 255, 65535}` using
  `CallArgConst(call_addr, 1, val)`. `BnSentinelCollisionRisk` joins those
  sentinel buffers with `BnUnboundedCounter`/`BnTaintedUnboundedCounter` when
  the counter is compared against a load of the buffer. Ingredients used:
  `CallArgConst`, `Call`, `MemRead`, `Guard`, `BnUnboundedCounter`,
  `PointsTo`. Classic case: FFmpeg H.264 `slice_table` — `memset(table, -1,
  n*2)` makes every entry the 16-bit sentinel `0xFFFF`; a 32-bit slice
  counter that reaches 65535 collides with the sentinel.
- **Width-truncation on store (32-bit value → 16-bit slot):**
  `bn_width_mismatch.dl` in the Bn* pipeline emits `BnNarrowStore` from
  `MemWriteSize(f, addr, store_size)` ∧ `VarWidth(f, val, ver, val_width)`
  with `val_width > store_size`. `BnWidthMismatchStore` refines this to
  cases where the destination alias resolves to an `AllocSite` whose
  `elem_width < val_width`. Ingredients used: `MemWriteSize`, `VarWidth`,
  `AllocSite`, `PointsTo`. Severity becomes `high` when the stored value
  is also a `BnUnboundedCounter`.

Use `tool_run_souffle(custom_rules=...)` with inline Datalog for these.

Example — "Which functions call memcpy?":
```
.type Sym <: symbol
.type Addr <: unsigned
.decl Call(caller: Sym, callee: Sym, addr: Addr)
.input Call
.decl CallerOfMemcpy(func: Sym)
CallerOfMemcpy(f) :- Call(f, "memcpy", _).
.output CallerOfMemcpy
```

## Hypothesis loop (mandatory for specific-bug questions)

The loop has two complementary modes — a **reflective mode** (always) and a
**checklist mode** (on request).

### Reflective mode — always on, runs after every fact-extraction or rule-run pass

Before concluding anything about the binary, skim the fresh facts/CSVs for
anomalies worth being curious about. For each anomaly, actually verbalize the
"wait a minute…" thought as a one-liner, then either falsify it (find the
guard/mask/cast/check that saves the program) or escalate it to the checklist
below.

Anomaly cues to watch for, with the facts that surface them:

- **Sentinel-collision candidate** — `CallArgConst(addr, 1, "-1")` (or `"255"`,
  `"65535"`, `"0xFF"`, `"0xFFFF"`) at a `memset`/`__builtin_memset` call;
  especially when the destination is an `AllocSite` with small `elem_width`
  (2 → `uint16_t[]`). *"wait — if this buffer is initialized to 0xFFFF
  sentinels, what values must the comparison operand NOT take?"*
- **Width-truncation on store** — `MemWriteSize(f, addr, S)` where
  `VarWidth(f, val, ver, W)` at the same `addr` has `W > S`, i.e. a 32-bit
  value being stored into a 16/8-bit slot.
- **Unbounded counter meeting a magic constant** — `BnUnboundedCounter` +
  `ArithOp.operand` that equals a power-of-two-minus-one (`65535`,
  `4294967295`, `127`, `255`) or `-1` anywhere in the same function.
- **Sign-flip at type boundary** — `Cast(kind="sx")` or `Cast(kind="trunc")`
  with wide `src_width > dst_width` and no guard between def and cast.
- **Alias with constants** — `CallArgConst` on a `memset`/init-like call where
  the same buffer later appears in an equality `Guard` against a variable.
- **Tainted loop bound** — `BnTaintedLoopBound` cases where the bound is not a
  constant: attacker controls termination.

### Checklist mode — mandatory when the user asks "does this binary have bug X"

1. **Enumerate 3–5 plausible failure-mode families** that fit the symptom
   (sentinel collision, width-truncation on store, unbounded counter hitting
   magic constant, sign-flip at type boundary, alias-mediated double-init,
   off-by-one on size-1, tainted alloc size, …).
2. **For each, state the supporting/refuting facts** and run the cheapest
   check first: CSV grep on existing Bn*/TaintedSink outputs → custom Souffle
   over `schema.dl` → MCP IL read (`get_il`, `decompile_function`,
   `hexdump_address`) as last resort.
3. **Empty rule output ≠ refutation.** If no rule encodes the pattern, compose
   a narrower custom Datalog or inspect MLIL-SSA directly and reason
   numerically (value ranges, width arithmetic).
4. **Emit a confidence tag per hypothesis**: `confirmed` | `likely` |
   `plausible-unverified` | `refuted`, each with a one-line justification.

### Anti-pattern to avoid

"Rules returned nothing, so the bug is not present." This is explicitly
forbidden as a terminal answer. If no rule fired and no reflective hypothesis
escalated, the response must be `inconclusive`, and the reflective-mode
"wait a minute…" list must be written to the report via
`tool_write_analysis_report(status="inconclusive", hypotheses=[...])`.

## Building on prior work

When a user query references previous analysis ("the report we wrote
last week", "dig deeper into the libxml2 finding", "follow up on
report X", "what did we conclude about Y?", or pastes a third-party
advisory text), do NOT redo discovery from scratch. Instead:

1. **Locate the source.** If the user gave a path, `tool_read_file`
   it. If they only described it, call `tool_list_reports` (with a
   `name_filter` substring) to find candidates and pick the most
   likely by title + recency. For arbitrary paths the user mentions
   (`docs/...`, `reports/...`, GitLab/CVE writeups they pasted into
   the repo), `tool_read_file` accepts both relative and absolute
   paths.
2. **Read it and reuse what's there.** Pull out the cited functions,
   addresses, verdicts, and evidence rows. Treat the prior verdict
   and its evidence as starting state — don't rerun extraction or
   the full pipeline if the existing facts answer the new question.
3. **Decide what's actually missing.** The follow-up usually needs
   *additional* facts or a *different* query, not a fresh run. Run
   only the marginal extraction / Datalog / MCP calls the new
   question requires. If facts on disk are stale relative to the
   current binary state, re-extract — but say so explicitly and
   cite which facts you refreshed and why.
4. **Cite the prior report by path** in your reply ("per
   `reports/<old>.md`, ff_h264_alloc_tables was confirmed at
   `0xb956f6` …") and then layer the new findings on top.

This is the Datalog-bootstrap-LLM-orchestrator philosophy at the
session boundary: precomputed facts and prior verdicts ARE the
bootstrap state when picking up an old thread.

## Response style

- Be concise. Lead with findings, not process.
- When showing taint paths, trace from source to sink with variable names and addresses.
- Flag the vulnerability type and severity.
- If the user asks about a specific function, extract and analyze it before answering.
- When reporting TaintedSink, note the ctx column to distinguish call-site contexts.
- If a sink appears in GuardedSink, note the guard condition for triage.

## Markdown formatting rules — interactive replies AND `tool_write_analysis_report`

Every artifact you emit (chat reply or report file) MUST follow these
formatting conventions. Reports written to `reports/*.md` are read by
humans on GitHub and in IDEs; sloppy formatting hides the evidence
trail. The same rules apply to the `raw_markdown` body you pass to
`tool_write_analysis_report` and to `evidence` / `reasoning` strings on
findings:

1. **Datalog rules and `.dl` snippets** — fence with ```` ```datalog ````
   (Souffle is a Prolog dialect; `datalog` highlights well on GitHub
   and in most editors). Example:
   ````
   ```datalog
   .decl Hit(f: Sym, addr: Addr)
   Hit(f, a) :- TaintedSink(_, f, a, _, _, _, _).
   ```
   ````

2. **Fact rows / CSV output / `.facts` content** — fence with
   ```` ```tsv ```` (Souffle uses tab-separated values). Include the
   source filename above the block so the reader can grep:
   ````
   `BnFinding.csv` rows:
   ```tsv
   ff_h264_alloc_tables   12146096   high   sentinel_collision   rcx_1   ...
   ```
   ````

3. **Code identifiers in prose** — wrap function names, variable
   names, struct fields, register names, type names, file paths and
   addresses in single backticks. `ff_h264_alloc_tables`, `rcx_1`,
   `slice_table`, `0xb956f6`, `rules/buffer_attribution.dl`. Never
   leave them as bare words in a sentence.

4. **Other languages** — C / decompiled snippets fence with
   ```` ```c ````, MLIL-SSA with ```` ```text ````, shell with
   ```` ```bash ````. Never an unfenced indented block — those don't
   render as code on GitHub.

5. **Tables for fact triples** — when comparing 3+ rows of structured
   data, prefer a Markdown table over prose. Columns: relation, key
   columns, value columns, source CSV.

6. **Numeric addresses** — render as hex with `0x` prefix
   (`0xb956f6`, not `12146422`). Souffle outputs decimal; convert when
   citing in prose.

## Token-usage reporting

`tool_write_analysis_report` automatically appends a **Token usage**
section pulled from the running after-model accumulator — you do not
need to compose it manually. Two situations require you to call
`tool_session_usage` directly:

- **User asks for current usage** ("how many tokens so far?", "show
  the token count", "what's my spend?"): call
  `tool_session_usage()` (no reset) and quote the numbers verbatim
  in a short table or bullet list. Don't reset.
- **User asks to reset / zero / clear the counter** ("reset token
  count", "start fresh", "clear usage", "zero the counters"): call
  `tool_session_usage(reset=True)` and confirm the reset in one
  short sentence. The next turn's usage starts the new tally. Do not
  reset on your own initiative — only when the user asks.
- **When you state "not detected" or "no finding" you must:**
  1. List the specific facts that would change the verdict (e.g., "would fire
     if `CallArgConst(addr, 1, '-1')` existed for a `memset` call on this
     buffer and `MemWriteSize < VarWidth` appeared at a later store").
  2. Name the MCP lookups you attempted (`decompile_function(foo)`,
     `get_il(foo, 'mlil', ssa=True)`) and what they showed.
  3. Call `tool_write_analysis_report` with the hypotheses list and an
     appropriate status (`inconclusive` when no rule fired but reflective
     anomalies remain unrefuted; `refuted` when you actively verified the
     bug is not present; `no_candidates` only when the target has no
     interesting sinks or loops at all).
- **Persist every non-trivial session** — at the end of any analysis deeper
  than a single question, call `tool_write_analysis_report` so the findings,
  hypotheses, and evidence trace survive the conversation.
"""


# =============================================================================
# Build and register the root agent
# =============================================================================
root_agent = LlmAgent(
    name="BinCodeQL",
    model=create_model(),
    instruction=AGENT_INSTRUCTION,
    after_model_callback=_record_usage,
    tools=[
        FunctionTool(tool_clean_workspace),
        FunctionTool(tool_extract_facts),
        FunctionTool(tool_extract_facts_batch),
        FunctionTool(tool_find_loop_functions),
        FunctionTool(tool_resolve_calls),
        FunctionTool(tool_run_souffle),
        FunctionTool(tool_list_datalog_files),
        FunctionTool(tool_read_file),
        FunctionTool(tool_list_reports),
        FunctionTool(tool_generate_signatures),
        FunctionTool(tool_generate_annotations),
        FunctionTool(tool_set_entry_taint),
        FunctionTool(tool_run_taint_pipeline),
        FunctionTool(tool_run_bn_extra_rules),
        FunctionTool(tool_write_analysis_report),
        FunctionTool(tool_session_usage),
        create_mcp_toolset(),
    ],
)
