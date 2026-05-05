# Entry-point selection prompt

You are deciding whether a function is an **attack-surface entry** for a
security analysis of a compiled binary. Your output controls which
function parameters get seeded as tainted in an interprocedural taint
analysis. Wrong answers degrade analysis precision in both directions:

- Marking too many functions as entries → taint reaches almost every
  function (high noise floor, useless precision filter).
- Missing real entries → taint never enters the relevant region of the
  binary (false negatives).

## Inputs you receive

For one candidate function `F` you will be given:

1. `F`'s name and the reason it was flagged as a candidate
   (`libc_input_caller` / `named_main` / `named_libfuzzer` /
   `named_parser_api`).
2. The list of `F`'s parameters with names and indices.
3. `F`'s HLIL pseudocode (via `decompile_function`).
4. The set of *other candidate functions* that call `F` directly.
5. The set of other candidate functions that `F` itself calls directly.

You may use Binary Ninja MCP tools (`get_xrefs_to`, `decompile_function`,
`list_imports`) to fetch additional context if needed.

## Decision

Return one of:

- **`entry`** — `F` is a real attack-surface entry. Specify the parameter
  indices that carry attacker-controlled data.
- **`internal`** — `F` is an internal helper that is itself called by
  another candidate function. Skip; taint will propagate from the
  upstream entry.
- **`init-only`** — `F` is reachable from program startup but does not
  process attacker input from the binary's runtime input stream
  (e.g., `xmlInitializeCatalog` reads `getenv("XML_CATALOG_FILES")` at
  startup but does not handle per-invocation attacker input). Optional:
  flag for separate `entry:env` seeding rather than mainline `entry`.
- **`unreachable`** — `F` exists in the binary but is unreachable in
  this binary's runtime (e.g., FTP code present but `--network` flag
  not used by the target tool, dead code path).

## Decision rules

1. If `F` is named `main`/`wmain`/`WinMain` → **`entry`**, parameter 1
   (argv) is the attacker surface; parameter 0 (argc) is metadata.
2. If `F` is `LLVMFuzzerTestOneInput` → **`entry`**, parameter 0 is
   the byte buffer.
3. If `F` has *any* caller in the candidate set, default to
   **`internal`** unless the candidate-caller is itself classified
   `init-only` or `unreachable` (in which case re-evaluate).
4. If `F` is named in the public API of the library (e.g., `xmlReadFile`,
   `TIFFOpen`, `png_read_image`) AND has no candidate-caller in the
   binary → **`entry`**, parameter holding the input data is the
   attacker surface. Note: if the binary is xmllint-style (a CLI that
   itself calls these APIs from main), the public API is reachable from
   main and should be marked `internal`.
5. If `F` calls a libc input fn but `F` itself is only reachable from
   program init (no runtime caller chain from main) → **`init-only`**.

## Output format

Return JSON:

```json
{
  "function": "<name>",
  "decision": "entry" | "internal" | "init-only" | "unreachable",
  "tainted_params": [<idx>, ...],          // only if decision = "entry"
  "rationale": "<one sentence>",
  "evidence": [
    "<concrete evidence row, e.g. 'main called by libc_start_main'>"
  ]
}
```

`tainted_params` is a list of integers; for `main` typically `[1]`;
for a parser-API entry typically the index of the file/buffer/fd
parameter (`xmlReadFile.filename` = 0, `xmlReadMemory.buffer` = 0,
etc.). Do NOT include format/encoding/options parameters even though
they are formally attacker-typed — those are typically constants set
by the binary itself, not attacker input.

`evidence` should cite the concrete observation that drives the
decision (e.g., the caller-set, a specific HLIL line). One short item
per evidence row; avoid prose narrative.

## What NOT to do

- Do not mark every public API as `entry` reflexively. For a CLI tool
  like xmllint, `main` is the only true entry; the public APIs are
  internal callees of `main`.
- Do not mark `getenv`-only callers as full `entry` — environment
  variables are an axis-3-style surface (administrator-set, often
  static) distinct from per-invocation attacker input. Use
  `init-only` for these.
- Do not invent attacker scenarios. If `F`'s call chain from program
  start passes through arguments the binary itself controls (e.g.,
  hardcoded paths in `xmllint`'s catalog setup), that is not attacker
  surface for *this binary*.
