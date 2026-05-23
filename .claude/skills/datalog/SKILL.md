---
name: datalog
description: "Souffle Datalog for binary analysis. Use this skill when writing, debugging, or reasoning about Datalog rules and fact schemas for binary program analysis — especially rules over MLIL-SSA facts extracted from Binary Ninja. Trigger on: writing .dl files, Souffle syntax questions, defining Datalog relations for binaries, composing taint/reachability/lifecycle queries, fact schema design, debugging Souffle errors, or any task involving Datalog-based reasoning over disassembled code."
---

# Souffle Datalog for Binary Analysis

This skill covers writing Souffle Datalog programs for the BinCodeQL project — a query engine that reasons over facts extracted from Binary Ninja's MLIL-SSA intermediate representation.

## Souffle Syntax Quick Reference

### Type Declarations

Souffle uses `.type` for custom types and `.decl` for relation declarations.

```datalog
// Subtypes (recommended — catches cross-relation mistakes)
.type Address <: unsigned
.type Symbol <: symbol
.type Version <: unsigned
.type ArgIndex <: unsigned
.type Offset <: number

// Relations use typed columns
.decl Function(name: Symbol, addr: Address)
.decl Def(func: Symbol, var: Symbol, ver: Version, addr: Address)
```

### Rules

```datalog
// Basic rule: head :- body.
Reaches(a, b) :- CallEdge(a, b).
Reaches(a, c) :- Reaches(a, b), CallEdge(b, c).

// Negation (requires stratification — negated relation must be fully computed first)
Unused(f) :- Function(f, _), !CallEdge(_, f).

// Disjunction (multiple rules for same head)
InputSource(f, v, ver) :- Call(f, "read", addr), ActualArg(addr, 0, _, v, ver).
InputSource(f, v, ver) :- Call(f, "recv", addr), ActualArg(addr, 1, _, v, ver).
```

### IO Directives

```datalog
// Input facts from TSV files (one file per relation in the fact directory)
.input Function(IO=file, filename="Function.facts", delimiter="\t")
.input Def(IO=file, filename="Def.facts", delimiter="\t")

// Output query results
.output TaintedSink(IO=file, filename="TaintedSink.csv", delimiter="\t")

// Shorthand (uses relation name as filename, tab-delimited)
.input Function
.output TaintedSink
```

### Aggregation and Arithmetic

```datalog
// Count, min, max, sum
CallCount(f, n) :- f = caller, n = count : CallEdge(caller, _).

// Bounded recursion isn't needed — Souffle does fixed-point automatically
// but watch for Cartesian blowups in joins
```

### Components (Modules)

```datalog
.comp TaintAnalysis {
    .decl Source(func: Symbol, var: Symbol, ver: Version)
    .decl Sink(func: Symbol, addr: Address, arg: ArgIndex)
    .decl Flow(src_f: Symbol, src_v: Symbol, dst_f: Symbol, dst_v: Symbol, dst_ver: Version)

    // Rules here...
}

// Instantiate
.init taint = TaintAnalysis
```

### Important Souffle Behaviors

- **Fixed-point evaluation**: recursive rules iterate until no new tuples. No explicit loop needed.
- **Stratification**: negation and aggregation require the negated/aggregated relation to be fully computed in a prior stratum. Souffle checks this at compile time.
- **No duplicates**: relations are sets, not bags. Same tuple inserted twice = stored once.
- **Symbol type**: interned strings. Use for function names, variable names.
- **Unsigned type**: non-negative integers. Use for addresses (hex values are just numbers).
- **Number type**: signed integers. Use for offsets that can be negative.

## Running Souffle

```bash
# Interpreted mode (faster startup, good for interactive/small programs)
souffle -F fact_dir/ -D output_dir/ program.dl

# Compiled mode (compiles to C++ first — faster execution on large fact sets)
souffle -F fact_dir/ -D output_dir/ -c program.dl

# With parallel threads
souffle -F fact_dir/ -D output_dir/ -j4 program.dl

# Show warnings (useful for debugging unused relations)
souffle -F fact_dir/ -D output_dir/ -w program.dl
```

Key flags:
- `-F <dir>`: fact directory (where .facts/.csv input files live)
- `-D <dir>`: output directory (where output relations are written)
- `-c`: compile to C++ before running (slow start, fast execution)
- `-j <N>`: number of parallel threads
- `-p <file>`: profile output (for performance debugging)

## BinCodeQL Fact Schema

Facts are extracted from Binary Ninja MLIL-SSA output. Read `references/fact-schema.md` for the complete schema with all columns and types.

### Core Relations (extracted)

| Relation | Source | Purpose |
|----------|--------|---------|
| `Function(name, addr)` | `list_methods` | All functions in the binary |
| `Import(name, addr)` | `list_imports` | Imported symbols (libc, etc.) |
| `Export(name, addr)` | `list_exports` | Exported symbols |
| `Def(func, var, ver, addr)` | MLIL-SSA LHS | Variable definition site |
| `Use(func, var, ver, addr)` | MLIL-SSA RHS | Variable use site |
| `Call(caller, callee, addr)` | MLIL-SSA call stmt | Function call edge |
| `ActualArg(call_addr, idx, param, var, ver)` | MLIL-SSA call args | Argument at call site |
| `ReturnVal(func, var, ver)` | MLIL-SSA return | Return value |
| `PhiSource(func, var, def_ver, src_var, src_ver)` | MLIL-SSA phi | SSA phi node sources |
| `MemRead(func, addr, base, base_ver, offset)` | MLIL-SSA load | Memory load |
| `MemWrite(func, addr, target, offset, mem_in, mem_out)` | MLIL-SSA store | Memory store |
| `AddressOf(func, var, ver, target)` | MLIL-SSA `&` | Address-of expression |
| `CFGEdge(func, from_addr, to_addr)` | MLIL-SSA branch/goto | Control flow edge |

### SSA Property

The key insight: in MLIL-SSA, `Def(f, x, 3, ...)` and `Use(f, x, 3, ...)` refer to the *same definition* because SSA versioning is unique per definition. This makes def-use chains trivial:

```datalog
// In SSA, same (var, version) = same definition. No reaching-definition analysis needed.
DefUsePair(func, var, ver, def_addr, use_addr) :-
    Def(func, var, ver, def_addr),
    Use(func, var, ver, use_addr).
```

## Common Binary Analysis Patterns

### 1. Call Graph Reachability

```datalog
Reaches(a, b) :- Call(_, a, _), Call(_, b, _), a = b.  // reflexive (wrong)
// Correct:
Reaches(a, b) :- Call(a, b, _).
Reaches(a, c) :- Reaches(a, b), Call(b, c, _).

// "Can main reach dangerous_func?"
.output Reaches
// Then check: Reaches("main", "dangerous_func") in output
```

### 2. Taint Flow (Input to Sink)

```datalog
// Sources: return values from input functions
TaintVar(func, var, ver) :-
    Call(func, callee, addr),
    Import(callee, _),
    DangerousInput(callee),
    Def(func, var, ver, addr).   // the return value def

// Propagation through SSA assignments
TaintVar(func, var2, ver2) :-
    TaintVar(func, var1, ver1),
    Use(func, var1, ver1, addr),
    Def(func, var2, ver2, addr).

// Propagation through phi nodes
TaintVar(func, var, def_ver) :-
    TaintVar(func, src_var, src_ver),
    PhiSource(func, var, def_ver, src_var, src_ver).

// Interprocedural: caller arg → callee parameter
TaintVar(callee, param_var, param_ver) :-
    TaintVar(caller, arg_var, arg_ver),
    Call(caller, callee, call_addr),
    ActualArg(call_addr, idx, _, arg_var, arg_ver),
    // Need formal parameter mapping (callee's first Def of param at entry)
    FormalParam(callee, idx, param_var, param_ver).

// Sink detection
TaintedSink(func, call_addr, callee, idx) :-
    TaintVar(func, var, ver),
    Call(func, callee, call_addr),
    ActualArg(call_addr, idx, _, var, ver),
    DangerousSink(callee, idx).

// Configuration: which functions are sources and sinks
DangerousInput("read").
DangerousInput("recv").
DangerousInput("fread").
DangerousSink("memcpy", 2).   // size argument
DangerousSink("strcpy", 1).   // source argument
DangerousSink("sprintf", 2).  // format argument
DangerousSink("system", 0).   // command argument
```

### 3. Resource Lifecycle (Use-After-Free)

```datalog
// Track allocations
Allocated(func, var, ver, addr) :-
    Call(func, callee, addr),
    AllocFunc(callee),
    Def(func, var, ver, addr).

// Track frees
Freed(func, var, ver, addr) :-
    Call(func, callee, addr),
    FreeFunc(callee),
    ActualArg(addr, 0, _, var, ver).

// Use-after-free: a variable that was freed is later used
// (simplified — real check needs path sensitivity or CFG ordering)
PotentialUAF(func, use_addr, free_addr, var) :-
    Freed(func, var, ver_free, free_addr),
    Use(func, var, ver_use, use_addr),
    ver_use >= ver_free,  // approximate: later version used after free
    use_addr != free_addr.

AllocFunc("malloc"). AllocFunc("calloc"). AllocFunc("realloc").
FreeFunc("free").
```

### 4. Struct Field Access Tracking

```datalog
// Who writes to offset 0x10 of a buffer?
FieldWrite(func, addr, target, 0x10) :-
    MemWrite(func, addr, target, 0x10, _, _).

// Who reads from it?
FieldRead(func, addr, base, 0x10) :-
    MemRead(func, addr, base, _, 0x10).
```

### 5. Shortest Call Path (with path length)

```datalog
PathLen(a, b, 1) :- Call(a, b, _).
PathLen(a, c, n+1) :- PathLen(a, b, n), Call(b, c, _), n < 20.  // depth bound

ShortestPath(a, c, m) :- m = min n : PathLen(a, c, n).
```

## Common Mistakes

1. **Forgetting `.input` directives** — Souffle won't read fact files unless told to. Every base relation needs `.input`.

2. **Cartesian joins** — A rule like `R(x, y) :- A(x), B(y).` produces |A|×|B| tuples. Always join on shared variables.

3. **Unstratifiable negation** — You can't negate a relation that depends (transitively) on the rule's own head. Souffle will report an error.

4. **Type mismatches** — If you declare `Def(func: Symbol, ...)` but try to join with a relation using `unsigned` for the same column, Souffle will reject it. Keep types consistent.

5. **Missing base cases in recursion** — Every recursive rule needs a non-recursive base case. `Reaches(a,c) :- Reaches(a,b), Edge(b,c).` alone won't produce anything — you need `Reaches(a,b) :- Edge(a,b).` as the base.

6. **Address representation** — MLIL-SSA addresses are hex strings in MCP output but should be stored as unsigned integers in Souffle. Convert during extraction (`int("0x40a8b0", 16)` in Python).

## MLIL-SSA Statement Types

When extending the fact schema or debugging extraction, refer to the 10 MLIL-SSA statement types. Read `references/mlil-ssa-grammar.md` for the full grammar with regex patterns.

Quick summary:
| Type | Pattern | Facts Generated |
|------|---------|----------------|
| Assignment | `var#N = expr` | Def + Uses from RHS |
| Conditional | `if (cond) then L1 else L2` | CFGEdge ×2 + Uses |
| Goto | `goto L @ addr` | CFGEdge |
| Phi | `var#N = ϕ(x#1, x#2)` | Def + PhiSource per source |
| Return | `return expr` | ReturnVal + Uses |
| Call | `ret#N, mem#M = func(args) @ mem#J` | Call + Def + ActualArg + Use |
| MemRead | `var#N = [base + off].sz @ mem#K` | MemRead + Def + Use |
| MemWrite | `tgt:off @ mem#J -> mem#K = val` | MemWrite + Def(mem) + Use |
| AddressOf | `var#N = &symbol` | Def + AddressOf |
| NoReturn | `noreturn` | skip or NoReturn marker |

## Reference Files

- `references/fact-schema.md` — Complete fact schema with all column types, IO directives, and example .facts file format
- `references/mlil-ssa-grammar.md` — Full MLIL-SSA grammar with regex patterns for each statement type
