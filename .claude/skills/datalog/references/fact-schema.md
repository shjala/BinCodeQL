# BinCodeQL Fact Schema (v1)

Complete relation definitions for the BinCodeQL fact database. Facts are extracted from Binary Ninja MLIL-SSA output and MCP structural tools.

## Type Definitions

```datalog
.type Address <: unsigned    // instruction/function address (hex → uint)
.type Symbol <: symbol       // interned strings: function names, variable names
.type Version <: unsigned    // SSA version number
.type ArgIndex <: unsigned   // argument position (0-indexed)
.type Offset <: number       // memory offset (can be negative)
.type Size <: unsigned       // memory access size in bytes
.type MemVer <: unsigned     // memory SSA version
```

## Extracted Facts (from MCP tools)

### Structural (from MCP directly)

```datalog
// From list_methods
.decl Function(name: Symbol, addr: Address)
.input Function

// From get_entry_points
.decl EntryPoint(addr: Address)
.input EntryPoint

// From list_imports
.decl Import(name: Symbol, addr: Address)
.input Import

// From list_exports
.decl Export(name: Symbol, addr: Address)
.input Export

// From get_stack_frame_vars
.decl StackVar(func: Symbol, name: Symbol, offset: Offset, size: Size, type_name: Symbol)
.input StackVar
```

### Parsed from MLIL-SSA

```datalog
// Variable definition: LHS of any assignment
.decl Def(func: Symbol, var: Symbol, ver: Version, addr: Address)
.input Def

// Variable use: any SSA variable reference on RHS
.decl Use(func: Symbol, var: Symbol, ver: Version, addr: Address)
.input Use

// Function call (direct)
.decl Call(caller_func: Symbol, callee_func: Symbol, call_addr: Address)
.input Call

// Argument passed at a call site
// param_name may be "_" if BN doesn't have type info
.decl ActualArg(call_addr: Address, arg_idx: ArgIndex, param_name: Symbol, var: Symbol, ver: Version)
.input ActualArg

// Return value of a function
.decl ReturnVal(func: Symbol, var: Symbol, ver: Version)
.input ReturnVal

// SSA phi node: def_ver is the version being defined, src_ver is one incoming version
.decl PhiSource(func: Symbol, var: Symbol, def_ver: Version, src_var: Symbol, src_ver: Version)
.input PhiSource

// Memory load: var#ver = [base#base_ver + offset].size @ mem#mem_ver
.decl MemRead(func: Symbol, addr: Address, base_var: Symbol, base_ver: Version, offset: Offset)
.input MemRead

// Memory store: target:offset.size @ mem#mem_in -> mem#mem_out = value
.decl MemWrite(func: Symbol, addr: Address, target: Symbol, offset: Offset, mem_in: MemVer, mem_out: MemVer)
.input MemWrite

// Address-of expression: var#ver = &symbol_target
.decl AddressOf(func: Symbol, var: Symbol, ver: Version, symbol_target: Symbol)
.input AddressOf

// Control flow edge within a function
.decl CFGEdge(func: Symbol, from_addr: Address, to_addr: Address)
.input CFGEdge
```

## Derived Relations (computed by Datalog rules)

These are NOT extracted — they are computed by rule modules.

```datalog
// Call graph reachability (rules/core.dl)
.decl Reaches(caller: Symbol, callee: Symbol)

// Intraprocedural def-use (rules/core.dl)
// Trivial in SSA: same (var, version) = same definition
.decl DefUsePair(func: Symbol, var: Symbol, ver: Version, def_addr: Address, use_addr: Address)

// Taint tracking (rules/taint.dl)
.decl TaintVar(func: Symbol, var: Symbol, ver: Version)
.decl TaintedSink(func: Symbol, call_addr: Address, callee: Symbol, arg_idx: ArgIndex)

// Resource lifecycle (rules/resource.dl)
.decl Allocated(func: Symbol, var: Symbol, ver: Version, addr: Address)
.decl Freed(func: Symbol, var: Symbol, ver: Version, addr: Address)
.decl PotentialUAF(func: Symbol, use_addr: Address, free_addr: Address, var: Symbol)
```

## Fact File Format

Each relation is stored as a tab-separated file with no header row. File naming: `<RelationName>.facts` (matching the relation name exactly).

Example `Function.facts`:
```
main	4198400
parse_header	4199456
process_input	4200192
```

Example `Def.facts`:
```
parse_header	rax	1	4199460
parse_header	var_88	1	4199472
parse_header	mem	2	4199488
```

Example `Call.facts`:
```
main	parse_header	4198432
parse_header	memcpy	4199520
parse_header	strlen	4199504
```

## Notes

- Addresses are stored as decimal unsigned integers in fact files (Python: `int("0x40a8b0", 16) → 4237488`)
- Symbol columns use the raw name from MLIL-SSA (e.g., `rax`, `var_88`, `mem`, `parse_header`)
- SSA versions are 0-indexed (version 0 = function entry / initial state)
- `mem` is a special SSA variable tracking memory state — loads read it, stores define new versions
- Phi nodes generate one `PhiSource` tuple per incoming edge
- The `param_name` in `ActualArg` is `_` when BN lacks type info for the callee
