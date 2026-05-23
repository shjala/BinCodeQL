# MLIL-SSA Grammar Reference

Binary Ninja's MLIL-SSA output from `get_il(function_name, "mlil", true)` follows a regular line-oriented format.

## Line Format

```
<line_num> @ <hex_addr>  <statement>
```

Example: `30 @ 0040a8e4  result#2, mem#3 = TIFFVGetFieldDefaulted(tif: tif#0, tag: tag#0, ap: rdx_1#1) @ mem#2`

## SSA Variable Format

```
name#version           — e.g., rax#1, var_88#0, mem#3
name:offset.size       — subfield access, e.g., val#1:0.d, zmm1#4:0.d
```

- **name**: letters, digits, underscore, colon (e.g., `cond:0`, `var_88_1`, `fsbase`)
- **version**: non-negative integer
- **mem**: special SSA variable tracking memory state

## Statement Types

Parse order matters — match most specific patterns first to avoid misclassification.

### 1. Skip Lines
```
Pattern:  noreturn
          { Does not return }
Action:   Skip (or emit NoReturn marker)
```

### 2. Phi Node
```
Pattern:  var#N = ϕ(x#A, y#B, ...)
Regex:    (\S+)#(\d+)\s*=\s*ϕ\((.+)\)
Facts:    Def(func, var, N, addr)
          PhiSource(func, var, N, x, A) for each source
Example:  zmm1#5 = ϕ(zmm1#1, zmm1#2, zmm1#4)
```

### 3. Memory Write (Store)
```
Pattern:  target:off.sz @ mem#J -> mem#K = value
Regex:    (.+)\s*@\s*mem#(\d+)\s*->\s*mem#(\d+)\s*=\s*(.+)
Facts:    MemWrite(func, addr, target, off, J, K)
          Def(func, mem, K, addr)
          Use(func, mem, J, addr)
Key:      The -> arrow distinguishes stores from loads
Example:  ap:0.d @ mem#0 -> mem#1 = 0x10
```

### 4. Unconditional Goto
```
Pattern:  goto L @ target_addr
Regex:    goto\s+(\d+)\s*@\s*(0x[0-9a-f]+)
Facts:    CFGEdge(func, current_addr, target_addr)
Example:  goto 7 @ 0x40a954
```

### 5. Conditional Branch
```
Pattern:  if (cond) then L1 [@ addr1] else L2 @ addr2
Regex:    if\s*\((.+)\)\s*then\s+(\d+)(?:\s*@\s*(0x[0-9a-f]+))?\s+else\s+(\d+)\s*@\s*(0x[0-9a-f]+)
Facts:    CFGEdge(func, addr, addr1), CFGEdge(func, addr, addr2)
          Use(func, ...) for each SSA var in condition
Note:     "then" target may or may not have @ addr
Example:  if (cond:0#1) then 3 else 4 @ 0x40a936
          if (temp0#1 != temp1#1) then 36 @ 0x40a910 else 38 @ 0x40a90f
```

### 6. Return
```
Pattern:  return expr
Regex:    return\s+(.+)
Facts:    ReturnVal(func, var, ver) for the returned variable
          Use(func, ...) for each SSA var in expr
Example:  return result#2
          return val#1:0.d
```

### 7. Function Call (with return value)
```
Pattern:  ret#N, mem#M = callee(param: arg#K, ...) @ mem#J
Regex:    ((?:\S+#\d+,\s*)*\S+#\d+)\s*=\s*(\w+)\((.+)\)\s*@\s*mem#(\d+)
Facts:    Call(func, callee, addr)
          Def(func, ret, N, addr)
          Def(func, mem, M, addr)
          ActualArg(addr, idx, param_name, arg, K) per argument
          Use(func, mem, J, addr)
Note:     Arguments can be NAMED (param: var#ver) when BN has type info
Example:  result#2, mem#3 = TIFFVGetFieldDefaulted(tif: tif#0, tag: tag#0, ap: rdx_1#1) @ mem#2
```

### 8. Void/NoReturn Call
```
Pattern:  mem#M = callee(args) @ mem#J
Regex:    mem#(\d+)\s*=\s*(\w+)\((.*)\)\s*@\s*mem#(\d+)
Facts:    Call(func, callee, addr)
          Def(func, mem, M, addr)
          ActualArg(addr, idx, ...) per argument
Example:  mem#4 = __stack_chk_fail() @ mem#3
```

### 9. Address-Of
```
Pattern:  var#N = &symbol
Regex:    (\S+)#(\d+)\s*=\s*&(\w+)
Facts:    Def(func, var, N, addr)
          AddressOf(func, var, N, symbol)
Example:  rdx_1#1 = &ap
          var_d0#1 = &arg_8
```

### 10. Memory Read (Load)
```
Pattern:  [base#M + offset].size @ mem#K  (appears in RHS of assignment)
Regex:    \[.+\]\.\w+\s*@\s*mem#\d+  (detect in expression)
Facts:    MemRead(func, addr, base, M, offset)
          Use(func, mem, K, addr)
          Use(func, base, M, addr)
Example:  rax#1 = [fsbase#0 + 0x28].q @ mem#0
```

### 11. Plain Assignment (fallback)
```
Pattern:  var#N = expr   (anything not matched above)
Regex:    (.+)\s*=\s*(.+)
Facts:    Def(func, LHS_var, LHS_ver, addr)
          Use(func, ...) for each SSA var in RHS
Example:  var_a8#1 = rdx#0
          cond:0#1 = val#0 > 3.4028234663852886e+38
```

## Global SSA Variable Extraction

To find all Use facts in any expression, apply this regex to the RHS/condition/argument:

```
(?<!\&)(\w+(?::\w+)?)#(\d+)
```

- Negative lookbehind `(?<!\&)` avoids treating `&symbol` as a use
- Captures: group 1 = variable name (may contain `:` for subfields), group 2 = version

## Named Argument Parsing

Inside call argument lists, arguments may be named:

```
(\w+):\s*(\w+(?::\w+)?)#(\d+)
```

- group 1 = parameter name (from callee type info)
- group 2 = argument variable name
- group 3 = argument version

When BN lacks type info, arguments appear as positional: `var#N, var2#M`

## Edge Cases to Watch For

- **Indirect calls**: `var#N = [ptr#M](args)` — function pointer / vtable calls
- **Tail calls**: may appear as `tailcall func(args)` or `goto func`
- **Switch/jump tables**: multiple goto targets or explicit jump table syntax
- **SIMD operations**: operations on vector registers (zmm, xmm, ymm)
- **Intrinsics**: `__builtin_*` or architecture-specific operations
- **Deeply nested expressions**: address computations like `[rax#1 + rcx#2 * 4 + 0x10].d`
