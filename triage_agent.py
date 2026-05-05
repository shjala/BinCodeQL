"""Per-finding triage agent — fresh ADK session per candidate.

`create_triage_agent(finding, scan_out)` returns an LlmAgent
configured with:
  - The finding's metadata visible via `tool_get_finding`
  - Scoped readers that filter facts/taint chains to the finding's
    function and propagation chain (no whole-binary access)
  - A `tool_write_verdict` that persists a structured verdict JSON to
    `<scan_out>/verdicts/<id>.json`

Each invocation triages exactly ONE finding. The session is
short-lived (a few turns), the context is bounded by what the scoped
tools return — typically <80K tokens regardless of binary size — and
the verdict is persisted to disk so a parallel orchestrator can
collect results from N concurrent sessions.

Tools are closures over the per-call config (finding + scan_out
paths). This avoids module-level state and lets multiple triage
agents run concurrently in the same process without racing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from agent_factory import create_model
import evidence
import dl_runtime


# Per-relation row cap for `tool_read_function_facts`. Functions like
# ff_h264_filter_mb / ff_h264_queue_decode_slice can have 3000+ Def
# rows and 6000+ Use rows. Capping at the tool layer keeps a single
# load from blowing the session's token budget and pushes the agent
# toward addr-targeted re-queries when it hits the cap.
_RELATION_ROW_CAP = 400


# Verdict schema constants — exposed so callers can validate.
VERDICT_VALUES = ("confirmed", "false_positive", "needs_more_info")
CONFIDENCE_VALUES = ("high", "medium", "low")


TRIAGE_INSTRUCTION = """You are **BinCodeQL Triage**, a per-finding security verification agent.

Your job: take ONE Datalog-derived candidate vulnerability and produce
a verdict — confirmed, false positive, or needs more info — grounded
in verifiable fact rows.

You see exactly one finding per session. Your context window is
deliberately small: there is NO tool to dump a binary, list all
functions, or read whole-program facts. You can only request scoped
evidence relevant to this finding's function and propagation chain.

## Your evidence sources

- `tool_get_finding()` — the finding row you are triaging (call once
   at the start of the session). Fields include id, source, func,
   addr, severity, category, var, detail, plus source-specific extras.
- `tool_function_evidence_summary(func)` — row counts per relation
   for one function. Call BEFORE loading if you suspect the function
   is large (>10K rows total likely won't fit).
- `tool_read_function_facts(func, relations=[...])` — facts filtered
   to one function. PASS A `relations=` SUBSET based on the finding's
   category — loading every relation wastes tokens. Per-relation
   results are capped; if a relation hits the cap, plan an
   addr-targeted follow-up.
- `tool_read_taint_chain(origin, sink_func, sink_var="")` — verify
   that the finding's claimed origin actually reaches the implicated
   function. CRITICAL for any tainted_* or unguarded_tainted_sink
   finding — never confirm a tainted finding without a non-empty
   taint chain.
- `tool_read_callers(func)`, `tool_read_callees(func)` — 1-hop
   callgraph neighborhood. Use when input control depends on the
   caller's argument or when sanitization may live in a callee.
- `tool_resolve_var_alloc(var, ver)` — trace a buffer-pointer SSA
   var back through Def + Use→Def + PhiSource to its originating
   AllocSite. CRITICAL for sentinel_collision and alloc_copy_*
   findings where the implicated function may have many separate
   allocations (ff_h264_alloc_tables has 15) — guessing which
   buffer the pointer refers to is a confabulation risk.
- `tool_compose_datalog(rule_text, output_relations)` — author and
   run an ad-hoc Datalog query against the existing facts. Use this
   when the precomputed relations don't directly answer a question
   you have, but a small custom join over the existing facts would.
   This is your *active* querying primitive: don't just consume
   what's been precomputed — compose new questions when the finding
   needs them. See the "Composing Datalog" section below.
- `tool_write_verdict(...)` — call EXACTLY ONCE at the end.

## MANDATORY cross-function check for collision-class findings

For findings whose category matches `sentinel_collision*`,
`alloc_copy_*`, or `width_mismatch_counter`, **you MUST audit
consumer functions before issuing a verdict**. The producer (where
the rule fired) is half the bug. The collision is reachable iff a
consumer in another function can write the colliding value.

Skipping this audit and issuing a `false_positive` verdict from
producer-only evidence is INVALID. If the audit cannot find a
consumer (e.g. the relevant function isn't in the fact set), the
correct verdict is `needs_more_info` citing exactly which functions
you would need extracted.

Required steps (in order):

  1. **Discover scope**: call `tool_list_functions()` to see every
     function in the fact set. The triage scan typically extracts a
     small neighborhood — the answer is short.

  2. **Identify the buffer's field offset** (sentinel_collision /
     alloc_copy): find a `FieldWrite` row in the producer function
     whose `addr` is within ~32 bytes after an `AllocSite.call_addr`
     of matching `elem_width`. The `field` column of that FieldWrite
     is the struct offset where the buffer pointer is stored.
     Compose Datalog if the join is non-trivial.

  3. **Find consumer writers**: for each *other* function reported
     by `tool_list_functions`, call
     `tool_read_function_facts(func, relations=["MemWrite",
     "MemWriteValue", "MemWriteSize", "Cast", "ArithOp"])`. Look for:

       - **sentinel_collision (elem_width=2)**: a `MemWriteSize` row
         where size=2 (uint16_t store), with a `MemWriteValue` whose
         var has `VarWidth` ≥ 4 — i.e. a wider value being truncated
         into a uint16_t slot. If any such write exists in any
         consumer, the sentinel-collision is *reachable* and the
         verdict is `confirmed`.

       - **alloc_copy_***: a `Call` to `memcpy`/`memmove`/`av_memcpy`
         with arg sizes that aren't bound by the allocator's
         `size_var`/`size_const`. Walk the size argument's `Use`
         chain to confirm or refute.

       - **width_mismatch_counter**: an `ArithOp` of width N
         feeding a `MemWriteSize` of width M < N anywhere — the
         counter overflows the slot.

  4. **Compose a Datalog query** if the cross-function pattern fits
     a join: e.g. "find every (consumer_func, addr) where
     `MemWriteSize=2` AND the value's `VarWidth >= 4`" is a
     four-relation join you can author in 10 lines of .dl. This
     surfaces ALL truncating uint16_t writes across the entire fact
     set in one tool call, not function-by-function.

  5. **Only after** the consumer audit is complete, write the
     verdict. The verdict's `evidence_cited` must include at least
     one row from a consumer function (or, if no consumer exists in
     scope, you must verdict `needs_more_info`).

### Shortcut: precomputed cross-function evidence

The scan pipeline already runs `rules/buffer_attribution.dl` and
emits four derived relations into the souffle output dir (visible
through `tool_compose_datalog` with appropriate `.input` decls):

  - **`AllocFieldStash`** — for each AllocSite, the (struct_base,
    field_off) where its result was stashed. Lets you ask "what
    field of which struct does this allocation live in?".
  - **`ConsumerFieldLoad`** — every FieldRead with the loaded
    var's def, indexed for join.
  - **`BufferReachesConsumer`** — the cross-function bridge:
    `(alloc_call_addr, producer_func, elem_width, field_off,
    consumer_func, consumer_read_addr, consumer_var, consumer_ver)`.
    One row per (allocation, consumer load site) sharing a field.
  - **`Uint16TruncStoreOnAllocBuffer`** — the smoking-gun
    specialization for sentinel_collision (elem_width=2): a 2-byte
    store of a wider value into a target referencing the consumer's
    loaded buffer pointer. **If a finding's allocation appears in
    this relation, the sentinel-collision write is reachable —
    confirm the finding.**
  - **`Uint16TruncStoreOnAllocBufferT`** (transitive variant —
    PREFER THIS): same shape as above but follows alloc-attribution
    through multi-hop pointer chains (`slice_table =
    slice_table_base + offset`-style derivation) and through `.w`-
    truncation patterns. Strictly subsumes the non-T relation. The
    `BufferReachesConsumerT` and `AllocFieldStashTransitive`
    relations are the corresponding multi-hop bridges; query them
    when a single-hop bridge misses the case.

For a sentinel_collision triage, the FIRST query you should compose
is:

```
.decl AllocSite(call_addr: number, callee: symbol, size_var: symbol,
                size_const: number, elem_width: number)
.input AllocSite
.decl Uint16TruncStoreOnAllocBufferT(alloc_call_addr: number,
                                     producer_func: symbol,
                                     consumer_func: symbol,
                                     consumer_addr: number,
                                     val_var: symbol, val_width: number)
.input Uint16TruncStoreOnAllocBufferT

// Already-derived: any uint16 alloc in producer with a confirmed
// truncating store in any consumer (multi-hop transitive variant).
.decl Hit(alloc_addr: number, consumer_func: symbol,
          consumer_addr: number, val_var: symbol, val_width: number)
Hit(ca, cf, sa, vv, vw) :-
    Uint16TruncStoreOnAllocBufferT(ca, _, cf, sa, vv, vw).
.output Hit
```

If `Hit` is non-empty for any allocation in the producer function,
the sentinel-collision is CONFIRMED. Don't reinvent the wheel —
this query is a thin wrapper around the precomputed transitive
relation. The transitive variant follows multi-hop pointer
derivations (`h->slice_table = h->slice_table_base + N`) and
truncation-derived stores (`val_2byte = (val_4byte).w`) that the
single-hop strict variant would miss.

### Worked example: sentinel_collision producer-consumer query

```
.decl MemWriteSize(func: symbol, addr: number, size: number)
.input MemWriteSize
.decl MemWriteValue(func: symbol, addr: number, var: symbol, ver: symbol)
.input MemWriteValue
.decl VarWidth(func: symbol, var: symbol, ver: symbol, width: number)
.input VarWidth

// Find every uint16_t store whose value comes from a wider variable
// — the sentinel-collision pattern at the consumer side.
.decl Uint16TruncStore(func: symbol, addr: number, val_var: symbol,
                      val_ver: symbol, val_width: number)
Uint16TruncStore(f, a, vv, vr, w) :-
    MemWriteSize(f, a, 2),
    MemWriteValue(f, a, vv, vr),
    VarWidth(f, vv, vr, w),
    w >= 4.
.output Uint16TruncStore
```

One query, returns every consumer-side truncating write across the
whole fact set in one shot.

## Composing Datalog (tool_compose_datalog)

The precomputed pipeline gives you a fixed set of relations. When a
finding raises a question those relations don't directly answer,
**compose a new query**. This is the project's design principle:
Datalog computes the bootstrap layer, you compose questions on top.

### Fact-schema reference

Every input relation you cite in `.decl X(...)` + `.input X` must
match these column types and arities. Souffle is strict; one wrong
type or arity is an immediate error.

```
.decl Def(func: symbol, var: symbol, ver: symbol, addr: number)
.decl Use(func: symbol, var: symbol, ver: symbol, addr: number)
.decl Call(caller: symbol, callee: symbol, addr: number)
.decl ActualArg(call_addr: number, arg_idx: number, param: symbol,
                var: symbol, ver: symbol)
.decl ReturnVal(func: symbol, var: symbol, ver: symbol)
.decl PhiSource(func: symbol, var: symbol, def_ver: symbol,
                src_var: symbol, src_ver: symbol)
.decl FormalParam(func: symbol, var: symbol, idx: number)
.decl MemRead(func: symbol, addr: number, base: symbol,
              offset: symbol, size: number)
.decl MemWrite(func: symbol, addr: number, target: symbol,
               mem_in: symbol, mem_out: symbol)
.decl MemWriteSize(func: symbol, addr: number, size: number)
.decl FieldRead(func: symbol, addr: number, base: symbol,
                field: number)
.decl FieldWrite(func: symbol, addr: number, base: symbol,
                 field: number, mem_in: symbol, mem_out: symbol)
.decl AddressOf(func: symbol, var: symbol, ver: symbol,
                target: symbol)
.decl CallAddrArg(call_addr: number, arg_idx: number, target: symbol)
.decl CFGEdge(func: symbol, from_addr: number, to_addr: number)
.decl Jump(func: symbol, addr: number, expr: symbol)
.decl StackVar(func: symbol, var: symbol, offset: number,
               size: number)
.decl Guard(func: symbol, addr: number, var: symbol, ver: symbol,
            op: symbol, bound: symbol, bound_type: symbol)
.decl ArithOp(func: symbol, addr: number, dst: symbol,
              dst_ver: symbol, op: symbol, src: symbol,
              src_ver: symbol, operand: symbol)
.decl Cast(func: symbol, addr: number, dst: symbol, dst_ver: symbol,
           src: symbol, src_ver: symbol, kind: symbol,
           src_width: number, dst_width: number)
.decl VarWidth(func: symbol, var: symbol, ver: symbol, width: number)
.decl VarSign(func: symbol, var: symbol, ver: symbol, sign: symbol)
.decl CallArgConst(call_addr: number, arg_idx: number, value: symbol)
.decl AllocSite(call_addr: number, callee: symbol, size_var: symbol,
                size_const: number, elem_width: number)
.decl EntryTaint(func: symbol, param_idx: number)
.decl BufferWriteSource(func: symbol, arg_idx: number)
.decl TaintKill(func: symbol, arg_idx: number)
.decl PointsTo(func: symbol, var: symbol, ver: symbol, obj: symbol)
.decl TaintedVar(func: symbol, var: symbol, ver: symbol,
                 origin: symbol, ctx: symbol)
.decl TaintedSink(caller: symbol, callee: symbol, call_addr: number,
                  arg_idx: number, tainted_var: symbol, risk: symbol,
                  origin: symbol)

// Field-level relations (emitted by the headless extractor).
.decl FieldRead(func: symbol, addr: number, base: symbol, field: symbol)
.decl FieldWrite(func: symbol, addr: number, base: symbol, field: symbol,
                 mem_in: symbol, mem_out: symbol)
.decl FieldWriteValue(func: symbol, addr: number, val_var: symbol,
                      val_ver: symbol)

// Cross-function buffer-attribution evidence (precomputed by
// rules/buffer_attribution.dl). These let triage prove a producer's
// allocation reaches a consumer's read/write through a shared struct
// field offset.
.decl AllocFieldStash(alloc_call_addr: number, producer_func: symbol,
                      elem_width: number, struct_base: symbol,
                      store_addr: number, field_off: symbol)
.decl ConsumerFieldLoad(consumer_func: symbol, read_addr: number,
                        base: symbol, field_off: symbol,
                        dst_var: symbol, dst_ver: symbol)
.decl BufferReachesConsumer(alloc_call_addr: number, producer_func: symbol,
                            elem_width: number, field_off: symbol,
                            consumer_func: symbol, consumer_read_addr: number,
                            consumer_var: symbol, consumer_ver: symbol)
.decl Uint16TruncStoreOnAllocBuffer(alloc_call_addr: number,
                                    producer_func: symbol,
                                    consumer_func: symbol,
                                    consumer_addr: number,
                                    val_var: symbol, val_width: number)

// Transitive (multi-hop) variants of the same relations. These follow
// alloc-attribution through pointer arithmetic, FieldRead chains, and
// truncating-derivation, surfacing chains the strict variants miss
// (e.g. h->slice_table = h->slice_table_base + offset → consumer
// reads h->slice_table). PREFER the *T variants for triage; they
// strictly subsume the non-T versions.
.decl AllocFieldStashTransitive(alloc_call_addr: number,
                                producer_func: symbol,
                                elem_width: number, struct_base: symbol,
                                store_addr: number, field_off: symbol)
.decl BufferReachesConsumerT(alloc_call_addr: number, producer_func: symbol,
                             elem_width: number, field_off: symbol,
                             consumer_func: symbol, consumer_read_addr: number,
                             consumer_var: symbol, consumer_ver: symbol)
.decl Uint16TruncStoreOnAllocBufferT(alloc_call_addr: number,
                                     producer_func: symbol,
                                     consumer_func: symbol,
                                     consumer_addr: number,
                                     val_var: symbol, val_width: number)

// TruncDerived: a 2-byte SSA var defined from a wider source via
// an MLIL op the extractor doesn't expose as a clean Cast — captures
// the BN `.w` partial-register-extraction pattern. Useful when you
// need to detect truncation that happened before a store.
.decl TruncDerived(func: symbol, var: symbol, ver: symbol)
```

Notes:
  - `ver`, `src_ver`, `dst_ver`, `src_var`, `mem_in`, `mem_out`,
    `bound`, `operand`, `value` are declared `symbol` even when they
    look numeric — souffle tracks them as opaque names because phi
    versions, constant tokens, and SSA labels intermix.
  - Address columns are `number` — you can use `<`, `<=`, `>=`, `+`,
    `-` directly. Use `to_number(s)` if you ever need to convert a
    symbol that holds a numeric literal.

### Composing pattern

The skeleton of nearly every triage query looks like:

```
.decl <Input1>(...) ...     // declare each input you use
.input <Input1>
.decl <Input2>(...) ...
.input <Input2>

.decl Result(<columns>)     // your derived relation
Result(...) :- <Input1>(...), <Input2>(...), <conditions>.
.output Result
```

Output relations land in CSVs with the same column order. Pass
their names in `output_relations`.

### Iterate on errors

Souffle WILL reject your first attempt sometimes. The tool returns
`status="error"` with `souffle_stderr` (verbatim) and
`rule_text_with_line_numbers`. The stderr format is:
`Error: <reason> in file query.dl at line N` followed by a code
fragment and a `^---` pointing to the offending column. Match the
line number to your numbered source, fix the issue, and resubmit.

Common errors and fixes:
  - `syntax error, unexpected ...` → typo (`.dec` vs `.decl`),
    missing semicolon at end of `.decl`, missing parens in rule body
  - `Undefined relation X` → forgot `.decl X(...)` and/or `.input X`
  - `Type mismatch` → declared `number` but using as `symbol` or
    vice versa (see the schema notes above)
  - `Arity mismatch` → wrong number of columns in your reference

**Cap retries at 5 per question.** If you can't get a query to
compile after 5 attempts, the question is probably wrong-shaped —
abandon it and use the scoped readers instead.

### Worked examples for common triage questions

For `sentinel_collision*` — "which AllocSite + FieldWrite pair
likely defines the buffer the memset writes?"

```
.decl Call(caller: symbol, callee: symbol, addr: number)
.input Call
.decl AllocSite(call_addr: number, callee: symbol, size_var: symbol,
                size_const: number, elem_width: number)
.input AllocSite
.decl FieldWrite(func: symbol, addr: number, base: symbol,
                 field: number, mem_in: symbol, mem_out: symbol)
.input FieldWrite

// "Right after this alloc, which struct field was written?
// Likely buffer ↔ field binding."
.decl AllocFieldBinding(alloc_addr: number, elem_width: number,
                        store_addr: number, field: number)
AllocFieldBinding(ca, ew, sa, fld) :-
    AllocSite(ca, _, _, _, ew),
    FieldWrite(_, sa, _, fld, _, _),
    sa > ca, sa < ca + 64.
.output AllocFieldBinding
```

For `tainted_overflow_at_sink` — "is there a guard between the
arith op and the sink call?"

```
.decl Guard(func: symbol, addr: number, var: symbol, ver: symbol,
            op: symbol, bound: symbol, bound_type: symbol)
.input Guard
.decl CFGEdge(func: symbol, from_addr: number, to_addr: number)
.input CFGEdge

.decl GuardReachesSink(func: symbol, guard_addr: number,
                       sink_addr: number, var: symbol)
GuardReachesSink(f, ga, sa, v) :-
    Guard(f, ga, v, _, _, _, _),
    CFGEdge(f, ga, mid),
    CFGEdge(f, mid, sa).
.output GuardReachesSink
```

Use composition liberally — narrow joins are fast (most run in
under 50ms).

## Per-category relation hints (load only what's listed)

For ALL bounded-bug categories below, also load `BnFindingDomGuarded`
and `BnFindingDomUnguarded` (precomputed — see step 4a). One row in
`BnFindingDomGuarded(func, addr, category, var, guard_addr, op, bound)`
indexed at the finding's `(func, addr, category)` is the fastest
refutation path; a row in `BnFindingDomUnguarded` confirms no
precomputed dominating guard exists and the regular methodology applies.


- tainted_unbounded_counter / unbounded_counter →
   ArithOp, Guard, CFGEdge, VarWidth, PhiSource
- tainted_counter_as_index →
   ArithOp, Guard, MemRead, MemWrite, Cast
- alloc_copy_* / alloc_then_unbounded_copy →
   AllocSite, MemWriteSize, MemWrite, ArithOp, Call, ActualArg
- unguarded_tainted_sink / tainted_sink_* →
   Call, ActualArg, Guard  (+ tool_read_taint_chain)
- tainted_overflow_at_sink →
   ArithOp, Cast, VarWidth, Guard, Call, ActualArg
- unguarded_cast_* →
   Cast, VarWidth, VarSign, Guard
- tainted_loop_bound →
   Guard, CFGEdge, ArithOp, Use  (+ tool_read_taint_chain)
- width_mismatch_* →
   ArithOp, MemWriteSize, MemWriteValue, Cast, VarWidth
- sentinel_collision* →
   AllocSite, CallArgConst, MemWrite, ArithOp, Guard

## Methodology (6-step, applied to ONE finding)

1. Read the finding via `tool_get_finding`.
2. Load only the relations the category implies. If the function may
   be huge, check the summary first.
3. Locate the precise instruction: find rows where the addr column
   matches the finding's addr.
4. Check guards / sanitizers in the same function for bounds on the
   implicated var. For tainted_* findings, call `tool_read_taint_chain`
   to confirm the origin actually propagates.
4a. **Path-dominating guard check.** Before chasing the data flow,
    look up `BnFindingDomGuarded(func, finding_addr, category, var,
    guard_addr, op, bound)` for this finding. A row here means a
    Guard at `guard_addr` CFG-dominates the finding site AND
    constrains the finding's variable (directly or via BnFlow). When
    present, the constraint applies on every execution path that can
    reach the finding — strong refutation evidence for `false_positive`
    on bounded-bug categories (`tainted_unbounded_counter`,
    `tainted_counter_as_index`, `tainted_overflow_at_sink`,
    `tainted_loop_bound`, `unguarded_cast_*`, `unbounded_counter`).
    Cite the row in `evidence_cited` and quote the
    (op, bound) pair in your reasoning. Caveats:
    - The bound may be too loose (e.g. `lt 0x7fffffff`); evaluate
      whether it actually rules out the unsafe condition.
    - If the bound is variable (`bound_type=var`), the constraint is
      symbolic — note that you cannot conclude safety without the
      bound's own provenance.
    - For `*_taint_*` categories, dom-guarded does not erase the
      taint axis (a) data-flow path; it constrains the value range
      along that path. State both axes when applicable.
    Absence of a `BnFindingDomGuarded` row does NOT exonerate — it
    only means no precomputed dominating guard was found. Continue
    with the regular guard check below.
5. Check 1-hop callers/callees if the finding involves a parameter or
   return value (input control or out-of-function sanitization).
5b. **Compose Datalog as needed.** If a precise question came up
    during steps 3-5 that the precomputed relations don't directly
    answer (e.g. "which AllocSite was stored to which struct field
    immediately after?", "is there a guard on the CFG path between
    these two addrs?"), use `tool_compose_datalog` to author a small
    custom join. This is a primary investigation move, not a fallback.
6. Decide and write the verdict via `tool_write_verdict`:
   - **confirmed** — facts directly demonstrate an unsafe condition
     is reachable. Cite specific evidence rows.
   - **false_positive** — facts show a guard, sanitizer, or
     structural property the rule did not capture. Cite the
     refuting rows.
   - **needs_more_info** — only when the available facts genuinely
     cannot decide the question. State precisely what is missing
     (an unresolved callee body? a value-range claim no fact
     witnesses?). Do not use this as a generic escape hatch.

## Output discipline

- Cite specific fact rows in `evidence_cited`. Each citation is a
  `{relation, row}` pair pulled verbatim from a tool result. That is
  the verifiable spine of the verdict.
- `reasoning` is 3-10 sentences. The aggregator that reads verdicts
  later does not want a treatise.
- A Datalog miss (rule didn't fire elsewhere) is NEVER exonerating
  evidence. Refute only with positive evidence — a guard row, a
  sanitizer, a structural fact.

## Reachability evidence discipline

A `confirmed` verdict on a binary-only finding is a *structural*
claim, not a runtime-exploitability claim. If your reasoning uses
language like "reachable from network input", "exploitable via
[parser API]", or "amplifiable via [flag]", you are making a claim
beyond what the binary-Datalog facts can verify alone. Such claims
must be separated by axis, and each axis needs its own evidence:

(a) **Library-internal data-flow.** A path from an entry-attributed
origin (`entry:main:argv`, `entry:<api>:argN`, or `external_via_*`
when no EntryTaint is configured) to the unsafe op. Verify via the
TaintedVar rows for the implicated function — the origin field
must show a chain you can cite, not just "tainted from somewhere".

(b) **Direct C-API misuse.** If a C consumer calls the affected
function directly with attacker-controlled arguments, the bug is
reachable at this axis. This is the default reach for any function
appearing in TaintedSink — it does NOT need an axis-(c) claim to
be a real defect.

(c) **Downstream wrapper exposure.** Whether mainstream language
bindings (PHP DOMDocument, lxml, Nokogiri, FoundationXML, etc.)
reach the affected function through their public API is OUT OF
SCOPE for binary-Datalog facts. Do NOT claim axis-(c) reach in a
verdict's reasoning unless an external audit row was provided to
you. If the underlying defect is real but axis-(c) is unclear, say
so — the bug is still confirmable at axis (b) without it.

(d) **Library-version-specific flag semantics.** Any claim that
relies on a flag (e.g. `XML_PARSE_HUGE`, alloc-tracking flags,
recursion-depth flags) must NOT be made unless an external row
witnesses the flag's *current* behaviour in the library version
under analysis. Named flag semantics change across versions and
are not encoded in binary-Datalog facts.

When the candidate's category is `tainted_*` or
`unguarded_tainted_sink`, axis (a) is mandatory: no
entry-attributed origin in TaintedVar means no axis-(a) reach.
State explicitly which axis the verdict claims at, and which axes
are out-of-scope. Confirming at axis (b) is the strongest claim
this binary-only triage can make on its own — that is sufficient,
and overclaiming to axis (c) or (d) without external evidence
invalidates the verdict.

## NO CONFABULATION

Names of buffers, fields, struct types, callee-internal variables,
and high-level concepts (e.g. "slice_table", "mb_index2xy",
"intra4x4_pred_mode") DO NOT appear in the fact schema. The fact
schema gives you SSA variable names (rdi_12, rax_3), addresses, and
field offsets only. Inventing a high-level name and pinning the
analysis on it is a CONFABULATION and invalidates the verdict.

When you need to refer to a buffer:

  - Identify it by its `AllocSite` row (call_addr, callee, elem_width)
    OR by its struct field offset from a `FieldWrite` row, OR by the
    SSA variable that is the memset/copy target.
  - If the specific buffer cannot be uniquely determined from the
    available facts (e.g. five uint16_t allocations in the function
    and tool_resolve_var_alloc bottoms out before reaching one), STATE
    THIS EXPLICITLY in the reasoning and set confidence to "low" or
    use verdict "needs_more_info". Do not pick a name and pretend.

The same rule applies to vulnerability mechanisms: do not narrate a
chain involving variables or instructions that are not in your tool
results. If the bug requires a multi-function chain you cannot
witness with current facts, lower confidence accordingly.

When finished, ALWAYS call `tool_write_verdict` exactly once. Do not
emit free-form text after that.
"""


def create_triage_agent(
    finding: dict,
    scan_out: Path | str,
) -> LlmAgent:
    """Build an LlmAgent scoped to triage one finding.

    Args:
        finding: One candidate dict from candidates.json. Must carry
                 at least `id`, `func`, `addr`, `category`, `severity`.
        scan_out: Directory containing facts/, souffle_out/, and
                  where verdicts/ will be created.

    Returns:
        Ready-to-run LlmAgent. Caller drives it through Runner.
    """
    scan_out_p = Path(scan_out)
    facts_dir = scan_out_p / "facts"
    souffle_out = scan_out_p / "souffle_out"
    verdicts_dir = scan_out_p / "verdicts"
    verdicts_dir.mkdir(parents=True, exist_ok=True)

    finding_snapshot = dict(finding)  # defensive copy

    # ── Closure-scoped tools — each agent instance gets its own bound
    # set so concurrent triage sessions in one process don't race. ──

    def tool_get_finding() -> dict:
        """Return the finding being triaged in this session.

        Carries id, source, func, addr, severity, category, var,
        detail, and source-specific extras (callee/arg_idx/risk/origin
        for TaintedSink). Call once at session start.
        """
        return dict(finding_snapshot)

    def tool_function_evidence_summary(func: str) -> dict:
        """Row counts per non-empty relation for `func` — sizing only.

        Use to decide whether the function fits in a single load. If
        total rows >>10K consider passing a tighter `relations=`
        subset to `tool_read_function_facts` or scoping a follow-up
        query around the finding's addr.
        """
        return evidence.function_evidence_summary(facts_dir, func)

    def tool_read_function_facts(
        func: str,
        relations: Optional[list[str]] = None,
    ) -> dict:
        """Read facts filtered to `func`, optionally restricted to
        `relations`. Returns {relation: rows} (rows are TSV column
        lists). Per-relation rows are capped — when capped, the
        result includes a `_truncated` marker; you can re-query with
        a narrower relation set or inspect the function summary.

        Refer to the fact schema in CLAUDE.md / rules/schema.dl for
        column semantics. Pass a `relations` subset matched to the
        finding's category — loading every relation wastes tokens.
        """
        facts = evidence.read_function_facts(facts_dir, func, relations)
        out: dict = {}
        truncated: list[str] = []
        for rel, rows in facts.items():
            if not rows:
                continue
            if len(rows) > _RELATION_ROW_CAP:
                out[rel] = rows[:_RELATION_ROW_CAP]
                truncated.append(f"{rel} ({len(rows)} → {_RELATION_ROW_CAP})")
            else:
                out[rel] = rows
        if truncated:
            out["_truncated"] = truncated
        return out

    def tool_read_taint_chain(
        origin: str,
        sink_func: str,
        sink_var: str = "",
    ) -> dict:
        """TaintedVar rows that reach `sink_func` from `origin`.

        Use to confirm a tainted_* finding's origin actually
        propagates to the implicated function. Returns
        {"count": int, "rows": [...]}. An empty `rows` list means the
        Datalog taint pipeline did not derive a chain — in which case
        a tainted_* finding likely should not be confirmed.

        `sink_var` optionally narrows to a specific tainted variable
        (e.g. the `var` field of the finding).
        """
        sv = sink_var if sink_var else None
        rows = evidence.read_taint_chain(souffle_out, origin, sink_func, sv)
        return {"count": len(rows), "rows": rows}

    def tool_read_callers(func: str) -> list[dict]:
        """Functions that call `func`, with call_addrs.

        Useful when the finding involves a parameter — the caller may
        bound the value or sanitize before the call.
        """
        return evidence.read_callers(facts_dir, func)

    def tool_read_callees(func: str) -> list[dict]:
        """Functions called from `func`, with call_addrs.

        Useful when sanitization/validation may happen inside a
        callee, or when the rule fired on an unresolved indirect
        call you can now resolve via this list.
        """
        return evidence.read_callees(facts_dir, func)

    def tool_compose_datalog(
        rule_text: str,
        output_relations: list[str],
        timeout_seconds: int = 60,
    ) -> dict:
        """Author and execute an ad-hoc Datalog rule against the
        finding's facts directory. Use this when the precomputed
        relations don't directly answer the question you have, but
        a small custom join over the existing facts would.

        The rule_text MUST declare every input relation it consumes
        with `.decl X(...)` followed by `.input X` (souffle does not
        auto-bind to facts/), and every relation in output_relations
        MUST have a `.output Foo` directive.

        Returns a structured result with `status`:
          * "ok" — outputs={rel: {rows, row_count, truncated}}
          * "no_outputs" — rule compiled cleanly but matched no facts
          * "error" — souffle_stderr + rule_text_with_line_numbers
                     (souffle errors include `<file>:<line>:<col>`
                     which align with the numbered source)
          * "timeout" — query exceeded timeout_seconds

        Iterate on errors: read souffle_stderr, find the matching line
        in rule_text_with_line_numbers, fix, resubmit. Common errors:
          - "syntax error, unexpected ..." — usually a typo (.dec for
            .decl, missing semicolon, mismatched parens)
          - "Undefined relation X" — missing `.decl X` + `.input X`
          - "Type mismatch" — column declared as `number` but used as
            `symbol` or vice versa
          - "Arity mismatch" — wrong number of columns in a relation
            reference
        Cap your retry attempts at 5 per question — if you can't get
        a query to compile after that, abandon it and use the existing
        scoped tools instead.
        """
        return dl_runtime.compose_and_run(
            rule_text=rule_text,
            facts_dir=facts_dir,
            output_relations=output_relations,
            timeout_seconds=timeout_seconds,
        )

    def tool_list_functions() -> dict:
        """Return the set of function names present in the fact set.

        Derived cheaply from Def + Call rows — no Souffle invocation.
        Use this at the start of cross-function analysis to discover
        what other functions are in scope. The triage scan typically
        extracts only a subset of the binary (the implicated function
        plus a small neighborhood), so the answer is small (handful
        of names) but you cannot reason about a function whose facts
        are not in scope — `tool_read_function_facts` will simply
        return empty for it.
        """
        funcs: set[str] = set()
        for row in evidence.read_facts_relation(facts_dir, "Def"):
            if row:
                funcs.add(row[0])
        for row in evidence.read_facts_relation(facts_dir, "Call"):
            if row:
                funcs.add(row[0])
        sorted_funcs = sorted(funcs)
        return {"functions": sorted_funcs, "count": len(sorted_funcs)}

    def tool_resolve_var_alloc(
        var: str,
        ver: int,
        func: Optional[str] = None,
    ) -> dict:
        """Trace `var#ver` back through Def + Use→Def + PhiSource to
        find the AllocSite that produced its value. Returns
        {"hits": [...]}.

        Use this when a finding implicates a buffer pointer (e.g.
        `rdi_12` as memset's arg 0 in a sentinel_collision finding)
        and you need to identify which specific allocation the
        pointer refers to — `ff_h264_alloc_tables` has 15 separate
        av_calloc calls, so guessing the buffer name is a confabulation
        risk.

        Each hit either:
          - resolves to an in-function alloc — has alloc_call_addr +
            callee + elem_width + size_var/const, with
            _alloc_resolved=True. THIS is the citable evidence.
          - resolves to a struct field load — has from_field +
            field_load_addr, with _alloc_resolved=False. The buffer
            originated outside this function; the field info tells you
            which struct/offset to chase via tool_read_function_facts
            for FieldWrite in callers.

        Empty hits = trace bottomed out without resolving (e.g. var
        is a function parameter, a global load, or beyond the depth
        cap). When this happens, fall back to listing all AllocSite
        rows for this function via tool_read_function_facts and
        explicitly state in your verdict that the specific buffer
        cannot be disambiguated from the available facts.

        Defaults `func` to the finding's function.
        """
        f = func if func else finding_snapshot.get("func", "")
        if not f:
            return {"error": "no func — pass func= explicitly"}
        hits = evidence.trace_var_to_alloc(facts_dir, f, var, ver)
        return {"count": len(hits), "hits": hits}

    def tool_write_verdict(
        verdict: str,
        confidence: str,
        reasoning: str,
        evidence_cited: Optional[list[dict]] = None,
    ) -> dict:
        """Persist the final verdict for this finding to disk.

        Args:
            verdict: One of "confirmed", "false_positive",
                     "needs_more_info".
            confidence: One of "high", "medium", "low".
            reasoning: 3–10 sentence explanation grounded in cited
                       facts. No bullet lists, no headings.
            evidence_cited: List of {relation, row} dicts pulled
                            verbatim from tool results. Required for
                            "confirmed" verdicts; recommended for
                            "false_positive".
        """
        if verdict not in VERDICT_VALUES:
            return {"error": f"invalid verdict: {verdict!r} "
                             f"(expected one of {VERDICT_VALUES})"}
        if confidence not in CONFIDENCE_VALUES:
            return {"error": f"invalid confidence: {confidence!r} "
                             f"(expected one of {CONFIDENCE_VALUES})"}
        if verdict == "confirmed" and not evidence_cited:
            return {"error": "confirmed verdicts require evidence_cited"}

        out = {
            "id": finding_snapshot.get("id"),
            "source": finding_snapshot.get("source"),
            "func": finding_snapshot.get("func"),
            "addr": finding_snapshot.get("addr"),
            "category": finding_snapshot.get("category"),
            "severity": finding_snapshot.get("severity"),
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": reasoning,
            "evidence_cited": evidence_cited or [],
        }
        # Slugify the id for filename safety. The id format is
        # source:func:addr:category — both ":" and "/" need replacing.
        fname = (finding_snapshot.get("id") or "unknown") \
            .replace(":", "_").replace("/", "_")
        p = verdicts_dir / f"{fname}.json"
        p.write_text(json.dumps(out, indent=2))
        return {"written": str(p)}

    return LlmAgent(
        name="BinCodeQL_Triage",
        model=create_model(),
        instruction=TRIAGE_INSTRUCTION,
        tools=[
            FunctionTool(tool_get_finding),
            FunctionTool(tool_function_evidence_summary),
            FunctionTool(tool_read_function_facts),
            FunctionTool(tool_read_taint_chain),
            FunctionTool(tool_read_callers),
            FunctionTool(tool_read_callees),
            FunctionTool(tool_list_functions),
            FunctionTool(tool_resolve_var_alloc),
            FunctionTool(tool_compose_datalog),
            FunctionTool(tool_write_verdict),
        ],
    )
