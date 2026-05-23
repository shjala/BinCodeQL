# Entry-taint experiment: libxml2-vuln (xmllint)

**Date:** 2026-05-04
**Question:** When the original libxml2-vuln scan ran with `EntryTaint.facts`
empty (taint seeded only from `signatures.dl` libc-source heuristic), is the
data-flow path from a properly-attributed program entry point (`main:argv` or
the `xmlRead*` parser API) actually present in the binary, or did the libc
heuristic over-attribute reachability?

**Method:** Re-ran `pipeline.run_taint_pipeline` on the existing libxml2-vuln
facts directory (hardlinked copy at `runs/libxml2-vuln-entrytaint/`) with a
hand-picked `EntryTaint.facts` seeding seven entry points:

```
main                  1   (argv)
xmlReadFile           0   (filename)
xmlReadMemory         0   (buffer)
xmlReadFd             0   (fd)
xmlReadIO             0   (ioread callback)
xmlCtxtReadFile       1   (filename)
xmlSAXUserParseFile   2   (filename)
```

Libc-source seeding via `signatures.dl`-derived `TaintTransfer.facts` was kept
(additive scenario), so the new entry-attributed origins appear alongside the
existing `external_via_*` origins.

Wall-clock: 605 seconds (alias.dl + interproc.dl). Pass exit codes both 0.

## Result

`TaintedVar` rows for `xmlAutomataNewNegTrans` grouped by origin label:

| Origin | Rows |
|---|---:|
| `entry:main:arg1` | 264 |
| `entry:xmlReadFile:arg0` | 264 |
| `entry:xmlReadMemory:arg0` | 264 |
| `entry:xmlReadFd:arg0` | 264 |
| `entry:xmlReadIO:arg0` | 264 |
| `entry:xmlCtxtReadFile:arg1` | 264 |
| `entry:xmlSAXUserParseFile:arg2` | 264 |
| `external_via_read` (libc baseline) | 264 |
| `external_via_fread` | 264 |
| `external_via_mmap64` | 264 |
| `external_via_getenv` | 264 |
| `bufwrite_via_fread` | 264 |
| `bufwrite_via_recv` | 264 |
| **Total** | **3432** (13 origins × 264 distinct (var,ver)) |

Each origin propagates to the same 264 SSA variable instances inside
`xmlAutomataNewNegTrans`, just relabeled. The libc heuristic was not
fabricating reachability; it was attributing a real path imprecisely.

## Three answers

1. **Data-flow path from `main:argv` to `xmlAutomataNewNegTrans:str` exists.**
   Confirmed empirically. Our finding's reachability claim is correct at the
   data-flow level.

2. **The methodological gap (empty `EntryTaint`) was real but
   methodologically secondary.** Fixing it gives honest origin labels but
   does not change the verdict.

3. **What is *not* shown is whether the path carries strings long enough to
   trigger the integer overflow.** The overflow needs `lenn + lenp + 2` to
   wrap a 32-bit signed int, i.e. ~4 GiB combined. The parser-level length
   caps Nick described clamp strings to a few MB along this path. Our
   analysis treats taint as binary (reachable yes/no) and does not model
   length constraints. This is the deeper methodological gap (Gap 2 below).

## Breadth: how broad is `entry:main:arg1` reachability?

Across the whole binary, **2298 of 3084 functions (75%)** receive at least
one `entry:main:arg1`-tainted variable. Top by row count includes the entire
parser surface (`xmlParseTryOrFinish`, `xmlParseStartTag2`,
`htmlParseTryOrFinish`), the XPath compiler, schema validators, dictionary
lookups, error helpers — i.e., effectively the whole library.

This means binary-grade data-flow taint reachability is too broad to act as
a precision filter on its own. What distinguishes a reachable-but-
not-triggerable site from a reachable-and-triggerable one is the
constraint propagation along the path (length caps, value ranges, sanitiser
chains), not the data-flow reach itself.

## Implications for §6.3 / §7

The maintainer's correction (Nick Wellnhofer, 2026-05-04) is not refuted by
this experiment. The data-flow path exists; the parser caps along it bound
the strings well below the overflow threshold. Nick was right *quantitatively*,
even though our binary-Datalog analysis correctly identifies the path
*qualitatively*.

The experiment confirms two things our paper should say honestly:

- **Gap 1 (proper entry-point seeding) is real** — the `external_via_*`
  origin labels in our published evaluation are imprecise attributions of
  what is genuinely a `main:argv`-rooted data-flow path. Future scans
  should seed `EntryTaint` from the binary's natural entry surface, with
  LLM-driven entry selection a credible follow-up.

- **Gap 2 (constraint propagation) is the dominant missing piece on this
  specific class of bug.** Even with perfect entry-point seeding, our
  taint analysis cannot distinguish "data flows" from "data flows with
  strings long enough to overflow". The path-sensitive `GuardDominates`
  relation in the post-paper roadmap is exactly the right home for this.

## Reproducibility

```bash
cd bin_datalog
mkdir -p magma_eval/runs/libxml2-vuln-entrytaint/{facts,souffle_out}
cp -al magma_eval/runs/libxml2-vuln/facts/* \
       magma_eval/runs/libxml2-vuln-entrytaint/facts/
rm magma_eval/runs/libxml2-vuln-entrytaint/facts/EntryTaint.facts
cat > magma_eval/runs/libxml2-vuln-entrytaint/facts/EntryTaint.facts <<'EOF'
main	1
xmlReadFile	0
xmlReadMemory	0
xmlReadFd	0
xmlReadIO	0
xmlCtxtReadFile	1
xmlSAXUserParseFile	2
EOF

# Re-run taint pipeline
python3 -c "
from pipeline import run_taint_pipeline
r = run_taint_pipeline(
    'magma_eval/runs/libxml2-vuln-entrytaint/facts',
    'magma_eval/runs/libxml2-vuln-entrytaint/souffle_out',
    'rules', timeout_seconds=3600,
)
print(r['pass1_alias']['return_code'], r['pass2_interproc']['return_code'])
"

# Inspect origins
awk -F'\t' '$1=="xmlAutomataNewNegTrans" {print $4}' \
  magma_eval/runs/libxml2-vuln-entrytaint/souffle_out/TaintedVar.csv \
  | sort | uniq -c | sort -rn
```
