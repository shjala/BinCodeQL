# BinCodeQL CTF Findings — FFmpeg 8.0.1 VVC/EVC/CBS
**Date:** 2026-05-22  
**Target:** ffmpeg_g.bndb (FFmpeg 8.0.1 with debug symbols)  
**Subsystems analyzed:** VVC (H.266 decoder), CBS (Coded Bitstream), EVC  
**Method:** Datalog taint + structural analysis (BinCodeQL) → manual source verification

---

## CONFIRMED FINDING — VVC `slice_idx` Sentinel Collision (filter.c:599)  🔴

**Same class as the previously found H.264 bug, now in the VVC decoder.**

### The Pattern
```c
// dec.h: slice_idx table is int16_t (16-bit)
int16_t *slice_idx;   // in VVCFrameContext.tab

// dec.c:383 — initialized with memset(-1) = sentinel 0xFFFF per element
memset(fc->tab.slice_idx, -1, sizeof(*fc->tab.slice_idx) * ctu_count);

// dec.c:507 — slice number assigned without upper bound check
fc->slices[i]->slice_idx = i;   // i can exceed INT16_MAX!

// dec.c:599 — written into table
fc->tab.slice_idx[rs] = sc->slice_idx;
```

### The Vulnerability: filter.c line 599
```c
// filter.c:598-599 — NO bounds check on q_rs before slice_idx access
const int q_rs = rs - (vertical ? 1 : fc->ps.pps->ctb_width);
const SliceContext *q_slice = lc->fc->slices[lc->fc->tab.slice_idx[q_rs]];
```

**Attack vector:**
- VVC bitstream with `sps_num_subpics_minus1 > 0` (multiple sub-pictures)
- `BOUNDARY_LEFT_SUBPIC` flag set when `sps_subpic_ctu_top_left_x[curr_subpic_idx] == rx`
- If left neighbor CTU (at `q_rs = rs - 1`) belongs to an unprocessed sub-picture:  
  `tab.slice_idx[q_rs] = -1` (sentinel) → `fc->slices[-1]` = **OOB array read**

**Variant 2 (H.264-class collision):**
- Craft bitstream with ≥65536 slices per frame
- `fc->nb_slices` reaches 65535 → `sc->slice_idx = 65535 = 0xFFFF` = sentinel
- CTUs in slice #65535 are indistinguishable from uninitialized CTUs in filter logic
- Filter erroneously crosses slice boundary → accesses uninitialized pixel data

### BinCodeQL evidence
- `BnSentinelInit`: `ff_vvc_coding_tree_unit @ 0x122F42F` — rdi_14 init w/ sentinel=-1
- `BnSentinelInit`: `vvc_decode_frame @ 0xFB1A89` — rdi_43 init w/ sentinel=0xFFFFFFFF  
- `BnSentinelCollisionRisk`: 162 structural findings in `ff_vvc_coding_tree_unit`

### Files
- `libavcodec/vvc/filter.c:599` — OOB access, no guard on q_rs
- `libavcodec/vvc/dec.c:383, 507, 599` — sentinel pattern + unbounded counter
- `libavcodec/vvc/ctu.c:2851-2852` — BOUNDARY_LEFT_SUBPIC set without rx>0 guard

### Trigger
```
ffmpeg -i crafted.266 -f null - 
# crafted.266: multi-subpicture VVC stream with subpic at rx>0 +
# adjacent CTU in unprocessed sub-picture
```

---

## FALSE POSITIVES (documented for methodology record)

| Finding | Root cause of FP |
|---|---|
| VVC APS ALF delta_idx OOB | CBS `us()` macro bounds `alf_luma_coeff_delta_idx` to [0,24] upstream |
| vvc_decode_frame av_calloc overflow | av_calloc returns NULL on multiplication overflow; NULL-checked |
| "EVC" OOB counter-as-index | Function was `escape124_decode_frame` — BN naming confusion; standard bit-reader |
| ff_vvc_bump_frame DPB OOB | DPB array bounded by `FF_ARRAY_ELEMS`; `sps_max_sublayers_minus1` CBS-validated |
| vvc_decode_frame tainted memset | `rdx_29/rdx_30 = 8×ctu_count / 2×ctu_count`; table allocation matches memset size |

---

## METHODOLOGY NOTES

- BinCodeQL produced 7,667 BnFinding rows (4,064 high) — overwhelmingly structural
- Manual verification filtered 4/5 top leads as false positives in ≤20 lines of source each
- True positive confirmed by: BnSentinelCollisionRisk + BnSentinelInit → source trace
- Key lesson: Datalog finds H.264-class patterns reliably across codecs (H.264 → VVC)
- Key weakness: upstream CBS validation invisible to Datalog → false positives for bounds-checked fields
