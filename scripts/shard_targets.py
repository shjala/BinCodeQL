#!/usr/bin/env python3
"""Partition a `targets.txt` into per-subsystem shards.

Complementary to `BnFlowRelevant` (see docs/scaling_roadmap.md §3.5).
Findings are intraprocedural, so per-shard runs union trivially.

Usage:
    # Shard a targets file into <output_dir>/<shard>.txt
    python scripts/shard_targets.py SHARD targets.txt output_dir/

    # List the shards a target file would partition into (dry run)
    python scripts/shard_targets.py LIST targets.txt

Shard policy (FFmpeg-centric; the only large open-source binary we
currently run against). Falls back to `misc` for unrecognised prefixes.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

# (shard_name, regex_anchored_on_function_name_start). First match wins,
# so order matters — put longer/more-specific prefixes first.
SHARD_RULES: list[tuple[str, str]] = [
    ("h264",                r"^(ff_)?h264"),
    ("h264",                r"^ff_h2645"),
    ("hevc",                r"^(ff_)?hevc"),
    ("av1",                 r"^(ff_)?av1"),
    ("evc",                 r"^ff_evc"),
    ("mpegts",              r"^(ff_)?mpegts|^pat_cb|^pmt_cb|^sdt_cb|^sl_section_cb|^m4sl_cb"),
    ("mov_iso",             r"^mov_read"),
    ("mov_iso",             r"^mp[0-9]|^mxf_read|^ff_mov_"),
    ("matroska",            r"^matroska"),
    ("flv",                 r"^flv_"),
    ("avi",                 r"^avi_|^ff_avi_"),
    ("asf",                 r"^asf"),
    ("ape",                 r"^ape_|^ff_ape"),
    ("rtp_sdp",             r"^(amr|asf|h264|sdp)_?\w*parse|^sdp_|^ff_sdp"),
    ("audio_codec",         r"^(ff_)?(aac|ac3|dca|opus|flac|vorbis|mp3|amr|nellymoser|opus|qcelp|ra14|ra28|sbc|sipr|tak|truespeech|wmavoice|dsd|gsm|ape|dolby_e|chs)"),
    ("video_codec",         r"^(ff_)?(av1|bmp|escape|exr|fits|gif|hap|huffyuv|jpeg|jacosub|mjpeg|mpeg4|pcx|png|tga|tiff|webp|xan|xsub|xwd|yop|zerocodec|movtext|dvbsub|dvdsub|microdvd|mpl2|realtext|sami|srt|text|ttf|webvtt|adpcm)"),
    ("png_decode",          r"^(ff_)?png_"),
    ("av_parse",            r"^av_"),
    ("ff_parse",            r"^ff_(parse|nal_parse|cbs_|hap_parse)"),
    ("ff_id3v2",            r"^ff_id3v2"),
    ("ff_misc",             r"^ff_"),
    ("read_misc",           r"^read_"),
]


def shard_for(func: str) -> str:
    for shard, pat in SHARD_RULES:
        if re.match(pat, func):
            return shard
    return "misc"


def partition(targets_path: Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for line in targets_path.read_text().splitlines():
        name = line.strip()
        if not name or name.startswith("#"):
            continue
        out[shard_for(name)].append(name)
    return out


def cmd_list(args: argparse.Namespace) -> int:
    parts = partition(args.targets)
    total = sum(len(v) for v in parts.values())
    print(f"{args.targets}: {total} functions in {len(parts)} shards")
    for shard in sorted(parts, key=lambda s: -len(parts[s])):
        print(f"  {shard:<15} {len(parts[shard]):>4d}")
    return 0


def cmd_shard(args: argparse.Namespace) -> int:
    parts = partition(args.targets)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for shard, names in parts.items():
        out_path = args.output_dir / f"{shard}.txt"
        out_path.write_text("\n".join(names) + "\n")
        print(f"  wrote {out_path} ({len(names)} funcs)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp_list = sub.add_parser("LIST", help="Show the shard partition without writing files")
    sp_list.add_argument("targets", type=Path)
    sp_list.set_defaults(func=cmd_list)

    sp_shard = sub.add_parser("SHARD", help="Write per-shard <shard>.txt files into output_dir")
    sp_shard.add_argument("targets", type=Path)
    sp_shard.add_argument("output_dir", type=Path)
    sp_shard.set_defaults(func=cmd_shard)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
