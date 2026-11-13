#!/usr/bin/env python3
"""rea-raw-preflight: decide, offline, whether a binary file falls inside the limits
that morluto/rea's raw-binary provider documents for itself.

Core logic is pure stdlib and never touches the network. It reads only the file
you hand it and emits a decision + byte-level witnesses.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

DOC_RAW_LIMITS = "https://github.com/morluto/rea/blob/main/docs/providers/raw-binary.md#limitations"
DOC_DESIGN_LIMITS = "https://github.com/morluto/rea/blob/main/docs/design/limits-and-recovery.md"

RC_OK = 0
RC_BLOCKED = 1
RC_USAGE = 2

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}

# Heuristic RAM ranges used only to score a candidate Cortex-M vector table.
# Documented as heuristic in the README; no claim of device coverage.
RAM_RANGES = (
    (0x10000000, 0x10010000),  # DTCM
    (0x1FFE0000, 0x20100000),  # CCM / SRAM
    (0x20000000, 0x40000000),  # generic SRAM
    (0x30000000, 0x30020000),  # some ARMv8-M
)

CONTAINER_MAGICS = (
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE?"),
)

BLOCKER_FIXED_LOAD = {
    "code": "FIXED_LOAD_ADDRESS_REQUIRED",
    "doc_url": DOC_RAW_LIMITS,
    "detail": "No container header (ELF/Mach-O/PE) found, so no load address, entry point "
              "or memory map can be discovered from the file bytes. REA's raw-binary "
              "increment documents that it does not guess these.",
}
BLOCKER_BIG_ENDIAN = {
    "code": "BIG_ENDIAN_ARM_UNSUPPORTED",
    "doc_url": DOC_RAW_LIMITS,
    "detail": "A big-endian ARM-style vector table is the best explanation for the leading "
              "bytes; REA documents big-endian ARM as unsupported.",
}
BLOCKER_THUMB = {
    "code": "THUMB_ONLY_OR_CORTEX_M_UNSUPPORTED",
    "doc_url": DOC_RAW_LIMITS,
    "detail": "A little-endian Cortex-M/Thumb-only vector table is the best explanation for "
              "the leading bytes; REA documents Thumb-only, Cortex-M and other Ghidra "
              "processor variants as unsupported.",
}
BLOCKER_TINY = {
    "code": "INSUFFICIENT_BYTES_TO_CLASSIFY",
    "doc_url": DOC_DESIGN_LIMITS,
    "detail": "Fewer than 64 bytes: not enough material to classify the file, and REA "
              "documents that it cannot remove its own representation limits.",
}


def sha256_12(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def detect_container(data: bytes) -> str:
    """Magic-number based container detection. Returns 'ELF'/'Mach-O'/'PE'/'ASAR'/'raw'."""
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data[:4] in MACHO_MAGICS:
        return "Mach-O"
    if data[:2] == b"MZ":
        # PE: the e_lfanew field at 0x3c points at the PE\0\0 signature.
        if len(data) >= 0x40:
            try:
                off = struct.unpack_from("<I", data, 0x3C)[0]
            except struct.error:
                off = -1
            if 0 < off <= len(data) - 4 and data[off:off + 4] == b"PE\x00\x00":
                return "PE"
        return "raw"  # plain DOS/MZ stub, not enough on its own
    if looks_like_asar(data):
        return "ASAR"
    return "raw"


def looks_like_asar(data: bytes) -> bool:
    """ASAR layout: u32 pickle size, u32 header-string size, then that much JSON."""
    if len(data) < 16:
        return False
    pickle_size, header_size = struct.unpack_from("<II", data, 0)
    if pickle_size == 0 or header_size == 0:
        return False
    if header_size > 32 * 1024 * 1024 or 8 + header_size > len(data):
        return False
    blob = data[8:8 + header_size].rstrip(b"\x00")
    try:
        obj = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    return isinstance(obj, dict) and isinstance(obj.get("files"), dict)


def _in_ram(word: int) -> bool:
    return any(lo <= word < hi for lo, hi in RAM_RANGES)


def score_vector_table(data: bytes, base: int, endian: str, min_thumb: int):
    """Return (matched, score, witness) for a Cortex-M-style vector table at `base`.

    Heuristic: word 0 is plausibly an initial stack pointer in a RAM range, and at
    least `min_thumb` of the following 15 words are Thumb-bit-set pointers that land
    inside this file.
    """
    need = base + 16 * 4
    if need > len(data):
        return False, 0, None
    order = "big" if endian == ">" else "little"
    words = [int.from_bytes(data[base + 4 * i: base + 4 * i + 4], order) for i in range(16)]
    sp = words[0]
    if sp % 4 != 0 or not _in_ram(sp):
        return False, 0, None
    thumb_hits = []
    for i, w in enumerate(words[1:], start=1):
        if not (w & 1):
            continue
        target = w & ~1
        if base <= target < len(data):
            thumb_hits.append((i, w, target))
    score = len(thumb_hits)
    if score < min_thumb:
        return False, score, None
    witness = {
        "offset": base,
        "word0_stack_pointer": {"offset": base, "value": hex(sp)},
        "thumb_handlers": [
            {"index": i, "offset": base + 4 * i, "value": hex(w), "target": hex(t)}
            for i, w, t in thumb_hits[:8]
        ],
        "endian": "little" if endian == "<" else "big",
        "score": f"{score}/15",
    }
    return True, score, witness


def analyze_bytes(data: bytes, min_thumb: int = 12) -> dict:
    container = detect_container(data)
    blockers = []
    notes = []

    if len(data) < 64:
        blockers.append(dict(BLOCKER_TINY))
        return _report(data, container, "ABSTAIN", blockers, notes,
                       "Give REA an explicit entry point and memory map, or provide a "
                       "container file; this file is too small to classify.", "low")

    if container in ("ELF", "Mach-O", "PE", "ASAR"):
        notes.append("Container recognised by magic bytes; the raw-binary limits quoted here "
                     "are about headerless blobs and do not apply to this file.")
        if container == "PE":
            notes.append("PE layout confirmed (MZ plus the e_lfanew signature).")
        return _report(data, container, "CONTAINER_PATH", blockers, notes,
                       f"Hand REA the {container} file directly; no raw-binary workaround needed.",
                       "high")

    # Headerless: look for the two failure modes REA documents as unsupported.
    be_match = le_match = None
    for base in (0, 0x100, 0x1000, 0x8000, 0x10000, 0x20000):
        ok, score, witness = score_vector_table(data, base, ">", min_thumb)
        if ok and (be_match is None or score > be_match[1]):
            be_match = (base, score, witness)
        ok, score, witness = score_vector_table(data, base, "<", min_thumb)
        if ok and (le_match is None or score > le_match[1]):
            le_match = (base, score, witness)

    if le_match:
        b = dict(BLOCKER_THUMB)
        b["witness"] = le_match[2]
        blockers.append(b)
        return _report(data, container, "BLOCKED", blockers, notes,
                       "Convert the image to a supported processor variant (or extract a "
                       "container), otherwise REA's raw-binary path documents this as "
                       "unsupported.", "high")

    if be_match:
        # A big-endian read only beats a little-endian read of the same bytes when the
        # little-endian read produced nothing; say so rather than overclaiming.
        notes.append("No little-endian vector-table evidence was found; the big-endian read "
                     "is the best remaining explanation, not a certainty.")
        b = dict(BLOCKER_BIG_ENDIAN)
        b["witness"] = be_match[2]
        blockers.append(b)
        return _report(data, container, "BLOCKED", blockers, notes,
                       "Documented as unsupported; extract a container or obtain a "
                       "little-endian image.", "medium")

    notes.append("No container magic and no vector-table evidence; the file looks like an "
                 "opaque blob.")
    blockers.append(dict(BLOCKER_FIXED_LOAD))
    return _report(data, container, "NEEDS_ENTRY_POINT", blockers, notes,
                   "Supply --entry-point / load address yourself, or extract a container; REA "
                   "documents that it will not guess them.", "high")


def _report(data, container, verdict, blockers, notes, recommended, confidence) -> dict:
    return {
        "tool": "rea-raw-preflight",
        "file": None,
        "size": len(data),
        "sha256_12": sha256_12(data),
        "container": container,
        "verdict": verdict,
        "confidence": confidence,
        "blockers": blockers,
        "notes": notes,
        "recommended": recommended,
    }


def analyze_file(path: str, min_thumb: int = 12) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    rep = analyze_bytes(data, min_thumb=min_thumb)
    rep["file"] = path
    return rep


def exit_code_for(report: dict) -> int:
    if report["verdict"] == "CONTAINER_PATH":
        return RC_OK
    return RC_BLOCKED


def render_text(report: dict) -> str:
    lines = [
        f"file        : {report['file']}",
        f"size        : {report['size']} bytes",
        f"sha256[:12] : {report['sha256_12']}",
        f"container   : {report['container']}",
        f"verdict     : {report['verdict']} (confidence {report['confidence']})",
    ]
    for b in report["blockers"]:
        lines.append(f"blocker     : {b['code']}")
        lines.append(f"  doc       : {b['doc_url']}")
        lines.append(f"  why       : {b['detail']}")
        w = b.get("witness")
        if w:
            lines.append(f"  witness   : offset={w['offset']} word0={w['word0_stack_pointer']['value']} "
                         f"thumb={w['score']} endian={w['endian']}")
    for n in report["notes"]:
        lines.append(f"note        : {n}")
    lines.append(f"recommended : {report['recommended']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-raw-preflight",
        description="Offline preflight for morluto/rea raw-binary limits.")
    p.add_argument("file", nargs="?", help="binary file to classify")
    p.add_argument("--json", action="store_true", help="emit a JSON report on stdout")
    p.add_argument("--min-thumb", type=int, default=12,
                   help="Thumb-bit handler hits required to call it a Cortex-M table (default 12)")
    p.add_argument("--version", action="version", version="rea-raw-preflight 1.0.0")
    args = p.parse_args(argv)

    if not args.file:
        print("error: a file argument is required", file=sys.stderr)
        return RC_USAGE
    if not os.path.isfile(args.file):
        print(f"error: no such file: {args.file}", file=sys.stderr)
        return RC_USAGE
    if not (1 <= args.min_thumb <= 15):
        print("error: --min-thumb must be between 1 and 15", file=sys.stderr)
        return RC_USAGE
    try:
        report = analyze_file(args.file, min_thumb=args.min_thumb)
    except OSError as exc:
        print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
        return RC_USAGE

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return exit_code_for(report)


if __name__ == "__main__":
    sys.exit(main())
