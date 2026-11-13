#!/usr/bin/env python3
"""Generate the synthetic fixtures under examples/in/ deterministically.

Every fixture here is synthetic and built from the documented on-disk layout of the
format it stands for (ELF/Mach-O/PE magic, Electron ASAR header, Cortex-M vector
table). No real device firmware is bundled; see README "局限".
"""
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
IN = os.path.join(HERE, "in")


def write(name, data):
    os.makedirs(IN, exist_ok=True)
    path = os.path.join(IN, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def elf():
    # Minimal ELF64 identification block, padded past the 64-byte classifier floor.
    head = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HHI", 2, 0x3E, 1)
    return head + b"\x00" * 200


def macho():
    return b"\xcf\xfa\xed\xfe" + struct.pack("<IiiII", 0x01000007, 3, 2, 1, 0) + b"\x00" * 200


def pe():
    stub = bytearray(b"MZ" + b"\x00" * 0x3E)
    struct.pack_into("<I", stub, 0x3C, 0x40)
    return bytes(stub) + b"PE\x00\x00" + b"\x00" * 200


def asar():
    header = json.dumps({"files": {"index.js": {"size": 3, "offset": "0"}}}).encode()
    pad = (4 - len(header) % 4) % 4
    body = b"abc" + b"\x00" * 120
    pickle_size = 4 + len(header) + pad + len(body)
    return struct.pack("<II", pickle_size, len(header)) + header + b"\x00" * pad + body


def cortex_m(endian):
    words = [0x20001000] + [(0x100 + 8 * i) | 1 for i in range(15)]
    return b"".join(w.to_bytes(4, endian) for w in words) + b"\x00" * 0x200


def opaque():
    # Fixed-seed LCG: deterministic filler with no table structure.
    state, out = 12345, bytearray()
    for _ in range(512):
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        out.append((state >> 16) & 0xFF)
    return bytes(out)


def main():
    write("example.elf", elf())
    write("example.macho", macho())
    write("example.pe", pe())
    write("example.asar", asar())
    write("firmware-cortex-m.bin", cortex_m("little"))
    write("firmware-big-endian.bin", cortex_m("big"))
    write("opaque.bin", opaque())
    write("tiny.bin", b"\x01\x02\x03\x04" * 4)
    print("fixtures written to", IN)


if __name__ == "__main__":
    main()
