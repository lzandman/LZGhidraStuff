# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# Counts AArch64 instructions in __text that put a small-string tag (top nibble 0xE/0xA) or bit 63
# into bits 63-48: movk/movz/movn with hw=3. Usage: count_tags.py <thin arm64 Mach-O>...
import struct
import subprocess
import sys


def text_section(path):
    out = subprocess.run(
        ["otool", "-l", path], capture_output=True, text=True, check=True
    ).stdout.split("\n")
    for i, line in enumerate(out):
        if line.strip() == "sectname __text":
            f = {}
            for l2 in out[i + 1 : i + 10]:
                p = l2.split()
                if len(p) == 2:
                    f[p[0]] = p[1]
            return int(f["size"], 16), int(f["offset"])


for path in sys.argv[1:]:
    size, off = text_section(path)
    with open(path, "rb") as fh:
        fh.seek(off)
        data = fh.read(size)
    movk = movz = movn = large = 0
    for (w,) in struct.iter_unpack("<I", data[: size - size % 4]):
        top = w & 0xFFE00000
        imm = (w >> 5) & 0xFFFF
        if top == 0xF2E00000 and (imm >> 12) in (0xE, 0xA):
            movk += 1
        elif top == 0xD2E00000 and (imm >> 12) in (0xE, 0xA):
            movz += 1
        elif top == 0x92E00000 and ((~imm & 0xFFFF) >> 12) in (0xE, 0xA):
            movn += 1
        if top == 0xF2E00000 and imm == 0x8000:
            large += 1
    print(
        f"{path.split('/')[-1]}\t__text {size / 1e6:.2f} MB\tmovk {movk}\tmovz {movz}\tmovn {movn}\tmovk#0x8000 {large}"
    )
