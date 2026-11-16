#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
"""Compares the Swift Data Types analyzer's types with the Swift runtime's layouts.

    python3 devtools/compare_runtime.py [--details] RUNTIME.txt GHIDRA.txt

RUNTIME.txt is written by devtools/runtime-layouts.sh (RuntimeLayouts.swift), GHIDRA.txt
by ghidra_scripts/DumpSwiftTypes.java (or fixtures/DumpLayouts.swift, without the
Ghidra type column). For each type in Ghidra's file: the type line must be equal; each
FIELD must have the runtime's offset, name and Swift type, and its size where Ghidra
typed the field; an undefined field must be at least the runtime's size (it fills the gap
to the next field). A field whose type the binary gives only as a metadata accessor
function matches on offset and name, and is counted separately. Runtime fields of size 0 are left out (Ghidra gets no component for
them). CASE lines are not compared (the runtime file has none). Types the
runtime lists and Ghidra does not are counted, by kind; with --details, listed. Exit
status 1 if there are differences.
"""

import collections
import sys


def read(path):
    """Type name -> (type line, [FIELD lines]); SKIP lines as type lines without fields."""
    types = {}
    current = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            columns = line.rstrip("\n").split("\t")
            if not columns[0] or columns[0].startswith("#"):
                continue
            if columns[0] in ("STRUCT", "CLASS", "ENUM", "SKIP"):
                current = columns[1]
                types[current] = (columns, [])
            elif columns[0] == "FIELD" and current is not None:
                if columns[2] != "0":
                    types[current][1].append(columns)
            elif columns[0] != "CASE":
                raise SystemExit(f"{path}: unexpected line: {line.rstrip()}")
    return types


def compare_fields(name, runtime, ghidra, counts):
    """Yields the differences between two FIELD lists."""
    for i in range(max(len(runtime), len(ghidra))):
        r = runtime[i] if i < len(runtime) else None
        g = ghidra[i] if i < len(ghidra) else None
        if r is None or g is None:
            yield f"{name}: runtime {r}, Ghidra {g}"
            continue
        undefined = len(g) > 5 and g[5].startswith("undefined")
        if g[4].startswith("<metadata accessor at ") and g[1] == r[1] and g[3] == r[3]:
            # The binary gives the type only as a function that builds its metadata at run
            # time (sourcekit-lsp: nonisolated(nonsending) closures).
            counts["runtime_only"] += 1
            if int(g[2]) >= int(r[2]):
                continue
        size_ok = int(g[2]) >= int(r[2]) if undefined else g[2] == r[2]
        if g[1] != r[1] or g[3] != r[3] or g[4] != r[4] or not size_ok:
            yield f"{name}: runtime {r[1:5]}, Ghidra {g[1:]}"


def main():
    args = sys.argv[1:]
    details = "--details" in args
    args = [a for a in args if a != "--details"]
    if len(args) != 2:
        sys.exit(__doc__)
    runtime = read(args[0])
    ghidra = read(args[1])
    differences = compared = fields = typed = 0
    counts = collections.Counter()
    ghidra = {name: t for name, t in ghidra.items() if t[0][0] != "SKIP"}
    for name, (head, members) in sorted(ghidra.items()):
        if name not in runtime:
            print(f"{name}: not in the runtime's file")
            differences += 1
            continue
        compared += 1
        r_head, r_members = runtime[name]
        if head != r_head:
            print(f"{name}: runtime {r_head}, Ghidra {head}")
            differences += 1
        for line in compare_fields(name, r_members, members, counts):
            print(line)
            differences += 1
        fields += len(members)
        typed += sum(
            1 for g in members if len(g) > 5 and not g[5].startswith("undefined")
        )
    missing = collections.Counter()
    for name, (head, _) in sorted(runtime.items()):
        if name not in ghidra:
            kind = head[0] if head[0] != "SKIP" else f"SKIP {head[2]}"
            missing[kind] += 1
            if details:
                print(f"  not in Ghidra: {name} ({kind})")
    print(
        f"{compared} types compared, {differences} differences; {fields} fields "
        f"({typed} typed in Ghidra, {counts['runtime_only']} with a type known only at run "
        f"time); runtime types not in Ghidra: "
        + (", ".join(f"{k} {v}" for k, v in sorted(missing.items())) or "none")
    )
    sys.exit(1 if differences else 0)


if __name__ == "__main__":
    main()
