#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
"""Compares the Swift Data Types analyzer's types with the expected layouts.

    python3 fixtures/compare_layouts.py build/fixtures/expected-layouts.txt \
        build/fixtures/ghidra-layouts.txt

The second file is written by ghidra_scripts/DumpSwiftTypes.java. Types are compared
by name, in any order: the type line and the FIELD and CASE lines must be equal (the
Ghidra type, the sixth column of a FIELD line, is not compared). Expected fields of size
0 are left out: they take no space, and Ghidra gets no component for them. A field whose
type the binary gives only as a metadata accessor function matches if its offset and name
are equal and it is at least as large; it is counted separately. SKIP types must be
absent from Ghidra's file. Prints the differences and a summary with the number of
fields Ghidra left undefined; exit status 1 if there are differences.
"""

import sys


def read(path):
    """Type name -> (type line, [member lines]); SKIP lines as type lines with no members."""
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
            elif columns[0] in ("FIELD", "CASE") and current is not None:
                if columns[0] != "FIELD" or columns[2] != "0":
                    types[current][1].append(columns)
            else:
                raise SystemExit(f"{path}: unexpected line: {line.rstrip()}")
    return types


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    expected = read(sys.argv[1])
    ghidra = read(sys.argv[2])
    differences = 0
    compared = 0
    fields = 0
    undefined = 0
    runtime_only = 0
    for name, (head, members) in sorted(expected.items()):
        if head[0] == "SKIP":
            if name in ghidra:
                print(f"{name}: skipped ({head[2]}) but in Ghidra")
                differences += 1
            continue
        if name not in ghidra:
            print(f"{name}: not in Ghidra")
            differences += 1
            continue
        compared += 1
        g_head, g_members = ghidra[name]
        if head != g_head:
            print(f"{name}: expected {head}, Ghidra {g_head}")
            differences += 1
        for i in range(max(len(members), len(g_members))):
            e = members[i] if i < len(members) else None
            g = g_members[i] if i < len(g_members) else None
            if g is not None and g[0] == "FIELD":
                fields += 1
                if len(g) > 5 and g[5].startswith("undefined"):
                    undefined += 1
            g_compared = g[:5] if g is not None and g[0] == "FIELD" else g
            if (
                e is not None
                and g is not None
                and g[0] == "FIELD"
                and g[4].startswith("<metadata accessor at ")
                and e[1] == g[1]
                and e[3] == g[3]
                and int(g[2]) >= int(e[2])
            ):
                # The binary names the type only through a function that builds the metadata
                # at run time (x86_64 fixture, macOS 13: @isolated(any), typed throws).
                runtime_only += 1
                continue
            if e != g_compared:
                print(f"{name}: expected {e}, Ghidra {g}")
                differences += 1
    for name in sorted(set(ghidra) - set(expected)):
        print(f"{name}: in Ghidra only")
        differences += 1
    print(
        f"{compared} types compared, {differences} difference{'' if differences == 1 else 's'}; "
        f"{fields} fields, {undefined} undefined in Ghidra, "
        f"{runtime_only} with a type known only at run time"
    )
    sys.exit(1 if differences else 0)


if __name__ == "__main__":
    main()
