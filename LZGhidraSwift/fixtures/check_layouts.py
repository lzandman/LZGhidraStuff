#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
"""Checks that expected-layouts.txt covers every Swift type of the fixture library.

    python3 fixtures/check_layouts.py build/fixtures/libLayouts.dylib \
        build/fixtures/expected-layouts.txt

The types of the library are its nominal type descriptors (symbols ending in Mn),
demangled with swift demangle. Each must have a STRUCT, CLASS, ENUM or SKIP line in
the expected file, and each of those lines a descriptor. Prints the differences;
exit status 1 if there are any.
"""

import os
import subprocess
import sys

PREFIX = "nominal type descriptor for "


def library_types(dylib):
    # -U: defined symbols only (the library also references descriptors of Swift's types).
    nm = subprocess.run(["nm", "-U", dylib], capture_output=True, text=True, check=True)
    names = [
        line.split()[-1].lstrip("_")
        for line in nm.stdout.splitlines()
        if line.endswith("Mn")
    ]
    out = subprocess.run(
        ["swift", "demangle"],
        input="\n".join(names),
        capture_output=True,
        text=True,
        check=True,
    )
    return {
        line[len(PREFIX) :]
        for line in out.stdout.splitlines()
        if line.startswith(PREFIX)
    }


def expected_types(path):
    types = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            columns = line.rstrip("\n").split("\t")
            if columns[0] in ("STRUCT", "CLASS", "ENUM", "SKIP"):
                types.add(columns[1])
    return types


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    found = library_types(sys.argv[1])
    expected = expected_types(sys.argv[2])
    for name in sorted(found - expected):
        print(f"not in the expected file: {name}")
    for name in sorted(expected - found):
        print(f"not in the library: {name}")
    print(
        f"{os.path.basename(sys.argv[1])}: {len(found)} types, "
        f"{len(expected)} in the expected file"
    )
    sys.exit(1 if found != expected else 0)


if __name__ == "__main__":
    main()
