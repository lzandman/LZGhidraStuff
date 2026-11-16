# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
"""Compares the Swift Self Types result on libMethods.dylib with expected-self.txt.

check_self.py [--types-only] <dylib> <expected-self.txt> <DumpSwiftSelf output>

The functions are found by their symbols (nm -U, demangled with swift demangle --compact). For
each expected function: the type of self in the dump, or no self for "-", and every expected
text in its decompiled C (the dump must have been made with DECOMPILE=all). Every function with
self in the dump must be in the expected file. --types-only skips the texts (the x86_64 build:
the C differs in register allocation and variable names).
"""

import subprocess
import sys


def symbols(dylib):
    """Demangled name -> address, for the Swift symbols of the library."""
    nm = subprocess.run(["nm", "-U", dylib], capture_output=True, text=True, check=True)
    entries = [line.split() for line in nm.stdout.splitlines()]
    entries = [
        (int(e[0], 16), e[2]) for e in entries if len(e) == 3 and e[2].startswith("_$s")
    ]
    demangled = subprocess.run(
        ["swift", "demangle", "--compact"],
        input="\n".join(name for _, name in entries),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return {
        name: address for (address, _), name in zip(entries, demangled, strict=False)
    }


def read_dump(path):
    """(address -> self type name, address -> decompiled C)."""
    selves, code = {}, {}
    current = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if current is not None:
                if line == "END":
                    current = None
                else:
                    code[current].append(line)
            elif line.startswith("SELF\t"):
                _, address, _, path_name, _ = line.split("\t")
                selves[int(address, 16)] = path_name.rsplit("/", 1)[-1]
            elif line.startswith("C\t"):
                current = int(line.split("\t")[1], 16)
                code[current] = []
    return selves, {a: "\n".join(lines) for a, lines in code.items()}


def main():
    args = sys.argv[1:]
    types_only = "--types-only" in args
    args = [a for a in args if a != "--types-only"]
    dylib, expected_path, dump = args
    names = symbols(dylib)
    selves, code = read_dump(dump)
    errors = []
    expected_addresses = set()
    rows = 0
    with open(expected_path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            function, expected_type, *texts = line.split("\t")
            rows += 1
            address = names.get(function)
            if address is None:
                errors.append(f"{function}: no such symbol")
                continue
            expected_addresses.add(address)
            actual = selves.get(address)
            if expected_type == "-":
                if actual is not None:
                    errors.append(
                        f"{function} ({address:#x}): self {actual}, expected none"
                    )
                continue
            if actual != expected_type:
                errors.append(
                    f"{function} ({address:#x}): self {actual}, expected {expected_type}"
                )
                continue
            if types_only:
                continue
            c = code.get(address)
            if c is None:
                errors.append(f"{function} ({address:#x}): no decompiled C in the dump")
                continue
            for text in texts:
                if text not in c:
                    errors.append(f"{function} ({address:#x}): C lacks {text!r}")
    for address, type_name in sorted(selves.items()):
        if address not in expected_addresses:
            errors.append(f"{address:#x}: self {type_name}, not in the expected file")
    for e in errors:
        print(e)
    print(
        f"{rows} functions compared, {len(selves)} with self in the dump, "
        f"{len(errors)} difference{'' if len(errors) == 1 else 's'}{' (types only)' if types_only else ''}"
    )
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
