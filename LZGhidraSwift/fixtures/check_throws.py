# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
"""Compares the Swift Error Register result on libThrows.dylib with expected-throws.txt.

check_throws.py <dylib> <expected-throws.txt> <DumpSwiftThrows output>

The functions are found by their symbols (nm -U, demangled with swift demangle --compact). For
each expected function: whether its calling convention in the dump is a throwing variant (name
ending in _throws), and the texts in its decompiled C (the dump must have been made with
DECOMPILE_THROWS=all): each text must occur, a text with a leading "!" must not. "$ERR" in a
text is the error register named in the dump's first line. Every function with a throwing
convention in the dump must be in the expected file.
"""

import subprocess
import sys

SUFFIX = "_throws"


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
    """(error register, address -> convention, address -> decompiled C)."""
    register, conventions, code = None, {}, {}
    current = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if current is not None:
                if line == "END":
                    current = None
                else:
                    code[current].append(line)
            elif line.startswith("# DumpSwiftThrows\t"):
                register = line.split("\t")[2]
            elif line.startswith("CONV\t"):
                _, address, _, convention, _ = line.split("\t")
                if not address.startswith("EXTERNAL:"):
                    conventions[int(address, 16)] = convention
            elif line.startswith("C\t"):
                current = int(line.split("\t")[1], 16)
                code[current] = []
    return register, conventions, {a: "\n".join(lines) for a, lines in code.items()}


def check_function(function, address, expected, texts, dump, errors):
    register, conventions, code = dump
    convention = conventions.get(address)
    throwing = convention is not None and convention.endswith(SUFFIX)
    if throwing != (expected == "throws"):
        errors.append(
            f"{function} ({address:#x}): convention {convention}, expected {expected}"
        )
        return
    if not texts:
        return
    c = code.get(address)
    if c is None:
        errors.append(f"{function} ({address:#x}): no decompiled C in the dump")
        return
    for text in texts:
        wanted = not text.startswith("!")
        text = text.removeprefix("!").replace("$ERR", register)
        if (text in c) != wanted:
            verb = "lacks" if wanted else "contains"
            errors.append(f"{function} ({address:#x}): C {verb} {text!r}")


def main():
    dylib, expected_path, dump_path = sys.argv[1:4]
    names = symbols(dylib)
    dump = read_dump(dump_path)
    errors = []
    listed = set()
    rows = 0
    with open(expected_path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            function, expected, *texts = line.split("\t")
            rows += 1
            address = names.get(function)
            if address is None:
                errors.append(f"{function}: no such symbol")
                continue
            listed.add(address)
            check_function(function, address, expected, texts, dump, errors)
    throwing = {a: c for a, c in dump[1].items() if c.endswith(SUFFIX)}
    for address, convention in sorted(throwing.items()):
        if address not in listed:
            errors.append(
                f"{address:#x}: convention {convention}, not in the expected file"
            )
    for e in errors:
        print(e)
    print(
        f"{rows} functions compared, {len(throwing)} with a throwing convention "
        f"in the dump, {len(errors)} difference{'' if len(errors) == 1 else 's'}"
    )
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
