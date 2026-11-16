# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
"""Compares the Swift Runtime Prototypes result on libRuntime.dylib with expected-runtime.txt.

check_runtime.py <dylib> <expected-runtime.txt> <DumpSwiftRuntime output>

Two kinds of rows in the expected file. "ext": an external function's name, signature source,
calling convention and prototype, which must equal the dump's EXT line; a name with a leading
"?" is only compared when the binary imports it. Every external whose name starts with
_swift_ must have a row. "func": a function (swift demangle --compact of its symbol, found
with nm as in check_throws.py) and texts that its decompiled C must contain, or must not
contain with a leading "!"; the dump must have been made with DECOMPILE_RUNTIME=all.
"""

import sys

from check_throws import symbols

RUNTIME_PREFIX = "_swift_"


def read_dump(path):
    """(name -> (source, convention, prototype) of the externals, address -> decompiled C)."""
    externals, code = {}, {}
    current = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if current is not None:
                if line == "END":
                    current = None
                else:
                    code[current].append(line)
            elif line.startswith("EXT\t"):
                _, name, *signature = line.split("\t")
                externals[name] = tuple(signature)
            elif line.startswith("C\t"):
                current = int(line.split("\t")[1], 16)
                code[current] = []
    return externals, {a: "\n".join(lines) for a, lines in code.items()}


def check_external(name, signature, externals, errors):
    optional = name.startswith("?")
    name = name.removeprefix("?")
    have = externals.get(name)
    if have is None:
        if not optional:
            errors.append(f"{name}: not imported")
        return
    if have != tuple(signature):
        errors.append(f"{name}: {' '.join(have)}, expected {' '.join(signature)}")


def check_function(function, address, texts, code, errors):
    c = code.get(address)
    if c is None:
        errors.append(f"{function} ({address:#x}): no decompiled C in the dump")
        return
    for text in texts:
        wanted = not text.startswith("!")
        text = text.removeprefix("!")
        if (text in c) != wanted:
            verb = "lacks" if wanted else "contains"
            errors.append(f"{function} ({address:#x}): C {verb} {text!r}")


def main():
    dylib, expected_path, dump_path = sys.argv[1:4]
    names = symbols(dylib)
    externals, code = read_dump(dump_path)
    errors = []
    listed = set()
    functions = 0
    with open(expected_path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            kind, name, *rest = line.split("\t")
            if kind == "ext":
                listed.add(name.removeprefix("?"))
                check_external(name, rest, externals, errors)
                continue
            functions += 1
            address = names.get(name)
            if address is None:
                errors.append(f"{name}: no such symbol")
                continue
            check_function(name, address, rest, code, errors)
    runtime = [n for n in externals if n.startswith(RUNTIME_PREFIX)]
    for name in sorted(runtime):
        if name not in listed:
            errors.append(
                f"{name}: {' '.join(externals[name])}, not in the expected file"
            )
    for e in errors:
        print(e)
    print(
        f"{len(runtime)} runtime externals, {functions} functions compared, "
        f"{len(errors)} difference{'' if len(errors) == 1 else 's'}"
    )
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
