#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
"""Writes data/swift-runtime-functions.txt, the table of the Swift runtime functions.

    python3 devtools/gen_runtime_functions.py SWIFT_CHECKOUT [OUTPUT]

SWIFT_CHECKOUT is a checkout of the Swift repository (github.com/swiftlang/swift).
OUTPUT defaults to data/swift-runtime-functions.txt next to this script's directory.
Regenerate after a Swift release; the header line names the commit.

Sources, all in SWIFT_CHECKOUT/include/swift:

- Runtime/RuntimeFunctions.def, the compiler's list of runtime functions, expanded with
  `clang -E -P` (a regular expression misses the entries made by token pasting). It gives
  each function's module, calling convention, return types, parameter types (IRGen names
  such as TypeMetadataPtrTy) and attributes.
- The declarations in Runtime/*.h and ABI/{MetadataValues,Task,Executor}.h. When a
  declaration has the .def's number of parameters, it gives the parameter names, and a
  parameter whose type is a simple `enum class` gets that enum. A parameter that the .def
  types as an untyped pointer (Int8PtrTy, PtrTy) gets the header's pointee when the header
  names one, such as `ValueBuffer *` (see PARAM below). When the counts differ, the .def
  wins and the entry is reported.
- The simple `enum class Name : type { A = value, ... };` declarations of ABI/*.h and
  Runtime/*.h. Values that are not integer literals (or shifts of them) are left out, and
  so is a value that repeats an earlier value of the same enum; both are reported.

One rule is not read from the sources: UNDEFINED_ARGS drops trailing parameters that the
compiler passes as undefined values in most calls (swift_once's context, see there).

Output, tab-separated, after a header line `# swift <commit> <date>, ...`:

    enum  NAME  SIZE  A=0x0  B=0x1 ...
    func  NAME  MODULE  CC  RETURNS  ATTRS  PARAM ...

RETURNS is a comma-separated list of IRGen names (VoidTy for an empty RETURNS()).
ATTRS is a comma-separated list of the attributes NoReturn and FirstParamReturned (from the
.def) and SwiftRegisterParams (from the header: a parameter marked SWIFT_CONTEXT,
SWIFT_ERROR_RESULT or SWIFT_ASYNC_CONTEXT, which is passed in a Swift-only register, x20,
x21 or x22 on arm64, not in an argument register) and SwiftRegistersOnly (every parameter
is so; swift_willThrow), or `-`.
Each PARAM is `name:type` or just `type` (no name in a header), where type is an IRGen
name or `enum NAME`. An Int8PtrTy or PtrTy parameter may carry the header's pointee:
`buffer:PtrTy=ValueBuffer*`, `types:PtrTy=Metadata**` (one `*` per level, `const`,
`struct` and `swift::` removed). The pointee is written as the header names it, whatever
it is (`TaskGroup`, `uint32_t`); `void`, `char` and other C type words, function pointers
and templates are not written. The extension decides which pointees it uses
(RuntimeTypes). Enums are written only when a parameter uses one. Lines are sorted by
name within each kind. Reports go to standard error.
"""

import pathlib
import re
import subprocess
import sys
import tempfile

ATTRIBUTES = ("NoReturn", "FirstParamReturned")
# A header parameter attribute that puts the parameter in a Swift-only register.
SWIFT_REGISTER_PARAM = re.compile(r"\bSWIFT_(CONTEXT|ERROR_RESULT|ASYNC_CONTEXT)\b")
SWIFT_REGISTER_PARAMS = "SwiftRegisterParams"
SWIFT_REGISTERS_ONLY = "SwiftRegistersOnly"

# Trailing parameters left out of the table, by function. swift_once(predicate, fn, context):
# global initialisers use Builtin.once, for which IRGen passes an undefined context
# (lib/IRGen/GenBuiltin.cpp, BuiltinValueKind::Once); only Builtin.onceWithContext passes one.
# The caller leaves x2 (rdx) unset, and a typed context makes the decompiler read that register
# as a parameter of the caller: most global accessors got 3 parameters instead of none.
UNDEFINED_ARGS = {"swift_once": 1}

EXPAND = """\
#define FUNCTION(Id, Module, Name, CC, Availability, ReturnTys, ArgTys, Attrs, Effect, \
MemEffects) @@FN Name | Module | CC | ReturnTys | ArgTys | Attrs @@
#define RETURNS(...) R(__VA_ARGS__)
#define ARGS(...) A(__VA_ARGS__)
#define NO_ARGS A()
#define ATTRS(...) T(__VA_ARGS__)
#define NO_ATTRS T()
#define EFFECT(...)
#define MEMEFFECTS(...)
#define UNKNOWN_MEMEFFECTS
#include "swift/Runtime/RuntimeFunctions.def"
"""

# Sizes of the underlying types of the enums.
UNDERLYING_SIZES = {
    "bool": 1,
    "uint8_t": 1,
    "int8_t": 1,
    "uint16_t": 2,
    "int16_t": 2,
    "uint32_t": 4,
    "int32_t": 4,
    "unsigned": 4,
    "int": 4,
    "uint64_t": 8,
    "int64_t": 8,
    "uintptr_t": 8,
    "intptr_t": 8,
    "size_t": 8,
}

# Sizes of the IRGen integer types an enum parameter may replace.
IRGEN_INT_SIZES = {"Int1Ty": 1, "Int8Ty": 1, "Int32Ty": 4, "Int64Ty": 8, "SizeTy": 8}

C_TYPE_WORDS = {
    "void",
    "bool",
    "char",
    "short",
    "int",
    "long",
    "float",
    "double",
    "signed",
    "unsigned",
    "const",
    "volatile",
}


def report(message):
    print(message, file=sys.stderr)


def git(checkout, *args):
    return subprocess.run(
        ["git", "-C", str(checkout), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def split_list(text):
    """The items of `X(a, b, c)`, without the X and the parentheses."""
    inner = text.strip()[2:-1]
    return [item.strip() for item in inner.split(",") if item.strip()]


def read_def(include):
    """Name -> (module, cc, [return types], [param types], [attributes]), from clang -E."""
    with tempfile.TemporaryDirectory() as tmp:
        source = pathlib.Path(tmp) / "expand.c"
        source.write_text(EXPAND)
        out = subprocess.run(
            ["clang", "-E", "-P", "-I", str(include), str(source)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    entries = {}
    for record in re.findall(r"@@FN(.*?)@@", out, flags=re.S):
        name, module, cc, returns, args, attrs = (f.strip() for f in record.split("|"))
        if name in entries:
            raise SystemExit(f"RuntimeFunctions.def: {name} twice")
        entries[name] = (
            module,
            cc,
            split_list(returns) or ["VoidTy"],  # RETURNS() in 3 entries
            split_list(args),
            split_list(attrs),
        )
    return entries


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def header_text(include):
    paths = sorted((include / "Runtime").glob("*.h"))
    paths += [include / "ABI" / n for n in ("MetadataValues.h", "Task.h", "Executor.h")]
    return "\n".join(strip_comments(p.read_text(encoding="utf-8")) for p in paths)


def enum_texts(include):
    paths = sorted((include / "ABI").glob("*.h")) + sorted(
        (include / "Runtime").glob("*.h")
    )
    return "\n".join(strip_comments(p.read_text(encoding="utf-8")) for p in paths)


def literal(text):
    """The value of an integer literal, true, false, or a shift of two literals; else None."""
    text = text.strip()
    m = re.fullmatch(r"\(?\s*(\w+)\s*<<\s*(\w+)\s*\)?", text)
    if m:
        a, b = literal(m.group(1)), literal(m.group(2))
        return None if a is None or b is None else a << b
    if text in ("false", "true"):
        return int(text == "true")
    m = re.fullmatch(r"(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*", text)
    if not m:
        return None
    return int(m.group(1), 0)


def read_enums(include):
    """Name -> (size, [(value name, value)], [reports]) for the simple enum classes."""
    enums = {}
    pattern = r"\benum\s+class\s+(\w+)\s*:\s*([\w:]+)\s*\{([^{}]*)\}\s*;"
    for m in re.finditer(pattern, enum_texts(include)):
        name, underlying, body = (
            m.group(1),
            m.group(2).removeprefix("std::"),
            m.group(3),
        )
        if underlying not in UNDERLYING_SIZES or name in enums:
            continue
        values, notes, seen = [], [], {}
        previous = -1
        for item in (i.strip() for i in body.split(",")):
            if not item:
                continue
            key, _, expr = (s.strip() for s in item.partition("="))
            if expr:
                value = literal(expr)
            else:
                value = None if previous is None else previous + 1
            if value is None:
                notes.append(
                    f"{key} = {expr or 'previous + 1'}: not a literal, left out"
                )
                previous = None
                continue
            previous = value
            if value in seen:
                notes.append(f"{key} = {value:#x} repeats {seen[value]}, left out")
                continue
            seen[value] = key
            values.append((key, value))
        enums[name] = (UNDERLYING_SIZES[underlying], values, notes)
    return enums


def split_params(text):
    """The parameters of a declaration, split on commas outside <> and (), without defaults
    and SWIFT_ attributes."""
    params = [
        " ".join(re.sub(r"\bSWIFT_\w+(\([^)]*\))?", " ", p).split())
        for p in split_raw_params(text)
    ]
    return [p for p in params if p and p != "void"]


def split_raw_params(text):
    """The parameters of a declaration, split on commas outside <> and (), without defaults;
    with their SWIFT_ attributes."""
    params, depth, current = [], 0, ""
    for c in text:
        if c in "<(":
            depth += 1
        elif c in ">)":
            depth -= 1
        if c == "," and depth == 0:
            params.append(current)
            current = ""
        else:
            current += c
    params.append(current)
    params = [re.sub(r"\s*=.*", "", p, flags=re.S).strip() for p in params]
    return [p for p in params if p and p != "void"]


def name_and_type(param):
    """(name or None, type text) of one parameter of a declaration."""
    m = re.search(r"\(\s*\*\s*(\w+)\s*\)", param)
    if m:
        return m.group(1), param
    m = re.fullmatch(r"(.*?[\s*&>])(\w+)(\s*\[\s*\w*\s*\])?", param)
    if m and m.group(2) not in C_TYPE_WORDS and re.search(r"\w", m.group(1)):
        return m.group(2), m.group(1).strip()
    return None, param


def read_declarations(include, names):
    """Name -> [([(param name, param type)], Swift register params, only those), ...], each
    declaration found for the name; the first flag is true when a parameter is in a Swift-only
    register, the second when every parameter is (and there is one)."""
    text = header_text(include)
    found = {}
    for name in names:
        pattern = (
            r"\b"
            + name
            + r"\s*\(((?:[^;{()]|\([^()]*\))*)\)\s*(?:SWIFT_\w+(?:\([^)]*\))?\s*)*[;{]"
        )
        for m in re.finditer(pattern, text):
            # A declaration has a type before the name; a call (`p = malloc(1);`) does not.
            before = re.search(r"(\w+|[*&>])\s*$", text[: m.start()])
            if not before or before.group(1) in ("return", "else", "case"):
                continue
            raw = split_raw_params(m.group(1))
            in_swift_registers = [bool(SWIFT_REGISTER_PARAM.search(p)) for p in raw]
            found.setdefault(name, []).append(
                (
                    [name_and_type(p) for p in split_params(m.group(1))],
                    any(in_swift_registers),
                    bool(raw) and all(in_swift_registers),
                )
            )
    return found


# The .def's untyped pointers, which a header pointee may refine.
UNTYPED_POINTERS = ("Int8PtrTy", "PtrTy")


def pointee_of(type_text):
    """`Name*` (one `*` per level) for a pointer to a named type, else None."""
    words = re.sub(r"\b(const|volatile|struct|class)\b|\bswift::", " ", type_text)
    m = re.fullmatch(r"\s*(\w+)\s*((?:\*\s*)+)", words)
    if not m or m.group(1) in C_TYPE_WORDS:
        return None
    return m.group(1) + "*" * m.group(2).count("*")


def enum_of(type_text, enums):
    """The enum a parameter type names, if it is a simple enum taken by value."""
    if "*" in type_text or "&" in type_text:
        return None
    for word in re.findall(r"\w+", type_text):
        if word in enums:
            return word
    return None


def main():
    if len(sys.argv) not in (2, 3):
        raise SystemExit(__doc__.split("\n\n")[1])
    checkout = pathlib.Path(sys.argv[1])
    default_out = (
        pathlib.Path(__file__).resolve().parent.parent
        / "data"
        / "swift-runtime-functions.txt"
    )
    out = pathlib.Path(sys.argv[2]) if len(sys.argv) == 3 else default_out
    include = checkout / "include"
    commit = git(checkout, "rev-parse", "--short=11", "HEAD")
    date = git(checkout, "log", "-1", "--format=%cs")

    entries = read_def(include)
    declarations = read_declarations(include / "swift", entries)
    enums = read_enums(include / "swift")

    used_enums = set()
    funcs = []
    without = []
    for name in sorted(entries):
        module, cc, returns, args, attrs = entries[name]
        dropped = UNDEFINED_ARGS.get(name, 0)
        decl, swift_registers, swift_registers_only = next(
            (
                (d, r, o)
                for d, r, o in declarations.get(name, [])
                if len(d) == len(args)
            ),
            (None, False, False),
        )
        if decl is None and name in declarations:
            counts = sorted({len(d) for d, *_ in declarations[name]})
            report(
                f"{name}: header has {counts} parameters, .def {len(args)}; .def used"
            )
        elif decl is None and module in ("Swift", "_Concurrency"):
            without.append(name)
        params = []
        for i, arg in enumerate(args[: len(args) - dropped]):
            pname, ptype = decl[i] if decl else (None, "")
            enum = enum_of(ptype, enums)
            if enum and enums[enum][0] != IRGEN_INT_SIZES.get(arg):
                report(
                    f"{name}: {pname} is {enum} in the header and {arg} in the .def; {arg} used"
                )
                enum = None
            if enum:
                used_enums.add(enum)
            ptext = f"enum {enum}" if enum else arg
            pointee = pointee_of(ptype) if arg in UNTYPED_POINTERS else None
            if pointee:
                ptext += "=" + pointee
            params.append(f"{pname}:{ptext}" if pname else ptext)
        kept = [a for a in attrs if a in ATTRIBUTES]
        if swift_registers:
            kept.append(SWIFT_REGISTER_PARAMS)
        if swift_registers_only:
            kept.append(SWIFT_REGISTERS_ONLY)
        funcs.append(
            "\t".join(
                [
                    "func",
                    name,
                    module,
                    cc,
                    ",".join(returns),
                    ",".join(kept) or "-",
                    *params,
                ]
            )
        )
    report(
        f"{len(without)} Swift and _Concurrency entries without a header declaration"
    )
    for name, count in sorted(UNDEFINED_ARGS.items()):
        report(f"{name}: last {count} parameter(s) left out (UNDEFINED_ARGS)")

    lines = [f"# swift {commit} {date}, generated by devtools/gen_runtime_functions.py"]
    for name in sorted(used_enums):
        size, values, notes = enums[name]
        for note in notes:
            report(f"enum {name}: {note}")
        lines.append(
            "\t".join(["enum", name, str(size), *(f"{k}={v:#x}" for k, v in values)])
        )
    lines += funcs
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report(f"{out}: {len(used_enums)} enums, {len(funcs)} functions")


if __name__ == "__main__":
    main()
