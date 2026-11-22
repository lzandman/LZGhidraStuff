#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
"""Compares the hits in an analyzeHeadless log or a markup dump with expected-strings.txt.

    python3 fixtures/check_report.py headless.log fixtures/expected-strings.txt
    python3 fixtures/check_report.py headless.log --none   # -Onone build: no hit expected
    python3 fixtures/check_report.py strings-dump.txt fixtures/expected-strings.txt

The log has one SWIFTSTR line per hit (the analyzer's report); the dump, written by
ghidra_scripts/DumpSwiftStrings.java, has one MARK line per string in a bookmark.

A hit matches an expected line if the literal and kind are equal and one of the
mangled names at the function entry demangles (swift demangle --simplified) to
the expected function. Prints missing and unexpected entries; exit status 1 if
there are any.

A dump of a program with the string block (option "String block") also has BLOCK
and BLOCKREF lines. Then every expected small literal except the empty one must
be in the block once, no other literal may be there, and BLOCKREF lines (a
missing or an extra reference) count as errors.

A dump also has DECOMP, LARGEREF and LARGEREF-WRONG lines. Errors, one line each,
with the function's demangled name:
- "decompiler none": the decompiled C shows neither an equate nor the comment
  line of a string;
- "decompiler pointer": the C shows word 0 of a small string as an address,
  and the string has no comment line there;
- "large ref missing" / "large ref twice": a large string without a reference
  from its function to its bytes, or with more references than it has hits in
  the function;
- "large ref wrong": a reference from an instruction to the bytes of a large
  string less 32 whose value reaches an OR (the value word 1 is built from).
"""

import re
import subprocess
import sys

LINE = re.compile(
    r"SWIFTSTR\t(\S+)\t(.+?)\t(\S+)\t(small|large)\t(\w+)\t(\w+)\t(\".*\") \("
)
MARK = re.compile(r"^MARK\t(\S+)\t(.+?)\t(\S+)\t(small|large)\t(\w+)\t(\".*\")$")
BLOCK = re.compile(r"^BLOCK\t(\S+)\t(\".*\")\t(\S+)\t(\S+)$")
DECOMP = re.compile(r"^DECOMP\t(\S+)\t(\S+)\t(\".*\"\??)\t(\w+)\t(\S+)$")
LARGEREF = re.compile(r"^LARGEREF\t(\S+)\t(\S+)\t(\".*\")\t(\S+)\t(\S+)$")
LARGEREF_WRONG = re.compile(r"^LARGEREF-WRONG\t(\S+)\t(\S+)\t(\S+)\t(\".*\")$")


def demangle(names):
    out = subprocess.run(
        ["swift", "demangle", "--simplified"],
        input="\n".join(names),
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return dict(zip(names, out.splitlines(), strict=False))


def main():
    log, expected_path = sys.argv[1], sys.argv[2]
    hits = []
    block = []
    block_refs = []
    decomp = []
    large_refs = []
    large_wrong = []
    with open(log, encoding="utf-8") as f:
        for line in f:
            m = BLOCK.match(line.rstrip("\n"))
            if m:
                block.append(m.group(2))
                continue
            m = DECOMP.match(line.rstrip("\n"))
            if m:
                decomp.append(m.groups())
                continue
            m = LARGEREF.match(line.rstrip("\n"))
            if m:
                large_refs.append(m.groups())
                continue
            m = LARGEREF_WRONG.match(line.rstrip("\n"))
            if m:
                large_wrong.append(m.groups())
                continue
            if line.startswith("BLOCKREF-"):
                block_refs.append(line.rstrip("\n"))
                continue
            m = LINE.search(line)
            if m:
                hits.append(m.groups())
                continue
            m = MARK.match(line.rstrip("\n"))
            if m:
                entry, symbols, at, kind, confidence, literal = m.groups()
                hits.append((entry, symbols, at, kind, "-", confidence, literal))
    mangled = sorted({n for h in hits for n in h[1].split("|")})
    names = demangle(mangled) if mangled else {}
    expected = set()
    if expected_path != "--none":
        with open(expected_path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if line and not line.startswith("#"):
                    func, literal, kind = line.split("\t")
                    expected.add((func, literal, kind))

    expected_funcs = {e[0] for e in expected}
    found = set()
    unexpected = set()
    for _, symbols, _, kind, _, _, literal in hits:
        funcs = [names.get(n, n) for n in symbols.split("|")]
        # The linker folds identical functions; only the names expected-strings.txt lists count.
        listed = [f for f in funcs if f in expected_funcs]
        if not listed:
            unexpected.add((" | ".join(funcs), literal, kind))
        for f in listed:
            found.add((f, literal, kind))
            if (f, literal, kind) not in expected:
                unexpected.add((f, literal, kind))
    missing = sorted(expected - found)
    unexpected = sorted(unexpected)
    for m in missing:
        print("missing:   ", "\t".join(m))
    for u in unexpected:
        print("unexpected:", "\t".join(u))
    # One expected string can be built at several sites, so hits can outnumber the found entries.
    summary = (
        f"{len(expected)} expected, {len(expected) - len(missing)} found, {len(missing)} missing, "
        f"{len(unexpected)} unexpected; {len(hits)} hits"
    )
    block_errors = 0
    if block:
        want = {e[1] for e in expected if e[2] == "small" and e[1] != '""'}
        errors = [f"block missing:    {t}" for t in sorted(want - set(block))]
        errors += [f"block unexpected: {t}" for t in sorted(set(block) - want)]
        errors += [
            f"block twice:      {t}"
            for t in sorted({t for t in block if block.count(t) > 1})
        ]
        errors += block_refs
        for e in errors:
            print(e)
        block_errors = len(errors)
        summary += f"; block: {len(block)} strings, {block_errors} difference{'' if block_errors == 1 else 's'}"
    markup_errors = markup(hits, names, expected_funcs, decomp, large_refs, large_wrong)
    for e in markup_errors:
        print(e)
    if decomp or large_refs:
        n = len(markup_errors)
        summary += f"; markup: {n} difference{'' if n == 1 else 's'}"
    print(summary)
    return 1 if missing or unexpected or block_errors or markup_errors else 0


def markup(hits, names, expected_funcs, decomp, large_refs, large_wrong):
    """The error lines of the DECOMP, LARGEREF and LARGEREF-WRONG lines, sorted."""
    # Function entry -> its name: the expected one if a symbol demangles to it.
    func_at = {}
    for entry, symbols, *_ in hits:
        funcs = [names.get(n, n) for n in symbols.split("|")]
        listed = [f for f in funcs if f in expected_funcs]
        func_at[entry] = " | ".join(listed or funcs)
    errors = set()
    for entry, _, label, how, word0 in decomp:
        func = func_at.get(entry, entry)
        if how == "none":
            errors.add(f"decompiler none:    {func}\t{label}")
        if word0 == "pointer":
            errors.add(f"decompiler pointer: {func}\t{label}")
    # A literal can have several hits in a function, one reference each.
    hits_of = {}
    for entry, _, literal, _, _ in large_refs:
        hits_of[(entry, literal)] = hits_of.get((entry, literal), 0) + 1
    for entry, _, literal, _, froms in large_refs:
        func = func_at.get(entry, entry)
        n = 0 if froms == "-" else len(froms.split(","))
        if n == 0:
            errors.add(f"large ref missing:  {func}\t{literal}")
        elif n > hits_of[(entry, literal)]:
            errors.add(f"large ref twice:    {func}\t{literal}")
    for entry, _, _, literal in large_wrong:
        errors.add(f"large ref wrong:    {func_at.get(entry, entry)}\t{literal}")
    return sorted(errors)


if __name__ == "__main__":
    sys.exit(main())
