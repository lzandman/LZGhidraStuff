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
"""

import re
import subprocess
import sys

LINE = re.compile(
    r"SWIFTSTR\t(\S+)\t(.+?)\t(\S+)\t(small|large)\t(\w+)\t(\w+)\t(\".*\") \("
)
MARK = re.compile(r"^MARK\t(\S+)\t(.+?)\t(\S+)\t(small|large)\t(\w+)\t(\".*\")$")
BLOCK = re.compile(r"^BLOCK\t(\S+)\t(\".*\")\t(\S+)\t(\S+)$")


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
    with open(log, encoding="utf-8") as f:
        for line in f:
            m = BLOCK.match(line.rstrip("\n"))
            if m:
                block.append(m.group(2))
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
    print(summary)
    return 1 if missing or unexpected or block_errors else 0


if __name__ == "__main__":
    sys.exit(main())
