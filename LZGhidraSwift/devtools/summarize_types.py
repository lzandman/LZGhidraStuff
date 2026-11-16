#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
"""Summarizes headless-types.sh logs and dumps as Markdown survey tables.

    python3 summarize_types.py [--details] $OUT/*.log

Prints one Markdown table row per log (the first analyzer run; the second run
only for whether it changed the program), then the totals. With --details, also
per binary: the reasons for types without data type, the warnings, and the
Swift types of the fields left undefined (from the .txt dump next to the log),
grouped by module. Log lines appear twice in the logs, so lines are
deduplicated. The last column names the Java exceptions in the log (any
analyzer's or script's), with "(LZGhidraSwift)" when a stack frame is in this
extension; a run that threw in the analyzer has no summary line, so a row
without one shows only the exceptions.
"""

import collections
import re
import sys

COLUMNS = (
    "| Binary | Types | Static | Built | Fields | Typed | Undefined | Demangler replaced "
    "| Warnings | Unresolved refs | Second run | Total time | Peak RSS | Exceptions |"
)


def first(pattern, text):
    match = re.search(pattern, text)
    return match.groups() if match else None


def exceptions(text):
    """The distinct Java exceptions thrown in a log, and whether one came from this extension.

    The analyzer's SWIFTTYPE/SWIFTFIELD/SWIFTDT lines are left out: Swift type
    names such as llbuildSwift.DatabaseError look like Java class names.
    """
    text = re.sub(r"^INFO  SWIFT[^\n]*\n?", "", text, flags=re.MULTILINE)
    names = sorted(
        set(
            re.findall(
                r"\b((?:java|javax|jdk|sun|ghidra|docking|generic|lzghidraswift)"
                r"(?:\.\w+)*\.[A-Z]\w*(?:Exception|Error))\b",
                text,
            )
        )
    )
    if not names:
        return "none"
    ours = (
        " (LZGhidraSwift)"
        if re.search(r"^\s*at lzghidraswift\.", text, re.MULTILINE)
        else ""
    )
    return ", ".join(names) + ours


def summarize(path, details):
    with open(path, encoding="utf-8", errors="replace") as log:
        text = log.read()
    name = path.rsplit("/", 1)[-1].removesuffix(".log")
    run = text.split("RunSwiftTypes.java>")[0]
    types = first(r"found (\d+) Swift types", run)
    static = first(r"layouts: (\d+) types with static metadata", run)
    data = first(
        r"data types: (\d+) structs, (\d+) classes, (\d+) enums, (\d+) types skipped; "
        r"(\d+) fields: (\d+) typed, (\d+) undefined .*?placeholders: (\d+) replaced",
        run,
    )
    if not (types and static and data):
        print(
            f"| `{name}` | no summary (see the log); exceptions: {exceptions(text)} |"
        )
        return None
    unresolved = first(r"(\d+) unresolved\)", run)
    second = first(r"modification number \d+ -> \d+ \((\w+)\)", text)
    total = first(r"Total Time\s+(\d+) secs", text)
    peak = first(r"peak RSS ([\d.]+) GiB", text)
    warnings = set(re.findall(r"SWIFTDT-WARN\t([^\n]*?) \(Swift", run))
    row = [
        int(types[0]),
        int(static[0]),
        int(data[0]) + int(data[1]) + int(data[2]),
        int(data[4]),
        int(data[5]),
        int(data[6]),
        int(data[7]),
        len(warnings),
        int(unresolved[0]) if unresolved else 0,
    ]
    cells = " | ".join(f"{v:,}" for v in row)
    print(
        f"| `{name}` | {cells} | {second[0] if second else '?'} "
        f"| {total[0] + ' s' if total else '<1 s'} | {peak[0] + ' GiB' if peak else '?'} "
        f"| {exceptions(text)} |"
    )
    if details:
        skips = dict(re.findall(r"SWIFTDT-SKIP\t([^\t]*)\t([^\n(]*)", run))
        # Classes with an Objective-C superclass (and their subclasses) count as one
        # reason; the superclasses are listed after it.
        superclasses = collections.Counter()
        reasons = collections.Counter()
        for reason in skips.values():
            slid = re.match(r"Objective-C superclass (\S+):", reason)
            if slid:
                superclasses[slid.group(1)] += 1
                reasons["Objective-C superclass"] += 1
            else:
                reasons[reason.strip()] += 1
        print("    skipped:", dict(reasons))
        if superclasses:
            print("    Objective-C superclasses:", dict(superclasses.most_common()))
        for warning in sorted(warnings)[:10]:
            print("    WARN", warning)
        undefined = collections.Counter()
        try:
            with open(path.removesuffix(".log") + ".txt", encoding="utf-8") as dump:
                for line in dump:
                    cols = line.rstrip("\n").split("\t")
                    if (
                        cols[0] == "FIELD"
                        and len(cols) > 5
                        and cols[5].startswith("undefined")
                    ):
                        undefined[re.sub(r"<.*", "<…>", cols[4])] += 1
        except FileNotFoundError:
            pass
        for swift_type, count in undefined.most_common(12):
            print(f"    undefined x{count}: {swift_type}")
    return row


def main():
    args = [a for a in sys.argv[1:] if a != "--details"]
    if not args:
        sys.exit(__doc__)
    print(COLUMNS)
    print("|" + " --- |" * (COLUMNS.count("|") - 1))
    totals = [0] * 9
    for path in args:
        row = summarize(path, "--details" in sys.argv)
        if row:
            totals = [a + b for a, b in zip(totals, row, strict=False)]
    print("| Total | " + " | ".join(f"{v:,}" for v in totals) + " | | | | |")


if __name__ == "__main__":
    main()
