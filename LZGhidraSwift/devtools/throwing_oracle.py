# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
"""Classifies Swift symbols with swift-demangle --tree-only, as the reference for ThrowingSymbol.

throwing_oracle.py <symbols.txt> <out.tsv>

For each symbol (one per line), writes: symbol, class, wrappers (tab-separated). The class is
none, throws, typed, async-none, async-throws or async-typed, from the annotations of the
function type of the top entity (Function, Allocator, Constructor), looked up through the
wrappers Static, DispatchThunk, MethodDescriptor and ProtocolWitness, and after the
specialization nodes, which come first in the tree; "other" for symbols
without such an entity (accessors, metadata, ...), and "error" for symbols swift-demangle does
not demangle. The wrappers are the node kinds passed on the way, joined with "/".
"""

import subprocess
import sys

ENTITIES = {"Function", "Allocator", "Constructor"}
WRAPPERS = {"Static", "DispatchThunk", "MethodDescriptor", "ProtocolWitness"}
SPECIALIZATION = (
    "Specialization",
    "SpecializationNotReAbstracted",
    "SpecializationPrespecialized",
    "InlinedGenericFunction",
)


def parse(lines):
    """[(depth, kind)] from the indented tree."""
    nodes = []
    for line in lines:
        depth = (len(line) - len(line.lstrip(" "))) // 2
        nodes.append((depth, line.strip().split(",")[0].removeprefix("kind=")))
    return nodes


def children(nodes, i):
    depth = nodes[i][0]
    out = []
    j = i + 1
    while j < len(nodes) and nodes[j][0] > depth:
        if nodes[j][0] == depth + 1:
            out.append(j)
        j += 1
    return out


def first_entity(nodes, kids):
    """(index of the entity node or None, wrapper kinds)."""
    wrappers = []
    i = kids[0] if kids else None
    while i is not None and nodes[i][1] not in ENTITIES:
        wrappers.append(nodes[i][1])
        if nodes[i][1] not in WRAPPERS:
            return None, wrappers
        inner = [c for c in children(nodes, i) if nodes[c][1] in ENTITIES | WRAPPERS]
        i = inner[0] if inner else None
    return i, wrappers


def classify(nodes):
    if not nodes or nodes[0][1] != "Global":
        return "error", ""
    kids = children(nodes, 0)
    # A specialization node comes before the entity it specializes.
    spec = [k for k in kids if nodes[k][1].endswith(SPECIALIZATION)]
    rest = [k for k in kids if k not in spec]
    entity, wrappers = first_entity(nodes, rest)
    wrapped = "/".join(
        [nodes[k][1] for k in spec] + wrappers + [nodes[k][1] for k in rest[1:]]
    )
    if entity is None:
        return "other", wrapped
    types = [c for c in children(nodes, entity) if nodes[c][1] == "Type"]
    if not types:
        return "other", wrapped
    n = children(nodes, types[-1])[0]
    if nodes[n][1] == "DependentGenericType":
        inner = [c for c in children(nodes, n) if nodes[c][1] == "Type"][0]
        n = children(nodes, inner)[0]
    if nodes[n][1] != "FunctionType":
        return "other", wrapped
    kinds = {nodes[c][1] for c in children(nodes, n)}
    prefix = "async-" if "AsyncAnnotation" in kinds else ""
    if "ThrowsAnnotation" in kinds:
        return prefix + "throws", wrapped
    if "TypedThrowsAnnotation" in kinds:
        return prefix + "typed", wrapped
    return prefix + "none", wrapped


def main():
    source, target = sys.argv[1:3]
    with open(source, encoding="utf-8") as f:
        symbols = [s.strip() for s in f if s.strip()]
    tool = subprocess.check_output(
        ["xcrun", "--find", "swift-demangle"], text=True
    ).strip()
    batch = 5000
    with open(target, "w", encoding="utf-8") as out:
        for b in range(0, len(symbols), batch):
            chunk = symbols[b : b + batch]
            run = subprocess.run(
                [tool, "--tree-only"],
                input="\n".join(chunk) + "\n",
                capture_output=True,
                text=True,
                check=True,
            )
            blocks = run.stdout.split("Demangling for ")[1:]
            if len(blocks) != len(chunk):
                sys.exit(
                    f"swift-demangle: {len(blocks)} trees for {len(chunk)} symbols"
                )
            for symbol, block in zip(chunk, blocks, strict=True):
                lines = [line for line in block.splitlines()[1:] if line.strip()]
                cls, wrapped = classify(parse(lines))
                out.write(f"{symbol}\t{cls}\t{wrapped}\n")


if __name__ == "__main__":
    main()
