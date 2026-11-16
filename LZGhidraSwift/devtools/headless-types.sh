#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# headless-types.sh <binary> <name> [heap]
# Imports and auto-analyses <binary> headless (with the installed extension), runs the Swift
# Runtime Prototypes, Swift Data Types, Swift Self Types and Swift Error Register analyzers a
# second time (RunSwiftTypes: they must change nothing), DumpSwiftTypes, DumpSwiftSelf,
# DumpSwiftThrows and DumpSwiftRuntime, under memguard. Writes $OUT/<name>.log, $OUT/<name>.txt,
# $OUT/<name>-self.txt, $OUT/<name>-throws.txt and $OUT/<name>-runtime.txt and prints the summary
# lines. DECOMPILE (all, none, the default, or addresses separated by commas) chooses the
# functions whose decompiled C DumpSwiftSelf writes; DECOMPILE_THROWS=all makes DumpSwiftThrows
# write the C of every function with a Swift symbol, DECOMPILE_RUNTIME=all makes DumpSwiftRuntime
# write the C of every function in memory.
# OUT must be set (a directory outside the repository: no Apple content in the repo). FAST=1 adds the
# pre-script FastTypes.java, which turns off slow analyzers that this analyzer does not need.
# Reexports are off: for a binary with LC_REEXPORT_DYLIB (libSwiftDriver.dylib) the loader
# otherwise searches the dyld shared cache and extracts libraries from it, which ran out of a
# 4 GB heap during import.
# CACHE=<dyld shared cache file> makes <binary> an install name in that cache
# (/System/Library/PrivateFrameworks/X.framework/Versions/A/X): ImportDyldImage.java imports it
# with DyldCacheExtractLoader in a first run (analyzeHeadless -import takes only local files),
# and a second run analyses it with -process. CACHE_OPTS adds loader options to the import,
# without their leading dash (loader-authData true). The import reads the slide fixups of the whole
# cache and needs more heap than the analysis of a small image: IMPORT_HEAP, default 6G (4G ran
# out of heap on a large Swift framework).
: "${OUT:?set OUT to a scratch directory}"
BIN=$1; NAME=$2; HEAP=${3:-4G}
PRE=""; [ -n "$FAST" ] && PRE="-preScript FastTypes.java"
GHIDRA=${GHIDRA_INSTALL_DIR:-/opt/homebrew/opt/ghidra/libexec}
# shellcheck source=devtools/java-home.sh
. "$(dirname "$0")/../../devtools/java-home.sh"
mkdir -p "$OUT/sdt"
# A run killed by the deadline leaves its project; analyzeHeadless would reopen it.
rm -rf "$OUT/sdt/$NAME.gpr" "$OUT/sdt/$NAME.rep" "$OUT/sdt/$NAME.lock" "$OUT/sdt/$NAME.lock~"
cd "$(dirname "$0")/.." || exit
MEMGUARD=$(cd ../devtools && pwd)/memguard.py
START=$(date +%s)
if [ -n "$CACHE" ]; then
  # $CACHE_OPTS is split into words on purpose.
  # shellcheck disable=SC2086
  GHIDRA_HEADLESS_MAXMEM=${IMPORT_HEAP:-6G} python3 "$MEMGUARD" "${MEMGUARD_GIB:-12}" -- \
    "$GHIDRA"/support/analyzeHeadless "$OUT/sdt" "$NAME" -scriptPath "$(cd ../devtools && pwd)/ghidra_scripts" \
    -postScript ImportDyldImage.java "$CACHE" "$BIN" "$NAME" $CACHE_OPTS > "$OUT/$NAME.log" 2>&1
  echo "import exit $?, $(( $(date +%s) - START )) s"
  set -- -process "$NAME"
else
  set -- -import "$BIN" -loader MachoLoader -loader-reexport false
  : > "$OUT/$NAME.log"
fi
# $PRE is split into words on purpose.
# shellcheck disable=SC2086
GHIDRA_HEADLESS_MAXMEM=$HEAP python3 "$MEMGUARD" "${MEMGUARD_GIB:-12}" -- \
  "$GHIDRA"/support/analyzeHeadless "$OUT/sdt" "$NAME" "$@" -deleteProject \
  -scriptPath "ghidra_scripts;devtools/ghidra_scripts" $PRE -postScript RunSwiftTypes.java \
  -postScript DumpSwiftTypes.java "$OUT/$NAME.txt" \
  -postScript DumpSwiftSelf.java "$OUT/$NAME-self.txt" "${DECOMPILE:-none}" \
  -postScript DumpSwiftThrows.java "$OUT/$NAME-throws.txt" "${DECOMPILE_THROWS:-none}" \
  -postScript DumpSwiftRuntime.java "$OUT/$NAME-runtime.txt" "${DECOMPILE_RUNTIME:-none}" >> "$OUT/$NAME.log" 2>&1
echo "exit $?, $(( $(date +%s) - START )) s"
grep -E 'Swift (Data|Self) Types: |Swift Error Register: |Swift Runtime Prototypes: |RunSwift(Runtime|Types|Self|Throws):|DumpSwift(Types|Self|Throws|Runtime):|SWIFTRT-WARN[[:space:]]|SWIFTDT-(WARN|PLACEHOLDER)|SWIFTSELF-(WARN|VTABLE|DECOMP)|SWIFTERR-WARN|Total Time|OutOfMemory|Exception' \
  "$OUT/$NAME.log" | sed 's/^.*INFO  //' | cut -c1-400
