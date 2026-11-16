#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# headless.sh <binary> <name> [heap] [extra DumpSwiftStrings args...]
# Imports and auto-analyses <binary> headless (with the installed extension), runs
# DumpSwiftStrings, under memguard. Writes $OUT/<name>.log and $OUT/<name>.txt and prints the
# summary lines. OUT must be set (a directory outside the repository: no Apple content in the repo).
# CACHE=<dyld shared cache file> makes <binary> an install name in that cache, imported by
# ImportDyldImage.java in a first run with heap IMPORT_HEAP (default 6G) and loader options
# CACHE_OPTS, as in headless-types.sh.
: "${OUT:?set OUT to a scratch directory}"
BIN=$1; NAME=$2; HEAP=${3:-4G}; shift 3 2>/dev/null
GHIDRA=${GHIDRA_INSTALL_DIR:-/opt/homebrew/opt/ghidra/libexec}
# shellcheck source=devtools/java-home.sh
. "$(dirname "$0")/../../devtools/java-home.sh"
mkdir -p "$OUT/sss"
rm -rf "$OUT/sss/$NAME.gpr" "$OUT/sss/$NAME.rep" "$OUT/sss/$NAME.lock" "$OUT/sss/$NAME.lock~"
cd "$(dirname "$0")/.." || exit
MEMGUARD=$(cd ../devtools && pwd)/memguard.py
START=$(date +%s)
if [ -n "$CACHE" ]; then
  # $CACHE_OPTS is split into words on purpose.
  # shellcheck disable=SC2086
  GHIDRA_HEADLESS_MAXMEM=${IMPORT_HEAP:-6G} python3 "$MEMGUARD" "${MEMGUARD_GIB:-12}" -- \
    "$GHIDRA"/support/analyzeHeadless "$OUT/sss" "$NAME" -scriptPath "$(cd ../devtools && pwd)/ghidra_scripts" \
    -postScript ImportDyldImage.java "$CACHE" "$BIN" "$NAME" $CACHE_OPTS > "$OUT/$NAME.log" 2>&1
  echo "import exit $?, $(( $(date +%s) - START )) s"
  SOURCE="-process"; TARGET=$NAME
else
  SOURCE="-import"; TARGET=$BIN
  : > "$OUT/$NAME.log"
fi
GHIDRA_HEADLESS_MAXMEM=$HEAP python3 "$MEMGUARD" "${MEMGUARD_GIB:-12}" -- \
  "$GHIDRA"/support/analyzeHeadless "$OUT/sss" "$NAME" "$SOURCE" "$TARGET" -deleteProject \
  -scriptPath ghidra_scripts -postScript DumpSwiftStrings.java "$OUT/$NAME.txt" "$@" >> "$OUT/$NAME.log" 2>&1
echo "exit $?, $(( $(date +%s) - START )) s"
tail -1 "$OUT/$NAME.log"
grep -E 'Swift String Literals( |:)|DumpSwiftStrings:|Total Time|OutOfMemory' "$OUT/$NAME.log" | sed 's/^.*INFO  //' | cut -c1-400
