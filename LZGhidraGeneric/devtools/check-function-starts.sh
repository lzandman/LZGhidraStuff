#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# check-function-starts.sh <dyld shared cache file> <install name>
# Headless check of the Mach-O Function Starts (Extracted DYLD) analyzer with the
# installed extension. Imports one image of the cache (ImportDyldImage.java), analyses it twice
# without saving (-readOnly), once with the analyzer and once with it turned off
# (DisableFunctionStarts.java), and prints the function count of each. The first count must be
# higher. Example install name: /System/Library/Frameworks/<X>.framework/Versions/A/<X>.
# OUT must be set (a scratch directory: it holds the extracted image's project). Both runs go
# through memguard.py. IMPORT_HEAP (default 6G) and HEAP (default 4G) set the Java heaps.
: "${OUT:?set OUT to a scratch directory}"
CACHE=${1:?usage: check-function-starts.sh <cache file> <install name>}
IMAGE=${2:?usage: check-function-starts.sh <cache file> <install name>}
GHIDRA=${GHIDRA_INSTALL_DIR:-/opt/homebrew/opt/ghidra/libexec}
# shellcheck source=devtools/java-home.sh
. "$(dirname "$0")/../../devtools/java-home.sh"
R=$(cd "$(dirname "$0")/.." && pwd)
MEMGUARD=$R/../devtools/memguard.py
SCRIPTS="$R/../devtools/ghidra_scripts;$R/devtools/ghidra_scripts"
NAME=functionstarts
mkdir -p "$OUT/fs"
rm -rf "$OUT/fs/$NAME.gpr" "$OUT/fs/$NAME.rep" "$OUT/fs/$NAME.lock" "$OUT/fs/$NAME.lock~"

GHIDRA_HEADLESS_MAXMEM=${IMPORT_HEAP:-6G} python3 "$MEMGUARD" "${MEMGUARD_GIB:-12}" -- \
  "$GHIDRA/support/analyzeHeadless" "$OUT/fs" "$NAME" -scriptPath "$SCRIPTS" \
  -postScript ImportDyldImage.java "$CACHE" "$IMAGE" "$NAME" > "$OUT/import.log" 2>&1
echo "import exit $?"

GHIDRA_HEADLESS_MAXMEM=${HEAP:-4G} python3 "$MEMGUARD" "${MEMGUARD_GIB:-12}" -- \
  "$GHIDRA/support/analyzeHeadless" "$OUT/fs" "$NAME" -process "$NAME" -readOnly \
  -scriptPath "$SCRIPTS" -postScript ProgramInfo.java > "$OUT/with.log" 2>&1
echo "with the analyzer, exit $?:"
grep -E 'functions added|instructions .*functions' "$OUT/with.log" | sed 's/^.*INFO  //'

GHIDRA_HEADLESS_MAXMEM=${HEAP:-4G} python3 "$MEMGUARD" "${MEMGUARD_GIB:-12}" -- \
  "$GHIDRA/support/analyzeHeadless" "$OUT/fs" "$NAME" -process "$NAME" -readOnly \
  -scriptPath "$SCRIPTS" -preScript DisableFunctionStarts.java -postScript ProgramInfo.java \
  > "$OUT/without.log" 2>&1
echo "without the analyzer, exit $?:"
grep -E 'instructions .*functions' "$OUT/without.log" | sed 's/^.*INFO  //'
rm -rf "$OUT/fs/$NAME.gpr" "$OUT/fs/$NAME.rep" "$OUT/fs/$NAME.lock" "$OUT/fs/$NAME.lock~"
