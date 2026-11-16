#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# time-analyzers.sh <project dir> <project name> <program> <out dir> [heap]
# Opens <program> read-only in an existing project, imported with the LZ analyzers off
# (DisableLZAnalyzers.java as pre-script), runs TimeSwiftAnalyzers on it and writes the dumps of
# all five analyzers, under memguard, with the installed extension. Read-only: the changes are
# thrown away, so every run starts from the same program. Writes <out dir>/run.log, types.txt,
# self.txt, throws.txt, runtime.txt and strings.txt, and prints the TIME and PHASE lines.
# Heap default 4G. THREADS=N sets String Literals' option "Decompiler threads" (default 0,
# automatic), TIMEOUT=N its option "Decompiler timeout (sec)" (default 60). Install the build to
# measure first (install.sh) and quit the Ghidra GUI.
set -e
PROJ=$1; NAME=$2; PROG=$3; O=$4; HEAP=${5:-4G}
: "${O:?usage: time-analyzers.sh <project dir> <project name> <program> <out dir> [heap]}"
GHIDRA=${GHIDRA_INSTALL_DIR:-/opt/homebrew/opt/ghidra/libexec}
# shellcheck source=devtools/java-home.sh
. "$(dirname "$0")/../../devtools/java-home.sh"
O=$(mkdir -p "$O" && cd "$O" && pwd)
cd "$(dirname "$0")/.."
MEMGUARD=$(cd ../devtools && pwd)/memguard.py
START=$(date +%s)
status=0
GHIDRA_HEADLESS_MAXMEM=$HEAP python3 "$MEMGUARD" "${MEMGUARD_GIB:-12}" -- \
	"$GHIDRA"/support/analyzeHeadless "$PROJ" "$NAME" -process "$PROG" -readOnly -noanalysis \
	-scriptPath "ghidra_scripts;devtools/ghidra_scripts" \
	-postScript TimeSwiftAnalyzers.java ${THREADS:+threads=$THREADS} ${TIMEOUT:+timeout=$TIMEOUT} \
	-postScript DumpSwiftTypes.java "$O/types.txt" \
	-postScript DumpSwiftSelf.java "$O/self.txt" none \
	-postScript DumpSwiftThrows.java "$O/throws.txt" none \
	-postScript DumpSwiftRuntime.java "$O/runtime.txt" none \
	-postScript DumpSwiftStrings.java "$O/strings.txt" > "$O/run.log" 2>&1 || status=$?
echo "exit $status, $(( $(date +%s) - START )) s"
grep -E '^INFO  TimeSwiftAnalyzers.java> (TIME|PHASE|SKIP)	' "$O/run.log" |
	sed -e 's/^INFO  TimeSwiftAnalyzers.java> //' -e 's/ (GhidraScript) *$//'
grep -E 'memguard|OutOfMemory' "$O/run.log" || true
exit $status
