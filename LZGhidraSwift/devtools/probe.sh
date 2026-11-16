#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# probe.sh <project dir> <project path> <program> <entry>...
# Runs ProbeFlow.java (the analyzer's data flow on single functions, 20 s limit each) on a saved
# project, read-only, without analysis. Example, on a scratch copy of the GUI project:
#   devtools/probe.sh "$OUT/lproj" <project>/<folder>/<binary> AARCH64-64-cpu0x0 0x35d270
# Set SWIFTSTR_HITS=1 to print each hit. SWIFTSTR_TRACE=1 sets the property swiftstr.trace in the
# script's JVM (only useful with trace code added).
DIR=$1; P=$2; PROG=$3; shift 3
cd "$(dirname "$0")" || exit
MEMGUARD=$(cd ../../devtools && pwd)/memguard.py
GHIDRA=${GHIDRA_INSTALL_DIR:-/opt/homebrew/opt/ghidra/libexec}
# shellcheck source=devtools/java-home.sh
. ../../devtools/java-home.sh
GHIDRA_HEADLESS_MAXMEM=${HEAP:-6G} python3 "$MEMGUARD" "${MEMGUARD_GIB:-12}" -- \
  "$GHIDRA"/support/analyzeHeadless "$DIR" "$P" -process "$PROG" -noanalysis -readOnly \
  -scriptPath ghidra_scripts -postScript ProbeFlow.java "$@" 2>&1 | grep -E 'ProbeFlow.java>|Exception|memguard' | sed 's/^.*ProbeFlow.java> //'
