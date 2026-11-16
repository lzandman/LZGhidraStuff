#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# Builds LZGhidraGeneric and installs it into the user's extensions of the Ghidra in
# GHIDRA_INSTALL_DIR (default: Homebrew's).
# Quit the Ghidra GUI first: replacing the jar under a running Ghidra can break it.
set -e
if pgrep -f ghidra.GhidraRun >/dev/null; then
	echo "Ghidra GUI is running; quit it first." >&2
	exit 1
fi
cd "$(dirname "$0")/.."
export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/opt/homebrew/opt/ghidra/libexec}"
V=$(sed -n 's/^application.version=//p' "$GHIDRA_INSTALL_DIR/Ghidra/application.properties")
# shellcheck source=devtools/java-home.sh
. ../devtools/java-home.sh
gradle -q buildExtension
EXT=~/Library/ghidra/ghidra_${V:?no Ghidra in $GHIDRA_INSTALL_DIR}_PUBLIC/Extensions
rm -rf "$EXT/LZGhidraGeneric"
# dist/ keeps the zips of earlier days; install the newest (ls -t: by modification time).
# shellcheck disable=SC2012
unzip -q -o "$(ls -t dist/ghidra_"${V}"_PUBLIC_*_LZGhidraGeneric.zip | head -1)" -d "$EXT"
ls -la "$EXT/LZGhidraGeneric/lib"
