#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# run-fixtures.sh <outdir> <extension zip>
# Installs the zip into the user's extensions of the Ghidra in GHIDRA_INSTALL_DIR (default:
# Homebrew's, replacing LZGhidraSwift there), then
# analyses every fixture headless, one at a time under memguard: headless-types.sh on Layouts
# and Methods (arm64, x86_64, arm64e; DECOMPILE=all for Methods) and Throws (arm64, x86_64,
# both also stripped, arm64e, arm64 -Onone; DECOMPILE_THROWS=all) and Runtime (arm64 -O and -Onone,
# x86_64, arm64e; DECOMPILE_RUNTIME=all), and the Strings fixtures (arm64
# -O, -Onone, x86_64, arm64e) with DumpSwiftStrings before and after RerunSwiftStrings. Writes the
# logs and dumps to <outdir>; compare two runs with compare-fixtures.sh. About 3 minutes in all.
# Build the fixtures first (make -C fixtures all). Quit the Ghidra GUI first.
# STRING_BLOCK=1: only the Strings fixtures, with the String block option on, and after the
# second dump a one-shot run on one function (OneShotSwiftStrings) and a third dump, <name>-c.txt,
# which must equal <name>-b.txt.
# XDG_CONFIG_HOME=<dir>: Ghidra's user settings directory is under <dir> instead of ~/Library, so
# the zip is installed there and the user's own Ghidra settings and extensions are not touched
# (test-fixtures.sh does this). The Ghidra GUI may then stay open.
set -e
OUTDIR=$1; ZIP=$2
: "${OUTDIR:?usage: run-fixtures.sh <outdir> <zip>}"; : "${ZIP:?usage: run-fixtures.sh <outdir> <zip>}"
if [ -z "$XDG_CONFIG_HOME" ] && pgrep -f ghidra.GhidraRun >/dev/null; then
	echo "Ghidra GUI is running; quit it first." >&2
	exit 1
fi
# Absolute paths without "..": Ghidra rejects a project path with a ".." element.
OUTDIR=$(mkdir -p "$OUTDIR" && cd "$OUTDIR" && pwd)
ZIP=$(cd "$(dirname "$ZIP")" && pwd)/$(basename "$ZIP")
GHIDRA=${GHIDRA_INSTALL_DIR:-/opt/homebrew/opt/ghidra/libexec}
# shellcheck source=devtools/java-home.sh
. "$(dirname "$0")/../../devtools/java-home.sh"
V=$(sed -n 's/^application.version=//p' "$GHIDRA/Ghidra/application.properties")
if [ -n "$XDG_CONFIG_HOME" ]; then
	# ApplicationUtilities.getDefaultUserSettingsDir: <XDG_CONFIG_HOME>/ghidra/ghidra_<version>_PUBLIC,
	# with "<user>-ghidra" instead of "ghidra" when the directory is outside the home directory.
	XDG_CONFIG_HOME=$(mkdir -p "$XDG_CONFIG_HOME" && cd "$XDG_CONFIG_HOME" && pwd -P)
	export XDG_CONFIG_HOME
	case "$XDG_CONFIG_HOME/" in
	"$(cd ~ && pwd -P)"/*) APPDIR=ghidra ;;
	*) APPDIR=$(id -un)-ghidra ;;
	esac
	EXT=$XDG_CONFIG_HOME/$APPDIR/ghidra_${V:?no Ghidra in $GHIDRA}_PUBLIC/Extensions
	mkdir -p "$EXT"
else
	EXT=~/Library/ghidra/ghidra_${V:?no Ghidra in $GHIDRA}_PUBLIC/Extensions
fi
rm -rf "$EXT/LZGhidraSwift"
# -DD: the extraction time, not the zip's 1980 dates, so that Ghidra compiles the scripts again
# instead of running the classes it compiled from an earlier install.
unzip -q -o -DD "$ZIP" -d "$EXT"
R=$(cd "$(dirname "$0")/.." && pwd)
MEMGUARD=$(cd "$R/../devtools" && pwd)/memguard.py
F=$R/build/fixtures
mkdir -p "$OUTDIR"
export OUT="$OUTDIR"
if [ -n "$STRING_BLOCK" ]; then
	PRE="-preScript EnableSwiftStringBlock.java"
	POST="-postScript OneShotSwiftStrings.java -postScript DumpSwiftStrings.java"
else
# Each run prints one line, "<fixture> exit N, T s": the first line of headless-types.sh with the
# name in front. sed reads the rest, where head would close the pipe and make the summary at the
# end of headless-types.sh fail with "Broken pipe".
for b in Layouts Layouts-x86_64 Layouts-arm64e; do
	"$R/devtools/headless-types.sh" "$F/lib$b.dylib" "$b" | sed -n "1s/^/$b /p"
done
for b in Methods Methods-x86_64 Methods-arm64e; do
	DECOMPILE=all "$R/devtools/headless-types.sh" "$F/lib$b.dylib" "$b" | sed -n "1s/^/$b /p"
done
for b in Throws Throws-x86_64 Throws-stripped Throws-x86_64-stripped Throws-arm64e Throws-Onone; do
	DECOMPILE_THROWS=all "$R/devtools/headless-types.sh" "$F/lib$b.dylib" "$b" | sed -n "1s/^/$b /p"
done
for b in Runtime Runtime-Onone Runtime-x86_64 Runtime-arm64e; do
	DECOMPILE_RUNTIME=all "$R/devtools/headless-types.sh" "$F/lib$b.dylib" "$b" | sed -n "1s/^/$b /p"
done
fi
cd "$R"
for b in Strings Strings-Onone Strings-x86_64 Strings-arm64e; do
	rm -rf "$OUTDIR/sss"
	mkdir -p "$OUTDIR/sss"
	START=$(date +%s)
	status=0
	# $PRE and $POST are split into words on purpose.
	# shellcheck disable=SC2086
	GHIDRA_HEADLESS_MAXMEM=4G python3 "$MEMGUARD" "${MEMGUARD_GIB:-12}" -- \
		$GHIDRA/support/analyzeHeadless "$OUTDIR/sss" "$b" -import "$F/lib$b.dylib" -deleteProject \
		-scriptPath "ghidra_scripts;devtools/ghidra_scripts" $PRE -postScript DumpSwiftStrings.java "$OUTDIR/$b.txt" \
		-postScript RerunSwiftStrings.java -postScript DumpSwiftStrings.java "$OUTDIR/$b-b.txt" \
		${POST:+$POST "$OUTDIR/$b-c.txt"} > "$OUTDIR/$b.log" 2>&1 || status=$?
	echo "$b exit $status, $(( $(date +%s) - START )) s"
	[ "$status" -eq 0 ] || exit "$status"
done
