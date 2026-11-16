#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# runtime-layouts.sh <output file> <binary>
# Writes the layouts of <binary>'s Swift types as the Swift runtime sees them
# (runtime-layouts/RuntimeLayouts.swift), for devtools/compare_runtime.py against a
# DumpSwiftTypes dump. Builds the dylib into build/runtime-layouts first. An executable is run
# with the dylib inserted (it exits before main); a dylib is loaded into a small host program.
# The binary's own code does not run, but its dependencies' initializers do. Fails on binaries
# with hardened runtime (DYLD_INSERT_LIBRARIES is ignored there). The binary's directory is on
# DYLD_LIBRARY_PATH, for @rpath dependencies; add more with RUNTIME_LAYOUTS_PATH. Write the
# output to a directory outside the repository (third-party content).
# <binary> may also be an image of the dyld shared cache, which has no file on disk: a path that
# dyld_info resolves (for example /System/Library/PrivateFrameworks/<F>.framework/<F>). It is
# loaded with dlopen like a dylib, and its own initializers run.
set -e
OUTFILE=$1; BIN=$2
in_cache() { [ ! -e "$1" ] && dyld_info -platform "$1" 2>/dev/null | grep -q .; }
if [ -z "$OUTFILE" ] || { [ ! -f "$BIN" ] && ! in_cache "$BIN"; }; then
	echo "usage: runtime-layouts.sh <output file> <binary>" >&2
	exit 2
fi
DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD="$DIR/../build/runtime-layouts"
mkdir -p "$BUILD"
if [ ! -f "$BUILD/libRuntimeLayouts.dylib" ] ||
	[ -n "$(find "$DIR/runtime-layouts" -newer "$BUILD/libRuntimeLayouts.dylib")" ]; then
	clang -c -O1 "$DIR/runtime-layouts/runtime_layouts_init.c" -o "$BUILD/init.o"
	swiftc -emit-library -O -module-name RuntimeLayouts "$DIR/runtime-layouts/RuntimeLayouts.swift" \
		"$BUILD/init.o" -o "$BUILD/libRuntimeLayouts.dylib"
	printf 'int main(void) { return 0; }\n' | clang -x c - -o "$BUILD/host"
fi
# DYLD_INSERT_LIBRARIES is set only in the subshell that runs the binary: with SIP off it also
# reaches system tools (file, dyld_info, tail), which are arm64e and abort on the arm64 dylib.
if in_cache "$BIN"; then
	KIND=cache; LIBS=$RUNTIME_LAYOUTS_PATH
else
	file "$BIN" | grep -q 'dynamically linked shared library' && KIND=dylib || KIND=exe
	BINDIR="$(cd "$(dirname "$BIN")" && pwd)"
	LIBS="$BINDIR${RUNTIME_LAYOUTS_PATH:+:$RUNTIME_LAYOUTS_PATH}"
fi
NAME="$(basename "$BIN")"
(
	export DYLD_LIBRARY_PATH="$LIBS" DYLD_INSERT_LIBRARIES="$BUILD/libRuntimeLayouts.dylib"
	export RUNTIME_LAYOUTS_OUT="$OUTFILE"
	case $KIND in
	cache) RUNTIME_LAYOUTS_LOAD="$BIN" RUNTIME_LAYOUTS_IMAGE="/$NAME" "$BUILD/host" ;;
	dylib) RUNTIME_LAYOUTS_LOAD="$BINDIR/$NAME" RUNTIME_LAYOUTS_IMAGE="/$NAME" "$BUILD/host" ;;
	*) "$BIN" ;;
	esac
)
tail -1 "$OUTFILE"
