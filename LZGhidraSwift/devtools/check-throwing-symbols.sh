#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# check-throwing-symbols.sh [<symbols.txt>]
# Checks ThrowingSymbol (whether a Swift symbol names a throwing function) against swift-demangle.
# Without an argument, the symbols are the Swift symbols ($s) of the .tbd files in the macOS SDK
# (usr/lib/swift and the frameworks). Writes symbols.txt and oracle.tsv to OUT and prints the
# differences and a summary line. Needs Xcode (swift-demangle) and gradle compileJava first.
# About 10 seconds for the SDK's 460,000 symbols (M-series Mac).
: "${OUT:?set OUT to a scratch directory}"
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=devtools/java-home.sh
. ../devtools/java-home.sh
mkdir -p "$OUT"
if [ $# -gt 0 ]; then
	cp "$1" "$OUT/symbols.txt"
else
	SDK=$(xcrun --show-sdk-path) || exit 1
	find "$SDK/usr/lib/swift" "$SDK/System/Library/Frameworks" -maxdepth 4 -name '*.tbd' -print0 |
		xargs -0 grep -ho '_[$]s[A-Za-z0-9_]*' | LC_ALL=C sort -u >"$OUT/symbols.txt"
fi
python3 devtools/throwing_oracle.py "$OUT/symbols.txt" "$OUT/oracle.tsv" || exit 1
"${JAVA_HOME:+$JAVA_HOME/bin/}java" -cp build/classes/java/main devtools/CheckThrowingSymbols.java "$OUT/oracle.tsv"
