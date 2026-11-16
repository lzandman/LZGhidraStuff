#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# survey-types.sh <heap> <binary>...
# For each binary: thins the $ARCH slice (default arm64) into $OUT/bin, runs headless-types.sh
# with FAST=1 under a deadline of $DEADLINE seconds (default 580: the whole Java process tree is
# killed then), and removes the slice (to save disk space). Logs and dumps go to
# $OUT/<name>[-<arch>].log/.txt; summarize them with summarize_types.py. One binary at a time,
# in the foreground. OUT must be set (a directory outside the repository: no third-party
# content in the repo).
: "${OUT:?set OUT to a scratch directory}"
HEAP=$1; shift
ARCH=${ARCH:-arm64}
DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT/bin"
for B in "$@"; do
	NAME=$(basename "$B")
	[ "$ARCH" != arm64 ] && NAME="$NAME-$ARCH"
	SLICE="$OUT/bin/$NAME"
	if lipo -archs "$B" 2>/dev/null | grep -qw "$ARCH" && [ "$(lipo -archs "$B")" != "$ARCH" ]; then
		lipo -thin "$ARCH" "$B" -o "$SLICE" || continue
	else
		cp "$B" "$SLICE" || continue
	fi
	printf "%s: " "$NAME"
	FAST=1 python3 "$DIR/deadline.py" "${DEADLINE:-580}" -- \
		"$DIR/headless-types.sh" "$SLICE" "$NAME" "$HEAP" | sed -n 1p
	rm -f "$SLICE"
done
