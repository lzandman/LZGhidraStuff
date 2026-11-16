#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
#
# Runs every light check and stops at the first failure: per extension `gradle lint test
# buildExtension`, then ruff, `sh -n` on the shell scripts, and shellcheck when it is installed.
# Needs GHIDRA_INSTALL_DIR (a Ghidra release install) for the Gradle checks. The fixture runs
# and the headless checks are not part of it; they need Ghidra, swiftc and memory headroom.
set -eu

cd "$(dirname "$0")"
# shellcheck source=devtools/java-home.sh
. devtools/java-home.sh

if [ -z "${GHIDRA_INSTALL_DIR:-}" ] && ! grep -qs '^GHIDRA_INSTALL_DIR=' "$HOME/.gradle/gradle.properties"; then
	echo "check.sh: GHIDRA_INSTALL_DIR is not set (environment or ~/.gradle/gradle.properties)" >&2
	exit 1
fi

for dir in */; do
	[ -f "$dir/build.gradle" ] || continue
	echo "== gradle lint test buildExtension: $dir"
	(cd "$dir" && gradle lint test buildExtension)
done

echo "== ruff"
ruff check .
ruff format --check .

scripts=$(git ls-files --cached --others --exclude-standard '*.sh')
echo "== sh -n"
for f in $scripts; do
	sh -n "$f"
done

if command -v shellcheck >/dev/null 2>&1; then
	echo "== shellcheck"
	# shellcheck disable=SC2086
	shellcheck $scripts
else
	echo "== shellcheck skipped: not installed"
fi

echo "all checks passed"
