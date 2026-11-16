#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# test-fixtures.sh [<extension zip>]
# The fixture tests in one command, with a pass or fail result. Builds the extension zip (unless one
# is given) and the fixtures, runs run-fixtures.sh twice (every fixture; then the Strings fixtures
# with the String block option on) and runs the checkers on the results.
# Ghidra's user settings directory is build/test-fixtures/config (XDG_CONFIG_HOME), so the zip is
# installed there: the user's own Ghidra settings and extensions are not touched, and no script
# class compiled by an earlier install is reused. The Ghidra GUI may stay open.
# A checker passes when its differences are exactly the lines in fixtures/known-differences/<check>.txt
# (no file: no differences), compared without addresses (0x... and FUN_...), which change with the
# Swift compiler version. A known difference that no longer occurs fails too, so that the file
# stays current. The rerun checks need a second run of each analyzer to change nothing.
# Writes the runs and the checker output to build/test-fixtures (emptied first). Exit status 1 if a
# check fails. About 6 minutes (M-series Mac, Ghidra 12.2). Needs GHIDRA_INSTALL_DIR or Homebrew's
# Ghidra, swiftc, and Rosetta for the x86_64 layouts.
# CHECK_ONLY=1: no build and no Ghidra runs; the checks only, on the runs of the previous call.
set -u
if [ $# -gt 0 ]; then
	ZIP=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
fi
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=devtools/java-home.sh
. ../devtools/java-home.sh
R=$(pwd)
T=$R/build/test-fixtures
F=$R/build/fixtures
K=$R/fixtures/known-differences

if [ -z "${CHECK_ONLY:-}" ]; then
	if [ $# -eq 0 ]; then
		echo "== gradle buildExtension"
		gradle -q buildExtension || exit 1
		ZIP=""
		for z in dist/*.zip; do
			# -nt is POSIX since 2024; shellcheck before 0.11 (Ubuntu 24.04 in CI) still warns.
			# shellcheck disable=SC3013
			if [ -z "$ZIP" ] || [ "$z" -nt "$ZIP" ]; then
				ZIP=$z
			fi
		done
		ZIP=$R/$ZIP
	fi
	echo "== make -C fixtures ($(swiftc --version 2>&1 | grep -o 'Apple Swift version [^ ]*' | head -1))"
	make -s -C fixtures all || exit 1

	rm -rf "$T"
	mkdir -p "$T"
	XDG_CONFIG_HOME=$T/config
	export XDG_CONFIG_HOME
	echo "== run-fixtures.sh $(basename "$ZIP")"
	devtools/run-fixtures.sh "$T/run" "$ZIP" || {
		echo "run-fixtures.sh failed; logs in $T/run" >&2
		exit 1
	}
	echo "== run-fixtures.sh, String block"
	STRING_BLOCK=1 devtools/run-fixtures.sh "$T/block" "$ZIP" || {
		echo "run-fixtures.sh failed; logs in $T/block" >&2
		exit 1
	}
fi
rm -rf "$T/checks"
mkdir -p "$T/checks"

COUNT=0
FAILED=0
# Code addresses in difference lines: 0x1770, FUN_00000fb8.
noaddr() {
	sed -E 's/0x[0-9a-f]+/0x?/g; s/FUN_[0-9a-f]+/FUN_?/g'
}
# check <name> <command...>: runs a checker. Its last output line is the summary, the lines before
# it the differences; they must be the known ones, and the exit status 1 exactly when there are any.
# Output on stderr (a traceback) or no output at all is a failure.
check() {
	name=$1
	shift
	COUNT=$((COUNT + 1))
	c=$T/checks/$name
	"$@" >"$c.out" 2>"$c.err"
	status=$?
	sed '$d' "$c.out" | noaddr | LC_ALL=C sort >"$c.got"
	if [ -f "$K/$name.txt" ]; then
		grep -v -e '^#' -e '^$' "$K/$name.txt" | noaddr | LC_ALL=C sort >"$c.known"
	else
		: >"$c.known"
	fi
	if [ -s "$c.got" ]; then want=1; else want=0; fi
	if [ ! -s "$c.err" ] && [ -s "$c.out" ] && [ "$status" -eq "$want" ] && cmp -s "$c.known" "$c.got"; then
		# Differences in an ok line are the known ones, in fixtures/known-differences/<check>.txt.
		known=
		if [ "$want" -eq 1 ]; then known=" [known differences]"; fi
		echo "ok    $name: $(tail -1 "$c.out")$known"
		return
	fi
	FAILED=$((FAILED + 1))
	echo "FAIL  $name (exit $status): $(tail -1 "$c.out")"
	diff "$c.known" "$c.got" | sed -n 's/^< /        known, gone: /p; s/^> /        new:         /p'
	sed 's/^/        stderr: /' "$c.err" | head -5
}

# rerun_types <log>...: RunSwiftTypes runs Swift Runtime Prototypes, the type analyzers and Swift
# Error Register a second time and logs "unchanged" or "CHANGED" for each.
rerun_types() {
	n=0
	for log in "$@"; do
		u=$(grep -c 'RunSwift[A-Za-z]*: .*(unchanged)' "$log")
		if [ "$u" -eq 0 ] || grep -q 'RunSwift[A-Za-z]*: .*(CHANGED)' "$log"; then
			echo "$(basename "$log"): $(grep -E 'RunSwift[A-Za-z]*: ' "$log" | sed 's/^.*INFO  //' | tr '\n' ' ')"
			n=$((n + 1))
		fi
	done
	echo "$# logs, $n with a change or no RunSwiftTypes line"
	[ "$n" -eq 0 ]
}

# rerun_strings <run>...: for each <run> (a path without .txt), RerunSwiftStrings added "user note"
# to two comments and ran the Swift String Literals analyzer again. <run>-b.txt must keep every user
# note the log reports and, without them, equal <run>.txt. <run>-c.txt (String block runs, after
# OneShotSwiftStrings) must equal <run>-b.txt.
rerun_strings() {
	n=0
	tab=$(printf '\t')
	for run in "$@"; do
		label=$(basename "$(dirname "$run")")/$(basename "$run")
		added=$(grep -c 'RerunSwiftStrings: user' "$run.log")
		kept=$(grep -c 'user note' "$run-b.txt")
		sed -e "/^COMMENT${tab}[^${tab}]*${tab}[A-Z]*${tab}user note\$/d" -e "s/${tab}user note\\\\n/$tab/" \
			"$run-b.txt" >"$T/checks/rerun.tmp"
		if [ "$added" -ne "$kept" ]; then
			echo "$label: $added user notes added, $kept in the second dump"
			n=$((n + 1))
		elif ! cmp -s "$run.txt" "$T/checks/rerun.tmp"; then
			echo "$label: second dump differs by more than the user notes"
			n=$((n + 1))
		fi
		if [ -f "$run-c.txt" ] && ! cmp -s "$run-b.txt" "$run-c.txt"; then
			echo "$label: one-shot dump differs from the second dump"
			n=$((n + 1))
		fi
	done
	rm -f "$T/checks/rerun.tmp"
	if [ "$n" -eq 1 ]; then s=; else s=s; fi
	echo "$# runs compared, $n difference$s"
	[ "$n" -eq 0 ]
}

# decompiler <file>...: logs, DumpSwiftSelf, DumpSwiftThrows and DumpSwiftRuntime dumps without a
# decompiler failure. One line per failure: in a dump the function of the "C" line before it, in a
# log the log line.
# A Ghidra without the native decompiler for this platform (the release zip on macOS, before gradle
# buildNatives) fails every decompilation; the analyzers still run, but the C texts in
# expected-self.txt, expected-throws.txt and expected-runtime.txt all fail.
decompiler() {
	n=0
	for f in "$@"; do
		label=$(basename "$(dirname "$f")")/$(basename "$f")
		hits=$(awk -v label="$label" '
			/decompile does not exist|DECOMP-FAILED|DECOMP-NOSTART|decompiler failed/ {
				if (prev ~ /^C\t/) {
					split(prev, p, "\t")
					print label ": " p[3] " (0x" p[2] "): decompiler failed"
				} else {
					line = $0
					sub(/^.*(INFO|WARN|ERROR)  /, "", line)
					print label ": " substr(line, 1, 200)
				}
			}
			{ prev = $0 }' "$f")
		if [ -n "$hits" ]; then
			echo "$hits"
			n=$((n + 1))
		fi
	done
	echo "$# files, $n with decompiler failures"
	[ "$n" -eq 0 ]
}

echo "== checks"
RUN=$T/run
BLK=$T/block
check decompiler decompiler "$RUN"/*.log "$RUN"/*-self.txt "$RUN"/*-throws.txt "$RUN"/*-runtime.txt "$BLK"/*.log
check layouts python3 fixtures/compare_layouts.py "$F/expected-layouts.txt" "$RUN/Layouts.txt"
check layouts-x86_64 python3 fixtures/compare_layouts.py "$F/expected-layouts-x86_64.txt" "$RUN/Layouts-x86_64.txt"
check layouts-arm64e python3 fixtures/compare_layouts.py "$F/expected-layouts.txt" "$RUN/Layouts-arm64e.txt"
check self python3 fixtures/check_self.py "$F/libMethods.dylib" fixtures/expected-self.txt "$RUN/Methods-self.txt"
check self-x86_64 python3 fixtures/check_self.py "$F/libMethods-x86_64.dylib" fixtures/expected-self.txt "$RUN/Methods-x86_64-self.txt"
check self-arm64e python3 fixtures/check_self.py "$F/libMethods-arm64e.dylib" fixtures/expected-self.txt "$RUN/Methods-arm64e-self.txt"
check throws python3 fixtures/check_throws.py "$F/libThrows.dylib" fixtures/expected-throws.txt "$RUN/Throws-throws.txt"
check throws-x86_64 python3 fixtures/check_throws.py "$F/libThrows-x86_64.dylib" fixtures/expected-throws.txt "$RUN/Throws-x86_64-throws.txt"
# The stripped copies: the symbols (addresses) come from the unstripped library, strip moves no code.
check throws-stripped python3 fixtures/check_throws.py "$F/libThrows.dylib" fixtures/expected-throws.txt "$RUN/Throws-stripped-throws.txt"
check throws-x86_64-stripped python3 fixtures/check_throws.py "$F/libThrows-x86_64.dylib" fixtures/expected-throws.txt "$RUN/Throws-x86_64-stripped-throws.txt"
check throws-arm64e python3 fixtures/check_throws.py "$F/libThrows-arm64e.dylib" fixtures/expected-throws.txt "$RUN/Throws-arm64e-throws.txt"
check throws-onone python3 fixtures/check_throws.py "$F/libThrows-Onone.dylib" fixtures/expected-throws.txt "$RUN/Throws-Onone-throws.txt"
check runtime python3 fixtures/check_runtime.py "$F/libRuntime.dylib" fixtures/expected-runtime.txt "$RUN/Runtime-runtime.txt"
check runtime-onone python3 fixtures/check_runtime.py "$F/libRuntime-Onone.dylib" fixtures/expected-runtime.txt "$RUN/Runtime-Onone-runtime.txt"
check runtime-x86_64 python3 fixtures/check_runtime.py "$F/libRuntime-x86_64.dylib" fixtures/expected-runtime.txt "$RUN/Runtime-x86_64-runtime.txt"
check runtime-arm64e python3 fixtures/check_runtime.py "$F/libRuntime-arm64e.dylib" fixtures/expected-runtime.txt "$RUN/Runtime-arm64e-runtime.txt"
check strings python3 fixtures/check_report.py "$RUN/Strings.txt" fixtures/expected-strings.txt
check strings-log python3 fixtures/check_report.py "$RUN/Strings.log" fixtures/expected-strings.txt
check strings-onone python3 fixtures/check_report.py "$RUN/Strings-Onone.log" --none
check strings-x86_64 python3 fixtures/check_report.py "$RUN/Strings-x86_64.txt" fixtures/expected-strings.txt
check strings-arm64e python3 fixtures/check_report.py "$RUN/Strings-arm64e.txt" fixtures/expected-strings.txt
check block python3 fixtures/check_report.py "$BLK/Strings.txt" fixtures/expected-strings.txt
check block-onone python3 fixtures/check_report.py "$BLK/Strings-Onone.log" --none
check rerun-types rerun_types "$RUN"/Layouts*.log "$RUN"/Methods*.log "$RUN"/Throws*.log "$RUN"/Runtime*.log
check rerun-strings rerun_strings "$RUN/Strings" "$RUN/Strings-Onone" "$RUN/Strings-x86_64" \
	"$RUN/Strings-arm64e" "$BLK/Strings" "$BLK/Strings-Onone" "$BLK/Strings-x86_64" "$BLK/Strings-arm64e"

echo "$COUNT checks, $FAILED failed; output in $T"
[ "$FAILED" -eq 0 ]
