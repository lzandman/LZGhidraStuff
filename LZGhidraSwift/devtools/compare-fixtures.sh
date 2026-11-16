#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# compare-fixtures.sh <base dir> <new dir>
# For two run-fixtures.sh runs: the repository's checkers on the new run, then a diff of every
# dump and of the analyzers' SWIFT* and summary log lines (timings removed) against the base run.
# A behaviour-preserving change prints nothing between "diffs against base" and "done".
# The checkers' known differences are listed in fixtures/known-differences/ (test-fixtures.sh
# compares them; here they are printed as they are).
B=$1; N=$2
: "${B:?usage: compare-fixtures.sh <base dir> <new dir>}"; : "${N:?usage: compare-fixtures.sh <base dir> <new dir>}"
case "$B" in /*) ;; *) B="$PWD/$B" ;; esac
case "$N" in /*) ;; *) N="$PWD/$N" ;; esac
R=$(cd "$(dirname "$0")/.." && pwd)
F=$R/build/fixtures
cd "$R" || exit
echo "== checkers"
python3 fixtures/compare_layouts.py "$F"/expected-layouts.txt "$N"/Layouts.txt | tail -1
python3 fixtures/compare_layouts.py "$F"/expected-layouts-x86_64.txt "$N"/Layouts-x86_64.txt | tail -1
python3 fixtures/compare_layouts.py "$F"/expected-layouts.txt "$N"/Layouts-arm64e.txt | tail -1
python3 fixtures/check_self.py "$F"/libMethods.dylib fixtures/expected-self.txt "$N"/Methods-self.txt | tail -2
python3 fixtures/check_self.py "$F"/libMethods-x86_64.dylib fixtures/expected-self.txt "$N"/Methods-x86_64-self.txt | tail -2
python3 fixtures/check_self.py "$F"/libMethods-arm64e.dylib fixtures/expected-self.txt "$N"/Methods-arm64e-self.txt | tail -2
for b in Runtime Runtime-Onone Runtime-x86_64 Runtime-arm64e; do
	python3 fixtures/check_runtime.py "$F/lib$b.dylib" fixtures/expected-runtime.txt "$N/$b-runtime.txt" | tail -1
done
python3 fixtures/check_report.py "$N"/Strings.txt fixtures/expected-strings.txt | tail -1
python3 fixtures/check_report.py "$N"/Strings.log fixtures/expected-strings.txt | tail -1
python3 fixtures/check_report.py "$N"/Strings-Onone.log --none | tail -1
python3 fixtures/check_report.py "$N"/Strings-arm64e.txt fixtures/expected-strings.txt | tail -1
echo "== diffs against base"
norm() {
	grep -E 'SWIFT|LZ Swift [A-Za-z ]+:|Exception|ERROR' "$1" |
		grep -vE '[0-9.]+ secs$' |
		sed -E 's/^.*(INFO|WARN|ERROR) +//; s/[0-9]+\.[0-9]+ s([^[:alnum:]]|$)/T s\1/g; s/[0-9]+ ms([^[:alnum:]]|$)/T ms\1/g; s/ +\(.*Analyzer\) *$//'
}
TMP=$(mktemp -d)
for f in "$B"/*.txt; do
	n=$(basename "$f")
	if ! cmp -s "$f" "$N/$n"; then
		echo "DIFF $n: $(diff "$f" "$N/$n" | grep -c '^[<>]') lines"
	fi
done
for f in "$B"/*.log; do
	n=$(basename "$f")
	norm "$f" > "$TMP/b"
	norm "$N/$n" > "$TMP/n"
	if ! cmp -s "$TMP/b" "$TMP/n"; then
		echo "DIFF $n:"
		diff "$TMP/b" "$TMP/n" | head -20
	fi
done
rm -rf "$TMP"
echo "== done"
