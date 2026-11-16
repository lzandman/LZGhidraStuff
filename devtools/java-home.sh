# shellcheck shell=sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman
# Sourced (". devtools/java-home.sh") by the scripts that run Gradle, analyzeHeadless or java.
# Exports JAVA_HOME as Homebrew's JDK for the application.java.min of the Ghidra in GHIDRA (the
# headless scripts set it), else in GHIDRA_INSTALL_DIR, else in ~/.gradle/gradle.properties (as
# Gradle does), else Homebrew's Ghidra: openjdk@21 for Ghidra 12.1, openjdk@25 for 12.2.
# Gradle on an older JDK cannot read Ghidra's class files. analyzeHeadless with a new user settings directory (XDG_CONFIG_HOME) has no saved
# JDK and finds none without JAVA_HOME, so it stops ("Unable to prompt user for JDK path").
# A JAVA_HOME that is already set is kept (CI sets it with setup-java). Without that Homebrew JDK,
# JAVA_HOME stays unset.
lz_ghidra=${GHIDRA:-${GHIDRA_INSTALL_DIR:-}}
if [ -z "$lz_ghidra" ] && [ -f "$HOME/.gradle/gradle.properties" ]; then
	lz_ghidra=$(sed -n 's/^GHIDRA_INSTALL_DIR=//p' "$HOME/.gradle/gradle.properties")
fi
lz_ghidra=${lz_ghidra:-/opt/homebrew/opt/ghidra/libexec}
lz_java=""
if [ -f "$lz_ghidra/Ghidra/application.properties" ]; then
	lz_java=$(sed -n 's/^application.java.min=//p' "$lz_ghidra/Ghidra/application.properties")
fi
if [ -z "${JAVA_HOME:-}" ] && [ -n "$lz_java" ] && [ -d "/opt/homebrew/opt/openjdk@$lz_java" ]; then
	JAVA_HOME=/opt/homebrew/opt/openjdk@$lz_java
	export JAVA_HOME
fi
unset lz_ghidra lz_java
