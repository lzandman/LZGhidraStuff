// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Pre-script for headless-types.sh (FAST=1): turns off the slow analyzers that the Swift Data
// Types analyzer does not depend on, to survey large binaries. Kept: disassembly, functions,
// thunks, the Swift and Objective-C metadata analyzers, and Demangler Swift (its placeholder
// types are counted), unless NO_SWIFT_DEMANGLER is set in the environment: Demangler Swift starts
// one swift-frontend process per symbol (about 40 a second), too slow for libSwiftSyntax.dylib's
// 75,405 Swift symbols.
//@category Swift
import ghidra.app.script.GhidraScript;

public class FastTypes extends GhidraScript {
	@Override
	protected void run() throws Exception {
		for (String analyzer : new String[] { "LZ Swift String Literals",
			"Decompiler Switch Analysis",
			"Call Convention ID", "Objective-C Message Analyzer", "Stack" }) {
			setAnalysisOption(currentProgram, analyzer, "false");
		}
		if (System.getenv("NO_SWIFT_DEMANGLER") != null) {
			setAnalysisOption(currentProgram, "Demangler Swift", "false");
		}
	}
}
