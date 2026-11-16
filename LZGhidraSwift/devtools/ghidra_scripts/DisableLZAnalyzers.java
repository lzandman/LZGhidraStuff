// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Pre-script: turns every LZ analyzer off for this import (the five of LZGhidraSwift and LZ
// Mach-O Function Starts (Extracted DYLD) of LZGhidraGeneric), so that TimeSwiftAnalyzers.java
// can run them later on a program in the state just before them. An analyzer that does not
// apply to the program has no option (Function Starts applies only to extracted dyld images).
//@category Swift
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class DisableLZAnalyzers extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
		for (String name : new String[] { "LZ Swift Runtime Prototypes", "LZ Swift Data Types",
			"LZ Swift Self Types", "LZ Swift Error Register", "LZ Swift String Literals",
			"LZ Mach-O Function Starts (Extracted DYLD)" }) {
			if (options.contains(name)) {
				setAnalysisOption(currentProgram, name, "false");
			}
		}
	}
}
