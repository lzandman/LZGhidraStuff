// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Pre-script: turns the Mach-O Function Starts (Extracted DYLD) analyzer off for this
// run, to count the functions without it.
//@category LZGhidraStuff
import ghidra.app.script.GhidraScript;

public class DisableFunctionStarts extends GhidraScript {
	@Override
	protected void run() throws Exception {
		setAnalysisOption(currentProgram, "LZ Mach-O Function Starts (Extracted DYLD)",
			"false");
	}
}
