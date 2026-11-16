// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Pre-script: turns the Swift String Literals analyzer off for this import.
//@category Swift
import ghidra.app.script.GhidraScript;

public class DisableSwiftStrings extends GhidraScript {
	@Override
	protected void run() throws Exception {
		setAnalysisOption(currentProgram, "LZ Swift String Literals", "false");
	}
}
