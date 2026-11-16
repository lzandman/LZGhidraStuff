// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Runs the Swift Runtime Prototypes analyzer, then Swift Data Types, Swift Self Types and Swift
// Error Register, once more on an analysed program and reports whether that changed the program:
// a second run must change nothing (the summary lines then show 0 applied; 0 created, 0
// replaced; self added to 0 functions, updated in 0; convention set on 0). Prints the
// modification number and the data type count before and after each. Swift Runtime Prototypes
// and Swift Error Register are skipped on a program they do not analyse (no Swift sections, or
// a processor without the Swift registers).
//@category Swift
import ghidra.app.script.GhidraScript;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.util.importer.MessageLog;
import lzghidraswift.SwiftDataTypesAnalyzer;
import lzghidraswift.SwiftErrorRegisterAnalyzer;
import lzghidraswift.SwiftRuntimePrototypesAnalyzer;
import lzghidraswift.SwiftSelfTypesAnalyzer;

public class RunSwiftTypes extends GhidraScript {
	@Override
	protected void run() throws Exception {
		SwiftRuntimePrototypesAnalyzer runtime = new SwiftRuntimePrototypesAnalyzer();
		if (runtime.canAnalyze(currentProgram)) {
			rerun("RunSwiftRuntime", runtime);
		}
		rerun("RunSwiftTypes", new SwiftDataTypesAnalyzer());
		rerun("RunSwiftSelf", new SwiftSelfTypesAnalyzer());
		SwiftErrorRegisterAnalyzer errors = new SwiftErrorRegisterAnalyzer();
		if (errors.canAnalyze(currentProgram)) {
			rerun("RunSwiftThrows", errors);
		}
	}

	private void rerun(String label, AbstractAnalyzer analyzer) throws Exception {
		long before = currentProgram.getModificationNumber();
		int typesBefore = currentProgram.getDataTypeManager().getDataTypeCount(true);
		long t = System.nanoTime();
		int tx = currentProgram.startTransaction(analyzer.getName());
		try {
			analyzer.added(currentProgram, currentProgram.getMemory(), monitor, new MessageLog());
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
		long after = currentProgram.getModificationNumber();
		int typesAfter = currentProgram.getDataTypeManager().getDataTypeCount(true);
		println(("%s: %.2f s; modification number %d -> %d (%s), data types %d -> %d")
				.formatted(label, (System.nanoTime() - t) / 1e9, before, after,
					before == after ? "unchanged" : "CHANGED", typesBefore, typesAfter));
	}
}
