// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Runs the Swift String Literals analyzer on the whole program (no other analysis).
// Argument: "decomp" or "nodecomp" (the Decompiler equates option). Prints time and heap.
//@category Swift
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import lzghidraswift.SwiftStringLiteralsAnalyzer;

public class RunSwiftStrings extends GhidraScript {
	@Override
	protected void run() throws Exception {
		boolean decomp = getScriptArgs().length == 0 || getScriptArgs()[0].equals("decomp");
		SwiftStringLiteralsAnalyzer analyzer = new SwiftStringLiteralsAnalyzer();
		analyzer.setMarkupOptions("EOL", true, true, true, decomp);
		Runtime rt = Runtime.getRuntime();
		long t = System.nanoTime();
		int tx = currentProgram.startTransaction("Swift String Literals");
		try {
			analyzer.added(currentProgram, currentProgram.getMemory(), monitor, new MessageLog());
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
		println("RunSwiftStrings: decomp=%s, %.1f s, functions %d, heap used %d MiB of max %d MiB"
				.formatted(decomp, (System.nanoTime() - t) / 1e9,
					currentProgram.getFunctionManager().getFunctionCount(),
					(rt.totalMemory() - rt.freeMemory()) >> 20, rt.maxMemory() >> 20));
	}
}
