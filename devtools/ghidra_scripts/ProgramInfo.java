// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Prints basic facts about the program: path, size, instruction and function counts, Swift blocks.
//@category LZGhidraStuff
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;

public class ProgramInfo extends GhidraScript {
	@Override
	protected void run() throws Exception {
		println("path " + currentProgram.getExecutablePath() + ", md5 " +
			currentProgram.getExecutableMD5());
		println(
			"instructions " + currentProgram.getListing().getNumInstructions() + ", functions " +
				currentProgram.getFunctionManager().getFunctionCount());
		long text = 0;
		StringBuilder swift = new StringBuilder();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			if (b.getName().equals("__text"))
				text = b.getSize();
			if (b.getName().startsWith("__swift5"))
				swift.append(b.getName()).append(' ');
		}
		println("__text " + text + " bytes; swift blocks: " + swift);
		var opts = currentProgram.getOptions("Program Information");
		println("analyzed " + opts.getBoolean("Analyzed", false));
	}
}
