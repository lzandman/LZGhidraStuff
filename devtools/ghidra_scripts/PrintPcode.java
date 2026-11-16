// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Prints the p-code of the instructions at the given addresses.
//@category LZGhidraStuff
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

public class PrintPcode extends GhidraScript {
	@Override
	protected void run() throws Exception {
		for (String a : getScriptArgs()) {
			Instruction in = getInstructionAt(toAddr(a));
			println(a + "  " + in);
			for (PcodeOp op : in.getPcode()) {
				println("    " + op);
			}
		}
	}
}
