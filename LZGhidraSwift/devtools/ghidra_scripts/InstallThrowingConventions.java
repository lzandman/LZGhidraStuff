// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Installs the throwing variants of the program's Swift calling conventions
// (lzghidraswift.throwing.ThrowingConventions) and prints, for each convention of the program,
// whether a call kills or preserves the error register. With the argument "dump" it also prints
// each convention's XML as Ghidra encodes it. Run it twice on a saved program: the second run
// must find the variants present and add none.
//@category Swift
import java.util.Arrays;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.XmlEncode;
import lzghidraswift.abi.CallingConventions;
import lzghidraswift.throwing.ThrowingConventions;

public class InstallThrowingConventions extends GhidraScript {
	@Override
	protected void run() throws Exception {
		boolean dump = Arrays.asList(getScriptArgs()).contains("dump");
		Register error = CallingConventions.errorRegister(currentProgram);
		println("THROWS\tspec %s, error register %s".formatted(
			currentProgram.getCompilerSpec().getCompilerSpecID(), error));
		ThrowingConventions.Result result =
			ThrowingConventions.install(currentProgram, monitor);
		println("THROWS\t" + result.summary());
		for (PrototypeModel m : currentProgram.getCompilerSpec().getCallingConventions()) {
			println("THROWS\t%s\thasThis %s\tunaffected %s\tkilled %s".formatted(m.getName(),
				m.hasThisPointer(), contains(m.getUnaffectedList(), error),
				contains(m.getKilledByCallList(), error)));
			if (dump) {
				XmlEncode encoder = new XmlEncode();
				m.encode(encoder, currentProgram.getCompilerSpec().getPcodeInjectLibrary());
				println(encoder.toString());
			}
		}
	}

	private static boolean contains(Varnode[] list, Register r) {
		if (r == null) {
			return false;
		}
		for (Varnode v : list) {
			if (v.getAddress().equals(r.getAddress()) && v.getSize() == r.getMinimumByteSize()) {
				return true;
			}
		}
		return false;
	}
}
