// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Writes the functions that have a parameter self in the Swift context register (x20, r13) of
// the Swift Self Types analyzer, and the decompiled C of some of them, for fixtures/check_self.py.
// Arguments: the output file; which functions to decompile: "all" (every function with self),
// "none", or addresses separated by commas (0xee98,0xf884).
//
// Lines, tab-separated, functions by address:
//   SELF  entry  function name  self type (path)  Swift symbol at the entry (first one, or empty)
//   C     entry  then the decompiled C, one line each, and a line END
//@category Swift

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Symbol;
import lzghidraswift.abi.CallingConventions;

public class DumpSwiftSelf extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String output = args.length > 0 ? args[0] : askString("Output", "File");
		String which = args.length > 1 ? args[1] : "none";
		Register register = CallingConventions.selfRegister(currentProgram);
		Map<Address, Function> typed = new LinkedHashMap<>();
		try (PrintWriter out = new PrintWriter(output, StandardCharsets.UTF_8)) {
			out.println("# DumpSwiftSelf\t" + currentProgram.getName());
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				for (Parameter p : f.getParameters()) {
					Register r = p.getRegister();
					if (p.getName().equals("self") && r != null &&
						r.getBaseRegister().equals(register.getBaseRegister()) &&
						p.getDataType() instanceof Pointer ptr && ptr.getDataType() != null) {
						typed.put(f.getEntryPoint(), f);
						out.println("SELF\t%s\t%s\t%s\t%s".formatted(f.getEntryPoint(), f.getName(),
							ptr.getDataType().getPathName(), swiftSymbol(f.getEntryPoint())));
					}
				}
			}
			List<Function> decompile = new ArrayList<>();
			if (which.equals("all")) {
				decompile.addAll(typed.values());
			}
			else if (!which.equals("none")) {
				for (String a : which.split(",")) {
					Function f = getFunctionAt(toAddr(Long.decode(a.trim())));
					if (f != null) {
						decompile.add(f);
					}
				}
			}
			DecompInterface decompiler = new DecompInterface();
			DecompileOptions options = new DecompileOptions();
			options.grabFromProgram(currentProgram);
			decompiler.setOptions(options);
			decompiler.openProgram(currentProgram);
			try {
				for (Function f : decompile) {
					DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
					out.println("C\t" + f.getEntryPoint());
					if (r != null && r.getDecompiledFunction() != null) {
						out.println(r.getDecompiledFunction().getC().strip());
					}
					else {
						out.println("/* decompiler failed */");
					}
					out.println("END");
				}
			}
			finally {
				decompiler.dispose();
			}
		}
		println("DumpSwiftSelf: %d functions with self, %d decompiled, written to %s".formatted(
			typed.size(), which.equals("all") ? typed.size()
					: which.equals("none") ? 0
							: which.split(",").length,
			output));
	}

	private String swiftSymbol(Address entry) {
		for (Symbol s : currentProgram.getSymbolTable().getSymbols(entry)) {
			if (s.getName().startsWith("_$s") || s.getName().startsWith("$s")) {
				return s.getName();
			}
		}
		return "";
	}
}
