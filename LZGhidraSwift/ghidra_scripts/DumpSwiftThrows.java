// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Writes the calling convention of each function with a Swift symbol or a throwing convention,
// the call-site overrides, and the decompiled C of the functions in memory, for
// fixtures/check_throws.py (Swift Error Register analyzer).
// Arguments: the output file; "all" to decompile every listed function, or "none" (the default).
//
// Lines, tab-separated, functions by address:
//   # DumpSwiftThrows  program name  error register (x21, R12)
//   CONV      entry  function name  calling convention  Swift symbol (the first one, or -)
//   OVERRIDE  call address  calling function  calling convention of the override
//   C         entry  then the decompiled C, one line each, and a line END
// Thunks are left out (they use the convention of the function they call); external functions
// are listed with their external address.
//@category Swift

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import lzghidraswift.abi.CallingConventions;

public class DumpSwiftThrows extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String output = args.length > 0 ? args[0] : askString("Output", "File");
		boolean all = args.length > 1 && args[1].equals("all");
		List<Function> decompile = new ArrayList<>();
		int listed = 0;
		try (PrintWriter out = new PrintWriter(output, StandardCharsets.UTF_8)) {
			out.println("# DumpSwiftThrows\t%s\t%s".formatted(currentProgram.getName(),
				CallingConventions.errorRegister(currentProgram)));
			int overrides = 0;
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				overrides += printOverrides(out, f);
				String symbol = swiftSymbol(f);
				boolean throwing = f.getCallingConventionName().endsWith("_throws");
				if (f.isThunk() || (symbol == null && !throwing)) {
					continue;
				}
				out.println(line(f, symbol == null ? "-" : symbol));
				listed++;
				if (all) {
					decompile.add(f);
				}
			}
			println("DumpSwiftThrows: %d call-site overrides".formatted(overrides));
			for (Function f : currentProgram.getFunctionManager().getExternalFunctions()) {
				String symbol = swiftSymbol(f);
				if (symbol != null) {
					out.println(line(f, symbol));
					listed++;
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
		println("DumpSwiftThrows: %d functions listed, %d decompiled, written to %s"
				.formatted(listed, decompile.size(), output));
	}

	/** Prints the call-site overrides in {@code f}; returns their number. */
	private int printOverrides(PrintWriter out, Function f) {
		Namespace space = HighFunction.findOverrideSpace(f);
		if (space == null) {
			return 0;
		}
		int n = 0;
		SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(space);
		while (symbols.hasNext()) {
			Symbol s = symbols.next();
			DataTypeSymbol override = HighFunctionDBUtil.readOverride(s);
			if (override != null &&
				override.getDataType() instanceof FunctionSignature sig) {
				out.println("OVERRIDE\t%s\t%s\t%s".formatted(s.getAddress(), f.getName(),
					sig.getCallingConventionName()));
				n++;
			}
		}
		return n;
	}

	private static String line(Function f, String symbol) {
		return "CONV\t%s\t%s\t%s\t%s".formatted(f.getEntryPoint(), f.getName(),
			f.getCallingConventionName(), symbol);
	}

	/** The first Swift symbol of the function: a label at its entry, or the external's names. */
	private String swiftSymbol(Function f) {
		List<String> names = new ArrayList<>();
		if (f.isExternal()) {
			ExternalLocation location = f.getExternalLocation();
			names.add(location.getOriginalImportedName());
			names.add(location.getLabel());
		}
		else {
			for (Symbol s : currentProgram.getSymbolTable().getSymbols(f.getEntryPoint())) {
				names.add(s.getName());
			}
		}
		// The Swift demangler's labels start with $ too ($standard): a mangled name first.
		for (String prefix : new String[] { "_$s", "$s" }) {
			for (String n : names) {
				if (n != null && n.startsWith(prefix)) {
					return n;
				}
			}
		}
		return null;
	}
}
