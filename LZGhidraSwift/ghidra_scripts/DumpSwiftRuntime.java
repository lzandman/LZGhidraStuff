// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Writes the signature of each external function and, optionally, the decompiled C of the
// functions in memory, for fixtures/check_runtime.py (Swift Runtime Prototypes analyzer).
// Arguments: the output file; "all" to decompile every function in memory, or "none" (the
// default).
//
// Lines, tab-separated:
//   # DumpSwiftRuntime  program name  compiler spec ID
//   EXT  function name  signature source  calling convention  prototype (without convention)
//   C    entry  function name  then the decompiled C, one line each, and a line END
// External functions by name, functions in memory by address; thunks are left out (they show
// the signature of the function they call).
//@category Swift

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class DumpSwiftRuntime extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String output = args.length > 0 ? args[0] : askString("Output", "File");
		boolean all = args.length > 1 && args[1].equals("all");
		TreeMap<String, String> externals = new TreeMap<>();
		for (Function f : currentProgram.getFunctionManager().getExternalFunctions()) {
			externals.put(f.getName(), "EXT\t%s\t%s\t%s\t%s".formatted(f.getName(),
				f.getSignatureSource(), f.getCallingConventionName(),
				f.getPrototypeString(false, false)));
		}
		List<Function> decompile = new ArrayList<>();
		if (all) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (!f.isThunk()) {
					decompile.add(f);
				}
			}
		}
		try (PrintWriter out = new PrintWriter(output, StandardCharsets.UTF_8)) {
			out.println("# DumpSwiftRuntime\t%s\t%s".formatted(currentProgram.getName(),
				currentProgram.getCompilerSpec().getCompilerSpecID()));
			externals.values().forEach(out::println);
			DecompInterface decompiler = new DecompInterface();
			DecompileOptions options = new DecompileOptions();
			options.grabFromProgram(currentProgram);
			decompiler.setOptions(options);
			decompiler.openProgram(currentProgram);
			try {
				for (Function f : decompile) {
					monitor.checkCancelled();
					DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
					out.println("C\t%s\t%s".formatted(f.getEntryPoint(), f.getName()));
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
		println("DumpSwiftRuntime: %d externals listed, %d functions decompiled, written to %s"
				.formatted(externals.size(), decompile.size(), output));
	}
}
