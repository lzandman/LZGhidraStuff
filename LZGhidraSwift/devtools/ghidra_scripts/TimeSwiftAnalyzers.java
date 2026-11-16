// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Runs the five Swift analyzers once on the whole program, in priority order (Runtime
// Prototypes, Data Types, Self Types, Error Register, String Literals), each with its default
// options and in its own transaction, and times each analyzer and each of its phases. An
// analyzer whose canAnalyze is false is skipped. For measuring the analyzers on a program
// imported with them turned off (DisableLZAnalyzers.java); run it with -readOnly so that every
// run starts from the same program.
//
// The phases are the monitor messages "<analyzer>: <phase>" that the analyzers set
// (Progress.start); a phase lasts until the next message or the end of the analyzer.
//
// Arguments, optional: threads=N sets String Literals' option "Decompiler threads" (default 0,
// automatic), timeout=N its option "Decompiler timeout (sec)".
//
// Lines, tab-separated:
//   TIME   analyzer  seconds  heap used MiB  modification number before  after
//   PHASE  analyzer  phase  seconds
//   SKIP   analyzer
//@category Swift
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.WrappingTaskMonitor;
import lzghidraswift.SwiftDataTypesAnalyzer;
import lzghidraswift.SwiftErrorRegisterAnalyzer;
import lzghidraswift.SwiftRuntimePrototypesAnalyzer;
import lzghidraswift.SwiftSelfTypesAnalyzer;
import lzghidraswift.SwiftStringLiteralsAnalyzer;

public class TimeSwiftAnalyzers extends GhidraScript {

	/** Records the time of each message set on the wrapped monitor. */
	private static final class PhaseMonitor extends WrappingTaskMonitor {
		final List<String> messages = new ArrayList<>();
		final List<Long> times = new ArrayList<>();

		PhaseMonitor(TaskMonitor delegate) {
			super(delegate);
		}

		@Override
		public void setMessage(String message) {
			messages.add(message);
			times.add(System.nanoTime());
			super.setMessage(message);
		}
	}

	@Override
	protected void run() throws Exception {
		SwiftStringLiteralsAnalyzer strings = new SwiftStringLiteralsAnalyzer();
		for (String arg : getScriptArgs()) {
			if (arg.startsWith("threads=")) {
				strings.setDecompilerThreads(Integer.parseInt(arg.substring("threads=".length())));
			}
			else if (arg.startsWith("timeout=")) {
				strings.setDecompilerTimeout(Integer.parseInt(arg.substring("timeout=".length())));
			}
			else {
				throw new IllegalArgumentException("unknown argument: " + arg);
			}
		}
		List<AbstractAnalyzer> analyzers = List.of(new SwiftRuntimePrototypesAnalyzer(),
			new SwiftDataTypesAnalyzer(), new SwiftSelfTypesAnalyzer(),
			new SwiftErrorRegisterAnalyzer(), strings);
		long total = System.nanoTime();
		for (AbstractAnalyzer analyzer : analyzers) {
			if (analyzer.canAnalyze(currentProgram)) {
				time(analyzer);
			}
			else {
				println("SKIP\t" + analyzer.getName());
			}
		}
		println("TIME\tall\t%.2f".formatted((System.nanoTime() - total) / 1e9));
	}

	private void time(AbstractAnalyzer analyzer) throws Exception {
		Runtime rt = Runtime.getRuntime();
		PhaseMonitor phases = new PhaseMonitor(monitor);
		long before = currentProgram.getModificationNumber();
		long start = System.nanoTime();
		int tx = currentProgram.startTransaction(analyzer.getName());
		try {
			analyzer.added(currentProgram, currentProgram.getMemory(), phases, new MessageLog());
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
		long end = System.nanoTime();
		String name = analyzer.getName();
		println("TIME\t%s\t%.2f\t%d\t%d\t%d".formatted(name, (end - start) / 1e9,
			(rt.totalMemory() - rt.freeMemory()) >> 20, before,
			currentProgram.getModificationNumber()));
		String prefix = name + ": ";
		for (int i = 0; i < phases.messages.size(); i++) {
			String message = phases.messages.get(i);
			long next = i + 1 < phases.times.size() ? phases.times.get(i + 1) : end;
			String phase =
				message.startsWith(prefix) ? message.substring(prefix.length()) : message;
			println("PHASE\t%s\t%s\t%.2f".formatted(name, phase,
				(next - phases.times.get(i)) / 1e9));
		}
	}
}
