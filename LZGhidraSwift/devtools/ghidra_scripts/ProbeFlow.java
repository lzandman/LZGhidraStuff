// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Runs RegisterPairFinder on the functions at the given entry addresses, in a thread with a time
// limit, and prints the number of hits, iterations, instructions run and heap use. With
// SWIFTSTR_HITS set it also prints each hit. Uses reflection for ValueFlow.instructionsRun, which
// is package-private (see DevtoolsReflectionTest).
//@category Swift
import java.lang.reflect.*;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

public class ProbeFlow extends GhidraScript {
	@Override
	protected void run() throws Exception {
		System.setProperty("swiftstr.trace",
			String.valueOf(System.getenv("SWIFTSTR_TRACE") != null));
		ClassLoader cl = lzghidraswift.SwiftStringLiteralsAnalyzer.class.getClassLoader();
		Class<?> finderClass = Class.forName("lzghidraswift.strings.RegisterPairFinder", true, cl);
		Constructor<?> ctor =
			finderClass.getDeclaredConstructor(ghidra.program.model.listing.Program.class,
				Function.class);
		ctor.setAccessible(true);
		Method run = finderClass.getDeclaredMethod("run", TaskMonitor.class);
		run.setAccessible(true);
		Method flowM = finderClass.getDeclaredMethod("flow");
		flowM.setAccessible(true);
		for (String arg : getScriptArgs()) {
			Function f = getFunctionAt(toAddr(arg));
			lzghidraswift.strings.CandidateFilter.Result cand =
				lzghidraswift.strings.CandidateFilter.scan(currentProgram, f);
			println(
				"%s %s: %d bytes; candidate by %d tag words, %d bit-63 ORs, %d bit-63 loads; ORs at %s"
						.formatted(arg, f.getName(), f.getBody().getNumAddresses(),
							cand.tagWords().size(),
							cand.largeStringOrs().size(), cand.largeFlagLoads().size(),
							cand.largeStringOrs().stream().limit(4).toList()));
			Object finder = ctor.newInstance(currentProgram, f);
			Runtime rt = Runtime.getRuntime();
			rt.gc();
			long before = rt.totalMemory() - rt.freeMemory();
			long t = System.nanoTime();
			Object[] result = new Object[1];
			ghidra.util.task.TaskMonitorAdapter mon = new ghidra.util.task.TaskMonitorAdapter(true);
			Thread th = new Thread(() -> {
				try {
					result[0] = run.invoke(finder, mon);
				}
				catch (Throwable e) {
					result[0] = e;
				}
			});
			th.start();
			th.join(20_000);
			long used = rt.totalMemory() - rt.freeMemory() - before;
			if (th.isAlive()) {
				println("%s: still running after 20 s, heap +%d MiB".formatted(arg, used >> 20));
				mon.cancel();
				th.join();
				continue;
			}
			Object flow = flowM.invoke(finder);
			Method it = flow.getClass().getDeclaredMethod("iterations");
			it.setAccessible(true);
			Method conv = flow.getClass().getDeclaredMethod("converged");
			conv.setAccessible(true);
			Method work = flow.getClass().getDeclaredMethod("instructionsRun");
			work.setAccessible(true);
			println(
				("%s: %.3f s, heap +%d MiB, iterations %s, instructions run %s, converged %s, " +
					"result %s").formatted(arg, (System.nanoTime() - t) / 1e9, used >> 20,
						it.invoke(flow),
						work.invoke(flow), conv.invoke(flow),
						result[0] instanceof List<?> l ? l.size() + " hits"
								: String.valueOf(result[0])));
			if (result[0] instanceof List<?> l && System.getenv("SWIFTSTR_HITS") != null) {
				for (Object h : l) {
					println("  hit " + h);
				}
			}
		}
	}
}
