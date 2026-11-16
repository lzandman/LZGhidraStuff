// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * The phases of an analyzer run on its {@link TaskMonitor}. Before {@code added()}, Ghidra's
 * {@code AnalysisScheduler} sets the message to the analyzer's name and the progress to 0, but
 * not the maximum: an analyzer that does not initialize the monitor shows no progress. A helper
 * that loops (the type catalog, the type builder) initializes the monitor itself; the analyzer
 * sets the message before it.
 */
final class Progress {

	private Progress() {
	}

	/** Starts a phase of {@code max} steps, shown as {@code "<analyzer>: <phase>"}. */
	static void start(TaskMonitor monitor, String analyzer, String phase, long max) {
		monitor.initialize(max);
		monitor.setMessage(analyzer + ": " + phase);
	}

	/** The number of functions in {@code set} (cheap next to any analysis of them). */
	static int functions(Program program, AddressSetView set) {
		int n = 0;
		FunctionIterator it = program.getFunctionManager().getFunctions(set, true);
		while (it.hasNext()) {
			it.next();
			n++;
		}
		return n;
	}
}
