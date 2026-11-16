// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** {@link AnalysisLog} adds only the plain text, after the analyzer's name, to the message log. */
public class AnalysisLogTest {

	@Test
	public void warnAddsTextToMessageLog() {
		AbstractAnalyzer analyzer =
			new AbstractAnalyzer("Swift Test", "", AnalyzerType.BYTE_ANALYZER) {
				@Override
				public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
						MessageLog log) {
					return false;
				}
			};
		MessageLog log = new MessageLog();
		AnalysisLog warnings = new AnalysisLog(analyzer, log);
		assertFalse(log.hasMessages());
		warnings.warn("SWIFTTEST\t1000\tline for tools", "first warning");
		warnings.warn("SWIFTTEST\t2000\tline for tools", "second warning");
		assertEquals("Swift Test> first warning\nSwift Test> second warning\n", log.toString());
	}
}
