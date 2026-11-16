// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.Msg;

/**
 * The warnings of one analyzer run, sent to two places: the tab-separated {@code SWIFT*} line to
 * the application log ({@link Msg}), where tools grep it, and a short plain text to the
 * analyzer's {@link MessageLog}, which the GUI shows in its analysis log dialog at the end. Ghidra
 * 12.2 headless (as 12.1.3 and 12.1.4) does not print the {@code MessageLog}:
 * {@code AutoAnalysisManager} clears it when analysis ends, and only the GUI's {@code AutoAnalysisPlugin} reads it before that.
 *
 * @param analyzer the originator of both lines (its name in the message log)
 * @param log the {@code log} parameter of {@code added()}
 */
record AnalysisLog(AbstractAnalyzer analyzer, MessageLog log) {

	/**
	 * Logs {@code line} as a warning and adds {@code text} to the message log.
	 *
	 * @param line the application log line, unchanged from before the message log was used
	 * @param text the same warning in plain words for the analysis log dialog
	 */
	void warn(String line, String text) {
		Msg.warn(analyzer, line);
		log.appendMsg(analyzer.getName(), text);
	}
}
