// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidrageneric;

import ghidra.app.plugin.core.analysis.MachoFunctionStartsAnalyzer;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Creates functions from {@code LC_FUNCTION_STARTS} in an image extracted from the dyld shared
 * cache. Ghidra's "Mach-O Function Starts" analyzer accepts only the formats "Mac OS X Mach-O"
 * and the whole DYLD cache, not "Extracted DYLD Component" (Ghidra 12.1.3 to 12.2 and master,
 * {@code MachoFunctionStartsAnalyzer.canAnalyze}). Without it, code reached only through a
 * {@code swift_once}, a jump table or a tail branch stays outside functions, and the Swift
 * analyzers (LZGhidraSwift) do not see it.
 * <p>
 * The extracted file is an ordinary Mach-O with its own {@code __LINKEDIT}, so Ghidra's analyzer
 * does the work on its Mach-O path: its first {@code FileBytes} are the image's (the loader adds
 * those of other cache parts after them). This analyzer only lets it run, at the same priority.
 * It stands down once Ghidra's analyzer accepts the format itself.
 */
public class ExtractedFunctionStartsAnalyzer extends AbstractAnalyzer {

	static final String NAME = "LZ Mach-O Function Starts (Extracted DYLD)";
	private static final String DESCRIPTION =
		"Runs Ghidra's Mach-O Function Starts analyzer on an image extracted from the dyld " +
			"shared cache, which Ghidra's analyzer does not accept: creates functions at the " +
			"addresses in the image's LC_FUNCTION_STARTS.";
	/** {@code DyldCacheExtractLoader.DYLD_CACHE_EXTRACT_NAME}, in Ghidra's FileFormats module. */
	static final String EXTRACTED_FORMAT = "Extracted DYLD Component";

	/** A byte analyzer at the priority of Ghidra's own, on by default. */
	public ExtractedFunctionStartsAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return EXTRACTED_FORMAT.equals(program.getExecutableFormat()) &&
			!new MachoFunctionStartsAnalyzer().canAnalyze(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		int before = program.getFunctionManager().getFunctionCount();
		// A new instance takes the Mach-O path: canAnalyze, which selects the cache path, has
		// not run on it.
		boolean read = new MachoFunctionStartsAnalyzer().added(program, set, monitor, log);
		int after = program.getFunctionManager().getFunctionCount();
		if (!read) {
			new AnalysisLog(this, log).warn(NAME + ": could not read LC_FUNCTION_STARTS",
				"could not read LC_FUNCTION_STARTS; no functions added from it");
		}
		Msg.info(this, NAME + ": " + (after - before) + " functions added (" + before + " -> " +
			after + ")");
		return read;
	}
}
