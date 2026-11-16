// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import java.util.Arrays;

import ghidra.app.util.sourcelanguage.MachoSwiftSourceLanguage;
import ghidra.app.util.sourcelanguage.SwiftSourceLanguage;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

/**
 * Finds Swift in an image extracted from the dyld shared cache. Ghidra 12.2's
 * {@code MachoSwiftSourceLanguage} accepts only the format "Mac OS X Mach-O", not "Extracted DYLD
 * Component", so such an image gets no {@code Swift} source language: Ghidra's Swift demangler and
 * type metadata analyzers do not run, the program has no {@code __swift_stdcall} or
 * {@code __swift_thiscall}, and Swift Error Register adds no variants. Ghidra 12.1.4 found Swift
 * by the block names alone.
 * <p>
 * The ID is Ghidra's {@code Swift}, which those analyzers and the spec extensions test for.
 * {@code SourceLanguageService.find} asks every class until one with an ID returns true, so this
 * class and Ghidra's coexist in either order. The test is Ghidra's Mach-O one (a block whose name
 * starts with {@code __swift}) on the extracted format. It stands down once Ghidra's class accepts
 * the format itself; then this class can go.
 */
public class ExtractedSwiftSourceLanguage extends SwiftSourceLanguage {

	/** {@code DyldCacheExtractLoader.DYLD_CACHE_EXTRACT_NAME}, in Ghidra's FileFormats module. */
	static final String EXTRACTED_FORMAT = "Extracted DYLD Component";

	@Override
	public boolean existsIn(Program program, TaskMonitor monitor) {
		return EXTRACTED_FORMAT.equals(program.getExecutableFormat()) &&
			Arrays.stream(program.getMemory().getBlocks())
					.map(MemoryBlock::getName)
					.anyMatch(name -> name.startsWith("__swift")) &&
			!new MachoSwiftSourceLanguage().existsIn(program, monitor);
	}
}
