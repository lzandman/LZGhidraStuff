// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import static org.junit.Assert.*;

import java.lang.reflect.Proxy;
import java.util.Map;

import org.junit.Test;

import ghidra.app.util.sourcelanguage.SwiftSourceLanguage;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

public class ExtractedSwiftSourceLanguageTest {

	private static final String MACHO_FORMAT = "Mac OS X Mach-O";

	@Test
	public void idIsGhidrasSwift() {
		assertEquals(SwiftSourceLanguage.SWIFT_ID, new ExtractedSwiftSourceLanguage().getID());
	}

	@Test
	public void extractedImageWithSwiftBlocks() {
		assertTrue(existsIn(ExtractedSwiftSourceLanguage.EXTRACTED_FORMAT, "__text",
			"__swift5_types"));
	}

	@Test
	public void extractedImageWithoutSwiftBlocks() {
		assertFalse(existsIn(ExtractedSwiftSourceLanguage.EXTRACTED_FORMAT, "__text",
			"__objc_classlist"));
	}

	/** Ghidra's own class finds Swift in a standalone Mach-O; this one stays out of it. */
	@Test
	public void standaloneMachO() {
		assertFalse(existsIn(MACHO_FORMAT, "__text", "__swift5_types"));
	}

	private static boolean existsIn(String format, String... blockNames) {
		MemoryBlock[] blocks = new MemoryBlock[blockNames.length];
		for (int i = 0; i < blocks.length; i++) {
			blocks[i] = stub(MemoryBlock.class, Map.of("getName", blockNames[i]));
		}
		Memory memory = stub(Memory.class, Map.of("getBlocks", blocks));
		Program program =
			stub(Program.class, Map.of("getExecutableFormat", format, "getMemory", memory));
		return new ExtractedSwiftSourceLanguage().existsIn(program, TaskMonitor.DUMMY);
	}

	/** An instance of {@code type} that returns the map's value for a method name. */
	private static <T> T stub(Class<T> type, Map<String, Object> answers) {
		return type.cast(Proxy.newProxyInstance(Thread.currentThread().getContextClassLoader(),
			new Class<?>[] { type },
			(proxy, method, args) -> {
				if (!answers.containsKey(method.getName())) {
					throw new UnsupportedOperationException(method.getName());
				}
				return answers.get(method.getName());
			}));
	}
}
