// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

public class StringBlockTest {

	private static byte[] bytes(String s) {
		return s.getBytes(StandardCharsets.UTF_8);
	}

	@Test
	public void layoutTerminatesAndDedupes() {
		StringBlock.Layout l = StringBlock.layout(Set.of(), List.of("maj7", "C", "maj7", "dim"));
		assertEquals(Map.of("maj7", 0L, "C", 5L, "dim", 7L), l.offsets());
		assertArrayEquals(bytes("maj7\0C\0dim\0"), l.bytes());
		assertEquals(List.of("maj7", "C", "dim"), List.copyOf(l.offsets().keySet()));
	}

	@Test
	public void layoutSkipsEmptyAndNul() {
		assertFalse(StringBlock.fits(""));
		assertFalse(StringBlock.fits("a\0b"));
		assertTrue(StringBlock.fits("\n"));
		StringBlock.Layout l = StringBlock.layout(Set.of(), List.of("", "a\0b", "Flat"));
		assertEquals(Map.of("Flat", 0L), l.offsets());
		assertArrayEquals(bytes("Flat\0"), l.bytes());
	}

	@Test
	public void layoutNonAscii() {
		StringBlock.Layout l = StringBlock.layout(Set.of(), List.of("Füße", "×", "é"));
		// ü and ß are 2 bytes each, × and é 2 bytes.
		assertEquals(Map.of("Füße", 0L, "×", 7L, "é", 10L), l.offsets());
		assertArrayEquals(bytes("Füße\0×\0é\0"), l.bytes());
		assertEquals(l.offsets(), StringBlock.parse(l.bytes()));
	}

	@Test
	public void growthKeepsOffsets() {
		StringBlock.Layout first = StringBlock.layout(Set.of(), List.of("Sharp", "Flat"));
		Map<String, Long> old = StringBlock.parse(first.bytes());
		StringBlock.Layout second =
			StringBlock.layout(old.keySet(), List.of("Flat", "sus2", "Sharp", "m"));
		assertEquals(Map.of("sus2", 0L, "m", 5L), second.offsets());

		ByteArrayOutputStream joined = new ByteArrayOutputStream();
		joined.writeBytes(first.bytes());
		joined.writeBytes(second.bytes());
		Map<String, Long> all = StringBlock.parse(joined.toByteArray());
		assertEquals(Map.of("Sharp", 0L, "Flat", 6L, "sus2", 11L, "m", 16L), all);

		// Nothing new: no block.
		StringBlock.Layout third = StringBlock.layout(all.keySet(), List.of("Flat", "m"));
		assertTrue(third.offsets().isEmpty());
		assertEquals(0, third.bytes().length);
	}

	@Test
	public void parseFirstOffsetWinsAndIgnoresTail() {
		assertEquals(Map.of("a", 0L, "b", 3L), StringBlock.parse(bytes("a\0\0b\0a\0c")));
		assertTrue(StringBlock.parse(new byte[0]).isEmpty());
	}
}
