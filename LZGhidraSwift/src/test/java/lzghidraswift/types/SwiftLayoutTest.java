// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.types;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Test;

public class SwiftLayoutTest {

	@Test
	public void builtinWitnessTables() {
		assertArrayEquals(new long[] { 8, 8, 8, 0 }, SwiftLayout.builtin("_$sBi64_WV"));
		assertArrayEquals(new long[] { 0, 1, 1, 0 }, SwiftLayout.builtin("$sytWV"));
		assertArrayEquals(new long[] { 32, 32, 16, 0 }, SwiftLayout.builtin("_$sBi256_WV"));
		assertArrayEquals(new long[] { 8, 8, 8, SwiftLayout.MANY }, SwiftLayout.builtin("_$sBbWV"));
		assertNull(SwiftLayout.builtin("_$sSiN"));
		assertNull(SwiftLayout.builtin("_$sBf80_WV"));
		assertNull(SwiftLayout.builtin(null));
	}

	@Test
	public void offsetsOutside() {
		assertEquals(0, layout(16).offsetsOutside());
		assertEquals(0, layout(16, 0, 15).offsetsOutside());
		assertEquals(1, layout(16, 0, 16).offsetsOutside());
		assertEquals(1, layout(16, -1, 8).offsetsOutside());
		// Size 0 (an empty struct) still takes an offset of 0.
		assertEquals(0, layout(0, 0).offsetsOutside());
		assertEquals(1, layout(0, 0, 1).offsetsOutside());
	}

	private static SwiftLayout layout(long size, long... offsets) {
		return new SwiftLayout(size, size, 1, 0,
			Arrays.stream(offsets).boxed().toList(), null);
	}
}
