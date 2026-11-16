// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class DecompilerPoolTest {

	private static final long GIB = 1L << 30;

	@Test
	public void optionWins() {
		assertEquals(1, DecompilerPool.threads(1, 10, 24 * GIB, 4 * GIB));
		assertEquals(32, DecompilerPool.threads(32, 4, 8 * GIB, 4 * GIB));
	}

	@Test
	public void automaticKeepsOneProcessor() {
		assertEquals(9, DecompilerPool.threads(0, 10, 24 * GIB, 4 * GIB));
		assertEquals(63, DecompilerPool.threads(0, 64, 0, 4 * GIB));
		assertEquals(1, DecompilerPool.threads(0, 1, 24 * GIB, 4 * GIB));
	}

	@Test
	public void automaticIsCappedByMemoryOutsideTheHeap() {
		long per = DecompilerPool.MEMORY_PER_THREAD;
		assertEquals(3, DecompilerPool.threads(0, 64, 4 * GIB + 3 * per, 4 * GIB));
		assertEquals(3, DecompilerPool.threads(0, 64, 4 * GIB + 4 * per - 1, 4 * GIB));
		assertEquals(1, DecompilerPool.threads(0, 64, 4 * GIB, 4 * GIB));
		assertEquals(1, DecompilerPool.threads(0, 64, 2 * GIB, 4 * GIB));
	}
}
