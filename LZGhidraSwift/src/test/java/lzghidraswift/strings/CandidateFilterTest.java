// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class CandidateFilterTest {

	/**
	 * {@code orq $-0x1c} (count 4 or 5, "true"/"false") and {@code orq $-0x1e} (count 2 or 3,
	 * "no"/"yes") are tag bytes; a mask with other bits clear and a byte without a small tag
	 * are not.
	 */
	@Test
	public void tagByteOfAComputedTagWord() {
		assertTrue(CandidateFilter.isTagByte(-0x1c));
		assertTrue(CandidateFilter.isTagByte(-0x1e));
		assertTrue(CandidateFilter.isTagByte(-0x5c)); // 0xA4: not ASCII, count 4
		assertFalse(CandidateFilter.isTagByte(0xe4));
		assertFalse(CandidateFilter.isTagByte(-0x100));
		assertFalse(CandidateFilter.isTagByte(-0x2c)); // 0xD4: large-string flags
	}
}
