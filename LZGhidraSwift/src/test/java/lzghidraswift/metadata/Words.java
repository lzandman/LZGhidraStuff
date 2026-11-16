// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import java.util.HashMap;
import java.util.Map;

/**
 * A test stand-in for the binary: 32-bit words by address. Reading anything else fails, as
 * unmapped memory would. Used by the tests of {@link ClassMethods} and {@code SelfCandidates},
 * which read no {@code u16}.
 */
public final class Words implements WordReader {
	private final Map<Long, Integer> words = new HashMap<>();

	public void put(long address, int value) {
		words.put(address, value);
	}

	/** A relative pointer at {@code at} to {@code target}. */
	public void rel(long at, long target) {
		put(at, (int) (target - at));
	}

	@Override
	public int i32(long address) {
		Integer w = words.get(address);
		if (w == null) {
			throw new IllegalStateException("unmapped " + address);
		}
		return w;
	}

	@Override
	public int u16(long address) {
		throw new UnsupportedOperationException("u16 at " + address);
	}
}
