// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Large string literals (16 bytes or more): word 0 = {@code 0xD000...} or {@code 0x1000...} |
 * count, word 1 = bit 63 | (address - 32), with the bytes in {@code __cstring}. The pairing of
 * the two words is done by {@link RegisterPairFinder}; this class checks the bytes.
 */
public final class LargeStringFinder {

	private LargeStringFinder() {
	}

	/** The string at the header's address, or null if it is not a matching C string in __cstring. */
	static String verify(Program program, SwiftStringCodec.LargeHeader header) {
		Address addr;
		try {
			addr =
				program.getAddressFactory().getDefaultAddressSpace().getAddress(header.address());
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block == null || !block.getName().equals("__cstring") || !block.isInitialized()) {
			return null;
		}
		byte[] bytes = new byte[header.count() + 1];
		try {
			if (program.getMemory().getBytes(addr, bytes) != bytes.length) {
				return null;
			}
		}
		catch (MemoryAccessException e) {
			return null;
		}
		return SwiftStringCodec.checkLargeBytes(header, bytes);
	}

	/**
	 * The {@code INT_OR} instructions with bit 63 that did not produce a word 1 of a found large
	 * string. {@code used}: the word 1 producers of all large-string pairs.
	 */
	public static List<Address> unusedOrs(List<Address> largeStringOrs, Set<Address> used) {
		List<Address> unused = new ArrayList<>();
		for (Address a : largeStringOrs) {
			if (!used.contains(a)) {
				unused.add(a);
			}
		}
		return unused;
	}
}
