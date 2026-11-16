// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Reads the little-endian words of the binary by offset, for the plain Java readers of
 * {@link ClassMethods} and {@link FieldDescriptors}. Throws {@link IllegalStateException} where
 * it cannot read.
 */
public interface WordReader {

	int i32(long address);

	int u16(long address);

	/**
	 * A reader of {@code memory} in the address space of {@code space}; a byte it cannot read
	 * throws {@link IllegalStateException} with the message of Ghidra's exception.
	 */
	static WordReader of(Memory memory, Address space) {
		return new WordReader() {
			@Override
			public int i32(long address) {
				try {
					return memory.getInt(space.getNewAddress(address));
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					throw new IllegalStateException(e.getMessage(), e);
				}
			}

			@Override
			public int u16(long address) {
				try {
					return memory.getShort(space.getNewAddress(address)) & 0xffff;
				}
				catch (MemoryAccessException | AddressOutOfBoundsException e) {
					throw new IllegalStateException(e.getMessage(), e);
				}
			}
		};
	}
}
