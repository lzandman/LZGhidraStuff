// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/** Lookups of Swift sections by memory block name (the Mach-O loader names blocks after sections). */
public final class SwiftSections {

	public static final String TYPES = "__swift5_types";
	public static final String FIELDMD = "__swift5_fieldmd";

	private static final int MH_MAGIC_64 = 0xfeedfacf;
	private static final int LC_SEGMENT_64 = 0x19;

	private SwiftSections() {
	}

	/** Whether any memory block is a Swift section ({@code __swift5_*}), initialized or not. */
	public static boolean hasSwiftSections(Program program) {
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.getName().startsWith("__swift5_")) {
				return true;
			}
		}
		return false;
	}

	/** The first initialized block with this section name, or null. */
	public static MemoryBlock find(Program program, String name) {
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.getName().equals(name) && block.isInitialized()) {
				return block;
			}
		}
		return null;
	}

	/**
	 * The exact address range of a section, or null. Ghidra's Mach-O loader extends a section's
	 * block over the alignment padding up to the next section (in the Layouts fixture,
	 * {@code __swift5_fieldmd} is 0x354 bytes and its block 0x360), so the range comes from the
	 * section header in the Mach-O header at the image base. Falls back to the block if there is
	 * no readable 64-bit Mach-O header or no section of that name in it.
	 */
	public static AddressRange range(Program program, String name) {
		MemoryBlock block = find(program, name);
		if (block == null) {
			return null;
		}
		try {
			AddressRange section = sectionFromHeader(program, name);
			if (section != null && section.getMinAddress().equals(block.getStart()) &&
				section.getMaxAddress().compareTo(block.getEnd()) <= 0) {
				return section;
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			// fall back to the block
		}
		return new AddressRangeImpl(block.getStart(), block.getEnd());
	}

	/** The named section's range per the Mach-O header, or null. */
	private static AddressRange sectionFromHeader(Program program, String name)
			throws MemoryAccessException {
		Memory memory = program.getMemory();
		Address header = program.getImageBase();
		if (memory.getInt(header) != MH_MAGIC_64) {
			return null;
		}
		int ncmds = memory.getInt(header.add(16));
		Address cmd = header.add(32);
		for (int i = 0; i < ncmds; i++) {
			int type = memory.getInt(cmd);
			int size = memory.getInt(cmd.add(4));
			if (type == LC_SEGMENT_64) {
				// segment_command_64: nsects at +64, then section_64 records of 80 bytes
				// (sectname[16], segname[16], addr at +32, size at +40)
				int nsects = memory.getInt(cmd.add(64));
				Address sect = cmd.add(72);
				for (int j = 0; j < nsects; j++, sect = sect.add(80)) {
					if (fixedString(memory, sect, 16).equals(name)) {
						long sectionSize = memory.getLong(sect.add(40));
						Address start = header.getNewAddress(memory.getLong(sect.add(32)));
						return sectionSize <= 0 ? null
								: new AddressRangeImpl(start, start.add(sectionSize - 1));
					}
				}
			}
			if (size <= 0) {
				return null;
			}
			cmd = cmd.add(size);
		}
		return null;
	}

	private static String fixedString(Memory memory, Address at, int length)
			throws MemoryAccessException {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < length; i++) {
			int c = memory.getByte(at.add(i)) & 0xff;
			if (c == 0) {
				break;
			}
			sb.append((char) c);
		}
		return sb.toString();
	}
}
