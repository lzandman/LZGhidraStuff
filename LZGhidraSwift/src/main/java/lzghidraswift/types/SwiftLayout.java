// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.types;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import lzghidraswift.metadata.ContextDescriptor;
import lzghidraswift.metadata.MetadataLocator;
import lzghidraswift.metadata.SymbolNames;

/**
 * The layout of a type with static metadata (swift/ABI/Metadata.h), in bytes:
 * <pre>
 * struct, enum  metadata − 8: value witness table; table + 64: size (u64), stride (u64),
 *               flags (u32, alignment mask in bits 0–7), extra inhabitant count (u32)
 * struct        metadata + 8 × fieldOffsetVectorOffset: u32 field offsets
 * class         metadata + 48: instance size (u32), instance alignment mask (u16);
 *               metadata + 8 × fieldOffsetVectorOffset: u64 field offsets (own fields only)
 * </pre>
 * Enums have no field offsets. Classes have no stride ({@code stride} is −1) and no extra inhabitant count (−1). A value witness
 * table of the Swift runtime (an imported {@code $sBi64_WV} and the like, used by trivial types)
 * is not in the binary; its size and alignment come from {@link #builtin(String)}.
 * <p>
 * The extra inhabitant count is the number of bit patterns that are not valid values (the spare
 * values of an enum's tag byte, the null and low addresses of a pointer). If it is not 0, an
 * {@code Optional} of the type uses one of them for {@code nil} and has the type's size; else it
 * adds a tag byte.
 */
public record SwiftLayout(long size, long stride, int alignment, long extraInhabitants,
		List<Long> offsets, String witnesses) {

	/** The field offsets as a new array. */
	public long[] offsetArray() {
		return offsets.stream().mapToLong(Long::longValue).toArray();
	}

	/** The number of field offsets outside the layout: negative, or at or past the size. */
	public int offsetsOutside() {
		long end = Math.max(size, 1);
		return (int) offsets.stream().filter(offset -> offset < 0 || offset >= end).count();
	}

	private static List<Long> list(long[] offsets) {
		return Arrays.stream(offsets).boxed().toList();
	}

	private static final int VWT_SIZE = 64;

	/** Stands for "many": the extra inhabitants of a pointer (null and the low addresses). */
	public static final long MANY = Integer.MAX_VALUE;

	/**
	 * Size, stride, alignment and extra inhabitant count of the runtime's value witness tables for
	 * builtin types (swift/Runtime/BuiltinTypes.def, stdlib/public/runtime/KnownMetadata.cpp;
	 * arm64 and x86_64). Key: the mangled type in {@code $s<type>WV}. Pointer counts are
	 * {@link #MANY}; only zero or non-zero matters here. {@code Int7} and {@code Int63} are given
	 * 0, which was not checked: the safe side, since a wrong tag byte makes the field too large
	 * for its gap and leaves it undefined, while a missing one would type it silently wrong.
	 */
	private static final Map<String, long[]> BUILTINS = Map.ofEntries(
		Map.entry("Bi1_", new long[] { 1, 1, 1, 254 }),
		Map.entry("Bi7_", new long[] { 1, 1, 1, 0 }),
		Map.entry("Bi8_", new long[] { 1, 1, 1, 0 }), Map.entry("Bi16_", new long[] { 2, 2, 2, 0 }),
		Map.entry("Bi32_", new long[] { 4, 4, 4, 0 }),
		Map.entry("Bi63_", new long[] { 8, 8, 8, 0 }),
		Map.entry("Bi64_", new long[] { 8, 8, 8, 0 }),
		Map.entry("Bi128_", new long[] { 16, 16, 16, 0 }),
		Map.entry("Bi256_", new long[] { 32, 32, 16, 0 }),
		Map.entry("Bi512_", new long[] { 64, 64, 16, 0 }),
		Map.entry("Bw", new long[] { 8, 8, 8, 0 }),
		Map.entry("Bf16_", new long[] { 2, 2, 2, 0 }),
		Map.entry("Bf32_", new long[] { 4, 4, 4, 0 }),
		Map.entry("Bf64_", new long[] { 8, 8, 8, 0 }),
		Map.entry("Bo", new long[] { 8, 8, 8, MANY }),
		Map.entry("Bb", new long[] { 8, 8, 8, MANY }),
		Map.entry("Bp", new long[] { 8, 8, 8, MANY }),
		Map.entry("BO", new long[] { 8, 8, 8, MANY }), Map.entry("yt", new long[] { 0, 1, 1, 0 }));

	/**
	 * Size, stride, alignment and extra inhabitant count for a runtime value witness table symbol
	 * such as {@code _$sBi64_WV}, or null if the symbol is not one of {@link #BUILTINS}.
	 */
	public static long[] builtin(String symbol) {
		if (symbol == null) {
			return null;
		}
		String body = SymbolNames.swiftBody(symbol);
		if (body == null || !body.endsWith("WV")) {
			return null;
		}
		return BUILTINS.get(body.substring(0, body.length() - 2));
	}

	/** Reads the layout of {@code d} from its static metadata. */
	public static SwiftLayout read(Memory memory, MetadataLocator locator, ContextDescriptor d,
			Address metadata) throws MemoryAccessException {
		Address vector = metadata.add(8L * d.fieldOffsetVectorOffset());
		if (d.kind() == ContextDescriptor.KIND_CLASS) {
			long size = memory.getInt(metadata.add(48)) & 0xffffffffL;
			int alignment = (memory.getShort(metadata.add(52)) & 0xffff) + 1;
			long[] offsets = new long[d.numFields()];
			for (int i = 0; i < offsets.length; i++) {
				offsets[i] = memory.getLong(vector.add(8L * i));
			}
			return new SwiftLayout(size, -1, alignment, -1, list(offsets), null);
		}
		long[] offsets = new long[d.kind() == ContextDescriptor.KIND_STRUCT ? d.numFields() : 0];
		for (int i = 0; i < offsets.length; i++) {
			offsets[i] = memory.getInt(vector.add(4L * i)) & 0xffffffffL;
		}
		Address slot = metadata.subtract(8);
		Address table = ContextDescriptor.pointer(memory, slot);
		MemoryBlock block = memory.getBlock(table);
		if (block != null && block.isInitialized() && !memory.isExternalBlockAddress(table)) {
			long size = memory.getLong(table.add(VWT_SIZE));
			long stride = memory.getLong(table.add(VWT_SIZE + 8));
			int flags = memory.getInt(table.add(VWT_SIZE + 16));
			long extra = memory.getInt(table.add(VWT_SIZE + 20)) & 0xffffffffL;
			return new SwiftLayout(size, stride, (flags & 0xff) + 1, extra, list(offsets), null);
		}
		String symbol = locator.importedName(slot);
		long[] builtin = builtin(symbol);
		if (builtin == null) {
			throw new MemoryAccessException("value witness table at %s (%s) not readable"
					.formatted(table, symbol != null ? symbol : "no symbol"));
		}
		return new SwiftLayout(builtin[0], builtin[1], (int) builtin[2], builtin[3], list(offsets),
			SymbolNames.withoutUnderscore(symbol));
	}
}
