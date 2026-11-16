// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import java.util.ArrayList;
import java.util.List;

/**
 * Plain Java: a field descriptor of {@code __swift5_fieldmd} and its field records
 * (swift/RemoteInspection/Records.h, FieldDescriptor and FieldRecord). Offsets in bytes:
 * <pre>
 * field descriptor: +0 mangled type name, +4 superclass (relative pointers),
 *                   +8 kind (u16), +10 record size (u16), +12 record count, +16 records
 * field record:     +0 flags, +4 mangled type name, +8 field name (relative pointers)
 * </pre>
 * The mangled names stay addresses; {@code MangledTypeReader} resolves them.
 */
public final class FieldDescriptors {

	/** FieldDescriptorKind, by value. */
	private static final String[] KINDS = { "struct", "class", "enum", "multi-payload enum",
		"protocol", "class protocol", "objc protocol", "objc class" };
	private static final int HEADER = 16;
	/** The size of a field record; a larger record size leaves bytes that are not read. */
	public static final int RECORD_SIZE = 12;

	private FieldDescriptors() {
	}

	/**
	 * A field descriptor at {@code address}. {@code typeName} is the target of its mangled type
	 * name (0 if none). {@code records} is empty when the descriptor does not fit: its record size
	 * is below {@link #RECORD_SIZE}, its record count is negative, or its records run past the
	 * end of the section.
	 */
	public record Descriptor(long address, long typeName, int kind, int recordSize, int count,
			boolean fits, List<FieldRecord> records) {

		/** The kind's name, such as "struct", or "kind" and the number. */
		public String kindName() {
			return kind < KINDS.length ? KINDS[kind] : "kind " + kind;
		}

		/** The address after the last record: the next descriptor. */
		public long end() {
			return address + HEADER + (long) recordSize * count;
		}
	}

	/**
	 * A field record at {@code address}. {@code typeName} and {@code name} are the targets of its
	 * relative pointers, 0 if the offset is 0 (a record without type is an enum case without
	 * payload).
	 */
	public record FieldRecord(long address, int flags, long typeName, long name) {

		/** The flag bits 1, 2 and 4 as words ("indirect var artificial"), space-separated. */
		public String flagNames() {
			List<String> names = new ArrayList<>();
			if ((flags & 1) != 0) {
				names.add("indirect");
			}
			if ((flags & 2) != 0) {
				names.add("var");
			}
			if ((flags & 4) != 0) {
				names.add("artificial");
			}
			return String.join(" ", names);
		}
	}

	/**
	 * Reads the field descriptor at {@code at} in a section that ends before {@code end}, with
	 * its records if it fits (see {@link Descriptor}).
	 */
	public static Descriptor read(long at, long end, WordReader r) {
		long typeName = relative(at, r);
		int kind = r.u16(at + 8);
		int recordSize = r.u16(at + 10);
		int count = r.i32(at + 12);
		if (recordSize < RECORD_SIZE || count < 0 ||
			HEADER + (long) recordSize * count > end - at) {
			return new Descriptor(at, typeName, kind, recordSize, count, false, List.of());
		}
		List<FieldRecord> records = new ArrayList<>(count);
		for (int i = 0; i < count; i++) {
			long p = at + HEADER + (long) recordSize * i;
			records.add(new FieldRecord(p, r.i32(p), relative(p + 4, r), relative(p + 8, r)));
		}
		return new Descriptor(at, typeName, kind, recordSize, count, true, records);
	}

	/** Target of the relative pointer at {@code at}, 0 if the offset is 0. */
	private static long relative(long at, WordReader r) {
		int offset = r.i32(at);
		return offset == 0 ? 0 : at + offset;
	}
}
