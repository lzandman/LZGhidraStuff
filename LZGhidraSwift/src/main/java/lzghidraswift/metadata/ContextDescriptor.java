// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * A Swift context descriptor (swift/ABI/Metadata.h, TargetContextDescriptor and subclasses), with
 * the fields the Swift Data Types analyzer needs. Offsets in bytes:
 * <pre>
 * all      +0 flags (kind in bits 0–4, generic 0x80, kind-specific flags in bits 16–31)
 *          +4 parent (relative pointer, indirect if bit 0 is set)
 * module, protocol, type
 *          +8 name (relative pointer to a C string)
 * type     +12 metadata accessor function, +16 field descriptor (relative pointers)
 * struct   +20 numFields, +24 fieldOffsetVectorOffset (in words)
 * enum     +20 payload cases (bits 0–23) and payload size offset, +24 empty cases
 * class    +20 superclass (relative pointer to a mangled name), +36 numFields,
 *          +40 fieldOffsetVectorOffset (in words)
 * </pre>
 */
public record ContextDescriptor(Address address, int flags, Address parent, String name,
		Address accessor, Address fields, int numFields, int fieldOffsetVectorOffset,
		int payloadCases, int emptyCases, Address superclass) {

	// ContextDescriptorKind (swift/ABI/MetadataValues.h).
	public static final int KIND_MODULE = 0;
	public static final int KIND_EXTENSION = 1;
	public static final int KIND_ANONYMOUS = 2;
	public static final int KIND_PROTOCOL = 3;
	public static final int KIND_OPAQUE_TYPE = 4;
	public static final int KIND_CLASS = 16;
	public static final int KIND_STRUCT = 17;
	public static final int KIND_ENUM = 18;

	// MetadataInitializationKind of TypeContextDescriptorFlags (swift/ABI/MetadataValues.h).
	/** NoMetadataInitialization: the metadata is static. */
	public static final int INIT_NONE = 0;
	/** SingletonMetadataInitialization: the metadata is built at run time on first use. */
	public static final int INIT_SINGLETON = 1;
	/** ForeignMetadataInitialization: the metadata of an imported C type. */
	public static final int INIT_FOREIGN = 2;

	private static final int GENERIC = 0x80;
	private static final int PROTOCOL_ANY_CONSTRAINT = 1 << 16;
	private static final int CLASS_HAS_VTABLE = 1 << 31;
	private static final int CLASS_HAS_OVERRIDE_TABLE = 1 << 30;
	private static final int CLASS_HAS_RESILIENT_SUPERCLASS = 1 << 29;

	private static final int MAX_NAME = 1024;

	public int kind() {
		return flags & 0x1f;
	}

	public boolean isGeneric() {
		return isGeneric(flags);
	}

	/**
	 * ContextDescriptorFlags::isGeneric (bit 7, 0x80 of the flags {@code flags}): the descriptor
	 * is followed by a generic context.
	 */
	public static boolean isGeneric(int flags) {
		return (flags & GENERIC) != 0;
	}

	/**
	 * A class-constrained protocol: ProtocolContextDescriptorFlags::getClassConstraint (bit 0 of
	 * the kind-specific flags, flags bit 16) is ProtocolClassConstraint::Class, which is 0. False
	 * for a descriptor that is not a protocol.
	 */
	public boolean isClassConstrained() {
		return kind() == KIND_PROTOCOL && (flags & PROTOCOL_ANY_CONSTRAINT) == 0;
	}

	/**
	 * TypeContextDescriptorFlags::class_hasVTable (Class_HasVTable, kind-specific bit 15, flags
	 * bit 31) of the flags {@code flags} of a class descriptor: it has a vtable header.
	 */
	public static boolean classHasVTable(int flags) {
		return (flags & CLASS_HAS_VTABLE) != 0;
	}

	/**
	 * TypeContextDescriptorFlags::class_hasOverrideTable (Class_HasOverrideTable, kind-specific
	 * bit 14, flags bit 30) of the flags {@code flags} of a class descriptor: it has an override
	 * table.
	 */
	public static boolean classHasOverrideTable(int flags) {
		return (flags & CLASS_HAS_OVERRIDE_TABLE) != 0;
	}

	/**
	 * TypeContextDescriptorFlags::class_hasResilientSuperclass (Class_HasResilientSuperclass,
	 * kind-specific bit 13, flags bit 29) of the flags {@code flags} of a class descriptor: it
	 * has a resilient superclass pointer.
	 */
	public static boolean classHasResilientSuperclass(int flags) {
		return (flags & CLASS_HAS_RESILIENT_SUPERCLASS) != 0;
	}

	public boolean isType() {
		return kind() >= KIND_CLASS && kind() <= KIND_ENUM;
	}

	/**
	 * Metadata initialization (TypeContextDescriptorFlags bits 0–1, in bits 16–17 of the flags):
	 * {@link #INIT_NONE}, {@link #INIT_SINGLETON} or {@link #INIT_FOREIGN}; {@link #INIT_NONE}
	 * for a descriptor that is not a type.
	 */
	public int metadataInitialization() {
		return isType() ? initialization(flags) : INIT_NONE;
	}

	/** The metadata initialization in the flags {@code flags} of a type context descriptor. */
	public static int initialization(int flags) {
		return (flags >>> 16) & 3;
	}

	public String initName() {
		return initName(metadataInitialization());
	}

	/** The name of a metadata initialization: "none", "singleton", "foreign", or "?". */
	public static String initName(int initialization) {
		return switch (initialization) {
			case INIT_NONE -> "none";
			case INIT_SINGLETON -> "singleton";
			case INIT_FOREIGN -> "foreign";
			default -> "?";
		};
	}

	public String kindName() {
		return kindName(kind());
	}

	/** The name of a context descriptor kind, such as "struct", or "kind" and the number. */
	public static String kindName(int kind) {
		return switch (kind) {
			case KIND_MODULE -> "module";
			case KIND_EXTENSION -> "extension";
			case KIND_ANONYMOUS -> "anonymous";
			case KIND_PROTOCOL -> "protocol";
			case KIND_OPAQUE_TYPE -> "opaque type";
			case KIND_CLASS -> "class";
			case KIND_STRUCT -> "struct";
			case KIND_ENUM -> "enum";
			default -> "kind " + kind;
		};
	}

	/** Reads the descriptor at {@code at}. Throws if a field is outside initialized memory. */
	public static ContextDescriptor read(Memory memory, Address at) throws MemoryAccessException {
		int flags = memory.getInt(at);
		int kind = flags & 0x1f;
		Address parent = null;
		int parentOffset = memory.getInt(at.add(4));
		if (parentOffset != 0) {
			parent = at.add(4).add(parentOffset & ~1);
			if ((parentOffset & 1) != 0) {
				parent = pointer(memory, parent);
			}
		}
		String name = null;
		if (kind == KIND_MODULE || kind == KIND_PROTOCOL ||
			(kind >= KIND_CLASS && kind <= KIND_ENUM)) {
			name = cString(memory, relativeOrNull(memory, at.add(8)));
		}
		Address accessor = null;
		Address fields = null;
		int numFields = 0;
		int fieldOffsetVectorOffset = 0;
		int payloadCases = 0;
		int emptyCases = 0;
		Address superclass = null;
		if (kind >= KIND_CLASS && kind <= KIND_ENUM) {
			accessor = relativeOrNull(memory, at.add(12));
			fields = relativeOrNull(memory, at.add(16));
			switch (kind) {
				case KIND_STRUCT -> {
					numFields = memory.getInt(at.add(20));
					fieldOffsetVectorOffset = memory.getInt(at.add(24));
				}
				case KIND_ENUM -> {
					payloadCases = memory.getInt(at.add(20)) & 0xffffff;
					emptyCases = memory.getInt(at.add(24));
				}
				default -> {
					superclass = relativeOrNull(memory, at.add(20));
					numFields = memory.getInt(at.add(36));
					fieldOffsetVectorOffset = memory.getInt(at.add(40));
				}
			}
		}
		return new ContextDescriptor(at, flags, parent, name, accessor, fields, numFields,
			fieldOffsetVectorOffset, payloadCases, emptyCases, superclass);
	}

	/** Target of a relative pointer, or null if the offset is 0. */
	public static Address relativeOrNull(Memory memory, Address at) throws MemoryAccessException {
		int offset = memory.getInt(at);
		return offset == 0 ? null : at.add(offset);
	}

	/** The 64-bit pointer at {@code at}, in the same address space. */
	public static Address pointer(Memory memory, Address at) throws MemoryAccessException {
		return at.getNewAddress(memory.getLong(at));
	}

	/** The NUL-terminated string at {@code at} (Latin-1, at most 1024 bytes), or null. */
	public static String cString(Memory memory, Address at) throws MemoryAccessException {
		if (at == null) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < MAX_NAME; i++) {
			int c = memory.getByte(at.add(i)) & 0xff;
			if (c == 0) {
				return sb.toString();
			}
			sb.append((char) c);
		}
		throw new MemoryAccessException("no NUL within " + MAX_NAME + " bytes at " + at);
	}
}
