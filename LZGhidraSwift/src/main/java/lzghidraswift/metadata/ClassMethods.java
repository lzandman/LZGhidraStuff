// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import java.util.ArrayList;
import java.util.List;

/**
 * Plain Java: the method descriptors and method overrides of a class descriptor, from its
 * trailing objects (swift/ABI/Metadata.h, TargetClassDescriptor). Offsets in bytes from the
 * descriptor:
 * <pre>
 * +0 flags, ..., +40 fieldOffsetVectorOffset          44 bytes; generic classes are not read
 * resilient superclass      4 bytes, if flag bit 29 (Class_HasResilientSuperclass)
 * metadata initialization   foreign 4 bytes, singleton 12 bytes (flags bits 16-17)
 * vtable header             VTableOffset, VTableSize (words), if flag bit 31 (Class_HasVTable)
 * method descriptors        VTableSize x { flags, Impl (relative) }
 * override table header     NumEntries, if flag bit 30 (Class_HasOverrideTable)
 * override descriptors      NumEntries x { Class, Method (relative, indirectable), Impl (relative) }
 * </pre>
 * Method descriptor flags (MethodDescriptorFlags): kind in bits 0-3 (method, init, getter,
 * setter, modify, read), 0x10 instance, 0x20 dynamic, 0x40 async (for a coroutine kind: callee-
 * allocated). With 0x40 the Impl points to a function pointer record (AsyncFunctionPointer or
 * CoroFunctionPointer) whose first word is a relative pointer to the function.
 */
public record ClassMethods(long vtableOffset, List<Method> methods,
		List<MethodOverride> overrides) {

	public static final int KIND_METHOD = 0;
	public static final int KIND_INIT = 1;
	public static final int KIND_GETTER = 2;
	public static final int KIND_SETTER = 3;
	public static final int KIND_MODIFY = 4;
	public static final int KIND_READ = 5;
	private static final int INSTANCE = 0x10;
	private static final int ASYNC = 0x40;

	private static final int HEADER = 44;

	/**
	 * A method descriptor at {@code address}: {@code impl} is the target of its Impl pointer (0
	 * if null: the method was removed), {@code function} the function (the same, or for 0x40 the
	 * function of the record at {@code impl}).
	 */
	public record Method(long address, int flags, long impl, long function) {

		public int kind() {
			return flags & 0x0f;
		}

		public boolean isInstance() {
			return (flags & INSTANCE) != 0;
		}

		/** An instance method that gets self in the context register: not an initializer. */
		public boolean takesSelf() {
			return isInstance() && kind() != KIND_INIT && kind() <= KIND_READ;
		}
	}

	/**
	 * An override: the base method's descriptor ({@code base}, null if it is in another binary
	 * and could not be read) and the implementation.
	 */
	public record MethodOverride(long address, Method base, long impl, long function) {}

	/**
	 * Reads the tables of the class descriptor at {@code descriptor} with flags {@code flags}.
	 * Returns empty lists for a generic class (whose trailing objects start with a generic
	 * context, not read here) or a class without tables.
	 */
	public static ClassMethods read(long descriptor, int flags, WordReader r) {
		List<Method> methods = new ArrayList<>();
		List<MethodOverride> overrides = new ArrayList<>();
		if (ContextDescriptor.isGeneric(flags)) {
			return new ClassMethods(-1, methods, overrides);
		}
		long p = descriptor + HEADER;
		if (ContextDescriptor.classHasResilientSuperclass(flags)) {
			p += 4;
		}
		switch (ContextDescriptor.initialization(flags)) {
			case ContextDescriptor.INIT_SINGLETON -> p += 12;
			case ContextDescriptor.INIT_FOREIGN -> p += 4;
			default -> {
			}
		}
		long vtableOffset = -1;
		if (ContextDescriptor.classHasVTable(flags)) {
			vtableOffset = r.i32(p) & 0xffffffffL;
			int size = r.i32(p + 4);
			p += 8;
			for (int i = 0; i < size; i++, p += 8) {
				methods.add(method(p, r));
			}
		}
		if (ContextDescriptor.classHasOverrideTable(flags)) {
			int count = r.i32(p);
			p += 4;
			for (int i = 0; i < count; i++, p += 12) {
				Method base = null;
				int baseOffset = r.i32(p + 4);
				if (baseOffset != 0 && (baseOffset & 1) == 0) {
					base = method(p + 4 + baseOffset, r);
				}
				long impl = relative(p + 8, r);
				long function = base == null || impl == 0 ? 0 : function(base.flags(), impl, r);
				overrides.add(new MethodOverride(p, base, impl, function));
			}
		}
		return new ClassMethods(vtableOffset, methods, overrides);
	}

	private static Method method(long at, WordReader r) {
		int flags = r.i32(at);
		long impl = relative(at + 4, r);
		return new Method(at, flags, impl, impl == 0 ? 0 : function(flags, impl, r));
	}

	private static long function(int flags, long impl, WordReader r) {
		return (flags & ASYNC) != 0 ? relative(impl, r) : impl;
	}

	/** Target of the relative pointer at {@code at}, 0 if the offset is 0. */
	private static long relative(long at, WordReader r) {
		int offset = r.i32(at);
		return offset == 0 ? 0 : at + offset;
	}
}
