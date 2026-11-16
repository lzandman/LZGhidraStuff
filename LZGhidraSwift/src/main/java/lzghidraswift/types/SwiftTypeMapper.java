// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.types;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.Float2DataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.SignedCharDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import lzghidraswift.mangling.SwiftTypeName;
import lzghidraswift.mangling.SwiftTypeName.Existential;
import lzghidraswift.mangling.SwiftTypeName.FunctionType;
import lzghidraswift.mangling.SwiftTypeName.Nominal;
import lzghidraswift.mangling.SwiftTypeName.Tuple;

/**
 * Maps a parsed Swift type ({@link SwiftTypeName}) to a Ghidra data type with the type's Swift
 * size, alignment and extra inhabitant count. Types of the binary itself come from
 * {@link OwnTypes}; helper types (String, Optional with a tag byte, tuples, closures,
 * existentials) are created in {@code /SwiftTypes/Swift}. Returns null for anything it cannot
 * lay out (types of other modules whose size is unknown, payload enums, generics, ...).
 * <p>
 * Assumes 64-bit pointers (arm64 and x86_64).
 */
public class SwiftTypeMapper {

	/** A Ghidra type for a Swift type; {@code type} is null for a size-0 type. */
	public record Mapped(DataType type, long size, int alignment, long extraInhabitants) {}

	/** Lookups of the types of the binary, implemented by {@link SwiftTypeBuilder}. */
	public interface OwnTypes {

		/**
		 * The data type of a type of the binary: the embedded structure or enum for a value
		 * type, a pointer for a class; null if it has none.
		 */
		Mapped own(Nominal type);

		/** True if a protocol of the binary is constrained to classes, null if unknown. */
		Boolean classConstrained(Nominal protocol);
	}

	public static final CategoryPath ROOT = new CategoryPath("/SwiftTypes");
	public static final CategoryPath SWIFT = new CategoryPath(ROOT, "Swift");

	private static final int POINTER = 8;
	private static final long MANY = SwiftLayout.MANY;

	/** Fixed-size standard library types: data type, size, extra inhabitants. */
	private static final Map<String, Mapped> PRIMITIVES = Map.ofEntries(
		primitive("Swift.Int", LongLongDataType.dataType, 8, 0),
		primitive("Swift.UInt", UnsignedLongLongDataType.dataType, 8, 0),
		primitive("Swift.Int64", LongLongDataType.dataType, 8, 0),
		primitive("Swift.UInt64", UnsignedLongLongDataType.dataType, 8, 0),
		primitive("Swift.Int32", IntegerDataType.dataType, 4, 0),
		primitive("Swift.UInt32", UnsignedIntegerDataType.dataType, 4, 0),
		primitive("Swift.Int16", ShortDataType.dataType, 2, 0),
		primitive("Swift.UInt16", UnsignedShortDataType.dataType, 2, 0),
		primitive("Swift.Int8", SignedCharDataType.dataType, 1, 0),
		primitive("Swift.UInt8", UnsignedCharDataType.dataType, 1, 0),
		primitive("Swift.Double", DoubleDataType.dataType, 8, 0),
		primitive("Swift.Float", FloatDataType.dataType, 4, 0),
		primitive("Swift.Float16", Float2DataType.dataType, 2, 0),
		primitive("Swift.Bool", BooleanDataType.dataType, 1, 254),
		// A struct of one Double on 64-bit targets (CoreGraphics overlay)
		primitive("CoreGraphics.CGFloat", DoubleDataType.dataType, 8, 0));

	/** Standard library types that are one reference to a heap object (a buffer or storage). */
	private static final Set<String> REFERENCES = Set.of("Swift.Array", "Swift.ContiguousArray",
		"Swift.Dictionary", "Swift.Set", "Swift.AnyClass");

	/**
	 * Untyped raw pointers. Like the typed {@code UnsafePointer}, they have one extra inhabitant
	 * (null), not many: {@code MemoryLayout<UnsafeMutableRawPointer??>.size} is 9.
	 */
	private static final Set<String> RAW_POINTERS =
		Set.of("Swift.UnsafeRawPointer", "Swift.UnsafeMutableRawPointer", "Swift.OpaquePointer");

	/** Buffer pointers: a start pointer and a count, no extra inhabitants (Optional: 17 bytes). */
	private static final Set<String> BUFFER_POINTERS = Set.of("Swift.UnsafeBufferPointer",
		"Swift.UnsafeMutableBufferPointer", "Swift.UnsafeRawBufferPointer",
		"Swift.UnsafeMutableRawBufferPointer");

	/** Protocols without witness tables (marker protocols). */
	private static final Set<String> MARKER_PROTOCOLS =
		Set.of("Swift.Sendable", "Swift.Copyable", "Swift.Escapable", "Swift.BitwiseCopyable");

	private static Map.Entry<String, Mapped> primitive(String name, DataType type, int size,
			long extra) {
		return Map.entry(name, new Mapped(type, size, size, extra));
	}

	private final DataTypeManager dtm;
	private final OwnTypes own;
	private final SwiftTypeBuilder.Installer installer;

	public SwiftTypeMapper(DataTypeManager dtm, OwnTypes own,
			SwiftTypeBuilder.Installer installer) {
		this.dtm = dtm;
		this.own = own;
		this.installer = installer;
	}

	/** The data type for {@code type}, or null if it cannot be laid out. */
	public Mapped map(SwiftTypeName type) {
		return switch (type) {
			case Nominal n -> nominal(n);
			case Tuple t -> tuple(t);
			case FunctionType f -> switch (f.convention()) {
				case "swift" -> new Mapped(closure(), 16, POINTER, MANY);
				case "block", "c" -> pointer(VoidDataType.dataType);
				default -> null;
			};
			case Existential e -> existential(e);
			case SwiftTypeName.ExistentialMetatype m -> existentialMetatype(m.instance());
			// A class's metatype is the metadata pointer; a struct's, enum's or tuple's is thin.
			case SwiftTypeName.Metatype m -> switch (m.instance()) {
				case Nominal n when n.kind() == 'C' -> pointer(VoidDataType.dataType);
				case Nominal n when n.kind() == 'V' || n.kind() == 'O' -> new Mapped(null, 0, 1, 0);
				default -> m.instance() instanceof Tuple ? new Mapped(null, 0, 1, 0) : null;
			};
			// weak and unowned references: a class reference or a class existential, as without
			// the ownership (Darwin; weak references are Objective-C weak pointers there). Swift
			// gives them no extra inhabitants.
			case SwiftTypeName.Ownership o -> {
				Mapped m = map(o.type());
				yield m == null ? null : new Mapped(m.type(), m.size(), m.alignment(), 0);
			}
			default -> null;
		};
	}

	private Mapped nominal(Nominal n) {
		if (n.target() != null && "VCO".indexOf(n.kind()) >= 0) {
			return own.own(n);
		}
		if (n.args().isEmpty()) {
			Mapped primitive = PRIMITIVES.get(n.name());
			if (primitive != null) {
				return primitive;
			}
			Mapped builtin = builtin(n.name());
			if (builtin != null) {
				return builtin;
			}
		}
		switch (n.name()) {
			case "Swift.Optional" -> {
				return n.args().size() == 1 ? optional(n) : null;
			}
			case "Swift.String", "Swift.Character" -> {
				return new Mapped(string(), 16, POINTER, MANY);
			}
			case "Swift.UnsafePointer", "Swift.UnsafeMutablePointer" -> {
				Mapped p = pointer(pointee(n));
				return new Mapped(p.type(), POINTER, POINTER, 1);
			}
			default -> {
			}
		}
		if (RAW_POINTERS.contains(n.name()) && n.args().isEmpty()) {
			return new Mapped(new PointerDataType(VoidDataType.dataType, dtm), POINTER, POINTER, 1);
		}
		if (n.name().equals("Swift.InlineArray")) {
			return inlineArray(n);
		}
		if (BUFFER_POINTERS.contains(n.name())) {
			return bufferPointer(n);
		}
		if (REFERENCES.contains(n.name()) || n.kind() == 'C') {
			// Arrays, dictionaries, sets: the storage object; classes of other modules and
			// Objective-C classes: an object reference. Not typed further in this version.
			return pointer(VoidDataType.dataType);
		}
		return null;
	}

	/**
	 * Builtin types (swift/ABI/MetadataValues.h): object references and raw pointers; the actor
	 * storages (12 words, MaximumAlignment 16) and the value buffer (3 words) as opaque structures
	 * in {@code /SwiftTypes/Swift}; {@code Builtin.Int<n>} for n = 8, 16, 32, 64.
	 */
	private Mapped builtin(String name) {
		return switch (name) {
			case "Builtin.NativeObject", "Builtin.UnknownObject", "Builtin.BridgeObject" -> pointer(
				VoidDataType.dataType);
			case "Builtin.RawPointer" -> new Mapped(new PointerDataType(VoidDataType.dataType, dtm),
				POINTER, POINTER, 1);
			case "Builtin.Word", "Builtin.Int64" -> new Mapped(LongLongDataType.dataType, 8, 8, 0);
			case "Builtin.Int32" -> new Mapped(IntegerDataType.dataType, 4, 4, 0);
			case "Builtin.Int16" -> new Mapped(ShortDataType.dataType, 2, 2, 0);
			case "Builtin.Int8" -> new Mapped(SignedCharDataType.dataType, 1, 1, 0);
			case "Builtin.DefaultActorStorage", "Builtin.NonDefaultDistributedActorStorage" -> opaque(
				name.substring("Builtin.".length()), 96, 16);
			case "Builtin.UnsafeValueBuffer" -> opaque("UnsafeValueBuffer", 24, POINTER);
			default -> null;
		};
	}

	/**
	 * {@code InlineArray<N, T>}: N elements inline, at T's stride (a test library, not in the
	 * repository: InlineArray<3, Int16> is 6 bytes). Extra inhabitants: 0, the safe side.
	 */
	private Mapped inlineArray(Nominal n) {
		if (n.args().size() != 2 ||
			!(n.args().getFirst() instanceof SwiftTypeName.IntegerValue count) ||
			count.value() < 0 || count.value() > 1 << 20) {
			return null;
		}
		Mapped element = map(n.args().get(1));
		if (element == null) {
			return null;
		}
		long stride = Math.max(1, align(element.size(), element.alignment()));
		if (count.value() == 0 || element.size() == 0) {
			return new Mapped(null, 0, element.alignment(), 0);
		}
		if (element.type() == null) {
			return null;
		}
		long size = stride * (count.value() - 1) + element.size();
		if (stride != element.size()) {
			return null; // elements with padding: Ghidra arrays step by the element's length
		}
		return new Mapped(
			new ArrayDataType(element.type(), (int) count.value(), (int) element.size(), dtm),
			size, element.alignment(), 0);
	}

	/** An opaque structure of undefined bytes in {@code /SwiftTypes/Swift}. */
	private Mapped opaque(String name, int size, int alignment) {
		StructureDataType s = new StructureDataType(SWIFT, name, size, dtm);
		s.setExplicitMinimumAlignment(alignment);
		s.setDescription("Swift Builtin." + name + ", opaque");
		return installed(s, size, alignment, 0);
	}

	/** The data type a typed pointer points to: its argument's, or void. */
	private DataType pointee(Nominal n) {
		Mapped pointee = n.args().size() == 1 ? map(n.args().getFirst()) : null;
		return pointee != null && pointee.type() != null ? pointee.type() : VoidDataType.dataType;
	}

	/**
	 * {@code UnsafeBufferPointer<T>} and the other buffer pointers: the start (an optional
	 * pointer) and the count, as a structure in {@code /SwiftTypes/Swift}.
	 */
	private Mapped bufferPointer(Nominal n) {
		boolean typed = n.args().size() == 1;
		if (typed == n.name().contains("Raw")) {
			return null;
		}
		StructureDataType s = new StructureDataType(SWIFT,
			n.render().substring(n.name().indexOf('.') + 1), 16, dtm);
		s.replaceAtOffset(0, new PointerDataType(typed ? pointee(n) : VoidDataType.dataType, dtm),
			POINTER, "start", "null for an empty buffer");
		s.replaceAtOffset(8, LongLongDataType.dataType, 8, "count", null);
		s.setExplicitMinimumAlignment(POINTER);
		s.setDescription("Swift " + n.render());
		return installed(s, 16, POINTER, 0);
	}

	/**
	 * {@code T?}: T itself if T has extra inhabitants (nil is one of them), else T and a tag
	 * byte, as a structure {@code Optional<T>} in {@code /SwiftTypes/Swift}.
	 */
	private Mapped optional(Nominal n) {
		SwiftTypeName wrapped = n.args().getFirst();
		Mapped payload = map(wrapped);
		if (payload == null) {
			return null;
		}
		if (payload.extraInhabitants() > 0) {
			return new Mapped(payload.type(), payload.size(), payload.alignment(),
				payload.extraInhabitants() - 1);
		}
		StructureDataType s = new StructureDataType(SWIFT, "Optional<" + wrapped.render() + ">",
			(int) payload.size() + 1, dtm);
		if (payload.type() != null) {
			s.replaceAtOffset(0, payload.type(), (int) payload.size(), "value", null);
		}
		s.replaceAtOffset((int) payload.size(), UnsignedCharDataType.dataType, 1, "tag",
			"1 if nil, then value is 0");
		s.setExplicitMinimumAlignment(payload.alignment());
		s.setDescription("Swift " + n.render() + ": the value, then a tag byte");
		// The tag byte's spare values are extra inhabitants too, but 0 is the safe side.
		return installed(s, payload.size() + 1, payload.alignment(), 0);
	}

	/**
	 * A tuple: the elements in order, each at its alignment after the previous element's size
	 * (the same rule as a struct), as a structure in {@code /SwiftTypes/Swift}.
	 */
	private Mapped tuple(Tuple t) {
		List<Mapped> elements = new ArrayList<>();
		long offset = 0;
		int alignment = 1;
		long extra = 0;
		List<Long> offsets = new ArrayList<>();
		for (SwiftTypeName e : t.elements()) {
			Mapped m = map(e);
			if (m == null) {
				return null;
			}
			offset = align(offset, m.alignment());
			offsets.add(offset);
			elements.add(m);
			offset += m.size();
			alignment = Math.max(alignment, m.alignment());
			extra = Math.max(extra, m.extraInhabitants());
		}
		if (offset == 0) {
			return new Mapped(null, 0, 1, 0);
		}
		StructureDataType s = new StructureDataType(SWIFT, t.render(), (int) offset, dtm);
		for (int i = 0; i < elements.size(); i++) {
			Mapped m = elements.get(i);
			if (m.type() != null) {
				String label = t.labels().get(i);
				s.replaceAtOffset(offsets.get(i).intValue(), m.type(), (int) m.size(),
					label != null ? label : "_" + i, t.elements().get(i).render());
			}
		}
		s.setExplicitMinimumAlignment(alignment);
		s.setDescription("Swift tuple " + t.render());
		return installed(s, offset, alignment, extra);
	}

	/**
	 * A protocol existential. Opaque ({@code any P}): a 3-word inline buffer, the type metadata
	 * and one witness table per Swift protocol. Constrained to classes ({@code AnyObject}, a
	 * class-constrained protocol, an Objective-C protocol): the object reference and the witness
	 * tables; without Swift protocols just the reference.
	 */
	private Mapped existential(Existential e) {
		int witnessTables = 0;
		boolean classBound = e.anyObject();
		for (Nominal p : e.protocols()) {
			if (p.objc()) {
				classBound = true;
			}
			else if (!MARKER_PROTOCOLS.contains(p.name())) {
				witnessTables++;
				if (p.target() != null && Boolean.TRUE.equals(own.classConstrained(p))) {
					classBound = true;
				}
			}
		}
		if (classBound && witnessTables == 0) {
			return pointer(VoidDataType.dataType);
		}
		// any Error (also with marker protocols, & Sendable): one reference to a box that holds
		// the value, its type and the conformance (8 bytes, Optional too; measured with
		// MemoryLayout, Swift 6.4, arm64). Error with another protocol is an opaque existential.
		if (!classBound && witnessTables == 1 && e.protocols()
				.stream()
				.anyMatch(p -> !p.objc() && p.name().equals("Swift.Error"))) {
			return pointer(VoidDataType.dataType);
		}
		String name = (classBound ? "ClassExistential" : "Existential") +
			(witnessTables != 1 ? Integer.toString(witnessTables) : "");
		long size = (classBound ? 8 : 32) + 8L * witnessTables;
		StructureDataType s = new StructureDataType(SWIFT, name, (int) size, dtm);
		DataType voidPointer = new PointerDataType(VoidDataType.dataType, dtm);
		int offset;
		if (classBound) {
			s.replaceAtOffset(0, voidPointer, POINTER, "object", null);
			offset = 8;
		}
		else {
			s.replaceAtOffset(0, new ArrayDataType(voidPointer, 3, POINTER, dtm), 24, "buffer",
				"the value inline if it fits, else a reference to a box");
			s.replaceAtOffset(24, voidPointer, POINTER, "type", "type metadata of the value");
			offset = 32;
		}
		for (int i = 0; i < witnessTables; i++) {
			s.replaceAtOffset(offset + 8 * i, voidPointer, POINTER,
				witnessTables == 1 ? "witnessTable" : "witnessTable" + i, null);
		}
		s.setExplicitMinimumAlignment(POINTER);
		s.setDescription("Swift existential container" + (classBound ? ", class-constrained" : "") +
			", " + witnessTables + " witness table" + (witnessTables != 1 ? "s" : ""));
		return installed(s, size, POINTER, MANY);
	}

	/**
	 * An existential metatype ({@code any P.Type}): the type metadata, then one witness table per
	 * Swift protocol; only the metadata for {@code Any.Type}, {@code AnyObject.Type} and
	 * Objective-C protocols. Sizes measured with MemoryLayout (Swift 6.4, arm64): 16 for one
	 * protocol, 24 for two, 8 without; Optional adds nothing.
	 */
	private Mapped existentialMetatype(Existential e) {
		int witnessTables = 0;
		for (Nominal p : e.protocols()) {
			if (!p.objc() && !MARKER_PROTOCOLS.contains(p.name())) {
				witnessTables++;
			}
		}
		if (witnessTables == 0) {
			return pointer(VoidDataType.dataType);
		}
		String name =
			"ExistentialMetatype" + (witnessTables != 1 ? Integer.toString(witnessTables) : "");
		long size = 8 + 8L * witnessTables;
		StructureDataType s = new StructureDataType(SWIFT, name, (int) size, dtm);
		DataType voidPointer = new PointerDataType(VoidDataType.dataType, dtm);
		s.replaceAtOffset(0, voidPointer, POINTER, "type", "type metadata");
		for (int i = 0; i < witnessTables; i++) {
			s.replaceAtOffset(8 + 8 * i, voidPointer, POINTER,
				witnessTables == 1 ? "witnessTable" : "witnessTable" + i, null);
		}
		s.setExplicitMinimumAlignment(POINTER);
		s.setDescription("Swift existential metatype, " + witnessTables + " witness table" +
			(witnessTables != 1 ? "s" : ""));
		return installed(s, size, POINTER, MANY);
	}

	/** {@code Swift.String}: two words (stdlib/public/core/StringObject.swift). */
	DataType string() {
		StructureDataType s = new StructureDataType(SWIFT, "String", 16, dtm);
		s.replaceAtOffset(0, UnsignedLongLongDataType.dataType, 8, "countAndFlags",
			"small string: the first 8 bytes");
		s.replaceAtOffset(8, new PointerDataType(VoidDataType.dataType, dtm), POINTER,
			"object", "tag in the top bits; small string: bytes 8-14 and the count");
		s.setExplicitMinimumAlignment(POINTER);
		s.setDescription("Swift String");
		return installer.install(s);
	}

	/** A Swift closure: the function and its context (null or a heap object). */
	private DataType closure() {
		StructureDataType s = new StructureDataType(SWIFT, "Closure", 16, dtm);
		s.replaceAtOffset(0, new PointerDataType(VoidDataType.dataType, dtm), POINTER,
			"function", null);
		s.replaceAtOffset(8, new PointerDataType(VoidDataType.dataType, dtm), POINTER,
			"context", "captured values, or null");
		s.setExplicitMinimumAlignment(POINTER);
		s.setDescription("Swift closure (thick function)");
		return installer.install(s);
	}

	private Mapped pointer(DataType to) {
		return new Mapped(new PointerDataType(to, dtm), POINTER, POINTER, MANY);
	}

	private Mapped installed(Structure s, long size, int alignment, long extra) {
		DataType type = installer.install(s);
		return type == null ? null : new Mapped(type, size, alignment, extra);
	}

	static long align(long offset, int alignment) {
		return (offset + alignment - 1) / alignment * alignment;
	}
}
