// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.runtime;

import static java.util.Map.entry;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.VoidDataType;

/**
 * The Ghidra data types for the IRGen type names of {@link RuntimeTable}, in the category
 * {@link #CATEGORY}. Pointers to runtime objects point to empty structures with the runtime's
 * names ({@code HeapObject *}, {@code Metadata *}), so the decompiler shows their role and they do
 * not mix; the values returned in two registers are structures ({@code MetadataResponse},
 * {@code BoxPair}). The types are made for the data type manager but not added to it: Ghidra
 * resolves them when a function's signature is set. An IRGen name not in these tables throws;
 * a unit test runs every name of the data file, so a new one fails there.
 * <p>
 * Header pointees: where the .def has an untyped pointer ({@code Int8PtrTy}, {@code PtrTy}) and
 * the header names the pointee ({@link RuntimeTable.Param#pointee}), the parameter points to
 * that structure if it is one of these: the opaque structures above, the metadata kinds
 * ({@code ClassMetadata}, {@code EnumMetadata}, {@code StructMetadata}, {@code HeapMetadata},
 * which become {@code Metadata}, so one object does not get several pointer types and the
 * decompiler adds no casts between them), and {@code ValueBuffer}, a real structure of 24 bytes
 * (three words, {@code NumWords_ValueBuffer}) so that a caller's stack buffer gets its size.
 * Any other pointee ({@code TaskGroup}, {@code TypeLayout}, {@code uint32_t}) stays
 * {@code void *}, and does not throw: the header only refines the .def's type.
 */
public final class RuntimeTypes {

	/** The category of the runtime types. */
	public static final CategoryPath CATEGORY = new CategoryPath("/SwiftRuntime");

	/** Pointers to an opaque runtime structure: IRGen name, structure name. */
	private static final Map<String, String> OPAQUE = Map.ofEntries(
		entry("RefCountedPtrTy", "HeapObject"),
		entry("BridgeObjectPtrTy", "BridgeObject"),
		entry("TypeMetadataPtrTy", "Metadata"),
		entry("WitnessTablePtrTy", "WitnessTable"),
		entry("OpaquePtrTy", "OpaqueValue"),
		entry("ProtocolDescriptorPtrTy", "ProtocolDescriptor"),
		entry("ProtocolConformanceDescriptorPtrTy", "ProtocolConformanceDescriptor"),
		entry("TypeContextDescriptorPtrTy", "TypeContextDescriptor"),
		entry("OpaqueTypeDescriptorPtrTy", "OpaqueTypeDescriptor"),
		entry("ErrorPtrTy", "SwiftError"),
		entry("WeakReferencePtrTy", "WeakReference"),
		entry("UnownedReferencePtrTy", "UnownedReference"),
		entry("SwiftTaskPtrTy", "AsyncTask"),
		entry("SwiftContextPtrTy", "AsyncContext"),
		entry("ContinuationAsyncContextPtrTy", "AsyncContext"),
		entry("SwiftAsyncLetPtrTy", "AsyncLet"),
		entry("SwiftTaskOptionRecordPtrTy", "TaskOptionRecord"),
		entry("ObjCPtrTy", "objc_object"),
		entry("ObjCClassPtrTy", "objc_class"),
		entry("ObjCSELTy", "objc_selector"));

	/** Pointers to pointers: IRGen name, IRGen name of the pointer they point to. */
	private static final Map<String, String> POINTER_TO = Map.of(
		"TypeMetadataPtrPtrTy", "TypeMetadataPtrTy",
		"WitnessTablePtrPtrTy", "WitnessTablePtrTy",
		"Int8PtrPtrTy", "Int8PtrTy");

	/**
	 * Pointers that stay {@code void *}: raw bytes, code, blocks, objects that may be Swift or
	 * Objective-C ({@code UnknownRefCountedPtrTy}), and records nothing else refers to.
	 */
	private static final List<String> VOID_POINTERS = List.of("Int8PtrTy", "PtrTy",
		"UnknownRefCountedPtrTy", "ObjCBlockPtrTy", "FunctionPtrTy",
		"TaskContinuationFunctionPtrTy", "RelativeAddressPtrTy", "ProtocolRecordPtrTy",
		"TypeMetadataRecordPtrTy", "OpenedErrorTriplePtrTy");

	/** Header pointees that become another structure: the metadata kinds become Metadata. */
	private static final Map<String, String> POINTEE_ALIASES =
		Map.of("ClassMetadata", "Metadata", "EnumMetadata", "Metadata", "StructMetadata",
			"Metadata", "HeapMetadata", "Metadata");

	/** The structure with the runtime's buffer layout, see {@link #valueBuffer()}. */
	static final String VALUE_BUFFER = "ValueBuffer";

	/** The words of a {@code ValueBuffer}: {@code NumWords_ValueBuffer} in MetadataValues.h. */
	private static final int VALUE_BUFFER_WORDS = 3;

	/** A field of a pair structure, with an IRGen type. */
	private record Field(String name, String type) {}

	/** A value returned in two registers, with the runtime's name and field names. */
	private record Pair(String name, Field first, Field second) {}

	/** The IRGen structure types, and the pairs of a multi-type {@code RETURNS}, by key. */
	private static final Map<String, Pair> PAIRS = Map.of(
		"TypeMetadataResponseTy",
		new Pair("MetadataResponse", new Field("value", "TypeMetadataPtrTy"),
			new Field("state", "SizeTy")),
		"TypeMetadataDependencyTy",
		new Pair("MetadataDependency", new Field("value", "TypeMetadataPtrTy"),
			new Field("requirement", "SizeTy")),
		"OffsetPairTy",
		new Pair("OffsetPair", new Field("first", "SizeTy"), new Field("second", "SizeTy")),
		"SwiftExecutorTy",
		new Pair("SerialExecutorRef", new Field("identity", "RefCountedPtrTy"),
			new Field("implementation", "SizeTy")),
		"AsyncTaskAndContextTy",
		new Pair("AsyncTaskAndContext", new Field("task", "SwiftTaskPtrTy"),
			new Field("initialContext", "SwiftContextPtrTy")),
		"RefCountedPtrTy,OpaquePtrTy",
		new Pair("BoxPair", new Field("object", "RefCountedPtrTy"),
			new Field("buffer", "OpaquePtrTy")),
		"ErrorPtrTy,OpaquePtrTy",
		new Pair("ErrorBoxPair", new Field("object", "ErrorPtrTy"),
			new Field("buffer", "OpaquePtrTy")));

	private final DataTypeManager dtm;
	private final RuntimeTable table;
	private final Map<String, DataType> made = new HashMap<>();

	public RuntimeTypes(DataTypeManager dtm, RuntimeTable table) {
		this.dtm = dtm;
		this.table = table;
	}

	/** The return type of a runtime function: one type, or a pair structure for several. */
	public DataType returnType(RuntimeTable.Entry entry) {
		return type(String.join(",", entry.returns()));
	}

	/** The type of a parameter: the flag enum it names, or its IRGen type. */
	public DataType paramType(RuntimeTable.Param param) {
		if (param.isEnum()) {
			return flagEnum(param.type());
		}
		if (param.pointee() != null) {
			DataType t = pointee(param.pointee());
			if (t != null) {
				return t;
			}
		}
		return type(param.type());
	}

	/**
	 * The structure a header pointee names ({@code ClassMetadata} gives {@code Metadata}), or
	 * {@code null} if it is not one of the structures this class uses; see the class comment.
	 */
	static String pointeeStructure(String name) {
		String s = POINTEE_ALIASES.getOrDefault(name, name);
		return s.equals(VALUE_BUFFER) || OPAQUE.containsValue(s) ? s : null;
	}

	/** The pointer type of a header pointee ({@code Metadata**}), or {@code null}. */
	private DataType pointee(String pointee) {
		int star = pointee.indexOf('*');
		String structure = pointeeStructure(pointee.substring(0, star));
		if (structure == null) {
			return null;
		}
		String key = structure + pointee.substring(star);
		DataType t = made.get(key);
		if (t == null) {
			DataType target = key.endsWith("**") ? pointee(key.substring(0, key.length() - 1))
					: structure.equals(VALUE_BUFFER) ? valueBuffer() : opaqueStructure(structure);
			t = new PointerDataType(target, dtm);
			made.put(key, t);
		}
		return t;
	}

	/**
	 * The runtime's {@code ValueBuffer}: {@code void *privateData[3]}, the inline storage of an
	 * existential or the scratch buffer of {@code swift_beginAccess}.
	 */
	DataType valueBuffer() {
		return made.computeIfAbsent("struct " + VALUE_BUFFER, k -> {
			StructureDataType s = new StructureDataType(CATEGORY, VALUE_BUFFER, 0, dtm);
			DataType word = new PointerDataType(VoidDataType.dataType, dtm);
			s.add(new ArrayDataType(word, VALUE_BUFFER_WORDS, word.getLength(), dtm),
				"privateData", null);
			return s;
		});
	}

	/**
	 * The data type of an IRGen name, or of a comma-separated list of them (a multi-type
	 * {@code RETURNS}). The same name gives the same instance.
	 *
	 * @throws IllegalArgumentException for a name these tables do not know
	 */
	DataType type(String irgen) {
		DataType t = made.get(irgen);
		if (t == null) {
			t = make(irgen);
			made.put(irgen, t);
		}
		return t;
	}

	private DataType make(String irgen) {
		Pair pair = PAIRS.get(irgen);
		if (pair != null) {
			StructureDataType s = new StructureDataType(CATEGORY, pair.name(), 0, dtm);
			s.add(type(pair.first().type()), pair.first().name(), null);
			s.add(type(pair.second().type()), pair.second().name(), null);
			return s;
		}
		String opaque = OPAQUE.get(irgen);
		if (opaque != null) {
			return new PointerDataType(opaqueStructure(opaque), dtm);
		}
		String target = POINTER_TO.get(irgen);
		if (target != null) {
			return new PointerDataType(type(target), dtm);
		}
		if (VOID_POINTERS.contains(irgen)) {
			return new PointerDataType(VoidDataType.dataType, dtm);
		}
		return switch (irgen) {
			case "VoidTy" -> VoidDataType.dataType.clone(dtm);
			case "Int1Ty", "ObjCBoolTy" -> BooleanDataType.dataType.clone(dtm);
			case "Int32Ty" -> integer("int32_t", 4, true);
			case "Int64Ty" -> integer("int64_t", 8, true);
			case "SizeTy", "ExecutorFirstTy", "ExecutorSecondTy" -> integer("size_t",
				dtm.getDataOrganization().getPointerSize(), false);
			case "FloatTy" -> FloatDataType.dataType.clone(dtm);
			case "DoubleTy" -> DoubleDataType.dataType.clone(dtm);
			default -> throw new IllegalArgumentException("unknown IRGen type " + irgen);
		};
	}

	/**
	 * {@code Metadata *}, the type of a {@code TypeMetadataPtrTy} parameter, for the metadata
	 * that other analyzers pass (a class's allocating initializer gets it in x20). The same
	 * structure as the one in the signatures, so the decompiler adds no casts between them.
	 */
	public static DataType metadataPointer(DataTypeManager dtm) {
		return new PointerDataType(
			new StructureDataType(CATEGORY, OPAQUE.get("TypeMetadataPtrTy"), 0, dtm), dtm);
	}

	private DataType opaqueStructure(String name) {
		return made.computeIfAbsent("struct " + name,
			k -> new StructureDataType(CATEGORY, name, 0, dtm));
	}

	private DataType integer(String name, int size, boolean signed) {
		return made.computeIfAbsent(name, k -> {
			DataType base = signed ? AbstractIntegerDataType.getSignedDataType(size, dtm)
					: AbstractIntegerDataType.getUnsignedDataType(size, dtm);
			return new TypedefDataType(CATEGORY, name, base, dtm);
		});
	}

	/**
	 * The enum of a flag enum of the table, with its values and the table's source in its
	 * description.
	 *
	 * @throws IllegalArgumentException for a name not in the table
	 */
	public DataType flagEnum(String name) {
		DataType t = made.get("enum " + name);
		if (t != null) {
			return t;
		}
		RuntimeTable.FlagEnum flags = table.enums().get(name);
		if (flags == null) {
			throw new IllegalArgumentException("unknown flag enum " + name);
		}
		EnumDataType e = new EnumDataType(CATEGORY, name, flags.size(), dtm);
		flags.values().forEach(e::add);
		e.setDescription("Swift runtime flags, from swift " + table.source());
		made.put("enum " + name, e);
		return e;
	}
}
