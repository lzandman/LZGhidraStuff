// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.runtime;

import static org.junit.Assert.*;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.junit.BeforeClass;
import org.junit.Test;

import ghidra.program.model.data.DataOrganizationImpl;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.lang.Language;

/** {@link RuntimeTypes} on every entry of the committed data file, with 64-bit pointers. */
public class RuntimeTypesTest {

	private static RuntimeTable table;
	private static RuntimeTypes types;

	@BeforeClass
	public static void loadTable() throws IOException {
		table = RuntimeTableTest.committed();
		types = new RuntimeTypes(dataTypeManager(), table);
	}

	/**
	 * A stand-in for a 64-bit program's data type manager, which answers only
	 * {@code getDataOrganization} and fails on any other method. A real one
	 * ({@code StandAloneDataTypeManager}) needs an initialized Ghidra application.
	 */
	private static DataTypeManager dataTypeManager() {
		DataOrganizationImpl org = DataOrganizationImpl.getDefaultOrganization((Language) null);
		org.setPointerSize(8);
		org.setLongSize(8);
		return (DataTypeManager) Proxy.newProxyInstance(
			Thread.currentThread().getContextClassLoader(),
			new Class<?>[] { DataTypeManager.class },
			(proxy, method, args) -> {
				if (!method.getName().equals("getDataOrganization")) {
					throw new UnsupportedOperationException(method.getName());
				}
				return org;
			});
	}

	/** Every return and parameter type of the data file maps; a new IRGen name fails here. */
	@Test
	public void everyNameMaps() {
		List<String> unknown = new ArrayList<>();
		for (RuntimeTable.Entry e : table.functions().values()) {
			try {
				types.returnType(e);
			}
			catch (IllegalArgumentException x) {
				unknown.add(e.name() + " returns: " + x.getMessage());
			}
			for (RuntimeTable.Param p : e.params()) {
				try {
					types.paramType(p);
				}
				catch (IllegalArgumentException x) {
					unknown.add(e.name() + " " + p.name() + ": " + x.getMessage());
				}
			}
		}
		assertEquals(List.of(), unknown);
	}

	@Test
	public void opaquePointers() {
		assertPointerTo("HeapObject", types.type("RefCountedPtrTy"));
		assertPointerTo("Metadata", types.type("TypeMetadataPtrTy"));
		assertPointerTo("OpaqueValue", types.type("OpaquePtrTy"));
		assertSame(types.type("TypeMetadataPtrTy"), types.type("TypeMetadataPtrTy"));
		// Both async context names point to the same structure.
		assertSame(((Pointer) types.type("SwiftContextPtrTy")).getDataType(),
			((Pointer) types.type("ContinuationAsyncContextPtrTy")).getDataType());
		Pointer pp = (Pointer) types.type("TypeMetadataPtrPtrTy");
		assertSame(types.type("TypeMetadataPtrTy"), pp.getDataType());
		assertEquals("void *", types.type("Int8PtrTy").getDisplayName());
		assertEquals(8, types.type("Int8PtrTy").getLength());
	}

	@Test
	public void integers() {
		assertTypedef("size_t", 8, types.type("SizeTy"));
		assertSame(types.type("SizeTy"), types.type("ExecutorFirstTy"));
		assertTypedef("int32_t", 4, types.type("Int32Ty"));
		assertTypedef("int64_t", 8, types.type("Int64Ty"));
		assertEquals("bool", types.type("Int1Ty").getName());
		assertEquals("void", types.type("VoidTy").getName());
		assertEquals("double", types.type("DoubleTy").getName());
	}

	/** Two-register returns are 16-byte structures with the runtime's field names. */
	@Test
	public void pairs() {
		Structure box = (Structure) types.returnType(table.get("swift_allocBox"));
		assertEquals("BoxPair", box.getName());
		assertEquals(RuntimeTypes.CATEGORY, box.getCategoryPath());
		assertFields(box, "object", "HeapObject *", "buffer", "OpaqueValue *");

		Structure error = (Structure) types.returnType(table.get("swift_allocError"));
		assertFields(error, "object", "SwiftError *", "buffer", "OpaqueValue *");

		Structure response = (Structure) types.returnType(table.get("swift_getGenericMetadata"));
		assertEquals("MetadataResponse", response.getName());
		assertFields(response, "value", "Metadata *", "state", "size_t");

		assertEquals("MetadataDependency",
			types.returnType(table.get("swift_initClassMetadata2")).getName());
		assertEquals("SerialExecutorRef",
			types.returnType(table.get("swift_task_getCurrentExecutor")).getName());
		assertEquals("AsyncTaskAndContext",
			types.returnType(table.get("swift_task_create")).getName());

		try {
			types.type("RefCountedPtrTy,SizeTy");
			fail("an unknown pair maps");
		}
		catch (IllegalArgumentException e) {
			assertEquals("unknown IRGen type RefCountedPtrTy,SizeTy", e.getMessage());
		}
	}

	@Test
	public void flagEnums() {
		RuntimeTable.Param flags = table.get("swift_beginAccess").params().get(2);
		Enum e = (Enum) types.paramType(flags);
		assertEquals("ExclusivityFlags", e.getName());
		assertEquals(RuntimeTypes.CATEGORY, e.getCategoryPath());
		assertEquals(8, e.getLength());
		assertEquals(List.of("Read", "Modify", "Tracking"), List.of(e.getNames()));
		assertEquals(0x20, e.getValue("Tracking"));
		assertSame(e, types.flagEnum("ExclusivityFlags"));
		assertEquals(1, types.flagEnum("ProtocolClassConstraint").getLength());
		assertTrue(e.getDescription().contains(table.source()));
	}

	/** Header pointees: the known structures, with the metadata kinds as Metadata. */
	@Test
	public void headerPointees() {
		RuntimeTable.Param buffer = table.get("swift_beginAccess").params().get(1);
		DataType t = types.paramType(buffer);
		assertEquals("ValueBuffer *", t.getDisplayName());
		Structure vb = (Structure) ((Pointer) t).getDataType();
		assertEquals(24, vb.getLength());
		assertEquals("privateData", vb.getComponent(0).getFieldName());
		assertEquals("void *[3]", vb.getComponent(0).getDataType().getDisplayName());
		assertSame(t, types.paramType(table.get("swift_endAccess").params().get(0)));

		assertEquals("Metadata *",
			types.paramType(new RuntimeTable.Param("c", "Int8PtrTy", false, "ClassMetadata*"))
					.getDisplayName());
		assertEquals("Metadata * *",
			types.paramType(new RuntimeTable.Param(null, "PtrTy", false, "Metadata**"))
					.getDisplayName());
		assertEquals("SwiftError * *",
			types.paramType(new RuntimeTable.Param(null, "PtrTy", false, "SwiftError**"))
					.getDisplayName());
		// Unknown pointees keep the .def's type.
		assertEquals("void *",
			types.paramType(new RuntimeTable.Param("g", "Int8PtrTy", false, "TaskGroup*"))
					.getDisplayName());
	}

	/**
	 * The pointees of the data file that stay {@code void *}. A name that a new Swift release
	 * adds fails here: decide whether RuntimeTypes should use it, then add it to one list.
	 */
	@Test
	public void pointeesThatStayVoid() {
		Set<String> used = new TreeSet<>();
		Set<String> unused = new TreeSet<>();
		for (RuntimeTable.Entry e : table.functions().values()) {
			for (RuntimeTable.Param p : e.params()) {
				if (p.pointee() != null) {
					String name = p.pointee().replace("*", "");
					(RuntimeTypes.pointeeStructure(name) != null ? used : unused).add(name);
				}
			}
		}
		assertEquals(Set.of("ClassMetadata", "Metadata", "OpaqueValue", "SwiftError",
			"ValueBuffer", "WitnessTable"), used);
		assertEquals(Set.of("CancellationNotificationStatusRecord",
			"EscalationNotificationStatusRecord", "ExtendedExistentialTypeShape",
			"GenericClassMetadataPattern", "GenericValueMetadataPattern", "MethodDescriptor",
			"NonUniqueExtendedExistentialTypeShape", "ProtocolDescriptorRef",
			"ProtocolRequirement", "ResilientClassMetadataPattern", "TaskCancellationScopeRecord",
			"TaskDeadlineStatusRecord", "TaskGroup", "TypeLayout", "_Unwind_Context",
			"_Unwind_Exception", "getExtraInhabitantTag_t", "size_t", "storeExtraInhabitantTag_t",
			"swift_once_t", "uint32_t", "uint8_t"), unused);
	}

	private static void assertPointerTo(String name, DataType t) {
		assertTrue(t.getName(), t instanceof Pointer);
		DataType target = ((Pointer) t).getDataType();
		assertTrue(target instanceof Structure);
		assertEquals(name, target.getName());
		assertEquals(RuntimeTypes.CATEGORY, target.getCategoryPath());
		assertEquals(8, t.getLength());
	}

	private static void assertTypedef(String name, int size, DataType t) {
		assertTrue(t instanceof TypeDef);
		assertEquals(name, t.getName());
		assertEquals(size, t.getLength());
	}

	private static void assertFields(Structure s, String... namesAndTypes) {
		assertEquals(16, s.getLength());
		DataTypeComponent[] c = s.getDefinedComponents();
		assertEquals(2, c.length);
		for (int i = 0; i < 2; i++) {
			assertEquals(namesAndTypes[2 * i], c[i].getFieldName());
			assertEquals(namesAndTypes[2 * i + 1], c[i].getDataType().getDisplayName());
			assertEquals(8 * i, c[i].getOffset());
		}
	}
}
