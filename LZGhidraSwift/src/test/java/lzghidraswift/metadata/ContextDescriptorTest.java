// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class ContextDescriptorTest {

	@Test
	public void initNames() {
		assertEquals("none", ContextDescriptor.initName(ContextDescriptor.INIT_NONE));
		assertEquals("singleton", ContextDescriptor.initName(ContextDescriptor.INIT_SINGLETON));
		assertEquals("foreign", ContextDescriptor.initName(ContextDescriptor.INIT_FOREIGN));
		assertEquals("?", ContextDescriptor.initName(3));
	}

	@Test
	public void initializationIsInBits16And17() {
		assertEquals(ContextDescriptor.INIT_NONE, ContextDescriptor.initialization(0x80000051));
		assertEquals(ContextDescriptor.INIT_SINGLETON,
			ContextDescriptor.initialization(0x00010010));
		assertEquals(ContextDescriptor.INIT_FOREIGN, ContextDescriptor.initialization(0x00020011));
		assertEquals(3, ContextDescriptor.initialization(0x00030011));
	}

	@Test
	public void onlyTypesHaveAnInitialization() {
		assertEquals("foreign", descriptor(0x00020000 | ContextDescriptor.KIND_STRUCT).initName());
		// A module's kind-specific flags are not a metadata initialization.
		assertEquals("none", descriptor(0x00020000 | ContextDescriptor.KIND_MODULE).initName());
	}

	@Test
	public void genericIsBit7() {
		assertTrue(ContextDescriptor.isGeneric(0x80 | ContextDescriptor.KIND_STRUCT));
		assertFalse(ContextDescriptor.isGeneric(0xffffff7f));
		assertTrue(descriptor(0x000100d0).isGeneric());
		assertFalse(descriptor(0x00010050).isGeneric());
	}

	@Test
	public void classConstraintIsBit16OfAProtocol() {
		// ProtocolClassConstraint::Class is 0, Any is 1.
		assertTrue(descriptor(ContextDescriptor.KIND_PROTOCOL).isClassConstrained());
		assertTrue(descriptor(0xfffe0040 | ContextDescriptor.KIND_PROTOCOL).isClassConstrained());
		assertFalse(descriptor(0x00010040 | ContextDescriptor.KIND_PROTOCOL).isClassConstrained());
		// Bit 16 of a class is a metadata initialization bit, not a class constraint.
		assertFalse(descriptor(ContextDescriptor.KIND_CLASS).isClassConstrained());
		assertFalse(descriptor(ContextDescriptor.KIND_MODULE).isClassConstrained());
	}

	@Test
	public void classTableFlagsAreBits29To31() {
		int vtable = 0x80000000 | ContextDescriptor.KIND_CLASS;
		int overrides = 0x40000000 | ContextDescriptor.KIND_CLASS;
		int resilient = 0x20000000 | ContextDescriptor.KIND_CLASS;
		assertTrue(ContextDescriptor.classHasVTable(vtable));
		assertFalse(ContextDescriptor.classHasVTable(overrides | resilient));
		assertTrue(ContextDescriptor.classHasOverrideTable(overrides));
		assertFalse(ContextDescriptor.classHasOverrideTable(vtable | resilient));
		assertTrue(ContextDescriptor.classHasResilientSuperclass(resilient));
		assertFalse(ContextDescriptor.classHasResilientSuperclass(vtable | overrides));
		assertFalse(ContextDescriptor.classHasVTable(0x1fffffff));
		assertFalse(ContextDescriptor.classHasOverrideTable(0x1fffffff));
		assertFalse(ContextDescriptor.classHasResilientSuperclass(0x1fffffff));
	}

	private static ContextDescriptor descriptor(int flags) {
		return new ContextDescriptor(null, flags, null, null, null, null, 0, 0, 0, 0, null);
	}
}
