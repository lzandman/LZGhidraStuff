// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.program.model.data.*;

public class DemanglerStringTypeTest {

	/** The demangler's String: { char *str; void *bridgeObject; }. */
	private static StructureDataType demanglerString() {
		StructureDataType s = new StructureDataType(DemanglerStringType.CATEGORY, "String", 0);
		s.add(new PointerDataType(CharDataType.dataType, 8), 8, "str", null);
		s.add(new PointerDataType(VoidDataType.dataType, 8), 8, "bridgeObject", null);
		return s;
	}

	@Test
	public void word0BecomesAnIntegerWithItsName() {
		StructureDataType s = demanglerString();
		assertTrue(DemanglerStringType.retype(s));
		DataTypeComponent c = s.getComponent(0);
		assertTrue(c.getDataType() instanceof UnsignedLongLongDataType);
		assertEquals("str", c.getFieldName());
		assertEquals(8, c.getLength());
		assertEquals(16, s.getLength());
		assertTrue(s.getComponent(1).getDataType() instanceof Pointer);
		// A second run changes nothing.
		assertFalse(DemanglerStringType.retype(s));
	}

	@Test
	public void otherLayoutsStayAlone() {
		StructureDataType s = new StructureDataType("String", 0);
		s.add(new PointerDataType(CharDataType.dataType, 8), 8, "str", null);
		assertFalse(DemanglerStringType.retype(s));
	}
}
