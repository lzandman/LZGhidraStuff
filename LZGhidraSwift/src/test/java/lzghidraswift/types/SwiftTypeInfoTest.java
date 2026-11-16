// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.types;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import lzghidraswift.metadata.ContextDescriptor;

/** The details of {@code SWIFTTYPE} lines, for types modelled on the Layouts fixture (arm64). */
public class SwiftTypeInfoTest {

	private static final AddressSpace RAM =
		new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 1);

	private static Address at(long offset) {
		return RAM.getAddress(offset);
	}

	private static SwiftTypeInfo info(ContextDescriptor d, String name, Address metadata,
			SwiftLayout layout, String noLayout) {
		return new SwiftTypeInfo(d, name, metadata, layout, noLayout, new ArrayList<>());
	}

	private static ContextDescriptor descriptor(long address, int flags, long accessor,
			int numFields, int vectorOffset, int payloadCases, int emptyCases, Address superclass) {
		return new ContextDescriptor(at(address), flags, null, null, at(accessor), null, numFields,
			vectorOffset, payloadCases, emptyCases, superclass);
	}

	@Test
	public void classWithSuperclass() {
		ContextDescriptor d = descriptor(0x7a90, ContextDescriptor.KIND_CLASS, 0x49e4, 2, 23, 0,
			0, at(0x7aa4));
		SwiftTypeInfo info = info(d, "Layouts.LeafNode", at(0x10928),
			new SwiftLayout(57, -1, 8, -1, List.of(16L, 48L), null), null);
		assertEquals(
			("descriptor=%s class Layouts.LeafNode init=none accessor=%s numFields=2 " +
				"fieldOffsetVectorOffset=23 superclass=<Layouts.Node> metadata=%s size=57 align=8")
						.formatted(at(0x7a90), at(0x49e4), at(0x10928)),
			info.describe("<Layouts.Node>"));
		// An unreadable superclass is rendered "?" by the caller; without one there is none.
		assertTrue(info.describe("?").contains(" superclass=? metadata="));
		assertFalse(info.describe(null).contains("superclass"));
	}

	@Test
	public void structWithWitnessesAndGenericWithoutLayout() {
		ContextDescriptor empty =
			descriptor(0x7bec, ContextDescriptor.KIND_STRUCT, 0x5898, 0, 2, 0, 0, null);
		SwiftTypeInfo info = info(empty, "Layouts.Empty", at(0xc7c0),
			new SwiftLayout(0, 1, 1, 0, List.of(), "$sytWV"), null);
		assertEquals(
			("descriptor=%s struct Layouts.Empty init=none accessor=%s numFields=0 " +
				"fieldOffsetVectorOffset=2 metadata=%s size=0 stride=1 align=1 witnesses=$sytWV")
						.formatted(at(0x7bec), at(0x5898), at(0xc7c0)),
			info.describe(null));

		ContextDescriptor box =
			descriptor(0x7d88, ContextDescriptor.KIND_STRUCT | 0x80, 0x41e0, 2, 3, 0, 0, null);
		assertEquals(
			("descriptor=%s struct Layouts.Box generic init=none accessor=%s numFields=2 " +
				"fieldOffsetVectorOffset=3 layout=none: generic").formatted(at(0x7d88),
					at(0x41e0)),
			info(box, "Layouts.Box", null, null, "generic").describe(null));
	}

	@Test
	public void enumWithPayloadIsSkipped() {
		ContextDescriptor d = descriptor(0x7db8, ContextDescriptor.KIND_ENUM | 1 << 16, 0x698c,
			0, 0, 2, 1, null);
		SwiftTypeInfo info = info(d, "Layouts.Measurement", at(0xcba0),
			new SwiftLayout(17, 24, 8, 253, List.of(), null), null);
		assertEquals(
			("descriptor=%s enum Layouts.Measurement init=singleton accessor=%s payloadCases=2 " +
				"emptyCases=1 metadata=%s size=17 stride=24 align=8 skip=enum with payload")
						.formatted(at(0x7db8), at(0x698c), at(0xcba0)),
			info.describe(null));
	}
}
