// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.types;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.mem.MemoryAccessException;
import lzghidraswift.mangling.SwiftSymbol;
import lzghidraswift.metadata.ClassMethods;
import lzghidraswift.metadata.Words;
import lzghidraswift.types.SelfCandidates.Candidate;
import lzghidraswift.types.SelfCandidates.Source;

/** Symbols from the Methods and Runtime fixtures (swiftc 6.4, arm64, -O). */
public class SelfCandidatesTest {

	private static final AddressSpace RAM =
		new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 1);
	private static final Address GAUGE = at(0x1000); // struct, with a data type
	private static final Address PHASE = at(0x1100); // enum, with a data type
	private static final Address ENGINE = at(0x1200); // class, with a data type
	private static final Address BOX = at(0x1300); // generic class, without a data type
	private static final Address F = at(0x8000);

	private static Address at(long offset) {
		return RAM.getAddress(offset);
	}

	private static SelfCandidates candidates() {
		return new SelfCandidates(
			Map.of("7Methods5GaugeV", GAUGE, "7Methods5PhaseO", PHASE, "7Methods6EngineC", ENGINE,
				"7Runtime3BoxC", BOX),
			Set.of(ENGINE, BOX), Set.of(GAUGE, PHASE, ENGINE));
	}

	@Test
	public void valueTypeInitializersAndDeinitializersSkipped() {
		SelfCandidates c = candidates();
		String[] symbols = {
			"_$s7Methods5GaugeV5levelACSi_tcfC", // allocating init
			"_$s7Methods5GaugeV5levelACSi_tcfc", // initializing init
			"_$s7Methods5GaugeVfd", // deinit
			"_$s7Methods5PhaseO8rawValueACSgSi_tcfC", };
		for (String s : symbols) {
			// Members of the types, skipped for being initializers of value types.
			assertNotNull(s,
				SwiftSymbol.classify(s, Set.of("7Methods5GaugeV", "7Methods5PhaseO")::contains));
			assertFalse(s, c.addSymbol(F, s));
		}
		assertTrue(c.candidates().isEmpty());
		assertEquals(0, c.counts().symbols);
	}

	@Test
	public void valueTypeMethodTaken() {
		SelfCandidates c = candidates();
		assertTrue(c.addSymbol(F, "_$s7Methods5GaugeV5raise2byySi_tF"));
		Candidate m = c.candidates().get(F);
		assertEquals(GAUGE, m.type());
		assertEquals(Set.of(Source.SYMBOL), m.sources());
		assertTrue(m.instance());
		assertFalse(m.allocator() || m.getter() || m.conflict());
	}

	@Test
	public void classAllocatorWithoutDataType() {
		SelfCandidates c = candidates();
		assertTrue(c.addSymbol(F, "_$s7Runtime3BoxCyACyxGxcfC"));
		Candidate m = c.candidates().get(F);
		assertEquals(BOX, m.type());
		assertTrue(m.allocator());
		assertFalse(m.instance() || m.conflict());
		assertEquals(1, c.counts().symbols);
		assertEquals(1, c.counts().allocators);
	}

	@Test
	public void otherMembersNeedADataType() {
		SelfCandidates c = candidates();
		assertFalse(c.addSymbol(F, "_$s7Runtime3BoxCyACyxGxcfc")); // not an allocator
		assertTrue(c.addSymbol(at(0x8100), "_$s7Methods6EngineCACycfC"));
		assertTrue(c.addSymbol(at(0x8200), "_$s7Methods6EngineCACycfc"));
		assertTrue(c.addSymbol(at(0x8300), "_$s7Methods6EngineCfd"));
		assertFalse(c.addSymbol(F, "_$s7Methods5GaugeV4make5levelACSi_tFZ")); // static
		assertFalse(c.addSymbol(F, "_swift_retain"));
		assertEquals(3, c.candidates().size());
	}

	@Test
	public void getterFlagged() {
		SelfCandidates c = candidates();
		assertTrue(c.addSymbol(F, "_$s7Methods6EngineC5gaugeAA5GaugeVvg"));
		assertTrue(c.candidates().get(F).getter());
		Address setter = at(0x8100);
		assertTrue(c.addSymbol(setter, "_$s7Methods5GaugeV7doubledSivs"));
		assertFalse(c.candidates().get(setter).getter());
	}

	@Test
	public void allocatorAndInstanceMethodConflict() {
		SelfCandidates c = candidates();
		assertTrue(c.addSymbol(F, "_$s7Methods6EngineCACycfC"));
		assertFalse(c.candidates().get(F).conflict());
		assertTrue(c.addSymbol(F, "_$s7Methods6EngineC10accelerateyySdF"));
		Candidate m = c.candidates().get(F);
		assertTrue(m.allocator() && m.instance() && m.conflict());
		assertEquals(Set.of(ENGINE), m.types());
		assertEquals(List.of("_$s7Methods6EngineCACycfC", "_$s7Methods6EngineC10accelerateyySdF"),
			m.names());
	}

	@Test
	public void twoTypesConflict() {
		SelfCandidates c = candidates();
		assertTrue(c.addSymbol(F, "_$s7Methods5GaugeV5raise2byySi_tF"));
		assertTrue(c.addSymbol(F, "_$s7Methods5PhaseO7advanceyyF"));
		Candidate m = c.candidates().get(F);
		assertTrue(m.conflict());
		assertEquals(List.of(GAUGE, PHASE), List.copyOf(m.types()));
	}

	private static final int HAS_VTABLE = 1 << 31;
	private static final int HAS_OVERRIDES = 1 << 30;

	/**
	 * Engine's method table at 0x1200: an instance method (0x8000), an allocating init (0x8100,
	 * not taken), a removed getter, an override of the instance method (0x8300), an override of a
	 * method of another binary. VTableOffset 10.
	 */
	private static ClassMethods engineTable() {
		Words w = new Words();
		long p = ENGINE.getOffset() + 44;
		w.put(p, 10);
		w.put(p + 4, 3);
		w.put(p + 8, 0x10);
		w.rel(p + 12, 0x8000);
		w.put(p + 16, 0x01);
		w.rel(p + 20, 0x8100);
		w.put(p + 24, 0x12);
		w.put(p + 28, 0);
		w.put(p + 32, 2);
		w.put(p + 36, 0);
		w.rel(p + 40, p + 8);
		w.rel(p + 44, 0x8300);
		w.put(p + 48, 0);
		w.put(p + 52, 0x2001);
		w.rel(p + 56, 0x8400);
		return ClassMethods.read(ENGINE.getOffset(), 16 | HAS_VTABLE | HAS_OVERRIDES, w);
	}

	@Test
	public void methodTable() throws MemoryAccessException {
		SelfCandidates c = candidates();
		Address metadata = at(0x20000);
		// Entry 10 holds the instance method; entry 11 (the init) holds something else.
		Map<Address, Long> vtable = Map.of(metadata.add(80), 0x8000L, metadata.add(88), 0x9999L);
		List<SelfCandidates.VtableMismatch> mismatches =
			c.addClass(ENGINE, "Engine", engineTable(), metadata, a -> {
				Long v = vtable.get(a);
				if (v == null) {
					throw new MemoryAccessException("unmapped " + a);
				}
				return v;
			});
		assertEquals(List.of(new SelfCandidates.VtableMismatch("Engine", 11, metadata.add(88),
			0x9999, at(ENGINE.getOffset() + 44 + 16), 0x8100)), mismatches);
		assertEquals(Set.of(F, at(0x8300)), c.candidates().keySet());
		Candidate method = c.candidates().get(F);
		assertEquals(Set.of(Source.METHOD_TABLE), method.sources());
		assertEquals(List.of("Engine method 0"), method.names());
		assertTrue(method.instance());
		assertEquals(Set.of(Source.OVERRIDE_TABLE), c.candidates().get(at(0x8300)).sources());
		SelfCandidates.Counts n = c.counts();
		assertEquals(1, n.methodTable);
		assertEquals(1, n.overrideTable);
		assertEquals(1, n.overridesUnresolved);
		assertEquals(2, n.vtableChecked);
		assertEquals(1, n.vtableMismatches);
		// The allocator's symbol on the method table's instance method is a conflict.
		assertTrue(c.addSymbol(F, "_$s7Methods6EngineCACycfC"));
		assertTrue(c.candidates().get(F).conflict());
	}

	@Test
	public void unreadableVtableEntryCountedNotReturned() throws MemoryAccessException {
		SelfCandidates c = candidates();
		List<SelfCandidates.VtableMismatch> mismatches =
			c.addClass(ENGINE, "Engine", engineTable(), at(0x20000), a -> {
				throw new MemoryAccessException("unmapped " + a);
			});
		assertTrue(mismatches.isEmpty());
		assertEquals(2, c.counts().vtableMismatches);
	}

	@Test
	public void noMetadataNoVtableCheck() {
		SelfCandidates c = candidates();
		assertTrue(c.addClass(ENGINE, "Engine", engineTable(), null, a -> {
			throw new AssertionError(a);
		}).isEmpty());
		assertEquals(0, c.counts().vtableChecked);
		assertEquals(2, c.candidates().size());
	}

	@Test
	public void summary() {
		SelfCandidates c = candidates();
		c.addSymbol(F, "_$s7Runtime3BoxCyACyxGxcfC");
		assertEquals("candidates: 0 from method tables, 0 from override tables (0 overrides of " +
			"methods of other binaries not used), 1 from symbols (1 allocating initializers, " +
			"self is the metadata); vtables: 0 entries checked, 0 mismatches",
			c.counts().summary());
	}
}
