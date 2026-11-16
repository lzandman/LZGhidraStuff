// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.runtime;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import lzghidraswift.runtime.RuntimePrototypes.Decision;
import lzghidraswift.runtime.RuntimeTable.Entry;

public class RuntimePrototypesTest {

	private static Entry entry(String module, String convention) {
		return new Entry("f", module, convention, List.of("VoidTy"), Set.of(), List.of());
	}

	@Test
	public void runtimeNames() {
		assertTrue(RuntimePrototypes.isRuntimeName(List.of("_swift_getAtKeyPath")));
		assertTrue(RuntimePrototypes.isRuntimeName(List.of("x", "swift_stdlib_random")));
		assertFalse(RuntimePrototypes.isRuntimeName(List.of("_objc_retain", "_malloc")));
		assertFalse(RuntimePrototypes.isRuntimeName(List.of("$s4main3FooCMa")));
	}

	@Test
	public void skipRules() {
		Entry c = entry("Swift", RuntimePrototypes.C_CC);
		assertEquals(Decision.APPLY, RuntimePrototypes.decide(c, SourceType.DEFAULT, "unknown"));
		assertEquals(Decision.APPLY,
			RuntimePrototypes.decide(c, SourceType.ANALYSIS, "__swift_stdcall"));
		assertEquals(Decision.APPLY, RuntimePrototypes.decide(c, SourceType.DEFAULT, null));
		assertEquals(Decision.USER_DEFINED,
			RuntimePrototypes.decide(c, SourceType.USER_DEFINED, "default"));
		assertEquals(Decision.IMPORTED,
			RuntimePrototypes.decide(c, SourceType.IMPORTED, "unknown"));
		assertEquals(Decision.IMPORTED, RuntimePrototypes.decide(c, SourceType.AI, "unknown"));
		assertEquals(Decision.THROWING_VARIANT,
			RuntimePrototypes.decide(c, SourceType.ANALYSIS, "__swift_stdcall_throws"));
		assertEquals(Decision.THROWING_VARIANT,
			RuntimePrototypes.decide(c, SourceType.DEFAULT, "__swift_stdcall_indirect_throws"));

		assertEquals(Decision.APPLY,
			RuntimePrototypes.decide(entry("_Concurrency", RuntimePrototypes.SWIFT_CC),
				SourceType.DEFAULT, "unknown"));
		assertEquals(Decision.OTHER_MODULE,
			RuntimePrototypes.decide(entry("objc2", RuntimePrototypes.C_CC),
				SourceType.DEFAULT, "unknown"));
		assertEquals(Decision.OTHER_MODULE,
			RuntimePrototypes.decide(entry("c", RuntimePrototypes.C_CC),
				SourceType.USER_DEFINED, "unknown"));
		assertEquals(Decision.ASYNC,
			RuntimePrototypes.decide(entry("_Concurrency", RuntimePrototypes.SWIFT_ASYNC_CC),
				SourceType.USER_DEFINED, "unknown"));
		assertEquals(Decision.PRESERVE_MOST,
			RuntimePrototypes.decide(entry("Swift", RuntimePrototypes.SWIFT_DIRECT_RR_CC),
				SourceType.DEFAULT, "unknown"));
		Entry mixed = new Entry("f", "Swift", RuntimePrototypes.SWIFT_CC, List.of("VoidTy"),
			Set.of(RuntimeTable.SWIFT_REGISTER_PARAMS), List.of());
		assertEquals(Decision.SWIFT_REGISTERS,
			RuntimePrototypes.decide(mixed, SourceType.DEFAULT, "unknown"));
		Entry willThrow = new Entry("swift_willThrow", "Swift", RuntimePrototypes.SWIFT_CC,
			List.of("VoidTy"),
			Set.of(RuntimeTable.SWIFT_REGISTER_PARAMS, RuntimeTable.SWIFT_REGISTERS_ONLY),
			List.of());
		assertEquals(Decision.APPLY,
			RuntimePrototypes.decide(willThrow, SourceType.DEFAULT, "unknown"));
		assertEquals(Decision.USER_DEFINED,
			RuntimePrototypes.decide(willThrow, SourceType.USER_DEFINED, "unknown"));
	}

	@Test
	public void withoutParamsOnlyForSwiftccWithEveryParamInSwiftRegisters() {
		Set<String> only =
			Set.of(RuntimeTable.SWIFT_REGISTER_PARAMS, RuntimeTable.SWIFT_REGISTERS_ONLY);
		assertTrue(RuntimePrototypes.withoutParams(new Entry("swift_willThrow", "Swift",
			RuntimePrototypes.SWIFT_CC, List.of("VoidTy"), only, List.of())));
		assertFalse(RuntimePrototypes.withoutParams(new Entry("f", "_Concurrency",
			RuntimePrototypes.SWIFT_ASYNC_CC, List.of("VoidTy"), only, List.of())));
		assertFalse(RuntimePrototypes.withoutParams(new Entry("f", "Swift",
			RuntimePrototypes.SWIFT_CC, List.of("VoidTy"),
			Set.of(RuntimeTable.SWIFT_REGISTER_PARAMS), List.of())));
		assertFalse(
			RuntimePrototypes.withoutParams(entry("Swift", RuntimePrototypes.SWIFT_CC)));
	}

	@Test
	public void conventions() {
		String def = Function.DEFAULT_CALLING_CONVENTION_STRING;
		assertEquals(def, RuntimePrototypes.convention(RuntimePrototypes.C_CC, "__swift_stdcall"));
		assertEquals(def, RuntimePrototypes.convention(RuntimePrototypes.C_CC, null));
		assertEquals("__swift_stdcall",
			RuntimePrototypes.convention(RuntimePrototypes.SWIFT_CC, "__swift_stdcall"));
		assertEquals(def, RuntimePrototypes.convention(RuntimePrototypes.SWIFT_CC, null));
		assertThrows(IllegalArgumentException.class,
			() -> RuntimePrototypes.convention(RuntimePrototypes.SWIFT_ASYNC_CC,
				"__swift_stdcall"));
	}

	/**
	 * The decisions on every entry of the committed table, for a function nobody typed: the
	 * {@code Swift} and {@code _Concurrency} entries apply, except the 4 async and the 4
	 * {@code PreserveMost} ones. Of the two with Swift register parameters,
	 * {@code swift_willThrow} applies without parameters and {@code swift_asyncLet_finish} is
	 * async. Update the counts when the table is regenerated.
	 */
	@Test
	public void decisionsOnTheTable() throws IOException {
		Map<Decision, Integer> counts = new EnumMap<>(Decision.class);
		for (Entry e : RuntimeTableTest.committed().functions().values()) {
			Decision d = RuntimePrototypes.decide(e, SourceType.DEFAULT, "unknown");
			counts.merge(d, 1, Integer::sum);
			if (d == Decision.APPLY) {
				// Every entry that applies has a convention that maps.
				assertNotNull(RuntimePrototypes.convention(e.convention(), null));
			}
		}
		assertEquals(Map.of(Decision.APPLY, 314, Decision.OTHER_MODULE, 33, Decision.ASYNC, 4,
			Decision.PRESERVE_MOST, 4), counts);
		assertTrue(RuntimePrototypes
				.withoutParams(RuntimeTableTest.committed().get("swift_willThrow")));
	}
}
