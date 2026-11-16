// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.mangling;

import static org.junit.Assert.*;

import java.util.Set;

import org.junit.Test;

import lzghidraswift.mangling.SwiftSymbol.Kind;
import lzghidraswift.mangling.SwiftSymbol.Member;

/** Symbols from the Methods fixture (swiftc 6.4, arm64, -O). */
public class SwiftSymbolTest {

	private static final Set<String> TYPES = Set.of("7Methods5GaugeV", "7Methods5PhaseO",
		"7Methods6EngineC", "7Methods11TurboEngineC", "7Methods6SensorC");

	private static Member classify(String symbol) {
		return SwiftSymbol.classify(symbol, TYPES::contains);
	}

	private static void assertMember(String symbol, String context, Kind kind, String name) {
		Member m = classify(symbol);
		assertNotNull(symbol, m);
		assertEquals(symbol, context, m.context());
		assertEquals(symbol, kind, m.kind());
		assertEquals(symbol, name, m.name());
	}

	@Test
	public void methods() {
		assertMember("_$s7Methods5GaugeV5raise2byySi_tF", "7Methods5GaugeV", Kind.METHOD, "raise");
		assertMember("_$s7Methods5GaugeV7rescaleyySdF", "7Methods5GaugeV", Kind.METHOD, "rescale");
		assertMember("_$s7Methods5GaugeV6scaledSdyF", "7Methods5GaugeV", Kind.METHOD, "scaled");
		assertMember("_$s7Methods5PhaseO7advanceyyF", "7Methods5PhaseO", Kind.METHOD, "advance");
		assertMember("_$s7Methods5PhaseO4hash4intoys6HasherVz_tF", "7Methods5PhaseO", Kind.METHOD,
			"hash");
		assertMember("_$s7Methods6EngineC10accelerateyySdF", "7Methods6EngineC", Kind.METHOD,
			"accelerate");
		assertMember("_$s7Methods11TurboEngineC5spoolyySiF", "7Methods11TurboEngineC", Kind.METHOD,
			"spool");
		assertMember("$s7Methods6SensorC6recordyySfF", "7Methods6SensorC", Kind.METHOD, "record");
	}

	@Test
	public void accessors() {
		assertMember("_$s7Methods5GaugeV7doubledSivs", "7Methods5GaugeV", Kind.ACCESSOR, "doubled");
		assertMember("_$s7Methods5GaugeV5limits5Int32VvM", "7Methods5GaugeV", Kind.ACCESSOR,
			"limit");
		assertMember("_$s7Methods6EngineC5gaugeAA5GaugeVvg", "7Methods6EngineC", Kind.ACCESSOR,
			"gauge");
		assertMember("_$s7Methods5PhaseO9hashValueSivg", "7Methods5PhaseO", Kind.ACCESSOR,
			"hashValue");
	}

	@Test
	public void initializersAndDeinitializers() {
		assertMember("_$s7Methods6EngineCACycfc", "7Methods6EngineC", Kind.INITIALIZER, null);
		assertMember("_$s7Methods6EngineCfd", "7Methods6EngineC", Kind.DEINITIALIZER, null);
		assertMember("_$s7Methods11TurboEngineCfD", "7Methods11TurboEngineC", Kind.DEINITIALIZER,
			null);
		// Allocating init: x20 holds the metatype, the class's metadata.
		assertMember("_$s7Methods6EngineCACycfC", "7Methods6EngineC", Kind.ALLOCATOR, null);
	}

	/**
	 * The initializer of a generic class (Runtime fixture): the parser does not read the generic
	 * parameter x in its signature, the allocator is taken by its context. Its initializing
	 * initializer is not.
	 */
	@Test
	public void allocatorOfAGenericClass() {
		Member m = SwiftSymbol.classify("_$s7Runtime3BoxCyACyxGxcfC", "7Runtime3BoxC"::equals);
		assertNotNull(m);
		assertEquals("7Runtime3BoxC", m.context());
		assertEquals(Kind.ALLOCATOR, m.kind());
		assertNull(SwiftSymbol.classify("_$s7Runtime3BoxCyACyxGxcfc", "7Runtime3BoxC"::equals));
	}

	@Test
	public void rejected() {
		for (String symbol : new String[] {
			"_$s7Methods5GaugeV4make5levelACSi_tFZ", // static
			"_$s7Methods5GaugeV5levelSivM.resume.0", // coroutine continuation
			"_$s7Methods5GaugeV5levelSivpfi", // initial value expression
			"_$s7Methods5PhaseO8allCasesSayACGvgZ", // static getter
			"_$s7Methods5PhaseOSHAASH9hashValueSivgTW", // protocol witness thunk
			"_$s7Methods5GaugeVMa", // metadata accessor
			"_$s7Methods5GaugeVwst", // value witness
			"_$s7Methods5GaugeV4moveyyFyycfU_", // closure in a method
			"_$s7Methods5GaugeV4moveyyF5innerL_yyF", // local function in a method
			"_$s7Methods5OtherV4moveyyF", // a type not of interest
			"_$s7Methods5GaugeV5InnerV4moveyyF", // a member of a nested type not of interest
			"_objc_msgSend", "$s", }) {
			assertNull(symbol, classify(symbol));
		}
	}
}
