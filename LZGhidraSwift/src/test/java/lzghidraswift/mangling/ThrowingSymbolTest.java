// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.mangling;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import lzghidraswift.mangling.ThrowingSymbol.Effect;

/**
 * Symbols of the Throws fixture, and of a module Effects built from the declarations in the
 * comments (swiftc 6.4, arm64, -O, -enable-library-evolution for the dispatch thunks). Each
 * expected effect is what {@code swift-demangle --tree-only} shows for the symbol.
 */
public class ThrowingSymbolTest {

	private static void assertEffect(Effect expected, String symbol) {
		assertEquals(symbol, expected, ThrowingSymbol.classify(symbol));
	}

	@Test
	public void fixtureFunctions() {
		assertEffect(Effect.THROWS, "_$s6Throws8mayThrowyS2iKF");
		assertEffect(Effect.THROWS, "_$s6Throws14mayThrowDoubleyS2dKF");
		assertEffect(Effect.THROWS, "_$s6Throws5checkyySiKF");
		assertEffect(Effect.THROWS, "_$s6Throws9propagateyS2iKF");
		assertEffect(Effect.THROWS, "_$s6Throws6ParserC5parseyS2iKF");
		assertEffect(Effect.TYPED_THROWS, "_$s6Throws10typedThrowyS2iAA10ParseErrorVYKF");
		assertEffect(Effect.NONE, "_$s6Throws12callThrowingyS2iF");
		assertEffect(Effect.NONE, "_$s6Throws10callMethodySiAA6ParserC_SitF");
		assertEffect(Effect.NONE, "$s6Throws6ParserC5limitACSi_tcfC");
	}

	/** {@code callClosure(_ f: (Int) throws -> Int, _ x: Int) -> Int}: K in a parameter. */
	@Test
	public void throwingClosureParameter() {
		assertEffect(Effect.NONE, "_$s6Throws11callClosureyS3iKXE_SitF");
		// func returnsThrowingClosure() -> (Int) throws -> Int
		assertEffect(Effect.NONE, "_$s7Effects22returnsThrowingClosureS2iKcyF");
	}

	@Test
	public void notFunctions() {
		assertNull(ThrowingSymbol.classify("_$s6Throws6ParserC5limitSivg"));
		assertNull(ThrowingSymbol.classify("_$s6Throws6ParserCMa"));
		assertNull(ThrowingSymbol.classify("_$s6Throws6ParserCfD"));
		assertNull(ThrowingSymbol.classify("_swift_errorRelease"));
		assertNull(ThrowingSymbol.classify("mayThrow"));
		// Method descriptor (data) of a throwing method.
		assertNull(ThrowingSymbol.classify("_$s7Effects4BaseC6methodyS2iKFTq"));
		// An Objective-C thunk reports errors through NSError **, not the error register.
		assertNull(ThrowingSymbol.classify("_$s7Effects4BaseC6methodyS2iKFTo"));
	}

	/**
	 * {@code func genericThrow<T: Equatable>(_ a: T, _ b: T) throws -> T},
	 * {@code func takesThrowingClosureAndThrows<T>(_ f: () throws -> T) throws -> T},
	 * {@code func takesThrowingClosure<T>(_ f: () throws -> T) -> T?},
	 * {@code func genericBidi<C: BidirectionalCollection>(_ c: C) -> C.Element?},
	 * {@code func mapKeys<K: Hashable>(_ f: (T) throws -> K) rethrows -> [K]} in {@code Box<T>}.
	 */
	@Test
	public void generic() {
		assertEffect(Effect.THROWS, "_$s7Effects12genericThrowyxx_xtKSQRzlF");
		assertEffect(Effect.THROWS, "_$s7Effects29takesThrowingClosureAndThrowsyxxyKXEKlF");
		assertEffect(Effect.NONE, "_$s7Effects20takesThrowingClosureyxSgxyKXElF");
		// SK (Swift.BidirectionalCollection) is not a throws.
		assertEffect(Effect.NONE, "_$s7Effects11genericBidiy7ElementQzSgxSKRzlF");
		assertEffect(Effect.THROWS, "_$s7Effects3BoxV7mapKeysySayqd__Gqd__xKXEKSHRd__lF");
	}

	/**
	 * {@code init(value: T) throws} and
	 * {@code init<C: Collection>(first c: C) throws where C.Element == T} in {@code Box<T>},
	 * {@code static func make(_ v: T) throws -> Box<T>}, {@code class func classMethod() throws}.
	 */
	@Test
	public void initializersAndStatic() {
		assertEffect(Effect.THROWS, "_$s7Effects3BoxV5valueACyxGx_tKcfC");
		assertEffect(Effect.THROWS,
			"_$s7Effects3BoxV5firstACyxGqd___tKc7ElementQyd__RszSlRd__lufC");
		assertEffect(Effect.NONE, "_$s7Effects3KeyV1kACSi_tcfC");
		assertEffect(Effect.THROWS, "_$s7Effects3BoxV4makeyACyxGxKFZ");
		assertEffect(Effect.THROWS, "_$s7Effects4BaseC11classMethodyyKFZ");
		assertEffect(Effect.NONE, "_$s7Effects1EO2eeoiySbAC_ACtFZ");
	}

	/** Dispatch thunks of {@code open func method(_ x: Int) throws -> Int} and others. */
	@Test
	public void dispatchThunks() {
		assertEffect(Effect.THROWS, "_$s7Effects4BaseC6methodyS2iKFTj");
		assertEffect(Effect.THROWS, "_$s7Effects4BaseC11classMethodyyKFZTj");
		assertEffect(Effect.THROWS, "_$s7Effects11KeyProviderP08providedB0AA0B0VyKFTj");
		assertEffect(Effect.NONE, "_$s7Effects4BaseC11methodPlainyS2iFTj");
		assertNull(ThrowingSymbol.classify("_$s7Effects4BaseC5valueSivgTj"));
	}

	/**
	 * Local symbols of the Throws fixture and of a module Local (-O): the specialized copies that
	 * the callers call.
	 */
	@Test
	public void specializations() {
		// firstMatch<Int>
		assertEffect(Effect.THROWS, "_$s6Throws10firstMatchySiSayxG_xtKSQRzlFSi_Tg5");
		// Function signature specializations of Config.init(size:) and static Config.standard.
		assertEffect(Effect.THROWS, "_$s6Throws6ConfigV4sizeACSi_tKcfCTf4nd_n");
		assertEffect(Effect.THROWS, "_$s6Throws6ConfigV8standardyACSiKFZTf4nd_n");
		assertEffect(Effect.NONE, "_$s7Strings10AccidentalO8rawValueACSgSS_tcfCTf4nd_n");
		assertEffect(Effect.NONE, "_$s5Local8genPlainySiSayxG_xtSQRzlFSi_Tg5");
		// applyThrowing(_:_:) specialized for the closure in useClosure: the closure's name
		// follows the global and ends with an entity of its own.
		assertEffect(Effect.THROWS,
			"_$s5Local13applyThrowingyS3iKXE_SitKF34$s5Local10useClosureyS2iFS2iKXEfU_Tf1cn_n");
		// A merged copy (hand-made).
		assertEffect(Effect.THROWS, "_$s6Throws8mayThrowyS2iKFTm");
	}

	/**
	 * {@code func outer(_:) throws -> Int} with a local {@code func inner(_:) throws -> Int}; the
	 * other two symbols are hand-made (checked with swift-demangle).
	 */
	@Test
	public void localFunction() {
		assertEffect(Effect.THROWS, "_$s5Local5outeryS2iKF5innerL_yS2iKF");
		assertEffect(Effect.NONE, "_$s5Local5outeryS2iKF10innerPlainL_yS2iF");
		// Specialization of the local function, not of outer.
		assertEffect(Effect.THROWS, "_$s5Local5outeryS2iKF5innerL_yS2iKFTf4n_n");
	}

	/** {@code func keyKeyKeyLookupKey(_ keyKey: Key) throws -> Key}: K as a word reference. */
	@Test
	public void wordSubstitutions() {
		assertEffect(Effect.THROWS, "_$s7Effects06keyKeyc6LookupC0yAA0C0VADKF");
		List<String> tokens = ThrowingSymbol.tokens("7Effects06keyKeyc6LookupC0yAA0C0VADK");
		assertEquals(List.of("7Effects", "06keyKeyc6LookupC0", "y", "AA", "0C0", "V", "AD", "K"),
			tokens);
		// Word references in a generic requirement: 0a7MutableK0 is one identifier.
		assertEquals(List.of("AA", "0a7MutableK0", "Rd_0_", "l"),
			ThrowingSymbol.tokens("AA0a7MutableK0Rd_0_l"));
	}

	@Test
	public void asyncAndTyped() {
		assertEffect(Effect.ASYNC_THROWS, "_$s7Effects10asyncThrowyS2iYaKF");
		assertEffect(Effect.NONE, "_$s7Effects10asyncPlainyS2iYaF");
		assertEffect(Effect.TYPED_THROWS, "_$s7Effects5typedyS2iAA1EOYKF");
		assertEffect(Effect.ASYNC_TYPED_THROWS, "_$s7Effects10asyncTypedyS2iYaAA1EOYKF");
		// @MainActor func mainActorThrows() throws: isolation is not in the mangling.
		assertEffect(Effect.THROWS, "_$s7Effects15mainActorThrowsyyKF");
	}

	/** Hand-made: a global actor after a typed throws in a parameter's function type. */
	@Test
	public void globalActorAfterThrows() {
		// M.f<A where A: N.P>(@Swift.MainActor (A) throws(A.Failure) -> ()) -> (): the YK is
		// inside a parameter, followed by ScM Yc and the c of the function type.
		assertEffect(Effect.NONE, "$s1M1fyyyx7FailureQzYKScMYcc1N1PRzlF");
		// M.f<A>(@Swift.MainActor (A) throws(A) -> ()) -> ()
		assertEffect(Effect.NONE, "$s1M1fyyyxxYKScMYcclF");
	}
}
