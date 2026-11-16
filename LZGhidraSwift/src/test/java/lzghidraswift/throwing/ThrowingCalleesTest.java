// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.throwing;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import lzghidraswift.mangling.ThrowingSymbol.Effect;
import lzghidraswift.throwing.ThrowingCallees.Check;
import lzghidraswift.throwing.ThrowingCallees.Decision;

/** {@link ThrowingCallees}, with symbols of the Throws and Effects fixtures. */
public class ThrowingCalleesTest {

	private static final String THROWS = "_$s6Throws8mayThrowyS2iKF";
	private static final String TYPED = "_$s6Throws10typedThrowyS2iAA10ParseErrorVYKF";
	private static final String ASYNC = "_$s7Effects10asyncThrowyS2iYaKF";
	private static final String ASYNC_TYPED = "_$s7Effects10asyncTypedyS2iYaAA1EOYKF";
	private static final String PLAIN = "_$s6Throws12callThrowingyS2iF";
	private static final String DEMANGLED = "Throws.mayThrow(Swift.Int) throws -> Swift.Int";

	@Test
	public void check() {
		// The demangler keeps the mangled name as a second label.
		assertEquals(Check.THROWS, ThrowingCallees.check(List.of(DEMANGLED, THROWS)));
		assertEquals(Check.TYPED_THROWS, ThrowingCallees.check(List.of(TYPED)));
		assertEquals(Check.ASYNC, ThrowingCallees.check(List.of(ASYNC)));
		assertEquals(Check.ASYNC, ThrowingCallees.check(List.of(ASYNC_TYPED)));
		assertEquals(Check.NONE, ThrowingCallees.check(List.of(PLAIN)));
		assertEquals(Check.NONE, ThrowingCallees.check(List.of("_swift_beginAccess")));
		assertEquals(Check.NONE, ThrowingCallees.check(List.of()));
	}

	/** Throws before typed throws before async, whatever the order of the names. */
	@Test
	public void checkPrecedence() {
		assertEquals(Check.THROWS, ThrowingCallees.check(List.of(TYPED, THROWS)));
		assertEquals(Check.TYPED_THROWS, ThrowingCallees.check(List.of(ASYNC, TYPED)));
		assertEquals(Check.ASYNC, ThrowingCallees.check(List.of(PLAIN, ASYNC)));
	}

	@Test
	public void isThrowing() {
		assertTrue(Check.THROWS.isThrowing());
		assertTrue(Check.TYPED_THROWS.isThrowing());
		assertFalse(Check.ASYNC.isThrowing());
		assertFalse(Check.NONE.isThrowing());
	}

	/** The first Swift function symbol counts, not the strongest. */
	@Test
	public void firstEffect() {
		assertEquals(Effect.NONE, ThrowingCallees.firstEffect(List.of(DEMANGLED, PLAIN, THROWS)));
		assertEquals(Effect.THROWS, ThrowingCallees.firstEffect(List.of(THROWS, PLAIN)));
		assertNull(ThrowingCallees.firstEffect(List.of("_swift_beginAccess")));
		assertNull(ThrowingCallees.firstEffect(List.of()));
	}

	@Test
	public void decide() {
		assertEquals(Decision.INDIRECT, decide(true, false, false, false, false, null));
		assertEquals(Decision.NO_FUNCTION, decide(false, false, false, false, false, null));
		assertEquals(Decision.BY_SYMBOL, decide(false, true, true, false, false, Effect.THROWS));
		// No Swift symbol: found from its callers, unless it is an external.
		assertEquals(Decision.FOUND, decide(false, true, false, false, false, null));
		assertEquals(Decision.NOT_SWIFT, decide(false, true, false, false, true, null));
		// A throwing symbol outside the analyzed set.
		assertEquals(Decision.FOUND, decide(false, true, false, false, true, Effect.THROWS));
		assertEquals(Decision.FOUND, decide(false, true, false, false, false, Effect.TYPED_THROWS));
		assertEquals(Decision.CONTRADICTION, decide(false, true, false, false, false, Effect.NONE));
		assertEquals(Decision.ASYNC, decide(false, true, false, false, false, Effect.ASYNC_THROWS));
		assertEquals(Decision.ASYNC,
			decide(false, true, false, false, true, Effect.ASYNC_TYPED_THROWS));
	}

	/** A callee found from an earlier call stays found; its effect is not looked at again. */
	@Test
	public void decideFoundBefore() {
		assertEquals(Decision.FOUND, decide(false, true, false, true, true, null));
		assertEquals(Decision.FOUND, decide(false, true, false, true, false, Effect.NONE));
	}

	private static Decision decide(boolean indirect, boolean hasFunction, boolean bySymbol,
			boolean found, boolean external, Effect effect) {
		return ThrowingCallees.decide(indirect, hasFunction, bySymbol, found, external, effect);
	}
}
