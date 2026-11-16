// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.throwing;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import lzghidraswift.mangling.ThrowingSymbol;
import lzghidraswift.mangling.ThrowingSymbol.Effect;

/**
 * Which functions get the throwing variant of their calling convention: from the names of their
 * own symbols ({@link #check}), and for the callee of a call after which the caller tests the
 * error register ({@link ErrorTestSites}), from what is known about that call ({@link #decide}).
 * Takes names and facts, not a program, so that unit tests reach it; the analyzer reads them
 * from the program.
 */
public final class ThrowingCallees {

	/** What a function's own symbol names say. */
	public enum Check {
		/** A symbol with {@code throws}. */
		THROWS,
		/** A symbol with {@code throws(E)}, and none with {@code throws}. */
		TYPED_THROWS,
		/** A symbol with {@code async throws} or {@code async throws(E)}, and none that throws. */
		ASYNC,
		/** No symbol of a throwing function. */
		NONE;

		/** Whether the function gets the throwing variant. */
		public boolean isThrowing() {
			return this == THROWS || this == TYPED_THROWS;
		}
	}

	/** What to do with one call after which the caller tests the error register. */
	public enum Decision {
		/** An indirect call (a throwing closure): gets a call-site override. */
		INDIRECT,
		/** No function at the target. */
		NO_FUNCTION,
		/** The callee has a throwing symbol and is in the analyzed set: already taken. */
		BY_SYMBOL,
		/** The callee gets the throwing variant, or already has it from an earlier call. */
		FOUND,
		/**
		 * An external function without a Swift symbol: an imported C or Objective-C function
		 * ({@code swift_beginAccess}) cannot throw a Swift error, so the test after the call is of
		 * something else in the register.
		 */
		NOT_SWIFT,
		/** The callee's own Swift symbol says it does not throw. */
		CONTRADICTION,
		/** The callee's own Swift symbol is async; not handled. */
		ASYNC
	}

	private ThrowingCallees() {
	}

	/** What the names, the symbols of one function, say about it. */
	public static Check check(List<String> names) {
		Set<Effect> effects = effects(names);
		if (effects.contains(Effect.THROWS)) {
			return Check.THROWS;
		}
		if (effects.contains(Effect.TYPED_THROWS)) {
			return Check.TYPED_THROWS;
		}
		if (effects.contains(Effect.ASYNC_THROWS) || effects.contains(Effect.ASYNC_TYPED_THROWS)) {
			return Check.ASYNC;
		}
		return Check.NONE;
	}

	/** The effect of the first name that is a Swift function symbol; null if none is. */
	public static Effect firstEffect(List<String> names) {
		Set<Effect> effects = effects(names);
		return effects.isEmpty() ? null : effects.iterator().next();
	}

	/**
	 * The decision for one call, from the first fact that settles it.
	 *
	 * @param indirect whether the call is indirect
	 * @param hasFunction whether there is a function at the target (after thunks)
	 * @param bySymbol whether the callee has a throwing symbol and is in the analyzed set
	 * @param found whether an earlier call already gave {@link Decision#FOUND} for the callee
	 * @param external whether the callee is an external function
	 * @param effect {@link #firstEffect} of the callee's names; null if it has no Swift function
	 *        symbol. Not used if one of the facts before it settles the decision.
	 */
	public static Decision decide(boolean indirect, boolean hasFunction, boolean bySymbol,
			boolean found, boolean external, Effect effect) {
		if (indirect) {
			return Decision.INDIRECT;
		}
		if (!hasFunction) {
			return Decision.NO_FUNCTION;
		}
		if (bySymbol) {
			return Decision.BY_SYMBOL;
		}
		if (found) {
			return Decision.FOUND;
		}
		if (effect == null) {
			return external ? Decision.NOT_SWIFT : Decision.FOUND;
		}
		return switch (effect) {
			// A callee with a throwing symbol outside the analyzed set.
			case THROWS, TYPED_THROWS -> Decision.FOUND;
			case NONE -> Decision.CONTRADICTION;
			case ASYNC_THROWS, ASYNC_TYPED_THROWS -> Decision.ASYNC;
		};
	}

	/** The effects of the names that are Swift function symbols, in the order of the names. */
	private static Set<Effect> effects(List<String> names) {
		Set<Effect> effects = new LinkedHashSet<>();
		for (String name : names) {
			Effect e = ThrowingSymbol.classify(name);
			if (e != null) {
				effects.add(e);
			}
		}
		return effects;
	}
}
