// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.mangling;

import java.util.function.Predicate;

import lzghidraswift.metadata.SymbolNames;

/**
 * Plain Java: recognizes the Swift symbols of members of a nominal type whose functions may get
 * {@code self} in the context register (x20, r13): instance methods, property and subscript
 * accessors, initializing initializers and deinitializers, and allocating initializers, which get
 * the metatype there (a class's metadata). Everything else is rejected: static members
 * ({@code Z}), thunks and other suffixes
 * ({@code TW}, {@code To}, {@code .resume.0}), and nested entities (closures, local functions),
 * which {@link SwiftTypeName#parseEntity} does not parse.
 */
public final class SwiftSymbol {

	/**
	 * Method ({@code F}), property accessor ({@code v} and an accessor letter), subscript accessor
	 * ({@code i} and a letter), initializing initializer ({@code fc}), deinitializer ({@code fd},
	 * {@code fD}), allocating initializer ({@code fC}).
	 */
	public enum Kind {
		METHOD, ACCESSOR, SUBSCRIPT, INITIALIZER, DEINITIALIZER, ALLOCATOR
	}

	/**
	 * A member of the type whose mangled name (without {@code $s}) is {@code context}, as in its
	 * descriptor symbol {@code $s<context>Mn}. {@code accessor} is the accessor letter of an
	 * accessor or subscript ({@code g} getter, {@code s} setter, {@code M} modify, ...), else 0.
	 */
	public record Member(String context, Kind kind, String name, char accessor) {}

	/** Accessor letters after {@code v} or {@code i} (Swift's Demangler::demangleAccessor). */
	private static final String ACCESSORS = "gsMrxywWbz";

	private SwiftSymbol() {
	}

	/**
	 * The member that {@code symbol} names, or null. {@code isContext} says whether a mangled
	 * type name (without {@code $s}) is one of the types of interest; the longest such prefix of
	 * the symbol is its context.
	 */
	public static Member classify(String symbol, Predicate<String> isContext) {
		String body = SymbolNames.swiftBody(symbol);
		if (body == null || body.length() < 3) {
			return null;
		}
		char last = body.charAt(body.length() - 1);
		Kind kind = kind(body.charAt(body.length() - 2), last);
		if (kind == null) {
			return null;
		}
		int entity = kind == Kind.METHOD ? 1 : 2;
		String head = body.substring(0, body.length() - entity);
		String context = longestContext(head, isContext);
		if (context == null) {
			return null;
		}
		SwiftTypeName.Entity parsed = SwiftTypeName.parseEntity(head);
		SwiftTypeName.Entity alone = SwiftTypeName.parseEntity(context);
		if (parsed == null && alone != null && kind == Kind.ALLOCATOR) {
			// The parser does not read generic parameters (x, q_), so the initializer of a
			// generic class (Box<A>.init: ...BoxCyACyxGxcfC) does not parse. An allocating
			// initializer has no member name, and a closure or local function in it ends in
			// another suffix: its context is the longest one.
			return new Member(context, kind, null, (char) 0);
		}
		// The parsed context must be the type itself, not a type nested in it.
		if (parsed == null || alone == null || !parsed.context().equals(alone.context())) {
			return null;
		}
		switch (kind) {
			case METHOD, ACCESSOR -> {
				if (parsed.member() == null) {
					return null;
				}
			}
			case DEINITIALIZER -> {
				if (!head.equals(context)) {
					return null;
				}
			}
			default -> {
			}
		}
		char accessor = kind == Kind.ACCESSOR || kind == Kind.SUBSCRIPT ? last : 0;
		return new Member(context, kind, parsed.member(), accessor);
	}

	/**
	 * The kind of member from the symbol's last two characters, or null for another entity.
	 * The entity suffix is {@code F} for a method, else the two characters.
	 */
	private static Kind kind(char before, char last) {
		if (before == 'f' && (last == 'c' || last == 'd' || last == 'D' || last == 'C')) {
			return switch (last) {
				case 'c' -> Kind.INITIALIZER;
				case 'C' -> Kind.ALLOCATOR;
				default -> Kind.DEINITIALIZER;
			};
		}
		if (last == 'F') {
			// Also ...SfF (a Float in the type). Other entities ending in F (fF, a property
			// wrapper's init accessor) leave an f that SwiftTypeName.parseEntity rejects.
			return Kind.METHOD;
		}
		if (ACCESSORS.indexOf(last) >= 0 && (before == 'v' || before == 'i')) {
			return before == 'v' ? Kind.ACCESSOR : Kind.SUBSCRIPT;
		}
		return null;
	}

	/** The longest prefix of {@code head} that ends a nominal type and is a context of interest. */
	private static String longestContext(String head, Predicate<String> isContext) {
		for (int i = head.length(); i > 0; i--) {
			char c = head.charAt(i - 1);
			if ((c == 'V' || c == 'C' || c == 'O') && isContext.test(head.substring(0, i))) {
				return head.substring(0, i);
			}
		}
		return null;
	}
}
