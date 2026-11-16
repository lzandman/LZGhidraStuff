// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.mangling;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import lzghidraswift.metadata.SymbolNames;

/**
 * Plain Java: whether a Swift symbol names a function whose own type throws. The mangling marks a
 * throwing function type with {@code K}, typed throws with {@code <error type>YK}, async with
 * {@code Ya} before them ({@code function-signature} in swift/docs/ABI/Mangling.rst). The symbol
 * must be a function ({@code ...F}), an initializer ({@code ...cfC}, {@code ...cfc}), either of
 * them static ({@code Z}), or the dispatch thunk ({@code Tj}), protocol witness thunk
 * ({@code TW}), merged copy ({@code Tm}) or a specialization ({@code ...Tg5}, {@code ...Tf4nd_n})
 * of one of them. A specialization keeps the error convention; the optimizer calls the
 * specialized copies, so most calls in an optimized binary go to them. Other suffixes
 * (Objective-C thunks {@code To}, which report errors through {@code NSError **}; closures) and
 * accessors, whose mangling does not record throws, give null. So do symbols that are not
 * Swift's ({@code $s}).
 * <p>
 * A {@code K} also occurs in other places: in the type of a throwing closure parameter
 * ({@code yKXE}), in a protocol requirement ({@code SK} is Swift.BidirectionalCollection) and in
 * identifiers ({@code 0a7MutableK0} uses word substitutions). So the symbol is split into tokens
 * (identifiers, substitutions, generic parameter indices), and the function's own {@code K} is
 * the last one that is followed by the end of the function signature: the end of the symbol, or
 * the generic signature of a generic function. Checked against {@code swift-demangle --tree-only}
 * on the Swift symbols of the macOS SDK (devtools/check-throwing-symbols.sh).
 */
public final class ThrowingSymbol {

	/** The effect of a function's type. */
	public enum Effect {
		/** Neither throws nor typed throws (async or not). */
		NONE,
		/** {@code throws}: the error, an {@code any Error} box, in x21 (r12 on x86_64). */
		THROWS,
		/** {@code throws(E)}. */
		TYPED_THROWS,
		/** {@code async throws}. */
		ASYNC_THROWS,
		/** {@code async throws(E)}. */
		ASYNC_TYPED_THROWS
	}

	/**
	 * Tokens that continue a type to their left (postfix markers, list separators, the end of a
	 * tuple or bound generic) and so cannot start the generic signature: tuple end {@code t},
	 * separator {@code _}, bound generic end {@code G}, escaping function type {@code c},
	 * optional {@code Sg}, existential {@code p}, inout {@code z}, variadic {@code d}, owned
	 * {@code n}, shared {@code h}, metatype {@code m}, empty list {@code y}.
	 */
	private static final Set<String> POSTFIX =
		Set.of("t", "_", "G", "c", "Sg", "p", "z", "d", "n", "h", "m", "y");

	/**
	 * The second letter of the operators that start a specialization of the global before them:
	 * generic ({@code Tg}, {@code TG}, {@code TB}, {@code Ts}, {@code Ti}, {@code Tp},
	 * {@code TP}), with dropped arguments ({@code Tt}, before {@code g}), function signature
	 * ({@code Tf}). Not {@code Ta}, which makes an async function synchronous.
	 */
	private static final String SPECIALIZATIONS = "gGBsipPtf";

	private ThrowingSymbol() {
	}

	/** The effect of the function that {@code symbol} names, or null if it names no function. */
	public static Effect classify(String symbol) {
		String body = SymbolNames.swiftBody(symbol);
		if (body == null) {
			return null;
		}
		body = withoutSpecialization(body);
		if (body.endsWith("Tj") || body.endsWith("TW") || body.endsWith("Tm")) {
			body = body.substring(0, body.length() - 2);
		}
		if (body.endsWith("Z")) {
			body = body.substring(0, body.length() - 1);
		}
		boolean initializer = body.endsWith("fC") || body.endsWith("fc");
		String signature;
		if (initializer) {
			signature = body.substring(0, body.length() - 2);
			// A generic initializer's type is <function type>c <generic signature>u.
			if (signature.endsWith("u")) {
				signature = signature.substring(0, signature.length() - 1);
			}
		}
		else if (body.endsWith("F")) {
			// Also other entities ending in F (a field descriptor MF), which have no function
			// type: NONE. The analyzer reads only the symbols at function entry points.
			signature = body.substring(0, body.length() - 1);
		}
		else {
			return null;
		}
		List<String> tokens = tokens(signature);
		boolean generic = !tokens.isEmpty() && tokens.getLast().equals("l");
		for (int k = tokens.size() - 1; k >= 0; k--) {
			if (isOwnThrows(tokens, k, initializer, generic)) {
				return effect(tokens, k);
			}
		}
		return Effect.NONE;
	}

	/**
	 * The global that a specialization specializes: the text up to the first function entity
	 * ({@code F}, {@code fC}, {@code fc}, and a {@code Z} after it) that is not the context of a
	 * local declaration ({@code <name>L...} after it), before the first specialization operator.
	 * Not the last entity: a function signature specialization names the closures it takes as
	 * arguments, after the global ({@code ...F<closure>fU_Tf1cn_n}). {@code body} itself if it has
	 * no specialization.
	 */
	private static String withoutSpecialization(String body) {
		List<String> tokens = tokens(body);
		int end = -1;
		int position = 0;
		for (int k = 0; k < tokens.size(); k++) {
			String t = tokens.get(k);
			position += t.length();
			if (t.length() == 2 && t.charAt(0) == 'T' &&
				SPECIALIZATIONS.indexOf(t.charAt(1)) >= 0) {
				return end > 0 ? body.substring(0, end) : body;
			}
			boolean entity = t.equals("F") || t.equals("fC") || t.equals("fc");
			if (entity && end < 0 && !isLocalContext(tokens, k + 1)) {
				end = position;
			}
			else if (t.equals("Z") && end == position - 1) {
				end = position;
			}
		}
		return body;
	}

	/** Whether the tokens from {@code k} are a local declaration's name and discriminator. */
	private static boolean isLocalContext(List<String> tokens, int k) {
		return k + 1 < tokens.size() && isDigit(tokens.get(k).charAt(0)) &&
			tokens.get(k + 1).startsWith("L");
	}

	/**
	 * Whether token {@code k} is the function's own {@code K} or {@code YK}: followed by the end
	 * of the signature (for an initializer, by the {@code c} of its function type and then that
	 * end), or by the generic signature of a generic function. A {@code K} followed by {@code c},
	 * {@code X...} or another postfix token belongs to a function type inside the signature.
	 */
	private static boolean isOwnThrows(List<String> tokens, int k, boolean initializer,
			boolean generic) {
		String t = tokens.get(k);
		if (!t.equals("K") && !t.equals("YK")) {
			return false;
		}
		int end = skipAnnotations(tokens, k + 1);
		if (initializer) {
			if (end >= tokens.size() || !tokens.get(end).equals("c")) {
				return false;
			}
			end++;
		}
		if (end == tokens.size()) {
			return true;
		}
		String next = tokens.get(end);
		return generic && !next.startsWith("X") && !POSTFIX.contains(next);
	}

	private static Effect effect(List<String> tokens, int k) {
		boolean typed = tokens.get(k).equals("YK");
		if (!typed) {
			boolean async = (k >= 1 && tokens.get(k - 1).equals("Ya")) ||
				(k >= 2 && tokens.get(k - 1).equals("Yb") && tokens.get(k - 2).equals("Ya"));
			return async ? Effect.ASYNC_THROWS : Effect.THROWS;
		}
		// The error type stands between Ya (and Yb) and YK; it is mostly one or two tokens.
		for (int i = k - 1; i >= Math.max(0, k - 6); i--) {
			if (tokens.get(i).equals("Ya")) {
				return Effect.ASYNC_TYPED_THROWS;
			}
		}
		return Effect.TYPED_THROWS;
	}

	/**
	 * Skips what may follow {@code throws} in a function signature: a global actor
	 * ({@code <type>Yc}), {@code @isolated(any)} ({@code YA}), {@code nonisolated(nonsending)}
	 * ({@code YC}), {@code sending} result ({@code YT}), {@code @differentiable} ({@code Yj?}).
	 */
	private static int skipAnnotations(List<String> tokens, int k) {
		if (k + 1 < tokens.size() && tokens.get(k + 1).equals("Yc")) {
			k += 2;
		}
		while (k < tokens.size()) {
			String t = tokens.get(k);
			if (!t.equals("YT") && !t.equals("YA") && !t.equals("YC") && !t.startsWith("Yj")) {
				break;
			}
			k++;
		}
		return k;
	}

	/**
	 * The mangled text split into tokens: identifiers (with word substitutions), substitutions
	 * ({@code A...}, {@code S...}), generic parameters and requirements with their indices, and
	 * two-character operators ({@code Y?}, {@code X?}, {@code f?}, {@code T?}). Everything else is
	 * one character. Only as exact as {@link #classify} needs.
	 */
	static List<String> tokens(String s) {
		List<String> out = new ArrayList<>();
		int i = 0;
		while (i < s.length()) {
			int end = Math.min(Math.max(tokenEnd(s, i), i + 1), s.length());
			out.add(s.substring(i, end));
			i = end;
		}
		return out;
	}

	/** The end of the token that starts at {@code i}. */
	private static int tokenEnd(String s, int i) {
		char c = s.charAt(i);
		if (isDigit(c)) {
			return identifier(s, i);
		}
		return switch (c) {
			case 'A' -> substitution(s, i + 1);
			case 'S' -> standardSubstitution(s, i + 1);
			case 'q' -> orElse(genericParamIndex(s, i + 1), i + 1);
			case 'Q' -> associatedType(s, i + 1);
			case 'R' -> requirement(s, i + 1);
			case 'r' -> paramCounts(s, i + 1);
			case 'f', 'T' -> entityOperator(s, i);
			case 'L' -> local(s, i + 1);
			case 'Y' -> i + (charAt(s, i + 1) == 'j' ? 3 : 2);
			case 'X' -> i + 2;
			case 'B' -> charAt(s, i + 1) == 'i' ? orElse(index(s, i + 2), i + 2) : i + 2;
			default -> i + 1;
		};
	}

	/** Associated type after {@code Q}: {@code Qz}, {@code Qx}, {@code Qy} and {@code QY} with a generic parameter index, ... */
	private static int associatedType(String s, int i) {
		char kind = charAt(s, i);
		return kind == 'y' || kind == 'Y' ? orElse(genericParamIndex(s, i + 1), i + 1) : i + 1;
	}

	/** Generic signature counts after {@code r}: ({@code z} | NATURAL? {@code _})*, before {@code l}. */
	private static int paramCounts(String s, int i) {
		while (i < s.length()) {
			int j = s.charAt(i) == 'z' ? i + 1 : index(s, i);
			if (j < 0) {
				break;
			}
			i = j;
		}
		return i;
	}

	/** {@code f?} and {@code T?}, with the INDEX of a closure ({@code fu}, {@code fU}) or default argument ({@code fA}), and the NATURAL of {@code Tv}. */
	private static int entityOperator(String s, int i) {
		char c = s.charAt(i);
		char kind = charAt(s, i + 1);
		if (c == 'f' && (kind == 'u' || kind == 'U' || kind == 'A')) {
			return orElse(index(s, i + 2), i + 2);
		}
		if (c == 'T' && kind == 'v') {
			return natural(s, i + 2);
		}
		return i + 2;
	}

	/** After {@code L}: a letter ({@code LL}, {@code Ll}), or the INDEX of a local entity. */
	private static int local(String s, int i) {
		return Character.isLetter(charAt(s, i)) ? i + 1 : orElse(index(s, i), i);
	}

	/** The character at {@code i}, or 0 past the end. */
	private static char charAt(String s, int i) {
		return i < s.length() ? s.charAt(i) : 0;
	}

	/** An identifier at {@code i}, as Swift's {@code Demangler::demangleIdentifier} reads it. */
	private static int identifier(String s, int i) {
		int n = s.length();
		boolean words = false;
		if (s.charAt(i) == '0') {
			i++;
			if (i < n && s.charAt(i) == '0') {
				i++; // punycode
			}
			else {
				words = true;
			}
		}
		while (true) {
			while (words && i < n && Character.isLetter(s.charAt(i))) {
				// Lower-case letters refer to words; an upper-case letter is the last reference.
				if (Character.isUpperCase(s.charAt(i))) {
					words = false;
				}
				i++;
			}
			if (i < n && s.charAt(i) == '0') {
				return i + 1;
			}
			int j = natural(s, i);
			if (j == i) {
				return i;
			}
			i = (int) Math.min(j + Long.parseLong(s.substring(i, Math.min(j, i + 9))), n);
			if (!words) {
				return i;
			}
		}
	}

	/** {@code A} INDEX, or {@code A} (NATURAL? [a-z])* NATURAL? [A-Z]. */
	private static int substitution(String s, int i) {
		int j = index(s, i);
		if (j >= 0) {
			return j;
		}
		int n = s.length();
		while (i < n) {
			i = natural(s, i);
			if (i >= n) {
				break;
			}
			char c = s.charAt(i++);
			if (!Character.isLowerCase(c)) {
				break;
			}
		}
		return i;
	}

	/** {@code S} INDEX, or {@code S} NATURAL? (a known type letter, or {@code c} and a letter). */
	private static int standardSubstitution(String s, int i) {
		int j = index(s, i);
		if (j >= 0) {
			return j;
		}
		i = natural(s, i);
		if (i < s.length() && s.charAt(i) == 'c') {
			i++;
		}
		return Math.min(i + 1, s.length());
	}

	/**
	 * A requirement after {@code R}: a protocol requirement {@code R} GENERIC-PARAM-INDEX, or a
	 * kind letter, an INDEX for the inverse requirements ({@code i I j J}) and a generic
	 * parameter index unless the kind takes a substitution ({@code Q B S I}).
	 */
	private static int requirement(String s, int i) {
		if (i < s.length() && s.charAt(i) != 's') {
			int j = genericParamIndex(s, i);
			if (j >= 0) {
				return j;
			}
		}
		if (i >= s.length()) {
			return i;
		}
		char kind = s.charAt(i++);
		if ("iIjJ".indexOf(kind) >= 0) {
			i = orElse(index(s, i), i);
		}
		if ("QBSIm".indexOf(kind) < 0) {
			i = orElse(genericParamIndex(s, i), i);
		}
		return i;
	}

	/** GENERIC-PARAM-INDEX: {@code z}, {@code s}, INDEX, or {@code d} INDEX INDEX; -1 if none. */
	private static int genericParamIndex(String s, int i) {
		if (i >= s.length()) {
			return -1;
		}
		char c = s.charAt(i);
		if (c == 'z' || c == 's') {
			return i + 1;
		}
		if (c == 'd') {
			int j = index(s, i + 1);
			return j < 0 ? -1 : index(s, j);
		}
		return index(s, i);
	}

	/** INDEX: {@code _} or NATURAL {@code _}; -1 if none. */
	private static int index(String s, int i) {
		if (i < s.length() && s.charAt(i) == '_') {
			return i + 1;
		}
		int j = natural(s, i);
		return j > i && j < s.length() && s.charAt(j) == '_' ? j + 1 : -1;
	}

	private static int natural(String s, int i) {
		while (i < s.length() && isDigit(s.charAt(i))) {
			i++;
		}
		return i;
	}

	private static boolean isDigit(char c) {
		return c >= '0' && c <= '9';
	}

	private static int orElse(int position, int fallback) {
		return position >= 0 ? position : fallback;
	}
}
