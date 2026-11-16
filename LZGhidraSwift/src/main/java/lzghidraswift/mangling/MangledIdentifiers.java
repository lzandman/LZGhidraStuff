// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.mangling;

import java.util.ArrayList;
import java.util.List;

/**
 * Identifiers of the Swift mangling, with word substitutions (swift/docs/ABI/Mangling.rst,
 * "Identifiers"; Swift's Demangler::demangleIdentifier). An identifier is a length and its
 * characters ({@code 8Dispatch}), or {@code 0} and a mix of word references and literal parts:
 * a lowercase letter repeats a word and goes on, an uppercase letter repeats a word and ends the
 * substitutions, a length starts a literal part, and a {@code 0} ends an identifier whose last
 * part is a word ({@code 0A8WorkItem} is "Dispatch" + "WorkItem" after {@code 8Dispatch};
 * {@code 0aB0} two words). The words are those of the earlier identifiers of the same mangled
 * name, so one instance must parse all identifiers of a name in order. Punycode ({@code 00})
 * is not supported. Plain Java.
 */
public final class MangledIdentifiers {

	/** An identifier and the position after it. */
	public record Parsed(String text, int end) {}

	private static final int MAX_WORDS = 26;

	private final List<String> words = new ArrayList<>();

	/** Parses the identifier at {@code s[pos]} (a digit), or returns null. */
	public Parsed parse(String s, int pos) {
		if (pos >= s.length() || !Character.isDigit(s.charAt(pos))) {
			return null;
		}
		StringBuilder identifier = new StringBuilder();
		if (s.charAt(pos) != '0') {
			int end = literal(s, pos, identifier);
			return end < 0 ? null : new Parsed(identifier.toString(), end);
		}
		if (pos + 1 < s.length() && s.charAt(pos + 1) == '0') {
			return null; // punycode
		}
		pos++;
		boolean substitutions = true;
		while (substitutions) {
			int start = pos;
			pos = words(s, pos, identifier);
			if (pos < 0) {
				return null;
			}
			// An uppercase word reference ends the substitutions.
			substitutions = pos == start || !Character.isUpperCase(s.charAt(pos - 1));
			if (pos < s.length() && s.charAt(pos) == '0') {
				return new Parsed(identifier.toString(), pos + 1);
			}
			pos = literal(s, pos, identifier);
			if (pos < 0) {
				return null;
			}
		}
		return new Parsed(identifier.toString(), pos);
	}

	/**
	 * Appends the words that the letters at {@code s[pos]} refer to, up to and including the
	 * first uppercase one. Returns the position after them, or -1 for an unknown word.
	 */
	private int words(String s, int pos, StringBuilder identifier) {
		while (pos < s.length() && Character.isLetter(s.charAt(pos))) {
			char c = s.charAt(pos++);
			int index = Character.isLowerCase(c) ? c - 'a' : c - 'A';
			if (index >= words.size()) {
				return -1;
			}
			identifier.append(words.get(index));
			if (Character.isUpperCase(c)) {
				break;
			}
		}
		return pos;
	}

	/**
	 * Appends the literal part at {@code s[pos]} (a length and its characters) and adds its
	 * words. Returns the position after it, or -1.
	 */
	private int literal(String s, int pos, StringBuilder identifier) {
		int start = pos;
		while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
			pos++;
		}
		if (start == pos) {
			return -1;
		}
		int length = Integer.parseInt(s.substring(start, pos));
		if (length <= 0 || pos + length > s.length()) {
			return -1;
		}
		String literal = s.substring(pos, pos + length);
		identifier.append(literal);
		addWords(literal);
		return pos + length;
	}

	/**
	 * Adds the words of a literal part: a word starts at a character that is not a digit or
	 * {@code _}, and ends before {@code _}, the end, or an uppercase letter that follows a
	 * character that is not uppercase. Only words of two or more characters count.
	 */
	private void addWords(String literal) {
		int start = -1;
		for (int i = 0; i <= literal.length(); i++) {
			char c = i < literal.length() ? literal.charAt(i) : 0;
			if (start >= 0 && (c == '_' || c == 0 ||
				(!Character.isUpperCase(literal.charAt(i - 1)) && Character.isUpperCase(c)))) {
				if (i - start >= 2 && words.size() < MAX_WORDS) {
					words.add(literal.substring(start, i));
				}
				start = -1;
			}
			if (start < 0 && c != 0 && c != '_' && !Character.isDigit(c)) {
				start = i;
			}
		}
	}
}
