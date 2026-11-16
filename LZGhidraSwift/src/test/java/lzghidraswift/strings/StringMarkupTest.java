// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import lzghidraswift.strings.StringHit.Kind;
import lzghidraswift.strings.StringHit.Method;

public class StringMarkupTest {

	private static StringHit hit(Kind kind, String text, Method method) {
		return new StringHit(kind, text, null, null, null, method, 0, 0);
	}

	@Test
	public void labels() {
		assertEquals("\"Flat\"", StringMarkup.label(hit(Kind.SMALL, "Flat", Method.CALL)));
		assertEquals("\"C\"?", StringMarkup.label(hit(Kind.SMALL, "C", Method.FALLBACK)));
		assertEquals("\"\"?", StringMarkup.label(hit(Kind.SMALL, "", Method.EMPTY_TAG)));
		assertEquals("\"md5_ovs_blocklist\" (large)",
			StringMarkup.label(hit(Kind.LARGE, "md5_ovs_blocklist", Method.CALL)));
		assertEquals("\"a\\\"b\\n\"", StringMarkup.label(hit(Kind.SMALL, "a\"b\n", Method.STORE)));
	}

	@Test
	public void ownLines() {
		assertTrue(StringMarkup.isOwnLine("Swift \"Flat\""));
		assertTrue(StringMarkup.isOwnLine("Swift \"C\"?"));
		assertTrue(StringMarkup.isOwnLine("Swift \"md5_ovs_blocklist\" (large)"));
		assertTrue(StringMarkup.isOwnLine("Swift \"\""));
		assertFalse(StringMarkup.isOwnLine("Swift strings are two words"));
		assertFalse(StringMarkup.isOwnLine("note: Swift \"Flat\""));
		assertFalse(StringMarkup.isOwnLine("Swift \"Flat\" is the key"));
	}

	@Test
	public void equateNames() {
		assertEquals("S\"Flat\"", StringMarkup.equateName("Flat"));
		assertEquals("S\"Flat\".hi", StringMarkup.equateNameHi("Flat"));
		assertEquals("S\"a\\\"b\".hi", StringMarkup.equateNameHi("a\"b"));
	}

	@Test
	public void ownEquates() {
		assertTrue(StringMarkup.isOwnEquate("S\"Flat\""));
		assertTrue(StringMarkup.isOwnEquate("S\"Flat\".hi"));
		assertTrue(StringMarkup.isOwnEquate("S\"\".hi"));
		assertFalse(StringMarkup.isOwnEquate("FLAT"));
		assertFalse(StringMarkup.isOwnEquate("S\"Flat\".lo"));
		// A character constant from the decompiler's Convert action is the user's.
		assertFalse(StringMarkup.isOwnEquate("\"Flat\""));
	}

	@Test
	public void appendKeepsLines() {
		assertEquals("Swift \"Flat\"", StringMarkup.appendLines(null, List.of("Swift \"Flat\"")));
		assertEquals("user\nSwift \"Flat\"\nSwift \"Sharp\"",
			StringMarkup.appendLines("user\nSwift \"Flat\"",
				List.of("Swift \"Sharp\"", "Swift \"Flat\"")));
		assertNull(StringMarkup.appendLines(null, List.of()));
	}

	@Test
	public void mergeKeepsUserLines() {
		assertNull(StringMarkup.mergeComment(null, List.of()));
		assertNull(StringMarkup.mergeComment("Swift \"Flat\"", List.of()));
		assertEquals("Swift \"Flat\"", StringMarkup.mergeComment(null, List.of("Swift \"Flat\"")));
		assertEquals("user\nSwift \"Sharp\"",
			StringMarkup.mergeComment("user\nSwift \"Flat\"", List.of("Swift \"Sharp\"")));
		assertEquals("user", StringMarkup.mergeComment("Swift \"Flat\"\nuser", List.of()));
		assertEquals("a\n\nb", StringMarkup.mergeComment("a\n\nb", List.of()));
	}

	@Test
	public void mergeIsIdempotent() {
		List<String> own = List.of("Swift \"Flat\"", "Swift \"Sharp\"");
		String once = StringMarkup.mergeComment("user note", own);
		assertEquals(once, StringMarkup.mergeComment(once, own));
	}
}
