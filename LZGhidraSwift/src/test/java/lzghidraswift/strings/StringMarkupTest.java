// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import lzghidraswift.flow.PcodeFixtures;
import lzghidraswift.strings.StringHit.Kind;
import lzghidraswift.strings.StringHit.Method;

public class StringMarkupTest {

	private static StringHit hit(Kind kind, String text, Method method) {
		return new StringHit(kind, text, null, null, null, method, 0, 0);
	}

	@Test
	public void deletableReferences() {
		assertTrue(StringMarkup.isDeletable(SourceType.ANALYSIS, 1));
		assertTrue(StringMarkup.isDeletable(SourceType.DEFAULT, 0));
		assertFalse(StringMarkup.isDeletable(SourceType.USER_DEFINED, 1));
		assertFalse(StringMarkup.isDeletable(SourceType.IMPORTED, 1));
		// The analyzer's own reference is a mnemonic one.
		assertFalse(StringMarkup.isDeletable(SourceType.ANALYSIS, -1));
	}

	// x86-64 register offsets of Ghidra 12.2.
	private static final Varnode RAX = PcodeFixtures.reg(0x0, 8);
	private static final Varnode RCX = PcodeFixtures.reg(0x8, 8);
	private static final Varnode RSI = PcodeFixtures.reg(0x30, 8);

	private static PcodeOp op(int opcode, Varnode out, Varnode... in) {
		return PcodeFixtures.op(opcode, out, in);
	}

	private static Varnode constant(long value) {
		return PcodeFixtures.constant(value, 8);
	}

	@Test
	public void traceWritersFollowsCmovToBothValues() {
		// cmove rcx, rax: the write is conditional, so rcx (the other lea) stays needed.
		Varnode tmp = PcodeFixtures.unique(0x100, 8);
		PcodeOp[] cmov = { op(PcodeOp.COPY, tmp, RAX),
			op(PcodeOp.CBRANCH, null, constant(0), PcodeFixtures.ZF),
			op(PcodeOp.COPY, RCX, tmp) };
		List<Varnode> needed = new ArrayList<>(List.of(RCX));
		assertTrue(StringMarkup.traceWriters(cmov, needed));
		assertEquals(List.of(RCX, RAX), needed);
		// lea rcx, [rip + x]: a constant, so nothing is left of rcx.
		assertTrue(StringMarkup.traceWriters(
			new PcodeOp[] { op(PcodeOp.COPY, RCX, constant(0x1018663f0L)) }, needed));
		assertEquals(List.of(RAX), needed);
	}

	@Test
	public void traceWritersFollowsAddAndStopsAtLoad() {
		// add rsi, -0x20 keeps rsi needed for the lea before it.
		List<Varnode> needed = new ArrayList<>(List.of(RSI));
		assertTrue(StringMarkup.traceWriters(
			new PcodeOp[] { op(PcodeOp.INT_ADD, RSI, RSI, constant(-0x20)) }, needed));
		assertEquals(List.of(RSI), needed);
		// mov rsi, [rax]: the value comes from memory, rax is not followed.
		assertTrue(StringMarkup.traceWriters(
			new PcodeOp[] { op(PcodeOp.LOAD, RSI, PcodeFixtures.SPACE, RAX) },
			needed));
		assertTrue(needed.isEmpty());
		// An instruction that writes another register is not one of the string's.
		needed.add(RSI);
		assertFalse(StringMarkup.traceWriters(
			new PcodeOp[] { op(PcodeOp.COPY, RCX, constant(1)) }, needed));
		assertEquals(List.of(RSI), needed);
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
