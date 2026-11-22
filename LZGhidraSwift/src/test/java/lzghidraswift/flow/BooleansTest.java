// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.flow;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.program.model.pcode.PcodeOp;
import lzghidraswift.flow.ValueFlow.Sym;
import lzghidraswift.flow.ValueFlow.SymKind;
import lzghidraswift.flow.ValueFlow.Value;

public class BooleansTest {

	private final Map<List<Object>, Long> numbers = new HashMap<>();
	private final Booleans booleans = new Booleans(
		key -> new Sym(SymKind.NUMBERED, numbers.computeIfAbsent(key, k -> (long) numbers.size()),
			0));

	private static Value sym(Sym s) {
		return new Value(0, s, null, Map.of());
	}

	private static Value constant(long k) {
		return new Value(k, null, null, Map.of());
	}

	/**
	 * spelling(_:) on x86_64: {@code testb $1, %dil} reads RDI's entry value at 1 byte,
	 * {@code andl $1, %edi} at 4 bytes. Both are bit 0 of the same register.
	 */
	@Test
	public void entryValueHasOneBit0AtEverySize() {
		Value dil = booleans.bit0(sym(new Sym(SymKind.ENTRY, 0x38, 1)));
		Value edi = booleans.bit0(sym(new Sym(SymKind.ENTRY, 0x38, 4)));
		assertEquals(dil, edi);
		assertEquals(0, dil.k());
		assertTrue(booleans.isBoolean(dil));
		assertFalse(booleans.isBoolean(sym(new Sym(SymKind.ENTRY, 0x38, 4))));
	}

	/**
	 * {@code testb $1, %r14b; ...; notb %r14b; movzbl %r14b, %eax; andl $1, %eax}: the low
	 * byte, its negation and the zero extension of that have bit 0 of R14, inverted once.
	 */
	@Test
	public void bit0FollowsTruncationNegationAndExtension() {
		Value r14 = sym(new Sym(SymKind.CALL, 0x100, 0xb0));
		Sym low = new Sym(SymKind.NUMBERED, 100, 0);
		booleans.truncated(low, r14);
		Sym not = new Sym(SymKind.NUMBERED, 101, 0);
		booleans.numbered(PcodeOp.INT_NEGATE, 1, not, List.of(sym(low)));
		Sym zext = new Sym(SymKind.NUMBERED, 102, 0);
		booleans.numbered(PcodeOp.INT_ZEXT, 4, zext, List.of(sym(not)));
		Value tested = booleans.bit0(sym(low));
		Value masked = booleans.bit0(sym(zext));
		assertEquals(tested.sym(), masked.sym());
		assertEquals(0, tested.k());
		assertEquals(1, masked.k());
		// xor with an odd constant inverts bit 0, an offset of 1 too
		Sym xor = new Sym(SymKind.NUMBERED, 103, 0);
		booleans.numbered(PcodeOp.INT_XOR, 4, xor, List.of(sym(low), constant(1)));
		assertEquals(1, booleans.bit0(sym(xor)).k());
		assertEquals(1, booleans.bit0(new Value(1, low, null, Map.of())).k());
	}

	@Test
	public void comparesAreBooleans() {
		Sym zf = new Sym(SymKind.NUMBERED, 7, 0);
		booleans.numbered(PcodeOp.INT_EQUAL, 1, zf, List.of(sym(new Sym(SymKind.OP, 1, 2)),
			constant(0)));
		assertTrue(booleans.isBoolean(sym(zf)));
		Sym sum = new Sym(SymKind.NUMBERED, 8, 0);
		booleans.numbered(PcodeOp.INT_ADD, 1, sum, List.of(sym(zf), sym(zf)));
		assertFalse(booleans.isBoolean(sym(sum)));
	}

	/** {@code ZF = (b & 1) == 0} is the negation of b; {@code b & 0xff} is b. */
	@Test
	public void constantsThatKeepTheBoolean() {
		Value b = new Value(0, new Sym(SymKind.NUMBERED, 1, 0), null, Map.of());
		Value notB = new Value(1, b.sym(), null, Map.of());
		assertEquals(notB, Booleans.withConstant(PcodeOp.INT_EQUAL, b, 0));
		assertEquals(b, Booleans.withConstant(PcodeOp.INT_EQUAL, b, 1));
		assertEquals(b, Booleans.withConstant(PcodeOp.INT_NOTEQUAL, b, 0));
		assertEquals(b, Booleans.withConstant(PcodeOp.INT_AND, b, 0xff));
		assertEquals(notB, Booleans.withConstant(PcodeOp.INT_XOR, b, 1));
		assertNull(Booleans.withConstant(PcodeOp.INT_OR, b, -0x1c));
		assertNull(Booleans.withConstant(PcodeOp.INT_EQUAL, b, 2));
	}

	/**
	 * The two constants of {@code b xor 1}: 1 where b is 0, 0 where b is 1. A label that
	 * contradicts b's own labels leaves its constant out.
	 */
	@Test
	public void splitLabelsEachConstant() {
		Sym s = new Sym(SymKind.NUMBERED, 1, 0);
		List<Value> both = Booleans.split(new Value(1, s, null, Map.of()), null);
		assertEquals(2, both.size());
		assertEquals(1, both.get(0).k());
		assertEquals(Map.of(s, 0L), both.get(0).labels());
		assertEquals(0, both.get(1).k());
		assertEquals(Map.of(s, 1L), both.get(1).labels());
		List<Value> one = Booleans.split(new Value(0, s, null, Map.of(s, 1L)), null);
		assertEquals(1, one.size());
		assertEquals(1, one.getFirst().k());
	}
}
