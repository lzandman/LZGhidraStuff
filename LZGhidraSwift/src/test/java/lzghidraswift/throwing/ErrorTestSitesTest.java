// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.throwing;

import static lzghidraswift.flow.PcodeFixtures.CF;
import static lzghidraswift.flow.PcodeFixtures.R12;
import static lzghidraswift.flow.PcodeFixtures.RAM;
import static lzghidraswift.flow.PcodeFixtures.SP;
import static lzghidraswift.flow.PcodeFixtures.SPACE;
import static lzghidraswift.flow.PcodeFixtures.W21;
import static lzghidraswift.flow.PcodeFixtures.X0;
import static lzghidraswift.flow.PcodeFixtures.X21;
import static lzghidraswift.flow.PcodeFixtures.X22;
import static lzghidraswift.flow.PcodeFixtures.ZF;
import static lzghidraswift.flow.PcodeFixtures.constant;
import static lzghidraswift.flow.PcodeFixtures.op;
import static lzghidraswift.flow.PcodeFixtures.ops;
import static lzghidraswift.flow.PcodeFixtures.rangeOf;
import static lzghidraswift.flow.PcodeFixtures.unique;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import lzghidraswift.flow.PcodeFixtures;

/** The p-code checks of {@link ErrorTestSites} on the instructions in the comments. */
public class ErrorTestSitesTest {

	/** stp x22, x21, [sp, #0x10]: the prologue's save is no read; cbz x21 is one. */
	@Test
	public void saveIsNoRead() {
		Varnode u1 = unique(0x74000, 8);
		Varnode u2 = unique(0x74100, 8);
		Varnode addr = unique(0xf000, 8);
		Varnode addr2 = unique(0x74200, 8);
		PcodeOp[] stp = ops(op(PcodeOp.COPY, u1, X22), op(PcodeOp.COPY, u2, X21),
			op(PcodeOp.INT_ADD, addr, SP, constant(0x10, 8)),
			op(PcodeOp.STORE, null, SPACE, addr, u1),
			op(PcodeOp.INT_ADD, addr2, addr, constant(8, 8)),
			op(PcodeOp.STORE, null, SPACE, addr2, u2));
		assertFalse(ErrorTestSites.reads(stp, rangeOf(X21)));
		Varnode cond = unique(0x31700, 1);
		PcodeOp[] cbz = ops(op(PcodeOp.INT_EQUAL, cond, X21, constant(0, 8)),
			op(PcodeOp.CBRANCH, null, new Varnode(RAM.getAddress(0xc54), 8), cond));
		assertTrue(ErrorTestSites.reads(cbz, rangeOf(X21)));
		assertFalse(ErrorTestSites.writes(cbz, rangeOf(X21)));
	}

	/** test r12, r12 writes only flags and temporaries; mov x0, x21 writes x0. */
	@Test
	public void flagsOnly() {
		Varnode u = unique(0xd5700, 8);
		PcodeOp[] test = ops(op(PcodeOp.COPY, CF, constant(0, 1)),
			op(PcodeOp.INT_AND, u, R12, R12), op(PcodeOp.INT_EQUAL, ZF, u, constant(0, 8)));
		assertTrue(ErrorTestSites.writesOnlyFlags(test));
		assertTrue(ErrorTestSites.reads(test, rangeOf(R12)));
		assertFalse(ErrorTestSites.writesOnlyFlags(ops(op(PcodeOp.COPY, X0, X21))));
	}

	/**
	 * mov x8, x21 (-Onone, before cbnz x21) is a copy out; mov w8, w21 (a part), add x8, x21, #1
	 * and mov x21, x21 are not.
	 */
	@Test
	public void copyOut() {
		Varnode x8 = PcodeFixtures.reg(0x4040, 8);
		Varnode w8 = PcodeFixtures.reg(0x4040, 4);
		assertTrue(ErrorTestSites.isCopyOut(ops(op(PcodeOp.COPY, x8, X21)), rangeOf(X21)));
		assertFalse(ErrorTestSites.isCopyOut(ops(op(PcodeOp.COPY, w8, W21)), rangeOf(X21)));
		assertFalse(ErrorTestSites.isCopyOut(
			ops(op(PcodeOp.INT_ADD, x8, X21, constant(1, 8))), rangeOf(X21)));
		assertFalse(ErrorTestSites.isCopyOut(ops(op(PcodeOp.COPY, X21, X21)), rangeOf(X21)));
	}

	/**
	 * Ghidra 12.1.4's p-code (12.2 did not change these instructions) of cbz x21, cmp x21, #0 and test r12, r12 compares with 0;
	 * cmp r12, 0x7fffffffffffffe9 (a loop counter's overflow check after a call) and
	 * tbz x21, #63 do not.
	 */
	@Test
	public void comparesWithZero() {
		Varnode cond = unique(0x31700, 1);
		assertTrue(ErrorTestSites.comparesWithZero(
			ops(op(PcodeOp.INT_EQUAL, cond, X21, constant(0, 8))), rangeOf(X21)));
		Varnode zero = unique(0x39100, 8);
		Varnode diff = unique(0x39300, 8);
		assertTrue(ErrorTestSites.comparesWithZero(ops(op(PcodeOp.COPY, zero, constant(0, 8)),
			op(PcodeOp.INT_SUB, diff, X21, zero), op(PcodeOp.INT_EQUAL, ZF, diff, constant(0, 8))),
			rangeOf(X21)));
		Varnode and = unique(0xd5700, 8);
		assertTrue(ErrorTestSites.comparesWithZero(ops(op(PcodeOp.INT_AND, and, R12, R12),
			op(PcodeOp.INT_EQUAL, ZF, and, constant(0, 8))), rangeOf(R12)));
		assertFalse(ErrorTestSites.comparesWithZero(
			ops(op(PcodeOp.INT_SUB, diff, R12, constant(0x7fffffffffffffe9L, 8)),
				op(PcodeOp.INT_EQUAL, ZF, diff, constant(0, 8))),
			rangeOf(R12)));
		Varnode bit = unique(0x31800, 8);
		assertFalse(ErrorTestSites.comparesWithZero(
			ops(op(PcodeOp.INT_RIGHT, bit, X21, constant(63, 8)),
				op(PcodeOp.INT_EQUAL, cond, bit, constant(0, 8))),
			rangeOf(X21)));
	}

	/**
	 * test r12, r12; cmove rax, rbx: the select reads ZF, which the test writes. mov rax, rbx
	 * reads no flag; a select on CF after an instruction that writes only ZF does not count.
	 */
	@Test
	public void conditionalSelectReadsFlags() {
		Varnode u = unique(0xd5700, 8);
		PcodeOp[] test = ops(op(PcodeOp.INT_AND, u, R12, R12),
			op(PcodeOp.INT_EQUAL, ZF, u, constant(0, 8)));
		Varnode notZ = unique(0x31700, 1);
		PcodeOp[] cmove = ops(op(PcodeOp.BOOL_NEGATE, notZ, ZF),
			op(PcodeOp.CBRANCH, null, constant(1, 8), notZ), op(PcodeOp.COPY, X0, X22));
		assertTrue(ErrorTestSites.readsFlags(cmove, test));
		assertFalse(ErrorTestSites.readsFlags(ops(op(PcodeOp.COPY, X0, X22)), test));
		PcodeOp[] cmovb = ops(op(PcodeOp.BOOL_NEGATE, notZ, CF),
			op(PcodeOp.CBRANCH, null, constant(1, 8), notZ), op(PcodeOp.COPY, X0, X22));
		assertFalse(ErrorTestSites.readsFlags(cmovb, test));
	}

	/**
	 * Of the calls with a test after them, only those the flow reached with x21 clean stay, by
	 * address: not 0x1010 (x21 not clean), not 0x1020 (not reached). Too large a function (no
	 * flow) gives none.
	 */
	@Test
	public void keepsTestedCallsWithCleanRegister() {
		Address a = RAM.getAddress(0x1000);
		Address b = RAM.getAddress(0x1010);
		Address c = RAM.getAddress(0x1020);
		Address d = RAM.getAddress(0x1030);
		ErrorTestSites.Site direct = new ErrorTestSites.Site(d, RAM.getAddress(0x2000),
			RAM.getAddress(0x1034));
		ErrorTestSites.Site indirect = new ErrorTestSites.Site(a, null, RAM.getAddress(0x1004));
		List<ErrorTestSites.Site> tested = List.of(direct,
			new ErrorTestSites.Site(b, null, RAM.getAddress(0x1014)),
			new ErrorTestSites.Site(c, null, RAM.getAddress(0x1024)), indirect);
		CleanValues clean = CleanValues.entry(X21);
		Map<Address, CleanValues> flow = Map.of(a, clean, b, new CleanValues(Set.of(), Set.of()),
			d, clean);
		assertEquals(List.of(indirect, direct), ErrorTestSites.clean(tested, flow, X21));
		assertTrue(ErrorTestSites.clean(tested, null, X21).isEmpty());
	}
}
