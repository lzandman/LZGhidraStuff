// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.throwing;

import static lzghidraswift.flow.PcodeFixtures.CF;
import static lzghidraswift.flow.PcodeFixtures.R12;
import static lzghidraswift.flow.PcodeFixtures.R12D;
import static lzghidraswift.flow.PcodeFixtures.SP;
import static lzghidraswift.flow.PcodeFixtures.W21;
import static lzghidraswift.flow.PcodeFixtures.X0;
import static lzghidraswift.flow.PcodeFixtures.X19;
import static lzghidraswift.flow.PcodeFixtures.X21;
import static lzghidraswift.flow.PcodeFixtures.X29;
import static lzghidraswift.flow.PcodeFixtures.ZF;
import static lzghidraswift.flow.PcodeFixtures.bl;
import static lzghidraswift.flow.PcodeFixtures.constant;
import static lzghidraswift.flow.PcodeFixtures.load;
import static lzghidraswift.flow.PcodeFixtures.op;
import static lzghidraswift.flow.PcodeFixtures.ops;
import static lzghidraswift.flow.PcodeFixtures.range;
import static lzghidraswift.flow.PcodeFixtures.store;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.Test;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import lzghidraswift.flow.PcodeFixtures;

/** {@link CleanValues#after} on the p-code of the instructions in the comments. */
public class CleanValuesTest {

	/** x0 to x18 on AArch64, as CallingConventions.volatileRegisters names them. */
	private static final List<AddressRange> KILLED = List.of(range(0x4000, 19 * 8));

	private static CleanValues after(PcodeOp[] ops, CleanValues in) {
		return in.after(ops, KILLED);
	}

	private static Set<Varnode> registers(PcodeOp[] ops, Set<Varnode> in) {
		return after(ops, new CleanValues(in, Set.of())).registers();
	}

	/** mov x21, #0x0 */
	@Test
	public void movZeroMakesTheRegisterClean() {
		assertEquals(Set.of(X21), registers(ops(op(PcodeOp.COPY, X21, constant(0, 8))), Set.of()));
	}

	@Test
	public void otherValueOrPartialWriteIsNotClean() {
		// mov x21, x0
		assertEquals(Set.of(), registers(ops(op(PcodeOp.COPY, X21, X0)), Set.of(X21)));
		// mov w21, #0x1 (typed throws: a flag)
		assertEquals(Set.of(),
			registers(ops(op(PcodeOp.INT_ZEXT, X21, constant(1, 4))), Set.of(X21)));
		// A write of the low half alone leaves the full register not clean.
		assertEquals(Set.of(W21),
			registers(ops(op(PcodeOp.COPY, W21, constant(0, 4))), Set.of(X21)));
	}

	/** xor r12d, r12d: R12D = R12D ^ R12D, then R12 = zext(R12D), with flags in between. */
	@Test
	public void x86XorOfTheLowHalfZeroesTheWholeRegister() {
		PcodeOp[] xor = ops(op(PcodeOp.COPY, CF, constant(0, 1)),
			op(PcodeOp.INT_XOR, R12D, R12D, R12D), op(PcodeOp.INT_ZEXT, R12, R12D),
			op(PcodeOp.INT_EQUAL, ZF, R12D, constant(0, 4)));
		// CF = 0 is a clean 1-byte register too.
		assertEquals(Set.of(CF, R12), registers(xor, Set.of()));
	}

	/**
	 * A throwing function keeps its entry x21 (0 by the ABI) in x19 across calls and puts it back
	 * before the throwing call: mov x19, x21; mov x21, x0; bl; mov x21, x19.
	 */
	@Test
	public void cleanCopyInACalleeSavedRegisterSurvivesACall() {
		Set<Varnode> s = registers(ops(op(PcodeOp.COPY, X19, X21)), Set.of(X21));
		assertEquals(Set.of(X19, X21), s);
		s = registers(ops(op(PcodeOp.COPY, X21, X0)), s);
		assertEquals(Set.of(X19), s);
		s = registers(bl(), s);
		assertEquals(Set.of(X19), s);
		s = registers(ops(op(PcodeOp.COPY, X21, X19)), s);
		assertEquals(Set.of(X19, X21), s);
	}

	@Test
	public void callKillsCleanVolatileRegisters() {
		Set<Varnode> s = registers(ops(op(PcodeOp.COPY, X0, constant(0, 8))), Set.of(X21));
		assertEquals(Set.of(X0, X21), s);
		assertEquals(Set.of(X21), registers(bl(), s));
	}

	/**
	 * A throwing function spills its entry x21 and loads it back before a throwing call:
	 * stur x21, [x29, #-0x80]; mov x21, x0; bl; ldur x21, [x29, #-0x80].
	 */
	@Test
	public void cleanValueSurvivesASpillToTheStack() {
		CleanValues s = after(store(X21, X29, -0x80), CleanValues.entry(X21));
		assertEquals(Set.of(new CleanValues.StackSlot(X29, -0x80, 8)), s.slots());
		s = after(ops(op(PcodeOp.COPY, X21, X0)), s);
		s = after(bl(), s);
		assertFalse(s.contains(X21));
		s = after(load(X21, X29, -0x80), s);
		assertTrue(s.contains(X21));
		// Another offset, or a load of another size, is not the slot.
		assertFalse(after(load(X21, X29, -0x78), s).contains(X21));
		assertFalse(after(load(W21, X29, -0x80), s).contains(W21));
	}

	@Test
	public void slotIsDroppedByAnOverlappingStoreOrAWriteToItsBase() {
		CleanValues s = after(store(X21, SP, 8), CleanValues.entry(X21));
		assertEquals(1, s.slots().size());
		// str w0, [sp, #0xc]: the upper half of the slot.
		assertEquals(Set.of(), after(store(reg4(), SP, 0xc), s).slots());
		// sub sp, sp, #0x10
		assertEquals(Set.of(), after(ops(op(PcodeOp.INT_SUB, SP, SP, constant(0x10, 8))), s)
				.slots());
		// A store through another base is not seen.
		assertEquals(s.slots(), after(store(X0, X29, 8), s).slots());
	}

	private static Varnode reg4() {
		return PcodeFixtures.reg(0x4000, 4);
	}

	@Test
	public void meetKeepsWhatIsCleanOnBothPaths() {
		CleanValues a =
			new CleanValues(Set.of(X19, X21), Set.of(new CleanValues.StackSlot(SP, 8, 8)));
		CleanValues b = new CleanValues(Set.of(X21), Set.of());
		CleanValues m = a.meet(b);
		assertEquals(Set.of(X21), m.registers());
		assertEquals(Set.of(), m.slots());
		assertEquals(1, m.size());
	}
}
