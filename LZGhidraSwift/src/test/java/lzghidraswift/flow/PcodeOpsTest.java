// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.flow;

import static lzghidraswift.flow.PcodeFixtures.REG;
import static lzghidraswift.flow.PcodeFixtures.SP;
import static lzghidraswift.flow.PcodeFixtures.SPACE;
import static lzghidraswift.flow.PcodeFixtures.W21;
import static lzghidraswift.flow.PcodeFixtures.X21;
import static lzghidraswift.flow.PcodeFixtures.X22;
import static lzghidraswift.flow.PcodeFixtures.constant;
import static lzghidraswift.flow.PcodeFixtures.op;
import static lzghidraswift.flow.PcodeFixtures.ops;
import static lzghidraswift.flow.PcodeFixtures.rangeOf;
import static lzghidraswift.flow.PcodeFixtures.unique;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/** The p-code tests of {@link PcodeOps} on the instructions in the comments. */
public class PcodeOpsTest {

	/** x21 covers the 8 bytes from its offset. */
	@Test
	public void range() {
		Register x21 = new Register("x21", "", REG.getAddress(X21.getOffset()), 8, false, 0);
		AddressRange r = PcodeOps.range(x21);
		assertEquals(X21.getOffset(), r.getMinAddress().getOffset());
		assertEquals(8, r.getLength());
	}

	/** w21 overlaps x21; x22, the constant and null do not, nor a unique at x21's offset. */
	@Test
	public void overlaps() {
		AddressRange x21 = rangeOf(X21);
		assertTrue(PcodeOps.overlaps(X21, x21));
		assertTrue(PcodeOps.overlaps(W21, x21));
		assertTrue(PcodeOps.overlaps(X21, rangeOf(W21)));
		assertFalse(PcodeOps.overlaps(X22, x21));
		assertFalse(PcodeOps.overlaps(constant(X21.getOffset(), 8), x21));
		assertFalse(PcodeOps.overlaps(unique(X21.getOffset(), 8), x21));
		assertFalse(PcodeOps.overlaps(null, x21));
	}

	/** str x21, [sp, #0x8]: input 2 of the STORE is the value; input 1 the address. */
	@Test
	public void storedValue() {
		Varnode addr = unique(0xf000, 8);
		PcodeOp store = op(PcodeOp.STORE, null, SPACE, addr, X21);
		assertTrue(PcodeOps.isStoredValue(store, 2));
		assertFalse(PcodeOps.isStoredValue(store, 1));
		assertFalse(PcodeOps.isStoredValue(op(PcodeOp.INT_ADD, addr, SP, constant(8, 8)), 1));
	}

	/**
	 * stp x22, x21, [sp, #0x10]: the copies to uniques are saves. A copy to a unique that
	 * another op reads, and a copy to a register, are not.
	 */
	@Test
	public void saveCopy() {
		Varnode u1 = unique(0x74000, 8);
		Varnode u2 = unique(0x74100, 8);
		Varnode addr = unique(0xf000, 8);
		PcodeOp copy1 = op(PcodeOp.COPY, u1, X22);
		PcodeOp copy2 = op(PcodeOp.COPY, u2, X21);
		PcodeOp[] stp = ops(copy1, copy2, op(PcodeOp.INT_ADD, addr, SP, constant(0x10, 8)),
			op(PcodeOp.STORE, null, SPACE, addr, u1),
			op(PcodeOp.STORE, null, SPACE, addr, u2));
		assertTrue(PcodeOps.isSaveCopy(copy1, stp));
		assertTrue(PcodeOps.isSaveCopy(copy2, stp));
		PcodeOp[] read = ops(copy2, op(PcodeOp.INT_ADD, addr, u2, constant(1, 8)),
			op(PcodeOp.STORE, null, SPACE, addr, u2));
		assertFalse(PcodeOps.isSaveCopy(copy2, read));
		PcodeOp toRegister = op(PcodeOp.COPY, X22, X21);
		assertFalse(PcodeOps.isSaveCopy(toRegister, ops(toRegister)));
	}
}
