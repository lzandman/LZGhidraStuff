// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.flow;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

/**
 * Hand-built p-code for the tests in {@code flow} and {@code throwing}, with the register
 * offsets of Ghidra 12.2's AARCH64 and x86-64 languages (the same as in 12.1.4).
 */
public final class PcodeFixtures {

	public static final AddressSpace RAM =
		new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 1);
	public static final AddressSpace REG =
		new GenericAddressSpace("register", 32, AddressSpace.TYPE_REGISTER, 2);
	public static final AddressSpace CONST =
		new GenericAddressSpace("const", 64, AddressSpace.TYPE_CONSTANT, 0);
	public static final AddressSpace UNIQUE =
		new GenericAddressSpace("unique", 32, AddressSpace.TYPE_UNIQUE, 3);

	public static final Varnode SP = reg(0x8, 8);
	public static final Varnode X0 = reg(0x4000, 8);
	public static final Varnode X19 = reg(0x4098, 8);
	public static final Varnode X21 = reg(0x40a8, 8);
	public static final Varnode W21 = reg(0x40a8, 4);
	public static final Varnode X22 = reg(0x40b0, 8);
	public static final Varnode X29 = reg(0x40e8, 8);
	public static final Varnode R12 = reg(0xa0, 8);
	public static final Varnode R12D = reg(0xa0, 4);
	public static final Varnode CF = reg(0x200, 1);
	public static final Varnode ZF = reg(0x206, 1);
	public static final Varnode SPACE = constant(0x1b1, 8);

	private PcodeFixtures() {
	}

	public static Varnode reg(long offset, int size) {
		return new Varnode(REG.getAddress(offset), size);
	}

	public static Varnode constant(long value, int size) {
		return new Varnode(CONST.getAddress(value), size);
	}

	public static Varnode unique(long offset, int size) {
		return new Varnode(UNIQUE.getAddress(offset), size);
	}

	public static AddressRange range(long offset, int size) {
		return new AddressRangeImpl(REG.getAddress(offset), REG.getAddress(offset + size - 1));
	}

	public static AddressRange rangeOf(Varnode v) {
		return range(v.getOffset(), v.getSize());
	}

	public static PcodeOp op(int opcode, Varnode out, Varnode... in) {
		return new PcodeOp(new SequenceNumber(RAM.getAddress(0x1000), 0), opcode, in, out);
	}

	public static PcodeOp[] ops(PcodeOp... ops) {
		return ops;
	}

	/** bl: the return address in x30, then the call. */
	public static PcodeOp[] bl() {
		return ops(op(PcodeOp.INT_ADD, reg(0x40f0, 8), constant(0xc40, 8), constant(4, 8)),
			op(PcodeOp.CALL, null, new Varnode(RAM.getAddress(0x9f4), 8)));
	}

	/** {@code str value, [base, #offset]} (also stur): the address in a unique, then the STORE. */
	public static PcodeOp[] store(Varnode value, Varnode base, long offset) {
		Varnode addr = unique(0xf000, 8);
		return ops(op(PcodeOp.INT_ADD, addr, base, constant(offset, 8)),
			op(PcodeOp.STORE, null, SPACE, addr, value));
	}

	/** {@code ldr reg, [base, #offset]} (also ldur). */
	public static PcodeOp[] load(Varnode reg, Varnode base, long offset) {
		Varnode addr = unique(0xf000, 8);
		return ops(op(PcodeOp.INT_ADD, addr, base, constant(offset, 8)),
			op(PcodeOp.LOAD, reg, SPACE, addr));
	}
}
