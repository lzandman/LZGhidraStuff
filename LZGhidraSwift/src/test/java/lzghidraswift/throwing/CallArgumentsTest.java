// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.throwing;

import static lzghidraswift.flow.PcodeFixtures.SP;
import static lzghidraswift.flow.PcodeFixtures.SPACE;
import static lzghidraswift.flow.PcodeFixtures.X0;
import static lzghidraswift.flow.PcodeFixtures.X22;
import static lzghidraswift.flow.PcodeFixtures.X29;
import static lzghidraswift.flow.PcodeFixtures.bl;
import static lzghidraswift.flow.PcodeFixtures.constant;
import static lzghidraswift.flow.PcodeFixtures.op;
import static lzghidraswift.flow.PcodeFixtures.ops;
import static lzghidraswift.flow.PcodeFixtures.range;
import static lzghidraswift.flow.PcodeFixtures.reg;
import static lzghidraswift.flow.PcodeFixtures.store;
import static lzghidraswift.flow.PcodeFixtures.unique;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import lzghidraswift.throwing.CallArguments.Arguments;
import lzghidraswift.throwing.CallArguments.Kind;
import lzghidraswift.throwing.CallArguments.Registers;

/**
 * {@link ArgumentValues} and {@link CallArguments#arguments} on the AArch64 p-code of the
 * instructions in the comments (Ghidra 12.1.4; 12.2 did not change them).
 */
public class CallArgumentsTest {

	private static final Varnode X1 = reg(0x4008, 8);
	private static final Varnode X2 = reg(0x4010, 8);
	private static final Varnode X8 = reg(0x4040, 8);
	private static final Varnode X20 = reg(0x40a0, 8);
	private static final Varnode D0 = reg(0x5000, 8);
	private static final Varnode Q0 = reg(0x5000, 16);

	private static final Registers REGISTERS = registers();

	private static Registers registers() {
		List<Varnode> integers = new ArrayList<>();
		List<Varnode> floats = new ArrayList<>();
		for (int i = 0; i < 8; i++) {
			integers.add(reg(0x4000 + 8 * i, 8));
			floats.add(reg(0x5000 + 0x20 * i, 8));
		}
		return new Registers(integers, floats, X8, X20, SP, Set.of(SP, X29),
			List.of(range(0x4000, 19 * 8), range(0x5000, 8 * 0x20)), 0);
	}

	private static ArgumentValues run(ArgumentValues state, PcodeOp[]... instructions) {
		ArgumentValues s = state;
		for (PcodeOp[] ops : instructions) {
			s = s.after(ops, REGISTERS);
		}
		return s;
	}

	private static ArgumentValues start() {
		return ArgumentValues.entry(Set.of());
	}

	/** add x0, sp, #0x50: the constant goes through a unique, the flags are set. */
	private static PcodeOp[] addSp(Varnode out, long offset) {
		Varnode c = unique(0x23600, 8);
		Varnode sum = unique(0x23800, 8);
		return ops(op(PcodeOp.COPY, c, constant(offset, 8)),
			op(PcodeOp.INT_CARRY, reg(0x105, 1), SP, c), op(PcodeOp.INT_ADD, sum, SP, c),
			op(PcodeOp.COPY, out, sum));
	}

	/** blr reg: the return address in x30, then the call through the register. */
	private static PcodeOp[] blr(Varnode target) {
		return ops(op(PcodeOp.INT_ADD, reg(0x40f0, 8), constant(0xc40, 8), constant(4, 8)),
			op(PcodeOp.CALLIND, null, target));
	}

	private static PcodeOp[] mov(Varnode out, Varnode in) {
		return ops(op(PcodeOp.COPY, out, in));
	}

	@Test
	public void stackAddresses() {
		// add x0, sp, #0x50; mov x1, sp; sub x2, x29, #0x78
		ArgumentValues s = run(start(), addSp(X0, 0x50), mov(X1, SP),
			ops(op(PcodeOp.INT_SUB, X2, X29, constant(0x78, 8))));
		assertEquals(Map.of(X0, Kind.STACK, X1, Kind.STACK, X2, Kind.STACK), s.arguments());
		// mov x22, sp; mov x0, x22: through a register that is no argument
		s = run(start(), mov(X22, SP), mov(X0, X22));
		assertEquals(Map.of(X0, Kind.STACK), s.arguments());
		// mov x0, x22 without a stack address in x22
		assertEquals(Map.of(X0, Kind.VALUE), run(start(), mov(X0, X22)).arguments());
	}

	/** mov x0, x22; add x9, x0, #1: x0 was a temporary. A save (str x0, [sp]) is no read. */
	@Test
	public void readRemovesSaveDoesNot() {
		Varnode x9 = reg(0x4048, 8);
		ArgumentValues s = run(start(), mov(X0, X22),
			ops(op(PcodeOp.INT_ADD, x9, X0, constant(1, 8))));
		assertEquals(Map.of(), s.arguments());
		s = run(start(), mov(X0, X22), store(X0, SP, 8));
		assertEquals(Map.of(X0, Kind.VALUE), s.arguments());
	}

	/** A call keeps only the self register; its results are no arguments of the next call. */
	@Test
	public void callKeepsSelfOnly() {
		ArgumentValues s = run(start(), mov(X0, SP), mov(X20, X22), mov(D0, X22), bl());
		assertEquals(Map.of(X20, Kind.VALUE), s.arguments());
		assertEquals(Set.of(), s.stackAddresses());
		// mov x22, sp is in a callee-saved register and survives the call.
		s = run(start(), mov(X22, SP), bl(), mov(X0, X22));
		assertEquals(Map.of(X0, Kind.STACK), s.arguments());
	}

	/**
	 * callBig in the fixture: x0 is the caller's parameter passed on, x1 the target, x2 the
	 * context. add x8, sp, #0x8; mov x20, x2; blr x1.
	 */
	@Test
	public void entryParametersAndTarget() {
		ArgumentValues s = run(ArgumentValues.entry(Set.of(X0, X1, X2)), addSp(X8, 8),
			mov(X20, X2));
		ArgumentValues atCall = s.atCall(blr(X1), REGISTERS);
		assertEquals(Map.of(X0, Kind.ENTRY, X8, Kind.STACK, X20, Kind.VALUE),
			atCall.arguments());
		Arguments args = CallArguments.arguments(atCall, REGISTERS);
		assertEquals(List.of(Kind.ENTRY), args.integers());
		assertEquals(Kind.STACK, args.indirectResult());
		assertEquals(Kind.VALUE, args.context());
	}

	/**
	 * As callInout, without its read of x2: mov x8, x0; add x0, sp, #0x10; mov x20, x1; blr x8.
	 * The target in x8 is no indirect result.
	 */
	@Test
	public void targetIsNoIndirectResult() {
		ArgumentValues s = run(ArgumentValues.entry(Set.of(X0, X1, X2)), mov(X8, X0),
			addSp(X0, 0x10), mov(X20, X1));
		Arguments args = CallArguments.arguments(s.atCall(blr(X8), REGISTERS), REGISTERS);
		assertNull(args.indirectResult());
		// x2 is still the caller's parameter: a gap in x1 before it.
		assertEquals(List.of(Kind.STACK, Kind.VALUE, Kind.ENTRY), args.integers());
	}

	/** A write of q0 counts for d0; the floats are listed up to the last one. */
	@Test
	public void floatArguments() {
		ArgumentValues s = run(start(), mov(Q0, constant(0, 16)));
		Arguments args = CallArguments.arguments(s, REGISTERS);
		assertEquals(List.of(Kind.VALUE), args.floats());
		assertEquals(List.of(), args.integers());
		// x20 is not written: the context is an argument all the same.
		assertEquals(Kind.VALUE, args.context());
	}

	/** stp x10, x11, [sp]: two copies to uniques, then the STOREs at sp + 0 and sp + 8. */
	private static PcodeOp[] stpAtSp(Varnode a, Varnode b) {
		Varnode u1 = unique(0x74000, 8);
		Varnode u2 = unique(0x74100, 8);
		Varnode addr = unique(0xf000, 8);
		Varnode addr2 = unique(0x74200, 8);
		return ops(op(PcodeOp.COPY, u1, a), op(PcodeOp.COPY, u2, b),
			op(PcodeOp.INT_ADD, addr, SP, constant(0, 8)),
			op(PcodeOp.STORE, null, SPACE, addr, u1),
			op(PcodeOp.INT_ADD, addr2, addr, constant(8, 8)),
			op(PcodeOp.STORE, null, SPACE, addr2, u2));
	}

	/**
	 * callManyArgs in the fixture: add x10, x2, #0x8; add x11, x2, #0x9; stp x10, x11, [sp],
	 * then x0 to x7, x20 and blr x9. Ten arguments: eight in registers, two on the stack.
	 */
	@Test
	public void stackArguments() {
		Varnode x9 = reg(0x4048, 8);
		Varnode x10 = reg(0x4050, 8);
		Varnode x11 = reg(0x4058, 8);
		ArgumentValues computed = run(ArgumentValues.entry(Set.of(X2)),
			ops(op(PcodeOp.INT_ADD, x10, X2, constant(8, 8))),
			ops(op(PcodeOp.INT_ADD, x11, X2, constant(9, 8))));
		ArgumentValues s = run(computed, stpAtSp(x10, x11));
		for (Varnode r : REGISTERS.integers()) {
			s = run(s, mov(r, X22));
		}
		s = run(s, mov(X20, X22));
		Arguments args = CallArguments.arguments(s.atCall(blr(x9), REGISTERS), REGISTERS);
		assertEquals(8, args.integers().size());
		assertEquals(2, args.stackArguments());
		// Fewer integer registers: the slots are locals, not arguments.
		s = run(computed, stpAtSp(x10, x11), mov(X0, X22));
		assertEquals(0, CallArguments.arguments(s, REGISTERS).stackArguments());
		// A call removes the slots; sub sp, sp, #0x10 moves them by 0x10.
		assertEquals(Set.of(), run(computed, stpAtSp(x10, x11), bl()).stackSlots());
		assertEquals(Set.of(0x10L, 0x18L), run(computed, stpAtSp(x10, x11),
			ops(op(PcodeOp.INT_SUB, SP, SP, constant(0x10, 8)))).stackSlots());
		// mov sp, x29: another write of the stack pointer.
		assertEquals(Set.of(), run(computed, stpAtSp(x10, x11), mov(SP, X29)).stackSlots());
	}

	/**
	 * -Onone: mov x10, sp; str x11, [x10]; str x9, [x10, #0x8]. Through a copy of sp, also
	 * after sp moves; a call clears the copy in the volatile x10.
	 */
	@Test
	public void stackArgumentsThroughCopy() {
		Varnode x9 = reg(0x4048, 8);
		Varnode x10 = reg(0x4050, 8);
		Varnode x11 = reg(0x4058, 8);
		ArgumentValues computed = run(ArgumentValues.entry(Set.of(X2)),
			ops(op(PcodeOp.INT_ADD, x9, X2, constant(9, 8))),
			ops(op(PcodeOp.INT_ADD, x11, X2, constant(8, 8))));
		assertEquals(Set.of(0L, 8L),
			run(computed, mov(x10, SP), store(x11, x10, 0), store(x9, x10, 8)).stackSlots());
		assertEquals(Set.of(0x10L), run(computed, mov(x10, SP),
			ops(op(PcodeOp.INT_SUB, SP, SP, constant(0x10, 8))), store(x11, x10, 0))
					.stackSlots());
		assertEquals(Set.of(), run(computed, mov(x10, SP), bl(), store(x11, x10, 0))
				.stackSlots());
	}

	/**
	 * stp x22, x10, [sp]: x22 still holds its entry value, a save; x10 was computed. A
	 * parameter (x2) stored is a slot, and after a call x0 is the callee's result, also a slot.
	 */
	@Test
	public void savesAreNoStackArguments() {
		Varnode x10 = reg(0x4050, 8);
		ArgumentValues s = run(ArgumentValues.entry(Set.of(X2)),
			ops(op(PcodeOp.INT_ADD, x10, X2, constant(8, 8))), stpAtSp(X22, x10));
		assertEquals(Set.of(8L), s.stackSlots());
		assertEquals(Set.of(0L), run(ArgumentValues.entry(Set.of(X2)), store(X2, SP, 0))
				.stackSlots());
		assertEquals(Set.of(0L), run(start(), bl(), store(X0, SP, 0)).stackSlots());
	}

	@Test
	public void meet() {
		ArgumentValues a = run(start(), mov(X0, SP), mov(X1, X22), mov(X22, SP));
		ArgumentValues b = run(start(), mov(X0, X22), mov(X22, SP));
		ArgumentValues m = a.meet(b);
		assertEquals(Map.of(X0, Kind.VALUE), m.arguments());
		assertEquals(Set.of(X22), m.stackAddresses());
		assertEquals(m, b.meet(a));
		assertEquals(a, a.meet(a));
	}
}
