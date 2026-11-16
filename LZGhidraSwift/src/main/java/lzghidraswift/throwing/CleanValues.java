// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.throwing;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import lzghidraswift.flow.PcodeOps;

/**
 * The registers and stack slots that hold a "clean" value at one point of a function, for
 * {@link ErrorTestSites}: 0, or the entry value of the error register, which is 0 by the ABI in a
 * throwing function. Immutable, compared by value; {@link #after} gives the state after one
 * instruction.
 * <p>
 * A stack slot is a base register and an offset, as in {@code str x21, [sp, #0x8]} or
 * {@code stur x21, [x29, #-0x80]}: a throwing function that keeps its entry x21 across a loop
 * spills it there. A write to the base register drops its slots. A store through another
 * register to the same memory is not seen.
 */
record CleanValues(Set<Varnode> registers, Set<StackSlot> slots) {

	/** A stack slot: {@code size} bytes at {@code base + offset}. */
	record StackSlot(Varnode base, long offset, int size) {
		boolean overlaps(StackSlot o) {
			return base.equals(o.base) && offset < o.offset + o.size && o.offset < offset + size;
		}
	}

	CleanValues {
		registers = Set.copyOf(registers);
		slots = Set.copyOf(slots);
	}

	/** The state at a function's entry: only the error register is clean. */
	static CleanValues entry(Varnode error) {
		return new CleanValues(Set.of(error), Set.of());
	}

	/** True if exactly this register varnode is clean. */
	boolean contains(Varnode register) {
		return registers.contains(register);
	}

	/** The values clean in both states: a value is clean only if it is on every path. */
	CleanValues meet(CleanValues o) {
		Set<Varnode> r = new HashSet<>(registers);
		r.retainAll(o.registers);
		Set<StackSlot> s = new HashSet<>(slots);
		s.retainAll(o.slots);
		return new CleanValues(r, s);
	}

	/** The number of clean values; {@link #meet} never makes it larger. */
	int size() {
		return registers.size() + slots.size();
	}

	/**
	 * The state after the p-code of one instruction. A register written by the instruction is
	 * clean if the value is: a constant 0, a copy or extension of a clean value, an XOR or
	 * difference of a varnode with itself or of two clean values, an AND with 0, or a load from
	 * a clean slot. A store of a clean value makes its slot clean, any other store to the slot
	 * removes it. A call removes the registers that overlap {@code killed} and keeps the slots.
	 * Varnodes are compared exactly: a clean {@code x19} does not make {@code w19} clean.
	 */
	CleanValues after(PcodeOp[] ops, List<AddressRange> killed) {
		Set<Varnode> clean = new HashSet<>(registers);
		Set<StackSlot> cleanSlots = new HashSet<>(slots);
		// Register-relative addresses computed inside the instruction: varnode -> base, offset.
		Map<Varnode, StackSlot> addresses = new HashMap<>();
		for (PcodeOp op : ops) {
			int opcode = op.getOpcode();
			if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
				clean.removeIf(v -> killed.stream().anyMatch(r -> PcodeOps.overlaps(v, r)));
				continue;
			}
			if (opcode == PcodeOp.STORE) {
				Varnode value = op.getInput(2);
				StackSlot slot = slot(op.getInput(1), value.getSize(), addresses);
				if (slot != null) {
					cleanSlots.removeIf(slot::overlaps);
					if (isClean(value, clean)) {
						cleanSlots.add(slot);
					}
				}
				continue;
			}
			Varnode out = op.getOutput();
			if (out == null) {
				continue;
			}
			boolean value = isClean(op, clean) || (opcode == PcodeOp.LOAD &&
				cleanSlots.contains(slot(op.getInput(1), out.getSize(), addresses)));
			StackSlot address = address(op, addresses);
			clean.removeIf(v -> v.intersects(out));
			cleanSlots.removeIf(s -> s.base().intersects(out));
			addresses.keySet().removeIf(v -> v.intersects(out));
			if (value) {
				clean.add(out);
			}
			if (address != null) {
				addresses.put(out, address);
			}
		}
		clean.removeIf(Varnode::isUnique);
		return new CleanValues(clean, cleanSlots);
	}

	/** The register-relative address that {@code op} computes, or null. */
	private static StackSlot address(PcodeOp op, Map<Varnode, StackSlot> addresses) {
		int opcode = op.getOpcode();
		if (opcode == PcodeOp.COPY) {
			return base(op.getInput(0), addresses);
		}
		if ((opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB) &&
			op.getInput(1).isConstant()) {
			StackSlot base = base(op.getInput(0), addresses);
			if (base == null) {
				return null;
			}
			long c = op.getInput(1).getOffset();
			long offset = opcode == PcodeOp.INT_ADD ? base.offset() + c : base.offset() - c;
			return new StackSlot(base.base(), offset, 0);
		}
		return null;
	}

	/** {@code v} as a register-relative address: a register (offset 0) or a computed address. */
	private static StackSlot base(Varnode v, Map<Varnode, StackSlot> addresses) {
		if (v.isRegister()) {
			return new StackSlot(v, 0, 0);
		}
		return addresses.get(v);
	}

	/** The slot of {@code size} bytes at the address {@code v}, or null if not register-relative. */
	private static StackSlot slot(Varnode v, int size, Map<Varnode, StackSlot> addresses) {
		StackSlot a = base(v, addresses);
		return a == null ? null : new StackSlot(a.base(), a.offset(), size);
	}

	private static boolean isClean(PcodeOp op, Set<Varnode> clean) {
		return switch (op.getOpcode()) {
			case PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT -> isClean(op.getInput(0), clean);
			case PcodeOp.INT_XOR, PcodeOp.INT_SUB -> op.getInput(0).equals(op.getInput(1)) ||
				(isClean(op.getInput(0), clean) && isClean(op.getInput(1), clean));
			case PcodeOp.INT_AND -> isZero(op.getInput(0)) || isZero(op.getInput(1));
			default -> false;
		};
	}

	private static boolean isClean(Varnode v, Set<Varnode> clean) {
		return isZero(v) || clean.contains(v);
	}

	private static boolean isZero(Varnode v) {
		return v.isConstant() && v.getOffset() == 0;
	}
}
