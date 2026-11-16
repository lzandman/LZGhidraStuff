// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.flow;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Whether a function reads the value that a register holds at its entry: the check that a
 * struct or enum method gets {@code self} in the context register (x20, r13). A non-mutating
 * method of a loadable struct gets its value in the argument registers; it only saves and
 * restores x20 (a callee-saved register) or reuses it after writing it.
 * <p>
 * Walks the instructions from the entry over their p-code, along jumps and fall-throughs (after
 * a call too: the register is callee-saved), until each path writes the register or returns. A
 * read is any input that overlaps the register (x20 or w20), except the value of a STORE: the
 * prologue's {@code stp x20, x19, [sp, #-0x20]!} or {@code push r13}.
 */
public final class SelfRegisterUse {

	/** Instructions examined per function. */
	static final int LIMIT = 4000;

	private SelfRegisterUse() {
	}

	/** True if some path from the entry reads the entry value of {@code register}. */
	public static boolean readsEntryValue(Function function, Register register) {
		Listing listing = function.getProgram().getListing();
		AddressRange reg = PcodeOps.range(register);
		Deque<Address> work = new ArrayDeque<>();
		Set<Address> seen = new HashSet<>();
		work.push(function.getEntryPoint());
		int count = 0;
		while (!work.isEmpty()) {
			Address at = work.pop();
			if (!seen.add(at) || !function.getBody().contains(at)) {
				continue;
			}
			Instruction instr = listing.getInstructionAt(at);
			if (instr == null || ++count > LIMIT) {
				return false;
			}
			Effect effect = effect(instr, reg);
			if (effect == Effect.READ) {
				return true;
			}
			if (effect == Effect.NONE) {
				// Also the fall-through after a call: x20 is callee-saved.
				for (Address next : ForwardFlow.successors(instr)) {
					work.push(next);
				}
			}
		}
		return false;
	}

	private enum Effect {
		READ, WRITTEN, NONE
	}

	/** Whether {@code instr} reads the register first, writes it first, or does neither. */
	private static Effect effect(Instruction instr, AddressRange reg) {
		// Temporaries that hold a copy of the register: AArch64's stp copies x20 to a unique
		// before the STORE.
		Set<Long> copies = new HashSet<>();
		for (PcodeOp op : instr.getPcode()) {
			Varnode out = op.getOutput();
			if (readsRegister(op, reg, copies)) {
				if (op.getOpcode() != PcodeOp.COPY || out == null || !out.isUnique()) {
					return Effect.READ;
				}
				copies.add(out.getOffset());
				continue;
			}
			if (out != null && out.isUnique()) {
				copies.remove(out.getOffset());
			}
			if (PcodeOps.overlaps(out, reg)) {
				return Effect.WRITTEN;
			}
		}
		return Effect.NONE;
	}

	/** True if an input of {@code op} other than a STORE's value is the register or a copy. */
	private static boolean readsRegister(PcodeOp op, AddressRange reg, Set<Long> copies) {
		for (int i = 0; i < op.getNumInputs(); i++) {
			if (PcodeOps.isStoredValue(op, i)) {
				continue; // a save
			}
			Varnode in = op.getInput(i);
			if (PcodeOps.overlaps(in, reg) || (in.isUnique() && copies.contains(in.getOffset()))) {
				return true;
			}
		}
		return false;
	}
}
