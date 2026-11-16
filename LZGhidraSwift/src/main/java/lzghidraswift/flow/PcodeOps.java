// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.flow;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Tests on p-code ops and varnodes that several analyses need: whether a varnode overlaps a
 * register, and which inputs are only saved to memory.
 */
public final class PcodeOps {

	private PcodeOps() {
	}

	/** The register addresses of {@code register}, all its bytes. */
	public static AddressRange range(Register register) {
		Address base = register.getAddress();
		return new AddressRangeImpl(base, base.add(register.getMinimumByteSize() - 1));
	}

	/** True if {@code v} is a register varnode that shares a byte with {@code reg}. */
	public static boolean overlaps(Varnode v, AddressRange reg) {
		return v != null && v.isRegister() &&
			v.getAddress().getAddressSpace().equals(reg.getAddressSpace()) &&
			v.getOffset() <= reg.getMaxAddress().getOffset() &&
			v.getOffset() + v.getSize() - 1 >= reg.getMinAddress().getOffset();
	}

	/** True if input {@code i} of {@code op} is the value of a STORE: written, not read. */
	public static boolean isStoredValue(PcodeOp op, int i) {
		return op.getOpcode() == PcodeOp.STORE && i == 2;
	}

	/**
	 * True if {@code copy} is a COPY of a register into a unique that, in {@code ops}, only a
	 * STORE's value uses: AArch64's {@code stp} copies both registers before it stores them.
	 */
	public static boolean isSaveCopy(PcodeOp copy, PcodeOp[] ops) {
		Varnode out = copy.getOutput();
		if (copy.getOpcode() != PcodeOp.COPY || out == null || !out.isUnique()) {
			return false;
		}
		for (PcodeOp op : ops) {
			for (int i = 0; i < op.getNumInputs(); i++) {
				if (op.getInput(i).equals(out) && !isStoredValue(op, i)) {
					return false;
				}
			}
		}
		return true;
	}
}
