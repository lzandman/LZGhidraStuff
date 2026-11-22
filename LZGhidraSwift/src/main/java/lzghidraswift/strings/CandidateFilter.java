// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Finds instructions that may build a Swift string word, by their p-code constants. Sleigh
 * folds the shift of {@code movk ..., lsl #48} into the constant, so one test covers
 * {@code mov}/{@code movk}/{@code orr} on AArch64 and {@code movabs} on x86_64.
 */
public final class CandidateFilter {

	/**
	 * Bit 63 of a large string's object word (address - 32, ORed in by the compiler). An
	 * instruction that moves or ORs this constant is a large-string candidate.
	 */
	static final long LARGE_STRING_FLAG = 0x8000_0000_0000_0000L;

	/**
	 * Candidate instructions of one function. {@code tagWords}: a small-string tag word, or the
	 * OR of a tag byte ({@link #isTagByte}). {@code largeStringOrs}: an OR of bit 63 as an
	 * immediate (AArch64 {@code orr}, {@code movk #0x8000, lsl #48}); the OR is then word 1 of a
	 * large string, if it is one. {@code largeFlagLoads}: bit 63 loaded into a register (x86_64
	 * {@code movabs}), which a later {@code orq} combines with the address; one load can serve
	 * several literals.
	 */
	public record Result(List<Address> tagWords, List<Address> largeStringOrs,
			List<Address> largeFlagLoads) {
		public boolean isEmpty() {
			return tagWords.isEmpty() && largeStringOrs.isEmpty() && largeFlagLoads.isEmpty();
		}
	}

	private CandidateFilter() {
	}

	/** Top nibble 0xE (small ASCII) or 0xA (small, not ASCII). */
	static boolean hasSmallTag(long value) {
		int nibble = (int) (value >>> 60);
		return nibble == 0xE || nibble == 0xA;
	}

	/**
	 * True for the constant of {@code orq $-0x1c, %rdi} before {@code shlq $0x38, %rdi}: the
	 * x86_64 tag word computed from a Bool, ((b & 1) | -0x1c) << 56, count 4 or 5. Its low byte
	 * is the tag byte, every other bit is set.
	 */
	static boolean isTagByte(long value) {
		return (value | 0xFF) == -1L && hasSmallTag(value << 56);
	}

	/** Finds the candidate instructions of {@code function}; see {@link Result}. */
	public static Result scan(Program program, Function function) {
		List<Address> tagWords = new ArrayList<>();
		List<Address> largeStringOrs = new ArrayList<>();
		List<Address> largeFlagLoads = new ArrayList<>();
		InstructionIterator it = program.getListing().getInstructions(function.getBody(), true);
		while (it.hasNext()) {
			Instruction instr = it.next();
			int kinds = constantKinds(instr);
			if ((kinds & TAG) != 0) {
				tagWords.add(instr.getAddress());
			}
			if ((kinds & LARGE_OR) != 0) {
				largeStringOrs.add(instr.getAddress());
			}
			else if ((kinds & LARGE_LOAD) != 0) {
				largeFlagLoads.add(instr.getAddress());
			}
		}
		return new Result(tagWords, largeStringOrs, largeFlagLoads);
	}

	/** Bits of {@link #constantKinds}. */
	private static final int TAG = 1;
	private static final int LARGE_OR = 2;
	private static final int LARGE_LOAD = 4;

	/** What the 64-bit constants that {@code instr} moves or ORs into registers can be. */
	private static int constantKinds(Instruction instr) {
		int kinds = 0;
		for (PcodeOp op : instr.getPcode()) {
			// Only constants that are moved or ORed into a register: mov, movk, orr, movabs.
			// This leaves out the masks of and (frame pointer bit 60 in async functions) and
			// rbit, and the p-code temporaries of x86 tzcnt (inputTmp | 0x8000000000000000).
			if ((op.getOpcode() != PcodeOp.COPY && op.getOpcode() != PcodeOp.INT_OR) ||
				op.getOutput() == null || !op.getOutput().isRegister()) {
				continue;
			}
			for (Varnode in : op.getInputs()) {
				if (in.isConstant() && in.getSize() == 8) {
					kinds |= constantKind(in.getOffset(), op.getOpcode());
				}
			}
		}
		return kinds;
	}

	private static int constantKind(long v, int opcode) {
		int kind = hasSmallTag(v) || (opcode == PcodeOp.INT_OR && isTagByte(v)) ? TAG : 0;
		// AArch64 ORs the immediate (orr, or movk #0x8000, lsl #48); x86_64 loads it with movabs
		// into a register and ORs that register (orq %r14, %rsi).
		if (v == LARGE_STRING_FLAG) {
			kind |= opcode == PcodeOp.INT_OR ? LARGE_OR : LARGE_LOAD;
		}
		return kind;
	}
}
