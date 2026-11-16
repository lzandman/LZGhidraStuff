// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

/**
 * Decodes the start of an AArch64 metadata accessor ({@code …Ma}) far enough to find the address
 * it returns. Plain Java over instruction words, so that it can be unit tested. Accessors of
 * non-generic types with static metadata look like this (Layouts fixture, Swift 6, -O):
 * <pre>
 * struct, enum:  adrp x0, page; add x0, x0, #off; mov x1, #0; ret
 * class:         stp x29, x30, [sp, #-16]!; mov x29, sp; adrp x0, page; add x0, x0, #off;
 *                bl objc_opt_self; mov x1, #0; ldp x29, x30, [sp], #16; ret
 * generic:       adrp x4, page; add x4, x4, #off; b swift_instantiateGenericMetadata
 * </pre>
 * In arm64e code (Layouts fixture built for arm64e), the class accessor starts with
 * {@code pacibsp} and returns with {@code retab}.
 * The decoder follows {@code adrp}, {@code add} (immediate), {@code ldr} (64-bit, unsigned
 * offset), {@code mov} (register and wide immediate), the frame setup and teardown, and the hints
 * that sign or check the return address. It stops at the first {@code ret} ({@code retaa},
 * {@code retab}), {@code bl}, {@code b} or any other instruction. Which call means static
 * metadata is decided by the caller ({@link MetadataLocator}), which knows the call targets' names.
 */
public final class AccessorDecoder {

	/** How the decoded sequence ends. */
	public enum Exit {
		/** {@code ret}: x0 holds the result. */
		RETURN,
		/** {@code bl}: a call, x0 holds its first argument. */
		CALL,
		/** {@code b}: a tail call, x0 holds its first argument. */
		TAIL_CALL,
		/** An instruction the decoder does not follow, or the words ran out. */
		UNRECOGNIZED
	}

	/** Reads a 64-bit value from the program, or returns null if the address is not readable. */
	@FunctionalInterface
	public interface Reader {
		Long read64(long address);
	}

	/**
	 * The end of the decoded sequence: {@code x0} is null if its value is not known,
	 * {@code target} is the call target ({@code CALL}, {@code TAIL_CALL}), {@code index} the
	 * instruction's index and {@code word} its encoding.
	 */
	public record Result(Exit exit, Long x0, long target, int index, int word) {}

	private static final int SP = 31;
	private static final int FP = 29;
	private static final int LR = 30;

	private AccessorDecoder() {
	}

	/**
	 * Decodes {@code words}, the instructions at {@code pc}. {@code memory} resolves {@code ldr}
	 * from a known address; it may be null, and then a load makes the register unknown.
	 */
	public static Result decode(long pc, int[] words, Reader memory) {
		Long[] x = new Long[32];
		for (int i = 0; i < words.length; i++) {
			Result end = step(x, pc + 4L * i, words[i], i, memory);
			if (end != null) {
				return end;
			}
		}
		return new Result(Exit.UNRECOGNIZED, null, 0, words.length, 0);
	}

	/**
	 * Executes the instruction {@code w} at {@code at} on the registers {@code x}. Returns the
	 * result if the sequence ends with it, else null.
	 */
	private static Result step(Long[] x, long at, int w, int i, Reader memory) {
		int rd = w & 31;
		if ((w & 0x9f000000) == 0x90000000) {
			// adrp: page of pc + sign-extended immhi:immlo << 12
			long imm = ((long) (((w >>> 5) & 0x7ffff) << 2 | ((w >>> 29) & 3)) << 43) >> 31;
			x[rd] = (at & ~0xfffL) + imm;
			return null;
		}
		if ((w & 0xff800000) == 0x91000000) {
			// add xd, xn, #imm12; the mask leaves out bit 22, so this matches both shifts (0 and 12)
			return addImmediate(x, w) ? null : unrecognized(i, w);
		}
		if ((w & 0xffc00000) == 0xf9400000) {
			return load(x, w, memory) ? null : unrecognized(i, w);
		}
		if ((w & 0xffe0ffe0) == 0xaa0003e0) {
			// mov xd, xm (orr xd, xzr, xm)
			int rm = (w >>> 16) & 31;
			x[rd] = rm == 31 ? Long.valueOf(0) : x[rm];
			return null;
		}
		if ((w & 0xff800000) == 0xd2800000) {
			// movz xd, #imm16, lsl #(hw * 16)
			x[rd] = (long) ((w >>> 5) & 0xffff) << (16 * ((w >>> 21) & 3));
			return null;
		}
		if (isReturnAddressHint(w)) {
			// pacibsp, autibsp and the like, bti: they change or check x30 only
			return null;
		}
		if (isFramePairWithSp(w)) {
			// stp/ldp x29, x30 or callee-saved registers, [sp, ...]: frame setup and teardown
			if ((w & 0x00400000) != 0) {
				x[w & 31] = null;
				x[(w >>> 10) & 31] = null;
			}
			return null;
		}
		if (w == 0xd65f03c0 || w == 0xd65f0bff || w == 0xd65f0fff) {
			// ret, retaa, retab
			return new Result(Exit.RETURN, x[0], 0, i, w);
		}
		if ((w & 0xfc000000) == 0x94000000 || (w & 0xfc000000) == 0x14000000) {
			long target = at + ((long) (w << 6) >> 4);
			Exit exit = (w & 0x80000000) != 0 ? Exit.CALL : Exit.TAIL_CALL;
			return new Result(exit, x[0], target, i, w);
		}
		return unrecognized(i, w);
	}

	/**
	 * {@code add xd, xn, #imm12 {, lsl #12}}; xn = 31 is sp. Only frame-pointer setup may use
	 * sp. Returns false for an instruction the decoder does not follow.
	 */
	private static boolean addImmediate(Long[] x, int w) {
		int rd = w & 31;
		int rn = (w >>> 5) & 31;
		if (rn == SP) {
			return rd == FP || rd == SP;
		}
		if (rd == SP) {
			return false;
		}
		long imm = (long) ((w >>> 10) & 0xfff) << ((w >>> 22 & 1) == 1 ? 12 : 0);
		x[rd] = x[rn] == null ? null : x[rn] + imm;
		return true;
	}

	/**
	 * {@code ldr xd, [xn, #imm12 * 8]}. The register becomes unknown if xn is unknown or
	 * {@code memory} is null. Returns false for an sp base, which the decoder does not follow.
	 */
	private static boolean load(Long[] x, int w, Reader memory) {
		int rd = w & 31;
		int rn = (w >>> 5) & 31;
		if (rn == SP) {
			return false;
		}
		long address = x[rn] == null ? 0 : x[rn] + 8L * ((w >>> 10) & 0xfff);
		x[rd] = x[rn] == null || memory == null ? null : memory.read64(address);
		return true;
	}

	/**
	 * {@code stp}/{@code ldp} of x29 and x30, or of a pair of callee-saved registers x19–x28,
	 * with sp as base (signed offset, pre- or post-index, 64-bit).
	 */
	private static boolean isFramePairWithSp(int w) {
		int opc = w & 0xffc00000;
		boolean pair = opc == 0xa9000000 || opc == 0xa9800000 || opc == 0xa8800000 || // stp
			opc == 0xa9400000 || opc == 0xa9c00000 || opc == 0xa8c00000; // ldp
		if (!pair || ((w >>> 5) & 31) != SP) {
			return false;
		}
		int rt = w & 31;
		int rt2 = (w >>> 10) & 31;
		return (rt == FP && rt2 == LR) || (rt >= 19 && rt <= 28 && rt2 >= 19 && rt2 <= 28);
	}

	/**
	 * The hints of arm64e and BTI code around the return address: {@code paciaz},
	 * {@code paciasp}, {@code pacibz}, {@code pacibsp}, {@code autiaz}, {@code autiasp},
	 * {@code autibz}, {@code autibsp} (hint #24–#31) and {@code bti} (#32, #34, #36, #38).
	 */
	private static boolean isReturnAddressHint(int w) {
		if ((w & 0xfffff01f) != 0xd503201f) {
			return false;
		}
		int hint = (w >>> 5) & 0x7f;
		return (hint >= 24 && hint <= 31) || (hint >= 32 && hint <= 38 && hint % 2 == 0);
	}

	private static Result unrecognized(int index, int word) {
		return new Result(Exit.UNRECOGNIZED, null, 0, index, word);
	}
}
