// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import lzghidraswift.metadata.AccessorDecoder.Exit;
import lzghidraswift.metadata.AccessorDecoder.Reader;
import lzghidraswift.metadata.AccessorDecoder.Result;

/**
 * The x86_64 counterpart of {@link AccessorDecoder}: decodes the start of a metadata accessor far
 * enough to find the address it returns. Accessors of non-generic types with static metadata look
 * like this (Layouts fixture, Swift 6, -O, -target x86_64-apple-macos13):
 * <pre>
 * struct, enum:  lea rax, [rip + metadata]; xor edx, edx; ret
 * class:         push rbp; mov rbp, rsp; lea rdi, [rip + metadata]; call objc_opt_self;
 *                xor edx, edx; pop rbp; ret
 * generic:       lea r8, [rip + descriptor]; jmp swift_instantiateGenericMetadata
 * </pre>
 * The decoder follows {@code lea} and {@code mov} from {@code [rip + disp32]}, 64-bit register
 * moves, {@code xor} of a register with itself, {@code push}, {@code pop}, {@code mov rbp, rsp},
 * and stops at the first {@code ret}, {@code call rel32}, {@code jmp rel32/rel8} or any other
 * instruction. The result's {@code x0} is rax at a {@code ret} and rdi (the first argument) at a
 * call; its {@code index} is the byte offset of the last instruction, and {@code word} holds up to
 * four bytes from there (first byte in the top bits).
 */
public final class X86AccessorDecoder {

	private static final int RAX = 0;
	private static final int RSP = 4;
	private static final int RBP = 5;
	private static final int RDI = 7;

	private X86AccessorDecoder() {
	}

	/**
	 * Decodes {@code code}, the bytes at {@code pc}. {@code memory} resolves a load from
	 * {@code [rip + disp32]}; it may be null, and then a load makes the register unknown.
	 */
	public static Result decode(long pc, byte[] code, Reader memory) {
		Decoder d = new Decoder(pc, code, memory);
		while (d.i < code.length) {
			Result end = d.step();
			if (end != null) {
				return end;
			}
		}
		return new Result(Exit.UNRECOGNIZED, null, 0, code.length, 0);
	}

	/** The registers and the position while decoding. */
	private static final class Decoder {
		final long pc;
		final byte[] code;
		final Reader memory;
		final Long[] r = new Long[16];
		/** Offset of the next byte. */
		int i;
		/** Offset of the current instruction and its REX bits (0 without a prefix). */
		int start;
		int rex;

		Decoder(long pc, byte[] code, Reader memory) {
			this.pc = pc;
			this.code = code; // NOPMD ArrayIsStoredDirectly: private class, only reads the array
			this.memory = memory;
		}

		/** Decodes one instruction. Returns the result if the sequence ends with it, else null. */
		Result step() {
			start = i;
			rex = 0;
			if ((code[i] & 0xf0) == 0x40) {
				rex = code[i] & 0x0f;
				i++;
			}
			if (i >= code.length) {
				return null;
			}
			int op = code[i] & 0xff;
			boolean w = (rex & 8) != 0;
			if (op >= 0x50 && op <= 0x5f && (rex & ~1) == 0) {
				// push r64 / pop r64
				if (op >= 0x58) {
					r[(op - 0x58) + rmExt()] = null;
				}
				i++;
				return null;
			}
			if (rex == 0 && (op == 0xc3 || op == 0xe8 || op == 0xe9 || op == 0xeb)) {
				return controlTransfer(op);
			}
			if ((op == 0x8d || op == 0x8b) && w && i + 6 <= code.length &&
				(code[i + 1] & 0xc7) == 0x05) {
				ripRelative(op);
				return null;
			}
			boolean registerOperands = i + 2 <= code.length && (code[i + 1] & 0xc0) == 0xc0;
			if ((op == 0x89 || op == 0x8b) && w && registerOperands) {
				return moveRegister(op);
			}
			if ((op == 0x31 || op == 0x33) && (rex & ~5) == 0 && registerOperands) {
				return xorZero();
			}
			return unrecognized(code, start);
		}

		/** {@code ret}, {@code call rel32}, {@code jmp rel32}, {@code jmp rel8}. */
		private Result controlTransfer(int op) {
			if (op == 0xc3) {
				return new Result(Exit.RETURN, r[RAX], 0, start, word(code, start));
			}
			if (op != 0xeb && i + 5 <= code.length) {
				long next = pc + i + 5;
				long target = next + int32(code, i + 1);
				Exit exit = op == 0xe8 ? Exit.CALL : Exit.TAIL_CALL;
				return new Result(exit, r[RDI], target, start, word(code, start));
			}
			if (op == 0xeb && i + 2 <= code.length) {
				long target = pc + i + 2 + code[i + 1];
				return new Result(Exit.TAIL_CALL, r[RDI], target, start, word(code, start));
			}
			return unrecognized(code, start);
		}

		/** {@code lea r64, [rip + disp32]} / {@code mov r64, [rip + disp32]}. */
		private void ripRelative(int op) {
			int reg = ((code[i + 1] >>> 3) & 7) + regExt();
			long address = pc + i + 6 + int32(code, i + 2);
			if (op == 0x8d) {
				r[reg] = address;
			}
			else {
				r[reg] = memory == null ? null : memory.read64(address);
			}
			i += 6;
		}

		/** {@code mov r64, r64} (89: rm <- reg, 8b: reg <- rm). */
		private Result moveRegister(int op) {
			int reg = ((code[i + 1] >>> 3) & 7) + regExt();
			int rm = (code[i + 1] & 7) + rmExt();
			int dst = op == 0x89 ? rm : reg;
			int src = op == 0x89 ? reg : rm;
			if (dst == RSP) {
				return unrecognized(code, start);
			}
			// mov rbp, rsp: the frame setup; rsp is not tracked
			r[dst] = src == RSP ? null : r[src];
			i += 2;
			return null;
		}

		/** {@code xor r32, r32} with the same register: zero (the upper half too). */
		private Result xorZero() {
			int reg = ((code[i + 1] >>> 3) & 7) + regExt();
			int rm = (code[i + 1] & 7) + rmExt();
			if (reg != rm || reg == RSP || reg == RBP) {
				return unrecognized(code, start);
			}
			r[reg] = 0L;
			i += 2;
			return null;
		}

		private int regExt() {
			return (rex & 4) != 0 ? 8 : 0;
		}

		private int rmExt() {
			return (rex & 1) != 0 ? 8 : 0;
		}
	}

	private static long int32(byte[] code, int at) {
		return (code[at] & 0xff) | (code[at + 1] & 0xff) << 8 | (code[at + 2] & 0xff) << 16 |
			code[at + 3] << 24;
	}

	/** Up to four bytes at {@code at}, the first in the top bits. */
	private static int word(byte[] code, int at) {
		int w = 0;
		for (int k = 0; k < 4; k++) {
			w = w << 8 | (at + k < code.length ? code[at + k] & 0xff : 0);
		}
		return w;
	}

	private static Result unrecognized(byte[] code, int at) {
		return new Result(Exit.UNRECOGNIZED, null, 0, at, word(code, at));
	}
}
