// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.abi;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

/**
 * Registers of the Swift calling convention on the two Apple 64-bit targets, the check for
 * those targets ({@link #isSwiftTarget}), and the program's Swift conventions by name
 * ({@link #swiftConvention}). A {@code String} argument or result takes two adjacent
 * registers of these lists. The register lists take every program that is not AArch64 as x86_64;
 * callers that can see other processors check {@link #isSwiftTarget} first.
 */
public final class CallingConventions {

	/**
	 * Ends the name of each convention variant that this extension adds to a program (the
	 * throwing variants of {@code ThrowingConventions}); such a variant is not one of Swift's
	 * own conventions.
	 */
	public static final String VARIANT_SUFFIX = "_throws";

	/** Name prefix of Ghidra's Swift conventions (spec extensions since Ghidra 12.2). */
	private static final String SWIFT_PREFIX = "__swift_";

	private static final String[] AARCH64_ARGS = { "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7" };
	private static final String[] AARCH64_FLOAT_ARGS =
		{ "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7" };
	private static final String[] AARCH64_RESULTS = { "x0", "x1", "x2", "x3" };
	private static final String[] X86_64_ARGS = { "RDI", "RSI", "RDX", "RCX", "R8", "R9" };
	private static final String[] X86_64_FLOAT_ARGS = { "XMM0_Qa", "XMM1_Qa", "XMM2_Qa",
		"XMM3_Qa", "XMM4_Qa", "XMM5_Qa", "XMM6_Qa", "XMM7_Qa" };
	private static final String[] X86_64_RESULTS = { "RAX", "RDX", "RCX", "R8" };

	private CallingConventions() {
	}

	/** The name of the program's processor, as Ghidra's language names it ("AARCH64", "x86"). */
	public static String processor(Program program) {
		return program.getLanguage().getProcessor().toString();
	}

	/** Whether the program is 64-bit AArch64 or 64-bit x86, the targets of these registers. */
	public static boolean isSwiftTarget(Program program) {
		if (program.getDefaultPointerSize() != 8) {
			return false;
		}
		String processor = processor(program);
		return processor.equals("AARCH64") || processor.equals("x86");
	}

	/** Whether the processor is AArch64, whatever the pointer size. */
	public static boolean isAArch64(Program program) {
		return processor(program).equals("AARCH64");
	}

	public static List<Register> argumentRegisters(Program program) {
		return registers(program, isAArch64(program) ? AARCH64_ARGS : X86_64_ARGS);
	}

	public static List<Register> resultRegisters(Program program) {
		return registers(program, isAArch64(program) ? AARCH64_RESULTS : X86_64_RESULTS);
	}

	/** The floating-point argument registers, 8 bytes each: d0 to d7, XMM0 to XMM7. */
	public static List<Register> floatArgumentRegisters(Program program) {
		return registers(program, isAArch64(program) ? AARCH64_FLOAT_ARGS : X86_64_FLOAT_ARGS);
	}

	/**
	 * The register in which a Swift caller passes the address of an indirect result: x8, and
	 * RAX on x86_64 (LLVM's {@code CC_X86_64_Swift}; Ghidra's Swift conventions list both as
	 * the {@code hiddenret} entry).
	 */
	public static Register indirectResultRegister(Program program) {
		return program.getRegister(isAArch64(program) ? "x8" : "RAX");
	}

	/**
	 * Swift's self register, also the context of a closure: x20, r13 on x86_64. Null if the
	 * program is not a {@linkplain #isSwiftTarget Swift target}.
	 */
	public static Register selfRegister(Program program) {
		if (!isSwiftTarget(program)) {
			return null;
		}
		return program.getRegister(isAArch64(program) ? "x20" : "R13");
	}

	/** The frame pointer, which Apple's ABIs require: x29, RBP. */
	public static Register framePointer(Program program) {
		return program.getRegister(isAArch64(program) ? "x29" : "RBP");
	}

	/**
	 * The register in which a throwing Swift function returns its error: x21 on AArch64, r12 on
	 * x86_64 ({@code docs/ABI/CallingConventionSummary.rst} in the Swift repository). Null if the
	 * program is not a {@linkplain #isSwiftTarget Swift target}.
	 */
	public static Register errorRegister(Program program) {
		if (!isSwiftTarget(program)) {
			return null;
		}
		return program.getRegister(isAArch64(program) ? "x21" : "R12");
	}

	/**
	 * Offset from the stack pointer of the first stack argument, as {@code ValueFlow} sees it at
	 * a call or tail branch: 0 on AArch64; 8 on x86_64, where the CALL p-code has pushed the
	 * return address before the call (and a tail jmp leaves the caller's return address there).
	 */
	public static long stackArgumentOffset(Program program) {
		return isAArch64(program) ? 0 : 8;
	}

	/**
	 * Registers through which a callee can receive an address: the argument registers, the
	 * indirect result register, and Swift's self and error registers (x20 and x21 on AArch64,
	 * r13 and r12 on x86_64). Swift passes an inout {@code self} on the stack in x20.
	 */
	public static List<Register> pointerRegisters(Program program) {
		List<String> names = new ArrayList<>();
		if (isAArch64(program)) {
			names.addAll(List.of(AARCH64_ARGS));
			names.addAll(List.of("x8", "x20", "x21"));
		}
		else {
			names.addAll(List.of(X86_64_ARGS));
			names.addAll(List.of("RAX", "R13", "R12"));
		}
		return registers(program, names.toArray(String[]::new));
	}

	/** Registers a call may change, beyond those in the calling convention's killed list. */
	public static List<String> volatileRegisters(Program program) {
		List<String> names = new ArrayList<>();
		if (isAArch64(program)) {
			for (int i = 0; i <= 18; i++) {
				names.add("x" + i);
			}
			names.add("x30");
		}
		else {
			names.addAll(List.of("RAX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11"));
		}
		return names;
	}

	/**
	 * The first Swift convention with or without a {@code this} parameter: in Ghidra 12.2
	 * {@code __swift_stdcall} or {@code __swift_thiscall}, spec extensions next to the default
	 * C convention. Null if there is none, as on a program without the Swift source language.
	 */
	public static String swiftConvention(CompilerSpec spec, boolean thisPointer) {
		for (PrototypeModel m : spec.getCallingConventions()) {
			if (m.hasThisPointer() == thisPointer && !m.isMerged() &&
				isSwiftConvention(m.getName())) {
				return m.getName();
			}
		}
		return null;
	}

	/**
	 * Whether a convention is one of Swift's: the {@code __swift_} conventions that Ghidra adds
	 * as spec extensions ({@code __swift_stdcall}, {@code __swift_thiscall}). Not other program
	 * extensions: Ghidra's Objective-C analysis adds {@code __objc_msgSend_stub} to Mach-O
	 * programs. Not a variant of this extension ({@link #VARIANT_SUFFIX}).
	 */
	public static boolean isSwiftConvention(String name) {
		return name.startsWith(SWIFT_PREFIX) && !name.endsWith(VARIANT_SUFFIX);
	}

	private static List<Register> registers(Program program, String[] names) {
		List<Register> regs = new ArrayList<>();
		for (String n : names) {
			Register r = program.getRegister(n);
			if (r != null) {
				regs.add(r);
			}
		}
		return regs;
	}
}
