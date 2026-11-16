// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.throwing;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lzghidraswift.abi.CallingConventions;
import lzghidraswift.flow.ForwardFlow;
import lzghidraswift.flow.PcodeOps;

/**
 * Finds the calls after which a function tests the Swift error register (x21, r12): the caller's
 * side of a call to a throwing function, for callees without a Swift symbol and for indirect
 * calls.
 * <p>
 * A site is a call with the error register "clean" before it, followed by a test of the
 * register. Clean means 0 on every path from the entry: the caller sets it to 0
 * ({@code mov x21, #0}, {@code xor r12d, r12d}), or passes on its own entry value, which is 0 by
 * the ABI in a throwing caller that propagates the error, also through a copy in another register
 * ({@code mov x19, x21} ... {@code mov x21, x19}) or a stack slot ({@link CleanValues}). A call
 * keeps the callee-saved registers clean, and so the error register: after a tested throwing call
 * the code goes on along the no-error path with the register 0. The test is the first instruction
 * after the call that
 * reads the register, along fall-throughs and unconditional jumps, if it compares the register
 * with 0: a conditional jump ({@code cbz x21}), or an instruction that writes only flags followed by one that reads them: a
 * conditional jump ({@code test r12, r12; je}) or a conditional select ({@code cmp x21, #0;
 * csel}, {@code cmove}), which the compiler prefers when both paths only pick a value (typed
 * throws, {@code try?}). A copy of the register into another one comes first in code built with
 * {@code -Onone} ({@code mov x8, x21; str x8, [sp, #0x18]; cbnz x21}) and is passed over.
 * <p>
 * Outside Swift the error register is an ordinary callee-saved register. Code that sets it to 0
 * and tests it after a call that preserves it would be folded by the compiler, and code that
 * reads its entry value does so only to save it, so the pattern marks Swift's error protocol.
 */
public final class ErrorTestSites {

	/** Instructions examined after a call for the test. */
	static final int TEST_WINDOW = 8;

	/**
	 * A call followed by a test of the error register.
	 *
	 * @param call the call instruction
	 * @param target the called address for a direct call; null for an indirect call
	 * @param test the instruction that reads the register after the call
	 */
	public record Site(Address call, Address target, Address test) {
		public boolean isIndirect() {
			return target == null;
		}
	}

	private ErrorTestSites() {
	}

	/**
	 * The sites in {@code function}, by call address. Empty if the function is too large
	 * ({@link ForwardFlow#LIMIT}).
	 * <p>
	 * Most calls have no test after them, and the test is local, so the calls with one are found
	 * first; the flow runs only if there are any.
	 */
	public static List<Site> find(Function function, Register error, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = function.getProgram().getListing();
		List<Site> tested = testedCalls(function, listing, PcodeOps.range(error));
		if (tested.isEmpty()) {
			return tested;
		}
		Varnode full = new Varnode(error.getAddress(), error.getMinimumByteSize());
		List<AddressRange> killed = new ArrayList<>();
		for (String name : CallingConventions.volatileRegisters(function.getProgram())) {
			Register r = function.getProgram().getRegister(name);
			if (r != null) {
				killed.add(PcodeOps.range(r));
			}
		}
		return clean(tested, cleanBefore(function, full, killed, monitor), full);
	}

	/**
	 * The calls in the function's body followed by a test of the register ({@link #testAfter}),
	 * whether or not the register is clean before them, by address.
	 */
	private static List<Site> testedCalls(Function function, Listing listing, AddressRange reg) {
		List<Site> sites = new ArrayList<>();
		for (Instruction call : listing.getInstructions(function.getBody(), true)) {
			FlowType flow = call.getFlowType();
			if (!flow.isCall()) {
				continue;
			}
			Address test = testAfter(call, listing, reg);
			if (test == null) {
				continue;
			}
			Address target = null;
			if (!flow.isComputed()) {
				Address[] flows = call.getFlows();
				if (flows.length != 1) {
					continue;
				}
				target = flows[0];
			}
			sites.add(new Site(call.getAddress(), target, test));
		}
		return sites;
	}

	/**
	 * The {@code tested} calls that the flow reached with {@code error} clean before them, by
	 * call address; empty if {@code clean} is null (the function is too large).
	 */
	static List<Site> clean(List<Site> tested, Map<Address, CleanValues> clean, Varnode error) {
		List<Site> sites = new ArrayList<>();
		if (clean == null) {
			return sites;
		}
		for (Site site : tested) {
			CleanValues before = clean.get(site.call());
			if (before != null && before.contains(error)) {
				sites.add(site);
			}
		}
		sites.sort((a, b) -> a.call().compareTo(b.call()));
		return sites;
	}

	/** For each instruction reached from the entry: the clean values before it; or null. */
	private static Map<Address, CleanValues> cleanBefore(Function function, Varnode error,
			List<AddressRange> killed, TaskMonitor monitor) throws CancelledException {
		return ForwardFlow.before(function, CleanValues.entry(error),
			(state, instr) -> state.after(instr.getPcode(), killed), CleanValues::meet, monitor);
	}

	/**
	 * The instruction that tests the error register after {@code call}, or null if the first
	 * instruction that reads it is no test, or it is written, or another call, a return or a
	 * branch on something else comes first.
	 */
	private static Address testAfter(Instruction call, Listing listing, AddressRange reg) {
		Address at = call.getFallThrough();
		Set<Address> seen = new HashSet<>();
		for (int i = 0; i < TEST_WINDOW && at != null && seen.add(at); i++) {
			Instruction instr = listing.getInstructionAt(at);
			if (instr == null) {
				return null;
			}
			PcodeOp[] ops = instr.getPcode();
			FlowType flow = instr.getFlowType();
			if (reads(ops, reg)) {
				if (isTest(instr, ops, listing, reg)) {
					return at;
				}
				if (!isCopyOut(ops, reg) || writes(ops, reg)) {
					return null;
				}
			}
			if (writes(ops, reg) || flow.isCall() || flow.isTerminal() ||
				isConditionalJump(flow) || flow.isComputed()) {
				return null;
			}
			at = next(instr);
		}
		return null;
	}

	/**
	 * Whether an instruction that reads the register tests it against 0
	 * ({@link #comparesWithZero}): a conditional jump, or an instruction that writes only flags
	 * followed by one that reads a flag it wrote (a conditional jump or select).
	 */
	private static boolean isTest(Instruction instr, PcodeOp[] ops, Listing listing,
			AddressRange reg) {
		if (!comparesWithZero(ops, reg)) {
			return false;
		}
		FlowType flow = instr.getFlowType();
		if (isConditionalJump(flow)) {
			return true;
		}
		Address fall = instr.getFallThrough();
		Instruction next = fall == null ? null : listing.getInstructionAt(fall);
		return flow.isFallthrough() && writesOnlyFlags(ops) && next != null &&
			(isConditionalJump(next.getFlowType()) || readsFlags(next.getPcode(), ops));
	}

	/**
	 * True if {@code ops} compare the register with 0: an {@code INT_EQUAL} or
	 * {@code INT_NOTEQUAL} of 0 and the register, or of 0 and a temporary that is the register
	 * ANDed or ORed with itself, minus 0, or a copy of it. Ghidra's p-code: {@code cbz x21}
	 * compares x21 with 0; {@code cmp x21, #0} subtracts a temporary that holds 0;
	 * {@code test r12, r12} ANDs r12 with itself. A comparison with another value is no error
	 * test: after a call {@code cmp r12, 0x7fffffffffffffe9} checks a loop counter in r12 for
	 * overflow, and {@code tbz x21, #63} tests a bit.
	 */
	static boolean comparesWithZero(PcodeOp[] ops, AddressRange reg) {
		Set<Varnode> zero = new HashSet<>();
		Set<Varnode> same = new HashSet<>();
		for (PcodeOp op : ops) {
			Varnode out = op.getOutput();
			int opcode = op.getOpcode();
			if (opcode == PcodeOp.INT_EQUAL || opcode == PcodeOp.INT_NOTEQUAL) {
				Varnode a = op.getInput(0);
				Varnode b = op.getInput(1);
				if ((isZero(a, zero) && isSame(b, reg, same)) ||
					(isZero(b, zero) && isSame(a, reg, same))) {
					return true;
				}
			}
			if (out == null || !out.isUnique()) {
				continue;
			}
			if (opcode == PcodeOp.COPY && isZero(op.getInput(0), zero)) {
				zero.add(out);
			}
			else if (keepsZeroness(op, reg, zero, same)) {
				same.add(out);
			}
		}
		return false;
	}

	/**
	 * Whether {@code op} computes a value that is 0 exactly when the register is: a copy, the
	 * register ANDed or ORed with itself, or minus 0.
	 */
	private static boolean keepsZeroness(PcodeOp op, AddressRange reg, Set<Varnode> zero,
			Set<Varnode> same) {
		return switch (op.getOpcode()) {
			case PcodeOp.COPY -> isSame(op.getInput(0), reg, same);
			case PcodeOp.INT_AND, PcodeOp.INT_OR -> isSame(op.getInput(0), reg, same) &&
				isSame(op.getInput(1), reg, same);
			case PcodeOp.INT_SUB -> isSame(op.getInput(0), reg, same) &&
				isZero(op.getInput(1), zero);
			default -> false;
		};
	}

	private static boolean isZero(Varnode v, Set<Varnode> zero) {
		return (v.isConstant() && v.getOffset() == 0) || zero.contains(v);
	}

	private static boolean isSame(Varnode v, AddressRange reg, Set<Varnode> same) {
		return PcodeOps.overlaps(v, reg) || same.contains(v);
	}

	/** True if {@code ops} read a flag (a 1-byte register) that {@code flagOps} write. */
	static boolean readsFlags(PcodeOp[] ops, PcodeOp[] flagOps) {
		for (PcodeOp f : flagOps) {
			Varnode flag = f.getOutput();
			if (flag == null || !flag.isRegister() || flag.getSize() != 1) {
				continue;
			}
			for (PcodeOp op : ops) {
				for (int i = 0; i < op.getNumInputs(); i++) {
					if (flag.equals(op.getInput(i))) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/** The next instruction along a fall-through or an unconditional jump with one target. */
	private static Address next(Instruction instr) {
		if (instr.getFlowType().isJump()) {
			Address[] flows = instr.getFlows();
			return flows.length == 1 ? flows[0] : null;
		}
		return instr.getFallThrough();
	}

	private static boolean isConditionalJump(FlowType flow) {
		return flow.isJump() && flow.isConditional();
	}

	/** True if an op writes a varnode that overlaps the register. */
	static boolean writes(PcodeOp[] ops, AddressRange reg) {
		for (PcodeOp op : ops) {
			if (PcodeOps.overlaps(op.getOutput(), reg)) {
				return true;
			}
		}
		return false;
	}

	/** True if an input of an op other than a STORE's value overlaps the register. */
	static boolean reads(PcodeOp[] ops, AddressRange reg) {
		for (PcodeOp op : ops) {
			for (int i = 0; i < op.getNumInputs(); i++) {
				if (PcodeOps.isStoredValue(op, i)) {
					continue; // a save; AArch64's stp copies to a unique first, see PcodeOps.isSaveCopy
				}
				if (PcodeOps.overlaps(op.getInput(i), reg) && !PcodeOps.isSaveCopy(op, ops)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * True if every op that reads the register is a COPY of the whole register into another
	 * register ({@code mov x8, x21}; {@code mov rax, r12}).
	 */
	static boolean isCopyOut(PcodeOp[] ops, AddressRange reg) {
		for (PcodeOp op : ops) {
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode in = op.getInput(i);
				if (!PcodeOps.overlaps(in, reg)) {
					continue;
				}
				Varnode out = op.getOutput();
				if (op.getOpcode() != PcodeOp.COPY || out == null || !out.isRegister() ||
					PcodeOps.overlaps(out, reg) || in.getSize() != reg.getLength()) {
					return false;
				}
			}
		}
		return true;
	}

	/** True if the op writes only temporaries and 1-byte registers (the flags) and no memory. */
	static boolean writesOnlyFlags(PcodeOp[] ops) {
		for (PcodeOp op : ops) {
			if (op.getOpcode() == PcodeOp.STORE) {
				return false;
			}
			Varnode out = op.getOutput();
			if (out != null && !out.isUnique() && !(out.isRegister() && out.getSize() == 1)) {
				return false;
			}
		}
		return true;
	}
}
