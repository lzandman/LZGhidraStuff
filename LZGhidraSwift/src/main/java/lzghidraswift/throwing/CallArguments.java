// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.throwing;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lzghidraswift.abi.CallingConventions;
import lzghidraswift.flow.ForwardFlow;
import lzghidraswift.flow.PcodeOps;

/**
 * The registers that a caller sets up for an indirect call, for the call-site override of a call
 * to a throwing closure ({@link ThrowingCallOverride}). With the prototype locked by an override,
 * the decompiler takes only the inputs that the signature names; an argument that the signature
 * leaves out is lost, and with it the code that computes it (a stack address in x0, the indirect
 * result buffer in x8).
 * <p>
 * An argument is a register that holds a value for the call on every path to it
 * ({@link ArgumentValues}): written by the caller, or one of the caller's own register
 * parameters, and not read since. The integer and floating-point argument registers count up to
 * the last one that holds an argument; the ones before it are arguments too (a gap is a value
 * that the caller passes on unchanged, or that the callee does not use). Separately: the
 * indirect result register (x8, RAX), and the self register (x20, r13), which is always an
 * argument: Swift passes a closure's context or a witness method's {@code self} there on every
 * call of a function value (a {@link Kind#VALUE} if the flow does not see it written, as when
 * {@code -Onone} code copies it to x1 before the call). If every integer argument register holds one, the stack arguments: the 8-byte slots
 * that the caller wrote from the first stack argument on, without a gap.
 */
public final class CallArguments {

	/** What an argument register holds. */
	public enum Kind {
		/** The caller's own parameter, passed on. */
		ENTRY,
		/** A value the caller computed or loaded. */
		VALUE,
		/** An address in the caller's stack frame. */
		STACK
	}

	/**
	 * The arguments of one call.
	 *
	 * @param integers the integer argument registers from the first one up to the last one that
	 *            holds an argument (x0 to x7; RDI, RSI, RDX, RCX, R8, R9); a gap is a
	 *            {@link Kind#VALUE}
	 * @param floats the same for the floating-point argument registers (d0 to d7, XMM0 to XMM7)
	 * @param indirectResult what the indirect result register holds, or null if it holds no
	 *            argument
	 * @param context what the self register holds; null only for a call the flow does not
	 *            reach
	 * @param stackArguments the number of 8-byte stack arguments, after the integer registers
	 */
	public record Arguments(List<Kind> integers, List<Kind> floats, Kind indirectResult,
			Kind context, int stackArguments) {
		public Arguments {
			integers = List.copyOf(integers);
			floats = List.copyOf(floats);
		}

		/** No arguments. */
		static Arguments none() {
			return new Arguments(List.of(), List.of(), null, null, 0);
		}
	}

	/** Stack arguments looked for, at most. */
	static final int MAX_STACK_ARGUMENTS = 16;

	/**
	 * The registers of the program's Swift convention that {@link ArgumentValues} looks at, as
	 * full-register varnodes.
	 *
	 * @param integers the integer argument registers, in order
	 * @param floats the floating-point argument registers, in order
	 * @param indirectResult x8 or RAX
	 * @param self x20 or r13; a call preserves it
	 * @param stackPointer sp or RSP
	 * @param stackBases the stack and frame pointers
	 * @param killed the registers a call may change, for the stack addresses
	 * @param stackArgumentOffset the offset of the first stack argument from the stack pointer
	 *            at the call ({@link CallingConventions#stackArgumentOffset})
	 */
	record Registers(List<Varnode> integers, List<Varnode> floats, Varnode indirectResult,
			Varnode self, Varnode stackPointer, Set<Varnode> stackBases,
			List<AddressRange> killed, long stackArgumentOffset) {

		static Registers of(Program program) {
			Varnode sp = varnode(program.getCompilerSpec().getStackPointer());
			Set<Varnode> bases = new HashSet<>();
			bases.add(sp);
			bases.add(varnode(CallingConventions.framePointer(program)));
			List<AddressRange> killed = new ArrayList<>();
			for (String name : CallingConventions.volatileRegisters(program)) {
				Register r = program.getRegister(name);
				if (r != null) {
					killed.add(PcodeOps.range(r));
				}
			}
			for (Register r : CallingConventions.floatArgumentRegisters(program)) {
				killed.add(PcodeOps.range(r));
			}
			return new Registers(varnodes(CallingConventions.argumentRegisters(program)),
				varnodes(CallingConventions.floatArgumentRegisters(program)),
				varnode(CallingConventions.indirectResultRegister(program)),
				varnode(CallingConventions.selfRegister(program)), sp, bases, killed,
				CallingConventions.stackArgumentOffset(program));
		}

		/** Every register whose value is tracked as a possible argument. */
		List<Varnode> tracked() {
			List<Varnode> all = new ArrayList<>(integers);
			all.addAll(floats);
			all.add(indirectResult);
			all.add(self);
			return all;
		}
	}

	private CallArguments() {
	}

	/**
	 * The arguments of the calls at {@code calls} in {@code caller}, by call address. A call that
	 * the flow does not reach, or a caller with too many instructions, has none.
	 */
	public static Map<Address, Arguments> at(Function caller, Collection<Address> calls,
			TaskMonitor monitor) throws CancelledException {
		Program program = caller.getProgram();
		Registers registers = Registers.of(program);
		Map<Address, ArgumentValues> before = ForwardFlow.before(caller,
			ArgumentValues.entry(parameters(caller, registers)),
			(state, instr) -> state.after(instr.getPcode(), registers), ArgumentValues::meet,
			monitor);
		Map<Address, Arguments> result = new HashMap<>();
		for (Address call : calls) {
			ArgumentValues state = before == null ? null : before.get(call);
			Instruction instr = program.getListing().getInstructionAt(call);
			if (state == null || instr == null) {
				result.put(call, Arguments.none());
				continue;
			}
			result.put(call, arguments(state.atCall(instr.getPcode(), registers), registers));
		}
		return result;
	}

	/** The arguments that {@code state}, at a call, holds. */
	static Arguments arguments(ArgumentValues state, Registers registers) {
		Map<Varnode, Kind> args = state.arguments();
		List<Kind> integers = upToLast(registers.integers(), args);
		int onStack = 0;
		if (integers.size() == registers.integers().size()) {
			while (onStack < MAX_STACK_ARGUMENTS && state.stackSlots()
					.contains(registers.stackArgumentOffset() + 8L * onStack)) {
				onStack++;
			}
		}
		return new Arguments(integers, upToLast(registers.floats(), args),
			args.get(registers.indirectResult()),
			args.getOrDefault(registers.self(), Kind.VALUE), onStack);
	}

	/** The kinds of {@code order} up to the last one in {@code args}; gaps are values. */
	private static List<Kind> upToLast(List<Varnode> order, Map<Varnode, Kind> args) {
		int last = -1;
		for (int i = 0; i < order.size(); i++) {
			if (args.containsKey(order.get(i))) {
				last = i;
			}
		}
		List<Kind> kinds = new ArrayList<>();
		for (int i = 0; i <= last; i++) {
			kinds.add(args.getOrDefault(order.get(i), Kind.VALUE));
		}
		return kinds;
	}

	/** The tracked registers that hold a parameter of {@code f}, also a part of one (w0). */
	private static Set<Varnode> parameters(Function f, Registers registers) {
		Set<Varnode> params = new HashSet<>();
		for (Parameter p : f.getParameters()) {
			for (Varnode v : p.getVariableStorage().getVarnodes()) {
				for (Varnode t : registers.tracked()) {
					if (v.isRegister() && t.intersects(v)) {
						params.add(t);
					}
				}
			}
		}
		return params;
	}

	private static Varnode varnode(Register r) {
		return new Varnode(r.getAddress(), r.getMinimumByteSize());
	}

	private static List<Varnode> varnodes(List<Register> registers) {
		List<Varnode> list = new ArrayList<>();
		for (Register r : registers) {
			list.add(varnode(r));
		}
		return list;
	}
}
