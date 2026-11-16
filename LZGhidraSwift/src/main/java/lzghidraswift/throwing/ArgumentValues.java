// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.throwing;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import lzghidraswift.flow.PcodeOps;
import lzghidraswift.throwing.CallArguments.Kind;
import lzghidraswift.throwing.CallArguments.Registers;

/**
 * The registers that hold an argument for the next call at one point of a function, for
 * {@link CallArguments}. A register of {@link Registers#tracked()} holds one if the function
 * wrote it, or it is one of the function's own parameters, and no instruction read it since: a
 * value that the function computed and then used is a temporary. A save to memory is no read
 * (an argument spilled before the call). A call removes them all except the self register,
 * which the callee preserves.
 * <p>
 * Also the registers that hold a stack address ({@code mov x0, sp}, {@code add x1, sp, #0x18},
 * {@code sub x0, x29, #0x78}, {@code lea rdi, [rbp - 0x20]}), so that an argument that points
 * into the caller's frame becomes a pointer. A call removes those in volatile registers.
 * <p>
 * And the stack slots written at a constant offset from the stack pointer
 * ({@code stp x10, x11, [sp]}, {@code push r15}; also through a register that holds it,
 * {@code mov x10, sp; str x11, [x10]} at {@code -Onone}), as offsets from its current value: the stack
 * arguments of the next call. A change of the stack pointer by a constant moves them (x86_64's
 * {@code call} pushes the return address), any other write of it and a call remove them. A store
 * of a register that still holds its value from the function's entry is a save, no slot (the
 * prologue's {@code push rbx}, {@code push rax} for alignment, which lie next to the arguments
 * that x86_64 pushes): the registers that the function wrote, received as parameters, or that a
 * call changed are recorded as defined, on any path.
 * <p>
 * Immutable, compared by value. Varnodes of the tracked registers are full registers; a write
 * of a part (w1 of x1) makes a {@link Kind#VALUE}.
 */
record ArgumentValues(Map<Varnode, Kind> arguments, Set<Varnode> stackAddresses,
		Set<Long> stackSlots, Set<Varnode> defined, Map<Varnode, Long> fromStackPointer) {

	ArgumentValues {
		arguments = Map.copyOf(arguments);
		stackAddresses = Set.copyOf(stackAddresses);
		stackSlots = Set.copyOf(stackSlots);
		defined = Set.copyOf(defined);
		fromStackPointer = Map.copyOf(fromStackPointer);
	}

	/** The state at a function's entry: its own register parameters. */
	static ArgumentValues entry(Set<Varnode> parameters) {
		Map<Varnode, Kind> args = new HashMap<>();
		for (Varnode p : parameters) {
			args.put(p, Kind.ENTRY);
		}
		return new ArgumentValues(args, Set.of(), Set.of(), parameters, Map.of());
	}

	/**
	 * On both paths; a register with two different kinds is a {@link Kind#VALUE}. Defined on
	 * either path (a union, which only grows, so the flow still ends).
	 */
	ArgumentValues meet(ArgumentValues o) {
		Map<Varnode, Kind> args = new HashMap<>();
		for (Map.Entry<Varnode, Kind> e : arguments.entrySet()) {
			Kind other = o.arguments.get(e.getKey());
			if (other != null) {
				args.put(e.getKey(), other == e.getValue() ? other : Kind.VALUE);
			}
		}
		Set<Varnode> stack = new HashSet<>(stackAddresses);
		stack.retainAll(o.stackAddresses);
		Set<Long> slots = new HashSet<>(stackSlots);
		slots.retainAll(o.stackSlots);
		Set<Varnode> def = new HashSet<>(defined);
		def.addAll(o.defined);
		Map<Varnode, Long> fromSp = new HashMap<>(fromStackPointer);
		fromSp.entrySet().removeIf(e -> !e.getValue().equals(o.fromStackPointer.get(e.getKey())));
		return new ArgumentValues(args, stack, slots, def, fromSp);
	}

	/** The state after the p-code of one instruction, a call included. */
	ArgumentValues after(PcodeOp[] ops, Registers registers) {
		return run(ops, registers, false);
	}

	/**
	 * The state at the call in {@code ops}, the p-code of a call instruction: after its reads,
	 * also of the register that holds the target ({@code blr x8}, {@code call rax}), which is
	 * then no argument.
	 */
	ArgumentValues atCall(PcodeOp[] ops, Registers registers) {
		return run(ops, registers, true);
	}

	private ArgumentValues run(PcodeOp[] ops, Registers registers, boolean stopAtCall) {
		Step state = new Step(this, registers);
		for (PcodeOp op : ops) {
			state.removeRead(op, ops);
			int opcode = op.getOpcode();
			if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
				if (stopAtCall) {
					break;
				}
				state.call();
			}
			else if (op.getOutput() != null) {
				state.write(op);
			}
			else if (opcode == PcodeOp.STORE) {
				state.store(op);
			}
		}
		Map<Varnode, Long> fromSp = new HashMap<>(state.fromStackPointer);
		fromSp.keySet().removeIf(v -> !v.isRegister());
		return new ArgumentValues(state.args, state.stack, state.slots, state.defined, fromSp);
	}

	/** The state while the p-code of one instruction runs. */
	private static final class Step {
		private final Registers registers;
		private final Map<Varnode, Kind> args;
		private final Set<Varnode> stack;
		private final Set<Long> slots;
		private final Set<Varnode> defined;
		/** Uniques that hold a copy of a register (AArch64's stp copies to them first). */
		private final Map<Varnode, Varnode> copies = new HashMap<>();
		/** Uniques that hold a stack address. */
		private final Set<Varnode> uniques = new HashSet<>();
		/** Registers and uniques that hold the stack pointer plus a constant, with the constant. */
		private final Map<Varnode, Long> fromStackPointer;
		/** Uniques that hold a constant: AArch64's add x0, sp, #0x50 copies 0x50 to one. */
		private final Map<Varnode, Long> constants = new HashMap<>();

		Step(ArgumentValues before, Registers registers) {
			this.registers = registers;
			this.args = new HashMap<>(before.arguments);
			this.stack = new HashSet<>(before.stackAddresses);
			this.slots = new HashSet<>(before.stackSlots);
			this.defined = new HashSet<>(before.defined);
			this.fromStackPointer = new HashMap<>(before.fromStackPointer);
		}

		/** Removes the arguments that {@code op} reads, except as the value of a save. */
		void removeRead(PcodeOp op, PcodeOp[] ops) {
			if (PcodeOps.isSaveCopy(op, ops)) {
				return;
			}
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode in = op.getInput(i);
				if (in.isRegister() && !PcodeOps.isStoredValue(op, i)) {
					args.keySet().removeIf(t -> t.intersects(in));
				}
			}
		}

		void call() {
			args.keySet().retainAll(Set.of(registers.self()));
			slots.clear();
			for (AddressRange r : registers.killed()) {
				defined.add(new Varnode(r.getMinAddress(), (int) r.getLength()));
				fromStackPointer.keySet().removeIf(v -> PcodeOps.overlaps(v, r));
			}
			stack.removeIf(v -> registers.killed()
					.stream()
					.anyMatch(r -> PcodeOps.overlaps(v, r)));
		}

		void write(PcodeOp op) {
			Varnode out = op.getOutput();
			boolean isStack = isStackAddress(op);
			Long offset = stackPointerOffset(op);
			stack.removeIf(v -> v.intersects(out));
			uniques.removeIf(v -> v.intersects(out));
			fromStackPointer.keySet().removeIf(v -> v.intersects(out));
			constants.keySet().removeIf(v -> v.intersects(out));
			copies.keySet().removeIf(v -> v.intersects(out));
			if (out.isRegister()) {
				defined.add(out);
			}
			else if (out.isUnique() && op.getOpcode() == PcodeOp.COPY &&
				op.getInput(0).isRegister()) {
				copies.put(out, op.getInput(0));
			}
			if (out.equals(registers.stackPointer())) {
				moveSlots(offset);
			}
			else if (offset != null) {
				fromStackPointer.put(out, offset);
			}
			if (isStack) {
				(out.isUnique() ? uniques : stack).add(out);
			}
			else if (out.isUnique() && op.getOpcode() == PcodeOp.COPY &&
				op.getInput(0).isConstant()) {
				constants.put(out, op.getInput(0).getOffset());
			}
			for (Varnode t : registers.tracked()) {
				if (t.intersects(out)) {
					args.put(t, isStack && out.equals(t) ? Kind.STACK : Kind.VALUE);
				}
			}
		}

		/**
		 * A STORE at a constant offset from the stack pointer writes that slot; a save of a
		 * register's entry value removes it.
		 */
		void store(PcodeOp op) {
			Long offset = offset(op.getInput(1));
			if (offset == null) {
				return;
			}
			Varnode value = copies.getOrDefault(op.getInput(2), op.getInput(2));
			if (value.isRegister() && defined.stream().noneMatch(d -> d.intersects(value))) {
				slots.remove(offset);
			}
			else {
				slots.add(offset);
			}
		}

		/**
		 * The stack pointer is now its old value plus {@code delta}: the slots move by
		 * {@code -delta}. Null (another write of it) removes them.
		 */
		private void moveSlots(Long delta) {
			if (delta == null) {
				slots.clear();
				fromStackPointer.clear();
				return;
			}
			Set<Long> moved = new HashSet<>();
			for (long slot : slots) {
				moved.add(slot - delta);
			}
			slots.clear();
			slots.addAll(moved);
			fromStackPointer.replaceAll((v, off) -> off - delta);
		}

		/** The offset from the stack pointer that {@code v} holds, or null. */
		private Long offset(Varnode v) {
			if (v.equals(registers.stackPointer())) {
				return 0L;
			}
			return fromStackPointer.get(v);
		}

		/**
		 * The offset from the stack pointer (before {@code op}) of the value that {@code op}
		 * computes: a copy, or a sum or difference with a constant; or null.
		 */
		private Long stackPointerOffset(PcodeOp op) {
			int opcode = op.getOpcode();
			Long base = op.getNumInputs() == 0 ? null : offset(op.getInput(0));
			if (base == null) {
				return null;
			}
			if (opcode == PcodeOp.COPY) {
				return base;
			}
			Long c = op.getNumInputs() < 2 ? null : constant(op.getInput(1));
			if (c == null) {
				return null;
			}
			return switch (opcode) {
				case PcodeOp.INT_ADD -> base + c;
				case PcodeOp.INT_SUB -> base - c;
				default -> null;
			};
		}

		private Long constant(Varnode v) {
			if (v.isConstant()) {
				return v.getOffset();
			}
			return constants.get(v);
		}

		/**
		 * Whether {@code op} computes a stack address: a copy of the stack or frame pointer or
		 * of a stack address, or one of them plus or minus a constant.
		 */
		private boolean isStackAddress(PcodeOp op) {
			int opcode = op.getOpcode();
			if (opcode != PcodeOp.COPY &&
				!((opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB) &&
					constant(op.getInput(1)) != null)) {
				return false;
			}
			Varnode base = op.getInput(0);
			return registers.stackBases().contains(base) || stack.contains(base) ||
				uniques.contains(base);
		}
	}
}
