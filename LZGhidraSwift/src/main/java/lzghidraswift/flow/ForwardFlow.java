// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.flow;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.BinaryOperator;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A forward data flow over the instructions of one function, for the Swift Error Register
 * ({@code ErrorTestSites} and {@code CallArguments} in {@code throwing}). The states form a
 * lattice of finite height: {@code meet} gives a state that is never larger than either input,
 * so the work list ends. A call falls through to the next instruction; a jump outside the
 * function's body is not followed.
 */
public final class ForwardFlow {

	/** Instructions examined per function. */
	public static final int LIMIT = 100_000;

	private ForwardFlow() {
	}

	/**
	 * For each instruction reached from the entry: the state before it. Every key is the address
	 * of an instruction; the map is empty if the entry holds none (Ghidra creates functions at the
	 * async function pointers, {@code Tu} symbols in {@code __const}). Null if the function has
	 * more than {@link #LIMIT} instructions on the way.
	 *
	 * @param entry the state at the function's entry
	 * @param transfer the state after an instruction, from the state before it
	 * @param meet the state at a merge of two paths
	 */
	public static <S> Map<Address, S> before(Function function, S entry,
			BiFunction<S, Instruction, S> transfer, BinaryOperator<S> meet, TaskMonitor monitor)
			throws CancelledException {
		Listing listing = function.getProgram().getListing();
		Map<Address, S> states = new HashMap<>();
		Deque<Address> work = new ArrayDeque<>();
		if (listing.getInstructionAt(function.getEntryPoint()) == null) {
			return states;
		}
		states.put(function.getEntryPoint(), entry);
		work.push(function.getEntryPoint());
		int count = 0;
		while (!work.isEmpty()) {
			monitor.checkCancelled();
			Address at = work.pop();
			Instruction instr = listing.getInstructionAt(at);
			if (++count > LIMIT) {
				return null;
			}
			S out = transfer.apply(states.get(at), instr);
			for (Address next : successors(instr)) {
				if (!function.getBody().contains(next) || listing.getInstructionAt(next) == null) {
					continue;
				}
				S old = states.get(next);
				S merged = old == null ? out : meet.apply(old, out);
				if (old == null || !merged.equals(old)) {
					states.put(next, merged);
					work.push(next);
				}
			}
		}
		return states;
	}

	/**
	 * The jump targets and the fall-through (also after a call), in this order; none after a
	 * terminal flow. Also the successors of {@link SelfRegisterUse}.
	 */
	static List<Address> successors(Instruction instr) {
		List<Address> next = new ArrayList<>();
		FlowType flow = instr.getFlowType();
		if (flow.isTerminal()) {
			return next;
		}
		if (flow.isJump()) {
			next.addAll(List.of(instr.getFlows()));
		}
		if (flow.hasFallthrough() || flow.isCall()) {
			Address fall = instr.getFallThrough();
			if (fall != null) {
				next.add(fall);
			}
		}
		return next;
	}
}
