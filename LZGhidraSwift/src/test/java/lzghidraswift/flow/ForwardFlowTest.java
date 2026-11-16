// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.flow;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;

/** The successors of an instruction, shared by {@link ForwardFlow} and {@link SelfRegisterUse}. */
public class ForwardFlowTest {

	private static final AddressSpace RAM =
		new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 1);
	private static final Address TARGET = RAM.getAddress(0x2000);
	private static final Address NEXT = RAM.getAddress(0x1004);

	@Test
	public void terminalHasNone() {
		assertEquals(List.of(), ForwardFlow.successors(instruction(RefType.TERMINATOR, NEXT)));
		// A tail call: a terminal call, though the instruction has a target.
		assertEquals(List.of(),
			ForwardFlow.successors(instruction(RefType.CALL_TERMINATOR, NEXT, TARGET)));
	}

	@Test
	public void conditionalJumpGivesTargetThenFallThrough() {
		assertEquals(List.of(TARGET, NEXT),
			ForwardFlow.successors(instruction(RefType.CONDITIONAL_JUMP, NEXT, TARGET)));
	}

	@Test
	public void unconditionalJumpGivesTargetOnly() {
		assertEquals(List.of(TARGET),
			ForwardFlow.successors(instruction(RefType.UNCONDITIONAL_JUMP, null, TARGET)));
	}

	@Test
	public void callFallsThrough() {
		assertEquals(List.of(NEXT),
			ForwardFlow.successors(instruction(RefType.UNCONDITIONAL_CALL, NEXT, TARGET)));
	}

	@Test
	public void missingFallThroughIsLeftOut() {
		assertEquals(List.of(), ForwardFlow.successors(instruction(RefType.FALL_THROUGH, null)));
		assertEquals(List.of(TARGET),
			ForwardFlow.successors(instruction(RefType.CONDITIONAL_JUMP, null, TARGET)));
	}

	/** An instruction with only a flow type, a fall-through (or null) and jump targets. */
	private static Instruction instruction(FlowType flow, Address fallThrough, Address... flows) {
		Map<String, Object> answers = new HashMap<>();
		answers.put("getFlowType", flow);
		answers.put("getFallThrough", fallThrough);
		answers.put("getFlows", flows);
		return (Instruction) Proxy.newProxyInstance(
			Thread.currentThread().getContextClassLoader(), new Class<?>[] { Instruction.class },
			(proxy, method, args) -> {
				if (!answers.containsKey(method.getName())) {
					throw new UnsupportedOperationException(method.getName());
				}
				return answers.get(method.getName());
			});
	}
}
