// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.flow;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.pcode.Varnode;

public class ValueFlowTest {

	private static final AddressSpace CONST =
		new GenericAddressSpace("const", 64, AddressSpace.TYPE_CONSTANT, 0);

	private static Varnode constant(long offset, int size) {
		return new Varnode(CONST.getAddress(offset), size);
	}

	/**
	 * Sleigh stores p-code-relative branch targets masked to the varnode size; x86 tzcnt has a
	 * backward branch of -4 stored as 0xfffffffc in a 4-byte constant. Read as a long, that was
	 * a large forward jump, and the internal loop never ended.
	 */
	@Test
	public void relativeTargetSignExtendsFromVarnodeSize() {
		assertEquals(-4, PcodeStep.relativeTarget(constant(0xffff_fffcL, 4)));
		assertEquals(3, PcodeStep.relativeTarget(constant(3, 4)));
		assertEquals(-1, PcodeStep.relativeTarget(constant(0xffffL, 2)));
		assertEquals(-2, PcodeStep.relativeTarget(constant(-2L, 8)));
	}

	/**
	 * waypointName(_:) on x86_64: {@code jmpq *%rcx} of a recovered switch (targets 0x1cd0 and
	 * 0x1e28 in the body) is no tail branch. Without flows, or with one flow out of the body, the
	 * indirect branch may leave the function.
	 */
	@Test
	public void switchJumpDoesNotLeave() {
		AddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 1);
		AddressSet body = new AddressSet(ram.getAddress(0x1ca0), ram.getAddress(0x1e47));
		Address inside = ram.getAddress(0x1cd0);
		Address tail = ram.getAddress(0x1e28);
		Address outside = ram.getAddress(0x2000);
		assertFalse(PcodeStep.indirectLeaves(new Address[] { inside, tail }, body));
		assertTrue(PcodeStep.indirectLeaves(new Address[0], body));
		assertTrue(PcodeStep.indirectLeaves(new Address[] { inside, outside }, body));
	}

	/**
	 * A loop body before its header in address order (for example 0xc8b158 before 0xc8b160) must not
	 * run before the header has a state; a block without predecessors (jump-table target) and
	 * the entry always run.
	 */
	@Test
	public void blockWaitsForAPredecessorWithAState() {
		AddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 1);
		Address entry = ram.getAddress(0x100);
		Address body = ram.getAddress(0x158);
		Address header = ram.getAddress(0x160);
		Address table = ram.getAddress(0x200);
		Map<Address, List<Address>> preds =
			Map.of(body, List.of(body, header), header, List.of(entry, body));
		Map<Address, ValueFlow.State> out = new HashMap<>();
		assertTrue(ValueFlow.reached(entry, entry, preds, out));
		assertTrue(ValueFlow.reached(table, entry, preds, out));
		assertFalse(ValueFlow.reached(header, entry, preds, out));
		assertFalse(ValueFlow.reached(body, entry, preds, out));
		out.put(entry, new ValueFlow.State());
		assertTrue(ValueFlow.reached(header, entry, preds, out));
		assertFalse(ValueFlow.reached(body, entry, preds, out));
		out.put(header, new ValueFlow.State());
		assertTrue(ValueFlow.reached(body, entry, preds, out));
	}
}
