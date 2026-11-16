// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import lzghidraswift.strings.DecompilerEquates.Ref;

public class DecompilerEquatesTest {

	private static final AddressSpace RAM =
		new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 1);

	private static Ref ref(long addr, long hash) {
		return new Ref(null, hash, RAM.getAddress(addr));
	}

	/** References are added by address, then hash, whatever order the decompile gave them. */
	@Test
	public void refOrderIsAddressThenHash() {
		Ref a = ref(0x1000, 0x20);
		Ref b = ref(0x1000, 0x503020556de68eL);
		Ref c = ref(0x1000, 0x8000_0000_0000_0001L); // above any positive hash, unsigned
		Ref d = ref(0x1004, 0x10);
		List<Ref> expected = List.of(a, b, c, d);
		for (List<Ref> input : List.of(List.of(d, c, b, a), List.of(b, d, a, c),
			List.of(c, a, d, b))) {
			List<Ref> refs = new ArrayList<>(input);
			refs.sort(Ref.ORDER);
			assertEquals(expected, refs);
		}
	}
}
