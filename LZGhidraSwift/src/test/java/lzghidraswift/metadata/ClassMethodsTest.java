// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import static org.junit.Assert.*;

import org.junit.Test;

public class ClassMethodsTest {

	private static final int HAS_VTABLE = 1 << 31;
	private static final int HAS_OVERRIDES = 1 << 30;
	private static final int CLASS = 16;

	@Test
	public void vtableAndOverrides() {
		Words w = new Words();
		long d = 0x1000;
		long p = d + 44;
		w.put(p, 10); // VTableOffset
		w.put(p + 4, 4); // VTableSize
		w.put(p + 8, 0x10); // instance method
		w.rel(p + 12, 0x8000);
		w.put(p + 16, 0x01); // init (allocating)
		w.rel(p + 20, 0x8100);
		w.put(p + 24, 0x10 | 0x40); // async instance method: Impl -> AsyncFunctionPointer
		w.rel(p + 28, 0x9000);
		w.rel(0x9000, 0x8200);
		w.put(p + 32, 0x12); // getter, removed
		w.put(p + 36, 0);
		w.put(p + 40, 2); // override count
		w.put(p + 44, 0); // Class (not read)
		w.rel(p + 48, p + 8); // base: the instance method above
		w.rel(p + 52, 0x8300);
		w.put(p + 56, 0);
		w.put(p + 60, 0x2001); // base in another binary (indirect)
		w.rel(p + 64, 0x8400);
		ClassMethods m = ClassMethods.read(d, CLASS | HAS_VTABLE | HAS_OVERRIDES, w);
		assertEquals(10, m.vtableOffset());
		assertEquals(4, m.methods().size());
		assertEquals(0x8000, m.methods().getFirst().function());
		assertTrue(m.methods().getFirst().takesSelf());
		assertFalse(m.methods().get(1).takesSelf());
		assertEquals(0x9000, m.methods().get(2).impl());
		assertEquals(0x8200, m.methods().get(2).function());
		assertTrue(m.methods().get(2).takesSelf());
		assertEquals(0, m.methods().get(3).impl());
		assertEquals(2, m.overrides().size());
		assertEquals(p + 8, m.overrides().getFirst().base().address());
		assertEquals(0x8300, m.overrides().getFirst().function());
		assertNull(m.overrides().get(1).base());
		assertEquals(0x8400, m.overrides().get(1).impl());
	}

	@Test
	public void trailingObjectsBeforeTheVtable() {
		Words w = new Words();
		long d = 0x1000;
		// Resilient superclass (4 bytes) and singleton metadata initialization (12 bytes).
		long p = d + 44 + 4 + 12;
		w.put(p, 13);
		w.put(p + 4, 1);
		w.put(p + 8, 0x10);
		w.rel(p + 12, 0x8000);
		ClassMethods m = ClassMethods.read(d, CLASS | HAS_VTABLE | 1 << 29 | 1 << 16, w);
		assertEquals(13, m.vtableOffset());
		assertEquals(0x8000, m.methods().getFirst().function());
	}

	@Test
	public void genericAndPlainClasses() {
		Words w = new Words();
		assertTrue(ClassMethods.read(0x1000, CLASS | 0x80 | HAS_VTABLE, w).methods().isEmpty());
		ClassMethods m = ClassMethods.read(0x1000, CLASS, w);
		assertEquals(-1, m.vtableOffset());
		assertTrue(m.methods().isEmpty() && m.overrides().isEmpty());
	}
}
