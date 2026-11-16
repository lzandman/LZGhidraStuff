// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import org.junit.Test;

import lzghidraswift.metadata.FieldDescriptors.Descriptor;
import lzghidraswift.metadata.FieldDescriptors.FieldRecord;

public class FieldDescriptorsTest {

	private static final long BASE = 0x1000;
	private static final int SIZE = 0x100;

	/** A little-endian section of {@link #SIZE} bytes at {@link #BASE}; reading outside fails. */
	private static final class Section implements WordReader {
		final ByteBuffer bytes = ByteBuffer.allocate(SIZE).order(ByteOrder.LITTLE_ENDIAN);

		void i32(long address, int value) {
			bytes.putInt(index(address, 4), value);
		}

		void u16(long address, int value) {
			bytes.putShort(index(address, 2), (short) value);
		}

		/** A relative pointer at {@code at} to {@code target}. */
		void rel(long at, long target) {
			i32(at, (int) (target - at));
		}

		/** A descriptor header at {@code at}. */
		void header(long at, long typeName, int kind, int recordSize, int count) {
			rel(at, typeName);
			u16(at + 8, kind);
			u16(at + 10, recordSize);
			i32(at + 12, count);
		}

		@Override
		public int i32(long address) {
			return bytes.getInt(index(address, 4));
		}

		@Override
		public int u16(long address) {
			return bytes.getShort(index(address, 2)) & 0xffff;
		}

		private static int index(long address, int length) {
			if (address < BASE || address + length > BASE + SIZE) {
				throw new IllegalStateException("unmapped " + Long.toHexString(address));
			}
			return (int) (address - BASE);
		}
	}

	@Test
	public void descriptorWithTwoRecords() {
		Section s = new Section();
		long d = BASE + 0x10;
		s.header(d, BASE + 0xc0, 1, 12, 2);
		long r0 = d + 16;
		long r1 = r0 + 12;
		s.i32(r0, 2);
		s.rel(r0 + 4, BASE + 0xd0);
		s.rel(r0 + 8, BASE + 0xe0);
		s.i32(r1, 0);
		// r1 + 4 stays 0: no type, an enum case without payload.
		s.rel(r1 + 8, BASE + 0xf0);
		Descriptor fd = FieldDescriptors.read(d, BASE + SIZE, s);
		assertTrue(fd.fits());
		assertEquals(BASE + 0xc0, fd.typeName());
		assertEquals("class", fd.kindName());
		assertEquals(2, fd.count());
		assertEquals(List.of(new FieldRecord(r0, 2, BASE + 0xd0, BASE + 0xe0),
			new FieldRecord(r1, 0, 0, BASE + 0xf0)), fd.records());
		assertEquals(r1 + 12, fd.end());
	}

	@Test
	public void largerRecordSizeSkipsTheRest() {
		Section s = new Section();
		s.header(BASE, 0, 0, 16, 2);
		s.i32(BASE + 16 + 16, 4);
		Descriptor fd = FieldDescriptors.read(BASE, BASE + SIZE, s);
		assertEquals(0, fd.typeName());
		assertEquals("struct", fd.kindName());
		assertEquals(BASE + 32, fd.records().get(1).address());
		assertEquals(4, fd.records().get(1).flags());
		assertEquals(BASE + 48, fd.end());
	}

	@Test
	public void kindOutsideTheTable() {
		Section s = new Section();
		s.header(BASE, 0, 8, 12, 0);
		assertEquals("kind 8", FieldDescriptors.read(BASE, BASE + SIZE, s).kindName());
	}

	@Test
	public void recordSizeBelowTwelveDoesNotFit() {
		Section s = new Section();
		s.header(BASE, 0, 0, 11, 1);
		Descriptor fd = FieldDescriptors.read(BASE, BASE + SIZE, s);
		assertFalse(fd.fits());
		assertEquals(11, fd.recordSize());
		assertTrue(fd.records().isEmpty());
	}

	@Test
	public void negativeCountDoesNotFit() {
		Section s = new Section();
		s.header(BASE, 0, 0, 12, -1);
		Descriptor fd = FieldDescriptors.read(BASE, BASE + SIZE, s);
		assertFalse(fd.fits());
		assertEquals(-1, fd.count());
	}

	@Test
	public void recordsPastTheSectionEndDoNotFit() {
		Section s = new Section();
		// 16 + 12 x 2 = 40 bytes: fits in 40, not in 39.
		s.header(BASE, 0, 0, 12, 2);
		assertTrue(FieldDescriptors.read(BASE, BASE + 40, s).fits());
		assertFalse(FieldDescriptors.read(BASE, BASE + 39, s).fits());
		// A count whose records would overflow an int.
		s.header(BASE, 0, 0, 0xffff, Integer.MAX_VALUE);
		assertFalse(FieldDescriptors.read(BASE, BASE + SIZE, s).fits());
	}

	@Test
	public void unreadableHeaderThrows() {
		Section s = new Section();
		assertThrows(IllegalStateException.class,
			() -> FieldDescriptors.read(BASE + SIZE - 8, BASE + SIZE, s));
	}

	@Test
	public void flagBits() {
		assertEquals("", new FieldRecord(0, 0, 0, 0).flagNames());
		assertEquals("indirect", new FieldRecord(0, 1, 0, 0).flagNames());
		assertEquals("var", new FieldRecord(0, 2, 0, 0).flagNames());
		assertEquals("artificial", new FieldRecord(0, 4, 0, 0).flagNames());
		assertEquals("indirect var artificial", new FieldRecord(0, 7 | 8, 0, 0).flagNames());
	}
}
