// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

import org.junit.Test;

public class SwiftStringCodecTest {

	/** Encodes a small string the way the Swift compiler does; the test's own reference. */
	private static long[] small(String s) {
		byte[] b = s.getBytes(StandardCharsets.UTF_8);
		assertTrue(b.length <= 15);
		boolean ascii = true;
		long w0 = 0;
		long w1 = 0;
		for (int i = 0; i < b.length; i++) {
			long v = b[i] & 0xFFL;
			ascii &= v < 0x80;
			if (i < 8) {
				w0 |= v << (8 * i);
			}
			else {
				w1 |= v << (8 * (i - 8));
			}
		}
		w1 |= (ascii ? 0xEL : 0xAL) << 60;
		w1 |= (long) b.length << 56;
		return new long[] { w0, w1 };
	}

	@Test
	public void everyCount() {
		String all = "abcdefghijklmno";
		for (int n = 0; n <= 15; n++) {
			String s = all.substring(0, n);
			long[] w = small(s);
			assertTrue(SwiftStringCodec.isSmallTag(w[1]));
			assertEquals(s, SwiftStringCodec.decodeSmall(w[0], w[1]));
		}
	}

	@Test
	public void handWrittenWords() {
		// From the fixture: "chord_change" in otool, and the empty string.
		assertEquals("tempo_change",
			SwiftStringCodec.decodeSmall(0x6863_5f6f_706d_6574L, 0xEC00_0000_6567_6E61L));
		assertEquals("", SwiftStringCodec.decodeSmall(0, 0xE000_0000_0000_0000L));
		assertEquals("Flat", SwiftStringCodec.decodeSmall(0x7461_6c46L, 0xE400_0000_0000_0000L));
		assertEquals("harmonyAnalyzer",
			SwiftStringCodec.decodeSmall(0x4179_6e6f_6d72_6168L, 0xEF72_657a_796c_616eL));
	}

	@Test
	public void nonAscii() {
		for (String s : new String[] { "é", "×", "Füße", "Füße über" }) {
			long[] w = small(s);
			assertEquals(0xAL, w[1] >>> 60);
			assertEquals(s, SwiftStringCodec.decodeSmall(w[0], w[1]));
		}
		// "é" from the fixture: mov w0, #0xa9c3; mov x1, #-0x5e00000000000000
		assertEquals("é", SwiftStringCodec.decodeSmall(0xa9c3L, 0xA200_0000_0000_0000L));
	}

	@Test
	public void asciiFlagMustMatch() {
		long[] w = small("Flat");
		assertNull(SwiftStringCodec.decodeSmall(w[0], (w[1] & ~(0xFL << 60)) | (0xAL << 60)));
		long[] u = small("é");
		assertNull(SwiftStringCodec.decodeSmall(u[0], (u[1] & ~(0xFL << 60)) | (0xEL << 60)));
	}

	@Test
	public void bytePastCount() {
		long[] w = small("Flat");
		assertNull(SwiftStringCodec.decodeSmall(w[0] | (0x41L << 32), w[1]));
		assertNull(SwiftStringCodec.decodeSmall(w[0], w[1] | 0x41));
		assertFalse(SwiftStringCodec.isSmallTag(w[1] | 0x41));
	}

	@Test
	public void invalidUtf8() {
		// 0xC3 needs a continuation byte.
		assertNull(SwiftStringCodec.decodeSmall(0xC3L, 0xA100_0000_0000_0000L));
		// Overlong encoding of '/'.
		assertNull(SwiftStringCodec.decodeSmall(0xAFC0L, 0xA200_0000_0000_0000L));
	}

	@Test
	public void notTags() {
		assertFalse(SwiftStringCodec.isSmallTag(0xAAAA_AAAA_AAAA_AAABL));
		assertNull(SwiftStringCodec.decodeSmall(0, 0xAAAA_AAAA_AAAA_AAABL));
		assertFalse(SwiftStringCodec.isSmallTag(0xAAAA_AAAA_AAAA_AAAAL));
		assertFalse(SwiftStringCodec.isSmallTag(0xCCCC_CCCC_CCCC_CCCDL));
		assertFalse(SwiftStringCodec.isSmallTag(0x6000_0000_0000_0000L));
		// A NUL inside the count is valid Swift: "Flat" bytes with count 5 decode as "Flat\0".
		// The pairing, not the codec, has to keep the "Flat" word 0 away from the "Sharp" tag.
		assertTrue(SwiftStringCodec.isSmallTag(0xE500_0000_0000_0000L));
		assertEquals("Flat\0", SwiftStringCodec.decodeSmall(0x7461_6c46L, 0xE500_0000_0000_0000L));
	}

	@Test
	public void largeHeaders() {
		// "md5_ovs_blocklist" style: 17 bytes, ASCII.
		SwiftStringCodec.LargeHeader h =
			SwiftStringCodec.decodeLargeHeader(0xD000_0000_0000_0011L, 0x8000_0000_0000_08C0L);
		assertNotNull(h);
		assertEquals(17, h.count());
		assertTrue(h.ascii());
		assertEquals(0x8E0L, h.address());

		h = SwiftStringCodec.decodeLargeHeader(0x1000_0000_0000_0013L, 0x8000_0000_0000_2310L);
		assertNotNull(h);
		assertEquals(19, h.count());
		assertFalse(h.ascii());
		assertEquals(0x2330L, h.address());

		assertNull(
			SwiftStringCodec.decodeLargeHeader(0xD000_0000_0000_0005L, 0x8000_0000_0000_08C0L));
		assertNull(
			SwiftStringCodec.decodeLargeHeader(0xC000_0000_0000_0011L, 0x8000_0000_0000_08C0L));
		assertNull(
			SwiftStringCodec.decodeLargeHeader(0xD000_0000_0000_0011L, 0x4000_0000_0000_08C0L));
	}

	@Test
	public void largeBytes() {
		SwiftStringCodec.LargeHeader h = new SwiftStringCodec.LargeHeader(16, true, 0);
		byte[] ok = "0123456789abcdef\0".getBytes(StandardCharsets.UTF_8);
		assertEquals("0123456789abcdef", SwiftStringCodec.checkLargeBytes(h, ok));
		byte[] noNul = "0123456789abcdefg".getBytes(StandardCharsets.UTF_8);
		assertNull(SwiftStringCodec.checkLargeBytes(h, noNul));
		SwiftStringCodec.LargeHeader nonAscii = new SwiftStringCodec.LargeHeader(16, false, 0);
		assertNull(SwiftStringCodec.checkLargeBytes(nonAscii, ok));
	}

	@Test
	public void quoting() {
		assertEquals("\"Flat\"", SwiftStringCodec.quote("Flat"));
		assertEquals("\"a\\\"b\\\\c\\n\\x01\"", SwiftStringCodec.quote("a\"b\\c\n\u0001"));
		assertEquals("\"Füße\"", SwiftStringCodec.quote("Füße"));
	}
}
