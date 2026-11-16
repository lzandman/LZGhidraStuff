// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Test;

import lzghidraswift.metadata.AccessorDecoder.Exit;
import lzghidraswift.metadata.AccessorDecoder.Result;

/**
 * Encodings from the x86_64 Layouts fixture's metadata accessors (otool -tvj), unless noted.
 */
public class X86AccessorDecoderTest {

	private static byte[] bytes(int... values) {
		byte[] b = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			b[i] = (byte) values[i];
		}
		return b;
	}

	@Test
	public void structAccessor() {
		// _$s7Layouts7ScalarsVMa: lea rax, [rip + 0x32c1]; xor edx, edx; ret; nopw
		Result r = X86AccessorDecoder.decode(0x2db0, bytes(0x48, 0x8d, 0x05, 0xc1, 0x32, 0x00,
			0x00, 0x31, 0xd2, 0xc3, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00), null);
		assertEquals(Exit.RETURN, r.exit());
		assertEquals(Long.valueOf(0x2db7 + 0x32c1), r.x0());
		assertEquals(9, r.index());
	}

	@Test
	public void classAccessor() {
		// _$s7Layouts4NodeCMa: push rbp; mov rbp, rsp; lea rdi, [rip + 0x4a25];
		// call objc_opt_self (0x4112); xor edx, edx; pop rbp; ret
		Result r = X86AccessorDecoder.decode(0x2a50, bytes(0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d,
			0x3d, 0x25, 0x4a, 0x00, 0x00, 0xe8, 0xb2, 0x16, 0x00, 0x00, 0x31, 0xd2, 0x5d, 0xc3),
			null);
		assertEquals(Exit.CALL, r.exit());
		assertEquals(Long.valueOf(0x2a5b + 0x4a25), r.x0());
		assertEquals(0x4112, r.target());
		assertEquals(11, r.index());
	}

	@Test
	public void genericAccessorTailCalls() {
		// _$s7Layouts3BoxVMa: lea r8, [rip + 0x1e0d]; jmp swift_instantiateGenericMetadata
		Result r = X86AccessorDecoder.decode(0x2af0, bytes(0x4c, 0x8d, 0x05, 0x0d, 0x1e, 0x00,
			0x00, 0xe9, 0x44, 0x15, 0x00, 0x00), null);
		assertEquals(Exit.TAIL_CALL, r.exit());
		assertNull(r.x0());
		assertEquals(0x4040, r.target());
	}

	@Test
	public void loadThroughPointer() {
		// Hand-assembled: mov rax, [rip + 0x100]; ret
		byte[] code = bytes(0x48, 0x8b, 0x05, 0x00, 0x01, 0x00, 0x00, 0xc3);
		Map<Long, Long> memory = Map.of(0x1107L, 0x9000L);
		Result r = X86AccessorDecoder.decode(0x1000, code, memory::get);
		assertEquals(Exit.RETURN, r.exit());
		assertEquals(Long.valueOf(0x9000), r.x0());
		assertNull(X86AccessorDecoder.decode(0x1000, code, null).x0());
	}

	@Test
	public void negativeDisplacementAndRegisterMove() {
		// Hand-assembled: lea rcx, [rip - 0x10]; mov rax, rcx; ret
		Result r = X86AccessorDecoder.decode(0x5000, bytes(0x48, 0x8d, 0x0d, 0xf0, 0xff, 0xff,
			0xff, 0x48, 0x89, 0xc8, 0xc3), null);
		assertEquals(Long.valueOf(0x5007 - 0x10), r.x0());
	}

	@Test
	public void backwardShortJump() {
		// jmp -2 (eb fe) at 0x2000
		Result r = X86AccessorDecoder.decode(0x2000, bytes(0xeb, 0xfe), null);
		assertEquals(Exit.TAIL_CALL, r.exit());
		assertEquals(0x2000, r.target());
	}

	@Test
	public void stopsAtOtherInstructions() {
		// test rax, rax (48 85 c0) is how a cache check starts: not static metadata
		Result r = X86AccessorDecoder.decode(0x1000, bytes(0x48, 0x8b, 0x05, 0, 0, 0, 0, 0x48,
			0x85, 0xc0, 0x74, 0x01), null);
		assertEquals(Exit.UNRECOGNIZED, r.exit());
		assertEquals(7, r.index());
		assertEquals(0x4885c074, r.word());
		// The bytes run out
		r = X86AccessorDecoder.decode(0x1000, bytes(0x55), null);
		assertEquals(Exit.UNRECOGNIZED, r.exit());
		assertEquals(1, r.index());
	}
}
