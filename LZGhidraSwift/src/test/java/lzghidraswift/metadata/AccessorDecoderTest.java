// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Test;

import lzghidraswift.metadata.AccessorDecoder.Exit;
import lzghidraswift.metadata.AccessorDecoder.Result;

/** Encodings from the Layouts fixture's metadata accessors (otool -tvj), unless noted. */
public class AccessorDecoderTest {

	@Test
	public void structAccessor() {
		// _$s7Layouts7ScalarsVMa: adrp x0, 6; add x0, x0, #0xf0; mov x1, #0; ret
		Result r = AccessorDecoder.decode(0x281c,
			new int[] { 0xd0000020, 0x9103c000, 0xd2800001, 0xd65f03c0 }, null);
		assertEquals(Exit.RETURN, r.exit());
		assertEquals(Long.valueOf(0x80f0), r.x0());
		assertEquals(3, r.index());
	}

	@Test
	public void classAccessor() {
		// _$s7Layouts4NodeCMa: stp x29, x30, [sp, #-16]!; mov x29, sp; adrp x0, 10;
		// add x0, x0, #0x3d8; bl objc_opt_self (0x3ad0); mov x1, #0; ldp x29, x30, [sp], #16
		Result r = AccessorDecoder.decode(0x24d4, new int[] { 0xa9bf7bfd, 0x910003fd, 0xd0000040,
			0x910f6000, 0x9400057b, 0xd2800001, 0xa8c17bfd, 0xd65f03c0 }, null);
		assertEquals(Exit.CALL, r.exit());
		assertEquals(Long.valueOf(0xc3d8), r.x0());
		assertEquals(0x3ad0, r.target());
		assertEquals(4, r.index());
	}

	@Test
	public void arm64eClassAccessor() {
		// _$s7Layouts6WorkerCMa, arm64e: pacibsp; stp x29, x30, [sp, #-16]!; mov x29, sp;
		// adrp x0, 12; add x0, x0, #0x628; bl objc_opt_self (0x7bb8); mov x1, #0;
		// ldp x29, x30, [sp], #16; retab
		Result r = AccessorDecoder.decode(0x4cfc, new int[] { 0xd503237f, 0xa9bf7bfd, 0x910003fd,
			0x90000060, 0x9118a000, 0x94000baa, 0xd2800001, 0xa8c17bfd, 0xd65f0fff }, null);
		assertEquals(Exit.CALL, r.exit());
		assertEquals(Long.valueOf(0x10628), r.x0());
		assertEquals(0x7bb8, r.target());
		assertEquals(5, r.index());
	}

	@Test
	public void authenticatedReturnAndHints() {
		// Hand-assembled: bti c; paciasp; adrp x0, 1; autiasp; retaa
		Result r = AccessorDecoder.decode(0x1000,
			new int[] { 0xd503245f, 0xd503233f, 0xb0000000, 0xd50323bf, 0xd65f0bff }, null);
		assertEquals(Exit.RETURN, r.exit());
		assertEquals(Long.valueOf(0x2000), r.x0());
		assertEquals(4, r.index());
		// hint #0 (nop) and #7 (xpaclri) are not followed
		assertEquals(Exit.UNRECOGNIZED,
			AccessorDecoder.decode(0x1000, new int[] { 0xd503201f }, null).exit());
		assertEquals(Exit.UNRECOGNIZED,
			AccessorDecoder.decode(0x1000, new int[] { 0xd50320ff }, null).exit());
	}

	@Test
	public void genericAccessorTailCalls() {
		// _$s7Layouts3BoxVMa: adrp x4, 2; add x4, x4, #0x334; b swift_instantiateGenericMetadata
		Result r = AccessorDecoder.decode(0x2570, new int[] { 0xd0000004, 0x910cd084, 0x14000527 },
			null);
		assertEquals(Exit.TAIL_CALL, r.exit());
		assertNull(r.x0());
		assertEquals(0x2570 + 8 + 4 * 0x527, r.target());
	}

	@Test
	public void loadThroughPointer() {
		// Hand-assembled: adrp x8, 1; ldr x0, [x8, #0x188]; ret
		Map<Long, Long> memory = Map.of(0x2188L, 0x9000L);
		Result r = AccessorDecoder.decode(0x1000, new int[] { 0xb0000008, 0xf940c500, 0xd65f03c0 },
			memory::get);
		assertEquals(Exit.RETURN, r.exit());
		assertEquals(Long.valueOf(0x9000), r.x0());
		// Without memory the loaded value is unknown.
		assertNull(AccessorDecoder.decode(0x1000, new int[] { 0xb0000008, 0xf940c500, 0xd65f03c0 },
			null).x0());
	}

	@Test
	public void negativeAdrpAndShiftedAdd() {
		// Hand-assembled: adrp x0, -1; add x0, x0, #1, lsl #12; ret
		Result r = AccessorDecoder.decode(0x5004, new int[] { 0xf0ffffe0, 0x91400400, 0xd65f03c0 },
			null);
		assertEquals(Long.valueOf(0x5000), r.x0());
	}

	@Test
	public void backwardBranch() {
		// bl -4 (0x97ffffff) at 0x2000
		Result r = AccessorDecoder.decode(0x2000, new int[] { 0x97ffffff }, null);
		assertEquals(Exit.CALL, r.exit());
		assertEquals(0x1ffc, r.target());
	}

	@Test
	public void stopsAtOtherInstructions() {
		// cbz x0, ... (0xb4000040) is how a cache check starts: not static metadata
		Result r = AccessorDecoder.decode(0x1000, new int[] { 0xd0000020, 0xb4000040 }, null);
		assertEquals(Exit.UNRECOGNIZED, r.exit());
		assertEquals(1, r.index());
		assertEquals(0xb4000040, r.word());
		// The words run out
		r = AccessorDecoder.decode(0x1000, new int[] { 0xd0000020 }, null);
		assertEquals(Exit.UNRECOGNIZED, r.exit());
		assertEquals(1, r.index());
	}
}
