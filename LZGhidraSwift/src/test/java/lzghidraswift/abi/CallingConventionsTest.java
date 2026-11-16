// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.abi;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class CallingConventionsTest {

	@Test
	public void swiftConventions() {
		assertTrue(CallingConventions.isSwiftConvention("__swift_stdcall"));
		assertTrue(CallingConventions.isSwiftConvention("__swift_thiscall"));
		assertFalse(CallingConventions.isSwiftConvention("__cdecl"));
		assertFalse(CallingConventions.isSwiftConvention("__thiscall"));
		assertFalse(CallingConventions.isSwiftConvention("__objc_msgSend_stub"));
		assertFalse(CallingConventions.isSwiftConvention("__swift_stdcall_throws"));
		assertFalse(CallingConventions.isSwiftConvention("__swift_thiscall_indirect_throws"));
	}
}
