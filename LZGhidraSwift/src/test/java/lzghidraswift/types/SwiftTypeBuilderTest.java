// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.types;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

public class SwiftTypeBuilderTest {

	@Test
	public void nameParts() {
		assertEquals(List.of("Layouts", "Outer", "Inner"),
			SwiftTypeBuilder.nameParts("Layouts.Outer.Inner"));
		assertEquals(List.of("__C", "URLResourceKey"),
			SwiftTypeBuilder.nameParts("__C.URLResourceKey"));
		// Dots inside generic arguments do not split.
		assertEquals(List.of("Swift", "Array<Swift.Int>", "Helper"),
			SwiftTypeBuilder.nameParts("Swift.Array<Swift.Int>.Helper"));
		assertEquals(List.of("M", "a_b"), SwiftTypeBuilder.nameParts("M.a/b"));
		// A type in an extension in another module, as Swift names it
		assertEquals(List.of("(extension in Layouts):Foundation", "URL", "Component"),
			SwiftTypeBuilder.nameParts("(extension in Layouts):Foundation.URL.Component"));
		assertEquals("Inner", SwiftTypeBuilder.simpleName("Layouts.Outer.Inner"));
		assertEquals("/SwiftTypes/Layouts/Outer",
			SwiftTypeBuilder.category("Layouts.Outer.Inner").getPath());
	}

	@Test
	public void align() {
		assertEquals(24, SwiftTypeMapper.align(17, 8));
		assertEquals(16, SwiftTypeMapper.align(16, 8));
		assertEquals(17, SwiftTypeMapper.align(17, 1));
	}
}
