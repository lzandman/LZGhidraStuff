// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.types;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/** The summary line of {@link SwiftTypeCatalog}, which needs no program. */
public class SwiftTypeCatalogTest {

	@Test
	public void summary() {
		SwiftTypeCatalog.Counts counts = new SwiftTypeCatalog.Counts();
		counts.entries = 12;
		counts.classes = 2;
		counts.structs = 7;
		counts.enums = 1;
		counts.other = 1;
		counts.unreadable = 1;
		assertEquals("found 10 Swift types in __swift5_types (12 entries): 2 classes, " +
			"7 structs, 1 enums, 1 other, 1 unreadable", counts.summary(10));
	}
}
