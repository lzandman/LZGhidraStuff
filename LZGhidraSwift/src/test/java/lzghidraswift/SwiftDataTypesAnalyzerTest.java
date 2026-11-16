// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import lzghidraswift.metadata.MetadataLocator.Missing;

/** The layouts summary line of Swift Data Types, which needs no program. */
public class SwiftDataTypesAnalyzerTest {

	@Test
	public void layoutSummary() {
		SwiftDataTypesAnalyzer.Counts counts = new SwiftDataTypesAnalyzer.Counts();
		counts.withMetadata = 279;
		for (int i = 0; i < 122; i++) {
			counts.withoutMetadata.merge(Missing.SINGLETON.text(), 1, Integer::sum);
		}
		counts.withoutMetadata.merge(Missing.GENERIC.text(), 27, Integer::sum);
		counts.withoutMetadata.merge(Missing.FOREIGN.text(), 21, Integer::sum);
		counts.layoutErrors = 1;
		counts.badOffsets = 2;
		assertEquals("layouts: 279 types with static metadata, 170 without (21 foreign metadata, " +
			"27 generic, 122 singleton metadata initialization); 1 layout errors, " +
			"2 field offsets out of range", counts.layoutSummary());
	}

	@Test
	public void layoutSummaryWithoutMissing() {
		SwiftDataTypesAnalyzer.Counts counts = new SwiftDataTypesAnalyzer.Counts();
		counts.withMetadata = 10;
		assertEquals("layouts: 10 types with static metadata, 0 without; 0 layout errors, " +
			"0 field offsets out of range", counts.layoutSummary());
	}
}
