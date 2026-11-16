// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.Test;

import lzghidraswift.metadata.MetadataLocator.Missing;

/**
 * The groups of the reasons for missing metadata. {@code locate} needs a program; of its
 * reasons, the fixtures reach only the generic one.
 */
public class MetadataLocatorTest {

	@Test
	public void groupTexts() {
		assertEquals(List.of("generic", "singleton metadata initialization", "foreign metadata",
			"no metadata accessor", "accessor decoding not implemented",
			"accessor calls another function", "accessor: no ret or call",
			"accessor: unrecognized instruction", "accessor result not constant",
			"metadata describes another type", "metadata not readable"),
			Arrays.stream(Missing.values()).map(Missing::text).toList());
	}

	/** The summary lists the groups in the order of their text. */
	@Test
	public void summaryOrderOfTheGroupsThatOccur() {
		assertEquals(List.of("foreign metadata", "generic", "singleton metadata initialization"),
			Stream.of(Missing.SINGLETON, Missing.GENERIC, Missing.FOREIGN)
					.map(Missing::text)
					.sorted()
					.toList());
	}
}
