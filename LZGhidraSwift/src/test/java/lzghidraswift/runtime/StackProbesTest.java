// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.runtime;

import static org.junit.Assert.*;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.Test;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/** The convention XML of {@link StackProbes}. */
public class StackProbesTest {

	private static Element prototype() throws Exception {
		return DocumentBuilderFactory.newInstance()
				.newDocumentBuilder()
				.parse(new InputSource(new StringReader(StackProbes.PROTOTYPE)))
				.getDocumentElement();
	}

	/** The register names under the first {@code tag} element, in order. */
	private static List<String> registers(Element prototype, String tag) {
		Element list = (Element) prototype.getElementsByTagName(tag).item(0);
		NodeList regs = list.getElementsByTagName("register");
		List<String> names = new ArrayList<>();
		for (int i = 0; i < regs.getLength(); i++) {
			names.add(((Element) regs.item(i)).getAttribute("name"));
		}
		return names;
	}

	@Test
	public void takesTheSizeInX9() throws Exception {
		Element p = prototype();
		assertEquals(StackProbes.CONVENTION, p.getAttribute("name"));
		assertEquals(List.of("x9"), registers(p, "input"));
	}

	@Test
	public void killsOnlyX9X16X17() throws Exception {
		assertEquals(List.of("x9", "x16", "x17"), registers(prototype(), "killedbycall"));
	}

	@Test
	public void keepsEveryOtherRegister() throws Exception {
		Set<String> unaffected = new HashSet<>(registers(prototype(), "unaffected"));
		// x0 to x30 without the 3 killed ones, sp, q0 to q31.
		assertEquals(28 + 1 + 32, unaffected.size());
		for (String r : List.of("x0", "x1", "x8", "x10", "x15", "x18", "x29", "x30", "sp", "q0",
			"q31")) {
			assertTrue(r, unaffected.contains(r));
		}
		for (String r : StackProbes.KILLED) {
			assertFalse(r, unaffected.contains(r));
		}
	}
}
