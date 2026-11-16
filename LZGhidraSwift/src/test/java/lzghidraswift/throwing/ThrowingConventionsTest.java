// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.throwing;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.xml.sax.SAXException;

import lzghidraswift.throwing.ThrowingConventions.XmlRegister;

/**
 * The XML transformation of {@link ThrowingConventions}. The prototypes are in the form of
 * {@code PrototypeModel.encode}, shortened from Ghidra 12.2's Swift conventions
 * ({@code Features/Swift/data/extensions}).
 */
public class ThrowingConventionsTest {

	private static final XmlRegister X21 = new XmlRegister("x21", "register", 0x40a8, 8);
	private static final XmlRegister R12 = new XmlRegister("R12", "register", 0xa0, 8);

	/**
	 * aarch64/swift_thiscall.xml: x19, x21 and x22 unaffected, no return address; results in d0
	 * and in x0, x1.
	 */
	private static final String AARCH64_SWIFT_THISCALL = """
			<prototype name="__swift_thiscall" extrapop="0" stackshift="0" hasthis="true">
			  <input killedbycall="false">
			    <pentry minsize="1" maxsize="8" extension="zero">
			      <addr space="register" offset="0x40a0"/>
			    </pentry>
			  </input>
			  <output killedbycall="false">
			    <pentry minsize="2" maxsize="8" storage="float">
			      <addr space="register" offset="0x5000"/>
			    </pentry>
			    <pentry minsize="1" maxsize="8">
			      <addr space="register" offset="0x4000"/>
			    </pentry>
			    <pentry minsize="1" maxsize="8">
			      <addr space="register" offset="0x4008"/>
			    </pentry>
			    <rule>
			      <datatype name="any" minsize="0x1" maxsize="0x20"/>
			      <join align="false" stackspill="false" backfill="false"/>
			    </rule>
			  </output>
			  <unaffected>
			    <varnode space="register" offset="0x4098" size="8"/>
			    <varnode space="register" offset="0x40a8" size="8"/>
			    <varnode space="register" offset="0x40b0" size="8"/>
			  </unaffected>
			  <killedbycall>
			    <varnode space="register" offset="0x4040" size="8"/>
			  </killedbycall>
			  <returnaddress/>
			</prototype>
			""";

	/**
	 * x86_64/swift_stdcall.xml: R12 is the fourth unaffected register; results in XMM0 and
	 * in RAX, RDX, RCX, R8, of which RAX and RDX are killed, as XMM0 is.
	 */
	private static final String X86_64_SWIFT_STDCALL = """
			<prototype name="__swift_stdcall" extrapop="8" stackshift="8">
			  <output killedbycall="false">
			    <pentry minsize="4" maxsize="8" storage="float">
			      <addr space="register" offset="0x1200"/>
			    </pentry>
			    <pentry minsize="1" maxsize="8">
			      <addr space="register" offset="0x0"/>
			    </pentry>
			    <pentry minsize="1" maxsize="8">
			      <addr space="register" offset="0x10"/>
			    </pentry>
			    <pentry minsize="1" maxsize="8">
			      <addr space="register" offset="0x8"/>
			    </pentry>
			    <pentry minsize="1" maxsize="8">
			      <addr space="register" offset="0x80"/>
			    </pentry>
			  </output>
			  <unaffected>
			    <varnode space="register" offset="0x18" size="8"/>
			    <varnode space="register" offset="0xa0" size="8"/>
			    <varnode space="register" offset="0xa8" size="8"/>
			  </unaffected>
			  <killedbycall>
			    <varnode space="register" offset="0x0" size="8"/>
			    <varnode space="register" offset="0x10" size="8"/>
			    <varnode space="register" offset="0x1200" size="16"/>
			  </killedbycall>
			  <returnaddress>
			    <varnode space="stack" offset="0x0" size="8"/>
			  </returnaddress>
			</prototype>
			""";

	@Test
	public void movesErrorRegisterToKilledByCall() throws SAXException {
		String xml =
			ThrowingConventions.variantXml(AARCH64_SWIFT_THISCALL, "__swift_thiscall_throws", X21);
		assertTrue(xml, xml.startsWith(
			"<prototype extrapop=\"0\" hasthis=\"true\" name=\"__swift_thiscall_throws\""));
		String unaffected = section(xml, "unaffected");
		assertFalse(unaffected, unaffected.contains("0x40a8"));
		assertTrue(unaffected, unaffected.contains("0x4098"));
		assertTrue(unaffected, unaffected.contains("0x40b0"));
		String killed = section(xml, "killedbycall");
		assertTrue(killed, killed.contains("0x4040"));
		assertTrue(killed, killed.contains("<register name=\"x21\"/>"));
		assertTrue(xml, xml.contains("offset=\"0x40a0\""));
	}

	/**
	 * The result registers are killed too, each once: integer and float ones. XMM0_Qa (0x1200,
	 * 8 bytes) overlaps the XMM0 that x86_64 kills already.
	 */
	@Test
	public void killsResultRegisters() throws SAXException {
		String arm =
			ThrowingConventions.variantXml(AARCH64_SWIFT_THISCALL, "__swift_thiscall_throws", X21);
		String armKilled = section(arm, "killedbycall");
		assertTrue(armKilled, armKilled.contains(
			"<varnode offset=\"0x4000\" size=\"8\" space=\"register\"/>"));
		assertTrue(armKilled, armKilled.contains("offset=\"0x4008\""));
		assertTrue(armKilled, armKilled.contains(
			"<varnode offset=\"0x5000\" size=\"8\" space=\"register\"/>"));
		String x86 =
			ThrowingConventions.variantXml(X86_64_SWIFT_STDCALL, "__swift_stdcall_throws", R12);
		String x86Killed = section(x86, "killedbycall");
		for (String offset : new String[] { "0x0", "0x10", "0x8", "0x80", "0x1200" }) {
			String text = "offset=\"" + offset + "\"";
			assertEquals(x86Killed, x86Killed.indexOf(text), x86Killed.lastIndexOf(text));
			assertTrue(x86Killed, x86Killed.contains(text));
		}
	}

	/** The cspec form: registers by name; X1 is killed already. */
	@Test
	public void killsResultRegistersByName() throws SAXException {
		String cspec = """
				<prototype name="p">
				  <output>
				    <pentry minsize="2" maxsize="8" metatype="float"><register name="d0"/></pentry>
				    <pentry minsize="1" maxsize="8"><register name="x0"/></pentry>
				    <pentry minsize="1" maxsize="8"><register name="x1"/></pentry>
				  </output>
				  <unaffected><register name="x21"/></unaffected>
				  <killedbycall><register name="X1"/></killedbycall>
				</prototype>""";
		String killed = section(ThrowingConventions.variantXml(cspec, "p_throws", X21),
			"killedbycall");
		assertTrue(killed, killed.contains("<register name=\"x0\"/>"));
		assertFalse(killed, killed.contains("<register name=\"x1\"/>"));
		assertTrue(killed, killed.contains("<register name=\"d0\"/>"));
	}

	@Test
	public void dropsEmptyReturnAddressKeepsOthers() throws SAXException {
		String arm =
			ThrowingConventions.variantXml(AARCH64_SWIFT_THISCALL, "__swift_thiscall_throws", X21);
		assertFalse(arm, arm.contains("returnaddress"));
		String x86 =
			ThrowingConventions.variantXml(X86_64_SWIFT_STDCALL, "__swift_stdcall_throws", R12);
		assertTrue(x86, section(x86, "returnaddress").contains("space=\"stack\""));
	}

	@Test
	public void x86ErrorRegisterIsR12() throws SAXException {
		String xml =
			ThrowingConventions.variantXml(X86_64_SWIFT_STDCALL, "__swift_stdcall_throws", R12);
		assertFalse(xml, section(xml, "unaffected").contains("0xa0\""));
		assertTrue(xml, section(xml, "unaffected").contains("0xa8\""));
		assertTrue(xml, section(xml, "killedbycall").contains("<register name=\"R12\"/>"));
	}

	/** The cspec form names registers; a partial register (w21) also counts as x21. */
	@Test
	public void matchesRegisterNamesAndOverlaps() throws SAXException {
		String byName = """
				<prototype name="p">
				  <unaffected><register name="X21"/><register name="x22"/></unaffected>
				</prototype>""";
		String xml = ThrowingConventions.variantXml(byName, "p_throws", X21);
		assertFalse(xml, section(xml, "unaffected").contains("X21"));
		assertTrue(xml, section(xml, "unaffected").contains("x22"));
		String w21 = """
				<prototype name="p">
				  <unaffected><varnode space="register" offset="0x40a8" size="4"/></unaffected>
				</prototype>""";
		assertFalse(ThrowingConventions.variantXml(w21, "p_throws", X21).contains("0x40a8"));
		String x22 = """
				<prototype name="p">
				  <unaffected><varnode space="register" offset="0x40b0" size="8"/></unaffected>
				</prototype>""";
		assertNull(ThrowingConventions.variantXml(x22, "p_throws", X21));
	}

	@Test
	public void addsKilledByCallOnceAfterUnaffected() throws SAXException {
		String noKilled = """
				<prototype name="p">
				  <unaffected><register name="x21"/></unaffected>
				  <returnaddress><register name="x30"/></returnaddress>
				</prototype>""";
		String xml = ThrowingConventions.variantXml(noKilled, "p_throws", X21);
		assertTrue(xml, xml.indexOf("<killedbycall>") > xml.indexOf("<unaffected"));
		assertTrue(xml, xml.indexOf("<killedbycall>") < xml.indexOf("<returnaddress>"));
		String alreadyKilled = """
				<prototype name="p">
				  <unaffected><register name="x21"/></unaffected>
				  <killedbycall><varnode space="register" offset="0x40a8" size="8"/></killedbycall>
				</prototype>""";
		String once = ThrowingConventions.variantXml(alreadyKilled, "p_throws", X21);
		assertFalse(once, once.contains("<register name=\"x21\"/>"));
	}

	@Test
	public void noVariantWithoutErrorRegisterOrForAlias() throws SAXException {
		assertNull(ThrowingConventions.variantXml(
			"<prototype name=\"p\"><killedbycall><register name=\"x0\"/></killedbycall></prototype>",
			"p_throws", X21));
		assertNull(ThrowingConventions.variantXml(
			"<modelalias name=\"__cdecl\" parent=\"__swift_stdcall\"/>", "x_throws", X21));
	}

	/**
	 * The indirect variant: x8 (hiddenret, first) becomes an ordinary entry before the first
	 * integer entry (x20 of __swift_thiscall), after the float entries.
	 */
	@Test
	public void indirectResultBecomesFirstIntegerParameter() throws SAXException {
		String input = """
				<prototype name="__swift_thiscall_throws" hasthis="true">
				  <input killedbycall="false">
				    <pentry minsize="8" maxsize="8" storage="hiddenret">
				      <addr space="register" offset="0x4040"/>
				    </pentry>
				    <pentry minsize="2" maxsize="8" storage="float">
				      <addr space="register" offset="0x5000"/>
				    </pentry>
				    <pentry minsize="1" maxsize="8" extension="zero">
				      <addr space="register" offset="0x40a0"/>
				    </pentry>
				    <pentry minsize="1" maxsize="8" extension="zero">
				      <addr space="register" offset="0x4000"/>
				    </pentry>
				  </input>
				  <killedbycall><register name="x21"/></killedbycall>
				</prototype>""";
		String xml =
			ThrowingConventions.indirectVariantXml(input, "__swift_thiscall_indirect_throws");
		assertTrue(xml, xml.contains("name=\"__swift_thiscall_indirect_throws\""));
		assertFalse(xml, xml.contains("hiddenret"));
		String in = section(xml, "input");
		int d0 = in.indexOf("0x5000");
		int x8 = in.indexOf("0x4040");
		int x20 = in.indexOf("0x40a0");
		assertTrue(in, d0 >= 0 && d0 < x8 && x8 < x20 && x20 < in.indexOf("0x4000"));
		assertTrue(xml, section(xml, "killedbycall").contains("x21"));
	}

	@Test
	public void noIndirectVariantWithoutHiddenReturn() throws SAXException {
		assertNull(ThrowingConventions.indirectVariantXml("""
				<prototype name="p_throws">
				  <input><pentry minsize="1" maxsize="8"><register name="x0"/></pentry></input>
				</prototype>""", "p_indirect_throws"));
	}

	@Test
	public void variantNames() {
		assertEquals("__swift_stdcall_throws",
			ThrowingConventions.variantName("__swift_stdcall"));
		assertEquals("__swift_stdcall_indirect_throws",
			ThrowingConventions.indirectVariantName("__swift_stdcall"));
	}

	@Test
	public void summary() {
		ThrowingConventions.Result result = new ThrowingConventions.Result();
		assertEquals("throwing conventions: 0 added [], 0 present [], 0 skipped [], 0 failed []",
			result.summary());
		result.added.add("__swift_stdcall_throws");
		result.added.add("__swift_stdcall_indirect_throws");
		result.present.add("__swift_thiscall_throws");
		result.skipped.add("__swift_asynccall");
		result.failed.add("__swift_thiscall_indirect_throws: no output");
		assertEquals("throwing conventions: 2 added [__swift_stdcall_throws, " +
			"__swift_stdcall_indirect_throws], 1 present [__swift_thiscall_throws], 1 skipped " +
			"[__swift_asynccall], 1 failed [__swift_thiscall_indirect_throws: no output]",
			result.summary());
	}

	private static String section(String xml, String tag) {
		int start = xml.indexOf("<" + tag);
		int end = xml.indexOf("</" + tag + ">", start);
		return xml.substring(start, end);
	}
}
