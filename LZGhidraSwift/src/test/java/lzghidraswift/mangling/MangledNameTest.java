// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.mangling;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.Test;

import lzghidraswift.mangling.MangledName.Reference;
import lzghidraswift.mangling.MangledName.Text;

public class MangledNameTest {

	/** Builds a byte sequence from strings (as ASCII) and byte values (Integer). */
	private static byte[] bytes(Object... parts) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (Object part : parts) {
			if (part instanceof String s) {
				out.writeBytes(s.getBytes(StandardCharsets.US_ASCII));
			}
			else {
				out.write((Integer) part);
			}
		}
		return out.toByteArray();
	}

	@Test
	public void plainText() {
		MangledName name = MangledName.parse(bytes("SaySdG", 0), 0);
		assertEquals(List.of(new Text("SaySdG")), name.parts());
		assertEquals(6, name.length());
		assertNull(name.soleReference());
		assertEquals("SaySdG", name.render(r -> "x"));
	}

	@Test
	public void empty() {
		MangledName name = MangledName.parse(bytes(0), 0);
		assertEquals(List.of(), name.parts());
		assertEquals(0, name.length());
	}

	/**
	 * A small positive offset has 0x00 in its high bytes: a field type
	 * seen in a real binary, 02 4f 7e 00 00. A NUL-terminated
	 * read stops after 3 bytes.
	 */
	@Test
	public void offsetWithZeroBytes() {
		MangledName name = MangledName.parse(bytes(0x02, 0x4f, 0x7e, 0x00, 0x00, 0), 0);
		Reference ref = name.soleReference();
		assertEquals(new Reference(0x02, 0, 0x7e4f), ref);
		assertEquals(5, name.length());
		assertEquals(1 + 0x7e4f, ref.targetOffset());
	}

	/** Offset 0x00000100: two NUL bytes in the middle and one at the end of the operand. */
	@Test
	public void zeroBytesInsideOperand() {
		MangledName name = MangledName.parse(bytes(0x01, 0x00, 0x01, 0x00, 0x00, "Sg", 0), 0);
		assertEquals(List.of(new Reference(0x01, 0, 0x100), new Text("Sg")), name.parts());
		assertEquals(7, name.length());
	}

	@Test
	public void negativeOffset() {
		// 0x0c with 0xffffc585 (-0x3a7b): seen in a real binary
		MangledName name = MangledName.parse(bytes(0x0c, 0x85, 0xc5, 0xff, 0xff, "_p", 0), 0);
		assertEquals(new Reference(0x0c, 0, -0x3a7b), name.parts().getFirst());
		assertEquals(1 - 0x3a7b, name.references().getFirst().targetOffset());
	}

	/** Several references with text between them; positions count from the start of the name. */
	@Test
	public void mixed() {
		byte[] b =
			bytes("xx", 0x02, 0x10, 0, 0, 0, "_p", 0x02, 0x20, 0, 0, 0, "_", 0x01, 0xf0, 0xff,
				0xff, 0xff, "tc", 0);
		MangledName name = MangledName.parse(b, 2);
		assertEquals(List.of(new Reference(0x02, 0, 0x10), new Text("_p"),
			new Reference(0x02, 7, 0x20), new Text("_"), new Reference(0x01, 13, -0x10),
			new Text("tc")), name.parts());
		assertEquals(20, name.length());
		assertEquals(3, name.references().size());
		assertEquals("<A>_p<A>_<A>tc", name.render(r -> "A"));
		assertEquals(14 - 0x10, name.references().get(2).targetOffset());
	}

	@Test
	public void absolutePointer() {
		MangledName name =
			MangledName.parse(bytes(0x18, 0x00, 0x10, 0, 0, 0, 0, 0, 0x01, "Sg", 0), 0);
		Reference ref = name.parts().getFirst() instanceof Reference r ? r : null;
		assertEquals(new Reference(0x18, 0, 0x0100000000001000L), ref);
		assertFalse(ref.isRelative());
		assertEquals(11, name.length());
	}

	@Test
	public void truncated() {
		assertNull(MangledName.parse(bytes("Si"), 0));
		assertNull(MangledName.parse(bytes(0x01, 0x00, 0x00, 0x00), 0));
		assertNull(MangledName.parse(bytes(0x01, 0x00, 0x00, 0x00, 0x00), 0));
		assertNull(MangledName.parse(bytes(0x18, 0, 0, 0, 0, 0, 0, 0), 0));
	}

	@Test
	public void nominalTypeNames() {
		assertEquals("SwiftUI.Color",
			MangledName.nominalTypeName("_$s7SwiftUI5ColorVMn"));
		assertEquals("Foundation.URL", MangledName.nominalTypeName("$s10Foundation3URLVMn"));
		assertEquals("Foundation.URL.ResourceKey",
			MangledName.nominalTypeName("_$s10Foundation3URLV11ResourceKeyVMn"));
		assertEquals("NSString", MangledName.nominalTypeName("_$sSo8NSStringCMn"));
		// Nested in a standard type (swift-package: Dictionary<K, V>.Index)
		assertEquals("Swift.Dictionary.Index", MangledName.nominalTypeName("_$sSD5IndexVMn"));
		assertEquals("Swift.Task.Handle", MangledName.nominalTypeName("$sScT6HandleVMn"));
		assertEquals("Swift.Int8", MangledName.nominalTypeName("_$ss4Int8VMn"));
		assertEquals("Swift.UInt16", MangledName.nominalTypeName("_$ss6UInt16VMn"));
		assertEquals("Swift.Optional", MangledName.nominalTypeName("_$s5Swift8OptionalOMn"));
		assertNull(MangledName.nominalTypeName("_$s7SwiftUI5ColorVMa"));
		assertNull(MangledName.nominalTypeName("_objc_msgSend"));
		assertNull(MangledName.nominalTypeName("_$s7SwiftUI99UIVMn"));
		// Word substitutions (checked with swift demangle)
		assertEquals("Dispatch.DispatchWorkItem",
			MangledName.nominalTypeName("_$s8Dispatch0A8WorkItemCMn"));
		assertEquals("SwiftData.SwiftDataError",
			MangledName.nominalTypeName("_$s9SwiftData0aB5ErrorVMn"));
		assertEquals("AppIntents.AppIntents",
			MangledName.nominalTypeName("_$s10AppIntents0aB0CMn"));
		assertNull(MangledName.nominalTypeName("_$s4Test0B4TypeVMn")); // no word 1
		// Protocol descriptors: no kind letter
		assertEquals("AppIntents.AppIntent",
			MangledName.nominalTypeName("_$s10AppIntents0A6IntentMp"));
		assertEquals('P', MangledName.nominalTypeKind("_$s10AppIntents0A6IntentMp"));
		assertEquals('C', MangledName.nominalTypeKind("_$s8Dispatch0A8WorkItemCMn"));
		assertEquals("Swift.Hashable", MangledName.nominalTypeName("_$sSHMp"));
		assertEquals("Swift.CVarArg", MangledName.nominalTypeName("_$ss7CVarArgMp"));
		assertNull(MangledName.nominalTypeName("_$sSiMp")); // a struct, not a protocol
		assertNull(MangledName.nominalTypeName("_$s7Layouts5ShapePMp"));
	}

	@Test
	public void identifiers() {
		MangledIdentifiers ids = new MangledIdentifiers();
		// Words: "Main", then "my" and "URLItem" (an uppercase run stays in one word)
		assertEquals(new MangledIdentifiers.Parsed("Main", 5), ids.parse("4Main", 0));
		assertEquals("my_URLItem", ids.parse("10my_URLItem", 0).text());
		assertEquals(new MangledIdentifiers.Parsed("myURLItemTest", 8), ids.parse("0bC4Test", 0));
		assertEquals("MainmyTest", ids.parse("0aB4Test", 0).text());
		assertEquals(new MangledIdentifiers.Parsed("Main", 3), ids.parse("0A0V", 0));
		assertNull(ids.parse("0Z0", 0)); // no such word
		assertNull(ids.parse("0aB", 0)); // neither a literal nor 0 after the last word
		assertNull(ids.parse("00", 0)); // punycode
		assertNull(ids.parse("V", 0));
	}
}
