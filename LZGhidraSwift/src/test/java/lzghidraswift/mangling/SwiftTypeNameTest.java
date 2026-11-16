// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.mangling;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.util.Map;

import org.junit.Test;

import lzghidraswift.mangling.SwiftTypeName.Existential;
import lzghidraswift.mangling.SwiftTypeName.Nominal;

public class SwiftTypeNameTest {

	/**
	 * Parses a mangled name given as text with references written as {@code <N>}: a direct
	 * reference (kind 0x01) that resolves to {@code types.get(N)}.
	 */
	private static SwiftTypeName parse(String mangled, Map<Long, Nominal> types) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int i = 0;
		while (i < mangled.length()) {
			char c = mangled.charAt(i);
			if (c == '<') {
				int end = mangled.indexOf('>', i);
				int id = Integer.parseInt(mangled.substring(i + 1, end));
				out.write(1);
				out.write(id);
				out.write(0); // offsets with 0x00 bytes, as in the binaries
				out.write(0);
				out.write(0);
				i = end + 1;
			}
			else {
				out.write(c);
				i++;
			}
		}
		out.write(0);
		MangledName name = MangledName.parse(out.toByteArray(), 0);
		assertNotNull(name);
		return SwiftTypeName.parse(name, ref -> types.get(ref.operand()));
	}

	private static String render(String mangled, Map<Long, Nominal> types) {
		SwiftTypeName t = parse(mangled, types);
		return t == null ? null : t.render();
	}

	private static String render(String mangled) {
		return render(mangled, Map.of());
	}

	private static final Nominal POINT = new Nominal("Layouts.Point", 'V', "point", false);
	private static final Nominal NODE = new Nominal("Layouts.Node", 'C', "node", false);
	private static final Nominal SHAPE = new Nominal("Layouts.Shape", 'P', "shape", false);
	private static final Nominal FEATURE_PROVIDER =
		new Nominal("__C.MLFeatureProvider", 'P', "objc", true);
	private static final Nominal URL = new Nominal("Foundation.URL", 'V', null, false);
	private static final Map<Long, Nominal> TYPES =
		Map.of(1L, POINT, 2L, NODE, 3L, SHAPE, 4L, FEATURE_PROVIDER, 5L, URL);

	@Test
	public void standardTypes() {
		assertEquals("Swift.Int", render("Si"));
		assertEquals("Swift.String", render("SS"));
		assertEquals("Swift.Array<Swift.Double>", render("SaySdG"));
		assertEquals("Swift.Optional<Swift.Array<Swift.Float>>", render("SaySfGSg"));
		assertEquals("Swift.Array<Swift.Array<Swift.Float>>", render("SaySaySfGG"));
		assertEquals("Swift.Dictionary<Swift.String, Swift.Int>", render("SDySSSiG"));
		assertEquals("Swift.Set<Swift.String>", render("ShySSG"));
		assertEquals("Swift.Optional<Swift.Double>", render("SdSg"));
		assertEquals("Swift.Optional<Swift.Int>", render("SqySiG"));
		// Concurrency substitutions (swift-package: Deque<CheckedContinuation<(), Never>>)
		assertEquals("Swift.CheckedContinuation<(), Swift.Never>", render("ScCyyts5NeverOG"));
		assertEquals("@Swift.MainActor () -> ()", render("yyScMYcc"));
		assertNull(render("ScZ"));
	}

	@Test
	public void namedTypes() {
		assertEquals("Swift.Int8", render("s4Int8V"));
		// Objective-C classes: with their module inside other types, without on their own, as
		// String(reflecting:) writes them (measured, Swift 6.4); C structs always with it
		assertEquals("__C.NSString", render("So8NSStringC"));
		assertEquals("NSString", SwiftTypeName.renderField(parse("So8NSStringC", Map.of())));
		assertEquals("Swift.Optional<__C.NSString>",
			SwiftTypeName.renderField(parse("So8NSStringCSg", Map.of())));
		assertEquals("__C.CGSize", SwiftTypeName.renderField(parse("So6CGSizeV", Map.of())));
		assertEquals("NSView", SwiftTypeName.renderField(parse("So6NSViewCXo", Map.of())));
		assertTrue(((Nominal) parse("So8NSStringC", Map.of())).objc());
		assertEquals("Foundation.URL", render("10Foundation3URLV"));
		// Word substitution: Dispatch.DispatchWorkItem
		assertEquals("Swift.Array<Dispatch.DispatchWorkItem>", render("Say8Dispatch0A8WorkItemCG"));
		assertEquals("Layouts.Outer.Inner", render("7Layouts5OuterV5InnerV"));
		assertEquals('C', ((Nominal) parse("So7MLModelC", Map.of())).kind());
		// Objective-C protocols keep their module (classes do not); in a protocol list a
		// protocol has no P (Layouts fixture x86_64, MoreFields.copying)
		assertEquals("__C.NSCopying", render("So9NSCopying_p"));
		assertEquals("Layouts.Named & Layouts.Shape", render("7Layouts5Named_AA5Shapep"));
	}

	@Test
	public void references() {
		assertEquals("Layouts.Point", render("<1>", TYPES));
		assertSame(POINT, parse("<1>", TYPES));
		assertEquals("Swift.Optional<Layouts.Node>", render("<2>Sg", TYPES));
		assertEquals("SwiftUI.Binding<Swift.Float>",
			render("<6>ySfG", Map.of(6L, new Nominal("SwiftUI.Binding", 'V', null, false))));
		assertNull(render("<9>", TYPES)); // unresolved
	}

	@Test
	public void tuples() {
		assertEquals("(Swift.Int, Swift.Float)", render("Si_Sft"));
		assertEquals("()", render("yt"));
		assertEquals("(Swift.Int, Swift.Float, Swift.Bool)", render("Si_SfSbt"));
		// A repeat count
		assertEquals("(Swift.Double, Swift.Double, Swift.Double)", render("Sd_S2dt"));
	}

	@Test
	public void functions() {
		assertEquals("() -> ()", render("yyc"));
		assertEquals("(Swift.Int) throws -> Swift.Double", render("SdSiKc"));
		assertEquals("Swift.Optional<() -> ()>", render("yycSg"));
		assertEquals("(Foundation.URL, Layouts.Point) -> Layouts.Shape",
			render("<3>_p<5>_<1>tc", TYPES));
		assertEquals("() throws -> Layouts.Shape", render("<3>_pyKc", TYPES));
		assertEquals("@convention(block) (Swift.Int) -> ()", render("ySiXB"));
		assertEquals("(Swift.Int) async throws -> ()", render("ySiYaKc"));
		assertEquals("(inout Swift.Int) -> ()", render("ySizc"));
		// Attributes, in the order of Swift's NodePrinter (a test library not in the repository, swift-package)
		assertEquals("@Sendable (Swift.Int) -> ()", render("ySiYbc"));
		assertEquals("Swift.Optional<@Swift.MainActor @Sendable (Swift.Int) -> Swift.Int>",
			render("S2iYbScMYccSg"));
		assertEquals("@isolated(any) () -> ()", render("yyYAc"));
		assertEquals("nonisolated(nonsending) @Sendable () async -> ()", render("yyYaYbYCc"));
		assertEquals("() throws(Layouts.Point) -> ()", render("yy<1>YKc", TYPES));
		assertEquals("@Sendable () async throws -> ()", render("yyYaYbKc"));
		assertEquals("() -> sending Layouts.Node", render("<2>yYTc", TYPES));
	}

	@Test
	public void nestedGenericArguments() {
		// One argument list per nesting level, outermost first (swift-package)
		Map<Long, Nominal> types =
			Map.of(7L, new Nominal("Swift.Dictionary.Index", 'V', null, false),
				8L, new Nominal("_CryptoExtras.ARC.Credential", 'V', "credential", false),
				9L, new Nominal("Basics.InMemoryFileSystem.WeakReference", 'V', "weak", false));
		assertEquals("Swift.Dictionary<Swift.Int, Swift.String>.Index",
			render("<7>ySiSS_G", types));
		assertEquals("_CryptoExtras.ARC.Credential<Swift.Int>", render("<8>y_SiG", types));
		assertEquals(
			"Swift.Dictionary<Swift.Int, Basics.InMemoryFileSystem.WeakReference<__C.OS_dispatch_queue>>",
			render("SDySi<9>y_So17OS_dispatch_queueCGG", types));
		assertNull(render("<8>y_Si_SiG", types)); // three lists for two levels
		// A constrained extension's type: the extended type is already bound (swift-package)
		Map<Long, Nominal> ext = Map.of(11L,
			new Nominal("(extension in M):Swift.Array<M.T>.Package", 'V', "package", false));
		assertEquals("Swift.Array<(extension in M):Swift.Array<M.T>.Package>",
			render("Say<11>y<12>_GG", Map.of(11L, ext.get(11L), 12L,
				new Nominal("M.T", 'V', "t", false))));
	}

	@Test
	public void metatypesAndBuiltins() {
		assertEquals("Swift.Int.Type", render("Sim"));
		assertEquals("Layouts.Node.Type", render("<2>m", TYPES));
		assertEquals("__C.NSObject.Type", render("So8NSObjectCm"));
		assertEquals("Builtin.DefaultActorStorage", render("BD"));
		assertEquals("Builtin.Int64", render("Bi64_"));
		assertNull(render("Bi_"));
		// Integer generic arguments: $2_ is 3 (a test library not in the repository, InlineArray<3, Int16>)
		Map<Long, Nominal> inline = Map.of(10L, new Nominal("Swift.InlineArray", 'V', null, false));
		assertEquals("Swift.InlineArray<3, Swift.Int16>", render("<10>y$2_s5Int16VG", inline));
		assertEquals("Swift.InlineArray<0, Swift.Int>", render("<10>y$_SiG", inline));
	}

	@Test
	public void existentials() {
		assertEquals("Layouts.Shape", render("<3>_p", TYPES));
		assertEquals("__C.MLFeatureProvider", render("<4>_p", TYPES));
		assertEquals("Layouts.Shape & __C.MLFeatureProvider", render("<3>_<4>p", TYPES));
		assertEquals("Any", render("yp"));
		assertEquals("Swift.AnyObject", render("yXl"));
		// weak and unowned: rendered as the referenced type (seen in real binaries)
		assertEquals("Swift.Optional<__C.NSScrollView>", render("So12NSScrollViewCSgXw"));
		assertTrue(parse("<2>Xo", TYPES) instanceof SwiftTypeName.Ownership o &&
			o.ownership().equals("unowned") && o.type().equals(NODE));
		assertEquals("Swift.Optional<Layouts.Shape>", render("<3>_pSgXw", TYPES));
		Existential e = (Existential) parse("<4>_p", TYPES);
		assertEquals(1, e.protocols().size());
		assertFalse(e.anyObject());
		assertNull(render("<1>_p", TYPES)); // a struct is not a protocol
	}

	@Test
	public void existentialMetatypes() {
		// swift-format: ArgumentParser.CommandConfiguration.defaultSubcommand,
		// <ArgumentParser.ParsableCommand>_pXpSg; Swift renders compositions without parentheses
		assertEquals("Swift.Optional<Layouts.Shape.Type>", render("<3>_pXpSg", TYPES));
		assertEquals("Swift.Array<Layouts.Shape.Type>", render("Say<3>_pXpG", TYPES));
		assertEquals("Layouts.Shape & __C.MLFeatureProvider.Type", render("<3>_<4>pXp", TYPES));
		assertEquals("Any.Type", render("ypXp"));
		assertEquals("Swift.Error.Type", render("s5Error_pXp"));
		assertNull(render("SiXp")); // only an existential has an existential metatype
	}

	@Test
	public void substitutions() {
		// Layouts fixture, MoreFields.cFunction: a reference to Int32, then AA repeats it
		assertEquals("@convention(c) (Foundation.URL) -> Foundation.URL",
			render("<5>AAXC", TYPES));
		// Identifiers are substitutions too: Foundation 0, URL 1, Foundation.URL 2
		assertEquals("(Foundation.URL) -> Foundation.URL", render("10Foundation3URLVACc"));
		// Bound generics and Sg: Swift.Array<Swift.Int> is 0, its Optional 1
		assertEquals("(Swift.Array<Swift.Int>) -> Swift.Optional<Swift.Array<Swift.Int>>",
			render("SaySiGSgAAc"));
		// A lowercase letter pushes and continues, a count repeats
		assertEquals("(Layouts.Point, Layouts.Point, Layouts.Point, Layouts.Point)",
			render("<1>_A2aAt", TYPES));
		assertNull(render("<1>A0_", TYPES)); // index 27: out of range
		assertNull(render("SiAA")); // standard types are not substitutions
		assertNull(render("<1>Aa", TYPES)); // no final uppercase letter
	}

	@Test
	public void unsupported() {
		assertNull(render("x")); // generic parameter
		assertNull(render("SiXp")); // metatype
		assertNull(render("10Foundation3URLV0Z0V")); // no word 25
		assertNull(render("SiSd")); // two types
		assertNull(render("Sg")); // nothing to wrap
		assertNull(render("S"));
		assertNull(render("9Foundation"));
	}
}
