// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * {@link SymbolNames} on stand-ins for Ghidra's interfaces (the tests cannot create a program):
 * each answers only the methods named in its map and fails on any other.
 */
public class SymbolNamesTest {

	/** The names in the symbol table's order, the demangled label next to the mangled one. */
	@Test
	public void atEntry() {
		Symbol[] symbols = { symbol("$s4Main3fooyyKF"), symbol("Main.foo()") };
		SymbolTable table = stub(SymbolTable.class, Map.of("getSymbols", symbols));
		Program program = stub(Program.class, Map.of("getSymbolTable", table));
		Function f = stub(Function.class, Map.of("getProgram", program));
		assertEquals(List.of("$s4Main3fooyyKF", "Main.foo()"), SymbolNames.atEntry(f));
	}

	/** The label first, then the original imported name if a demangler renamed the external. */
	@Test
	public void ofExternal() {
		assertEquals(List.of("Main.foo()", "$s4Main3fooyyKF"),
			SymbolNames.ofExternal(external(location("Main.foo()", "$s4Main3fooyyKF"))));
		assertEquals(List.of("_malloc"),
			SymbolNames.ofExternal(external(location("_malloc", null))));
		assertEquals(List.of(), SymbolNames.ofExternal(external(null)));
	}

	/** The original imported name, else the label. */
	@Test
	public void imported() {
		assertEquals("$s4Main3fooyyKF",
			SymbolNames.imported(location("Main.foo()", "$s4Main3fooyyKF")));
		assertEquals("_malloc", SymbolNames.imported(location("_malloc", null)));
	}

	/** One leading underscore goes, a second one stays. */
	@Test
	public void withoutUnderscore() {
		assertEquals("swift_retain", SymbolNames.withoutUnderscore("_swift_retain"));
		assertEquals("_Block_copy", SymbolNames.withoutUnderscore("__Block_copy"));
		assertEquals("swift_retain", SymbolNames.withoutUnderscore("swift_retain"));
	}

	/** Every leading underscore goes, also those that belong to the name. */
	@Test
	public void withoutLeadingUnderscores() {
		assertEquals("", SymbolNames.withoutLeadingUnderscores("_"));
		assertEquals("", SymbolNames.withoutLeadingUnderscores("__"));
		assertEquals("chkstk_darwin", SymbolNames.withoutLeadingUnderscores("___chkstk_darwin"));
		assertEquals("swift_retain", SymbolNames.withoutLeadingUnderscores("swift_retain"));
		assertEquals("", SymbolNames.withoutLeadingUnderscores(""));
	}

	/**
	 * The test in {@code MangledTypeReader.nominal} for a type imported from C or Objective-C:
	 * the body of its descriptor symbol starts with {@code So}, with or without Mach-O's {@code _}.
	 */
	@Test
	public void importedTypeDescriptor() {
		assertTrue(SymbolNames.swiftBody("_$sSo8NSObjectCMn").startsWith("So"));
		assertTrue(SymbolNames.swiftBody("$sSo8NSObjectCMn").startsWith("So"));
		assertFalse(SymbolNames.swiftBody("_$s4Main3FooVMn").startsWith("So"));
	}

	/** The external reference's imported name; null without one, other references ignored. */
	@Test
	public void importedFrom() {
		Reference plain = stub(Reference.class, Map.of());
		ExternalReference ext = stub(ExternalReference.class,
			Map.of("getExternalLocation", location("_swift_retain", null)));
		assertEquals("_swift_retain",
			SymbolNames.importedFrom(references(plain, ext), null));
		assertNull(SymbolNames.importedFrom(references(plain), null));
		assertNull(SymbolNames.importedFrom(references(), null));
	}

	/** The end of the thunk chain for a thunk, else the function; null without a function. */
	@Test
	public void callee() {
		Function target = stub(Function.class, Map.of("isThunk", false));
		Function thunk =
			stub(Function.class, Map.of("isThunk", true, "getThunkedFunction", target));
		assertSame(target, SymbolNames.callee(functionAt(thunk), null));
		assertSame(target, SymbolNames.callee(functionAt(target), null));
		assertNull(SymbolNames.callee(functionAt(null), null));
	}

	/** Both prefixes, the Mach-O one first; not the old mangling {@code $S}, nor a C symbol. */
	@Test
	public void swiftBody() {
		assertEquals("4Main3fooyyF", SymbolNames.swiftBody("_$s4Main3fooyyF"));
		assertEquals("4Main3fooyyF", SymbolNames.swiftBody("$s4Main3fooyyF"));
		assertEquals("", SymbolNames.swiftBody("$s"));
		assertNull(SymbolNames.swiftBody("$S4Main3fooyyF"));
		assertNull(SymbolNames.swiftBody("_$S4Main3fooyyF"));
		assertNull(SymbolNames.swiftBody("__$s4Main3fooyyF"));
		assertNull(SymbolNames.swiftBody("_swift_retain"));
		assertNull(SymbolNames.swiftBody(""));
		assertTrue(SymbolNames.isSwift("_$sBi64_WV"));
		assertFalse(SymbolNames.isSwift("Main.foo()"));
	}

	private static Symbol symbol(String name) {
		return stub(Symbol.class, Map.of("getName", name));
	}

	private static ExternalLocation location(String label, String original) {
		Map<String, Object> answers = new HashMap<>();
		answers.put("getLabel", label);
		answers.put("getOriginalImportedName", original);
		return stub(ExternalLocation.class, answers);
	}

	private static Program references(Reference... from) {
		ReferenceManager manager = stub(ReferenceManager.class, Map.of("getReferencesFrom", from));
		return stub(Program.class, Map.of("getReferenceManager", manager));
	}

	private static Program functionAt(Function f) {
		Map<String, Object> answers = new HashMap<>();
		answers.put("getFunctionAt", f);
		FunctionManager manager = stub(FunctionManager.class, answers);
		return stub(Program.class, Map.of("getFunctionManager", manager));
	}

	private static Function external(ExternalLocation location) {
		Map<String, Object> answers = new HashMap<>();
		answers.put("getExternalLocation", location);
		return stub(Function.class, answers);
	}

	/**
	 * An instance of {@code type} that returns the map's value for a method name (null for
	 * {@code getEntryPoint}, which {@code atEntry} only passes on to the stubbed symbol table).
	 */
	private static <T> T stub(Class<T> type, Map<String, Object> answers) {
		return type.cast(Proxy.newProxyInstance(Thread.currentThread().getContextClassLoader(),
			new Class<?>[] { type },
			(proxy, method, args) -> {
				String name = method.getName();
				if (!answers.containsKey(name) && !name.equals("getEntryPoint")) {
					throw new UnsupportedOperationException(name);
				}
				return answers.get(name);
			}));
	}
}
