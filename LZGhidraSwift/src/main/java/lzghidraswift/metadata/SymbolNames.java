// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

/**
 * The names of a function's symbols and of externals, as the analyzers match them, and the
 * function at a call target whose names they match.
 */
public final class SymbolNames {

	private SymbolNames() {
	}

	/**
	 * The names of the symbols at the function's entry, in the symbol table's order: the Swift
	 * demangler keeps the mangled name as a second label next to the demangled one, and the
	 * linker folds identical functions, so one address can carry several.
	 */
	public static List<String> atEntry(Function f) {
		List<String> names = new ArrayList<>();
		for (Symbol s : f.getProgram().getSymbolTable().getSymbols(f.getEntryPoint())) {
			names.add(s.getName());
		}
		return names;
	}

	/**
	 * The external function's label and, if a demangler renamed it, its original imported name;
	 * empty if {@code f} has no external location.
	 */
	public static List<String> ofExternal(Function f) {
		List<String> names = new ArrayList<>();
		ExternalLocation location = f.getExternalLocation();
		if (location != null) {
			names.add(location.getLabel());
			if (location.getOriginalImportedName() != null) {
				names.add(location.getOriginalImportedName());
			}
		}
		return names;
	}

	/**
	 * The symbol without one leading {@code _}, the C symbol prefix of Mach-O
	 * ({@code _swift_retain} → {@code swift_retain}, {@code _$sBi64_WV} → {@code $sBi64_WV}); else
	 * as it is.
	 */
	public static String withoutUnderscore(String symbol) {
		return symbol.startsWith("_") ? symbol.substring(1) : symbol;
	}

	/**
	 * The name without any leading {@code _} ({@code ___chkstk_darwin} → {@code chkstk_darwin}).
	 * Unlike {@link #withoutUnderscore}, which removes only Mach-O's prefix, this also removes the
	 * underscores that belong to the name, so {@code __Block_copy} and {@code _Block_copy} give
	 * the same result.
	 */
	public static String withoutLeadingUnderscores(String name) {
		int start = 0;
		while (start < name.length() && name.charAt(start) == '_') {
			start++;
		}
		return name.substring(start);
	}

	/**
	 * The mangled body of a Swift symbol, without its prefix {@code _$s} (Mach-O) or {@code $s}
	 * ({@code _$s4Main3fooyyF} → {@code 4Main3fooyyF}); null for a name that is not a Swift
	 * symbol. The old mangling {@code $S} (Swift 4.2 and before) is not accepted.
	 */
	public static String swiftBody(String symbol) {
		return symbol.startsWith("_$s") ? symbol.substring(3)
				: symbol.startsWith("$s") ? symbol.substring(2) : null;
	}

	/** Whether the name is a Swift symbol, as {@link #swiftBody} accepts it. */
	public static boolean isSwift(String symbol) {
		return swiftBody(symbol) != null;
	}

	/** The original imported name of the external (before a demangler renamed it), else its label. */
	public static String imported(ExternalLocation location) {
		String original = location.getOriginalImportedName();
		return original != null ? original : location.getLabel();
	}

	/**
	 * The original imported name of the external that {@code address} refers to (a pointer slot
	 * bound to an import), as {@link #imported}; null if no external reference starts there.
	 */
	public static String importedFrom(Program program, Address address) {
		for (Reference ref : program.getReferenceManager().getReferencesFrom(address)) {
			if (ref instanceof ExternalReference ext) {
				return imported(ext.getExternalLocation());
			}
		}
		return null;
	}

	/**
	 * The function at a call target, through thunks: the end of the thunk chain if the function
	 * there is a thunk (a stub), else the function; null if there is none.
	 */
	public static Function callee(Program program, Address target) {
		Function f = program.getFunctionManager().getFunctionAt(target);
		Function thunked = f != null && f.isThunk() ? f.getThunkedFunction(true) : null;
		return thunked != null ? thunked : f;
	}
}
