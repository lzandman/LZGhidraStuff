// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.data.*;

/**
 * Word 0 of the Swift demangler's {@code String} and {@code Character} as an integer. Ghidra's
 * demangler defines both in {@code /Demangler/Swift} as {@code { char *str; void *bridgeObject; }},
 * and the decompiler's variables of these types use them. Word 0 is {@code _countAndFlagsBits}
 * in Swift ({@code StringObject.swift}; a {@code Character} holds a {@code String}), never a
 * pointer: the first bytes of a small string, or the count and flags of a large one. With
 * {@code char *} the decompiler shows every small string whose word 0 is an address in the
 * program as a pointer ({@code ActionConstantPtr} does not check for an equate, and a pointer
 * type skips its plausibility checks), and the equate is lost.
 */
public final class DemanglerStringType {

	static final CategoryPath CATEGORY = new CategoryPath("/Demangler/Swift");
	static final List<String> NAMES = List.of("String", "Character");

	private DemanglerStringType() {
	}

	/**
	 * Replaces the type of field 0 of the program's {@code /Demangler/Swift/String} and
	 * {@code Character} by {@code ulonglong}, keeping its name and comment, where it is a
	 * pointer. This changes every use of the types in the program. Returns the paths of the
	 * types changed.
	 */
	public static List<String> retype(DataTypeManager dtm) {
		List<String> changed = new ArrayList<>();
		for (String name : NAMES) {
			if (dtm.getDataType(CATEGORY, name) instanceof Structure s && retype(s)) {
				changed.add(s.getPathName());
			}
		}
		return changed;
	}

	/** {@link #retype(DataTypeManager)} on one structure. */
	static boolean retype(Structure s) {
		if (s.getNumComponents() != 2 || s.getLength() != 16) {
			return false;
		}
		DataTypeComponent c = s.getComponent(0);
		if (c.getLength() != 8 || !(c.getDataType() instanceof Pointer)) {
			return false;
		}
		s.replace(0, UnsignedLongLongDataType.dataType, 8, c.getFieldName(), c.getComment());
		return true;
	}
}
