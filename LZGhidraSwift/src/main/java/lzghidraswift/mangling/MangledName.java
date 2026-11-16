// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.mangling;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import lzghidraswift.metadata.SymbolNames;

/**
 * A mangled type name as Swift reflection metadata stores it ({@code __swift5_fieldmd},
 * {@code __swift5_typeref}): mangling text with embedded symbolic references, ended by a NUL.
 * <p>
 * A control byte 0x01–0x17 is followed by a signed 32-bit offset, relative to the address of the
 * offset itself; 0x18–0x1f by a 64-bit pointer (swift/docs/ABI/Mangling.rst, "Symbolic
 * references"). Either can contain 0x00 bytes, so the name must be read byte by byte and not as a
 * C string. Plain Java over a byte array; {@link MangledTypeReader} reads it from a program.
 */
public record MangledName(List<Part> parts, int length) {

	/** Direct reference to a context descriptor. */
	public static final int CONTEXT_DIRECT = 0x01;
	/** Indirect reference to a context descriptor, through a pointer (a GOT entry for imports). */
	public static final int CONTEXT_INDIRECT = 0x02;
	/**
	 * Reference to an Objective-C protocol: the target holds a relative pointer to an
	 * {@code __objc_protorefs} entry, which points to the {@code protocol_t} (a field of type
	 * {@code MLFeatureProvider}).
	 */
	public static final int OBJC_PROTOCOL = 0x0c;
	/**
	 * A function that returns the metadata (SymbolicReferenceKind::AccessorFunctionReference):
	 * used when the deployment target's runtime cannot demangle the type, such as
	 * {@code @isolated(any)} or typed throws below macOS 15 (Layouts fixture, x86_64).
	 */
	public static final int ACCESSOR_FUNCTION = 0x09;

	/** A piece of the name: text or a symbolic reference. */
	public sealed interface Part permits Text, Reference {
	}

	/** Mangling text between references, decoded as Latin-1 (it is ASCII in practice). */
	public record Text(String text) implements Part {}

	/**
	 * A symbolic reference: the control byte {@code kind} at index {@code position} of the name,
	 * and its operand, the signed 32-bit offset (kinds 0x01–0x17) or the 64-bit pointer (0x18–0x1f).
	 */
	public record Reference(int kind, int position, long operand) implements Part {

		public boolean isRelative() {
			return kind <= 0x17;
		}

		/** For a relative reference: the target's offset from the start of the name. */
		public long targetOffset() {
			return position + 1 + operand;
		}
	}

	/**
	 * Parses the name that starts at {@code bytes[start]}. Returns null if the bytes end before the
	 * terminating NUL or inside an operand.
	 */
	public static MangledName parse(byte[] bytes, int start) {
		List<Part> parts = new ArrayList<>();
		int p = start;
		int text = start;
		while (p < bytes.length) {
			int c = bytes[p] & 0xff;
			if (c == 0) {
				addText(parts, bytes, text, p);
				return new MangledName(List.copyOf(parts), p - start);
			}
			if (c > 0x1f) {
				p++;
				continue;
			}
			int size = c <= 0x17 ? 4 : 8;
			if (p + 1 + size > bytes.length) {
				return null;
			}
			addText(parts, bytes, text, p);
			long operand =
				size == 4 ? littleEndianInt(bytes, p + 1) : littleEndianLong(bytes, p + 1);
			parts.add(new Reference(c, p - start, operand));
			p += 1 + size;
			text = p;
		}
		return null;
	}

	/** The symbolic references, in the order of the name. */
	public List<Reference> references() {
		List<Reference> refs = new ArrayList<>();
		for (Part part : parts) {
			if (part instanceof Reference ref) {
				refs.add(ref);
			}
		}
		return refs;
	}

	/** The single reference, if the name is nothing else (a type of this or another module). */
	public Reference soleReference() {
		return parts.size() == 1 && parts.getFirst() instanceof Reference ref ? ref : null;
	}

	/** The text with each reference replaced by {@code <name>}, as fieldmd.py prints it. */
	public String render(Function<Reference, String> names) {
		StringBuilder sb = new StringBuilder();
		for (Part part : parts) {
			switch (part) {
				case Text t -> sb.append(t.text());
				case Reference r -> sb.append('<').append(names.apply(r)).append('>');
			}
		}
		return sb.toString();
	}

	private static void addText(List<Part> parts, byte[] bytes, int from, int to) {
		if (to > from) {
			parts.add(new Text(new String(bytes, from, to - from, StandardCharsets.ISO_8859_1)));
		}
	}

	private static int littleEndianInt(byte[] b, int at) {
		return (b[at] & 0xff) | (b[at + 1] & 0xff) << 8 | (b[at + 2] & 0xff) << 16 |
			(b[at + 3] & 0xff) << 24;
	}

	private static long littleEndianLong(byte[] b, int at) {
		return (littleEndianInt(b, at) & 0xffffffffL) | (long) littleEndianInt(b, at + 4) << 32;
	}

	/**
	 * The qualified name in a nominal type or protocol descriptor symbol, such as
	 * {@code _$s7SwiftUI5ColorVMn} → {@code SwiftUI.Color},
	 * {@code _$s8Dispatch0A8WorkItemCMn} → {@code Dispatch.DispatchWorkItem} (word substitution),
	 * {@code _$s10AppIntents0A6IntentMp} → {@code AppIntents.AppIntent},
	 * {@code _$sSHMp} → {@code Swift.Hashable}: the symbol that an indirect reference to an
	 * imported type is bound to. Handles module-qualified and nested identifiers; returns null for
	 * anything else.
	 */
	public static String nominalTypeName(String symbol) {
		String s = SymbolNames.swiftBody(symbol);
		if (s == null || (!s.endsWith("Mn") && !s.endsWith("Mp"))) {
			return null;
		}
		boolean protocol = s.endsWith("Mp");
		s = s.substring(0, s.length() - 2);
		if (protocol && s.length() == 2 && s.charAt(0) == 'S') {
			String entry = SwiftTypeName.STANDARD_TYPES.get(s.charAt(1));
			return entry != null && entry.charAt(0) == 'P' ? "Swift." + entry.substring(1) : null;
		}
		StringBuilder name = new StringBuilder();
		int p = appendIdentifiers(s, contextPrefix(s, name), name);
		if (p < 0 || name.isEmpty()) {
			return null;
		}
		// What remains is the kind of the type itself: V struct, C class, O enum; a protocol
		// descriptor has none.
		boolean kind = protocol ? p == s.length()
				: p == s.length() - 1 && "VCO".indexOf(s.charAt(p)) >= 0;
		return kind ? name.toString() : null;
	}

	/**
	 * Appends the module of a prefix ({@code So} imported, {@code s} the standard library, or a
	 * standard type the type is nested in) to {@code name}. Returns the position after it.
	 */
	private static int contextPrefix(String s, StringBuilder name) {
		if (s.startsWith("So")) { // imported from C or Objective-C (module __C)
			return 2;
		}
		if (s.startsWith("s")) { // the standard library
			name.append("Swift");
			return 1;
		}
		String standard = SwiftTypeName.standardEntry(s, 0);
		if (standard != null) {
			// Nested in a standard type: $sSD5IndexVMn is Swift.Dictionary.Index
			name.append("Swift.").append(standard.substring(1));
			return s.charAt(1) == 'c' ? 3 : 2;
		}
		return 0;
	}

	/**
	 * Appends the identifiers from {@code s[p]}, separated by dots, skipping the kinds of outer
	 * types. Returns the position after them, or -1 if one does not parse.
	 */
	private static int appendIdentifiers(String s, int p, StringBuilder name) {
		MangledIdentifiers identifiers = new MangledIdentifiers();
		while (p < s.length() && Character.isDigit(s.charAt(p))) {
			MangledIdentifiers.Parsed identifier = identifiers.parse(s, p);
			if (identifier == null) {
				return -1;
			}
			if (!name.isEmpty()) {
				name.append('.');
			}
			name.append(identifier.text());
			p = identifier.end();
			if (p + 1 < s.length() && "VCOP".indexOf(s.charAt(p)) >= 0 &&
				Character.isDigit(s.charAt(p + 1))) {
				p++; // kind of an outer type; the next identifier is nested in it
			}
		}
		return p;
	}

	/**
	 * The kind of the type in a descriptor symbol that {@link #nominalTypeName} accepts: V, C, O
	 * or P.
	 */
	public static char nominalTypeKind(String symbol) {
		return symbol.endsWith("Mp") ? 'P' : symbol.charAt(symbol.length() - 3);
	}
}
