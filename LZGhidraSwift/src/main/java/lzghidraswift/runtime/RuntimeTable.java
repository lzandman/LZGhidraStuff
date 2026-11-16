// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import lzghidraswift.metadata.SymbolNames;

/**
 * The Swift runtime functions of {@code data/swift-runtime-functions.txt}, which
 * {@code devtools/gen_runtime_functions.py} writes from the Swift source: each function's module,
 * calling convention, return and parameter types (IRGen names such as {@code TypeMetadataPtrTy},
 * or a flag enum, and for untyped pointers the header's pointee) and parameter names, and the flag
 * enums with their values. The generator's docstring describes the format. Parsing is pure and
 * needs no Ghidra program; {@link #load} reads the file from the installed extension.
 */
public final class RuntimeTable {

	/** The data file's name, in the extension's {@code data} directory. */
	public static final String FILE_NAME = "swift-runtime-functions.txt";

	/** The start of the header line, followed by the Swift commit and its date. */
	static final String HEADER = "# swift ";

	/** The attribute of a function that does not return. */
	public static final String NO_RETURN = "NoReturn";

	/** The attribute of a function that returns its first argument (the retains). */
	public static final String FIRST_PARAM_RETURNED = "FirstParamReturned";

	/**
	 * The attribute of a function with a parameter that the header passes in a Swift-only register
	 * ({@code SWIFT_CONTEXT}, {@code SWIFT_ERROR_RESULT}, {@code SWIFT_ASYNC_CONTEXT}: x20, x21,
	 * x22 on arm64), not in an argument register of its convention ({@code swift_willThrow}).
	 */
	public static final String SWIFT_REGISTER_PARAMS = "SwiftRegisterParams";

	/**
	 * The attribute of a function whose parameters are all in Swift-only registers, next to
	 * {@link #SWIFT_REGISTER_PARAMS} ({@code swift_willThrow}).
	 */
	public static final String SWIFT_REGISTERS_ONLY = "SwiftRegistersOnly";

	private static final String ENUM_PREFIX = "enum ";

	private static final Pattern POINTEE = Pattern.compile("\\w+\\*+");

	/**
	 * A parameter: its name in the runtime's header, or {@code null} if the header has none; its
	 * type, an IRGen name or (with {@code isEnum}) the name of a {@link FlagEnum}; and for an
	 * untyped pointer ({@code Int8PtrTy}, {@code PtrTy}) the header's pointee, or {@code null}.
	 * The pointee is a type name with one {@code *} per level ({@code ValueBuffer*},
	 * {@code Metadata**}), as the header names it; {@link RuntimeTypes} decides whether to use it.
	 */
	public record Param(String name, String type, boolean isEnum, String pointee) {

		/** A parameter without a header pointee. */
		public Param(String name, String type, boolean isEnum) {
			this(name, type, isEnum, null);
		}
	}

	/**
	 * A runtime function. {@code convention} is the .def's ({@code C_CC}, {@code SwiftCC},
	 * {@code SwiftAsyncCC}, {@code SwiftDirectRR_CC}); {@code returns} holds one IRGen name, or
	 * several for a function that returns a pair in two registers.
	 */
	public record Entry(String name, String module, String convention, List<String> returns,
			Set<String> attributes, List<Param> params) {}

	/** A flag enum of the runtime: its size in bytes and its values in the header's order. */
	public record FlagEnum(String name, int size, Map<String, Long> values) {}

	/** The table of the installed extension, read by the first {@link #load}. */
	private static RuntimeTable loaded;

	private final String source;
	private final Map<String, Entry> functions;
	private final Map<String, FlagEnum> enums;

	private RuntimeTable(String source, Map<String, Entry> functions, Map<String, FlagEnum> enums) {
		this.source = source;
		this.functions = Collections.unmodifiableMap(functions);
		this.enums = Collections.unmodifiableMap(enums);
	}

	/** The Swift commit and date the table was generated from, as the header line names them. */
	public String source() {
		return source;
	}

	/** The functions by name, sorted. */
	public Map<String, Entry> functions() {
		return functions;
	}

	/** The flag enums by name, sorted. */
	public Map<String, FlagEnum> enums() {
		return enums;
	}

	/** The entry of a runtime function, or {@code null}. */
	public Entry get(String name) {
		return functions.get(name);
	}

	/**
	 * The entry of a function with these symbol names, or {@code null}: of the first name that,
	 * without one leading {@code _} (the C symbol prefix of Mach-O) or else as it is, is in the
	 * table. The table has names that start with {@code _} itself ({@code _Block_copy}).
	 */
	public Entry entry(List<String> names) {
		for (String n : names) {
			Entry e = get(SymbolNames.withoutUnderscore(n));
			if (e == null) {
				e = get(n);
			}
			if (e != null) {
				return e;
			}
		}
		return null;
	}

	/**
	 * The table of the extension's data file ({@link #FILE_NAME} in its {@code data} directory),
	 * read and parsed once per Ghidra session.
	 *
	 * @throws IOException if the file is missing or cannot be read
	 * @throws IllegalArgumentException if it does not parse, as {@link #parse}
	 */
	public static synchronized RuntimeTable load() throws IOException {
		if (loaded == null) {
			ResourceFile file = Application.getModuleDataFile(FILE_NAME);
			try (InputStream in = file.getInputStream()) {
				loaded = parse(
					new String(in.readAllBytes(), StandardCharsets.UTF_8).lines().toList());
			}
		}
		return loaded;
	}

	/**
	 * Parses the lines of the data file.
	 *
	 * @throws IllegalArgumentException with the line number, for a missing header, a malformed
	 *             line, a name given twice or a parameter whose enum is not in the file
	 */
	public static RuntimeTable parse(List<String> lines) {
		if (lines.isEmpty() || !lines.get(0).startsWith(HEADER)) {
			throw new IllegalArgumentException("line 1: no header \"" + HEADER + "...\"");
		}
		String header = lines.get(0).substring(HEADER.length());
		int comma = header.indexOf(',');
		String source = comma < 0 ? header : header.substring(0, comma);
		Map<String, Entry> functions = new TreeMap<>();
		Map<String, FlagEnum> enums = new TreeMap<>();
		for (int i = 1; i < lines.size(); i++) {
			String line = lines.get(i);
			if (line.isEmpty() || line.startsWith("#")) {
				continue;
			}
			try {
				String[] c = line.split("\t", -1);
				String name = c.length > 1 ? c[1] : "";
				boolean added = switch (c[0]) {
					case "enum" -> enums.putIfAbsent(name, flagEnum(c)) == null;
					case "func" -> functions.putIfAbsent(name, entry(c)) == null;
					default -> throw new IllegalArgumentException("unknown kind " + c[0]);
				};
				if (!added) {
					throw new IllegalArgumentException(name + " twice");
				}
			}
			catch (IllegalArgumentException e) {
				throw new IllegalArgumentException("line " + (i + 1) + ": " + e.getMessage(), e);
			}
		}
		for (Entry e : functions.values()) {
			for (Param p : e.params()) {
				if (p.isEnum() && !enums.containsKey(p.type())) {
					throw new IllegalArgumentException(
						e.name() + ": enum " + p.type() + " is not in the table");
				}
			}
		}
		return new RuntimeTable(source, functions, enums);
	}

	private static FlagEnum flagEnum(String[] c) {
		if (c.length < 4) {
			throw new IllegalArgumentException("enum needs a name, a size and values");
		}
		int size = Integer.parseInt(c[2]);
		if (size != 1 && size != 2 && size != 4 && size != 8) {
			throw new IllegalArgumentException("enum size " + size);
		}
		Map<String, Long> values = new LinkedHashMap<>();
		for (String v : Arrays.asList(c).subList(3, c.length)) {
			int eq = v.indexOf('=');
			if (eq <= 0 || !v.startsWith("0x", eq + 1)) {
				throw new IllegalArgumentException("enum value " + v);
			}
			if (values.put(v.substring(0, eq),
				Long.parseUnsignedLong(v.substring(eq + 3), 16)) != null) {
				throw new IllegalArgumentException("enum value " + v + " twice");
			}
		}
		return new FlagEnum(c[1], size, Collections.unmodifiableMap(values));
	}

	private static Entry entry(String[] c) {
		if (c.length < 6 || c[1].isEmpty() || c[4].isEmpty()) {
			throw new IllegalArgumentException("func needs name, module, cc, returns, attributes");
		}
		List<String> returns = List.of(c[4].split(","));
		Set<String> attributes = c[5].equals("-") ? Set.of() : Set.of(c[5].split(","));
		List<Param> params = new ArrayList<>();
		for (String p : Arrays.asList(c).subList(6, c.length)) {
			params.add(param(p));
		}
		return new Entry(c[1], c[2], c[3], returns, attributes, List.copyOf(params));
	}

	private static Param param(String text) {
		int colon = text.indexOf(':');
		String name = colon < 0 ? null : text.substring(0, colon);
		String type = text.substring(colon + 1);
		String pointee = null;
		int eq = type.indexOf('=');
		if (eq >= 0) {
			pointee = type.substring(eq + 1);
			type = type.substring(0, eq);
			if (!POINTEE.matcher(pointee).matches()) {
				throw new IllegalArgumentException("pointee " + text);
			}
		}
		boolean isEnum = type.startsWith(ENUM_PREFIX);
		if (isEnum) {
			type = type.substring(ENUM_PREFIX.length());
		}
		if (type.isEmpty() || (name != null && name.isEmpty()) || (isEnum && pointee != null)) {
			throw new IllegalArgumentException("parameter " + text);
		}
		return new Param(name, type, isEnum, pointee);
	}
}
