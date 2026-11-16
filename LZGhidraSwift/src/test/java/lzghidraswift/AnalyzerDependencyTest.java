// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.Test;

/**
 * The analyzers depend on the other classes, never the other way round, and not on each other:
 * code that two analyzers need goes into its own class (as {@code SwiftTypeCatalog}). Checked on
 * the source files, without comments. Scripts may use the analyzers. The packages also depend
 * only in one direction, as {@code ALLOWED} lists.
 */
public class AnalyzerDependencyTest {

	private static final Path SOURCES = Path.of("src/main/java/lzghidraswift");
	private static final Pattern COMMENTS = Pattern.compile("(?s)/\\*.*?\\*/|//[^\n]*");

	/** The Java files under {@link #SOURCES}, sorted. Also used by {@code ArchitectureTest}. */
	static List<Path> sourceFiles() throws IOException {
		assertTrue("run from LZGhidraSwift/: " + SOURCES.toAbsolutePath(),
			Files.isDirectory(SOURCES));
		try (Stream<Path> s = Files.walk(SOURCES)) {
			return s.filter(p -> p.toString().endsWith(".java")).sorted().toList();
		}
	}

	/** The code of a source file without its comments. */
	static String code(Path p) throws IOException {
		return COMMENTS.matcher(Files.readString(p)).replaceAll("");
	}

	/** The package of a source file: its directory's name, "lzghidraswift" for the top level. */
	static String packageOf(Path p) {
		return p.getParent().getFileName().toString();
	}

	@Test
	public void noClassUsesAnotherAnalyzer() throws IOException {
		List<Path> files = sourceFiles();
		List<String> analyzers = new ArrayList<>();
		for (Path p : files) {
			String name = className(p);
			if (name.endsWith("Analyzer")) {
				analyzers.add(name);
			}
		}
		assertFalse(analyzers.isEmpty());
		List<String> uses = new ArrayList<>();
		for (Path p : files) {
			String code = code(p);
			for (String analyzer : analyzers) {
				if (!analyzer.equals(className(p)) &&
					Pattern.compile("\\b" + analyzer + "\\b").matcher(code).find()) {
					uses.add(className(p) + " uses " + analyzer);
				}
			}
		}
		assertEquals(List.of(), uses);
	}

	/** The packages that each package may import; "lzghidraswift" is the top-level package. A new dependency is a decision: edit this map. */
	private static final Map<String, Set<String>> ALLOWED = Map.of(
		"lzghidraswift",
		Set.of("abi", "flow", "mangling", "metadata", "runtime", "strings", "throwing", "types"),
		"types", Set.of("mangling", "metadata"),
		"strings", Set.of("abi", "flow"),
		"mangling", Set.of("metadata"),
		"throwing", Set.of("abi", "flow", "mangling", "metadata"),
		"flow", Set.of("abi"),
		"metadata", Set.of("abi"),
		"runtime", Set.of("abi", "metadata"),
		"abi", Set.of());

	/** An import (also a wildcard one) or a full class name in the code, without comments. */
	private static final Pattern REFERENCE =
		Pattern.compile("\\blzghidraswift\\.(?:([a-z]+)\\.)?(?:[A-Z]|\\*)");

	@Test
	public void packagesDependOnlyDownwards() throws IOException {
		List<String> found = new ArrayList<>();
		for (Path p : sourceFiles()) {
			String pkg = packageOf(p);
			assertTrue(p + " is in an unlisted package", ALLOWED.containsKey(pkg));
			var m = REFERENCE.matcher(code(p));
			while (m.find()) {
				String dep = m.group(1) == null ? "lzghidraswift" : m.group(1);
				if (!dep.equals(pkg) && !ALLOWED.get(pkg).contains(dep)) {
					found.add(className(p) + " (" + pkg + ") uses " + dep);
				}
			}
		}
		assertEquals(List.of(), found);
	}

	static String className(Path p) {
		String f = p.getFileName().toString();
		return f.substring(0, f.length() - ".java".length());
	}
}
