// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidrageneric;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.Test;

/**
 * The analyzers depend on the other classes, never the other way round, and not on each other:
 * code that two analyzers need goes into its own class. Checked on
 * the source files, without comments. Scripts may use the analyzers.
 */
public class AnalyzerDependencyTest {

	private static final Path SOURCES = Path.of("src/main/java/lzghidrageneric");
	private static final Pattern COMMENTS = Pattern.compile("(?s)/\\*.*?\\*/|//[^\n]*");

	@Test
	public void noClassUsesAnotherAnalyzer() throws IOException {
		assertTrue("run from LZGhidraGeneric/: " + SOURCES.toAbsolutePath(),
			Files.isDirectory(SOURCES));
		List<Path> files;
		try (Stream<Path> s = Files.list(SOURCES)) {
			files = s.filter(p -> p.toString().endsWith(".java")).sorted().toList();
		}
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
			String code = COMMENTS.matcher(Files.readString(p)).replaceAll("");
			for (String analyzer : analyzers) {
				if (!analyzer.equals(className(p)) &&
					Pattern.compile("\\b" + analyzer + "\\b").matcher(code).find()) {
					uses.add(className(p) + " uses " + analyzer);
				}
			}
		}
		assertEquals(List.of(), uses);
	}

	private static String className(Path p) {
		String f = p.getFileName().toString();
		return f.substring(0, f.length() - ".java".length());
	}
}
