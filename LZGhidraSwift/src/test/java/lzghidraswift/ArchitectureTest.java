// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.junit.Test;

/**
 * Checks against structural drift, on the source files without comments (see
 * {@link AnalyzerDependencyTest}). The Swift Error Register work passed lint and tests at every
 * step, yet left the same Program lookups written three or four times and a package that did six
 * things. These tests fail when that comes back.
 */
public class ArchitectureTest {

	/**
	 * A Ghidra call, p-code test or symbol name rule that only one class may make, with that
	 * class. A new duplicate fails with the owner to use instead. Add a row when another
	 * duplicated lookup is found.
	 */
	private static final Map<Pattern, String> OWNERS = Map.ofEntries(
		Map.entry(Pattern.compile("\\.getProcessor\\(\\)"), "CallingConventions"),
		Map.entry(Pattern.compile("\\.getDefaultPointerSize\\(\\)"), "CallingConventions"),
		Map.entry(Pattern.compile("getSymbols\\([^;]*getEntryPoint\\(\\)"), "SymbolNames"),
		Map.entry(Pattern.compile("\\.getOriginalImportedName\\(\\)"), "SymbolNames"),
		Map.entry(Pattern.compile("startsWith\\(\"_\"\\)"), "SymbolNames"),
		Map.entry(Pattern.compile("startsWith\\(\"_?\\$s\"\\)"), "SymbolNames"),
		Map.entry(Pattern.compile("replaceFirst\\(\"\\^_"), "SymbolNames"),
		Map.entry(Pattern.compile("instanceof ExternalReference\\b"), "SymbolNames"),
		Map.entry(Pattern.compile("\\.getThunkedFunction\\("), "SymbolNames"),
		Map.entry(Pattern.compile("HighFunctionDBUtil\\.writeOverride\\("), "CallOverrides"),
		Map.entry(Pattern.compile("HighFunctionDBUtil\\.readOverride\\("), "CallOverrides"),
		Map.entry(Pattern.compile("PcodeOp\\.STORE\\s*&&\\s*\\w+\\s*==\\s*2\\b"), "PcodeOps"),
		Map.entry(Pattern.compile("new DecompInterface\\("), "DecompilerPool"));

	@Test
	public void eachLookupHasOneOwner() throws IOException {
		List<String> found = new ArrayList<>();
		for (Path p : AnalyzerDependencyTest.sourceFiles()) {
			String name = AnalyzerDependencyTest.className(p);
			String code = AnalyzerDependencyTest.code(p);
			OWNERS.forEach((pattern, owner) -> {
				if (!owner.equals(name) && pattern.matcher(code).find()) {
					found.add(name + " has " + pattern + ": use " + owner);
				}
			});
		}
		assertEquals(List.of(), found);
	}

	private static final Path CLAUDE_MD = Path.of("CLAUDE.md");
	private static final Pattern ROW = Pattern.compile("^\\| `([a-z]+)` \\|(.*)\\|$");

	/**
	 * Each class in {@code src/main} is named in its package's row of the table under "Packages"
	 * in CLAUDE.md, a top-level class in the text above the table. A new class needs a few words
	 * there; a row that then needs a second sentence shows that the package does two things.
	 */
	@Test
	public void eachClassIsInThePackageTable() throws IOException {
		Map<String, String> rows = new HashMap<>();
		StringBuilder intro = new StringBuilder();
		boolean inSection = false;
		for (String line : Files.readAllLines(CLAUDE_MD)) {
			if (line.startsWith("## ")) {
				inSection = line.equals("## Packages");
				continue;
			}
			if (!inSection) {
				continue;
			}
			var m = ROW.matcher(line);
			if (m.matches()) {
				rows.put(m.group(1), m.group(2));
			}
			else if (!line.startsWith("|")) {
				intro.append(line).append('\n');
			}
		}
		assertFalse("no package table in " + CLAUDE_MD.toAbsolutePath(), rows.isEmpty());
		List<String> missing = new ArrayList<>();
		for (Path p : AnalyzerDependencyTest.sourceFiles()) {
			String pkg = AnalyzerDependencyTest.packageOf(p);
			String name = AnalyzerDependencyTest.className(p);
			String text = pkg.equals("lzghidraswift") ? intro.toString() : rows.get(pkg);
			if (text == null) {
				missing.add(pkg + " has no row");
			}
			else if (!Pattern.compile("\\b" + name + "\\b").matcher(text).find()) {
				missing.add(name + " is not named in the row of " + pkg);
			}
		}
		assertEquals(List.of(), missing.stream().distinct().toList());
	}
}
