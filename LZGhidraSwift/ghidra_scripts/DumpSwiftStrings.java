// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Writes the Swift string markup of the Swift String Literals analyzer to a text file, for
// fixtures/check_report.py and for comparing two runs. Arguments: the output file, and optionally
// a directory for the decompiled C of each function with a marked string (<entry>.c).
//
// Lines, tab-separated, in address order within each section:
//   MARK     entry  names  address  kind  confidence  literal   one per string in a bookmark
//   COMMENT  address  EOL|PRE  text                             comments at marked addresses and
//                                                               wherever the analyzer has a line
//   EQUATE   address  op=N hash=H  name  value                 the analyzer's equates
//   MISMATCH address  label                                     bookmark string without comment line
//   BLOCK    address  literal  type  from,from,...             each string in the string block
//                                                               (only if the program has one): its
//                                                               data type (- if undefined) and the
//                                                               addresses that reference it
//   BLOCKREF-MISSING  address  literal                          small string in a bookmark without a
//                                                               reference to its block string
//   BLOCKREF-EXTRA    from  to  literal                         reference into the block from an
//                                                               address with no such bookmark string
//   DECOMP   entry  address  label  equate|comment|none         how the decompiled C of the
//                                                               function shows each marked string:
//                                                               an equate name of the string, else
//                                                               its comment line, else neither
//@category Swift

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateReference;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.Reference;
import lzghidraswift.SwiftStringLiteralsAnalyzer;
import lzghidraswift.strings.StringBlock;
import lzghidraswift.strings.SwiftStringCodec;

public class DumpSwiftStrings extends GhidraScript {

	private static final String CATEGORY_SMALL = "Swift string (small)";
	private static final String CATEGORY_LARGE = "Swift string (large)";

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1 || args.length > 2) {
			throw new IllegalArgumentException(
				"usage: DumpSwiftStrings.java <output file> [<directory for C>]");
		}
		File cDir = args.length == 2 ? new File(args[1]) : null;
		Listing listing = currentProgram.getListing();
		int marks = 0;
		int mismatches = 0;
		int comments = 0;
		int equates = 0;
		List<Address> marked = new ArrayList<>();
		// "address\tliteral" of each small string in a bookmark, for the BLOCKREF lines.
		Set<String> smallMarks = new LinkedHashSet<>();
		int[] block = null;
		// Function entry -> (address, label) of its marked strings, for the DECOMP lines.
		Map<Function, List<String[]>> byFunction =
			new TreeMap<>(Comparator.comparing(Function::getEntryPoint));
		int[] decomp = new int[3];
		try (PrintWriter out = new PrintWriter(args[0], StandardCharsets.UTF_8)) {
			// The iterator gives creation order: a one-shot run on one function puts its bookmarks
			// last. Sorted (stable) by address.
			List<Bookmark> bookmarks = new ArrayList<>();
			currentProgram.getBookmarkManager()
					.getBookmarksIterator(BookmarkType.ANALYSIS)
					.forEachRemaining(bookmarks::add);
			bookmarks.sort(Comparator.comparing(Bookmark::getAddress));
			for (Bookmark b : bookmarks) {
				boolean large = b.getCategory().equals(CATEGORY_LARGE);
				if (!large && !b.getCategory().equals(CATEGORY_SMALL)) {
					continue;
				}
				Address a = b.getAddress();
				marked.add(a);
				Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
				String entry = f == null ? "-" : f.getEntryPoint().toString();
				String names =
					f == null ? "-" : SwiftStringLiteralsAnalyzer.reportName(f);
				String eol = listing.getComment(CommentType.EOL, a);
				String pre = listing.getComment(CommentType.PRE, a);
				for (String label : splitLabels(b.getComment())) {
					String literal = label;
					String kind = large ? "large" : "small";
					String confidence = "certain";
					if (literal.endsWith("?")) {
						confidence = "probable";
						literal = literal.substring(0, literal.length() - 1);
					}
					out.println(String.join("\t", "MARK", entry, names, a.toString(), kind,
						confidence, literal));
					marks++;
					if (!large) {
						smallMarks.add(a + "\t" + literal);
					}
					if (f != null) {
						byFunction.computeIfAbsent(f, k -> new ArrayList<>())
								.add(new String[] { a.toString(), label, literal });
					}
					String line = "Swift " + label;
					if (!hasLine(eol, line) && !hasLine(pre, line)) {
						out.println(String.join("\t", "MISMATCH", a.toString(), label));
						mismatches++;
					}
				}
			}
			// Both comment types at every bookmarked address (so user lines there show too) and at
			// every address with a line of the analyzer (so stale lines show).
			Set<Address> addrs = new TreeSet<>(marked);
			for (CommentType type : new CommentType[] { CommentType.EOL, CommentType.PRE }) {
				AddressIterator it =
					listing.getCommentAddressIterator(type, currentProgram.getMemory(), true);
				while (it.hasNext()) {
					Address a = it.next();
					for (String l : listing.getComment(type, a).split("\n")) {
						if (l.startsWith("Swift \"")) {
							addrs.add(a);
						}
					}
				}
			}
			for (Address a : addrs) {
				for (CommentType type : new CommentType[] { CommentType.EOL, CommentType.PRE }) {
					String c = listing.getComment(type, a);
					if (c != null) {
						out.println(String.join("\t", "COMMENT", a.toString(), type.name(),
							c.replace("\\", "\\\\").replace("\n", "\\n")));
						comments++;
					}
				}
			}
			EquateTable table = currentProgram.getEquateTable();
			AddressIterator it = table.getEquateAddresses();
			while (it.hasNext()) {
				Address a = it.next();
				for (Equate e : table.getEquates(a)) {
					if (!e.getName().startsWith("S\"")) {
						continue;
					}
					for (EquateReference r : e.getReferences(a)) {
						String where = "op=%d hash=%x".formatted(r.getOpIndex(),
							r.getDynamicHashValue());
						out.println(String.join("\t", "EQUATE", a.toString(), where, e.getName(),
							"0x" + Long.toHexString(e.getValue())));
						equates++;
					}
				}
			}
			if (StringBlock.space(currentProgram) != null) {
				block = dumpBlock(out, smallMarks);
			}
			decompile(out, byFunction, cDir, decomp);
		}
		println(("DumpSwiftStrings: %d strings in bookmarks, %d comments, %d equate references, " +
			"%d mismatches; in the decompiler %d by equate, %d by comment, %d not shown")
					.formatted(marks, comments, equates, mismatches, decomp[0], decomp[1],
						decomp[2]));
		if (block != null) {
			println(("DumpSwiftStrings: string block: %d memory blocks, %d strings (%d defined), " +
				"%d references, %d missing, %d extra").formatted(block[5], block[0], block[1],
					block[2], block[3], block[4]));
		}
	}

	/**
	 * Writes the BLOCK and BLOCKREF lines. Returns the counts: strings, strings defined as data,
	 * references, missing references, extra references, memory blocks in the space.
	 */
	private int[] dumpBlock(PrintWriter out, Set<String> smallMarks) {
		int[] counts = new int[6];
		AddressSpace space = StringBlock.space(currentProgram);
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			counts[5] += b.getStart().getAddressSpace().equals(space) ? 1 : 0;
		}
		Listing listing = currentProgram.getListing();
		Set<String> referenced = new HashSet<>();
		List<String> extra = new ArrayList<>();
		Map<Address, String> texts = new TreeMap<>();
		StringBlock.read(currentProgram).forEach((t, a) -> texts.put(a, t));
		for (Address to : texts.keySet()) {
			String literal = SwiftStringCodec.quote(texts.get(to));
			Data d = listing.getDefinedDataAt(to);
			String type = d == null ? "-" : d.getDataType().getName();
			List<Address> froms = new ArrayList<>();
			for (Reference r : currentProgram.getReferenceManager().getReferencesTo(to)) {
				froms.add(r.getFromAddress());
			}
			Collections.sort(froms);
			List<String> fromText = new ArrayList<>();
			for (Address from : froms) {
				fromText.add(from.toString());
				String key = from + "\t" + literal;
				referenced.add(key);
				if (!smallMarks.contains(key)) {
					extra.add(String.join("\t", "BLOCKREF-EXTRA", from.toString(), to.toString(),
						literal));
				}
			}
			out.println(String.join("\t", "BLOCK", to.toString(), literal, type,
				froms.isEmpty() ? "-" : String.join(",", fromText)));
			counts[0]++;
			counts[1] += d == null ? 0 : 1;
			counts[2] += froms.size();
		}
		for (String key : smallMarks) {
			String literal = key.substring(key.indexOf('\t') + 1);
			// The block leaves out empty strings and strings with a NUL.
			if (!referenced.contains(key) && !literal.equals("\"\"") &&
				!literal.contains("\\x00")) {
				out.println("BLOCKREF-MISSING\t" + key);
				counts[3]++;
			}
		}
		for (String line : extra) {
			out.println(line);
			counts[4]++;
		}
		return counts;
	}

	/**
	 * Decompiles each function with marked strings, with the decompiler's default options as the
	 * GUI has them, and writes one DECOMP line per string.
	 */
	private void decompile(PrintWriter out, Map<Function, List<String[]>> byFunction, File cDir,
			int[] counts) throws Exception {
		DecompInterface d = new DecompInterface();
		try {
			DecompileOptions options = new DecompileOptions();
			options.grabFromProgram(currentProgram);
			d.setOptions(options);
			d.openProgram(currentProgram);
			for (Map.Entry<Function, List<String[]>> e : byFunction.entrySet()) {
				Function f = e.getKey();
				DecompileResults res = d.decompileFunction(f, 60, monitor);
				String c = res.getDecompiledFunction() == null ? ""
						: res.getDecompiledFunction().getC();
				if (cDir != null) {
					Files.writeString(new File(cDir, f.getEntryPoint() + ".c").toPath(), c);
				}
				// The decompiler wraps long comments; join the lines before searching.
				c = c.replaceAll("\\s*\\n\\s*", " ");
				for (String[] m : e.getValue()) {
					String literal = m[2];
					String how;
					if (c.contains("S" + literal + ".hi") || c.contains("S" + literal + " ") ||
						c.contains("S" + literal + ";") || c.contains("S" + literal + ")") ||
						c.contains("S" + literal + ",")) {
						how = "equate";
						counts[0]++;
					}
					else if (c.contains("Swift " + m[1])) {
						how = "comment";
						counts[1]++;
					}
					else {
						how = "none";
						counts[2]++;
					}
					out.println(
						String.join("\t", "DECOMP", f.getEntryPoint().toString(), m[0], m[1],
							how));
				}
			}
		}
		finally {
			d.dispose();
		}
	}

	private static boolean hasLine(String comment, String line) {
		if (comment == null) {
			return false;
		}
		for (String l : comment.split("\n")) {
			if (l.equals(line)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Splits a bookmark comment {@code "a", "b"?, "c" (large)} into its labels. The literals are
	 * C-escaped, so a quote inside one is always preceded by a backslash.
	 */
	static List<String> splitLabels(String comment) {
		List<String> labels = new ArrayList<>();
		int i = 0;
		while (i < comment.length()) {
			int start = i;
			if (comment.charAt(i) != '"') {
				throw new IllegalArgumentException("bad bookmark comment: " + comment);
			}
			i++;
			while (comment.charAt(i) != '"') {
				i += comment.charAt(i) == '\\' ? 2 : 1;
			}
			i++;
			if (i < comment.length() && comment.charAt(i) == '?') {
				i++;
			}
			if (comment.startsWith(" (large)", i)) {
				i += " (large)".length();
			}
			labels.add(comment.substring(start, i));
			if (comment.startsWith(", ", i)) {
				i += 2;
			}
		}
		return labels;
	}
}
