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
//   DECOMP   entry  address  label  equate|comment|none  word0  how the decompiled C of the
//                                                               function shows each marked string:
//                                                               an equate name of the string, else
//                                                               its comment line, else neither; and
//                                                               word 0 of a small string: its
//                                                               equate (S"..." without .hi), else
//                                                               pointer if the statement assigning
//                                                               it shows an address (&, a symbol or
//                                                               a quoted string), else none; comment
//                                                               instead of pointer or none if the C
//                                                               has the string's comment line; - for
//                                                               large, empty and probable strings
//   LARGEREF entry  address  literal  bytes  from,from,...|-   each large string in a bookmark: the
//                                                               address of its bytes in __cstring
//                                                               (? if not found) and the references
//                                                               from the function into the bytes,
//                                                               without the LARGEREF-WRONG ones
//   LARGEREF-WRONG  entry  from  to  literal                   operand reference from the function
//                                                               to the bytes of a large string of the
//                                                               function less 32, the value that word
//                                                               1 is built from, not the bytes: the
//                                                               instruction's register reaches an OR
//                                                               within 12 instructions (copies, cmov,
//                                                               jumps), not a call or an add first
//@category Swift

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
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
	/** Word 1 of a large string is the address of its bytes less this (NATIVE_BIAS). */
	private static final int LARGE_BIAS = 32;
	/** {@code SVar1.bridgeObject = (void *)S"C".hi;}: the variable whose word 1 is the equate. */
	private static final Pattern HI_ASSIGN =
		Pattern.compile(
			"(\\w+)\\.bridgeObject = (?:\\([^()]*\\) ?)?(S\"(?:[^\"\\\\]|\\\\.)*\"\\.hi);");

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
		// Function -> its large strings in bookmarks: address, literal.
		Map<Function, List<String[]>> largeByFunction =
			new TreeMap<>(Comparator.comparing(Function::getEntryPoint));
		LargeRefCounts largeRefs = null;
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
					else if (f != null) {
						largeByFunction.computeIfAbsent(f, k -> new ArrayList<>())
								.add(new String[] { a.toString(), literal });
					}
					if (f != null) {
						byFunction.computeIfAbsent(f, k -> new ArrayList<>())
								.add(new String[] { a.toString(), label, literal, kind });
					}
					// The comment line of a large string ends in " (large)", its bookmark label not.
					String line = "Swift " + label + (large ? " (large)" : "");
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
			largeRefs = dumpLargeRefs(out, largeByFunction);
			decompile(out, byFunction, cDir, decomp);
		}
		println(("DumpSwiftStrings: %d strings in bookmarks, %d comments, %d equate references, " +
			"%d mismatches; in the decompiler %d by equate, %d by comment, %d not shown")
					.formatted(marks, comments, equates, mismatches, decomp[0], decomp[1],
						decomp[2]));
		println(("DumpSwiftStrings: large strings: %d, %d without a reference to their bytes, " +
			"%d with more than one, %d not in __cstring, %d references to the bytes less 32")
					.formatted(largeRefs.strings, largeRefs.none, largeRefs.several,
						largeRefs.notFound, largeRefs.wrong));
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
					String word0 = m[3].equals("large") ? "-" : word0(c, m[1], literal);
					if ((word0.equals("pointer") || word0.equals("none")) &&
						c.contains("Swift " + m[1])) {
						word0 = "comment";
					}
					out.println(String.join("\t", "DECOMP", f.getEntryPoint().toString(), m[0],
						m[1], how, word0));
				}
			}
		}
		finally {
			d.dispose();
		}
	}

	/**
	 * How the decompiled C {@code c} (lines joined) shows word 0 of the string with bookmark label
	 * {@code label}: {@code equate} if {@code S"..."} occurs without {@code .hi}, else
	 * {@code pointer} if a statement assigning word 0 of a variable whose word 1 is the
	 * {@code .hi} equate shows an address, else {@code none}; {@code -} for the empty string (word
	 * 0 is 0, no equate) and probable strings (no equates). Small strings only.
	 */
	static String word0(String c, String label, String literal) {
		if (label.endsWith("?") || literal.equals("\"\"")) {
			return "-";
		}
		String name = "S" + literal;
		for (int i = c.indexOf(name); i >= 0; i = c.indexOf(name, i + 1)) {
			if (!c.startsWith(".hi", i + name.length())) {
				return "equate";
			}
		}
		Matcher m = HI_ASSIGN.matcher(c);
		while (m.find()) {
			if (!m.group(2).equals(name + ".hi")) {
				continue;
			}
			// The assignment of word 0 of the same variable, after word 1 or before it.
			String prefix = m.group(1) + ".str = ";
			int at = c.indexOf(prefix, m.end());
			if (at < 0) {
				at = c.lastIndexOf(prefix, m.start());
			}
			if (at < 0) {
				continue;
			}
			int end = c.indexOf(';', at);
			String value = c.substring(at + prefix.length(), end < 0 ? c.length() : end);
			if (showsAddress(value)) {
				return "pointer";
			}
		}
		return "none";
	}

	/**
	 * True if the C expression shows an address: {@code &}, a quoted string, or a symbol (an
	 * identifier that is not a type in a cast); an equate {@code S"..."} or a number is none.
	 */
	static boolean showsAddress(String value) {
		// Casts like (char *) or (long), then the equates.
		String v = value.replaceAll("\\((?:char|long|ulong|void|int|uint|byte|undefined\\d*)" +
			" ?\\**\\)", "").replaceAll("S\"(?:[^\"\\\\]|\\\\.)*\"", "");
		return v.contains("&") || v.contains("\"") || v.matches("(?s).*\\b[A-Za-z_]\\w*.*");
	}

	/** Counts of the LARGEREF lines. */
	private static final class LargeRefCounts {
		int strings;
		int none;
		int several;
		int notFound;
		int wrong;
	}

	/**
	 * Writes the LARGEREF and LARGEREF-WRONG lines for the large strings in bookmarks, by
	 * function. The bytes are found by their text in the {@code __cstring} blocks.
	 */
	private LargeRefCounts dumpLargeRefs(PrintWriter out,
			Map<Function, List<String[]>> largeByFunction) throws Exception {
		LargeRefCounts counts = new LargeRefCounts();
		Map<String, Address> cstrings = cstrings();
		for (Map.Entry<Function, List<String[]>> e : largeByFunction.entrySet()) {
			Function f = e.getKey();
			// Bytes less 32 -> literal, for the wrong references.
			Map<Address, String> biased = new HashMap<>();
			for (String[] m : e.getValue()) {
				Address bytes = cstrings.get(m[1]);
				if (bytes != null) {
					biased.put(bytes.subtract(LARGE_BIAS), m[1]);
				}
			}
			Set<String> wrong = new LinkedHashSet<>();
			Set<String> wrongRefs = new HashSet<>();
			for (Address from : f.getBody().getAddresses(true)) {
				for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(from)) {
					String literal = biased.get(r.getToAddress());
					if (literal != null && r.getOperandIndex() >= 0 && reachesOr(f, from)) {
						wrongRefs.add(refKey(r));
						wrong.add(String.join("\t", "LARGEREF-WRONG", f.getEntryPoint().toString(),
							from.toString(),
							r.getToAddress().toString(), literal));
					}
				}
			}
			for (String[] m : e.getValue()) {
				counts.strings++;
				Address bytes = cstrings.get(m[1]);
				List<String> froms = new ArrayList<>();
				if (bytes != null) {
					int n = utf8Length(m[1]);
					AddressSet range = new AddressSet(bytes, bytes.add(n - 1));
					for (Address from : f.getBody().getAddresses(true)) {
						for (Reference r : currentProgram.getReferenceManager()
								.getReferencesFrom(from)) {
							if (range.contains(r.getToAddress()) &&
								!wrongRefs.contains(refKey(r))) {
								froms.add(from.toString());
							}
						}
					}
				}
				else {
					counts.notFound++;
				}
				counts.none += froms.isEmpty() ? 1 : 0;
				counts.several += froms.size() > 1 ? 1 : 0;
				out.println(String.join("\t", "LARGEREF", f.getEntryPoint().toString(), m[0],
					m[1], bytes == null ? "?" : bytes.toString(),
					froms.isEmpty() ? "-" : String.join(",", froms)));
			}
			for (String w : wrong) {
				out.println(w);
				counts.wrong++;
			}
		}
		return counts;
	}

	/**
	 * True if a register that {@code from} writes reaches an INT_OR within 12 instructions of
	 * {@code f}, following fall-through and jumps, through copies (also cmov) but not through
	 * other ops (an add of -32 makes the value the bytes, a call ends the path). Independent of
	 * the analyzer's backward walk: the lea of a StaticString argument or of the bytes
	 * themselves is not a wrong reference, though its target can be another literal's bytes
	 * less 32.
	 */
	private boolean reachesOr(Function f, Address from) {
		Instruction start = currentProgram.getListing().getInstructionAt(from);
		if (start == null) {
			return false;
		}
		List<Varnode> written = new ArrayList<>();
		for (PcodeOp op : start.getPcode()) {
			if (op.getOutput() != null && op.getOutput().isRegister()) {
				written.add(op.getOutput());
			}
		}
		Deque<Object[]> todo = new ArrayDeque<>();
		for (Address next : successors(f, start)) {
			todo.add(new Object[] { next, written, 1 });
		}
		Set<Address> seen = new HashSet<>();
		while (!todo.isEmpty()) {
			Object[] s = todo.poll();
			Address at = (Address) s[0];
			@SuppressWarnings("unchecked")
			List<Varnode> tainted = new ArrayList<>((List<Varnode>) s[1]);
			int depth = (Integer) s[2];
			Instruction instr = currentProgram.getListing().getInstructionAt(at);
			if (instr == null || !seen.add(at) || instr.getFlowType().isCall()) {
				continue;
			}
			PcodeOp[] ops = instr.getPcode();
			boolean conditional =
				Arrays.stream(ops).anyMatch(o -> o.getOpcode() == PcodeOp.CBRANCH);
			for (PcodeOp op : ops) {
				boolean in = Arrays.stream(op.getInputs())
						.anyMatch(v -> tainted.stream().anyMatch(t -> t.intersects(v)));
				if (op.getOpcode() == PcodeOp.INT_OR && in) {
					return true;
				}
				Varnode out = op.getOutput();
				if (out == null) {
					continue;
				}
				if (op.getOpcode() == PcodeOp.COPY && in) {
					tainted.add(out);
				}
				else if (!conditional) {
					tainted.removeIf(t -> t.intersects(out));
				}
			}
			tainted.removeIf(Varnode::isUnique);
			if (!tainted.isEmpty() && depth < 12) {
				for (Address next : successors(f, instr)) {
					todo.add(new Object[] { next, tainted, depth + 1 });
				}
			}
		}
		return false;
	}

	/** A key for a reference: two lookups of the same one may give unequal objects. */
	private static String refKey(Reference r) {
		return r.getFromAddress() + ">" + r.getToAddress() + "@" + r.getOperandIndex();
	}

	/** The fall-through and jump targets of {@code instr} inside {@code f}. */
	private static List<Address> successors(Function f, Instruction instr) {
		List<Address> next = new ArrayList<>();
		if (instr.getFallThrough() != null) {
			next.add(instr.getFallThrough());
		}
		if (instr.getFlowType().isJump()) {
			next.addAll(Arrays.asList(instr.getFlows()));
		}
		next.removeIf(a -> !f.getBody().contains(a));
		return next;
	}

	/** The NUL-terminated UTF-8 strings of the __cstring blocks, quoted, to their addresses. */
	private Map<String, Address> cstrings() throws Exception {
		Map<String, Address> map = new HashMap<>();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			if (!b.getName().equals("__cstring") || !b.isInitialized()) {
				continue;
			}
			byte[] bytes = new byte[(int) b.getSize()];
			b.getBytes(b.getStart(), bytes);
			int start = 0;
			for (int i = 0; i < bytes.length; i++) {
				if (bytes[i] == 0) {
					if (i > start) {
						String text = new String(bytes, start, i - start, StandardCharsets.UTF_8);
						map.putIfAbsent(SwiftStringCodec.quote(text), b.getStart().add(start));
					}
					start = i + 1;
				}
			}
		}
		return map;
	}

	/** The UTF-8 length of the text of a quoted literal (as SwiftStringCodec.quote writes it). */
	static int utf8Length(String literal) {
		String body = literal.substring(1, literal.length() - 1);
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < body.length(); i++) {
			char ch = body.charAt(i);
			if (ch != '\\') {
				sb.append(ch);
				continue;
			}
			char next = body.charAt(++i);
			if (next == 'x') {
				sb.append((char) Integer.parseInt(body.substring(i + 1, i + 3), 16));
				i += 2;
			}
			else {
				sb.append(switch (next) {
					case 'n' -> '\n';
					case 'r' -> '\r';
					case 't' -> '\t';
					default -> next;
				});
			}
		}
		return sb.toString().getBytes(StandardCharsets.UTF_8).length;
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
