// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import java.util.*;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import lzghidraswift.strings.StringHit.Kind;

/**
 * Puts the strings found in a function into the listing: a comment line {@code Swift "text"} and
 * a bookmark at the instruction that completes each string, an equate on each instruction
 * operand whose scalar is a whole word of a small string ({@code movabs} on x86_64, a single
 * {@code mov} on AArch64), and a data reference to the bytes of a large string if the function
 * has none. {@link DecompilerEquates} adds equates on decompiler constants, and
 * {@link #addPreLines} a PRE comment line for strings the decompiler does not show. With the
 * string block option, small strings also go into {@link StringBlock}, written by
 * {@link #writeBlock} at the end of the run. Re-running replaces this markup and leaves the rest
 * alone: comment lines are recognised by {@link #isOwnLine}, bookmarks by their category, equates
 * by {@link #isOwnEquate}, block references by their target space.
 */
public final class StringMarkup {

	public static final String BOOKMARK_CATEGORY_SMALL = "Swift string (small)";
	public static final String BOOKMARK_CATEGORY_LARGE = "Swift string (large)";
	static final String LINE_PREFIX = "Swift ";

	/** {@code Swift "..."}, optionally followed by {@code ?} (probable) and {@code  (large)}. */
	private static final Pattern OWN_LINE = Pattern.compile("^Swift \".*\"\\??( \\(large\\))?$");
	/**
	 * {@code S"..."} or {@code S"...".hi}. Not {@code "..."}: the decompiler takes an equate name
	 * that starts with a quote as a request to show the value as a character constant
	 * ({@code EquateSymbol.convertName}), not as a name.
	 */
	private static final Pattern OWN_EQUATE = Pattern.compile("^S\".*\"(\\.hi)?$");

	/** The comment type of the {@code Swift "text"} lines: end-of-line or pre comment. */
	public enum CommentStyle {
		EOL, PRE
	}

	/**
	 * What to mark: the comment style, and whether to add bookmarks, probable hits, large strings,
	 * decompiler equates and the string block.
	 */
	public record Options(CommentStyle style, boolean bookmarks, boolean probable, boolean large,
			boolean decompilerEquates, boolean stringBlock) {
		public static Options defaults() {
			return new Options(CommentStyle.EOL, true, true, true, true, false);
		}
	}

	/** What one call of {@link #apply} created. */
	public record Counts(int comments, int bookmarks, int equates, int refsAdded, int refsPresent) {
		public Counts plus(Counts o) {
			return new Counts(comments + o.comments, bookmarks + o.bookmarks, equates + o.equates,
				refsAdded + o.refsAdded, refsPresent + o.refsPresent);
		}
	}

	public static final Counts NONE = new Counts(0, 0, 0, 0, 0);

	private final Program program;
	private final Options options;
	/** Null without the string block option. */
	private final StringBlock block;

	public StringMarkup(Program program, Options options) {
		this.program = program;
		this.options = options;
		this.block = options.stringBlock() ? new StringBlock(program) : null;
	}

	// ---------------------------------------------------------------- text, no Ghidra types

	/** The text of a hit in bookmarks: quoted, {@code ?} if probable. The category gives the kind. */
	static String bookmarkLabel(StringHit h) {
		return SwiftStringCodec.quote(h.text()) + (h.method().probable() ? "?" : "");
	}

	/** The text of a hit in comments: as {@link #bookmarkLabel}, plus {@code (large)}. */
	public static String label(StringHit h) {
		return bookmarkLabel(h) + (h.kind() == Kind.LARGE ? " (large)" : "");
	}

	static String bookmarkCategory(Kind kind) {
		return kind == Kind.LARGE ? BOOKMARK_CATEGORY_LARGE : BOOKMARK_CATEGORY_SMALL;
	}

	static boolean isOwnLine(String line) {
		return OWN_LINE.matcher(line).matches();
	}

	/** The equate name of word 0 of a small string: {@code S"Flat"}. */
	static String equateName(String text) {
		return "S" + SwiftStringCodec.quote(text);
	}

	/** The equate name of word 1 (the tag word): {@code S"Flat".hi}. */
	static String equateNameHi(String text) {
		return equateName(text) + ".hi";
	}

	static boolean isOwnEquate(String name) {
		return OWN_EQUATE.matcher(name).matches();
	}

	/**
	 * The comment with this class's lines replaced by {@code own}: other lines first, in their
	 * order, then {@code own}. Null if nothing is left.
	 */
	static String mergeComment(String existing, List<String> own) {
		List<String> lines = new ArrayList<>();
		if (existing != null) {
			for (String l : existing.split("\n", -1)) {
				if (!isOwnLine(l)) {
					lines.add(l);
				}
			}
			// A comment that was only our lines leaves one empty line from split; drop it.
			if (lines.size() == 1 && lines.getFirst().isEmpty()) {
				lines.clear();
			}
		}
		lines.addAll(own);
		return lines.isEmpty() ? null : String.join("\n", lines);
	}

	/** The comment with the lines of {@code add} appended that it does not have yet. */
	static String appendLines(String existing, List<String> add) {
		List<String> lines = new ArrayList<>();
		if (existing != null) {
			lines.addAll(Arrays.asList(existing.split("\n", -1)));
		}
		for (String l : add) {
			if (!lines.contains(l)) {
				lines.add(l);
			}
		}
		return lines.isEmpty() ? null : String.join("\n", lines);
	}

	// ---------------------------------------------------------------- program changes

	/**
	 * Removes this class's comment lines, bookmarks, equates and string block references in
	 * {@code body}. The block references go with the option off too.
	 */
	public void clear(AddressSetView body, TaskMonitor monitor) throws CancelledException {
		for (CommentType type : new CommentType[] { CommentType.EOL, CommentType.PRE }) {
			clearComments(body, type);
		}
		for (String category : new String[] { BOOKMARK_CATEGORY_SMALL, BOOKMARK_CATEGORY_LARGE }) {
			program.getBookmarkManager()
					.removeBookmarks(body, BookmarkType.ANALYSIS, category,
						monitor);
		}
		clearEquates(body);
		StringBlock.clearReferences(program, body);
	}

	private void clearComments(AddressSetView body, CommentType type) {
		Listing listing = program.getListing();
		List<Address> addrs = new ArrayList<>();
		AddressIterator it = listing.getCommentAddressIterator(type, body, true);
		while (it.hasNext()) {
			addrs.add(it.next());
		}
		for (Address a : addrs) {
			String old = listing.getComment(type, a);
			String merged = mergeComment(old, List.of());
			if (!Objects.equals(old, merged)) {
				listing.setComment(a, type, merged);
			}
		}
	}

	private void clearEquates(AddressSetView body) {
		EquateTable table = program.getEquateTable();
		List<Address> addrs = new ArrayList<>();
		AddressIterator it = table.getEquateAddresses(body);
		while (it.hasNext()) {
			addrs.add(it.next());
		}
		for (Address a : addrs) {
			for (Equate e : table.getEquates(a)) {
				if (isOwnEquate(e.getName())) {
					removeReferences(table, e, a);
				}
			}
		}
	}

	/** Removes the references of {@code e} at {@code a}, and {@code e} if none are left. */
	private static void removeReferences(EquateTable table, Equate e, Address a) {
		for (EquateReference r : e.getReferences(a)) {
			if (r.getDynamicHashValue() != 0) {
				e.removeReference(r.getDynamicHashValue(), a);
			}
			else {
				e.removeReference(a, r.getOpIndex());
			}
		}
		if (e.getReferenceCount() == 0) {
			table.removeEquate(e.getName());
		}
	}

	/**
	 * Marks the hits of {@code function}; call {@link #clear} on its body first. The string block
	 * references follow in {@link #writeBlock}.
	 */
	public Counts apply(Function function, List<StringHit> hits) {
		List<StringHit> marked = new ArrayList<>();
		for (StringHit h : hits) {
			if (marks(h)) {
				marked.add(h);
			}
		}
		// Stable order: by completing instruction, then text.
		marked.sort(Comparator.comparing(StringHit::completedAt).thenComparing(StringHit::text));
		int comments = setComments(marked);
		int bookmarks = options.bookmarks() ? setBookmarks(marked) : 0;
		int equates = 0;
		int refsAdded = 0;
		int refsPresent = 0;
		for (StringHit h : marked) {
			if (h.kind() == Kind.SMALL) {
				equates += equates(h);
				if (block != null) {
					block.add(h.completedAt(), h.text());
				}
				continue;
			}
			switch (reference(function, h)) {
				case 1 -> refsAdded++;
				case 0 -> refsPresent++;
				default -> {
				}
			}
		}
		return new Counts(comments, bookmarks, equates, refsAdded, refsPresent);
	}

	/**
	 * Writes the small strings of every {@link #apply} since the last call into the string block
	 * and adds their references. Null without the string block option.
	 */
	public StringBlock.Result writeBlock(TaskMonitor monitor) throws CancelledException {
		return block == null ? null : block.write(monitor);
	}

	/** One comment line per string at each completing instruction. Returns the comments set. */
	private int setComments(List<StringHit> marked) {
		Map<Address, List<String>> labels = new LinkedHashMap<>();
		for (StringHit h : marked) {
			addOnce(labels.computeIfAbsent(h.completedAt(), a -> new ArrayList<>()), label(h));
		}
		Listing listing = program.getListing();
		CommentType type = options.style() == CommentStyle.PRE ? CommentType.PRE : CommentType.EOL;
		for (Map.Entry<Address, List<String>> e : labels.entrySet()) {
			List<String> lines = new ArrayList<>();
			for (String s : e.getValue()) {
				lines.add(LINE_PREFIX + s);
			}
			listing.setComment(e.getKey(), type,
				mergeComment(listing.getComment(type, e.getKey()), lines));
		}
		return labels.size();
	}

	/**
	 * One bookmark per address, type and category: strings of one kind share it. Returns the
	 * bookmarks set.
	 */
	private int setBookmarks(List<StringHit> marked) {
		Map<Kind, Map<Address, List<String>>> byKind = new EnumMap<>(Kind.class);
		for (StringHit h : marked) {
			addOnce(byKind.computeIfAbsent(h.kind(), k -> new LinkedHashMap<>())
					.computeIfAbsent(h.completedAt(), a -> new ArrayList<>()),
				bookmarkLabel(h));
		}
		BookmarkManager bm = program.getBookmarkManager();
		int bookmarks = 0;
		for (Map.Entry<Kind, Map<Address, List<String>>> k : byKind.entrySet()) {
			for (Map.Entry<Address, List<String>> e : k.getValue().entrySet()) {
				bm.setBookmark(e.getKey(), BookmarkType.ANALYSIS, bookmarkCategory(k.getKey()),
					String.join(", ", e.getValue()));
				bookmarks++;
			}
		}
		return bookmarks;
	}

	/** The equates on the two words of a certain small string. Returns the number added. */
	private int equates(StringHit h) {
		if (h.method().probable()) {
			return 0;
		}
		int added = 0;
		if (h.word0() != 0 && equate(h.word0At(), h.word0(), equateName(h.text()))) {
			added++;
		}
		if (equate(h.word1At(), h.word1(), equateNameHi(h.text()))) {
			added++;
		}
		return added;
	}

	private static void addOnce(List<String> list, String s) {
		if (!list.contains(s)) {
			list.add(s);
		}
	}

	/** True for the hits that {@link #apply} marks with the current options. */
	public boolean marks(StringHit h) {
		return !(h.method().probable() && !options.probable()) &&
			!(h.kind() == Kind.LARGE && !options.large());
	}

	/**
	 * Adds a PRE comment line {@code Swift "text"} at the use site of each hit (the call, store
	 * or compare that the decompiler shows as a statement), keeping the lines already there.
	 * For strings the decompiler does not show by an equate. Returns the number of comments
	 * changed.
	 */
	public int addPreLines(List<StringHit> hits) {
		Map<Address, List<String>> lines = new TreeMap<>();
		List<StringHit> sorted = new ArrayList<>(hits);
		sorted.sort(Comparator.comparing(StringHit::useAt).thenComparing(StringHit::text));
		for (StringHit h : sorted) {
			List<String> l = lines.computeIfAbsent(h.useAt(), a -> new ArrayList<>());
			String s = LINE_PREFIX + label(h);
			if (!l.contains(s)) {
				l.add(s);
			}
		}
		Listing listing = program.getListing();
		int changed = 0;
		for (Map.Entry<Address, List<String>> e : lines.entrySet()) {
			String old = listing.getComment(CommentType.PRE, e.getKey());
			String merged = appendLines(old, e.getValue());
			if (!Objects.equals(old, merged)) {
				listing.setComment(e.getKey(), CommentType.PRE, merged);
				changed++;
			}
		}
		return changed;
	}

	/**
	 * Puts the equate {@code name = value} on the operand of the instruction at {@code at} whose
	 * scalar is {@code value}, unless that operand already has an equate. Returns true if added.
	 */
	private boolean equate(Address at, long value, String name) {
		if (at == null) {
			return false;
		}
		Instruction instr = program.getListing().getInstructionAt(at);
		if (instr == null) {
			return false;
		}
		int op = scalarOperand(instr, value);
		EquateTable table = program.getEquateTable();
		if (op < 0 || !table.getEquates(at, op).isEmpty()) {
			return false;
		}
		Scalar s = instr.getScalar(op);
		Equate eq = table.getEquate(name);
		try {
			if (eq == null) {
				eq = table.createEquate(name, s.getValue());
			}
		}
		catch (DuplicateNameException | InvalidInputException e) {
			Msg.warn(this, "SWIFTSTR-EQUATE\t%s\t%s\t%s".formatted(at, name, e.getMessage()));
			return false;
		}
		if (eq.getValue() != s.getValue()) {
			Msg.warn(this, "SWIFTSTR-EQUATE\t%s\t%s\texists with value 0x%x"
					.formatted(at, name, eq.getValue()));
			return false;
		}
		eq.addReference(at, op);
		return true;
	}

	/** The first operand of {@code instr} whose scalar is {@code value}, or -1. */
	private static int scalarOperand(Instruction instr, long value) {
		for (int op = 0; op < instr.getNumOperands(); op++) {
			Scalar s = instr.getScalar(op);
			if (s != null && (s.getValue() == value || s.getUnsignedValue() == value)) {
				return op;
			}
		}
		return -1;
	}

	/**
	 * Adds a data reference from the instruction that produced word 1 of a large string to its
	 * bytes, if no instruction of the function refers to them yet. Returns 1 if added, 0 if one
	 * was present, -1 if neither was possible.
	 */
	private int reference(Function function, StringHit h) {
		if (h.word1At() == null) {
			return -1;
		}
		long offset =
			(h.word1() & ~SwiftStringCodec.LARGE_OBJECT_FLAG) + SwiftStringCodec.NATIVE_BIAS;
		Address str = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		ReferenceManager rm = program.getReferenceManager();
		for (Reference r : rm.getReferencesTo(str)) {
			if (function.getBody().contains(r.getFromAddress())) {
				return 0;
			}
		}
		rm.addMemoryReference(h.word1At(), str, RefType.DATA, SourceType.ANALYSIS,
			Reference.MNEMONIC);
		return 1;
	}
}
