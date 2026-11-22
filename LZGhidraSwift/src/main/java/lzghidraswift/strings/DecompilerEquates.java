// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import lzghidraswift.strings.StringHit.Kind;

/**
 * Names the words of small strings in the decompiler. Decompiles a function once, finds the
 * constant varnodes whose value is a word of a string found in it, and attaches an equate to each
 * by its dynamic hash, as the decompiler's "Convert constant" action does
 * ({@code ConvertConstantEquateTask}). This also reaches constants that are folded from several
 * instructions ({@code mov}/{@code movk} chains), which have no instruction operand to carry an
 * equate. Reports which strings the decompiler shows, so that the others can get a comment, and
 * which small strings have no constant for word 0 that prints as a number: the decompiler shows
 * that word as a pointer when its value is the address of a symbol or lies inside a defined
 * string, and then ignores its equate ({@code ActionConstantPtr}, {@code RulePtrsubCharConstant}). The decompiling itself is done by {@link DecompilerPool}.
 */
public final class DecompilerEquates {

	/**
	 * Word 0 values below this are strings of one or two bytes ({@code "C"} is 0x43) and also
	 * common numbers; they are matched only at the string's own instructions, not anywhere in the
	 * function.
	 */
	private static final long WEAK_LIMIT = 0x1_0000L;

	/**
	 * What happened to the strings of one function. {@code word0Hidden}: the equated hits with a
	 * word 0 other than 0 that no constant of the decompiled function stands for.
	 */
	public record Result(boolean decompiled, String error, Set<StringHit> shown,
			Set<StringHit> word0Hidden, int added, int present) {}

	/** One word of a string: the value the decompiler may show, and the equate name for it. */
	private record Word(StringHit hit, long value, String name) {
		boolean weak() {
			return Long.compareUnsigned(value, WEAK_LIMIT) < 0;
		}

		/** The string's own instructions: its two producers and its use site. */
		boolean isOwnAddress(Address a) {
			return a.equals(hit.word0At()) || a.equals(hit.word1At()) || a.equals(hit.useAt());
		}

		/** True for word 0, false for the tag word. */
		boolean isWord0() {
			return !name.endsWith(".hi");
		}
	}

	private final Program program;

	public DecompilerEquates(Program program) {
		this.program = program;
	}

	/** True for the hits this class equates: certain small strings. */
	public static boolean equates(StringHit h) {
		return h.kind() == Kind.SMALL && !h.method().probable();
	}

	/** True if {@link #plan} needs the decompiled function for {@code hits}. */
	public static boolean needsDecompiler(List<StringHit> hits) {
		return hits.stream().anyMatch(DecompilerEquates::equates);
	}

	/** An equate reference to add: the word's equate on the constant with this hash. */
	record Ref(Word word, long hash, Address addr) {
		/**
		 * The order in which {@link #apply} adds a plan's references: by address, then by hash.
		 * The equate table lists the references at an address in the order they were added.
		 * The p-code op order of a decompile is no good for this: a decompiler process that
		 * decompiled other functions before can give the same constants other op numbers, so
		 * the order would depend on the number of decompiler threads.
		 */
		static final Comparator<Ref> ORDER = Comparator.comparing(Ref::addr)
				.thenComparing(Ref::hash, Long::compareUnsigned);
	}

	/**
	 * What {@link #apply} will do for one function: the references to add, and the hits that
	 * an equate already shows. Made from the decompiler results alone, so on any thread.
	 */
	public static final class Plan {
		private final boolean decompiled;
		private final String error;
		private final Set<StringHit> present;
		private final Set<StringHit> word0Hidden;
		private final int presentCount;
		private final List<Ref> refs;

		private Plan(boolean decompiled, String error, Set<StringHit> present,
				Set<StringHit> word0Hidden, int presentCount, List<Ref> refs) {
			this.decompiled = decompiled;
			this.error = error;
			this.present = present;
			this.word0Hidden = word0Hidden;
			this.presentCount = presentCount;
			this.refs = refs;
		}

		private static Plan failed(String error) {
			return new Plan(false, error, Set.of(), Set.of(), 0, List.of());
		}
	}

	/**
	 * Finds the constants of the decompiled function that stand for the words of the certain
	 * small strings in {@code hits}. Only reads the decompiler results, not the program.
	 *
	 * @param res the function's decompiler results, null if the decompiler did not start (or
	 *            not needed, see {@link #needsDecompiler})
	 */
	public static Plan plan(List<StringHit> hits, DecompileResults res) {
		List<Word> words = new ArrayList<>();
		for (StringHit h : hits) {
			if (!equates(h)) {
				continue;
			}
			if (h.word0() != 0) {
				words.add(new Word(h, h.word0(), StringMarkup.equateName(h.text())));
			}
			words.add(new Word(h, h.word1(), StringMarkup.equateNameHi(h.text())));
		}
		if (words.isEmpty()) {
			return new Plan(true, null, Set.of(), Set.of(), 0, List.of());
		}
		if (res == null) {
			return Plan.failed("decompiler did not start");
		}
		HighFunction hf = res.getHighFunction();
		if (!res.decompileCompleted() || hf == null) {
			return Plan.failed(res.getErrorMessage());
		}
		Pass pass = new Pass(hf, words);
		Iterator<PcodeOpAST> ops = hf.getPcodeOps();
		while (ops.hasNext()) {
			PcodeOp op = ops.next();
			for (int i = 0; i < op.getNumInputs(); i++) {
				Varnode vn = op.getInput(i);
				if (vn != null && vn.isConstant() && !isSpaceSlot(op, i) && !isPointerOp(op)) {
					pass.mark(vn, op.getSeqnum().getTarget());
				}
			}
		}
		pass.refs.sort(Ref.ORDER);
		Set<StringHit> hidden = new HashSet<>();
		for (Word w : words) {
			if (w.isWord0() && !pass.word0Seen.contains(w.hit())) {
				hidden.add(w.hit());
			}
		}
		return new Plan(true, null, pass.present, hidden, pass.presentCount, pass.refs);
	}

	/** Adds the equate references of {@code plan} to the program. */
	public Result apply(Plan plan) {
		if (!plan.decompiled) {
			return new Result(false, plan.error, Set.of(), Set.of(), 0, 0);
		}
		EquateTable table = program.getEquateTable();
		Set<StringHit> shown = new HashSet<>(plan.present);
		int added = 0;
		for (Ref r : plan.refs) {
			if (addReference(r.word(), r.hash(), r.addr(), table)) {
				shown.add(r.word().hit());
				added++;
			}
		}
		return new Result(true, null, shown, plan.word0Hidden, added, plan.presentCount);
	}

	/** One {@link #plan}: the decompiled function, its words and what was found. */
	private static final class Pass {
		final HighFunction hf;
		final List<Word> words;
		final Map<String, List<StringHit>> byName = new HashMap<>();
		final Set<StringHit> present = new HashSet<>();
		/** The hits whose word 0 a constant stands for, by an equate or a planned reference. */
		final Set<StringHit> word0Seen = new HashSet<>();
		final List<Ref> refs = new ArrayList<>();
		int presentCount;

		Pass(HighFunction hf, List<Word> words) {
			this.hf = hf;
			this.words = words;
			for (Word w : words) {
				byName.computeIfAbsent(w.name(), k -> new ArrayList<>()).add(w.hit());
			}
		}

		/** Plans an equate on the constant {@code vn}, read at {@code at}, if it stands for a word. */
		void mark(Varnode vn, Address at) {
			HighVariable high = vn.getHigh();
			HighSymbol sym = high == null ? null : high.getSymbol();
			boolean pointer = high != null && printsAsAddress(high.getDataType());
			if (sym instanceof EquateSymbol) {
				// An equate already shows here: ours from the listing markup, or the user's.
				List<StringHit> named = byName.get(sym.getName());
				if (named != null) {
					present.addAll(named);
					presentCount++;
					if (!sym.getName().endsWith(".hi") && !pointer) {
						word0Seen.addAll(named);
					}
				}
				return;
			}
			if (sym != null) {
				return;
			}
			Word w = pick(words, vn.getOffset(), at);
			if (w == null || (w.isWord0() && pointer)) {
				return;
			}
			DynamicHash dh = new DynamicHash(vn, hf);
			if (dh.getHash() != 0 && dh.getAddress() != null) {
				refs.add(new Ref(w, dh.getHash(), dh.getAddress()));
				if (w.isWord0()) {
					word0Seen.add(w.hit());
				}
			}
		}
	}

	/**
	 * PTRSUB and PTRADD: the decompiler has made the constant a pointer ({@code &DAT_0000a9c3},
	 * {@code "cidentalOWV"}), and prints no equate on it.
	 */
	private static boolean isPointerOp(PcodeOp op) {
		return op.getOpcode() == PcodeOp.PTRSUB || op.getOpcode() == PcodeOp.PTRADD;
	}

	/**
	 * True for a constant type that the decompiler prints as a string or a function name, never
	 * as the constant's equate ({@code PrintC::pushConstant}): a pointer to characters or code.
	 * {@code RulePtrsubCharConstant} makes a pointer into a string such a constant. Other
	 * pointers print as a cast of the equate ({@code (NSBundle *)S"FluentUI"}). Word 0 counts as
	 * shown only on another type.
	 */
	static boolean printsAsAddress(DataType t) {
		if (!(t instanceof Pointer p)) {
			return false;
		}
		DataType to = p.getDataType();
		if (to instanceof TypeDef td) {
			to = td.getBaseDataType();
		}
		return to instanceof CharDataType || to instanceof WideCharDataType ||
			to instanceof WideChar16DataType || to instanceof WideChar32DataType ||
			to instanceof FunctionDefinition;
	}

	/** Slot 0 of LOAD and STORE is the address space id, not a value. */
	private static boolean isSpaceSlot(PcodeOp op, int slot) {
		int code = op.getOpcode();
		return slot == 0 && (code == PcodeOp.LOAD || code == PcodeOp.STORE);
	}

	/**
	 * The word that a constant with {@code value}, read at {@code at}, stands for. If words of
	 * several strings have this value (the first 8 bytes of {@code "chord_ch"} and
	 * {@code "chord_change"}), the one whose instructions are at {@code at} wins, else the one
	 * produced nearest before it.
	 */
	private static Word pick(List<Word> words, long value, Address at) {
		Word best = null;
		long bestRank = Long.MAX_VALUE;
		for (Word w : words) {
			if (w.value() != value) {
				continue;
			}
			boolean own = w.isOwnAddress(at);
			if (w.weak() && !own) {
				continue;
			}
			long rank;
			if (own) {
				rank = 0;
			}
			else {
				Address p = w.value() == w.hit().word0() ? w.hit().word0At() : w.hit().word1At();
				long dist = p == null ? Long.MAX_VALUE / 4 : at.subtract(p);
				// Producers before the use rank ahead of producers after it.
				rank = dist >= 0 ? 1 + dist : Long.MAX_VALUE / 2 - dist;
			}
			if (rank < bestRank) {
				best = w;
				bestRank = rank;
			}
		}
		return best;
	}

	private boolean addReference(Word w, long hash, Address addr, EquateTable table) {
		Equate eq = table.getEquate(w.name());
		try {
			if (eq == null) {
				eq = table.createEquate(w.name(), w.value());
			}
		}
		catch (DuplicateNameException | InvalidInputException e) {
			Msg.warn(this, "SWIFTSTR-EQUATE\t%s\t%s\t%s".formatted(addr, w.name(), e.getMessage()));
			return false;
		}
		if (eq.getValue() != w.value()) {
			Msg.warn(this, "SWIFTSTR-EQUATE\t%s\t%s\texists with value 0x%x"
					.formatted(addr, w.name(), eq.getValue()));
			return false;
		}
		eq.addReference(hash, addr);
		return true;
	}
}
