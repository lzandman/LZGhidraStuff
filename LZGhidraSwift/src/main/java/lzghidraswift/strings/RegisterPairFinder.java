// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lzghidraswift.abi.CallingConventions;
import lzghidraswift.flow.ValueFlow;
import lzghidraswift.flow.ValueFlow.Value;
import lzghidraswift.strings.StringHit.Kind;
import lzghidraswift.strings.StringHit.Method;

/**
 * Pairs the two words of Swift string literals at the places where they are used: adjacent
 * argument registers at calls and tail branches, result registers at returns, word 1 stored 8
 * bytes after word 0, and a compare with the tag word right after a compare with word 0.
 * The register values come from {@link ValueFlow}.
 */
public final class RegisterPairFinder implements ValueFlow.Listener {

	/** Largest distance in bytes from a word 0 compare to the following tag-word compare. */
	private static final int COMPARE_WINDOW = 64;

	/** Outgoing stack words searched for string arguments at calls and tail branches. */
	private static final int STACK_WORDS = 8;

	/** A register that holds exactly one constant after the instruction that produced it. */
	public record Constant(Address at, Varnode register, long value) {}

	private record Use(Address at, Method method, List<List<Value>> registers) {}

	private record Store(Address at, List<Value> addresses, List<Value> values) {}

	private record Compare(Address at, List<Value> a, List<Value> b) {}

	private final Program program;
	private final Function function;
	private final List<Register> args;
	private final List<Register> results;
	private final long stackArgs;
	private ValueFlow flow;

	private final List<Use> uses = new ArrayList<>();
	private final List<Store> stores = new ArrayList<>();
	private final List<Compare> compares = new ArrayList<>();
	private final List<Constant> constants = new ArrayList<>();
	private final Map<List<Object>, StringHit> hits = new LinkedHashMap<>();
	private final Set<Address> largeWord1Producers = new HashSet<>();

	/** Prepares a search of {@code function}; {@link #run} does the work. */
	public RegisterPairFinder(Program program, Function function) {
		this.program = program;
		this.function = function;
		this.args = CallingConventions.argumentRegisters(program);
		this.results = CallingConventions.resultRegisters(program);
		this.stackArgs = CallingConventions.stackArgumentOffset(program);
	}

	/** Runs the data flow and the pairing. */
	public List<StringHit> run(TaskMonitor monitor) throws CancelledException {
		flow = new ValueFlow(program, function, this);
		flow.run(monitor);
		for (Use u : uses) {
			pairRegisters(u);
		}
		pairStores();
		pairCompares();
		return new ArrayList<>(hits.values());
	}

	/** The data flow of the last {@link #run}. Also called by ProbeFlow (by reflection). */
	public ValueFlow flow() {
		return flow;
	}

	/** The instructions that produced word 1 of a large string, in any pairing (before dedupe). */
	public Set<Address> largeWord1Producers() {
		return largeWord1Producers;
	}

	/** Every register constant produced in the function, in address order. */
	public List<Constant> constants() {
		List<Constant> c = new ArrayList<>(constants);
		c.sort(Comparator.comparing(Constant::at));
		return c;
	}

	// ---------------------------------------------------------------- events

	@Override
	public void use(Instruction instr, ValueFlow.UseKind kind, ValueFlow.State state) {
		List<Register> regs = kind == ValueFlow.UseKind.RETURN ? results : args;
		List<List<Value>> vals = new ArrayList<>();
		for (Register r : regs) {
			vals.add(flow.readRegister(state, r));
		}
		if (kind != ValueFlow.UseKind.RETURN) {
			// Arguments after the last argument register are on the stack, and a String can
			// span the two: NSLocalizedString's comment: has word 0 in x7 and word 1 at [sp].
			for (int i = 0; i < STACK_WORDS; i++) {
				vals.add(flow.readStackWord(state, stackArgs + 8L * i));
			}
		}
		Method m = switch (kind) {
			case CALL -> Method.CALL;
			case TAIL -> Method.TAIL;
			case RETURN -> Method.RETURN;
		};
		uses.add(new Use(instr.getAddress(), m, vals));
	}

	@Override
	public void store(Instruction instr, List<Value> address, List<Value> values, int size) {
		// Every alternative address is kept: blocks that Ghidra reaches only through a jump table
		// have no predecessor here and start with the entry value of x29, so after a merge the
		// frame pointer can have two values although both stores use the same one.
		if (size == 8 && !address.isEmpty()) {
			stores.add(new Store(instr.getAddress(), address, values));
		}
	}

	@Override
	public void compare(Instruction instr, List<Value> a, List<Value> b) {
		compares.add(new Compare(instr.getAddress(), a, b));
	}

	@Override
	public void constant(Instruction instr, Varnode register, Value value) {
		constants.add(new Constant(instr.getAddress(), register, value.k()));
	}

	// ---------------------------------------------------------------- pairing

	/** Tries all combinations of the two value sets whose labels agree; returns true on a hit. */
	private boolean tryPair(List<Value> w0s, List<Value> w1s, Address useAt, Method method) {
		boolean found = false;
		for (Value w1 : w1s) {
			if (!w1.isConst()) {
				continue;
			}
			boolean small = SwiftStringCodec.isSmallTag(w1.k());
			boolean large = (w1.k() & 0xF000_0000_0000_0000L) == SwiftStringCodec.LARGE_OBJECT_FLAG;
			if (!small && !large) {
				continue;
			}
			for (Value w0 : w0s) {
				if (!w0.isConst() || ValueFlow.joinLabels(w0.labels(), w1.labels()) == null) {
					continue;
				}
				StringHit h = hit(w0, w1, small, useAt, method);
				if (h != null) {
					add(h);
					found = true;
				}
			}
		}
		return found;
	}

	/**
	 * The string of the constant words {@code w0} and {@code w1}, a small string if {@code small},
	 * else a large one with a matching C string in __cstring; null if they decode to none.
	 */
	private StringHit hit(Value w0, Value w1, boolean small, Address useAt, Method method) {
		if (small) {
			String s = SwiftStringCodec.decodeSmall(w0.k(), w1.k());
			return s != null ? new StringHit(Kind.SMALL, s, w0.producer(), w1.producer(), useAt,
				method, w0.k(), w1.k()) : null;
		}
		SwiftStringCodec.LargeHeader h = SwiftStringCodec.decodeLargeHeader(w0.k(), w1.k());
		String s = h != null ? LargeStringFinder.verify(program, h) : null;
		return s != null ? new StringHit(Kind.LARGE, s, w0.producer(), w1.producer(), useAt,
			method, w0.k(), w1.k()) : null;
	}

	private void add(StringHit h) {
		if (h.kind() == Kind.LARGE && h.word1At() != null) {
			largeWord1Producers.add(h.word1At());
		}
		hits.putIfAbsent(
			List.of(String.valueOf(h.word0At()), String.valueOf(h.word1At()), h.text()), h);
	}

	private void pairRegisters(Use u) {
		for (int i = 0; i + 1 < u.registers().size(); i++) {
			tryPair(u.registers().get(i), u.registers().get(i + 1), u.at(), u.method());
		}
	}

	private void pairStores() {
		for (Store s1 : stores) {
			boolean hasWord1 = false;
			for (Value v : s1.values()) {
				hasWord1 |= v.isConst() && (SwiftStringCodec.isSmallTag(v.k()) ||
					(v.k() & 0xF000_0000_0000_0000L) == SwiftStringCodec.LARGE_OBJECT_FLAG);
			}
			if (!hasWord1) {
				continue;
			}
			List<Store> partners = new ArrayList<>();
			for (Store s0 : stores) {
				if (adjacent(s0.addresses(), s1.addresses())) {
					partners.add(s0);
				}
			}
			partners.sort(Comparator.comparingLong(s0 -> Math.abs(s0.at().subtract(s1.at()))));
			for (Store s0 : partners) {
				if (tryPair(s0.values(), s1.values(), s1.at(), Method.STORE)) {
					break;
				}
			}
		}
	}

	/** True if some address of word 1 is 8 bytes after some address of word 0, same base. */
	private static boolean adjacent(List<Value> w0Addresses, List<Value> w1Addresses) {
		for (Value a0 : w0Addresses) {
			for (Value a1 : w1Addresses) {
				if (Objects.equals(a0.sym(), a1.sym()) && a0.k() + 8 == a1.k()) {
					return true;
				}
			}
		}
		return false;
	}

	private void pairCompares() {
		List<Compare> sorted = new ArrayList<>(compares);
		sorted.sort(Comparator.comparing(Compare::at));
		for (int i = 0; i < sorted.size(); i++) {
			Compare c1 = sorted.get(i);
			List<Value> tags = new ArrayList<>();
			for (Value v : concat(c1.a(), c1.b())) {
				if (v.isConst() && SwiftStringCodec.isSmallTag(v.k())) {
					tags.add(v);
				}
			}
			if (tags.isEmpty()) {
				continue;
			}
			for (int j = i - 1; j >= 0; j--) {
				Compare c0 = sorted.get(j);
				if (c1.at().subtract(c0.at()) > COMPARE_WINDOW) {
					break;
				}
				if (tryPair(concat(c0.a(), c0.b()), tags, c1.at(), Method.COMPARE)) {
					break;
				}
			}
		}
	}

	private static List<Value> concat(List<Value> a, List<Value> b) {
		List<Value> l = new ArrayList<>(a);
		l.addAll(b);
		return l;
	}
}
