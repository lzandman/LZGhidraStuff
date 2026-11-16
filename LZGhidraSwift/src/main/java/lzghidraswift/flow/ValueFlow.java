// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.flow;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Forward value-set data flow over the p-code of one function. Each register, p-code temporary
 * and tracked memory slot holds up to {@link #MAX_VALUES} values; a value is a constant or a
 * symbol plus an offset (a register at entry, the result of an operation that is not tracked,
 * a merge). Constants remember the instruction that produced them.
 * <p>
 * An instruction with an internal conditional branch on an unknown condition (AArch64
 * {@code csel}) is run on both paths. Values that differ between the paths get a label (the
 * condition symbol and its value on that path), so that two {@code csel} on the same condition
 * keep their pairing: {@code x0 = "Flat"/"Sharp"} and {@code x1 = tag 4/tag 5} combine into two
 * strings, not four. Ghidra's {@code SymbolicPropogator} runs such an instruction as two flows
 * and visits the following instructions only once, which loses this pairing. Where blocks
 * merge, values that differ between predecessors are labelled with their predecessor in the same
 * way (a {@code switch} that returns a different string from each case).
 * <p>
 * Memory is tracked by base symbol and offset (stack slots, fields of an object whose address is
 * in a register). Calls clear the registers outside the calling convention's unaffected list and
 * the memory that is not on the stack.
 */
public final class ValueFlow {

	/**
	 * Values per register or slot; a merge of more keeps none. 16, not 8: x86_64 switches whose
	 * cases jump to one shared tail that sets the tag word merge 9 to 15 string words there. On a
	 * 5.4 MB arm64 app, 16 found 38 more strings than 8 for 2 % more finder time; 32 and 64 found
	 * none more.
	 */
	static final int MAX_VALUES = 16;
	private static final int WIDEN_AFTER = 8;
	/**
	 * Instructions run by the fixpoint iteration of one function before it stops and the final
	 * pass uses the states reached so far. The most seen in a 28 MB binary was 65,818
	 * (a 33 KB function, 0.7 s).
	 */
	public static final long MAX_INSTRUCTIONS = 300_000;

	/** What a {@link Sym} stands for; {@code a} and {@code b} mean different things per kind. */
	public enum SymKind {
		/** Register value at function entry: a = register offset, b = size. */
		ENTRY,
		/** Merge of too many values at a block start: a = block address, b = storage key. */
		PHI,
		/** Result of an operation that is not tracked: a = instruction address, b = op index. */
		OP,
		/** Result of a call: a = instruction address, b = register offset. */
		CALL,
		/** Result of a pure operation on single-valued inputs: a = value number. */
		NUMBERED,
		/** Label only: the predecessor a value came from at a merge, a = block address. */
		MERGE
	}

	/** A symbolic value; public because {@link Value} carries it. */
	public record Sym(SymKind kind, long a, long b) {}

	/**
	 * A constant ({@code sym == null}, value {@code k}) or {@code sym + k}. For a boolean symbol,
	 * {@code k} is 0 or 1 and means "sym xor k". {@code labels} describe the path that produced
	 * this value: a condition symbol maps to its value on that path (0 or 1), a {@link
	 * SymKind#MERGE} symbol to the predecessor block. Two values combine only if their labels
	 * agree.
	 */
	public record Value(long k, Sym sym, Address producer, Map<Sym, Long> labels) {
		public boolean isConst() {
			return sym == null;
		}

		Value withLabels(Map<Sym, Long> l) {
			return new Value(k, sym, producer, l);
		}
	}

	record MemKey(Sym base, long offset, int size) {}

	/** A storage location's values; equality ignores their order. */
	record Slot(int size, List<Value> values) {
		@Override
		public boolean equals(Object obj) {
			return obj instanceof Slot s && size == s.size && sameValues(values, s.values);
		}

		@Override
		public int hashCode() {
			return size * 31 + new HashSet<>(values).hashCode();
		}
	}

	static boolean sameValues(List<Value> a, List<Value> b) {
		if (a == null || b == null) {
			return a == null && b == null;
		}
		if (a.size() != b.size()) {
			return false;
		}
		return a.equals(b) || new HashSet<>(a).equals(new HashSet<>(b));
	}

	/** The union of two label maps, or null if they disagree on a condition. */
	public static Map<Sym, Long> joinLabels(Map<Sym, Long> a, Map<Sym, Long> b) {
		if (a.isEmpty()) {
			return b;
		}
		if (b.isEmpty()) {
			return a;
		}
		Map<Sym, Long> m = new HashMap<>(a);
		for (Map.Entry<Sym, Long> e : b.entrySet()) {
			Long old = m.put(e.getKey(), e.getValue());
			if (old != null && !old.equals(e.getValue())) {
				return null;
			}
		}
		return Map.copyOf(m);
	}

	/** Where a register value is used: a call, a tail branch or a return. */
	public enum UseKind {
		CALL, TAIL, RETURN
	}

	/** Receives the events of the final pass. */
	public interface Listener {
		void use(Instruction instr, UseKind kind, State state);

		void store(Instruction instr, List<Value> address, List<Value> values, int size);

		void compare(Instruction instr, List<Value> a, List<Value> b);

		/** A register that holds exactly one constant, produced by this instruction. */
		void constant(Instruction instr, Varnode register, Value value);
	}

	/** The register, temporary and memory values at one point of the walk. */
	public static final class State {
		final TreeMap<Long, Slot> regs;
		final HashMap<Long, Slot> uniques;
		final HashMap<MemKey, List<Value>> mem;
		Map<Sym, Long> pathLabels = Map.of();

		State() {
			regs = new TreeMap<>();
			uniques = new HashMap<>();
			mem = new HashMap<>();
		}

		State(State o) {
			regs = new TreeMap<>(o.regs);
			uniques = new HashMap<>(o.uniques);
			mem = new HashMap<>(o.mem);
			pathLabels = o.pathLabels;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof State s) || !regs.equals(s.regs) ||
				!mem.keySet().equals(s.mem.keySet())) {
				return false;
			}
			for (Map.Entry<MemKey, List<Value>> e : mem.entrySet()) {
				if (!sameValues(e.getValue(), s.mem.get(e.getKey()))) {
					return false;
				}
			}
			return true;
		}

		@Override
		public int hashCode() {
			return regs.hashCode() * 31 + mem.keySet().hashCode();
		}
	}

	private final Program program;
	private final Function function;
	private final AddressSetView body;
	private final ValueMerger merger = new ValueMerger();
	private final PcodeStep step;
	private final Map<Address, Integer> visits = new HashMap<>();
	private final Map<Address, State> lastIn = new HashMap<>();

	private boolean recording;
	private int iterations;
	private long instructionsRun;
	private boolean converged;

	public ValueFlow(Program program, Function function, Listener listener) {
		this.program = program;
		this.function = function;
		this.body = function.getBody();
		step = new PcodeStep(program, function, body, listener);
	}

	public int iterations() {
		return iterations;
	}

	/**
	 * Instructions run before the final pass: the work of the fixpoint iteration. Called by
	 * ProbeFlow (by reflection; see DevtoolsReflectionTest).
	 */
	long instructionsRun() {
		return instructionsRun;
	}

	public boolean converged() {
		return converged;
	}

	/** The values of register {@code r} in state {@code s}. */
	public List<Value> readRegister(State s, Register r) {
		return step.readRegister(s, r);
	}

	/**
	 * The values of the 8-byte stack slot at {@code offset} bytes above the current stack
	 * pointer, or an empty list if the stack pointer or the slot is not known.
	 */
	public List<Value> readStackWord(State s, long offset) {
		return step.readStackWord(s, offset);
	}

	// ---------------------------------------------------------------- driver

	/** Walks the function until the values stop changing or a limit is reached, reporting to the listener. */
	public void run(TaskMonitor monitor) throws CancelledException {
		BasicBlockModel model = new BasicBlockModel(program);
		Map<Address, CodeBlock> blocks = new TreeMap<>();
		CodeBlockIterator it = model.getCodeBlocksContaining(body, monitor);
		while (it.hasNext()) {
			CodeBlock b = it.next();
			blocks.put(b.getFirstStartAddress(), b);
		}
		Map<Address, List<Address>> succs = new HashMap<>();
		Map<Address, List<Address>> preds = new HashMap<>();
		for (CodeBlock b : blocks.values()) {
			List<Address> s = new ArrayList<>();
			CodeBlockReferenceIterator refs = b.getDestinations(monitor);
			while (refs.hasNext()) {
				CodeBlockReference ref = refs.next();
				if (ref.getFlowType().isCall()) {
					continue;
				}
				Address dest = ref.getDestinationAddress();
				if (blocks.containsKey(dest)) {
					s.add(dest);
					preds.computeIfAbsent(dest, k -> new ArrayList<>())
							.add(b.getFirstStartAddress());
				}
			}
			succs.put(b.getFirstStartAddress(), s);
		}
		Address entry = function.getEntryPoint();

		Map<Address, State> out = new HashMap<>();
		TreeSet<Address> work = new TreeSet<>(blocks.keySet());
		iterations = 0;
		instructionsRun = 0;
		while (!work.isEmpty() && instructionsRun < MAX_INSTRUCTIONS) {
			monitor.checkCancelled();
			Address a = work.pollFirst();
			if (!reached(a, entry, preds, out)) {
				continue; // queued again when a predecessor gets a state
			}
			iterations++;
			State s = runBlock(blocks.get(a), inState(a, entry, preds, out));
			if (!s.equals(out.get(a))) {
				out.put(a, s);
				work.addAll(succs.get(a));
			}
		}
		converged = work.isEmpty();

		recording = true;
		for (Address a : blocks.keySet()) {
			monitor.checkCancelled();
			runBlock(blocks.get(a), inState(a, entry, preds, out));
		}
		recording = false;
	}

	/**
	 * True if the block can run: it is the entry, it has no predecessor in the block model (a
	 * jump-table target; it starts from the empty state), or a predecessor has a state. A block
	 * whose predecessors have not run yet must wait: run on the empty state, a loop body that
	 * comes before its header in address order is its own only predecessor with a state, so it
	 * never meets a merge, is never widened, and steps a pointer (x3 + 16, + 32, ...) until the
	 * iteration limit (seen in 15 functions of a 28 MB binary).
	 */
	static boolean reached(Address block, Address entry, Map<Address, List<Address>> preds,
			Map<Address, State> out) {
		List<Address> p = preds.get(block);
		if (block.equals(entry) || p == null) {
			return true;
		}
		for (Address a : p) {
			if (out.containsKey(a)) {
				return true;
			}
		}
		return false;
	}

	private State inState(Address block, Address entry, Map<Address, List<Address>> preds,
			Map<Address, State> out) {
		List<State> ins = new ArrayList<>();
		List<Long> ids = new ArrayList<>();
		if (block.equals(entry)) {
			ins.add(new State());
			ids.add(-1L);
		}
		for (Address p : preds.getOrDefault(block, List.of())) {
			State s = out.get(p);
			if (s != null) {
				ins.add(s);
				ids.add(p.getOffset());
			}
		}
		if (ins.isEmpty()) {
			return new State();
		}
		if (ins.size() == 1) {
			return new State(ins.getFirst());
		}
		State m = merger.mergeAtBlock(ins, ids, block);
		if (!recording) {
			int n = visits.merge(block, 1, Integer::sum);
			State prev = lastIn.get(block);
			if (n > WIDEN_AFTER && prev != null) {
				merger.widenChanges(m, prev, block);
			}
			lastIn.put(block, m);
		}
		return m;
	}

	private State runBlock(CodeBlock block, State in) {
		State s = in;
		InstructionIterator it = program.getListing().getInstructions(block, true);
		while (it.hasNext()) {
			s = step.step(s, it.next(), recording);
			if (!recording) {
				instructionsRun++;
			}
		}
		return s;
	}
}
