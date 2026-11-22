// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.flow;

import static lzghidraswift.flow.ValueFlow.MAX_VALUES;
import static lzghidraswift.flow.ValueFlow.joinLabels;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehavior;
import ghidra.pcode.opbehavior.OpBehaviorFactory;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import lzghidraswift.abi.CallingConventions;
import lzghidraswift.flow.ValueFlow.Listener;
import lzghidraswift.flow.ValueFlow.MemKey;
import lzghidraswift.flow.ValueFlow.Slot;
import lzghidraswift.flow.ValueFlow.State;
import lzghidraswift.flow.ValueFlow.Sym;
import lzghidraswift.flow.ValueFlow.SymKind;
import lzghidraswift.flow.ValueFlow.UseKind;
import lzghidraswift.flow.ValueFlow.Value;

/**
 * Runs the p-code of one instruction on a {@link ValueFlow} state: the evaluation of the ops on
 * value sets, the paths of internal conditional branches, loads and stores to tracked memory,
 * and the effect of calls on registers and memory. In the final pass it reports the events to
 * the {@link Listener}.
 */
final class PcodeStep {

	private static final int MAX_PATHS = 16;
	private static final int MAX_COMBINATIONS = 64;
	private static final int REGISTER_LOOKBACK = 64;
	/** P-code ops run for one instruction, over all its paths; a safety limit. */
	private static final int MAX_STEP_OPS = 4096;

	/** Next p-code index from {@link #conditionalBranch}: stop the path here. */
	private static final int STOP = -1;
	/** Next p-code index from {@link #conditionalBranch}: the path is infeasible. */
	private static final int DEAD = -2;

	private record Path(State state, int index) {}

	private final AddressSetView body;
	private final Listener listener;
	private final long spOffset;
	private final Sym spEntry;
	private final int extrapop;
	private final List<Varnode> unaffected = new ArrayList<>();
	private final List<Register> volatileRegs = new ArrayList<>();
	private final List<Register> pointerRegs;
	private final Map<List<Object>, Long> valueNumbers = new HashMap<>();
	private final Booleans booleans = new Booleans(this::number);

	private Instruction cur;
	private boolean recording;
	private boolean compareRecorded;
	/** Paths and p-code ops of the current {@link #step}, against MAX_PATHS and MAX_STEP_OPS. */
	private int stepPaths;
	private int stepOps;

	PcodeStep(Program program, Function function, AddressSetView body, Listener listener) {
		this.body = body;
		this.listener = listener;
		Register sp = program.getCompilerSpec().getStackPointer();
		spOffset = sp.getOffset();
		spEntry = new Sym(SymKind.ENTRY, spOffset, sp.getMinimumByteSize());
		PrototypeModel cc = function.getCallingConvention();
		if (cc == null) {
			cc = program.getCompilerSpec().getDefaultCallingConvention();
		}
		int pop = cc.getExtrapop();
		extrapop = pop == PrototypeModel.UNKNOWN_EXTRAPOP ? 0 : pop;
		// The registers a call preserves are the platform's, not this function's: Ghidra 12.2's
		// __swift_thiscall (AArch64) leaves out x20 (its self input), so a function typed so lost
		// x20 at every call, also where x20 held the address of an inout stack variable. The
		// default convention (__cdecl on AArch64, __stdcall on x86_64) has x19 to x30, or RBX,
		// RBP and R12 to R15.
		for (Varnode v : program.getCompilerSpec()
				.getDefaultCallingConvention()
				.getUnaffectedList()) {
			if (v.isRegister()) {
				unaffected.add(v);
			}
		}
		pointerRegs = CallingConventions.pointerRegisters(program);
		for (String name : CallingConventions.volatileRegisters(program)) {
			Register r = program.getRegister(name);
			if (r != null) {
				volatileRegs.add(r);
			}
		}
	}

	// ---------------------------------------------------------------- one instruction

	/**
	 * The state after {@code instr}. With {@code record}, the final pass: report uses, stores,
	 * compares and constants to the listener.
	 */
	State step(State in, Instruction instr, boolean record) {
		cur = instr;
		recording = record;
		compareRecorded = false;
		PcodeOp[] ops = instr.getPcode();
		Set<Varnode> written = new LinkedHashSet<>();
		List<State> done = new ArrayList<>();
		Deque<Path> todo = new ArrayDeque<>();
		State start = new State(in);
		start.pathLabels = Map.of();
		todo.push(new Path(start, 0));
		stepPaths = 1;
		stepOps = 0;
		while (!todo.isEmpty()) {
			State end = runPath(todo.pop(), ops, todo, written);
			if (end != null) {
				done.add(end);
			}
		}
		if (done.isEmpty()) {
			done.add(new State(in));
		}
		State outState = ValueMerger.mergePaths(done, instr.getAddress());
		outState.uniques.clear();
		if (recording) {
			reportConstants(instr, outState, written);
		}
		return outState;
	}

	/**
	 * Runs one path through the instruction's p-code from its index to the end, pushing the
	 * taken side of each conditional branch it cannot decide. The end state, or null if the
	 * path's labels contradict.
	 */
	private State runPath(Path p, PcodeOp[] ops, Deque<Path> todo, Set<Varnode> written) {
		State s = p.state();
		int i = p.index();
		while (i < ops.length && ++stepOps <= MAX_STEP_OPS) {
			PcodeOp op = ops[i];
			int opc = op.getOpcode();
			if (opc == PcodeOp.BRANCH && op.getInput(0).isConstant()) {
				int rel = relativeTarget(op.getInput(0));
				if (rel <= 0) {
					break; // internal loop (x86 tzcnt, bsf): stop this path
				}
				i += rel;
			}
			else if (opc == PcodeOp.CBRANCH &&
				(op.getInput(0).isConstant() || skipsRest(op.getInput(0)))) {
				int rel = op.getInput(0).isConstant() ? relativeTarget(op.getInput(0))
						: ops.length - i;
				i = conditionalBranch(s, op, i, rel, todo);
				if (i == DEAD) {
					return null;
				}
				if (i == STOP) {
					break;
				}
			}
			else {
				execute(s, op, i, written);
				i++;
			}
		}
		return s;
	}

	/**
	 * An internal conditional branch at p-code index {@code i}: follows a known condition, else
	 * pushes the taken side (with the condition's label) and continues with the other. Returns
	 * the next index, {@link #STOP} or {@link #DEAD}. {@code rel} is the target relative to
	 * {@code i}.
	 */
	private int conditionalBranch(State s, PcodeOp op, int i, int rel, Deque<Path> todo) {
		List<Value> cond = read(s, op.getInput(1));
		Boolean known = constantTruth(cond);
		if (known != null) {
			if (known && rel <= 0) {
				return STOP;
			}
			return known ? i + rel : i + 1;
		}
		if (rel <= 0 || stepPaths >= MAX_PATHS) {
			return i + 1;
		}
		State taken = new State(s);
		Value c = cond.size() == 1 ? cond.getFirst() : null;
		if (c == null || c.isConst()) {
			todo.push(new Path(taken, i + rel));
			stepPaths++;
			return i + 1;
		}
		boolean symTrue = c.k() == 0; // condition true <=> sym == !k
		Map<Sym, Long> lt = joinLabels(s.pathLabels, Map.of(c.sym(), symTrue ? 1L : 0L));
		Map<Sym, Long> lf = joinLabels(s.pathLabels, Map.of(c.sym(), symTrue ? 0L : 1L));
		if (lt != null) {
			taken.pathLabels = lt;
			todo.push(new Path(taken, i + rel));
			stepPaths++;
		}
		if (lf == null) {
			return DEAD;
		}
		s.pathLabels = lf;
		return i + 1;
	}

	/**
	 * True if a branch to {@code target} skips the rest of the current instruction's p-code: x86
	 * {@code cmov} branches to the next instruction's address ({@code CBRANCH (ram, next)}) when
	 * the condition fails. Its two paths are run like those of AArch64 {@code csel}.
	 */
	private boolean skipsRest(Varnode target) {
		return target.isAddress() && target.getAddress().equals(cur.getMaxAddress().next());
	}

	/** Reports each register that {@code instr} set to a single constant it produced. */
	private void reportConstants(Instruction instr, State outState, Set<Varnode> written) {
		for (Varnode w : written) {
			Slot slot = outState.regs.get(w.getOffset());
			if (slot == null || slot.size() != w.getSize() || slot.values().size() != 1) {
				continue;
			}
			Value v = slot.values().getFirst();
			if (v.isConst() && instr.getAddress().equals(v.producer())) {
				listener.constant(instr, w, v);
			}
		}
	}

	/**
	 * The p-code-relative target of an internal branch. Sleigh masks the offset to the size of
	 * the constant varnode ({@code PcodeEmitObjects.resolveRelatives}), so a backward branch
	 * reads as a large positive number unless it is sign-extended from that size.
	 */
	static int relativeTarget(Varnode target) {
		int bits = 8 * Math.min(target.getSize(), 8);
		long v = target.getOffset();
		return (int) (bits >= 64 ? v : (v << (64 - bits)) >> (64 - bits));
	}

	/**
	 * True if an indirect branch with the flows {@code flows} may leave the function. A switch
	 * jump whose targets Ghidra recovered (every flow inside {@code body}) does not, so its
	 * registers are no arguments: on x86_64, {@code leaq table(%rip), %rsi} before
	 * {@code jmpq *%rcx} paired the table address with a tag word in rdx as a string.
	 */
	static boolean indirectLeaves(Address[] flows, AddressSetView body) {
		if (flows.length == 0) {
			return true;
		}
		for (Address a : flows) {
			if (!body.contains(a)) {
				return true;
			}
		}
		return false;
	}

	private static Boolean constantTruth(List<Value> cond) {
		Boolean truth = null;
		for (Value v : cond) {
			if (!v.isConst()) {
				return null;
			}
			boolean t = v.k() != 0;
			if (truth != null && truth != t) {
				return null;
			}
			truth = t;
		}
		return truth;
	}

	private Value fresh(long index) {
		return new Value(0, new Sym(SymKind.OP, cur.getAddress().getOffset(), index), null,
			Map.of());
	}

	private void execute(State s, PcodeOp op, int index, Set<Varnode> written) {
		int opc = op.getOpcode();
		Varnode out = op.getOutput();
		switch (opc) {
			case PcodeOp.BRANCH, PcodeOp.BRANCHIND -> {
				Varnode target = op.getInput(0);
				boolean leaves = opc == PcodeOp.BRANCHIND ? indirectLeaves(cur.getFlows(), body)
						: !target.isAddress() || !body.contains(target.getAddress());
				if (leaves && recording) {
					listener.use(cur, UseKind.TAIL, s);
				}
			}
			case PcodeOp.CBRANCH -> {
				// branch out of the instruction: the CFG follows it
			}
			case PcodeOp.CALL, PcodeOp.CALLIND -> {
				if (recording) {
					listener.use(cur, UseKind.CALL, s);
				}
				applyCall(s);
			}
			case PcodeOp.RETURN -> {
				if (recording) {
					listener.use(cur, UseKind.RETURN, s);
				}
			}
			case PcodeOp.LOAD -> load(s, op, index, written);
			case PcodeOp.STORE -> store(s, op);
			case PcodeOp.CALLOTHER -> {
				if (out != null) {
					write(s, out, List.of(fresh(index)), written);
				}
			}
			default -> {
				if (out == null) {
					return;
				}
				recordCompare(s, op);
				write(s, out, evaluate(s, op, index), written);
			}
		}
	}

	private void recordCompare(State s, PcodeOp op) {
		if (!recording || compareRecorded || op.getNumInputs() != 2 ||
			op.getInput(0).getSize() != 8) {
			return;
		}
		switch (op.getOpcode()) {
			case PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL, PcodeOp.INT_SBORROW, PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY -> {
				String m = cur.getMnemonicString().toLowerCase(Locale.ROOT);
				if (m.equals("cmp") || m.equals("subs") || m.equals("cmn") || m.equals("ccmp") ||
					m.equals("ccmn")) {
					compareRecorded = true;
					listener.compare(cur, read(s, op.getInput(0)), read(s, op.getInput(1)));
				}
			}
			case PcodeOp.INT_XOR -> {
				// x86_64 compares a string with a literal word by word: xorq w0, a; xorq tag, b;
				// orq a, b; je.
				if (cur.getMnemonicString().equalsIgnoreCase("xor")) {
					compareRecorded = true;
					listener.compare(cur, read(s, op.getInput(0)), read(s, op.getInput(1)));
				}
			}
			default -> {
			}
		}
	}

	// ---------------------------------------------------------------- memory

	private void load(State s, PcodeOp op, int index, Set<Varnode> written) {
		Varnode out = op.getOutput();
		Value addr = singleAddress(read(s, op.getInput(1)));
		List<Value> m = addr != null ? s.mem.get(memKey(addr, out.getSize())) : null;
		write(s, out, m != null ? m : List.of(fresh(index)), written);
	}

	/**
	 * A store to a known address replaces the slots it overlaps; to an unknown address it
	 * forgets all memory but the stack.
	 */
	private void store(State s, PcodeOp op) {
		List<Value> addr = read(s, op.getInput(1));
		List<Value> vals = read(s, op.getInput(2));
		int size = op.getInput(2).getSize();
		if (recording) {
			listener.store(cur, addr, vals, size);
		}
		Value single = singleAddress(addr);
		if (single == null) {
			s.mem.keySet().removeIf(k -> !spEntry.equals(k.base()));
			return;
		}
		MemKey key = memKey(single, size);
		s.mem.keySet()
				.removeIf(k -> Objects.equals(k.base(), key.base()) &&
					k.offset() < key.offset() + size && key.offset() < k.offset() + k.size());
		s.mem.put(key, vals);
	}

	/** The address if all values agree on it (they may differ in labels only), else null. */
	static Value singleAddress(List<Value> addr) {
		if (addr.isEmpty()) {
			return null;
		}
		Value a = addr.getFirst();
		for (Value v : addr) {
			if (!Objects.equals(v.sym(), a.sym()) || v.k() != a.k()) {
				return null;
			}
		}
		return a;
	}

	private static MemKey memKey(Value addr, int size) {
		return new MemKey(addr.sym(), addr.k(), size);
	}

	// ---------------------------------------------------------------- calls

	private void applyCall(State s) {
		Address at = cur.getAddress();
		forgetEscapedStack(s);
		List<Long> kill = new ArrayList<>();
		for (Map.Entry<Long, Slot> e : s.regs.entrySet()) {
			long off = e.getKey();
			int size = e.getValue().size();
			if (off == spOffset || preserved(off, size)) {
				continue;
			}
			kill.add(off);
		}
		for (Long off : kill) {
			Slot old = s.regs.get(off);
			s.regs.put(off, new Slot(old.size(),
				List.of(new Value(0, new Sym(SymKind.CALL, at.getOffset(), off), null, Map.of()))));
		}
		for (Register r : volatileRegs) {
			writeReg(s, r.getOffset(), r.getMinimumByteSize(), List.of(
				new Value(0, new Sym(SymKind.CALL, at.getOffset(), r.getOffset()), null,
					Map.of())));
		}
		s.mem.keySet().removeIf(k -> !spEntry.equals(k.base()));
		if (extrapop != 0) {
			Slot sp = s.regs.get(spOffset);
			List<Value> vals = sp != null ? sp.values()
					: List.of(new Value(0, spEntry, null, Map.of()));
			List<Value> moved = new ArrayList<>();
			for (Value v : vals) {
				moved.add(new Value(v.k() + extrapop, v.sym(), v.producer(), v.labels()));
			}
			writeReg(s, spOffset, (int) spEntry.b(), moved);
		}
	}

	/**
	 * A callee may write the stack memory whose address it receives in a register (an inout
	 * {@code self} in x20, an indirect result in x8): forget every stack slot from the lowest
	 * such address up. Without this, {@code String.append} on a stack variable left the old
	 * words in the slot, and a later spill paired them with an unrelated word 0.
	 */
	private void forgetEscapedStack(State s) {
		long lowest = Long.MAX_VALUE;
		for (Register r : pointerRegs) {
			for (Value v : readRegister(s, r)) {
				if (spEntry.equals(v.sym())) {
					lowest = Math.min(lowest, v.k());
				}
			}
		}
		if (lowest != Long.MAX_VALUE) {
			long from = lowest;
			s.mem.keySet().removeIf(k -> spEntry.equals(k.base()) && k.offset() + k.size() > from);
		}
	}

	private boolean preserved(long off, int size) {
		for (Varnode v : unaffected) {
			if (v.getOffset() <= off && off + size <= v.getOffset() + v.getSize()) {
				return true;
			}
		}
		return false;
	}

	// ---------------------------------------------------------------- values

	List<Value> readRegister(State s, Register r) {
		return readReg(s, r.getOffset(), r.getMinimumByteSize());
	}

	/**
	 * The values of the 8-byte stack slot at {@code offset} bytes above the current stack
	 * pointer, or an empty list if the stack pointer or the slot is not known.
	 */
	List<Value> readStackWord(State s, long offset) {
		Value sp = singleAddress(readReg(s, spOffset, (int) spEntry.b()));
		if (sp == null) {
			return List.of();
		}
		List<Value> m = s.mem.get(new MemKey(sp.sym(), sp.k() + offset, 8));
		return m != null ? m : List.of();
	}

	private List<Value> read(State s, Varnode vn) {
		if (vn.isConstant()) {
			return List.of(new Value(vn.getOffset() & mask(vn.getSize()), null,
				cur != null ? cur.getAddress() : null, Map.of()));
		}
		if (vn.isRegister()) {
			return readReg(s, vn.getOffset(), vn.getSize());
		}
		if (vn.isUnique()) {
			Slot slot = s.uniques.get(vn.getOffset());
			if (slot != null) {
				return slot.values();
			}
			return List.of(fresh(-1000 - vn.getOffset()));
		}
		if (vn.isAddress()) {
			List<Value> m = s.mem.get(new MemKey(null, vn.getOffset(), vn.getSize()));
			if (m != null) {
				return m;
			}
		}
		return List.of(fresh(-3000 - vn.getOffset()));
	}

	private List<Value> readReg(State s, long off, int size) {
		Slot exact = s.regs.get(off);
		if (exact != null && exact.size() == size) {
			return exact.values();
		}
		Map.Entry<Long, Slot> covering = coveringSlot(s, off, size);
		if (covering != null) {
			return extract(covering.getKey(), covering.getValue(), off, size);
		}
		// a smaller slot inside the requested range is not combined: treat as unknown
		if (exact != null || hasOverlap(s, off, size)) {
			return List.of(fresh(-2000 - off));
		}
		return List.of(new Value(0, new Sym(SymKind.ENTRY, off, size), null, Map.of()));
	}

	/** The nearest slot at or below {@code off} that covers the whole range, or null. */
	private static Map.Entry<Long, Slot> coveringSlot(State s, long off, int size) {
		Map.Entry<Long, Slot> e = s.regs.subMap(off - REGISTER_LOOKBACK, true, off, true)
				.descendingMap()
				.entrySet()
				.stream()
				.filter(x -> x.getKey() + x.getValue().size() > off)
				.findFirst()
				.orElse(null);
		if (e == null || e.getKey() + e.getValue().size() < off + size) {
			return null; // none, or a partial overlap
		}
		return e;
	}

	/** The bytes {@code off .. off + size} of the constants in the slot at {@code eoff}. */
	private List<Value> extract(long eoff, Slot slot, long off, int size) {
		int shift = (int) (off - eoff) * 8;
		if (shift == 0 && slot.values().size() == 1 && !slot.values().getFirst().isConst()) {
			return List.of(lowBytes(slot.values().getFirst(), size));
		}
		List<Value> result = new ArrayList<>();
		for (Value v : slot.values()) {
			if (!v.isConst()) {
				return List.of(fresh(-2000 - off));
			}
			long k = (v.k() >>> shift) & mask(size);
			result.add(new Value(k, null, v.producer(), v.labels()));
		}
		return dedupe(result);
	}

	/**
	 * The low {@code size} bytes of the symbolic value {@code v}: a boolean itself, else one
	 * value-numbered symbol for every read of them, so that {@code testb $1, %r14b} and a later
	 * {@code notb %r14b} see the same bit 0.
	 */
	private Value lowBytes(Value v, int size) {
		if (booleans.isBoolean(v)) {
			return v;
		}
		Sym low = number(List.of("low", v.sym(), v.k(), size));
		booleans.truncated(low, v);
		return new Value(0, low, null, v.labels());
	}

	private static boolean hasOverlap(State s, long off, int size) {
		for (Map.Entry<Long, Slot> e : s.regs.subMap(off - REGISTER_LOOKBACK, true, off + size,
			false).entrySet()) {
			if (e.getKey() + e.getValue().size() > off) {
				return true;
			}
		}
		return false;
	}

	private void write(State s, Varnode out, List<Value> vals, Set<Varnode> written) {
		if (out.isRegister()) {
			if (!writePart(s, out, vals)) {
				writeReg(s, out.getOffset(), out.getSize(), vals);
			}
			written.add(out);
		}
		else if (out.isUnique()) {
			s.uniques.put(out.getOffset(), new Slot(out.getSize(), vals));
		}
		else if (out.isAddress()) {
			s.mem.put(new MemKey(null, out.getOffset(), out.getSize()), vals);
		}
	}

	/**
	 * Writes constants (or a boolean, split into its two) into part of a larger register slot that
	 * holds constants, keeping the other bytes: {@code xorl %ebx, %ebx; setne %bl} leaves RBX
	 * 0 or 1. Returns false, writing nothing, if the write is not such a part.
	 */
	private boolean writePart(State s, Varnode out, List<Value> vals) {
		long off = out.getOffset();
		int size = out.getSize();
		Map.Entry<Long, Slot> cover = coveringSlot(s, off, size);
		if (cover == null || cover.getValue().size() <= size ||
			!cover.getValue().values().stream().allMatch(Value::isConst)) {
			return false;
		}
		List<Value> parts = vals.size() == 1 && booleans.isBoolean(vals.getFirst())
				? Booleans.split(vals.getFirst(), cur.getAddress())
				: vals;
		if (!parts.stream().allMatch(Value::isConst)) {
			return false;
		}
		int shift = (int) (off - cover.getKey()) * 8;
		long partMask = mask(size) << shift;
		List<Value> result = new ArrayList<>();
		for (Value whole : cover.getValue().values()) {
			for (Value part : parts) {
				Map<Sym, Long> l = joinLabels(whole.labels(), part.labels());
				if (l != null) {
					long k = (whole.k() & ~partMask) | ((part.k() << shift) & partMask);
					result.add(new Value(k & mask(cover.getValue().size()), null, cur.getAddress(),
						l));
				}
			}
		}
		if (result.isEmpty() || result.size() > MAX_VALUES) {
			return false;
		}
		writeReg(s, cover.getKey(), cover.getValue().size(), dedupe(result));
		return true;
	}

	private static void writeReg(State s, long off, int size, List<Value> vals) {
		s.regs.subMap(off - REGISTER_LOOKBACK, true, off + size, false)
				.entrySet()
				.removeIf(e -> e.getKey() + e.getValue().size() > off);
		s.regs.put(off, new Slot(size, vals));
	}

	static long mask(int size) {
		return size >= 8 ? -1L : (1L << (8 * size)) - 1;
	}

	private static List<Value> dedupe(List<Value> vals) {
		if (vals.size() <= 1) {
			return vals;
		}
		return List.copyOf(new LinkedHashSet<>(vals));
	}

	// ---------------------------------------------------------------- operations

	private List<Value> evaluate(State s, PcodeOp op, int index) {
		if (op.getOpcode() == PcodeOp.COPY) {
			return read(s, op.getInput(0));
		}
		OpBehavior behavior = OpBehaviorFactory.getOpBehavior(op.getOpcode());
		int n = op.getNumInputs();
		if (n == 1 && behavior instanceof UnaryOpBehavior unary) {
			return evaluateUnary(s, op, index, unary);
		}
		if (n == 2 && behavior instanceof BinaryOpBehavior binary) {
			return evaluateBinary(s, op, index, binary);
		}
		return numbered(op, s, index);
	}

	private List<Value> evaluateUnary(State s, PcodeOp op, int index, UnaryOpBehavior unary) {
		int outSize = op.getOutput().getSize();
		Varnode in0 = op.getInput(0);
		List<Value> in = read(s, in0);
		if (in.size() == 1 && booleans.isBoolean(in.getFirst()) &&
			op.getOpcode() != PcodeOp.BOOL_NEGATE) {
			if (Booleans.keeps(op.getOpcode())) {
				return in;
			}
			in = Booleans.split(in.getFirst(), cur.getAddress()); // not, neg of a 0/1
		}
		List<Value> result = new ArrayList<>();
		for (Value v : in) {
			if (v.isConst()) {
				long r = unary.evaluateUnary(outSize, in0.getSize(), v.k()) & mask(outSize);
				result.add(new Value(r, null, r == v.k() ? v.producer() : cur.getAddress(),
					v.labels()));
			}
			else if (op.getOpcode() == PcodeOp.BOOL_NEGATE) {
				result.add(new Value(v.k() ^ 1, v.sym(), null, v.labels()));
			}
			else {
				return numbered(op, s, index);
			}
		}
		return limit(dedupe(result), index);
	}

	/** Every pair of input values whose labels agree, as long as they are few. */
	private List<Value> evaluateBinary(State s, PcodeOp op, int index, BinaryOpBehavior binary) {
		int outSize = op.getOutput().getSize();
		Varnode in0 = op.getInput(0);
		Varnode in1 = op.getInput(1);
		if ((op.getOpcode() == PcodeOp.INT_XOR || op.getOpcode() == PcodeOp.INT_SUB) &&
			in0.equals(in1)) {
			return List.of(new Value(0, null, cur.getAddress(), Map.of())); // xorl %ebx, %ebx
		}
		List<Value> a = read(s, in0);
		List<Value> b = read(s, in1);
		Value bool = booleanResult(op.getOpcode(), a, b);
		if (bool != null) {
			return List.of(bool);
		}
		a = splitBoolean(a, b);
		b = splitBoolean(b, a);
		if (a.size() * b.size() > MAX_COMBINATIONS) {
			return List.of(fresh(index));
		}
		List<Value> result = new ArrayList<>();
		for (Value x : a) {
			for (Value y : b) {
				Map<Sym, Long> l = joinLabels(x.labels(), y.labels());
				if (l == null) {
					continue;
				}
				Value r = binary(binary, op.getOpcode(), outSize, in0.getSize(), x, y, l, in0, in1);
				if (r == null) {
					return numbered(op, s, index);
				}
				result.add(r);
			}
		}
		if (result.isEmpty()) {
			return List.of(fresh(index));
		}
		return limit(dedupe(result), index);
	}

	/**
	 * The boolean result of a binary op on one single value and one constant, or null: bit 0 of
	 * a symbol ({@code x & 1}), or a boolean compared with or masked by a constant that gives
	 * the boolean or its negation ({@code ZF = (b & 1) == 0}).
	 */
	private Value booleanResult(int opcode, List<Value> a, List<Value> b) {
		if (a.size() != 1 || b.size() != 1) {
			return null;
		}
		Value x = a.getFirst().isConst() ? b.getFirst() : a.getFirst();
		Value c = a.getFirst().isConst() ? a.getFirst() : b.getFirst();
		if (x.isConst() || !c.isConst() || joinLabels(x.labels(), c.labels()) == null) {
			return null;
		}
		if (booleans.isBoolean(x)) {
			return Booleans.withConstant(opcode, x, c.k());
		}
		return opcode == PcodeOp.INT_AND && c.k() == 1 ? booleans.bit0(x) : null;
	}

	/**
	 * {@code vals}, or the two constants of the boolean if {@code vals} is one boolean and
	 * {@code other} holds constants only: {@code orq $-0x1c, %rbx} on the 0 or 1 of a
	 * {@code setne} gives two tag words.
	 */
	private List<Value> splitBoolean(List<Value> vals, List<Value> other) {
		if (vals.size() != 1 || !booleans.isBoolean(vals.getFirst()) ||
			!other.stream().allMatch(Value::isConst)) {
			return vals;
		}
		return Booleans.split(vals.getFirst(), cur.getAddress());
	}

	/**
	 * The symbol for a pure operation whose result is not tracked. If every input has a single
	 * value, equal operations on equal inputs get the same symbol (value numbering), wherever
	 * they are. This matters for conditions such as AArch64 {@code gt}, which the p-code of each
	 * {@code csel} computes anew from the flags: {@code csel x0, ..., gt} and
	 * {@code csel x1, ..., gt} then branch on the same symbol and keep their pairing.
	 */
	private List<Value> numbered(PcodeOp op, State s, int index) {
		List<Object> key = new ArrayList<>();
		key.add(op.getOpcode());
		key.add(op.getOutput().getSize());
		Map<Sym, Long> labels = Map.of();
		List<Value> inputs = new ArrayList<>();
		for (Varnode in : op.getInputs()) {
			List<Value> vals = read(s, in);
			if (vals.size() != 1) {
				return List.of(fresh(index));
			}
			Value v = vals.getFirst();
			labels = joinLabels(labels, v.labels());
			if (labels == null) {
				return List.of(fresh(index));
			}
			key.add(in.getSize());
			key.add(v.sym() != null ? v.sym() : "const");
			key.add(v.k());
			inputs.add(v);
		}
		Sym sym = number(key);
		booleans.numbered(op.getOpcode(), op.getOutput().getSize(), sym, inputs);
		return List.of(new Value(0, sym, null, labels));
	}

	/** The value-numbered symbol of {@code key}: the same for equal keys within the function. */
	private Sym number(List<Object> key) {
		long id = valueNumbers.computeIfAbsent(key, k -> (long) valueNumbers.size());
		return new Sym(SymKind.NUMBERED, id, 0);
	}

	private List<Value> limit(List<Value> vals, int index) {
		return vals.size() > MAX_VALUES ? List.of(fresh(index)) : vals;
	}

	private Value binary(BinaryOpBehavior behavior, int opc, int outSize, int inSize, Value x,
			Value y, Map<Sym, Long> labels, Varnode in0, Varnode in1) {
		if (x.isConst() && y.isConst()) {
			long r;
			try {
				r = behavior.evaluateBinary(outSize, inSize, x.k(), y.k()) & mask(outSize);
			}
			// Ghidra's op behaviors throw LowlevelError (division by 0), AssertException (sizes)
			// and the float formats' unchecked exceptions: the result is then unknown.
			catch (RuntimeException e) { // NOPMD AvoidCatchingGenericException
				return null;
			}
			Address producer = cur.getAddress();
			if (r == x.k() && !in0.isConstant()) {
				producer = x.producer();
			}
			else if (r == y.k() && !in1.isConstant()) {
				producer = y.producer();
			}
			return new Value(r, null, producer, labels);
		}
		if (opc == PcodeOp.INT_ADD && !x.isConst() && y.isConst()) {
			return new Value(x.k() + y.k(), x.sym(), null, labels);
		}
		if (opc == PcodeOp.INT_ADD && x.isConst() && !y.isConst()) {
			return new Value(x.k() + y.k(), y.sym(), null, labels);
		}
		if (opc == PcodeOp.INT_SUB && !x.isConst() && y.isConst()) {
			return new Value(x.k() - y.k(), x.sym(), null, labels);
		}
		if (opc == PcodeOp.INT_MULT && !x.isConst() && y.isConst() && y.k() == 1) {
			return x.withLabels(labels); // x86 index register with scale 1
		}
		if (opc == PcodeOp.INT_ADD && !x.isConst() && !y.isConst()) {
			return new Value(x.k() + y.k(), symbolSum(x.sym(), y.sym()), null, labels);
		}
		return null;
	}

	/**
	 * One symbol for the sum of two symbols, whatever their order. x86 addresses such as
	 * {@code [RAX + RCX*1]} and {@code [RAX + RCX*1 + 8]} are computed as {@code RAX + RCX} and
	 * {@code (8 + RAX) + RCX}; both must have the same base for the store pairing.
	 */
	private Sym symbolSum(Sym a, Sym b) {
		Comparator<Sym> order = Comparator.comparing(Sym::kind)
				.thenComparingLong(Sym::a)
				.thenComparingLong(Sym::b);
		return number(order.compare(a, b) <= 0 ? List.of("sum", a, b) : List.of("sum", b, a));
	}
}
