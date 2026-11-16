// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.flow;

import static lzghidraswift.flow.ValueFlow.MAX_VALUES;
import static lzghidraswift.flow.ValueFlow.joinLabels;
import static lzghidraswift.flow.ValueFlow.sameValues;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

import ghidra.program.model.address.Address;
import lzghidraswift.flow.ValueFlow.MemKey;
import lzghidraswift.flow.ValueFlow.Slot;
import lzghidraswift.flow.ValueFlow.State;
import lzghidraswift.flow.ValueFlow.Sym;
import lzghidraswift.flow.ValueFlow.SymKind;
import lzghidraswift.flow.ValueFlow.Value;

/**
 * The merges of {@link ValueFlow}: of the end states of a block's predecessors at the block
 * start, and of the end states of the paths through one instruction. Values that differ get a
 * label (the predecessor, or the path's condition values), so that values of different registers
 * stay paired. Holds the storage locations widened for good, per merge block.
 */
final class ValueMerger {

	private static final int MAX_LABELS = 12;

	private final Set<List<Object>> widened = new HashSet<>();

	// ---------------------------------------------------------------- block starts

	private static Value phi(Address block, long key) {
		return new Value(0, new Sym(SymKind.PHI, block.getOffset(), key), null, Map.of());
	}

	/**
	 * After {@code ValueFlow.WIDEN_AFTER} visits of a merge block, every register that still
	 * changes becomes a phi value and every memory slot that still changes is dropped, for good.
	 * This bounds the iteration in loops whose value sets do not settle.
	 */
	void widenChanges(State m, State prev, Address block) {
		Set<Long> keys = new TreeSet<>(m.regs.keySet());
		keys.addAll(prev.regs.keySet());
		for (Long off : keys) {
			Slot now = m.regs.get(off);
			if (!Objects.equals(now, prev.regs.get(off))) {
				widened.add(List.of(block, "r", off));
				int size = now != null ? now.size() : prev.regs.get(off).size();
				m.regs.put(off, new Slot(size, List.of(phi(block, off))));
			}
		}
		Iterator<Map.Entry<MemKey, List<Value>>> it = m.mem.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry<MemKey, List<Value>> e = it.next();
			if (!sameValues(e.getValue(), prev.mem.get(e.getKey()))) {
				widened.add(List.of(block, "m", e.getKey()));
				it.remove();
			}
		}
	}

	/**
	 * Labels a value with the predecessor it came from, so that values of different registers
	 * that came from the same predecessor stay paired after the merge. A label of the same merge
	 * from an earlier loop iteration is replaced. Values with too many labels lose the merge
	 * labels instead of growing without bound. Symbols are not labelled.
	 */
	private static Value mergeLabel(Value v, Sym mergeSym, long predId) {
		if (!v.isConst()) {
			return v; // symbols are addresses and conditions; only constants need pairing
		}
		Map<Sym, Long> l = new HashMap<>(v.labels());
		l.put(mergeSym, predId);
		if (l.size() > MAX_LABELS) {
			l.keySet().removeIf(s -> s.kind() == SymKind.MERGE);
		}
		return v.withLabels(Map.copyOf(l));
	}

	/**
	 * Merges the end states of a block's predecessors. {@code predIds} identifies each
	 * predecessor (its block address, or -1 for the function entry).
	 */
	State mergeAtBlock(List<State> ins, List<Long> predIds, Address block) {
		Sym mergeSym = new Sym(SymKind.MERGE, block.getOffset(), 0);
		State m = new State();
		Set<Long> keys = new TreeSet<>();
		for (State s : ins) {
			keys.addAll(s.regs.keySet());
		}
		for (Long off : keys) {
			m.regs.put(off, mergeRegAtBlock(ins, predIds, block, mergeSym, off));
		}
		for (MemKey key : ins.getFirst().mem.keySet()) {
			List<Value> vals = mergeMemAtBlock(ins, predIds, block, mergeSym, key);
			if (vals != null) {
				m.mem.put(key, vals);
			}
		}
		return m;
	}

	/** The merged register slot at {@code off}; widened to a phi if sizes or values diverge. */
	private Slot mergeRegAtBlock(List<State> ins, List<Long> predIds, Address block, Sym mergeSym,
			Long off) {
		List<Slot> slots = new ArrayList<>();
		int size = -1;
		boolean sameSize = true;
		for (State s : ins) {
			Slot slot = s.regs.get(off);
			slots.add(slot);
			if (slot == null) {
				continue;
			}
			if (size < 0) {
				size = slot.size();
			}
			else if (size != slot.size()) {
				sameSize = false;
			}
		}
		List<Object> wkey = List.of(block, "r", off);
		Slot first = slots.getFirst();
		boolean allEqual = slots.stream().allMatch(x -> Objects.equals(x, first));
		if (allEqual && !widened.contains(wkey)) {
			return first;
		}
		if (!sameSize || widened.contains(wkey)) {
			widened.add(wkey);
			return new Slot(Math.max(size, 1), List.of(phi(block, off)));
		}
		LinkedHashSet<Value> union = new LinkedHashSet<>();
		for (int i = 0; i < slots.size(); i++) {
			Slot slot = slots.get(i);
			List<Value> vals = slot != null ? slot.values()
					: List.of(new Value(0, new Sym(SymKind.ENTRY, off, size), null, Map.of()));
			for (Value v : vals) {
				union.add(mergeLabel(v, mergeSym, predIds.get(i)));
			}
		}
		if (union.size() > MAX_VALUES) {
			widened.add(wkey);
			return new Slot(size, List.of(phi(block, off)));
		}
		return new Slot(size, List.copyOf(union));
	}

	/**
	 * The merged values at memory {@code key}, or null if not every predecessor has them, they
	 * were widened, or they are too many (then widened).
	 */
	private List<Value> mergeMemAtBlock(List<State> ins, List<Long> predIds, Address block,
			Sym mergeSym, MemKey key) {
		LinkedHashSet<Value> union = new LinkedHashSet<>();
		boolean same = true;
		List<Value> firstVals = ins.getFirst().mem.get(key);
		for (int i = 0; i < ins.size(); i++) {
			List<Value> vals = ins.get(i).mem.get(key);
			if (vals == null) {
				return null;
			}
			same &= vals.equals(firstVals);
			for (Value v : vals) {
				union.add(mergeLabel(v, mergeSym, predIds.get(i)));
			}
		}
		List<Object> wkey = List.of(block, "m", key);
		if (widened.contains(wkey)) {
			return null;
		}
		if (same) {
			return firstVals;
		}
		if (union.size() > MAX_VALUES) {
			widened.add(wkey);
			return null;
		}
		return List.copyOf(union);
	}

	// ---------------------------------------------------------------- paths of one instruction

	/**
	 * Joins the end states of the paths through the instruction at {@code at}, labelling what
	 * differs.
	 */
	static State mergePaths(List<State> paths, Address at) {
		if (paths.size() == 1) {
			State s = paths.getFirst();
			s.pathLabels = Map.of();
			return s;
		}
		State m = new State();
		Set<Long> keys = new TreeSet<>();
		for (State s : paths) {
			keys.addAll(s.regs.keySet());
		}
		for (Long off : keys) {
			m.regs.put(off, mergeRegPaths(paths, off, at));
		}
		for (MemKey key : paths.getFirst().mem.keySet()) {
			List<Value> vals = mergeMemPaths(paths, key);
			if (vals != null) {
				m.mem.put(key, vals);
			}
		}
		return m;
	}

	/** The joined register slot at {@code off}; a fresh value if the paths cannot be joined. */
	private static Slot mergeRegPaths(List<State> paths, Long off, Address at) {
		List<Slot> slots = new ArrayList<>();
		for (State s : paths) {
			slots.add(s.regs.get(off));
		}
		Slot first = slots.getFirst();
		if (slots.stream().allMatch(x -> Objects.equals(x, first))) {
			return first;
		}
		int size = -1;
		for (Slot slot : slots) {
			if (slot != null) {
				size = slot.size();
			}
		}
		LinkedHashSet<Value> union = new LinkedHashSet<>();
		for (int i = 0; i < paths.size(); i++) {
			Slot slot = slots.get(i);
			if (slot != null && slot.size() != size) {
				return new Slot(size, List.of(unjoined(at, off)));
			}
			List<Value> vals = slot != null ? slot.values()
					: List.of(new Value(0, new Sym(SymKind.ENTRY, off, size), null, Map.of()));
			addJoined(union, vals, paths.get(i).pathLabels);
		}
		if (union.isEmpty() || union.size() > MAX_VALUES) {
			return new Slot(size, List.of(unjoined(at, off)));
		}
		return new Slot(size, List.copyOf(union));
	}

	/** The fresh value of register {@code off} after paths that cannot be joined. */
	private static Value unjoined(Address at, long off) {
		return new Value(0, new Sym(SymKind.OP, at.getOffset(), -2 - off), null, Map.of());
	}

	/** The joined values at memory {@code key}, or null if a path lacks them or they are too many. */
	private static List<Value> mergeMemPaths(List<State> paths, MemKey key) {
		LinkedHashSet<Value> union = new LinkedHashSet<>();
		boolean same = true;
		List<Value> firstVals = paths.getFirst().mem.get(key);
		for (State path : paths) {
			List<Value> vals = path.mem.get(key);
			if (vals == null) {
				return null;
			}
			same &= vals.equals(firstVals);
			addJoined(union, vals, path.pathLabels);
		}
		if (same) {
			return firstVals;
		}
		return !union.isEmpty() && union.size() <= MAX_VALUES ? List.copyOf(union) : null;
	}

	/** Adds each value with its labels joined with the path's; drops those that disagree. */
	private static void addJoined(Set<Value> union, List<Value> vals, Map<Sym, Long> pathLabels) {
		for (Value v : vals) {
			Map<Sym, Long> l = joinLabels(v.labels(), pathLabels);
			if (l != null) {
				union.add(v.withLabels(l));
			}
		}
	}
}
