// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.flow;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import lzghidraswift.flow.ValueFlow.Sym;
import lzghidraswift.flow.ValueFlow.SymKind;
import lzghidraswift.flow.ValueFlow.Value;

/**
 * The 0/1 values of {@link PcodeStep}. A boolean symbol {@code B} with offset {@code k} stands
 * for {@code B xor k}, as a condition of {@link ValueFlow}. Booleans are the results of compares
 * and bit 0 of a value; bit 0 of values that share it (a register and its low byte, a byte and
 * its zero extension, inverted by {@code not}) is one symbol. Combined with a constant, a
 * boolean is split into its two constants, each labelled with the symbol's value, so that a
 * Swift tag word computed from a Bool pairs with the word 0 that a {@code cmov} or {@code csel}
 * on the same condition selects. On x86_64 {@code sharp ? "Sharp" : "Flat"} computes the tag
 * word as {@code ((b & 1) | -0x1c) << 56}: count 4 or 5.
 */
final class Booleans {

	/** Bit 0 of a symbol is bit 0 of {@code source}, inverted if {@code inverted}. */
	private record Bit0(Value source, boolean inverted) {}

	/** Longest chain of {@link Bit0} links followed; they point to older symbols. */
	private static final int MAX_CHAIN = 32;

	private final Set<Sym> booleans = new HashSet<>();
	private final Map<Sym, Bit0> bit0Of = new HashMap<>();
	private final Function<List<Object>, Sym> numbering;

	/** {@code numbering} gives the value-numbered symbol of a key, the same for equal keys. */
	Booleans(Function<List<Object>, Sym> numbering) {
		this.numbering = numbering;
	}

	boolean isBoolean(Value v) {
		return !v.isConst() && booleans.contains(v.sym());
	}

	/**
	 * Records what the value-numbered result {@code result} of {@code op} says about 0/1 values:
	 * a compare gives a boolean; an extension, truncation, {@code not}, or {@code xor},
	 * {@code or} or {@code and} with a constant keeps bit 0 of its input (inverted or not).
	 */
	void numbered(int opcode, int outSize, Sym result, List<Value> inputs) {
		if (outSize == 1 && isCompare(opcode)) {
			booleans.add(result);
			return;
		}
		Value x = inputs.getFirst();
		if (x.isConst()) {
			return;
		}
		Long c = inputs.size() == 2 && inputs.get(1).isConst() ? inputs.get(1).k() : null;
		switch (opcode) {
			case PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT -> bit0Of.put(result, new Bit0(x, false));
			case PcodeOp.INT_NEGATE -> bit0Of.put(result, new Bit0(x, true));
			case PcodeOp.SUBPIECE -> {
				if (c != null && c == 0) {
					bit0Of.put(result, new Bit0(x, false));
				}
			}
			case PcodeOp.INT_XOR -> {
				if (c != null) {
					bit0Of.put(result, new Bit0(x, (c & 1) != 0));
				}
			}
			case PcodeOp.INT_OR -> {
				if (c != null && (c & 1) == 0) {
					bit0Of.put(result, new Bit0(x, false));
				}
			}
			case PcodeOp.INT_AND -> {
				if (c != null && (c & 1) != 0) {
					bit0Of.put(result, new Bit0(x, false));
				}
			}
			default -> {
			}
		}
	}

	/** Records that {@code low}, the low bytes of {@code source}, has bit 0 of {@code source}. */
	void truncated(Sym low, Value source) {
		bit0Of.put(low, new Bit0(source, false));
	}

	/**
	 * Bit 0 of the symbolic value {@code v} as a boolean: the same symbol for all values whose
	 * bit 0 is known to be the same, with the offset that says whether it is inverted.
	 */
	Value bit0(Value v) {
		long flip = v.k() & 1;
		Sym s = v.sym();
		for (int i = 0; i < MAX_CHAIN && !booleans.contains(s); i++) {
			Bit0 link = bit0Of.get(s);
			if (link == null) {
				break;
			}
			flip ^= (link.inverted() ? 1 : 0) ^ (link.source().k() & 1);
			s = link.source().sym();
		}
		if (!booleans.contains(s)) {
			// A register's entry value read at different sizes (dil, edi) has one bit 0.
			Sym root = s.kind() == SymKind.ENTRY ? new Sym(SymKind.ENTRY, s.a(), 0) : s;
			s = numbering.apply(List.of("bit0", root));
			booleans.add(s);
		}
		return new Value(flip, s, null, v.labels());
	}

	/**
	 * The result of {@code opcode} on the boolean {@code b} and the constant {@code c} if it is
	 * {@code b} or its negation again, else null.
	 */
	static Value withConstant(int opcode, Value b, long c) {
		Value negated = new Value(b.k() ^ 1, b.sym(), null, b.labels());
		return switch (opcode) {
			case PcodeOp.INT_EQUAL -> c == 0 ? negated : c == 1 ? b : null;
			case PcodeOp.INT_NOTEQUAL -> c == 0 ? b : c == 1 ? negated : null;
			case PcodeOp.INT_AND, PcodeOp.BOOL_AND -> (c & 1) != 0 ? b : null;
			case PcodeOp.INT_OR, PcodeOp.BOOL_OR -> c == 0 ? b : null;
			case PcodeOp.INT_XOR, PcodeOp.BOOL_XOR -> c == 0 ? b : c == 1 ? negated : null;
			default -> null;
		};
	}

	/** True if {@code opcode} on a boolean gives the same boolean. */
	static boolean keeps(int opcode) {
		return opcode == PcodeOp.COPY || opcode == PcodeOp.INT_ZEXT ||
			opcode == PcodeOp.INT_SEXT || opcode == PcodeOp.POPCOUNT;
	}

	/**
	 * The two constants of the boolean {@code b}, each labelled with the value of its symbol;
	 * a constant whose label disagrees with the labels {@code b} already has is left out.
	 */
	static List<Value> split(Value b, Address producer) {
		List<Value> l = new ArrayList<>(2);
		for (long symValue = 0; symValue <= 1; symValue++) {
			Map<Sym, Long> labels = ValueFlow.joinLabels(b.labels(), Map.of(b.sym(), symValue));
			if (labels != null) {
				l.add(new Value(b.k() ^ symValue, null, producer, labels));
			}
		}
		return l;
	}

	/** Ops whose 1-byte result is 0 or 1. */
	private static boolean isCompare(int opcode) {
		return switch (opcode) {
			case PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL -> true;
			case PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY, PcodeOp.INT_SBORROW -> true;
			case PcodeOp.BOOL_NEGATE, PcodeOp.BOOL_AND, PcodeOp.BOOL_OR, PcodeOp.BOOL_XOR -> true;
			case PcodeOp.FLOAT_EQUAL, PcodeOp.FLOAT_NOTEQUAL, PcodeOp.FLOAT_LESS, PcodeOp.FLOAT_LESSEQUAL, PcodeOp.FLOAT_NAN -> true;
			default -> false;
		};
	}
}
