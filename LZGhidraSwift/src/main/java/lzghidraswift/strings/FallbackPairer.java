// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lzghidraswift.strings.RegisterPairFinder.Constant;
import lzghidraswift.strings.StringHit.Kind;
import lzghidraswift.strings.StringHit.Method;

/**
 * Tag words that {@link RegisterPairFinder} did not pair at a use site. A tag word with count 0
 * is the empty string on its own. A tag word with count 1-8 is paired with the only other
 * register constant in its basic block that decodes with it. The rest are returned as unpaired.
 */
public final class FallbackPairer {

	private static final int MAX_FALLBACK_COUNT = 8;

	/** The hits that were paired, the tag words seen, and the tag words left unpaired. */
	public record Result(List<StringHit> hits, List<Constant> tagWords, List<Constant> unpaired) {}

	private FallbackPairer() {
	}

	/** Pairs the tag words in {@code constants} whose word 1 is not in {@code found}. */
	public static Result pair(Program program, List<Constant> constants, List<StringHit> found,
			TaskMonitor monitor) throws CancelledException {
		Set<Address> paired = new HashSet<>();
		for (StringHit h : found) {
			if (h.kind() == Kind.SMALL) {
				paired.add(h.word1At());
			}
		}
		List<Constant> tagWords = new ArrayList<>();
		for (Constant c : constants) {
			if (c.register().getSize() == 8 && SwiftStringCodec.isSmallTag(c.value())) {
				tagWords.add(c);
			}
		}
		Set<Constant> intermediate = intermediate(program, constants);
		BasicBlockModel model = new BasicBlockModel(program);
		List<StringHit> hits = new ArrayList<>();
		List<Constant> unpaired = new ArrayList<>();
		for (Constant tag : tagWords) {
			if (paired.contains(tag.at())) {
				continue;
			}
			StringHit hit = fallback(tag, constants, intermediate, model, monitor);
			if (hit != null) {
				hits.add(hit);
			}
			else {
				unpaired.add(tag);
			}
		}
		return new Result(hits, tagWords, unpaired);
	}

	/**
	 * Constants that the next instruction replaces in the same register: the first steps of a
	 * mov/movk chain, not candidates for word 0.
	 */
	private static Set<Constant> intermediate(Program program, List<Constant> constants) {
		Set<List<Object>> produced = new HashSet<>();
		for (Constant c : constants) {
			produced.add(List.of(c.at(), c.register().getOffset()));
		}
		Set<Constant> intermediate = new HashSet<>();
		for (Constant c : constants) {
			Instruction next = program.getListing().getInstructionAfter(c.at());
			if (next != null &&
				produced.contains(List.of(next.getAddress(), c.register().getOffset()))) {
				intermediate.add(c);
			}
		}
		return intermediate;
	}

	/** The empty string for count 0, the only partner in the block for counts 1-8, or null. */
	private static StringHit fallback(Constant tag, List<Constant> constants,
			Set<Constant> intermediate, BasicBlockModel model, TaskMonitor monitor)
			throws CancelledException {
		int count = SwiftStringCodec.smallCount(tag.value());
		if (count == 0) {
			return SwiftStringCodec.decodeSmall(0, tag.value()) == null ? null
					: new StringHit(Kind.SMALL, "", null, tag.at(), tag.at(), Method.EMPTY_TAG, 0,
						tag.value());
		}
		if (count > MAX_FALLBACK_COUNT) {
			return null;
		}
		CodeBlock block = model.getFirstCodeBlockContaining(tag.at(), monitor);
		if (block == null) {
			return null;
		}
		Map<String, Constant> partners = partners(tag, block, constants, intermediate);
		if (partners.size() != 1) {
			return null;
		}
		Map.Entry<String, Constant> e = partners.entrySet().iterator().next();
		return new StringHit(Kind.SMALL, e.getKey(), e.getValue().at(), tag.at(), tag.at(),
			Method.FALLBACK, e.getValue().value(), tag.value());
	}

	/** Per string: the nearest constant in {@code block} that decodes with the tag word to it. */
	private static Map<String, Constant> partners(Constant tag, CodeBlock block,
			List<Constant> constants, Set<Constant> intermediate) {
		Map<String, Constant> partners = new LinkedHashMap<>();
		for (Constant c : constants) {
			if (c.at().equals(tag.at()) || !block.contains(c.at()) || intermediate.contains(c)) {
				continue;
			}
			String s = SwiftStringCodec.decodeSmall(c.value(), tag.value());
			// A NUL inside the count is valid Swift but almost never a literal; for a guessed
			// pair it more likely means the wrong partner.
			if (s == null || s.indexOf('\0') >= 0) {
				continue;
			}
			Constant old = partners.get(s);
			if (old == null || distance(c, tag) < distance(old, tag)) {
				partners.put(s, c);
			}
		}
		return partners;
	}

	private static long distance(Constant a, Constant b) {
		return Math.abs(a.at().subtract(b.at()));
	}
}
