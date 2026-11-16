// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import ghidra.program.model.address.Address;

/**
 * A Swift string literal found in code.
 *
 * @param kind small (built from two immediates) or large (address of {@code __cstring} bytes)
 * @param text the decoded string
 * @param word0At the instruction that produced word 0 (count and flags, or the first 8 bytes);
 *        null if no partner was needed (empty string from its tag word alone)
 * @param word1At the instruction that produced word 1 (the tag word, or the object word)
 * @param useAt the call, branch, return, store or compare where the pair was found; for
 *        fallback pairs the tag-word instruction
 * @param method how the two words were paired
 * @param word0 the value of word 0
 * @param word1 the value of word 1
 */
public record StringHit(Kind kind, String text, Address word0At, Address word1At, Address useAt,
		Method method, long word0, long word1) {

	/**
	 * Small: up to 15 UTF-8 bytes in the two words. Large: word 1 holds the address of the bytes in
	 * {@code __cstring}, less 32, with bit 63 set ({@link SwiftStringCodec#decodeLargeHeader}).
	 */
	public enum Kind {
		SMALL, LARGE
	}

	/** How the two words were paired. The last two give probable strings only. */
	public enum Method {
		/** Adjacent argument registers at a call. */
		CALL(false),
		/** Adjacent argument registers at a branch out of the function. */
		TAIL(false),
		/** Result registers at a return. */
		RETURN(false),
		/** Word 1 stored 8 bytes after word 0, same base. */
		STORE(false),
		/** Two compares in a row, one with word 0 and one with the tag word. */
		COMPARE(false),
		/** The only constant in the tag word's basic block that decodes with it. */
		FALLBACK(true),
		/** A tag word with count 0 and no partner. */
		EMPTY_TAG(true);

		private final boolean probable;

		Method(boolean probable) {
			this.probable = probable;
		}

		public boolean probable() {
			return probable;
		}
	}

	/** The instruction that completes the string: the later of the two producers. */
	public Address completedAt() {
		if (word0At == null) {
			return word1At;
		}
		return word0At.compareTo(word1At) > 0 ? word0At : word1At;
	}
}
