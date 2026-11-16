// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Decodes the two words of a 64-bit Swift {@code String} (Apple platforms), as laid out in
 * {@code stdlib/public/core/StringObject.swift} and {@code SmallString.swift}. No Ghidra types.
 */
public final class SwiftStringCodec {

	/** Word 0 flags of an immortal large ASCII literal: isASCII, isNFC, isTailAllocated. */
	static final long LARGE_ASCII_FLAGS = 0xD000_0000_0000_0000L;
	/** Word 0 flags of an immortal large non-ASCII literal: isTailAllocated. */
	static final long LARGE_NON_ASCII_FLAGS = 0x1000_0000_0000_0000L;
	/** Word 1 of a large literal: bit 63 (isImmortal) | (address - nativeBias). */
	static final long LARGE_OBJECT_FLAG = 0x8000_0000_0000_0000L;
	/** {@code _StringObject.nativeBias}. */
	static final int NATIVE_BIAS = 32;

	/** A decoded large-literal header; the bytes still have to be checked at {@code address}. */
	public record LargeHeader(int count, boolean ascii, long address) {}

	private SwiftStringCodec() {
	}

	public static int smallCount(long word1) {
		return (int) (word1 >>> 56) & 0xF;
	}

	/**
	 * Quick filter for word 1 of a small string: discriminator 0xE (ASCII) or 0xA (not ASCII),
	 * the code units of word 1 past the count are 0, and with 0xE all code units are below 0x80.
	 */
	public static boolean isSmallTag(long word1) {
		int nibble = (int) (word1 >>> 60);
		if (nibble != 0xE && nibble != 0xA) {
			return false;
		}
		int count = smallCount(word1);
		for (int i = 8; i < 15; i++) {
			int b = (int) (word1 >>> (8 * (i - 8))) & 0xFF;
			if (i >= count && b != 0) {
				return false;
			}
			if (nibble == 0xE && b >= 0x80) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Decodes a small string, or returns null if the words are not one: count at most 15, all
	 * bytes past the count 0, valid UTF-8, and the ASCII bit matching the bytes.
	 */
	public static String decodeSmall(long word0, long word1) {
		if (!isSmallTag(word1)) {
			return null;
		}
		int count = smallCount(word1);
		byte[] bytes = new byte[15];
		for (int i = 0; i < 8; i++) {
			bytes[i] = (byte) (word0 >>> (8 * i));
		}
		for (int i = 8; i < 15; i++) {
			bytes[i] = (byte) (word1 >>> (8 * (i - 8)));
		}
		boolean ascii = true;
		for (int i = 0; i < 15; i++) {
			if (i >= count && bytes[i] != 0) {
				return null;
			}
			if (i < count && bytes[i] < 0) {
				ascii = false;
			}
		}
		if (ascii != ((word1 >>> 60) == 0xE)) {
			return null;
		}
		return utf8(bytes, count);
	}

	/**
	 * Decodes the header of an immortal large literal ({@code _StringObject.init(immortal:isASCII:)}):
	 * word 0 = flags | count, word 1 = bit 63 | (address - 32). Returns null if the words do not
	 * have that form or the count is below 16 (shorter literals are small strings).
	 */
	public static LargeHeader decodeLargeHeader(long word0, long word1) {
		long flags = word0 & 0xFFFF_0000_0000_0000L;
		boolean ascii;
		if (flags == LARGE_ASCII_FLAGS) {
			ascii = true;
		}
		else if (flags == LARGE_NON_ASCII_FLAGS) {
			ascii = false;
		}
		else {
			return null;
		}
		long count = word0 & 0x0000_FFFF_FFFF_FFFFL;
		if (count < 16 || count > Integer.MAX_VALUE) {
			return null;
		}
		if ((word1 & 0xF000_0000_0000_0000L) != LARGE_OBJECT_FLAG) {
			return null;
		}
		long address = (word1 & ~LARGE_OBJECT_FLAG) + NATIVE_BIAS;
		return new LargeHeader((int) count, ascii, address);
	}

	/**
	 * Checks the bytes of a large literal: valid UTF-8, the ASCII flag matching, and a NUL after
	 * {@code count} bytes. {@code bytes} holds count + 1 bytes. Returns the string or null.
	 */
	public static String checkLargeBytes(LargeHeader header, byte[] bytes) {
		int count = header.count();
		if (bytes.length != count + 1 || bytes[count] != 0) {
			return null;
		}
		boolean ascii = true;
		for (int i = 0; i < count; i++) {
			if (bytes[i] == 0) {
				return null;
			}
			if (bytes[i] < 0) {
				ascii = false;
			}
		}
		if (ascii != header.ascii()) {
			return null;
		}
		return utf8(bytes, count);
	}

	private static String utf8(byte[] bytes, int count) {
		try {
			return StandardCharsets.UTF_8.newDecoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT)
					.decode(ByteBuffer.wrap(bytes, 0, count))
					.toString();
		}
		catch (CharacterCodingException e) {
			return null;
		}
	}

	/**
	 * The string in double quotes, with C escapes for {@code "}, {@code \} and control characters;
	 * other characters, including non-ASCII, are kept.
	 */
	public static String quote(String s) {
		StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"' -> sb.append("\\\"");
				case '\\' -> sb.append("\\\\");
				case '\n' -> sb.append("\\n");
				case '\r' -> sb.append("\\r");
				case '\t' -> sb.append("\\t");
				default -> {
					if (c < 0x20 || c == 0x7F) {
						sb.append("\\x%02x".formatted((int) c));
					}
					else {
						sb.append(c);
					}
				}
			}
		}
		return sb.append('"').toString();
	}
}
