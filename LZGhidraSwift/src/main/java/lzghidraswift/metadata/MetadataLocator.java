// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.metadata;

import java.util.Arrays;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import lzghidraswift.abi.CallingConventions;

/**
 * Finds the static type metadata of a non-generic type from its metadata accessor (AArch64 and
 * x86_64; see {@link AccessorDecoder} and {@link X86AccessorDecoder} for the patterns). The
 * metadata is static if the accessor returns a constant address, or (classes) passes one to
 * {@code objc_opt_self}. The result is checked: the
 * metadata's description pointer (struct and enum: word 1; class: word 8) must point back to the
 * type's context descriptor.
 */
public class MetadataLocator {

	/**
	 * Why a type has no static metadata, with the text that groups the reasons in a summary. The
	 * full reason of {@link Located} adds the details (the processor, the callee, the count, the
	 * instruction, the addresses).
	 */
	public enum Missing {
		GENERIC("generic"),
		SINGLETON("singleton metadata initialization"),
		FOREIGN("foreign metadata"),
		NO_ACCESSOR("no metadata accessor"),
		UNSUPPORTED_PROCESSOR("accessor decoding not implemented"),
		ACCESSOR_CALLS("accessor calls another function"),
		NO_RETURN("accessor: no ret or call"),
		UNRECOGNIZED("accessor: unrecognized instruction"),
		NOT_CONSTANT("accessor result not constant"),
		WRONG_METADATA("metadata describes another type"),
		UNREADABLE("metadata not readable");

		private final String text;

		Missing(String text) {
			this.text = text;
		}

		/** The group's text for a summary, such as "generic". */
		public String text() {
			return text;
		}
	}

	/**
	 * The static metadata, or null, why there is none and the full reason (both null when the
	 * metadata was found).
	 */
	public record Located(Address metadata, Missing missing, String reason) {}

	/** Instructions decoded per accessor; the class pattern has 8. */
	private static final int MAX_WORDS = 16;
	/** Bytes decoded per x86_64 accessor; the class pattern has 20. */
	private static final int MAX_BYTES = 64;
	/** Callees that return their argument's class metadata unchanged (realized). */
	private static final Set<String> CLASS_REALIZERS =
		Set.of("objc_opt_self", "swift_getInitializedObjCClass");

	private final Program program;
	private final Memory memory;
	private final boolean aarch64;
	private final boolean x86_64;

	/** A locator for {@code program}. It decodes accessors only on 64-bit AArch64 and x86_64. */
	public MetadataLocator(Program program) {
		this.program = program;
		this.memory = program.getMemory();
		boolean target = CallingConventions.isSwiftTarget(program);
		this.aarch64 = target && CallingConventions.isAArch64(program);
		this.x86_64 = target && !CallingConventions.isAArch64(program);
	}

	/**
	 * The static metadata of the type that {@code d} describes. None for generic types, types whose
	 * metadata is built at run time or imported, and accessors that do not match a known pattern.
	 */
	public Located locate(ContextDescriptor d) {
		if (d.isGeneric()) {
			return none(Missing.GENERIC, "generic");
		}
		switch (d.metadataInitialization()) {
			case ContextDescriptor.INIT_SINGLETON -> {
				return none(Missing.SINGLETON,
					"singleton metadata initialization (built at run time)");
			}
			case ContextDescriptor.INIT_FOREIGN -> {
				return none(Missing.FOREIGN, "foreign metadata (imported C type)");
			}
			default -> {
			}
		}
		if (d.accessor() == null) {
			return none(Missing.NO_ACCESSOR, "no metadata accessor");
		}
		long pc = d.accessor().getOffset();
		AccessorDecoder.Result r;
		int decoded;
		if (aarch64) {
			int[] words = readWords(d.accessor());
			r = AccessorDecoder.decode(pc, words, this::read64);
			decoded = words.length;
		}
		else if (x86_64) {
			byte[] code = readBytes(d.accessor());
			r = X86AccessorDecoder.decode(pc, code, this::read64);
			decoded = code.length;
		}
		else {
			return none(Missing.UNSUPPORTED_PROCESSOR, "accessor decoding not implemented for " +
				CallingConventions.processor(program));
		}
		Long result = null;
		switch (r.exit()) {
			case RETURN -> result = r.x0();
			case CALL, TAIL_CALL -> {
				String callee = calleeName(d.accessor().getNewAddress(r.target()));
				if (!CLASS_REALIZERS.contains(callee)) {
					return none(Missing.ACCESSOR_CALLS, "accessor calls " + (callee != null ? callee
							: "0x" +
								Long.toHexString(r.target())));
				}
				result = r.x0();
			}
			case UNRECOGNIZED -> {
				return unrecognized(r, decoded);
			}
		}
		if (result == null) {
			return none(Missing.NOT_CONSTANT, "accessor result not constant");
		}
		return verified(d, result);
	}

	/** Why decoding stopped at an UNRECOGNIZED exit after {@code decoded} words or bytes. */
	private Located unrecognized(AccessorDecoder.Result r, int decoded) {
		if (r.index() >= decoded) {
			return none(Missing.NO_RETURN, "accessor: no ret or call in %d %s".formatted(decoded,
				aarch64 ? "instructions" : "bytes"));
		}
		return none(Missing.UNRECOGNIZED,
			aarch64 ? "accessor: unrecognized instruction 0x%08x at +%d".formatted(r.word(),
				4 * r.index())
					: "accessor: unrecognized instruction bytes %08x at +%d".formatted(r.word(),
						r.index()));
	}

	/**
	 * The metadata at {@code result} if its description pointer (struct and enum: word 1; class:
	 * word 8) points back to {@code d}.
	 */
	private Located verified(ContextDescriptor d, long result) {
		try {
			Address metadata = d.accessor().getNewAddress(result);
			Address description = ContextDescriptor.pointer(memory,
				metadata.add(d.kind() == ContextDescriptor.KIND_CLASS ? 64 : 8));
			if (!description.equals(d.address())) {
				return none(Missing.WRONG_METADATA, "metadata at %s describes %s, not this type"
						.formatted(metadata, description));
			}
			return new Located(metadata, null, null);
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return none(Missing.UNREADABLE,
				"metadata at 0x%x not readable: %s".formatted(result, e.getMessage()));
		}
	}

	private static Located none(Missing missing, String reason) {
		return new Located(null, missing, reason);
	}

	private int[] readWords(Address at) {
		int[] words = new int[MAX_WORDS];
		int n = 0;
		try {
			for (; n < MAX_WORDS; n++) {
				words[n] = memory.getInt(at.add(4L * n));
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			// decode what could be read
		}
		return Arrays.copyOf(words, n);
	}

	private byte[] readBytes(Address at) {
		byte[] code = new byte[MAX_BYTES];
		int n = 0;
		try {
			for (; n < MAX_BYTES; n++) {
				code[n] = memory.getByte(at.add(n));
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			// decode what could be read
		}
		return Arrays.copyOf(code, n);
	}

	private Long read64(long address) {
		try {
			return memory.getLong(program.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(address));
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * The name of a call target without leading underscores: the function a stub is a thunk
	 * for, the function, or the primary symbol there.
	 */
	String calleeName(Address target) {
		Function f = SymbolNames.callee(program, target);
		String name = f != null ? f.getName() : null;
		if (name == null) {
			Symbol s = program.getSymbolTable().getPrimarySymbol(target);
			name = s != null ? s.getName() : null;
		}
		return name == null ? null : SymbolNames.withoutLeadingUnderscores(name);
	}

	/**
	 * The name of what a pointer slot points to outside the program: the imported symbol of an
	 * external reference from the slot, or a symbol at the pointer's target in the external
	 * block. Null if none is found. Used for value witness tables bound to the Swift runtime.
	 */
	public String importedName(Address slot) throws MemoryAccessException {
		String external = SymbolNames.importedFrom(program, slot);
		if (external != null) {
			return external;
		}
		Address target = ContextDescriptor.pointer(memory, slot);
		for (Symbol symbol : program.getSymbolTable().getSymbols(target)) {
			if (SymbolNames.isSwift(symbol.getName())) {
				return symbol.getName();
			}
		}
		return null;
	}
}
