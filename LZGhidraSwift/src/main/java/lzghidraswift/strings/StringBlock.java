// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.StringUTF8DataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The string block, a workaround with side effects: small strings written into an artificial,
 * non-loaded overlay block on the OTHER space ({@value #NAME}), each defined as {@code utf8}
 * string data, with a data reference from the instruction that completes the string. Ghidra's Defined Strings window
 * then lists them. The block holds bytes that are not in the binary.
 * <p>
 * The block only grows, so that the addresses that references point at stay put: each
 * {@link #write} appends a block for the texts not there yet and joins it to the last one.
 * Texts whose references are gone stay in the block. Collect with {@link #add} while marking,
 * then {@link #write} once at the end of the run: one new block per run, not one per function.
 */
public final class StringBlock {

	/** The name of the block and of its overlay space; addresses read {@code swift_strings::0}. */
	public static final String NAME = "swift_strings";
	static final String COMMENT = "Swift small strings, written by the Swift String Literals " +
		"analyzer (option \"String block\"). Not in the binary: the code builds these strings " +
		"from two immediates.";

	/** What one {@link #write} did. {@code locked}: a new block needed an exclusive checkout. */
	public record Result(int stringsAdded, int references, boolean locked) {}

	/** A string to reference from {@code from}. */
	private record Use(Address from, String text) {}

	private final Program program;
	private final Set<Use> uses = new LinkedHashSet<>();

	public StringBlock(Program program) {
		this.program = program;
	}

	// ---------------------------------------------------------------- layout, no Ghidra types

	/**
	 * True for texts the block can hold: not empty (a lone NUL is no use in the window), and
	 * without NUL, which terminates each string in the block.
	 */
	static boolean fits(String text) {
		return !text.isEmpty() && text.indexOf('\0') < 0;
	}

	/**
	 * The strings in a block's bytes: text to offset, each the UTF-8 bytes before a NUL. The first
	 * offset of a text wins; bytes after the last NUL are ignored.
	 */
	static Map<String, Long> parse(byte[] bytes) {
		Map<String, Long> offsets = new LinkedHashMap<>();
		int start = 0;
		for (int i = 0; i < bytes.length; i++) {
			if (bytes[i] == 0) {
				if (i > start) {
					offsets.putIfAbsent(
						new String(bytes, start, i - start, StandardCharsets.UTF_8), (long) start);
				}
				start = i + 1;
			}
		}
		return offsets;
	}

	/** A new block: the offset of each text in it, in order. */
	record Layout(Map<String, Long> offsets) {
		/** The block's bytes: each text as UTF-8 plus a NUL. */
		byte[] bytes() {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			for (String t : offsets.keySet()) {
				out.writeBytes(t.getBytes(StandardCharsets.UTF_8));
				out.write(0);
			}
			return out.toByteArray();
		}
	}

	/**
	 * The new block for the {@code texts} that are not in {@code existing}: each once, in their
	 * order, as UTF-8 plus a NUL. Texts that do not {@link #fits fit} are left out.
	 */
	static Layout layout(Set<String> existing, Collection<String> texts) {
		Map<String, Long> offsets = new LinkedHashMap<>();
		long size = 0;
		for (String t : texts) {
			if (!fits(t) || existing.contains(t) || offsets.containsKey(t)) {
				continue;
			}
			offsets.put(t, size);
			size += t.getBytes(StandardCharsets.UTF_8).length + 1;
		}
		return new Layout(offsets);
	}

	// ---------------------------------------------------------------- program

	/** The overlay space of the block, or null if the program has none. */
	public static AddressSpace space(Program program) {
		AddressSpace s = program.getAddressFactory().getAddressSpace(NAME);
		return s != null && s.isOverlaySpace() ? s : null;
	}

	/** The blocks in the overlay space, in address order. */
	private static List<MemoryBlock> blocks(Program program, AddressSpace space) {
		List<MemoryBlock> list = new ArrayList<>();
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			if (b.getStart().getAddressSpace().equals(space)) {
				list.add(b);
			}
		}
		list.sort(Comparator.comparing(MemoryBlock::getStart));
		return list;
	}

	/** The strings in the block: text to address. */
	public static Map<String, Address> read(Program program) {
		Map<String, Address> addrs = new LinkedHashMap<>();
		AddressSpace space = space(program);
		if (space == null) {
			return addrs;
		}
		for (MemoryBlock b : blocks(program, space)) {
			byte[] bytes = new byte[(int) b.getSize()];
			try {
				b.getBytes(b.getStart(), bytes);
			}
			catch (MemoryAccessException e) {
				Msg.warn(StringBlock.class,
					"SWIFTSTR-BLOCK\t%s\t%s".formatted(b.getStart(), e.getMessage()));
				continue;
			}
			for (Map.Entry<String, Long> e : parse(bytes).entrySet()) {
				addrs.putIfAbsent(e.getKey(), b.getStart().add(e.getValue()));
			}
		}
		return addrs;
	}

	/** Removes the references from {@code body} into the block. */
	public static void clearReferences(Program program, AddressSetView body) {
		AddressSpace space = space(program);
		if (space == null) {
			return;
		}
		ReferenceManager rm = program.getReferenceManager();
		List<Reference> refs = new ArrayList<>();
		AddressIterator it = rm.getReferenceSourceIterator(body, true);
		while (it.hasNext()) {
			for (Reference r : rm.getReferencesFrom(it.next())) {
				if (r.getToAddress().getAddressSpace().equals(space)) {
					refs.add(r);
				}
			}
		}
		for (Reference r : refs) {
			rm.delete(r);
		}
	}

	/** Collects a reference from {@code from} to {@code text}, for {@link #write}. */
	public void add(Address from, String text) {
		if (fits(text)) {
			uses.add(new Use(from, text));
		}
	}

	/**
	 * Appends the collected texts that are not in the block yet, defines them, and adds the
	 * collected references. Without exclusive access no block is created; references to texts
	 * already there are still added.
	 */
	public Result write(TaskMonitor monitor) throws CancelledException {
		Map<String, Address> addrs = read(program);
		List<String> texts = new ArrayList<>();
		for (Use u : uses) {
			texts.add(u.text());
		}
		Layout layout = layout(addrs.keySet(), texts);
		boolean locked = false;
		int added = 0;
		if (!layout.offsets().isEmpty()) {
			try {
				Address start = append(layout, monitor);
				for (Map.Entry<String, Long> e : layout.offsets().entrySet()) {
					addrs.put(e.getKey(), start.add(e.getValue()));
				}
				added = define(layout, start);
			}
			catch (LockException e) {
				locked = true;
			}
			catch (MemoryConflictException | AddressOverflowException e) {
				Msg.warn(this, "SWIFTSTR-BLOCK\t%s".formatted(e.getMessage()));
			}
		}
		ReferenceManager rm = program.getReferenceManager();
		int refs = 0;
		for (Use u : uses) {
			Address to = addrs.get(u.text());
			if (to != null) {
				rm.addMemoryReference(u.from(), to, RefType.DATA, SourceType.ANALYSIS,
					Reference.MNEMONIC);
				refs++;
			}
		}
		uses.clear();
		return new Result(added, refs, locked);
	}

	/**
	 * Creates a block holding {@code layout}'s bytes after the last block of the space (a new
	 * space at OTHER:0 if there is none) and joins it to that block. Returns the new bytes' start.
	 */
	private Address append(Layout layout, TaskMonitor monitor) throws LockException,
			MemoryConflictException, AddressOverflowException, CancelledException {
		Memory memory = program.getMemory();
		AddressSpace space = space(program);
		List<MemoryBlock> existing = space == null ? List.of() : blocks(program, space);
		Address start = existing.isEmpty()
				? AddressSpace.OTHER_SPACE.getAddress(0)
				: existing.getLast().getEnd().add(1);
		byte[] bytes = layout.bytes();
		MemoryBlock block = memory.createInitializedBlock(NAME, start,
			new ByteArrayInputStream(bytes), bytes.length, monitor, true);
		block.setPermissions(true, false, false);
		block.setArtificial(true);
		block.setComment(COMMENT);
		// A new overlay space: OTHER:0 mapped into it. Read before join, which replaces the block.
		Address newStart = block.getStart();
		if (!existing.isEmpty()) {
			try {
				memory.join(existing.getLast(), block);
			}
			catch (MemoryBlockException e) {
				// Two blocks in the Memory Map; read() finds the strings in both.
				Msg.warn(this, "SWIFTSTR-BLOCK\tjoin\t%s".formatted(e.getMessage()));
			}
		}
		return newStart;
	}

	/** Defines each new text as {@code utf8} data. Returns the number defined. */
	private int define(Layout layout, Address start) {
		Listing listing = program.getListing();
		int defined = 0;
		for (Map.Entry<String, Long> e : layout.offsets().entrySet()) {
			Address a = start.add(e.getValue());
			int length = e.getKey().getBytes(StandardCharsets.UTF_8).length + 1;
			try {
				listing.createData(a, StringUTF8DataType.dataType, length);
				defined++;
			}
			catch (CodeUnitInsertionException ex) {
				Msg.warn(this, "SWIFTSTR-BLOCK\t%s\t%s".formatted(a, ex.getMessage()));
			}
		}
		return defined;
	}
}
