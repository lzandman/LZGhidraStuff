// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.types;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lzghidraswift.mangling.MangledTypeReader;
import lzghidraswift.metadata.ContextDescriptor;
import lzghidraswift.metadata.SwiftSections;

/**
 * The types listed in {@code __swift5_types}: their context descriptors, in order, and the
 * qualified name of each, as Swift Data Types names its data type. Read by Swift Data Types and
 * Swift Self Types.
 */
public final class SwiftTypeCatalog {

	/** Counts for the summary line. */
	static final class Counts {
		int entries, classes, structs, enums, other, unreadable;

		/** The summary line, with {@code types} distinct descriptors found. */
		String summary(int types) {
			return "found %d Swift types in %s (%d entries): "
					.formatted(types, SwiftSections.TYPES, entries) +
				"%d classes, %d structs, %d enums, ".formatted(classes, structs, enums) +
				"%d other, %d unreadable".formatted(other, unreadable);
		}
	}

	private final Map<Address, ContextDescriptor> descriptors;
	private final Map<Address, String> names;
	private final MangledTypeReader reader;
	private final Counts counts;

	private SwiftTypeCatalog(Map<Address, ContextDescriptor> descriptors,
			Map<Address, String> names, MangledTypeReader reader, Counts counts) {
		this.descriptors = descriptors;
		this.names = names;
		this.reader = reader;
		this.counts = counts;
	}

	/**
	 * Reads the descriptors listed in {@code types} and names them. Initializes {@code monitor}
	 * to the number of entries; the caller sets the message.
	 */
	public static SwiftTypeCatalog read(Program program, AddressRange types, TaskMonitor monitor)
			throws CancelledException {
		Counts counts = new Counts();
		Map<Address, ContextDescriptor> descriptors =
			readDescriptors(program.getMemory(), types, counts, monitor);
		MangledTypeReader reader = new MangledTypeReader(program);
		return new SwiftTypeCatalog(descriptors, typeNames(reader, descriptors.values()), reader,
			counts);
	}

	/** The distinct context descriptors, by address, in the order of {@code __swift5_types}. */
	public Map<Address, ContextDescriptor> descriptors() {
		return descriptors;
	}

	/** The qualified name of the type with this descriptor, or null. */
	public String name(Address descriptor) {
		return names.get(descriptor);
	}

	/** The reader the names were read with, for the types' other mangled names. */
	public MangledTypeReader reader() {
		return reader;
	}

	/** The summary of the reading, after {@code "<analyzer>: "}. */
	public String summary() {
		return counts.summary(descriptors.size());
	}

	/**
	 * Each entry is a relative pointer with the TypeReferenceKind in the low 2 bits: 0 points to
	 * the descriptor, 1 to a pointer to it.
	 */
	private static Map<Address, ContextDescriptor> readDescriptors(Memory memory,
			AddressRange types, Counts counts, TaskMonitor monitor) throws CancelledException {
		Map<Address, ContextDescriptor> descriptors = new LinkedHashMap<>();
		counts.entries = (int) (types.getLength() / 4);
		monitor.initialize(counts.entries);
		for (int i = 0; i < counts.entries; i++) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			Address at = types.getMinAddress().add(4L * i);
			try {
				int value = memory.getInt(at);
				Address target = at.add(value & ~3);
				if ((value & 3) == 1) {
					target = ContextDescriptor.pointer(memory, target);
				}
				else if ((value & 3) != 0) {
					counts.unreadable++;
					continue;
				}
				if (descriptors.containsKey(target)) {
					continue;
				}
				ContextDescriptor d = ContextDescriptor.read(memory, target);
				descriptors.put(target, d);
				switch (d.kind()) {
					case ContextDescriptor.KIND_CLASS -> counts.classes++;
					case ContextDescriptor.KIND_STRUCT -> counts.structs++;
					case ContextDescriptor.KIND_ENUM -> counts.enums++;
					default -> counts.other++;
				}
			}
			catch (MemoryAccessException | AddressOutOfBoundsException e) {
				counts.unreadable++;
			}
		}
		return descriptors;
	}

	/**
	 * Private types of different source files can have the same qualified name (their anonymous
	 * parent contexts do not show in it): a framework can have two
	 * {@code TestKnob}s. Data types with the same path would replace each other on every run.
	 * Types whose names collide get names with their anonymous contexts instead.
	 */
	private static Map<Address, String> typeNames(MangledTypeReader reader,
			Collection<ContextDescriptor> descriptors) {
		Map<Address, String> names = new LinkedHashMap<>();
		Map<String, Integer> counts = new HashMap<>();
		for (ContextDescriptor d : descriptors) {
			String name = qualifiedName(reader, d);
			names.put(d.address(), name);
			counts.merge(name, 1, Integer::sum);
		}
		for (Map.Entry<Address, String> e : names.entrySet()) {
			if (counts.get(e.getValue()) < 2) {
				continue;
			}
			try {
				e.setValue(reader.qualifiedNameWithAnonymousContexts(e.getKey()));
			}
			catch (MemoryAccessException | AddressOutOfBoundsException ex) {
				// keep the colliding name
			}
		}
		return names;
	}

	private static String qualifiedName(MangledTypeReader reader, ContextDescriptor d) {
		try {
			return reader.qualifiedName(d.address());
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return d.name() != null ? d.name() : "?";
		}
	}
}
