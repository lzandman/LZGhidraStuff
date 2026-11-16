// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.types;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import lzghidraswift.mangling.SwiftSymbol;
import lzghidraswift.metadata.ClassMethods;
import lzghidraswift.metadata.ContextDescriptor;
import lzghidraswift.metadata.SymbolNames;
import lzghidraswift.metadata.WordReader;

/**
 * The functions that may get {@code self} in the context register, for Swift Self Types, and the
 * types they were found for. They come from a class's method and override tables
 * ({@link #addClass}, checked against the vtable) and from the Swift symbols of members of the
 * types ({@link #addSymbol}). A candidate found for more than one type, or as both an allocating
 * initializer and an instance method, is a conflict ({@link Candidate#conflict()}). Only
 * {@link #of} and {@link #methodTable} read a program.
 */
public final class SelfCandidates {

	/** Where a function was found, for the counts and log lines. */
	public enum Source {
		METHOD_TABLE("method table"), OVERRIDE_TABLE("override table"), SYMBOL("symbol");

		private final String text;

		Source(String text) {
			this.text = text;
		}

		/** The text in the log lines. */
		public String text() {
			return text;
		}
	}

	/** A function and the types it was found for. */
	public static final class Candidate {
		private final Set<Address> types = new LinkedHashSet<>();
		private final Set<Source> sources = new LinkedHashSet<>();
		private final List<String> names = new ArrayList<>();
		private boolean getter;
		private boolean allocator;
		private boolean instance;

		/** The descriptors of the types, in the order found. */
		public Set<Address> types() {
			return Collections.unmodifiableSet(types);
		}

		/** The descriptor of the first type found. */
		public Address type() {
			return types.iterator().next();
		}

		/** Where it was found, in the order found. */
		public Set<Source> sources() {
			return Collections.unmodifiableSet(sources);
		}

		/** The symbols or method table entries it was found by. */
		public List<String> names() {
			return Collections.unmodifiableList(names);
		}

		/** A symbol names a property getter: Ghidra's demangler adds self as a parameter. */
		public boolean getter() {
			return getter;
		}

		/** A symbol names an allocating initializer: self is the metatype. */
		public boolean allocator() {
			return allocator;
		}

		/** Found as a method that gets an instance as self. */
		public boolean instance() {
			return instance;
		}

		/** Found for more than one type, or as an allocating initializer and an instance method. */
		public boolean conflict() {
			return types.size() > 1 || (allocator && instance);
		}
	}

	/**
	 * Vtable entry {@code index} (in words from the metadata) at {@code at} holds {@code entry},
	 * but the method descriptor at {@code method} has the Impl {@code impl}.
	 */
	public record VtableMismatch(String type, long index, Address at, long entry, Address method,
			long impl) {}

	/** Reads a 64-bit word of the vtable. */
	public interface Words {
		long u64(Address at) throws MemoryAccessException;
	}

	/** Counts for the candidates' summary line. */
	public static final class Counts {
		int methodTable, overrideTable, symbols, allocators, overridesUnresolved;
		int vtableChecked, vtableMismatches;

		/** The candidates and vtables part of the summary line. */
		public String summary() {
			return "candidates: %d from method tables, %d from override tables "
					.formatted(methodTable, overrideTable) +
				"(%d overrides of methods of other binaries not used), %d from symbols "
						.formatted(overridesUnresolved, symbols) +
				"(%d allocating initializers, self is the metadata); ".formatted(allocators) +
				"vtables: %d entries checked, %d mismatches".formatted(vtableChecked,
					vtableMismatches);
		}
	}

	private final Map<String, Address> contexts;
	private final Set<Address> classes;
	private final Set<Address> typed;
	private final Map<Address, Candidate> candidates = new LinkedHashMap<>();
	private final Counts counts = new Counts();

	/**
	 * {@code contexts}: the descriptors by the mangled context of their symbols
	 * {@code $s<context>Mn}; {@code classes}: the descriptors of classes; {@code typed}: the
	 * descriptors of the types with a data type.
	 */
	SelfCandidates(Map<String, Address> contexts, Set<Address> classes, Set<Address> typed) {
		this.contexts = contexts;
		this.classes = classes;
		this.typed = typed;
	}

	/**
	 * Candidates for the types of {@code descriptors}; {@code typed} are those with a data type.
	 * Reads the descriptors' symbols.
	 */
	public static SelfCandidates of(Program program, Map<Address, ContextDescriptor> descriptors,
			Set<Address> typed) {
		Set<Address> classes = new HashSet<>();
		for (ContextDescriptor d : descriptors.values()) {
			if (d.kind() == ContextDescriptor.KIND_CLASS) {
				classes.add(d.address());
			}
		}
		return new SelfCandidates(contexts(program, descriptors.keySet()), classes, typed);
	}

	/** The descriptors by the mangled context of their symbols {@code $s<context>Mn}. */
	private static Map<String, Address> contexts(Program program, Set<Address> descriptors) {
		Map<String, Address> contexts = new HashMap<>();
		for (Address descriptor : descriptors) {
			for (Symbol s : program.getSymbolTable().getSymbols(descriptor)) {
				String body = SymbolNames.swiftBody(s.getName());
				if (body != null && body.endsWith("Mn")) {
					contexts.put(body.substring(0, body.length() - 2), descriptor);
				}
			}
		}
		return contexts;
	}

	/**
	 * The method and override tables of the class descriptor {@code d}; throws
	 * {@link IllegalStateException} if they cannot be read.
	 */
	public static ClassMethods methodTable(Memory memory, ContextDescriptor d) {
		Address descriptor = d.address();
		return ClassMethods.read(descriptor.getOffset(), d.flags(),
			WordReader.of(memory, descriptor));
	}

	/** The candidates by function entry, in the order found. */
	public Map<Address, Candidate> candidates() {
		return Collections.unmodifiableMap(candidates);
	}

	/** The counts so far. */
	public Counts counts() {
		return counts;
	}

	/** Whether any descriptor has a symbol {@code $s<context>Mn}, so symbols can be matched. */
	public boolean hasContexts() {
		return !contexts.isEmpty();
	}

	/**
	 * Adds the instance methods (not initializers) of the method table of the class at
	 * {@code descriptor}, named {@code name}, and its overrides of methods of the binary. Checks
	 * each method against the vtable of the class metadata at {@code metadata} (null if not
	 * found) and returns the entries that differ; an entry that cannot be read is counted as a
	 * mismatch but not returned.
	 */
	public List<VtableMismatch> addClass(Address descriptor, String name, ClassMethods table,
			Address metadata, Words words) {
		List<VtableMismatch> mismatches = new ArrayList<>();
		for (int i = 0; i < table.methods().size(); i++) {
			ClassMethods.Method m = table.methods().get(i);
			if (m.impl() == 0) {
				continue;
			}
			if (metadata != null && table.vtableOffset() >= 0) {
				checkVtable(words, metadata, table.vtableOffset() + i, m, name, mismatches);
			}
			if (m.takesSelf()) {
				add(descriptor.getNewAddress(m.function()), descriptor, Source.METHOD_TABLE,
					name + " method " + i).instance = true;
				counts.methodTable++;
			}
		}
		for (ClassMethods.MethodOverride o : table.overrides()) {
			if (o.impl() == 0) {
				continue;
			}
			if (o.base() == null) {
				counts.overridesUnresolved++;
				continue;
			}
			if (o.base().takesSelf()) {
				add(descriptor.getNewAddress(o.function()), descriptor, Source.OVERRIDE_TABLE,
					name + " override").instance = true;
				counts.overrideTable++;
			}
		}
		return mismatches;
	}

	/** The vtable entry {@code index} (words from the metadata) must hold the method's Impl. */
	private void checkVtable(Words words, Address metadata, long index, ClassMethods.Method m,
			String name, List<VtableMismatch> mismatches) {
		counts.vtableChecked++;
		try {
			Address at = metadata.add(8 * index);
			long entry = words.u64(at);
			if (entry != m.impl()) {
				counts.vtableMismatches++;
				mismatches.add(new VtableMismatch(name, index, at, entry,
					metadata.getNewAddress(m.address()), m.impl()));
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			counts.vtableMismatches++;
		}
	}

	/**
	 * Adds the function at {@code function} if its symbol {@code symbol} names a member of one of
	 * the types with a data type, or an allocating initializer of a class (also one without a
	 * data type). A struct's or enum's initializers and deinitializers are skipped. Returns
	 * whether it was added.
	 */
	public boolean addSymbol(Address function, String symbol) {
		SwiftSymbol.Member m = SwiftSymbol.classify(symbol, contexts::containsKey);
		if (m == null) {
			return false;
		}
		Address descriptor = contexts.get(m.context());
		boolean allocator = m.kind() == SwiftSymbol.Kind.ALLOCATOR;
		// A struct's or enum's initializer returns the value; there is no self in x20 (a value
		// type's metatype is thin, it is not passed).
		if (!classes.contains(descriptor) && (allocator ||
			m.kind() == SwiftSymbol.Kind.INITIALIZER ||
			m.kind() == SwiftSymbol.Kind.DEINITIALIZER)) {
			return false;
		}
		if (!allocator && !typed.contains(descriptor)) {
			return false;
		}
		Candidate c = add(function, descriptor, Source.SYMBOL, symbol);
		c.getter |= m.kind() == SwiftSymbol.Kind.ACCESSOR && m.accessor() == 'g';
		c.allocator |= allocator;
		c.instance |= !allocator;
		counts.symbols++;
		if (allocator) {
			counts.allocators++;
		}
		return true;
	}

	private Candidate add(Address function, Address descriptor, Source source, String name) {
		Candidate c = candidates.computeIfAbsent(function, k -> new Candidate());
		c.types.add(descriptor);
		c.sources.add(source);
		c.names.add(name);
		return c;
	}
}
