// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lzghidraswift.mangling.MangledName;
import lzghidraswift.mangling.MangledTypeReader;
import lzghidraswift.metadata.ContextDescriptor;
import lzghidraswift.metadata.FieldDescriptors;
import lzghidraswift.metadata.MetadataLocator;
import lzghidraswift.metadata.SwiftSections;
import lzghidraswift.metadata.WordReader;
import lzghidraswift.types.SwiftLayout;
import lzghidraswift.types.SwiftTypeBuilder;
import lzghidraswift.types.SwiftTypeCatalog;
import lzghidraswift.types.SwiftTypeInfo;

/**
 * Swift structs, classes and enums as Ghidra data types, from the reflection metadata
 * ({@code __swift5_types}, {@code __swift5_fieldmd}) and the static type metadata. Reads the type and field descriptors and the
 * layouts from the static metadata, logs them (tab-separated lines {@code SWIFTTYPE},
 * {@code SWIFTFIELD}), and creates the data types with {@link SwiftTypeBuilder} (log lines
 * {@code SWIFTDT-...}).
 */
public class SwiftDataTypesAnalyzer extends AbstractAnalyzer {

	static final String NAME = "LZ Swift Data Types";
	private static final String DESCRIPTION =
		"Creates data types for the Swift structs, classes and enums of the binary, with the " +
			"stored properties at their real offsets (from __swift5_types, __swift5_fieldmd " +
			"and the static type metadata), in /SwiftTypes/<Module>.";
	static final String OPTION_PLACEHOLDERS = "Replace demangler placeholders";
	private static final String OPTION_PLACEHOLDERS_DESCRIPTION =
		"Replace the structures that the Swift demangler creates in /Demangler/<Module> for a " +
			"type (1-byte placeholders, or a packed layout of the fields it could demangle) by " +
			"the type's new data type, so that function signatures that use them get the real " +
			"layout.";

	private boolean replacePlaceholders = true;

	/** A byte analyzer, on by default and available as one-shot analysis. */
	public SwiftDataTypesAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// After the Swift and Objective-C metadata analyzers (FORMAT_ANALYSIS) and the demangler
		// (DATA_TYPE_PROPOGATION - 3), whose placeholder types step 3 replaces.
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return SwiftSections.find(program, SwiftSections.TYPES) != null;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_PLACEHOLDERS, replacePlaceholders, null,
			OPTION_PLACEHOLDERS_DESCRIPTION);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		replacePlaceholders = options.getBoolean(OPTION_PLACEHOLDERS, replacePlaceholders);
	}

	/** Counts for the summary lines. */
	static final class Counts {
		int fieldDescriptors, fields, untyped, unreadableFields, symbolicTypes, references,
				unresolved, mismatches;
		int withMetadata, layoutErrors, badOffsets;
		/** By the text of {@link MetadataLocator.Missing}, so the summary lists them in its order. */
		final Map<String, Integer> withoutMetadata = new TreeMap<>();

		/** The field descriptors line; {@code fieldmd} tells whether the section exists. */
		String fieldSummary(boolean fieldmd) {
			return "%s: %d field descriptors, %d fields (%d without type, %d unreadable), "
					.formatted(fieldmd ? SwiftSections.FIELDMD : "no " + SwiftSections.FIELDMD,
						fieldDescriptors, fields, untyped, unreadableFields) +
				"%d field types with symbolic references (%d references, %d unresolved), "
						.formatted(symbolicTypes, references, unresolved) +
				"%d field count mismatches".formatted(mismatches);
		}

		/** The layouts line, with the reasons for missing metadata grouped. */
		String layoutSummary() {
			int without = withoutMetadata.values().stream().mapToInt(Integer::intValue).sum();
			String reasons = withoutMetadata.isEmpty() ? ""
					: " (" + String.join(", ", withoutMetadata.entrySet()
							.stream()
							.map(e -> e.getValue() + " " + e.getKey())
							.toList()) +
						")";
			return "layouts: %d types with static metadata, %d without%s; "
					.formatted(withMetadata, without, reasons) +
				"%d layout errors, %d field offsets out of range".formatted(layoutErrors,
					badOffsets);
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressRange types = SwiftSections.range(program, SwiftSections.TYPES);
		if (types == null || !set.intersects(types.getMinAddress(), types.getMaxAddress())) {
			return false;
		}
		Counts counts = new Counts();
		monitor.setMessage(NAME + ": reading " + SwiftSections.TYPES);
		SwiftTypeCatalog catalog = SwiftTypeCatalog.read(program, types, monitor);
		Map<Address, SwiftTypeInfo> byFields = new LinkedHashMap<>();
		Map<Address, SwiftTypeInfo> infos = new LinkedHashMap<>();
		MetadataLocator locator = new MetadataLocator(program);
		MangledTypeReader reader = catalog.reader();
		Progress.start(monitor, NAME, "layouts", catalog.descriptors().size());
		for (ContextDescriptor d : catalog.descriptors().values()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			SwiftTypeInfo info = layout(program.getMemory(), locator, d, catalog.name(d.address()),
				counts);
			infos.put(d.address(), info);
			if (d.fields() != null) {
				byFields.put(d.fields(), info);
			}
		}
		Set<Address> reported = new HashSet<>();
		AddressRange fieldmd = SwiftSections.range(program, SwiftSections.FIELDMD);
		if (fieldmd != null) {
			Progress.start(monitor, NAME, "reading " + SwiftSections.FIELDMD, fieldmd.getLength());
			reportFieldDescriptors(program, fieldmd, byFields, reader, reported, counts,
				new AnalysisLog(this, log), monitor);
		}
		for (SwiftTypeInfo info : infos.values()) {
			ContextDescriptor d = info.descriptor();
			if (!reported.contains(d.address())) {
				Msg.info(this, "SWIFTTYPE\t%s\t%s\t%s\t\t%s".formatted(d.address(), d.kindName(),
					info.name(), describe(reader, info)));
			}
		}
		List<SwiftTypeInfo> all = new ArrayList<>(infos.values());
		SwiftTypeBuilder builder = new SwiftTypeBuilder(program, reader, all);
		if (replacePlaceholders) {
			monitor.setMessage(NAME + ": moving the demangler's placeholders");
			builder.movePlaceholders(all);
		}
		monitor.setMessage(NAME + ": building data types");
		builder.build(all, monitor);
		if (replacePlaceholders) {
			monitor.setMessage(NAME + ": replacing the demangler's placeholders");
			builder.replacePlaceholders(all, monitor);
		}
		Msg.info(this, NAME + ": " + catalog.summary());
		Msg.info(this, NAME + ": " + counts.fieldSummary(fieldmd != null));
		Msg.info(this, NAME + ": " + counts.layoutSummary());
		Msg.info(this, NAME + ": " + builder.counts().summary());
		return true;
	}

	/**
	 * Finds the static metadata of {@code d} and reads its layout. Generic types and types whose
	 * metadata is built at run time get a reason instead.
	 */
	private SwiftTypeInfo layout(Memory memory, MetadataLocator locator, ContextDescriptor d,
			String name, Counts counts) {
		MetadataLocator.Located located = locator.locate(d);
		if (located.metadata() == null) {
			counts.withoutMetadata.merge(located.missing().text(), 1, Integer::sum);
			return new SwiftTypeInfo(d, name, null, null, located.reason(), new ArrayList<>());
		}
		counts.withMetadata++;
		try {
			SwiftLayout layout = SwiftLayout.read(memory, locator, d, located.metadata());
			counts.badOffsets += layout.offsetsOutside();
			return new SwiftTypeInfo(d, name, located.metadata(), layout, null, new ArrayList<>());
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			counts.layoutErrors++;
			return new SwiftTypeInfo(d, name, located.metadata(), null,
				"layout error at metadata %s: %s".formatted(located.metadata(), e.getMessage()),
				new ArrayList<>());
		}
	}

	/**
	 * Logs the field descriptors of {@code __swift5_fieldmd} in section order: a {@code SWIFTTYPE}
	 * line per descriptor (with the type context descriptor's details, if a type of
	 * {@code __swift5_types} points to it) and a {@code SWIFTFIELD} line per field record, with
	 * the field's offset if the type's layout is known. Adds the field records to the type. Stops
	 * at the first descriptor that does not fit or cannot be read ({@code SWIFTTYPE-BAD}).
	 */
	private void reportFieldDescriptors(Program program, AddressRange fieldmd,
			Map<Address, SwiftTypeInfo> byFields, MangledTypeReader reader, Set<Address> reported,
			Counts counts, AnalysisLog warnings, TaskMonitor monitor) throws CancelledException {
		Memory memory = program.getMemory();
		Address start = fieldmd.getMinAddress();
		WordReader words = WordReader.of(memory, start);
		long end = fieldmd.getMaxAddress().getOffset() + 1;
		Address p = start;
		while (p.compareTo(fieldmd.getMaxAddress()) < 0) {
			monitor.checkCancelled();
			monitor.setProgress(p.subtract(start));
			FieldDescriptors.Descriptor fd;
			try {
				fd = FieldDescriptors.read(p.getOffset(), end, words);
			}
			catch (IllegalStateException e) {
				notReadable(warnings, p, e.getMessage());
				return;
			}
			if (!fd.fits()) {
				warnings.warn("SWIFTTYPE-BAD\t%s\trecord size %d, %d records; stopped"
						.formatted(p, fd.recordSize(), fd.count()),
					("field descriptor at %s has record size %d and %d records; " +
						"the rest of %s was not read").formatted(p, fd.recordSize(), fd.count(),
							SwiftSections.FIELDMD));
				return;
			}
			try {
				reportFieldDescriptor(memory, reader, p, fd, byFields.get(p), reported, counts);
			}
			catch (MemoryAccessException | AddressOutOfBoundsException e) {
				notReadable(warnings, p, e.getMessage());
				return;
			}
			p = p.getNewAddress(fd.end());
		}
	}

	private static void notReadable(AnalysisLog warnings, Address descriptor, String message) {
		warnings.warn("SWIFTTYPE-BAD\t%s\t%s; stopped".formatted(descriptor, message),
			"field descriptor at %s not readable (%s); the rest of %s was not read"
					.formatted(descriptor, message, SwiftSections.FIELDMD));
	}

	/**
	 * Logs the field descriptor {@code fd} at {@code descriptor} and its records, and adds the
	 * records to {@code info}, the type that points to it (or null).
	 */
	private void reportFieldDescriptor(Memory memory, MangledTypeReader reader,
			Address descriptor, FieldDescriptors.Descriptor fd, SwiftTypeInfo info,
			Set<Address> reported, Counts counts) throws MemoryAccessException {
		counts.fieldDescriptors++;
		Address typeName = address(descriptor, fd.typeName());
		String name = typeName != null ? fieldTypeName(reader, typeName) : "?";
		long[] offsets =
			info != null && info.layout() != null ? info.layout().offsetArray() : new long[0];
		String details = details(reader, info, fd.count(), reported, counts);
		Msg.info(this, "SWIFTTYPE\t%s\t%s\t%s\t%d fields\t%s".formatted(descriptor,
			fd.kindName(), name, fd.count(), details));
		for (int i = 0; i < fd.records().size(); i++) {
			SwiftTypeInfo.Field field = reportField(memory, reader, descriptor,
				fd.records().get(i), i < offsets.length ? Long.toString(offsets[i]) : "", counts);
			if (info != null) {
				info.fields().add(field);
			}
		}
	}

	/** The address {@code offset} in the space of {@code space}, or null for 0. */
	private static Address address(Address space, long offset) {
		return offset == 0 ? null : space.getNewAddress(offset);
	}

	/** The name of a field descriptor's type, from its mangled name at {@code typeName}. */
	private static String fieldTypeName(MangledTypeReader reader, Address typeName)
			throws MemoryAccessException {
		MangledName mangled = reader.read(typeName);
		MangledName.Reference sole = mangled.soleReference();
		return sole == null ? reader.render(typeName, mangled)
				: Objects.requireNonNullElse(reader.referenceName(typeName, sole), "?");
	}

	/**
	 * The type context descriptor's details for the {@code SWIFTTYPE} line, empty if no type of
	 * {@code __swift5_types} points to the field descriptor. Marks the type as reported and
	 * counts a field count mismatch.
	 */
	private static String details(MangledTypeReader reader, SwiftTypeInfo info, int numRecords,
			Set<Address> reported, Counts counts) {
		ContextDescriptor type = info != null ? info.descriptor() : null;
		if (type == null) {
			return "";
		}
		reported.add(type.address());
		boolean mismatch =
			type.kind() != ContextDescriptor.KIND_ENUM && type.numFields() != numRecords;
		if (mismatch) {
			counts.mismatches++;
		}
		return describe(reader, info) + (mismatch ? "\tFIELD COUNT MISMATCH" : "");
	}

	/** Logs the field record {@code r} and returns it with its name and type resolved. */
	private SwiftTypeInfo.Field reportField(Memory memory, MangledTypeReader reader, Address space,
			FieldDescriptors.FieldRecord r, String offset, Counts counts) {
		counts.fields++;
		Address record = space.getNewAddress(r.address());
		String name;
		String type = "";
		Address typeName;
		MangledName mangled = null;
		try {
			name = ContextDescriptor.cString(memory, address(space, r.name()));
			typeName = address(space, r.typeName());
			if (typeName == null) {
				counts.untyped++;
			}
			else {
				mangled = reader.read(typeName);
				List<MangledName.Reference> refs = mangled.references();
				if (!refs.isEmpty()) {
					counts.symbolicTypes++;
					counts.references += refs.size();
					for (MangledName.Reference ref : refs) {
						if (reader.referenceName(typeName, ref) == null) {
							counts.unresolved++;
						}
					}
				}
				type = reader.render(typeName, mangled);
			}
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			counts.unreadableFields++;
			name = "?";
			type = "? " + e.getMessage();
			typeName = null;
			mangled = null;
		}
		Msg.info(this, "SWIFTFIELD\t%s\t%s\t%s\t%s\t%s".formatted(record, offset, name, type,
			r.flagNames()));
		return new SwiftTypeInfo.Field(record, name, typeName, mangled, r.flags());
	}

	/** The type's details for the log, with its superclass rendered ("?" if unreadable). */
	private static String describe(MangledTypeReader reader, SwiftTypeInfo info) {
		Address superclass = info.descriptor().superclass();
		if (superclass == null) {
			return info.describe(null);
		}
		String name;
		try {
			name = reader.render(superclass, reader.read(superclass));
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			name = "?";
		}
		return info.describe(name);
	}
}
