// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.types;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import lzghidraswift.mangling.MangledName;
import lzghidraswift.mangling.MangledTypeReader;
import lzghidraswift.mangling.SwiftTypeName;
import lzghidraswift.mangling.SwiftTypeName.Nominal;
import lzghidraswift.metadata.ContextDescriptor;
import lzghidraswift.types.SwiftTypeMapper.Mapped;

/**
 * Creates the data types for the types of {@code __swift5_types} that have a static layout, in
 * {@code /SwiftTypes/<Module>/<Outer>/<Name>}:
 * <ul>
 * <li>structs: a structure of the Swift size (not the stride) and alignment, each stored property
 * at its offset from the field offset vector;</li>
 * <li>classes: a structure of the instance size: the object header (Swift root class), the
 * {@code isa} (Objective-C superclass) or the superclass's structure as {@code super}, then the
 * class's own stored properties;</li>
 * <li>enums without payload: an enum data type with the case names, valued by declaration
 * order (the tag).</li>
 * </ul>
 * A field whose type does not map ({@link SwiftTypeMapper}), or does not fit before the next
 * field, becomes undefined bytes up to the next field; its comment still names the Swift type.
 * <p>
 * Running it again changes nothing: a type that exists with the same path is replaced only if it
 * differs. Optionally, the structures that Ghidra's Swift demangler creates in
 * {@code /Demangler/<Module>} for a type (1-byte placeholders, or a packed C layout of the fields
 * whose types it could demangle) are replaced by the new type, so that signatures using them get
 * the real layout: a placeholder for a structure is moved to the new type's path before the build
 * fills it in ({@link #movePlaceholders}), the others are replaced after it
 * ({@link #replacePlaceholders}).
 */
public class SwiftTypeBuilder implements SwiftTypeMapper.OwnTypes {

	/** Adds a data type to the program, or finds it there; null if a different kind is in the way. */
	public interface Installer {
		DataType install(DataType type);
	}

	/** Counts for the summary line. */
	public static final class Counts {
		public int structs, classes, enums, skipped, fields, typed, undefined, tooLarge, zeroSize,
				created, replaced, unchanged, conflicts, placeholders, placeholdersKept;

		/** The summary line, after {@code "<analyzer>: "}. */
		public String summary() {
			return "data types: %d structs, %d classes, %d enums, %d types skipped; "
					.formatted(structs, classes, enums, skipped) +
				"%d fields: %d typed, %d undefined (%d too large for their space), %d of size 0; "
						.formatted(fields, typed, undefined, tooLarge, zeroSize) +
				"%d data types created, %d replaced, %d unchanged, %d in conflict; "
						.formatted(created, replaced, unchanged, conflicts) +
				"placeholders: %d replaced, %d kept".formatted(placeholders, placeholdersKept);
		}
	}

	/** Marks the descriptions of the data types this builder creates; see {@link #find}. */
	private static final String DESCRIPTION_TAG = "(LZ Swift Data Types";

	public static final String DEMANGLER = "/Demangler";

	private enum State {
		BUILDING, DONE
	}

	private final Program program;
	private final DataTypeManager dtm;
	private final MangledTypeReader reader;
	private final Map<Address, SwiftTypeInfo> byDescriptor = new HashMap<>();
	private final Map<Address, State> state = new HashMap<>();
	private final Map<Address, DataType> built = new HashMap<>();
	private final Set<String> installedPaths = new HashSet<>();
	/**
	 * Class shells created in this run and placeholders moved to their type's path: filling them
	 * in counts as creating them.
	 */
	private final Set<String> shells = new HashSet<>();
	/** The placeholders moved by {@link #movePlaceholders}, by descriptor. */
	private final Map<Address, Moved> moved = new HashMap<>();
	/** Paths of moved placeholders that {@link #install} has not filled in yet. */
	private final Set<String> unfilled = new HashSet<>();

	/** A placeholder moved to its type's path: its old path and length, for the log line. */
	private record Moved(DataType placeholder, CategoryPath from, int length) {}

	private final SwiftTypeMapper mapper;
	private final Counts counts = new Counts();

	/**
	 * A builder for the types in {@code types}. A field whose type is one of them gets the new data
	 * type; other field types are mapped by {@link SwiftTypeMapper}.
	 */
	public SwiftTypeBuilder(Program program, MangledTypeReader reader, List<SwiftTypeInfo> types) {
		this.program = program;
		this.dtm = program.getDataTypeManager();
		this.reader = reader;
		for (SwiftTypeInfo info : types) {
			byDescriptor.put(info.descriptor().address(), info);
		}
		this.mapper = new SwiftTypeMapper(dtm, this, this::install);
	}

	public Counts counts() {
		return counts;
	}

	/**
	 * Builds every type. Initializes {@code monitor} to the number of types; the caller sets the
	 * message.
	 */
	public void build(List<SwiftTypeInfo> types, TaskMonitor monitor) throws CancelledException {
		// Class structures first, as empty shells of the right size: fields of other types point
		// to them, and class references can form cycles.
		for (SwiftTypeInfo info : types) {
			if (info.descriptor().kind() == ContextDescriptor.KIND_CLASS && skip(info) == null) {
				shell(info);
			}
		}
		monitor.initialize(types.size());
		for (SwiftTypeInfo info : types) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			build(info);
		}
	}

	/**
	 * Moves the demangler's structure placeholder of each struct and class that will get a
	 * structure to the path of that structure, if nothing is there yet. {@link #build} then
	 * fills it in with {@code replaceWith}, and every use of the placeholder keeps its ID. That
	 * avoids {@code replaceDataType}, which reads all defined data, symbols and functions of the
	 * program for each call: 0.72 s per placeholder in a 377281-function arm64 app, 2214
	 * placeholders, on an M5 Mac with 24 GB, 2026-10-30. Call before {@link #build}.
	 */
	public void movePlaceholders(List<SwiftTypeInfo> types) {
		for (SwiftTypeInfo info : types) {
			int kind = info.descriptor().kind();
			if ((kind != ContextDescriptor.KIND_STRUCT && kind != ContextDescriptor.KIND_CLASS) ||
				skip(info) != null) {
				continue;
			}
			CategoryPath from = demanglerCategory(info.name());
			DataType placeholder = dtm.getDataType(from, simpleName(info.name()));
			CategoryPath to = category(info.name());
			if (!(placeholder instanceof Structure) ||
				dtm.getDataType(to, simpleName(info.name())) != null) {
				continue;
			}
			int length = placeholder.getLength();
			try {
				placeholder.setCategoryPath(to);
			}
			catch (DuplicateNameException e) {
				continue; // replaced after the build, as the other placeholders
			}
			moved.put(info.descriptor().address(), new Moved(placeholder, from, length));
			shells.add(placeholder.getPathName());
			unfilled.add(placeholder.getPathName());
		}
	}

	/**
	 * Replaces the demangler's placeholders that {@link #movePlaceholders} did not move by the
	 * types {@link #build} built. Slow: 12.5 minutes for 6066 types in a 430984-function arm64
	 * app, on an M5 Mac with 24 GB, 2026-10-26.
	 * Initializes {@code monitor} to the number of types; the caller sets the message.
	 */
	public void replacePlaceholders(List<SwiftTypeInfo> types, TaskMonitor monitor)
			throws CancelledException {
		monitor.initialize(types.size());
		for (SwiftTypeInfo info : types) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			DataType type = built.get(info.descriptor().address());
			Moved m = moved.get(info.descriptor().address());
			if (m != null) {
				filled(m, type);
			}
			else if (type != null) {
				replacePlaceholder(info, type);
			}
		}
	}

	// --- types of the binary

	@Override
	public Mapped own(Nominal type) {
		if (!(type.target() instanceof Address descriptor)) {
			return null;
		}
		SwiftTypeInfo info = byDescriptor.get(descriptor);
		if (info == null) {
			return null;
		}
		if (info.descriptor().kind() == ContextDescriptor.KIND_CLASS) {
			// The shell or the finished structure: classes may refer to each other in cycles.
			DataType dt = skip(info) == null
					? dtm.getDataType(category(info.name()), simpleName(info.name()))
					: null;
			return new Mapped(new PointerDataType(dt != null ? dt : VoidDataType.dataType, dtm),
				8, 8, SwiftLayout.MANY);
		}
		DataType dt = build(info);
		SwiftLayout layout = info.layout();
		if (dt == null) {
			// A skipped type of size 0 (an enum with one case or none) takes no space; known
			// as such, it cannot be mistaken for a field that fills the gap.
			return layout != null && layout.size() == 0
					? new Mapped(null, 0, layout.alignment(), layout.extraInhabitants())
					: null;
		}
		return new Mapped(dt, layout.size(), layout.alignment(), layout.extraInhabitants());
	}

	@Override
	public Boolean classConstrained(Nominal protocol) {
		if (!(protocol.target() instanceof Address descriptor)) {
			return null;
		}
		try {
			ContextDescriptor d = ContextDescriptor.read(program.getMemory(), descriptor);
			return d.kind() == ContextDescriptor.KIND_PROTOCOL ? d.isClassConstrained() : null;
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * Why a type gets no data type, or null: the analyzer's reason (no static metadata, payload
	 * enum, ...), or for a class a superclass chain that reaches an Objective-C class other than
	 * NSObject. The binary lays such a class's own fields out after an 8-byte isa; the
	 * Objective-C runtime slides them past the superclass's ivars at load time, and the
	 * superclass's size is not in the binary (sourcekit-lsp's TSCBasic.ThreadImpl: NSThread, own
	 * fields 56 bytes further at run time; Layouts fixture: Worker, SubWorker).
	 */
	private String skip(SwiftTypeInfo info) {
		if (info.skip() != null || info.descriptor().kind() != ContextDescriptor.KIND_CLASS) {
			return info.skip();
		}
		// Not computeIfAbsent: the superclass's answer is computed recursively, and a map must not
		// change inside computeIfAbsent (ConcurrentModificationException on swift-format).
		Address key = info.descriptor().address();
		Optional<String> cached = slid.get(key);
		if (cached == null) {
			slid.put(key, Optional.empty()); // a cycle in superclasses ends here
			cached = Optional.ofNullable(slidSuperclass(info));
			slid.put(key, cached);
		}
		return cached.orElse(null);
	}

	private String slidSuperclass(SwiftTypeInfo info) {
		Nominal sup = superclass(info);
		if (sup == null) {
			return null;
		}
		if (sup.target() instanceof Address d && byDescriptor.get(d) != null) {
			String inherited = skip(byDescriptor.get(d));
			return inherited != null && inherited.startsWith(SLID) ? inherited : null;
		}
		String name = SwiftTypeName.renderField(sup);
		return sup.objc() && !name.equals("NSObject")
				? SLID + name + ": field offsets are slid at run time"
				: null;
	}

	private static final String SLID = "Objective-C superclass ";
	/** Per class descriptor: the reason from {@link #slidSuperclass}, or empty for none. */
	private final Map<Address, Optional<String>> slid = new HashMap<>();

	/** The superclass as a nominal type, or null for a Swift root class or if unreadable. */
	private Nominal superclass(SwiftTypeInfo info) {
		Address superclassName = info.descriptor().superclass();
		if (superclassName == null) {
			return null;
		}
		try {
			MangledName mangled = reader.read(superclassName);
			return SwiftTypeName.parse(mangled,
				ref -> reader.nominal(superclassName, ref)) instanceof Nominal n ? n : null;
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	/** Builds the data type of one type (once), after the types it embeds. */
	private DataType build(SwiftTypeInfo info) {
		Address key = info.descriptor().address();
		if (state.get(key) == State.DONE) {
			return built.get(key);
		}
		if (state.get(key) == State.BUILDING) {
			// Value types cannot contain themselves; a cycle here means bad metadata.
			Msg.warn(this, "SWIFTDT-WARN\t%s\tcycle through this type".formatted(info.name()));
			return null;
		}
		state.put(key, State.BUILDING);
		DataType result = null;
		String skip = skip(info);
		if (skip != null) {
			counts.skipped++;
			Msg.info(this, "SWIFTDT-SKIP\t%s\t%s".formatted(info.name(), skip));
		}
		else {
			result = switch (info.descriptor().kind()) {
				case ContextDescriptor.KIND_STRUCT -> structure(info);
				case ContextDescriptor.KIND_CLASS -> classStructure(info);
				case ContextDescriptor.KIND_ENUM -> enumeration(info);
				default -> null;
			};
		}
		built.put(key, result);
		state.put(key, State.DONE);
		return result;
	}

	private DataType structure(SwiftTypeInfo info) {
		SwiftLayout layout = info.layout();
		StructureDataType s = new StructureDataType(category(info.name()), simpleName(info.name()),
			(int) layout.size(), dtm);
		s.setExplicitMinimumAlignment(layout.alignment());
		s.setDescription("Swift struct %s %s: size %d, stride %d, metadata %s)".formatted(
			info.name(), DESCRIPTION_TAG, layout.size(), layout.stride(), info.metadata()));
		placeFields(s, info, layout.size());
		counts.structs++;
		return install(s);
	}

	/**
	 * A class instance. The length is the instance size from the metadata, which is not rounded
	 * up to the alignment (Swift lays a subclass's fields out from the unrounded size).
	 */
	private DataType classStructure(SwiftTypeInfo info) {
		SwiftLayout layout = info.layout();
		StructureDataType s = new StructureDataType(category(info.name()), simpleName(info.name()),
			(int) layout.size(), dtm);
		s.setExplicitMinimumAlignment(layout.alignment());
		long firstField = Arrays.stream(layout.offsetArray()).min().orElse(layout.size());
		String superclass = header(s, info, firstField);
		s.setDescription("Swift class %s; superclass %s %s: instance size %d, metadata %s)"
				.formatted(info.name(), superclass, DESCRIPTION_TAG, layout.size(),
					info.metadata()));
		placeFields(s, info, layout.size());
		counts.classes++;
		return install(s);
	}

	/**
	 * The part of a class instance before its own fields. Returns the superclass's name for the
	 * description: "none" for a Swift root class.
	 */
	private String header(StructureDataType s, SwiftTypeInfo info, long firstField) {
		DataType voidPointer = new PointerDataType(VoidDataType.dataType, dtm);
		Address superclassName = info.descriptor().superclass();
		if (superclassName == null) {
			// HeapObject (swift/shims/HeapObject.h): metadata, then the inline reference counts.
			if (firstField >= 16) {
				s.replaceAtOffset(0, voidPointer, 8, "metadata",
					"Swift object header: class metadata");
				s.replaceAtOffset(8, UnsignedLongLongDataType.dataType, 8, "refCounts",
					"Swift object header: reference counts");
			}
			return "none";
		}
		SwiftTypeName parsed = null;
		try {
			MangledName mangled = reader.read(superclassName);
			parsed = SwiftTypeName.parse(mangled, ref -> reader.nominal(superclassName, ref));
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			// below
		}
		if (!(parsed instanceof Nominal sup)) {
			return "?";
		}
		if (sup.target() instanceof Address d && byDescriptor.containsKey(d)) {
			DataType superType = build(byDescriptor.get(d));
			if (superType != null && superType.getLength() <= firstField) {
				s.replaceAtOffset(0, superType, superType.getLength(), "super",
					"superclass " + sup.render());
			}
		}
		else if (sup.objc() && firstField >= 8) {
			s.replaceAtOffset(0, voidPointer, 8, "isa", "Objective-C object header");
		}
		// As the Objective-C runtime names it: NSObject, not __C.NSObject.
		return SwiftTypeName.renderField(sup);
	}

	/**
	 * Puts each field at its offset. The space a field may take is the distance to the next
	 * larger offset (or to {@code end}); this includes padding, so an undefined field may be a
	 * few bytes longer than the Swift type. Fields of size 0 share their offset with the next
	 * field (or sit at {@code end}); a field of unknown size that shares its offset with a field
	 * of known, non-zero size is taken to be of size 0, so it does not replace that field.
	 */
	private void placeFields(StructureDataType s, SwiftTypeInfo info, long end) {
		long[] offsets = info.layout().offsetArray();
		long[] sorted = offsets.clone();
		Arrays.sort(sorted);
		List<SwiftTypeInfo.Field> fields = info.fields();
		int n = Math.min(fields.size(), offsets.length);
		String[] swiftTypes = new String[n];
		Mapped[] mapped = new Mapped[n];
		Set<Long> occupied = new HashSet<>();
		for (int i = 0; i < n; i++) {
			SwiftTypeInfo.Field f = fields.get(i);
			SwiftTypeName parsed = f.type() == null ? null
					: SwiftTypeName.parse(f.type(), ref -> reader.nominal(f.typeAt(), ref));
			swiftTypes[i] = parsed != null ? SwiftTypeName.renderField(parsed)
					: f.type() != null ? reader.render(f.typeAt(), f.type()) : "?";
			mapped[i] = parsed != null ? mapper.map(parsed) : null;
			if (mapped[i] != null && mapped[i].size() > 0) {
				occupied.add(offsets[i]);
			}
		}
		for (int i = 0; i < n; i++) {
			SwiftTypeInfo.Field f = fields.get(i);
			counts.fields++;
			long offset = offsets[i];
			long gap = gap(sorted, offset, end);
			String swiftType = swiftTypes[i];
			Mapped m = mapped[i];
			if (m == null && occupied.contains(offset)) {
				counts.zeroSize++;
				Msg.info(this, "SWIFTDT-ZERO\t%s.%s\t%s shares offset %d with a field of known size"
						.formatted(info.name(), f.name(), swiftType, offset));
				continue;
			}
			if ((m != null && m.size() == 0) || gap <= 0) {
				counts.zeroSize++;
				continue;
			}
			placeField(s, info, f, offset, gap, swiftType, m);
		}
	}

	/** The distance from {@code offset} to the next larger of the sorted offsets, or to {@code end}. */
	private static long gap(long[] sorted, long offset, long end) {
		for (long o : sorted) {
			if (o > offset) {
				return o - offset;
			}
		}
		return end - offset;
	}

	/**
	 * Puts field {@code f} at {@code offset}: with its mapped type if that is known and fits in
	 * {@code gap} bytes, else as an undefined of {@code gap} bytes.
	 */
	private void placeField(StructureDataType s, SwiftTypeInfo info, SwiftTypeInfo.Field f,
			long offset, long gap, String swiftType, Mapped m) {
		DataType type;
		int length;
		if (m != null && m.type() != null && m.size() <= gap) {
			type = m.type();
			length = (int) m.size();
			counts.typed++;
		}
		else {
			if (m != null) {
				counts.tooLarge++;
				Msg.warn(this, "SWIFTDT-WARN\t%s.%s\t%s (%d bytes) does not fit in %d bytes"
						.formatted(info.name(), f.name(), swiftType, m.size(), gap));
			}
			type = Undefined.getUndefinedDataType((int) gap);
			length = (int) gap;
			counts.undefined++;
		}
		s.replaceAtOffset((int) offset, type, length, f.name(), swiftType);
	}

	/** An enum without payload: one value per case, in declaration order. */
	private DataType enumeration(SwiftTypeInfo info) {
		SwiftLayout layout = info.layout();
		if (!List.of(1L, 2L, 4L, 8L).contains(layout.size())) {
			counts.skipped++;
			Msg.info(this,
				"SWIFTDT-SKIP\t%s\tenum of size %d".formatted(info.name(), layout.size()));
			return null;
		}
		if (info.fields().isEmpty()) {
			// @objc enums have no field descriptor, hence no case names; their size is that of
			// the raw value (for example an 8-byte raw value).
			counts.skipped++;
			Msg.info(this, "SWIFTDT-SKIP\t%s\tno case names (no field descriptor)"
					.formatted(info.name()));
			return null;
		}
		EnumDataType e = new EnumDataType(category(info.name()), simpleName(info.name()),
			(int) layout.size(), dtm);
		for (int i = 0; i < info.fields().size(); i++) {
			e.add(info.fields().get(i).name(), i);
		}
		e.setDescription("Swift enum %s %s: tag values, metadata %s)".formatted(info.name(),
			DESCRIPTION_TAG, info.metadata()));
		counts.enums++;
		return install(e);
	}

	/** Creates an empty class structure of the instance size if none exists. */
	private void shell(SwiftTypeInfo info) {
		CategoryPath category = category(info.name());
		String name = simpleName(info.name());
		if (dtm.getDataType(category, name) == null) {
			StructureDataType s = new StructureDataType(category, name,
				(int) info.layout().size(), dtm);
			s.setExplicitMinimumAlignment(info.layout().alignment());
			dtm.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER);
			shells.add(s.getPathName());
		}
	}

	/**
	 * Adds {@code type} to the program, or replaces the type with the same path if it differs.
	 * Returns the program's type, or null if a type of another kind has that path.
	 */
	DataType install(DataType type) {
		DataType existing = dtm.getDataType(type.getCategoryPath(), type.getName());
		boolean first = installedPaths.add(type.getPathName());
		if (existing == null) {
			counts.created++;
			return dtm.addDataType(type, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		// A moved placeholder is always filled in: it lacks the description.
		if (!unfilled.remove(type.getPathName()) && existing.isEquivalent(type)) {
			if (first) {
				counts.unchanged++;
			}
			return existing;
		}
		try {
			existing.replaceWith(type);
			if (shells.contains(type.getPathName())) {
				counts.created++;
			}
			else {
				counts.replaced++;
			}
			return existing;
		}
		catch (IllegalArgumentException | UnsupportedOperationException e) {
			counts.conflicts++;
			Msg.warn(this, "SWIFTDT-WARN\t%s\tnot replaced: %s".formatted(type.getPathName(),
				e.getMessage()));
			return null;
		}
	}

	/**
	 * Replaces the structure {@code /Demangler/<Module>/.../<Name>} by the new type; every use of
	 * it then uses the new type. The demangler's structure is a 1-byte placeholder, or its own
	 * layout of the fields whose types it demangled, packed without Swift's alignment: wrong
	 * whenever its size differs (Layouts fixture: Collections 3 bytes, Swift 40; Composite 16,
	 * Swift 148), and possibly wrong also when it does not. Other kinds of data type are kept.
	 */
	private void replacePlaceholder(SwiftTypeInfo info, DataType type) {
		CategoryPath category = demanglerCategory(info.name());
		DataType placeholder = dtm.getDataType(category, simpleName(info.name()));
		if (placeholder == null || placeholder.equals(type)) {
			return;
		}
		if (!(placeholder instanceof Structure)) {
			counts.placeholdersKept++;
			Msg.info(this, "SWIFTDT-PLACEHOLDER\t%s\tkept: %s, %d bytes".formatted(
				placeholder.getPathName(), placeholder.getClass().getSimpleName(),
				placeholder.getLength()));
			return;
		}
		int length = placeholder.getLength();
		try {
			dtm.replaceDataType(placeholder, type, false);
			counts.placeholders++;
			Msg.info(this, "SWIFTDT-PLACEHOLDER\t%s\treplaced by %s (was %d bytes)".formatted(
				category.getPath() + "/" + simpleName(info.name()), type.getPathName(), length));
		}
		catch (DataTypeDependencyException | IllegalArgumentException e) {
			counts.placeholdersKept++;
			Msg.warn(this, "SWIFTDT-WARN\t%s\tplaceholder not replaced: %s".formatted(
				placeholder.getPathName(), e.getMessage()));
		}
	}

	/**
	 * Counts and logs a placeholder moved by {@link #movePlaceholders} as replaced, if the build
	 * filled it in; otherwise moves it back to the demangler's category and keeps it.
	 */
	private void filled(Moved m, DataType type) {
		String from = m.from().getPath() + "/" + m.placeholder().getName();
		if (m.placeholder().equals(type) && !unfilled.contains(type.getPathName())) {
			counts.placeholders++;
			Msg.info(this, "SWIFTDT-PLACEHOLDER\t%s\treplaced by %s (was %d bytes)".formatted(
				from, type.getPathName(), m.length()));
			return;
		}
		counts.placeholdersKept++;
		String why = "not filled in by the build";
		try {
			unfilled.remove(m.placeholder().getPathName());
			m.placeholder().setCategoryPath(m.from());
		}
		catch (DuplicateNameException e) {
			why += ", and not moved back: " + e.getMessage();
		}
		Msg.warn(this, "SWIFTDT-WARN\t%s\tplaceholder not replaced: %s".formatted(from, why));
	}

	// --- names

	/**
	 * {@code Layouts.Outer.Inner} → Layouts, Outer, Inner. Dots inside angle brackets or
	 * parentheses (an extension's rendered type) do not split; slashes are replaced.
	 */
	static List<String> nameParts(String qualified) {
		List<String> parts = new ArrayList<>();
		int depth = 0;
		StringBuilder part = new StringBuilder();
		for (int i = 0; i < qualified.length(); i++) {
			char c = qualified.charAt(i);
			if (c == '<' || c == '(') {
				depth++;
			}
			else if (c == '>' || c == ')') {
				depth--;
			}
			if (c == '.' && depth == 0) {
				parts.add(part.toString());
				part.setLength(0);
			}
			else {
				part.append(c == '/' ? '_' : c);
			}
		}
		parts.add(part.toString());
		return parts;
	}

	/** The category of the demangler's placeholder: {@code /Demangler/<Module>/<Outer>}. */
	private static CategoryPath demanglerCategory(String qualified) {
		List<String> parts = nameParts(qualified);
		return new CategoryPath(new CategoryPath(DEMANGLER), parts.subList(0, parts.size() - 1));
	}

	static CategoryPath category(String qualified) {
		List<String> parts = nameParts(qualified);
		return new CategoryPath(SwiftTypeMapper.ROOT, parts.subList(0, parts.size() - 1));
	}

	static String simpleName(String qualified) {
		List<String> parts = nameParts(qualified);
		return parts.getLast();
	}

	/**
	 * The data type an earlier run built for {@code d} (named {@code name}), found by its path
	 * and checked by its description; null if there is none (skipped types, generic types) or if
	 * another data type has the path.
	 */
	public static DataType find(DataTypeManager dtm, ContextDescriptor d, String name) {
		if (!d.isType() || d.isGeneric() || name == null) {
			return null;
		}
		DataType type = dtm.getDataType(category(name), simpleName(name));
		if (!(type instanceof Structure || type instanceof Enum)) {
			return null;
		}
		String description = type.getDescription();
		return description != null && description.startsWith("Swift " + d.kindName() + " ") &&
			description.contains(DESCRIPTION_TAG) ? type : null;
	}
}
