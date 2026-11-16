// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import lzghidraswift.abi.CallingConventions;
import lzghidraswift.flow.SelfRegisterUse;
import lzghidraswift.metadata.ClassMethods;
import lzghidraswift.metadata.ContextDescriptor;
import lzghidraswift.metadata.MetadataLocator;
import lzghidraswift.metadata.SwiftSections;
import lzghidraswift.metadata.SymbolNames;
import lzghidraswift.runtime.RuntimeTypes;
import lzghidraswift.strings.DecompilerPool;
import lzghidraswift.types.SelfCandidates;
import lzghidraswift.types.SelfCandidates.Candidate;
import lzghidraswift.types.SwiftTypeBuilder;
import lzghidraswift.types.SwiftTypeCatalog;

/**
 * Gives the methods of the Swift types that Swift Data Types built a parameter {@code self} in
 * the context register (x20 on AArch64, r13 on x86_64), typed as a pointer to the type's data
 * type, so that the decompiler shows {@code self->field}.
 * <p>
 * Methods come from the class descriptors' method and override tables ({@link ClassMethods};
 * Swift passes a class's self in the context register in every instance method), and from Swift
 * symbols of members of the types; {@link SelfCandidates} collects both. A struct or enum method
 * gets self there only when it takes it inout (mutating, setters), so those must read the
 * register's entry value ({@link SelfRegisterUse}). A function found for more than one type is
 * left alone.
 * <p>
 * A class's allocating initializers get their self, the metatype, in the register too: the
 * class's metadata, typed {@code Metadata *} as in the runtime functions' signatures. They are
 * found by their symbols, also for classes without a data type (generic classes). Ghidra 12.2's
 * demangler gives them {@code __swift_thiscall} with {@code void *this}.
 * <p>
 * {@code self} needs custom storage, which locks the prototype: the decompiler then stops
 * inferring the other parameters. So the parameters the decompiler finds in a function without a
 * signature are committed first, as Decompiler Parameter ID does. Functions with a user-defined
 * signature are not changed; running it again changes nothing.
 */
public class SwiftSelfTypesAnalyzer extends AbstractAnalyzer {

	static final String NAME = "LZ Swift Self Types";
	private static final String DESCRIPTION =
		"Adds a parameter self in the Swift context register (x20, r13), typed as a pointer to " +
			"the data type from LZ Swift Data Types, to the methods of each Swift class, struct and " +
			"enum (from the class method tables and from Swift symbols). Commits the decompiler's " +
			"parameters of a function without a signature first.";
	static final String SELF = "self";
	private static final int DECOMPILE_TIMEOUT = 60;

	/** Counts for the summary lines. */
	private static final class Counts {
		int types;
		int added, updated, unchanged, conflicts, noFunction, thunks, userDefined, notReading,
				decompileFailed, failed;

		/** The candidates line, after {@code "<analyzer>: "}. */
		String candidateSummary(SelfCandidates.Counts candidates) {
			return "%d types with data types; ".formatted(types) + candidates.summary();
		}

		/** The results line, after {@code "<analyzer>: "}. */
		String resultSummary(Register register, double seconds) {
			String r = register.getName();
			return "self added to %d functions; ".formatted(added) +
				"self replaced another parameter in %s (the demangler's this) in %d; "
						.formatted(r, updated) +
				"unchanged in %d; ".formatted(unchanged) +
				"not typed: %d conflicts, %d without function, %d thunks, "
						.formatted(conflicts, noFunction, thunks) +
				"%d user-defined signatures, %d value-type methods that do not read %s, "
						.formatted(userDefined, notReading, r) +
				"%d decompiler failures, %d update failures; %.2f s".formatted(decompileFailed,
					failed, seconds);
		}
	}

	/** A byte analyzer, on by default and available as one-shot analysis. */
	public SwiftSelfTypesAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// After Swift Data Types (DATA_TYPE_PROPOGATION - 1), whose types it applies, and before
		// Swift String Literals, whose decompiler equates depend on function signatures.
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return CallingConventions.isSwiftTarget(program) &&
			SwiftSections.find(program, SwiftSections.TYPES) != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressRange typesRange = SwiftSections.range(program, SwiftSections.TYPES);
		Register register = CallingConventions.selfRegister(program);
		if (typesRange == null || register == null ||
			!set.intersects(typesRange.getMinAddress(), typesRange.getMaxAddress())) {
			return false;
		}
		long start = System.nanoTime();
		Counts counts = new Counts();
		AnalysisLog warnings = new AnalysisLog(this, log);
		monitor.setMessage(NAME + ": reading " + SwiftSections.TYPES);
		SwiftTypeCatalog catalog = SwiftTypeCatalog.read(program, typesRange, monitor);
		Map<Address, ContextDescriptor> descriptors = catalog.descriptors();
		Map<Address, DataType> selfTypes = new LinkedHashMap<>();
		for (ContextDescriptor d : descriptors.values()) {
			DataType type =
				SwiftTypeBuilder.find(program.getDataTypeManager(), d, catalog.name(d.address()));
			if (type != null) {
				selfTypes.put(d.address(), type);
			}
		}
		counts.types = selfTypes.size();
		SelfCandidates candidates = SelfCandidates.of(program, descriptors, selfTypes.keySet());
		classMethods(program, catalog, selfTypes.keySet(), candidates, warnings, monitor);
		symbolMethods(program, candidates, monitor);
		Progress.start(monitor, NAME, "typing self", candidates.candidates().size());
		DecompInterface decompiler = null;
		boolean decompilerOpened = false;
		try {
			for (Map.Entry<Address, Candidate> e : candidates.candidates().entrySet()) {
				monitor.checkCancelled();
				monitor.incrementProgress(1);
				Candidate c = e.getValue();
				Function f = check(program, e.getKey(), c, register, catalog, counts);
				if (f == null) {
					continue;
				}
				DataType type = selfTypes.get(c.type());
				DataType self = selfType(program, c, type);
				if (hasSelf(f, register, self)) {
					counts.unchanged++;
					continue;
				}
				if (needsParameters(f)) {
					if (!decompilerOpened) {
						// Once: if it does not start, each function below fails on its own.
						decompilerOpened = true;
						decompiler = DecompilerPool.open(program,
							message -> warnings.warn("SWIFTSELF-DECOMP-NOSTART\t" + message,
								"decompiler did not start: " + message));
					}
					if (decompiler == null || !commitParameters(decompiler, f, monitor)) {
						counts.decompileFailed++;
						warnings.warn(
							"SWIFTSELF-DECOMP-FAILED\t%s\t%s".formatted(f.getEntryPoint(),
								f.getName()),
							"%s at %s: decompiler failed; self not typed".formatted(f.getName(),
								f.getEntryPoint()));
						continue;
					}
				}
				boolean isClass = descriptors.get(c.type()).kind() == ContextDescriptor.KIND_CLASS;
				applySelf(program, f, register, self, type, isClass, c, counts);
			}
		}
		finally {
			if (decompiler != null) {
				decompiler.dispose();
			}
		}
		Msg.info(this, NAME + ": " + counts.candidateSummary(candidates.counts()));
		Msg.info(this, NAME + ": " +
			counts.resultSummary(register, (System.nanoTime() - start) / 1e9));
		return true;
	}

	/**
	 * The instance methods of the method tables of the classes among {@code typed}, and their
	 * overrides of methods of the binary; logs the vtable entries that differ.
	 */
	private void classMethods(Program program, SwiftTypeCatalog catalog, Set<Address> typed,
			SelfCandidates candidates, AnalysisLog warnings, TaskMonitor monitor)
			throws CancelledException {
		Memory memory = program.getMemory();
		MetadataLocator locator = new MetadataLocator(program);
		Progress.start(monitor, NAME, "method tables", typed.size());
		for (Address descriptor : typed) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			ContextDescriptor d = catalog.descriptors().get(descriptor);
			if (d.kind() != ContextDescriptor.KIND_CLASS) {
				continue;
			}
			String name = catalog.name(descriptor);
			ClassMethods table;
			try {
				table = SelfCandidates.methodTable(memory, d);
			}
			catch (IllegalStateException e) {
				warnings.warn(
					"SWIFTSELF-WARN\t%s\tmethod table not readable: %s".formatted(name,
						e.getMessage()),
					"%s: method table not readable (%s); its methods were not taken from it"
							.formatted(name, e.getMessage()));
				continue;
			}
			Address metadata = locator.locate(d).metadata();
			for (SelfCandidates.VtableMismatch m : candidates.addClass(descriptor, name, table,
				metadata, memory::getLong)) {
				Msg.warn(this,
					"SWIFTSELF-VTABLE\t%s\tentry %d at %s is 0x%x, method descriptor %s has 0x%x"
							.formatted(m.type(), m.index(), m.at(), m.entry(), m.method(),
								m.impl()));
			}
		}
	}

	/**
	 * Functions whose Swift symbol names a member of one of the types, and allocating
	 * initializers of every class, also one without a data type.
	 */
	private static void symbolMethods(Program program, SelfCandidates candidates,
			TaskMonitor monitor) throws CancelledException {
		if (!candidates.hasContexts()) {
			return;
		}
		Progress.start(monitor, NAME, "symbols", program.getFunctionManager().getFunctionCount());
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			for (String name : SymbolNames.atEntry(f)) {
				candidates.addSymbol(f.getEntryPoint(), name);
			}
		}
	}

	/** The function to type, or null with the reason counted and logged. */
	private Function check(Program program, Address entry, Candidate c, Register register,
			SwiftTypeCatalog catalog, Counts counts) {
		if (c.conflict()) {
			counts.conflicts++;
			Msg.info(this, "SWIFTSELF-CONFLICT\t%s\t%s\t%s".formatted(entry,
				c.types().stream().map(catalog::name).collect(Collectors.joining(", ")),
				String.join(", ", c.names())));
			return null;
		}
		Function f = program.getFunctionManager().getFunctionAt(entry);
		if (f == null) {
			counts.noFunction++;
			Msg.info(this, "SWIFTSELF-NOFUNCTION\t%s\t%s".formatted(entry, c.names().getFirst()));
			return null;
		}
		if (f.isThunk() || f.isExternal()) {
			counts.thunks++;
			return null;
		}
		if (f.getSignatureSource() == SourceType.USER_DEFINED) {
			counts.userDefined++;
			return null;
		}
		// Classes: self is in the register in every instance method. Structs and enums: only
		// in the methods that take self inout, which the mangled name does not tell.
		boolean valueType =
			catalog.descriptors().get(c.type()).kind() != ContextDescriptor.KIND_CLASS;
		if (valueType && !SelfRegisterUse.readsEntryValue(f, register)) {
			counts.notReading++;
			return null;
		}
		return f;
	}

	/** The type of self: {@code Metadata *} in an allocating initializer, else {@code type *}. */
	private static DataType selfType(Program program, Candidate c, DataType type) {
		return c.allocator() ? RuntimeTypes.metadataPointer(program.getDataTypeManager())
				: new PointerDataType(type, program.getDataTypeManager());
	}

	/** True if {@code f} has self in the register with type {@code self}. */
	private static boolean hasSelf(Function f, Register register, DataType self) {
		Parameter p = selfParameter(f, register);
		return p != null && p.getName().equals(SELF) && f.hasCustomVariableStorage() &&
			p.getDataType().isEquivalent(self);
	}

	/** The parameter stored in {@code register}, or null. */
	private static Parameter selfParameter(Function f, Register register) {
		for (Parameter p : f.getParameters()) {
			Register r = p.getRegister();
			if (r != null && r.getBaseRegister().equals(register.getBaseRegister())) {
				return p;
			}
		}
		return null;
	}

	/**
	 * Whether the decompiler's parameters must be committed before self locks the prototype: a
	 * function without a signature, or one with a parameter without storage. Ghidra's demangler
	 * leaves a parameter that it cannot place unassigned (the generic value of
	 * {@code Box<A>.init(A)}); in a locked prototype the decompiler then ignores the prototype.
	 */
	private static boolean needsParameters(Function f) {
		if (f.hasCustomVariableStorage()) {
			return false;
		}
		if (f.getSignatureSource() == SourceType.DEFAULT) {
			return true;
		}
		for (Parameter p : f.getParameters()) {
			if (p.getVariableStorage().isUnassignedStorage()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Commits the parameters the decompiler finds, without their data types and without the
	 * return value, so that they stay when self locks the prototype.
	 */
	private static boolean commitParameters(DecompInterface decompiler, Function f,
			TaskMonitor monitor) {
		DecompileResults results = decompiler.decompileFunction(f, DECOMPILE_TIMEOUT, monitor);
		HighFunction high = results != null ? results.getHighFunction() : null;
		if (high == null) {
			return false;
		}
		try {
			HighFunctionDBUtil.commitParamsToDatabase(high, false, ReturnCommitOption.NO_COMMIT,
				SourceType.ANALYSIS);
			return true;
		}
		catch (DuplicateNameException | InvalidInputException e) {
			return false;
		}
	}

	/**
	 * Adds self (or retypes it) after the other parameters, with custom storage. Replaces a
	 * parameter in the register (the auto-parameter {@code this} of Ghidra's Swift demangler,
	 * which gives class methods and some struct accessors {@code __swift_thiscall}). Removes the demangler's
	 * other copy of self, the last parameter: a struct's or enum's self by value (methods), or a
	 * pointer to the class in a class's property getter ({@code get_speed(Engine *param_1)}).
	 * Swift passes neither: self is only in the register.
	 */
	private void applySelf(Program program, Function f, Register register, DataType self,
			DataType type, boolean isClass, Candidate c, Counts counts) {
		Parameter existing = selfParameter(f, register);
		int existingOrdinal = existing != null ? existing.getOrdinal() : -1;
		Parameter[] old = f.getParameters();
		Parameter last = old.length > 0 ? old[old.length - 1] : null;
		boolean lastIsByValue = last != null && last.getOrdinal() != existingOrdinal &&
			(isClass ? c.getter() && last.getDataType().isEquivalent(self)
					: last.getDataType().isEquivalent(type));
		Parameter byValue = lastIsByValue ? last : null;
		int byValueOrdinal = lastIsByValue ? last.getOrdinal() : -1;
		// The names for the log line, read now: replaceParameters deletes the old parameters, and
		// a deleted one's name is "[Invalid VariableSymbol - Deleted!]".
		String existingName = existing != null ? existing.getName() : null;
		String byValueName = byValue != null ? byValue.getName() : null;
		List<Variable> params = new ArrayList<>();
		try {
			for (Parameter p : old) {
				if (p.getOrdinal() != existingOrdinal && p.getOrdinal() != byValueOrdinal) {
					params.add(new ParameterImpl(p, program));
				}
			}
			params.add(new ParameterImpl(SELF, self, new VariableStorage(program, register),
				program, SourceType.ANALYSIS));
			f.replaceParameters(params, FunctionUpdateType.CUSTOM_STORAGE, true,
				SourceType.ANALYSIS);
			if (existing != null) {
				counts.updated++;
			}
			else {
				counts.added++;
			}
			Msg.info(this, "SWIFTSELF\t%s\t%s\t%s\t%s\t%s%s".formatted(f.getEntryPoint(),
				f.getName(), self.getName(),
				c.sources()
						.stream()
						.map(SelfCandidates.Source::text)
						.collect(Collectors.joining(", ")),
				existingName != null ? "replaced " + existingName : "added",
				byValueName != null ? "; removed " + byValueName + " (the demangler's self)" : ""));
		}
		catch (DuplicateNameException | InvalidInputException e) {
			counts.failed++;
			Msg.warn(this, "SWIFTSELF-WARN\t%s\t%s\tnot updated: %s".formatted(f.getEntryPoint(),
				f.getName(), e.getMessage()));
		}
	}
}
