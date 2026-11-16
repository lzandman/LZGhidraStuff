// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.xml.sax.SAXException;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlParseException;
import lzghidraswift.abi.CallOverrides;
import lzghidraswift.abi.CallingConventions;
import lzghidraswift.metadata.SwiftSections;
import lzghidraswift.metadata.SymbolNames;
import lzghidraswift.runtime.RuntimePrototypes;
import lzghidraswift.runtime.RuntimePrototypes.Decision;
import lzghidraswift.runtime.RuntimeTable;
import lzghidraswift.runtime.StackProbes;

/**
 * Gives the Swift runtime functions that a binary imports ({@code swift_retain},
 * {@code swift_allocObject}, {@code swift_beginAccess}, ...) their signatures from the Swift
 * source ({@link RuntimeTable}): parameter names and types, return type and calling convention,
 * with enums for the flag arguments and structures for the values returned in two registers.
 * The stubs that call an imported function are thunks and show its signature at every call.
 * <p>
 * Covers external functions and, with the option {@value #OPTION_DEFINED}, functions in memory
 * with a runtime function's name (images of the dyld shared cache). Keeps signatures that the
 * user, an archive or the import set, and functions that Swift Error Register gave a throwing
 * convention; leaves async functions, the {@code PreserveMost} retains ({@code ...Direct}) and
 * functions with a parameter in a Swift-only register and another one not alone
 * ({@link RuntimePrototypes#decide}). A function with every parameter in a Swift-only register
 * ({@code swift_willThrow}) gets its signature without them.
 * <p>
 * On AArch64, with the option {@value #OPTION_STACK_PROBES}, each call to
 * {@code ___chkstk_darwin} gets a call-site override with a convention that keeps the registers
 * the probe keeps ({@link StackProbes}). Running it again changes nothing.
 */
public class SwiftRuntimePrototypesAnalyzer extends AbstractAnalyzer {

	static final String NAME = "LZ Swift Runtime Prototypes";
	private static final String DESCRIPTION =
		"Gives the Swift runtime functions (swift_retain, swift_allocObject, " +
			"swift_beginAccess, ...) their signatures and calling conventions from the Swift " +
			"source, with enums for flag arguments, so that calls show their arguments and results.";
	static final String OPTION_DEFINED = "Apply to defined functions";
	private static final String OPTION_DEFINED_DESCRIPTION =
		"Also give the signatures to functions in the program with a runtime function's name, " +
			"as in libswiftCore and other images of the dyld shared cache. Imported functions " +
			"get them either way.";

	static final String OPTION_STACK_PROBES = "Override stack probe calls";
	private static final String OPTION_STACK_PROBES_DESCRIPTION =
		"On arm64, give each call to ___chkstk_darwin a call-site override with a calling " +
			"convention that changes only x9, x16 and x17, so that the decompiler keeps the " +
			"values that live in other registers across the call. Needs exclusive access.";

	private boolean applyToDefined = true;
	private boolean stackProbes = true;

	/** Counts of the calls to {@code ___chkstk_darwin}, for their summary line. */
	private static final class ProbeCounts {
		final CallOverrides.Counts overrides = new CallOverrides.Counts();
		int calls, failed;
		boolean installed;

		/** The stack probe line. */
		String summary() {
			return NAME +
				": stack probes: %d calls to %s, %d overrides added, %d replaced, %d present, "
						.formatted(calls, StackProbes.SYMBOL, overrides.added, overrides.replaced,
							overrides.present) +
				"%d other overrides kept, %d failed; convention %s"
						.formatted(overrides.other, failed, installed ? "installed" : "present");
		}
	}

	/** Counts for the summary lines. */
	private static final class Counts {
		int applied, alreadySet, userDefined, notInTable, async, swiftccAsDefault;
		int imported, otherModule, preserveMost, swiftRegisters, throwingVariant, failed;
		final Set<String> missing = new TreeSet<>();

		void count(Decision d) {
			switch (d) {
				case OTHER_MODULE -> otherModule++;
				case ASYNC -> async++;
				case PRESERVE_MOST -> preserveMost++;
				case SWIFT_REGISTERS -> swiftRegisters++;
				case USER_DEFINED -> userDefined++;
				case IMPORTED -> imported++;
				case THROWING_VARIANT -> throwingVariant++;
				case APPLY -> {
				}
			}
		}

		/** The results line. */
		String summary() {
			return NAME + ": %d applied, %d already set, %d user signatures kept, "
					.formatted(applied, alreadySet, userDefined) +
				"%d not in table, %d async skipped, %d swiftcc as default"
						.formatted(notInTable, async, swiftccAsDefault);
		}

		/** The line of the other functions left unchanged. */
		String skipSummary(double seconds) {
			return NAME +
				": left unchanged: %d imported signatures, %d other modules, %d PreserveMost, "
						.formatted(imported, otherModule, preserveMost) +
				"%d Swift register parameters, %d throwing variants, "
						.formatted(swiftRegisters, throwingVariant) +
				"%d failures; %.2f s".formatted(failed, seconds);
		}
	}

	/** A byte analyzer, on by default and available as one-shot analysis. */
	public SwiftRuntimePrototypesAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// Before Swift Data Types (DATA_TYPE_PROPOGATION - 1), Swift Self Types
		// (DATA_TYPE_PROPOGATION) and Swift Error Register, so that their decompiler runs see
		// the typed calls.
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return CallingConventions.isSwiftTarget(program) &&
			SwiftSections.hasSwiftSections(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_DEFINED, applyToDefined, null, OPTION_DEFINED_DESCRIPTION);
		options.registerOption(OPTION_STACK_PROBES, stackProbes, null,
			OPTION_STACK_PROBES_DESCRIPTION);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		applyToDefined = options.getBoolean(OPTION_DEFINED, applyToDefined);
		stackProbes = options.getBoolean(OPTION_STACK_PROBES, stackProbes);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		long start = System.nanoTime();
		AnalysisLog warnings = new AnalysisLog(this, log);
		RuntimeTable table;
		try {
			table = RuntimeTable.load();
		}
		catch (IOException | IllegalArgumentException e) {
			warnings.warn("SWIFTRT-WARN\tno table: " + e.getMessage(),
				"The runtime function table " + RuntimeTable.FILE_NAME +
					" could not be read, so no signatures were set: " + e.getMessage());
			return false;
		}
		RuntimePrototypes prototypes = new RuntimePrototypes(program, table);
		Counts counts = new Counts();
		FunctionManager functions = program.getFunctionManager();
		monitor.setMessage(NAME + ": externals");
		for (Function f : functions.getExternalFunctions()) {
			monitor.checkCancelled();
			apply(prototypes, f, SymbolNames.ofExternal(f), counts, warnings);
		}
		if (applyToDefined) {
			Progress.start(monitor, NAME, "functions", Progress.functions(program, set));
			for (Function f : functions.getFunctions(set, true)) {
				monitor.checkCancelled();
				monitor.incrementProgress(1);
				// A thunk shows the signature of the function it calls. The set of a first analysis
				// includes the EXTERNAL space, so the externals come again here.
				if (!f.isThunk() && !f.isExternal()) {
					apply(prototypes, f, SymbolNames.atEntry(f), counts, warnings);
				}
			}
		}
		boolean probesSet = stackProbes && CallingConventions.isAArch64(program) &&
			stackProbes(program, set, warnings, monitor);
		Msg.info(this, counts.summary());
		Msg.info(this, counts.skipSummary((System.nanoTime() - start) / 1e9));
		if (!counts.missing.isEmpty()) {
			Msg.debug(this, "SWIFTRT-MISSING\t" + String.join(" ", counts.missing));
		}
		return counts.applied > 0 || probesSet;
	}

	/** The overrides of the calls to {@code ___chkstk_darwin} in {@code set}; true if any was written. */
	private boolean stackProbes(Program program, AddressSetView set, AnalysisLog warnings,
			TaskMonitor monitor) throws CancelledException {
		Function probe = StackProbes.external(program);
		if (probe == null) {
			return false;
		}
		List<StackProbes.Call> calls = StackProbes.calls(probe, set);
		if (calls.isEmpty()) {
			return false;
		}
		ProbeCounts counts = new ProbeCounts();
		counts.calls = calls.size();
		if (!program.hasExclusiveAccess()) {
			// SpecExtension needs it.
			warnings.warn("SWIFTRT-WARN\tno exclusive checkout: %d calls to %s not changed"
					.formatted(calls.size(), StackProbes.SYMBOL),
				"The program is not checked out exclusively, so the calling convention for " +
					StackProbes.SYMBOL + " cannot be added. Check it out exclusively and run " +
					"Swift Runtime Prototypes again.");
			return false;
		}
		try {
			counts.installed = StackProbes.install(program, monitor);
		}
		catch (LockException | SleighException | SAXException | XmlParseException e) {
			warnings.warn("SWIFTRT-WARN\tconvention not installed: " +
				StackProbes.CONVENTION + ": " + e.getMessage(),
				"Calling convention not installed: " + StackProbes.CONVENTION + ": " +
					e.getMessage());
			return false;
		}
		Progress.start(monitor, NAME, "stack probe calls", calls.size());
		for (StackProbes.Call c : calls) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			try {
				counts.overrides.count(StackProbes.apply(c.caller(), c.call()));
			}
			catch (InvalidInputException e) {
				counts.failed++;
				warnings.warn("SWIFTRT-WARN\t%s\toverride not set: %s".formatted(c.call(),
					e.getMessage()),
					"%s: call-site override not set (%s)".formatted(c.call(), e.getMessage()));
			}
		}
		Msg.info(this, counts.summary());
		return counts.overrides.written() || counts.installed;
	}

	private void apply(RuntimePrototypes prototypes, Function f, List<String> names,
			Counts counts, AnalysisLog warnings) {
		RuntimeTable.Entry entry = prototypes.entry(names);
		if (entry == null) {
			if (RuntimePrototypes.isRuntimeName(names)) {
				counts.notInTable++;
				counts.missing.add(f.getName());
			}
			return;
		}
		Decision decision = RuntimePrototypes.decide(entry, f.getSignatureSource(),
			f.getCallingConventionName());
		counts.count(decision);
		if (decision != Decision.APPLY) {
			return;
		}
		try {
			if (prototypes.apply(f, entry)) {
				counts.applied++;
				Msg.info(this, "SWIFTRT-SET\t%s\t%s\t%s".formatted(f.getEntryPoint(), f.getName(),
					f.getCallingConventionName()));
				if (prototypes.swiftccAsDefault(entry)) {
					counts.swiftccAsDefault++;
				}
			}
			else {
				counts.alreadySet++;
			}
		}
		catch (InvalidInputException | DuplicateNameException e) {
			counts.failed++;
			warnings.warn(
				"SWIFTRT-WARN\t%s\t%s\tsignature not set: %s".formatted(f.getEntryPoint(),
					f.getName(), e.getMessage()),
				"%s at %s: runtime signature not set (%s)".formatted(f.getName(),
					f.getEntryPoint(), e.getMessage()));
		}
	}
}
