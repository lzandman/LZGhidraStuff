// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import lzghidraswift.abi.CallOverrides;
import lzghidraswift.abi.CallingConventions;
import lzghidraswift.mangling.ThrowingSymbol;
import lzghidraswift.mangling.ThrowingSymbol.Effect;
import lzghidraswift.metadata.SwiftSections;
import lzghidraswift.metadata.SymbolNames;
import lzghidraswift.throwing.CallArguments;
import lzghidraswift.throwing.CallArguments.Arguments;
import lzghidraswift.throwing.ErrorTestSites;
import lzghidraswift.throwing.ThrowingCallOverride;
import lzghidraswift.throwing.ThrowingCallees;
import lzghidraswift.throwing.ThrowingCallees.Check;
import lzghidraswift.throwing.ThrowingCallees.Decision;
import lzghidraswift.throwing.ThrowingConventions;

/**
 * Gives each function whose Swift symbol has a throwing function type ({@link ThrowingSymbol})
 * the throwing variant of its calling convention ({@link ThrowingConventions}), in which a call
 * changes the error register (x21 on AArch64, r12 on x86_64). Ghidra's Swift conventions keep
 * that register across a call, so the decompiler takes the caller's 0 from before the call as
 * the error and removes the code that handles a thrown error as unreachable.
 * <p>
 * Covers functions in memory and external functions (the stubs that call them are thunks and
 * use their convention). Callees without a Swift symbol are found from their callers
 * ({@link ErrorTestSites}: the error register is 0 before the call and compared with 0 after it);
 * a callee whose Swift symbol says it does not throw, and an external function without a Swift
 * symbol (a C or Objective-C function), are left alone. An indirect call with that pattern
 * (a throwing closure) gets a call-site override ({@link ThrowingCallOverride}) that names the
 * arguments the caller sets up ({@link CallArguments}); an override from an earlier version is
 * replaced.
 * <p>
 * Typed throws ({@code throws(E)}) use the same variant: the callee sets the error register to 1
 * as a flag and returns the error in the result registers, which the variant also kills, or
 * through a pointer that the caller passes after the other arguments (not in the signature).
 * <p>
 * Changes only the calling convention: the parameters, also {@code self} of Swift Self Types in
 * custom storage, stay. Functions with a user-defined signature and calls with another override
 * are not changed. Async functions are counted, not changed. The variants are
 * added to the program as specification extensions when the first throwing function or call is
 * found; that needs an exclusive checkout in a shared project, without which the analyzer logs a
 * warning and changes nothing. Running it again changes nothing.
 */
public class SwiftErrorRegisterAnalyzer extends AbstractAnalyzer {

	static final String NAME = "LZ Swift Error Register";
	private static final String DESCRIPTION =
		"Gives functions whose Swift symbol has a throwing function type a calling convention " +
			"in which a call changes the Swift error register (x21, r12), so that the " +
			"decompiler keeps the code that handles a thrown error. Adds these conventions to " +
			"the program as specification extensions.";

	/** Counts for the summary lines. */
	private static final class Counts {
		int throwing, external, typed, changed, unchanged, userDefined, otherConvention, failed;
		int async;
		int sites, sitesBySymbol, sitesNew, indirect, noFunction, contradicted, notHandled;
		int notSwift;
		int fromCallers;
		final CallOverrides.Counts overrides = new CallOverrides.Counts();
		int overridesFailed;
		int withContext, withIndirectResult;

		/** The results line, after {@code "<analyzer>: "}. */
		String summary(double seconds) {
			return "%d functions with a throwing Swift symbol (%d external, %d typed throws); "
					.formatted(throwing, external, typed) +
				"convention set on %d, unchanged on %d; ".formatted(changed, unchanged) +
				"not changed: %d user-defined signatures, %d other conventions, %d failures; "
						.formatted(userDefined, otherConvention, failed) +
				"not handled: %d async; %.2f s".formatted(async, seconds);
		}

		/** The line about the calls that test the error register. */
		String siteSummary() {
			return "%d calls test the error register: %d to callees with a throwing symbol, "
					.formatted(sites, sitesBySymbol) +
				"%d to %d callees found from their callers; ".formatted(sitesNew, fromCallers) +
				"%d to callees whose symbol does not throw, %d to external non-Swift functions, "
						.formatted(contradicted, notSwift) +
				"%d async, %d no function; ".formatted(notHandled, noFunction) +
				"%d indirect (%d with a context, %d with an indirect result): "
						.formatted(indirect, withContext, withIndirectResult) +
				"override added on %d, replaced on %d, present on %d, "
						.formatted(overrides.added, overrides.replaced, overrides.present) +
				"other override on %d, %d failures".formatted(overrides.other, overridesFailed);
		}
	}

	/** An indirect call that tests the error register. */
	private record IndirectCall(Function caller, Address call) {}

	/** A function analyzer, on by default and available as one-shot analysis. */
	public SwiftErrorRegisterAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		// After the Swift demangler (DATA_TYPE_PROPOGATION - 3), which sets
		// __swift_thiscall on methods, and Swift Self Types (DATA_TYPE_PROPOGATION), whose self it keeps. Before
		// Swift String Literals: the catch paths it brings back hold strings too.
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return CallingConventions.isSwiftTarget(program) &&
			SwiftSections.hasSwiftSections(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		long start = System.nanoTime();
		Counts counts = new Counts();
		AnalysisLog warnings = new AnalysisLog(this, log);
		FunctionManager functions = program.getFunctionManager();
		List<Function> throwing = new ArrayList<>();
		int functionCount = Progress.functions(program, set);
		Progress.start(monitor, NAME, "throwing symbols", functionCount);
		for (Function f : functions.getFunctions(set, true)) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			// A thunk takes the convention of the function it calls.
			if (!f.isThunk() && isThrowing(SymbolNames.atEntry(f), counts)) {
				throwing.add(f);
			}
		}
		for (Function f : functions.getExternalFunctions()) {
			monitor.checkCancelled();
			if (isThrowing(SymbolNames.ofExternal(f), counts)) {
				throwing.add(f);
				counts.external++;
			}
		}
		counts.throwing = throwing.size();
		List<IndirectCall> indirect = new ArrayList<>();
		Progress.start(monitor, NAME, "error register tests", functionCount);
		throwing.addAll(callees(program, set, Set.copyOf(throwing), indirect, counts, monitor));
		if (throwing.isEmpty() && indirect.isEmpty()) {
			if (counts.sites > 0) {
				Msg.info(this, NAME + ": " + counts.siteSummary());
			}
			if (counts.async > 0) {
				Msg.info(this, NAME + ": " +
					counts.summary((System.nanoTime() - start) / 1e9));
			}
			return false;
		}
		if (!program.hasExclusiveAccess()) {
			// SpecExtension needs it; in a shared project without it, master's Swift conventions
			// (spec extensions themselves) are missing too, and nothing could be set.
			warnings.warn(
				"SWIFTERR-WARN\tno exclusive checkout: %d throwing functions and %d calls not changed"
						.formatted(throwing.size(), indirect.size()),
				"The program is not checked out exclusively, so the throwing calling conventions " +
					"cannot be added. Check it out exclusively and run Swift Error Register again.");
			return false;
		}
		ThrowingConventions.Result installed = ThrowingConventions.install(program, monitor);
		Msg.info(this, NAME + ": " + installed.summary());
		for (String failure : installed.failed) {
			warnings.warn("SWIFTERR-WARN\tconvention not installed: " + failure,
				"Calling convention not installed: " + failure);
		}
		// Installing reloads the compiler spec.
		CompilerSpec spec = program.getCompilerSpec();
		Progress.start(monitor, NAME, "conventions", throwing.size());
		for (Function f : throwing) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			apply(spec, f, counts, warnings);
		}
		overrides(spec, indirect, counts, warnings, monitor);
		if (counts.sites > 0) {
			Msg.info(this, NAME + ": " + counts.siteSummary());
		}
		Msg.info(this, NAME + ": " + counts.summary((System.nanoTime() - start) / 1e9));
		return true;
	}

	/**
	 * The callees, not in {@code bySymbol}, of the calls in {@code set} after which the caller
	 * tests the error register; adds the indirect calls to {@code indirect}.
	 */
	private static Set<Function> callees(Program program, AddressSetView set,
			Set<Function> bySymbol, List<IndirectCall> indirect, Counts counts, TaskMonitor monitor)
			throws CancelledException {
		Register error = CallingConventions.errorRegister(program);
		Callees callees = new Callees(program, bySymbol, indirect, counts);
		for (Function caller : program.getFunctionManager().getFunctions(set, true)) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			if (caller.isThunk()) {
				continue;
			}
			for (ErrorTestSites.Site site : ErrorTestSites.find(caller, error, monitor)) {
				callees.add(caller, site);
			}
		}
		counts.fromCallers = callees.found.size();
		return callees.found;
	}

	/**
	 * Counts and collects the calls that test the error register, as {@link ThrowingCallees}
	 * decides them: indirect calls, and callees found from their callers.
	 */
	private static final class Callees {
		private final Program program;
		private final Set<Function> bySymbol;
		private final List<IndirectCall> indirect;
		private final Counts counts;
		final Set<Function> found = new LinkedHashSet<>();
		private final Map<Function, Effect> symbolEffects = new LinkedHashMap<>();

		Callees(Program program, Set<Function> bySymbol, List<IndirectCall> indirect,
				Counts counts) {
			this.program = program;
			this.bySymbol = bySymbol;
			this.indirect = indirect;
			this.counts = counts;
		}

		void add(Function caller, ErrorTestSites.Site site) {
			counts.sites++;
			Function callee = site.isIndirect() ? null : SymbolNames.callee(program, site.target());
			boolean hasFunction = callee != null;
			boolean isBySymbol = hasFunction && bySymbol.contains(callee);
			boolean isFound = hasFunction && found.contains(callee);
			Effect effect = hasFunction && !isBySymbol && !isFound
					? symbolEffects.computeIfAbsent(callee,
						c -> ThrowingCallees.firstEffect(names(c)))
					: null;
			Decision decision = ThrowingCallees.decide(site.isIndirect(), hasFunction,
				isBySymbol, isFound, hasFunction && callee.isExternal(), effect);
			switch (decision) {
				case INDIRECT -> {
					counts.indirect++;
					indirect.add(new IndirectCall(caller, site.call()));
				}
				case NO_FUNCTION -> counts.noFunction++;
				case BY_SYMBOL -> counts.sitesBySymbol++;
				case FOUND -> {
					found.add(callee);
					counts.sitesNew++;
				}
				case NOT_SWIFT -> {
					counts.notSwift++;
					Msg.info(SwiftErrorRegisterAnalyzer.class,
						"SWIFTERR-NOT-SWIFT\t%s\t%s\t%s".formatted(site.call(), caller.getName(),
							callee.getName()));
				}
				case CONTRADICTION -> {
					counts.contradicted++;
					Msg.info(SwiftErrorRegisterAnalyzer.class,
						"SWIFTERR-CONTRADICTION\t%s\t%s\t%s".formatted(site.call(),
							caller.getName(), callee.getName()));
				}
				case ASYNC -> counts.notHandled++;
			}
		}

	}

	/** The names that say whether {@code f} throws: of its symbols, or of the external. */
	private static List<String> names(Function f) {
		return f.isExternal() ? SymbolNames.ofExternal(f) : SymbolNames.atEntry(f);
	}

	/**
	 * Writes the call-site overrides of the indirect calls, with the arguments that each caller
	 * sets up ({@link CallArguments}, one data flow per caller).
	 */
	private void overrides(CompilerSpec spec, List<IndirectCall> calls, Counts counts,
			AnalysisLog warnings, TaskMonitor monitor) throws CancelledException {
		Map<Function, List<Address>> byCaller = new LinkedHashMap<>();
		for (IndirectCall c : calls) {
			byCaller.computeIfAbsent(c.caller(), k -> new ArrayList<>()).add(c.call());
		}
		Progress.start(monitor, NAME, "indirect calls", byCaller.size());
		for (Map.Entry<Function, List<Address>> e : byCaller.entrySet()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			Map<Address, Arguments> args = CallArguments.at(e.getKey(), e.getValue(), monitor);
			for (Address call : e.getValue()) {
				override(spec, new IndirectCall(e.getKey(), call), args.get(call), counts,
					warnings);
			}
		}
	}

	private void override(CompilerSpec spec, IndirectCall c, Arguments args, Counts counts,
			AnalysisLog warnings) {
		counts.withContext += args.context() != null ? 1 : 0;
		counts.withIndirectResult += args.indirectResult() != null ? 1 : 0;
		String variant = ThrowingCallOverride.variant(spec, args);
		if (variant == null) {
			counts.overridesFailed++;
			return;
		}
		try {
			CallOverrides.Status status =
				ThrowingCallOverride.apply(c.caller(), c.call(), variant, args);
			counts.overrides.count(status);
			if (status.written()) {
				Msg.info(this, "SWIFTERR-CALL\t%s\t%s\t%s\t%s".formatted(c.call(),
					c.caller().getName(), variant, status));
			}
		}
		catch (InvalidInputException e) {
			counts.overridesFailed++;
			warnings.warn(
				"SWIFTERR-WARN\t%s\t%s\toverride not written: %s".formatted(c.call(),
					c.caller().getName(), e.getMessage()),
				"Call at %s in %s: override not written (%s)".formatted(c.call(),
					c.caller().getName(), e.getMessage()));
		}
	}

	/**
	 * Whether one of the names is the symbol of a throwing function, with typed throws or not
	 * ({@link ThrowingCallees#check}); counts typed throws, and async functions, which are not
	 * changed.
	 */
	private static boolean isThrowing(List<String> names, Counts counts) {
		Check check = ThrowingCallees.check(names);
		switch (check) {
			case TYPED_THROWS -> counts.typed++;
			case ASYNC -> counts.async++;
			case THROWS, NONE -> {
			}
		}
		return check.isThrowing();
	}

	private void apply(CompilerSpec spec, Function f, Counts counts, AnalysisLog warnings) {
		if (f.getSignatureSource() == SourceType.USER_DEFINED) {
			counts.userDefined++;
			return;
		}
		String current = f.getCallingConventionName();
		String variant = ThrowingConventions.variantFor(spec, current);
		if (variant == null) {
			counts.otherConvention++;
			Msg.info(this, "SWIFTERR-CONVENTION\t%s\t%s\t%s has no throwing variant"
					.formatted(f.getEntryPoint(), f.getName(), current));
			return;
		}
		if (variant.equals(current)) {
			counts.unchanged++;
			return;
		}
		try {
			f.setCallingConvention(variant);
			counts.changed++;
			Msg.info(this, "SWIFTERR\t%s\t%s\t%s -> %s".formatted(f.getEntryPoint(), f.getName(),
				current, variant));
		}
		catch (InvalidInputException e) {
			counts.failed++;
			warnings.warn(
				"SWIFTERR-WARN\t%s\t%s\tconvention not set: %s".formatted(f.getEntryPoint(),
					f.getName(), e.getMessage()),
				"%s at %s: calling convention %s not set (%s)".formatted(f.getName(),
					f.getEntryPoint(), variant, e.getMessage()));
		}
	}
}
