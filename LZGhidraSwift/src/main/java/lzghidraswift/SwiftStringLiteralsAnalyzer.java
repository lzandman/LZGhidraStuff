// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lzghidraswift.flow.ValueFlow;
import lzghidraswift.metadata.SwiftSections;
import lzghidraswift.metadata.SymbolNames;
import lzghidraswift.strings.CandidateFilter;
import lzghidraswift.strings.DecompilerEquates;
import lzghidraswift.strings.DecompilerPool;
import lzghidraswift.strings.FallbackPairer;
import lzghidraswift.strings.LargeStringFinder;
import lzghidraswift.strings.RegisterPairFinder;
import lzghidraswift.strings.StringBlock;
import lzghidraswift.strings.StringHit;
import lzghidraswift.strings.StringMarkup;
import lzghidraswift.strings.SwiftStringCodec;

/**
 * Finds the Swift String literals that code builds: small strings (up to 15 UTF-8 bytes, packed
 * into the two words as immediates) and large literals (count and flags, and the address of the
 * bytes in {@code __cstring}). Marks them in the listing ({@link StringMarkup}). Each hit is
 * also logged as a tab-separated line starting with {@code SWIFTSTR}.
 */
public class SwiftStringLiteralsAnalyzer extends AbstractAnalyzer {

	static final String NAME = "LZ Swift String Literals";
	private static final String DESCRIPTION =
		"Decodes Swift String literals built in code: small strings (up to 15 bytes, packed " +
			"into two immediates) and large literals (address of the bytes in __cstring). " +
			"Adds comments, bookmarks and equates.";

	static final String OPTION_COMMENT_STYLE = "Comment style";
	static final String OPTION_BOOKMARKS = "Bookmarks";
	static final String OPTION_PROBABLE = "Probable strings";
	static final String OPTION_LARGE = "Large strings";
	static final String OPTION_DECOMPILER = "Decompiler equates";
	static final String OPTION_STRING_BLOCK = "String block";
	static final String OPTION_DECOMPILER_THREADS = "Decompiler threads";
	static final String OPTION_DECOMPILER_TIMEOUT = "Decompiler timeout (sec)";

	private StringMarkup.Options markupOptions = StringMarkup.Options.defaults();
	/** The option "Decompiler threads": 0 for automatic. */
	private int decompilerThreads;
	/** The option "Decompiler timeout (sec)". */
	private int decompilerTimeout = DecompilerPool.DEFAULT_TIMEOUT_SECONDS;

	/** A function analyzer, on by default and available as one-shot analysis. */
	public SwiftStringLiteralsAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		// The Swift demangler runs at DATA_TYPE_PROPOGATION - 3; run after it and after
		// constant propagation (REFERENCE_ANALYSIS - 4). Also after Swift Self Types
		// (DATA_TYPE_PROPOGATION), which changes function signatures: the decompiler equates are
		// hashed in code that depends on the callees' signatures. And after Swift Error Register
		// (DATA_TYPE_PROPOGATION + 1), which brings back catch paths that may hold strings.
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return SwiftSections.hasSwiftSections(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		StringMarkup.Options d = StringMarkup.Options.defaults();
		options.registerOption(OPTION_COMMENT_STYLE, d.style(), null,
			"EOL: end-of-line comment at the instruction that completes the string. " +
				"PRE: pre comment, which the decompiler shows by default.");
		options.registerOption(OPTION_BOOKMARKS, d.bookmarks(), null,
			"Bookmark each string (type Analysis, category \"" +
				StringMarkup.BOOKMARK_CATEGORY_SMALL + "\" or \"" +
				StringMarkup.BOOKMARK_CATEGORY_LARGE + "\").");
		options.registerOption(OPTION_PROBABLE, d.probable(), null,
			"Also mark strings whose words were paired by guess (shown with '?').");
		options.registerOption(OPTION_LARGE, d.large(), null,
			"Also mark large literals (16 bytes or more, bytes in __cstring) and add a data " +
				"reference to their bytes if the function has none.");
		options.registerOption(OPTION_DECOMPILER, d.decompilerEquates(), null,
			"Decompile each function with strings and name the constants there (S\"Flat\", " +
				"S\"Flat\".hi). Strings the decompiler does not show get a pre comment at their " +
				"use. The slow part of the analyzer.");
		options.registerOption(OPTION_STRING_BLOCK, d.stringBlock(), null,
			"Workaround with side effects. Write the small strings into an artificial, non-loaded " +
				"memory block (" + StringBlock.NAME + ") and define them as string data, so " +
				"that the Defined Strings window lists them. The block holds bytes that are not " +
				"in the binary: it shows up in the Memory Map and in some exports and searches. " +
				"Turning the option off does not remove it. Needs an exclusive checkout in a " +
				"shared project.");
		options.registerOption(OPTION_DECOMPILER_THREADS, 0, null,
			"Number of functions decompiled at the same time for the decompiler equates, each " +
				"in its own decompiler process. 0: one per processor but one, fewer if the " +
				"machine's memory outside the Java heap cannot hold 2 GB for each. 1: one at a " +
				"time. The result does not depend on it, with one exception: under the load of " +
				"more threads a function near the decompiler timeout may time out and lose its " +
				"decompiler equates.");
		options.registerOption(OPTION_DECOMPILER_TIMEOUT, DecompilerPool.DEFAULT_TIMEOUT_SECONDS,
			null,
			"Seconds the decompiler may take for one function. A function that takes longer " +
				"gets no decompiler equates (SWIFTSTR-DECOMP-FAILED in the log); its comments " +
				"and bookmarks stay. Separate from the Decompiler window's timeout, which " +
				"analyzers do not get.");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		StringMarkup.Options d = StringMarkup.Options.defaults();
		markupOptions = new StringMarkup.Options(
			options.getEnum(OPTION_COMMENT_STYLE, d.style()),
			options.getBoolean(OPTION_BOOKMARKS, d.bookmarks()),
			options.getBoolean(OPTION_PROBABLE, d.probable()),
			options.getBoolean(OPTION_LARGE, d.large()),
			options.getBoolean(OPTION_DECOMPILER, d.decompilerEquates()),
			options.getBoolean(OPTION_STRING_BLOCK, d.stringBlock()));
		decompilerThreads = options.getInt(OPTION_DECOMPILER_THREADS, 0);
		decompilerTimeout =
			options.getInt(OPTION_DECOMPILER_TIMEOUT, DecompilerPool.DEFAULT_TIMEOUT_SECONDS);
	}

	/** For scripts that run the analyzer with other options than the program's; no string block. */
	public void setMarkupOptions(String style, boolean bookmarks, boolean probable, boolean large,
			boolean decompilerEquates) {
		setMarkupOptions(style, bookmarks, probable, large, decompilerEquates, false);
	}

	/** For scripts that run the analyzer with other options than the program's. */
	public void setMarkupOptions(String style, boolean bookmarks, boolean probable, boolean large,
			boolean decompilerEquates, boolean stringBlock) {
		markupOptions =
			new StringMarkup.Options(StringMarkup.CommentStyle.valueOf(style), bookmarks,
				probable, large, decompilerEquates, stringBlock);
	}

	/** For scripts: the option "Decompiler threads" (0 for automatic). */
	public void setDecompilerThreads(int threads) {
		decompilerThreads = threads;
	}

	/** For scripts: the option "Decompiler timeout (sec)". */
	public void setDecompilerTimeout(int seconds) {
		decompilerTimeout = seconds;
	}

	/** Counts for the summary lines. */
	private static final class Counts {
		int functions, candidateFunctions, notConverged, tagWords, unpaired, large;
		/** Bit-63 ORs of large strings, those whose result no string uses, and bit-63 loads. */
		int largeOrs, unusedOrs, flagLoads;
		final Map<StringHit.Method, Integer> byMethod = new EnumMap<>(StringHit.Method.class);
		StringMarkup.Counts marked = StringMarkup.NONE;
		/** The string block's write; null without the option. */
		StringBlock.Result block;
		/** Decompiler equates: functions decompiled, of which failed. */
		int decompiled, decompileFailed;
		/** Decompiler equates: references added and present, hits shown, pre comment lines. */
		int equatesAdded, equatesPresent, shown, preLines;
		/**
		 * Wall time of the decompiler pass: decompiling on the worker threads, then applying
		 * the results and logging the held lines on the analysis thread.
		 */
		double decompSeconds;

		/** The hits line, after {@code "<analyzer>: "}. */
		String summary(double seconds) {
			StringBuilder methods = new StringBuilder();
			for (StringHit.Method m : StringHit.Method.values()) {
				methods.append(' ')
						.append(m.name().toLowerCase(Locale.ROOT))
						.append('=')
						.append(byMethod.getOrDefault(m, 0));
			}
			return "%d functions, %d candidate functions (%d not converged), "
					.formatted(functions, candidateFunctions, notConverged) +
				"%d tag words, %d unpaired, %d large strings, ".formatted(tagWords, unpaired,
					large) +
				"%d of %d bit-63 ORs unused, %d bit-63 loads; ".formatted(unusedOrs, largeOrs,
					flagLoads) +
				"hits by method:%s; %.3f s".formatted(methods, seconds);
		}

		/** The markup line, after {@code "<analyzer> "}. */
		String markupSummary() {
			return "markup: %d comments, %d bookmarks, %d operand equates, ".formatted(
				marked.comments(), marked.bookmarks(), marked.equates()) +
				"%d large-string references added, %d present".formatted(marked.refsAdded(),
					marked.refsPresent()) +
				(block == null ? ""
						: ", %d block strings added, %d block references".formatted(
							block.stringsAdded(), block.references()));
		}

		/** The decompiler equates line, after {@code "<analyzer> "}. */
		String decompilerSummary() {
			return "decompiler: %d functions decompiled (%d failed), ".formatted(decompiled,
				decompileFailed) +
				"%d equate references added, %d present, ".formatted(equatesAdded,
					equatesPresent) +
				"%d strings shown by equates, %d pre comments; %.3f s".formatted(shown, preLines,
					decompSeconds);
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		long start = System.nanoTime();
		Counts counts = new Counts();
		AnalysisLog warnings = new AnalysisLog(this, log);
		StringMarkup markup = new StringMarkup(program, markupOptions);
		// Progress by function: count them first (cheap next to the analysis itself).
		Progress.start(monitor, NAME, "functions", Progress.functions(program, set));
		boolean decompiler = markupOptions.decompilerEquates();
		// With the decompiler equates, the candidate functions wait for the decompiler pass,
		// and so do their log lines, so that the log keeps the order of the functions.
		List<Job> jobs = new ArrayList<>();
		FunctionIterator it = program.getFunctionManager().getFunctions(set, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Function function = it.next();
			counts.functions++;
			monitor.incrementProgress(1);
			markup.clear(function.getBody(), monitor);
			CandidateFilter.Result r = CandidateFilter.scan(program, function);
			if (r.isEmpty()) {
				continue;
			}
			counts.candidateFunctions++;
			Job job = scan(program, function, r, markup, counts, warnings, monitor);
			if (decompiler) {
				jobs.add(job);
			}
			else {
				job.before.forEach(Runnable::run);
				job.after.forEach(Runnable::run);
			}
		}
		if (decompiler) {
			long t = System.nanoTime();
			decompilerPass(program, markup, jobs, counts, warnings, monitor);
			counts.decompSeconds = (System.nanoTime() - t) / 1e9;
		}
		counts.block = markup.writeBlock(monitor);
		if (counts.block != null && counts.block.locked()) {
			warnings.warn("SWIFTSTR-BLOCK-LOCKED\tno exclusive access; new strings not written",
				"String block: no exclusive checkout, so the new small strings were not written " +
					"into " + StringBlock.NAME);
		}
		Msg.info(this, NAME + ": " + counts.summary((System.nanoTime() - start) / 1e9));
		Msg.info(this, NAME + " " + counts.markupSummary());
		if (markupOptions.decompilerEquates()) {
			Msg.info(this, NAME + " " + counts.decompilerSummary());
		}
		return true;
	}

	/**
	 * A candidate function waiting for the decompiler pass: its marked hits, and its log lines
	 * before and after the decompiler's.
	 */
	private final class Job {
		final Function function;
		final String name;
		final List<StringHit> marked = new ArrayList<>();
		final List<Runnable> before = new ArrayList<>();
		final List<Runnable> after = new ArrayList<>();

		Job(Function function, String name) {
			this.function = function;
			this.name = name;
		}

		void info(String line) {
			before.add(() -> Msg.info(SwiftStringLiteralsAnalyzer.this, line));
		}
	}

	/**
	 * Finds the strings of one candidate function and marks them in the listing. Returns its
	 * job: the marked hits and the log lines, not yet logged.
	 */
	private Job scan(Program program, Function function, CandidateFilter.Result r,
			StringMarkup markup, Counts counts, AnalysisLog warnings, TaskMonitor monitor)
			throws CancelledException {
		String name = reportName(function);
		Job job = new Job(function, name);
		RegisterPairFinder finder = new RegisterPairFinder(program, function);
		List<StringHit> hits = finder.run(monitor);
		if (!finder.flow().converged()) {
			counts.notConverged++;
			String line = ("SWIFTSTR-NOT-CONVERGED\t%s\t%s\twork limit of %d " +
				"instructions reached after %d blocks; strings from the states so far")
						.formatted(function.getEntryPoint(), name,
							ValueFlow.MAX_INSTRUCTIONS, finder.flow().iterations());
			String text =
				"%s at %s: data flow stopped at the work limit; strings may be missing"
						.formatted(function.getName(), function.getEntryPoint());
			job.before.add(() -> warnings.warn(line, text));
		}
		FallbackPairer.Result fb =
			FallbackPairer.pair(program, finder.constants(), hits, monitor);
		List<StringHit> all = new ArrayList<>(hits);
		all.addAll(fb.hits());
		all.sort(Comparator.comparing(StringHit::completedAt));
		for (StringHit h : all) {
			counts.byMethod.merge(h.method(), 1, Integer::sum);
			if (h.kind() == StringHit.Kind.LARGE) {
				counts.large++;
			}
			job.info("SWIFTSTR\t%s\t%s\t%s\t%s\t%s\t%s\t%s".formatted(
				function.getEntryPoint(), name, h.completedAt(),
				h.kind().name().toLowerCase(Locale.ROOT),
				h.method().name().toLowerCase(Locale.ROOT),
				h.method().probable() ? "probable" : "certain",
				SwiftStringCodec.quote(h.text())));
		}
		counts.marked = counts.marked.plus(markup.apply(function, all));
		for (StringHit h : all) {
			if (markup.marks(h)) {
				job.marked.add(h);
			}
		}
		counts.tagWords += fb.tagWords().size();
		counts.unpaired += fb.unpaired().size();
		for (RegisterPairFinder.Constant c : fb.unpaired()) {
			job.after.add(() -> Msg.info(this,
				"SWIFTSTR-UNPAIRED\t%s\t%s\t%s\tcount=%d\t0x%016x".formatted(
					function.getEntryPoint(), name, c.at(),
					SwiftStringCodec.smallCount(c.value()), c.value())));
		}
		counts.largeOrs += r.largeStringOrs().size();
		counts.flagLoads += r.largeFlagLoads().size();
		for (Address a : LargeStringFinder.unusedOrs(r.largeStringOrs(),
			finder.largeWord1Producers())) {
			counts.unusedOrs++;
			job.after.add(() -> Msg.info(this, "SWIFTSTR-LARGE-OR-UNUSED\t%s\t%s\t%s"
					.formatted(function.getEntryPoint(), name, a)));
		}
		return job;
	}

	/**
	 * Decompiles the functions of {@code jobs} whose hits need it, on the worker threads, and
	 * then, on this thread and in the order of {@code jobs}, logs each function's lines and
	 * applies its decompiler equates and pre comments. Nothing is written until every function
	 * is decompiled, so the result is the same for any number of threads.
	 */
	private void decompilerPass(Program program, StringMarkup markup, List<Job> jobs,
			Counts counts, AnalysisLog warnings, TaskMonitor monitor) throws CancelledException {
		List<Job> needed = new ArrayList<>();
		for (Job job : jobs) {
			if (DecompilerEquates.needsDecompiler(job.marked)) {
				needed.add(job);
			}
		}
		Map<Job, DecompilerEquates.Plan> plans = new HashMap<>();
		if (!needed.isEmpty()) {
			Progress.start(monitor, NAME, "decompiling", needed.size());
			int threads = Math.min(DecompilerPool.threads(decompilerThreads), needed.size());
			try (DecompilerPool pool =
				new DecompilerPool(program, threads, decompilerTimeout, monitor)) {
				List<DecompilerEquates.Plan> list = pool.decompile(needed, job -> job.function,
					(job, res) -> DecompilerEquates.plan(job.marked, res));
				for (int i = 0; i < needed.size(); i++) {
					plans.put(needed.get(i), list.get(i));
				}
			}
		}
		DecompilerEquates equates = new DecompilerEquates(program);
		for (Job job : jobs) {
			monitor.checkCancelled();
			job.before.forEach(Runnable::run);
			DecompilerEquates.Plan plan = plans.get(job);
			if (plan == null) {
				plan = DecompilerEquates.plan(job.marked, null);
			}
			decompile(equates, markup, job, plan, counts, warnings);
			job.after.forEach(Runnable::run);
		}
	}

	/**
	 * Applies the decompiler equates of one function: equates for the marked hits, and a PRE
	 * comment line at the use of each marked hit that no equate shows. Logs one
	 * SWIFTSTR-DECOMP line per hit.
	 */
	private void decompile(DecompilerEquates equates, StringMarkup markup, Job job,
			DecompilerEquates.Plan plan, Counts counts, AnalysisLog warnings) {
		List<StringHit> marked = job.marked;
		if (marked.isEmpty()) {
			return;
		}
		Function function = job.function;
		DecompilerEquates.Result r = equates.apply(plan);
		if (DecompilerEquates.needsDecompiler(marked)) {
			counts.decompiled++;
		}
		if (!r.decompiled()) {
			counts.decompileFailed++;
			warnings.warn(
				"SWIFTSTR-DECOMP-FAILED\t%s\t%s\t%s".formatted(function.getEntryPoint(),
					job.name, r.error()),
				"%s at %s: decompiler failed (%s); no decompiler equates for its strings"
						.formatted(function.getName(), function.getEntryPoint(), r.error()));
			return;
		}
		counts.equatesAdded += r.added();
		counts.equatesPresent += r.present();
		List<StringHit> comment = new ArrayList<>();
		for (StringHit h : marked) {
			boolean shown = r.shown().contains(h);
			if (shown) {
				counts.shown++;
			}
			else {
				comment.add(h);
			}
			Msg.info(this, "SWIFTSTR-DECOMP\t%s\t%s\t%s\t%s\t%s".formatted(
				function.getEntryPoint(), job.name, h.useAt(), StringMarkup.label(h),
				shown ? "equate" : "comment"));
		}
		counts.preLines += markup.addPreLines(comment);
	}

	/**
	 * The mangled Swift symbols at the entry, sorted and joined with '|' (the linker folds
	 * identical functions, so one address can carry several), else the function name.
	 */
	public static String reportName(Function function) {
		List<String> names = new ArrayList<>();
		for (String n : SymbolNames.atEntry(function)) {
			if (SymbolNames.isSwift(n)) {
				names.add(n);
			}
		}
		if (names.isEmpty()) {
			return function.getName(true);
		}
		names.sort(null);
		return String.join("|", names);
	}
}
