// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.strings;

import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BiFunction;
import java.util.function.Consumer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Decompiles functions on worker threads, each with its own {@link DecompInterface} (its own
 * decompiler process). The workers only read the program, and each turns its decompiler results
 * into what the caller needs before taking the next function. The caller writes to the program
 * only after all are done, so no decompiler sees a write of this pass, and the result does not
 * depend on the number of threads. Plain {@code java.util.concurrent}, no Ghidra pool classes.
 */
public final class DecompilerPool implements AutoCloseable {

	/**
	 * The default decompiler timeout per function, in seconds: 60, as the option "Analysis
	 * Decompiler Timeout (sec)" of Ghidra's analyzers that decompile. Ghidra's Decompiler window
	 * has 30 s, a tool option, which analyzers do not get.
	 */
	public static final int DEFAULT_TIMEOUT_SECONDS = 60;

	/** Memory set aside for each automatic thread: its decompiler process. */
	static final long MEMORY_PER_THREAD = 2L << 30;

	private final Program program;
	private final TaskMonitor monitor;
	private final int timeoutSeconds;
	private final ExecutorService executor;
	private final List<DecompInterface> started = Collections.synchronizedList(new ArrayList<>());
	private final List<Future<?>> pending = new ArrayList<>();

	/**
	 * A pool of {@code threads} decompilers; they start with the first job of each thread.
	 * Each function may take {@code timeoutSeconds} (at least 1).
	 */
	public DecompilerPool(Program program, int threads, int timeoutSeconds, TaskMonitor monitor) {
		this.program = program;
		this.monitor = monitor;
		this.timeoutSeconds = Math.max(1, timeoutSeconds);
		this.executor = Executors.newFixedThreadPool(threads, Worker::new);
	}

	/**
	 * The number of threads: {@code option} if it is above 0. Otherwise one per processor but
	 * one, for the analysis thread, and no more than the memory outside the Java heap holds at
	 * {@link #MEMORY_PER_THREAD} each; at least 1.
	 *
	 * @param option the analyzer option, 0 for automatic
	 * @param processors {@code Runtime.availableProcessors()}
	 * @param memory the machine's physical memory in bytes, 0 if unknown (no cap)
	 * @param heap the Java heap's maximum in bytes
	 */
	public static int threads(int option, int processors, long memory, long heap) {
		if (option > 0) {
			return option;
		}
		long n = processors - 1L;
		if (memory > 0) {
			n = Math.min(n, (memory - heap) / MEMORY_PER_THREAD);
		}
		return (int) Math.max(1, n);
	}

	/** {@link #threads} for this machine. */
	public static int threads(int option) {
		long memory = 0;
		if (ManagementFactory
				.getOperatingSystemMXBean() instanceof com.sun.management.OperatingSystemMXBean os) {
			memory = os.getTotalMemorySize();
		}
		Runtime rt = Runtime.getRuntime();
		return threads(option, rt.availableProcessors(), memory, rt.maxMemory());
	}

	/**
	 * Decompiles the function of each item on the worker threads and turns the results into
	 * {@code R} there, with {@code use}, which may only read. The results are null if the
	 * decompiler did not start. Returns the {@code R}s in the order of {@code items}.
	 */
	public <T, R> List<R> decompile(List<T> items,
			java.util.function.Function<T, Function> function,
			BiFunction<T, DecompileResults, R> use) throws CancelledException {
		List<Future<R>> futures = new ArrayList<>();
		for (T item : items) {
			Function f = function.apply(item);
			Future<R> future = executor.submit(() -> use.apply(item, decompile(f)));
			futures.add(future);
			pending.add(future);
		}
		List<R> out = new ArrayList<>();
		for (Future<R> future : futures) {
			out.add(get(future));
			monitor.incrementProgress(1);
		}
		pending.clear();
		return out;
	}

	private <R> R get(Future<R> future) throws CancelledException {
		while (true) {
			monitor.checkCancelled();
			try {
				return future.get(1, TimeUnit.SECONDS);
			}
			catch (TimeoutException e) {
				// Check the monitor again.
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				CancelledException c = new CancelledException();
				c.initCause(e);
				throw c;
			}
			catch (ExecutionException e) {
				throw new IllegalStateException("decompiler thread failed", e);
			}
		}
	}

	/** A worker thread with its decompiler, started with its first function. */
	private static final class Worker extends Thread {
		DecompInterface decompiler;

		Worker(Runnable r) {
			super(r, "LZ Swift decompiler");
			setDaemon(true);
		}
	}

	/** On a worker thread: null if the decompiler did not start. */
	private DecompileResults decompile(Function function) {
		Worker w = (Worker) Thread.currentThread();
		if (w.decompiler == null) {
			w.decompiler = open(program,
				message -> Msg.warn(this, "SWIFTSTR-DECOMP-FAILED\t" + message));
			if (w.decompiler == null) {
				return null;
			}
			started.add(w.decompiler);
		}
		return w.decompiler.decompileFunction(function, timeoutSeconds, monitor);
	}

	/**
	 * A decompiler for {@code program}, set up as every decompiler of this extension: the
	 * program's decompiler options, the syntax tree without C code, style "decompile". Returns
	 * null if it does not start, after passing the decompiler's message to {@code failed}; the
	 * caller logs it in its own line. Used by the workers and by Swift Self Types.
	 */
	public static DecompInterface open(Program program, Consumer<String> failed) {
		DecompInterface d = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(program);
		d.setOptions(options);
		d.toggleCCode(false);
		d.toggleSyntaxTree(true);
		d.setSimplificationStyle("decompile");
		if (!d.openProgram(program)) {
			String message = d.getLastMessage();
			d.dispose();
			failed.accept(message);
			return null;
		}
		return d;
	}

	/**
	 * Stops the workers and disposes of the decompilers. After an exception or a cancel, the
	 * decompiler processes are stopped first, so that no worker reads the program after this
	 * returns.
	 */
	@Override
	public void close() {
		List<DecompInterface> all;
		synchronized (started) {
			all = new ArrayList<>(started);
		}
		if (!pending.isEmpty()) {
			pending.forEach(f -> f.cancel(false));
			all.forEach(DecompInterface::stopProcess);
		}
		executor.shutdownNow();
		try {
			executor.awaitTermination(2L * timeoutSeconds, TimeUnit.SECONDS);
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
		synchronized (started) {
			started.forEach(DecompInterface::dispose);
			started.clear();
		}
	}
}
