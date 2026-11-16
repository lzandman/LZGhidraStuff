// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.xml.sax.SAXException;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.framework.store.LockException;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlParseException;
import lzghidraswift.abi.CallOverrides;
import lzghidraswift.metadata.SymbolNames;

/**
 * Call-site overrides for {@code ___chkstk_darwin} on AArch64, the stack probe that a function
 * calls before it moves the stack pointer down by a size known only at run time (a buffer for a
 * generic value). The calls load the import from {@code __got} and branch to it
 * ({@code blr x16}), so they take the program's default convention, which kills x0, x1 and x8
 * to x18. The function keeps them: libsystem_pthread's (macOS 27.0.1) reads the size in x9,
 * saves and restores x10 and x11, and writes only x9 and the flags; x16 and x17 are the scratch
 * registers of the branch. With the default convention a value that lives in such a register
 * across the call is lost: the closure's box in x1 became an unassigned local, and the size in
 * x8, which the caller subtracts from the stack pointer after the call, an {@code extraout_x8}.
 * <p>
 * This class installs the convention {@value #CONVENTION} ({@link #PROTOTYPE}: the size in x9,
 * x9, x16 and x17 killed, the other integer registers, sp and q0 to q31 unaffected) as a
 * specification extension of the program, and gives each call the override
 * {@code void (ulong size)} with it. Setting the convention of the external does not reach the
 * calls, which stay indirect. Typing the {@code __got} entry as a pointer to that signature gives
 * the same C, but made the decompiler 41 % slower on the callers of one application (1,263
 * functions); the overrides cost no time there.
 * <p>
 * x86_64 calls a stub ({@code call ___chkstk_darwin}), with the size in RAX; its convention was
 * not checked, and this class is for AArch64 only.
 */
public final class StackProbes {

	/** The import's label. */
	public static final String SYMBOL = "___chkstk_darwin";
	/** The name of the installed convention. */
	public static final String CONVENTION = "__chkstk_darwin";

	/** The registers that the probe changes: the size and the branch's scratch registers. */
	static final List<String> KILLED = List.of("x9", "x16", "x17");

	/**
	 * The convention, in the cspec form. The output names x9 like the input; the override
	 * returns {@code void}, so the decompiler does not use it.
	 */
	static final String PROTOTYPE = prototype();

	/** A call to the probe. */
	public record Call(Function caller, Address call) {}

	private StackProbes() {
	}

	private static String prototype() {
		StringBuilder unaffected = new StringBuilder();
		for (int i = 0; i <= 30; i++) {
			if (!KILLED.contains("x" + i)) {
				unaffected.append(register("x" + i));
			}
		}
		unaffected.append(register("sp"));
		for (int i = 0; i <= 31; i++) {
			unaffected.append(register("q" + i));
		}
		StringBuilder killed = new StringBuilder();
		KILLED.forEach(r -> killed.append(register(r)));
		String size = "<pentry minsize=\"1\" maxsize=\"8\">" + register("x9") + "</pentry>";
		return "<prototype name=\"" + CONVENTION + "\" extrapop=\"0\" stackshift=\"0\">" +
			"<input>" + size + "</input><output>" + size + "</output>" +
			"<unaffected>" + unaffected + "</unaffected>" +
			"<killedbycall>" + killed + "</killedbycall></prototype>";
	}

	private static String register(String name) {
		return "<register name=\"" + name + "\"/>";
	}

	/** The external function {@value #SYMBOL}, or null if the program does not import it. */
	public static Function external(Program program) {
		for (Function f : program.getFunctionManager().getExternalFunctions()) {
			if (SymbolNames.ofExternal(f).contains(SYMBOL)) {
				return f;
			}
		}
		return null;
	}

	/**
	 * The calls in {@code set} to {@code probe} or one of its thunks, by address: the call
	 * instructions that refer to them (the {@code blr x16} after the load from {@code __got}
	 * refers to the external).
	 */
	public static List<Call> calls(Function probe, AddressSetView set) {
		Program program = probe.getProgram();
		List<Address> targets = new ArrayList<>();
		targets.add(probe.getEntryPoint());
		Address[] thunks = probe.getFunctionThunkAddresses(true);
		if (thunks != null) {
			targets.addAll(List.of(thunks));
		}
		Set<Address> sites = new TreeSet<>();
		for (Address target : targets) {
			for (Reference r : program.getReferenceManager().getReferencesTo(target)) {
				Address from = r.getFromAddress();
				Instruction instr = program.getListing().getInstructionAt(from);
				if (r.getReferenceType().isCall() && instr != null && set.contains(from)) {
					sites.add(from);
				}
			}
		}
		List<Call> calls = new ArrayList<>();
		for (Address a : sites) {
			Function caller = program.getFunctionManager().getFunctionContaining(a);
			if (caller != null) {
				calls.add(new Call(caller, a));
			}
		}
		return calls;
	}

	/**
	 * Installs {@value #CONVENTION}, unless the program has it already; true if installed. Needs a
	 * transaction and exclusive access to the program. Installing an extension reloads the
	 * program's compiler spec.
	 */
	public static boolean install(Program program, TaskMonitor monitor)
			throws LockException, SleighException, SAXException, XmlParseException {
		if (program.getCompilerSpec().getCallingConvention(CONVENTION) != null) {
			return false;
		}
		new SpecExtension(program).addReplaceCompilerSpecExtension(PROTOTYPE, monitor);
		return true;
	}

	/**
	 * Writes the override for the call at {@code call} in {@code caller}; needs {@value #CONVENTION}
	 * ({@link #install}). An override with {@value #CONVENTION} and another signature is replaced;
	 * one with another convention is kept.
	 */
	public static CallOverrides.Status apply(Function caller, Address call)
			throws InvalidInputException {
		return CallOverrides.write(caller, call,
			signature(caller.getProgram().getDataTypeManager()),
			CONVENTION::equals);
	}

	/** {@code void ___chkstk_darwin(ulong size)} with {@value #CONVENTION}. */
	static FunctionDefinitionDataType signature(DataTypeManager dtm) throws InvalidInputException {
		FunctionDefinitionDataType sig = new FunctionDefinitionDataType(SYMBOL, dtm);
		sig.setCallingConvention(CONVENTION);
		sig.setArguments(new ParameterDefinition[] {
			new ParameterDefinitionImpl("size", UnsignedLongDataType.dataType, null) });
		sig.setReturnType(VoidDataType.dataType);
		return sig;
	}
}
