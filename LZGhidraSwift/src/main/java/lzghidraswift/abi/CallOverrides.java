// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.abi;

import java.util.function.Predicate;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.InvalidInputException;

/**
 * The decompiler's call-site overrides, as {@link HighFunctionDBUtil} writes them: the marker
 * symbol of a call's override, the comparison of an override's signature with a new one, and
 * writing an override. An override that is not the caller's own (another calling convention,
 * for example one that the user set) is kept.
 */
public final class CallOverrides {

	/** What {@link #write} did. */
	public enum Status {
		/** Wrote the override. */
		ADDED,
		/** Replaced an override of the caller's own with another signature. */
		REPLACED,
		/** The call has this override already. */
		PRESENT,
		/** The call has an override that is not the caller's own, which is kept. */
		OTHER;

		/** Whether the override was written. */
		public boolean written() {
			return this == ADDED || this == REPLACED;
		}
	}

	/** The count of each {@link Status}, for a summary line. */
	public static final class Counts {
		public int added, replaced, present, other;

		/** Counts one result of {@link CallOverrides#write}. */
		public void count(Status status) {
			switch (status) {
				case ADDED -> added++;
				case REPLACED -> replaced++;
				case PRESENT -> present++;
				case OTHER -> other++;
			}
		}

		/** Whether any override was written. */
		public boolean written() {
			return added + replaced > 0;
		}
	}

	private CallOverrides() {
	}

	/** The marker symbol of the override at {@code call} in {@code caller}, or null. */
	public static Symbol marker(Function caller, Address call) {
		Namespace space = HighFunction.findOverrideSpace(caller);
		if (space == null) {
			return null;
		}
		for (Symbol s : caller.getProgram().getSymbolTable().getSymbols(call)) {
			if (space.equals(s.getParentNamespace()) &&
				HighFunctionDBUtil.readOverride(s) != null) {
				return s;
			}
		}
		return null;
	}

	/**
	 * Writes the override {@code sig} for the call at {@code call} in {@code caller}, unless the
	 * call has it already or has an override that is not ours. {@code ours} takes the calling
	 * convention name of the existing override.
	 */
	public static Status write(Function caller, Address call, FunctionSignature sig,
			Predicate<String> ours) throws InvalidInputException {
		Symbol marker = marker(caller, call);
		DataTypeSymbol old = marker == null ? null : HighFunctionDBUtil.readOverride(marker);
		if (old == null) {
			HighFunctionDBUtil.writeOverride(caller, call, sig);
			return Status.ADDED;
		}
		Status status = decide((FunctionSignature) old.getDataType(), sig, ours);
		if (status == Status.REPLACED) {
			// As Ghidra's Edit Signature Override: writeOverride does not remove the old marker.
			marker.delete();
			HighFunctionDBUtil.writeOverride(caller, call, sig);
			old.cleanupUnusedOverride();
		}
		return status;
	}

	/**
	 * What {@link #write} does with the existing override {@code existing}: keep it if it is not
	 * ours ({@link Status#OTHER}), keep it if it is {@code sig} ({@link Status#PRESENT}), or
	 * replace it ({@link Status#REPLACED}).
	 */
	static Status decide(FunctionSignature existing, FunctionSignature sig,
			Predicate<String> ours) {
		if (!ours.test(existing.getCallingConventionName())) {
			return Status.OTHER;
		}
		return same(existing, sig) ? Status.PRESENT : Status.REPLACED;
	}

	/** Same convention, return type, varargs, and parameters by name and type. */
	public static boolean same(FunctionSignature a, FunctionSignature b) {
		if (!a.getCallingConventionName().equals(b.getCallingConventionName()) ||
			a.hasVarArgs() != b.hasVarArgs() ||
			!a.getReturnType().isEquivalent(b.getReturnType())) {
			return false;
		}
		ParameterDefinition[] pa = a.getArguments();
		ParameterDefinition[] pb = b.getArguments();
		if (pa.length != pb.length) {
			return false;
		}
		for (int i = 0; i < pa.length; i++) {
			if (!pa[i].getName().equals(pb[i].getName()) ||
				!pa[i].getDataType().isEquivalent(pb[i].getDataType())) {
				return false;
			}
		}
		return true;
	}
}
