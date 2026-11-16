// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import lzghidraswift.abi.CallingConventions;
import lzghidraswift.metadata.SymbolNames;

/**
 * Gives a Swift runtime function the signature of its {@link RuntimeTable} entry: return type,
 * parameter names and types ({@link RuntimeTypes}) and calling convention, with source
 * {@link SourceType#ANALYSIS}. Which functions get it ({@link #decide}): entries of the
 * {@link #MODULES Swift and _Concurrency modules}, whose convention Ghidra has
 * ({@link #convention}) and whose parameters are all in its argument registers or all in Swift-only
 * registers ({@link #withoutParams}), on functions
 * whose signature nobody chose (source {@code DEFAULT}, or {@code ANALYSIS} from an earlier run)
 * and whose convention is not a throwing variant. A function that has the signature already is
 * not written again.
 */
public final class RuntimePrototypes {

	/**
	 * The modules of the .def whose entries are applied. Not {@code objc2}, {@code c},
	 * {@code BlocksRuntime}, {@code libgcc} and {@code tsan}: Ghidra's archives type
	 * {@code malloc} and the Objective-C runtime, with better types than IRGen's.
	 */
	public static final Set<String> MODULES = Set.of("Swift", "_Concurrency");

	/** The .def's conventions, as {@link RuntimeTable.Entry#convention} names them. */
	static final String C_CC = "C_CC";
	static final String SWIFT_CC = "SwiftCC";
	static final String SWIFT_ASYNC_CC = "SwiftAsyncCC";
	static final String SWIFT_DIRECT_RR_CC = "SwiftDirectRR_CC";

	/** What to do with a runtime function, in the order {@link #decide} tests it. */
	public enum Decision {
		/** Set the signature. */
		APPLY,
		/** An entry of a module this class does not apply ({@link #MODULES}). */
		OTHER_MODULE,
		/** {@code SwiftAsyncCC}: needs the async context register (x22) as a parameter. */
		ASYNC,
		/** {@code SwiftDirectRR_CC}: LLVM's {@code PreserveMost}, no Ghidra convention. */
		PRESERVE_MOST,
		/**
		 * A parameter in a Swift-only register ({@link RuntimeTable#SWIFT_REGISTER_PARAMS}), and
		 * another one not: the convention would put the first in an argument register, and calls
		 * would show wrong arguments.
		 */
		SWIFT_REGISTERS,
		/** The user set the signature. */
		USER_DEFINED,
		/** An archive or the import set the signature ({@code IMPORTED}, or {@code AI}). */
		IMPORTED,
		/** Swift Error Register gave the function a throwing variant of its convention. */
		THROWING_VARIANT
	}

	private final Program program;
	private final RuntimeTable table;
	private final RuntimeTypes types;
	private final String swiftConvention;

	/** For one program; the Swift convention is looked up once, so make one per run. */
	public RuntimePrototypes(Program program, RuntimeTable table) {
		this.program = program;
		this.table = table;
		this.types = new RuntimeTypes(program.getDataTypeManager(), table);
		this.swiftConvention = CallingConventions.swiftConvention(program.getCompilerSpec(), false);
	}

	/** The table's entry of a function with these symbol names ({@link RuntimeTable#entry}). */
	public RuntimeTable.Entry entry(List<String> names) {
		return table.entry(names);
	}

	/**
	 * Whether one of the names is a {@code swift_} function: a runtime function not in the table.
	 */
	public static boolean isRuntimeName(List<String> names) {
		return names.stream().anyMatch(n -> SymbolNames.withoutUnderscore(n).startsWith("swift_"));
	}

	/**
	 * Whether to set the signature of a function with this entry, signature source and calling
	 * convention name; the reason if not.
	 */
	public static Decision decide(RuntimeTable.Entry entry, SourceType source,
			String callingConvention) {
		if (!MODULES.contains(entry.module())) {
			return Decision.OTHER_MODULE;
		}
		Decision skip = switch (entry.convention()) {
			case SWIFT_ASYNC_CC -> Decision.ASYNC;
			case SWIFT_DIRECT_RR_CC -> Decision.PRESERVE_MOST;
			default -> entry.attributes().contains(RuntimeTable.SWIFT_REGISTER_PARAMS) &&
				!withoutParams(entry)
						? Decision.SWIFT_REGISTERS
						: switch (source) {
							case USER_DEFINED -> Decision.USER_DEFINED;
							case IMPORTED, AI -> Decision.IMPORTED;
							case DEFAULT, ANALYSIS -> null;
						};
		};
		if (skip != null) {
			return skip;
		}
		if (callingConvention != null &&
			callingConvention.endsWith(CallingConventions.VARIANT_SUFFIX)) {
			return Decision.THROWING_VARIANT;
		}
		return Decision.APPLY;
	}

	/**
	 * The Ghidra calling convention of a .def convention: {@code default} for {@code C_CC} (the
	 * Swift specs have no {@code __cdecl}, and their default is Swift's); for {@code SwiftCC} the
	 * program's Swift convention without a {@code this} parameter, or {@code default} if there is
	 * none (Ghidra's default specs: the runtime's SwiftCC functions use no Swift-only register).
	 *
	 * @param swiftConvention {@link CallingConventions#swiftConvention}, or {@code null}
	 * @throws IllegalArgumentException for a convention that {@link #decide} does not apply
	 */
	static String convention(String defConvention, String swiftConvention) {
		return switch (defConvention) {
			case C_CC -> Function.DEFAULT_CALLING_CONVENTION_STRING;
			case SWIFT_CC -> swiftConvention != null ? swiftConvention
					: Function.DEFAULT_CALLING_CONVENTION_STRING;
			default -> throw new IllegalArgumentException("convention " + defConvention);
		};
	}

	/**
	 * Whether the entry gets its signature without parameters and with {@code default}: a
	 * {@code SwiftCC} function whose parameters are all in Swift-only registers
	 * ({@link RuntimeTable#SWIFT_REGISTERS_ONLY}). In Ghidra 12.2's {@code __swift_stdcall} on
	 * AArch64, x0 to x7 are neither killed by the call nor unaffected, so the decompiler reads a
	 * value that x0 held before the call as the caller's return value
	 * ({@code return (__int64)pSVar1;} after {@code swift_willThrow}). The C convention kills x0,
	 * as the Swift function does (on x86_64 both kill RAX).
	 */
	static boolean withoutParams(RuntimeTable.Entry entry) {
		return entry.convention().equals(SWIFT_CC) &&
			entry.attributes().contains(RuntimeTable.SWIFT_REGISTERS_ONLY);
	}

	/**
	 * Whether the entry is {@code SwiftCC} and gets {@code default}, because the program has no
	 * Swift convention ({@link #convention}); not one that gets it {@link #withoutParams}.
	 */
	public boolean swiftccAsDefault(RuntimeTable.Entry entry) {
		return entry.convention().equals(SWIFT_CC) && swiftConvention == null &&
			!withoutParams(entry);
	}

	/**
	 * Sets the signature of the entry on {@code f}, for which {@link #decide} gave
	 * {@link Decision#APPLY}.
	 *
	 * @return false if {@code f} had this signature already, from an earlier run
	 * @throws InvalidInputException if Ghidra rejects a type or the convention
	 * @throws DuplicateNameException if Ghidra rejects a parameter name
	 */
	public boolean apply(Function f, RuntimeTable.Entry entry)
			throws InvalidInputException, DuplicateNameException {
		boolean without = withoutParams(entry);
		String cc = without ? Function.DEFAULT_CALLING_CONVENTION_STRING
				: convention(entry.convention(), swiftConvention);
		DataType returnType = types.returnType(entry);
		List<Parameter> params = new ArrayList<>();
		for (RuntimeTable.Param p : without ? List.<RuntimeTable.Param> of() : entry.params()) {
			params.add(new ParameterImpl(p.name(), types.paramType(p), program,
				SourceType.ANALYSIS));
		}
		if (hasSignature(f, cc, returnType, params)) {
			return false;
		}
		f.updateFunction(cc, new ReturnParameterImpl(returnType, program), params,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
		return true;
	}

	/**
	 * Whether {@code f} has this signature from analysis: convention, return type, and each
	 * parameter's type and name (a parameter without a name has Ghidra's {@code param_N}).
	 */
	private static boolean hasSignature(Function f, String cc, DataType returnType,
			List<Parameter> params) {
		if (f.getSignatureSource() != SourceType.ANALYSIS ||
			!cc.equals(f.getCallingConventionName()) ||
			!f.getReturnType().isEquivalent(returnType) || f.getParameterCount() != params.size()) {
			return false;
		}
		for (int i = 0; i < params.size(); i++) {
			Parameter want = params.get(i);
			Parameter have = f.getParameter(i);
			String name = want.getName() != null ? want.getName()
					: SymbolUtilities.getDefaultParamName(i);
			if (!name.equals(have.getName()) ||
				!have.getDataType().isEquivalent(want.getDataType())) {
				return false;
			}
		}
		return true;
	}
}
