// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.throwing;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.InvalidInputException;
import lzghidraswift.abi.CallOverrides;
import lzghidraswift.abi.CallingConventions;
import lzghidraswift.throwing.CallArguments.Arguments;
import lzghidraswift.throwing.CallArguments.Kind;

/**
 * The call-site override that gives an indirect call ({@code blr}) to a throwing closure the
 * throwing variant of a calling convention. The decompiler locks the prototype of an override and
 * takes only the inputs that it names, so the signature names the arguments that the caller sets
 * up ({@link CallArguments}): {@code result}, the indirect result buffer (x8, RAX), with the
 * variant that has it as a parameter; {@code context}, the closure's context in the self register
 * (x20, r13), with the variant of {@code __swift_thiscall}; then {@code arg0}, {@code arg1}, ... in the
 * integer argument registers, a pointer for a stack address and {@code undefined8} for others,
 * and on in the stack arguments as {@code undefined8}; then {@code farg0}, ... as {@code double}
 * in the floating-point registers.
 * <p>
 * The return type is pointer-sized {@code undefined}, so that the result in x0 or RAX stays;
 * {@code void} with an indirect result. A result in other registers (d0, the second word of a
 * {@code String} in x1) shows as a value that the call returns there ({@code extraout_d0}),
 * because the variant kills the result registers ({@link ThrowingConventions}).
 * <p>
 * Earlier versions wrote a signature with varargs and no parameters, which lost arguments. An
 * override with a throwing variant and another signature is replaced; one with another
 * convention is kept.
 */
public final class ThrowingCallOverride {

	private ThrowingCallOverride() {
	}

	/**
	 * The throwing variant for a call with {@code args}, or null
	 * ({@link ThrowingConventions#callVariant}).
	 */
	public static String variant(CompilerSpec spec, Arguments args) {
		return ThrowingConventions.callVariant(spec, args.context() != null,
			args.indirectResult() != null);
	}

	/**
	 * Writes the override with {@code variant} and the arguments {@code args} for the call at
	 * {@code call} in {@code caller}.
	 */
	public static CallOverrides.Status apply(Function caller, Address call, String variant,
			Arguments args) throws InvalidInputException {
		return CallOverrides.write(caller, call,
			signature(caller.getProgram().getDataTypeManager(), variant, args),
			name -> name.endsWith(CallingConventions.VARIANT_SUFFIX));
	}

	/** The signature of the override. */
	static FunctionDefinitionDataType signature(DataTypeManager dtm, String variant,
			Arguments args) throws InvalidInputException {
		List<ParameterDefinition> params = new ArrayList<>();
		if (args.indirectResult() != null) {
			params.add(new ParameterDefinitionImpl("result", PointerDataType.dataType, null));
		}
		if (args.context() != null) {
			params.add(new ParameterDefinitionImpl("context", type(args.context()), null));
		}
		for (int i = 0; i < args.integers().size(); i++) {
			params.add(new ParameterDefinitionImpl("arg" + i, type(args.integers().get(i)), null));
		}
		for (int i = 0; i < args.stackArguments(); i++) {
			params.add(new ParameterDefinitionImpl("arg" + (args.integers().size() + i),
				Undefined.getUndefinedDataType(8), null));
		}
		for (int i = 0; i < args.floats().size(); i++) {
			params.add(new ParameterDefinitionImpl("farg" + i, DoubleDataType.dataType, null));
		}
		FunctionDefinitionDataType sig = new FunctionDefinitionDataType("throwing", dtm);
		sig.setCallingConvention(variant);
		sig.setArguments(params.toArray(ParameterDefinition[]::new));
		sig.setReturnType(args.indirectResult() != null ? VoidDataType.dataType
				: Undefined.getUndefinedDataType(8));
		return sig;
	}

	private static DataType type(Kind kind) {
		return kind == Kind.STACK ? PointerDataType.dataType : Undefined.getUndefinedDataType(8);
	}
}
