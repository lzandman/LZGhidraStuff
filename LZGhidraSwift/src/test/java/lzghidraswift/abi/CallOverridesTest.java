// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.abi;

import static org.junit.Assert.*;

import java.util.List;
import java.util.function.Predicate;

import org.junit.Test;

import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.exception.InvalidInputException;
import lzghidraswift.abi.CallOverrides.Status;

public class CallOverridesTest {

	private static final Predicate<String> STDCALL = "__stdcall"::equals;

	private static FunctionDefinitionDataType sig(String param, boolean pointer) {
		FunctionDefinitionDataType f = new FunctionDefinitionDataType("f");
		f.setReturnType(VoidDataType.dataType);
		f.setArguments(new ParameterDefinition[] { new ParameterDefinitionImpl(param,
			pointer ? PointerDataType.dataType : UnsignedLongDataType.dataType, null) });
		return f;
	}

	@Test
	public void comparesParametersByNameAndType() {
		assertTrue(CallOverrides.same(sig("size", false), sig("size", false)));
		assertFalse(CallOverrides.same(sig("size", false), sig("n", false)));
		assertFalse(CallOverrides.same(sig("size", false), sig("size", true)));
	}

	@Test
	public void comparesVarargsAndReturnType() {
		FunctionDefinitionDataType varargs = sig("size", false);
		varargs.setVarArgs(true);
		assertFalse(CallOverrides.same(sig("size", false), varargs));
		FunctionDefinitionDataType returns = sig("size", false);
		returns.setReturnType(UnsignedLongDataType.dataType);
		assertFalse(CallOverrides.same(sig("size", false), returns));
	}

	private static FunctionDefinitionDataType sig(String convention, String param)
			throws InvalidInputException {
		FunctionDefinitionDataType f = sig(param, false);
		f.setCallingConvention(convention);
		return f;
	}

	@Test
	public void keepsAnOverrideThatIsNotOurs() throws InvalidInputException {
		// Not ours, even with the same signature.
		assertEquals(Status.OTHER, CallOverrides.decide(sig("__cdecl", "size"),
			sig("__cdecl", "size"), STDCALL));
		assertEquals(Status.OTHER, CallOverrides.decide(sig("__cdecl", "size"),
			sig("__stdcall", "size"), STDCALL));
	}

	@Test
	public void keepsOurOverrideWithTheSameSignature() throws InvalidInputException {
		assertEquals(Status.PRESENT, CallOverrides.decide(sig("__stdcall", "size"),
			sig("__stdcall", "size"), STDCALL));
	}

	@Test
	public void replacesOurOverrideWithAnotherSignature() throws InvalidInputException {
		assertEquals(Status.REPLACED, CallOverrides.decide(sig("__stdcall", "n"),
			sig("__stdcall", "size"), STDCALL));
		// Ours by the test, another convention than the new one.
		assertEquals(Status.REPLACED, CallOverrides.decide(sig("__stdcall", "size"),
			sig("__thiscall", "size"), name -> name.startsWith("__")));
	}

	@Test
	public void countsEachStatus() {
		CallOverrides.Counts counts = new CallOverrides.Counts();
		assertFalse(counts.written());
		for (Status s : new Status[] { Status.PRESENT, Status.OTHER, Status.OTHER }) {
			counts.count(s);
		}
		assertFalse(counts.written());
		counts.count(Status.REPLACED);
		counts.count(Status.ADDED);
		counts.count(Status.ADDED);
		assertEquals(List.of(2, 1, 1, 2),
			List.of(counts.added, counts.replaced, counts.present, counts.other));
		assertTrue(counts.written());
		assertTrue(Status.ADDED.written());
		assertTrue(Status.REPLACED.written());
		assertFalse(Status.PRESENT.written());
		assertFalse(Status.OTHER.written());
	}
}
