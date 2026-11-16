// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.junit.Test;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * The package-private members that devtools scripts call by reflection, looked up as the scripts
 * do. Nothing compiles those scripts against the extension, and an unused-code inspection sees
 * no caller: removing {@code ValueFlow.instructionsRun()} once broke ProbeFlow. Add a lookup here for every new reflective call in a script.
 */
public class DevtoolsReflectionTest {

	private static final String PROBE_FLOW = "devtools/ghidra_scripts/ProbeFlow.java";

	@Test
	public void probeFlowFindsRegisterPairFinder() throws ClassNotFoundException {
		Class<?> c = Class.forName("lzghidraswift.strings.RegisterPairFinder");
		try {
			assertNotNull(c.getDeclaredConstructor(Program.class, Function.class));
			assertNotNull(c.getDeclaredMethod("run", TaskMonitor.class));
			assertNotNull(c.getDeclaredMethod("flow"));
		}
		catch (NoSuchMethodException e) {
			fail(PROBE_FLOW + " calls a missing member: " + e.getMessage());
		}
	}

	@Test
	public void probeFlowFindsValueFlow() throws ClassNotFoundException {
		Class<?> c = Class.forName("lzghidraswift.flow.ValueFlow");
		try {
			assertNotNull(c.getDeclaredMethod("iterations"));
			assertNotNull(c.getDeclaredMethod("converged"));
			assertNotNull(c.getDeclaredMethod("instructionsRun"));
		}
		catch (NoSuchMethodException e) {
			fail(PROBE_FLOW + " calls a missing member: " + e.getMessage());
		}
	}
}
