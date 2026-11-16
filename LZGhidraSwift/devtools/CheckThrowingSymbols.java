// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Compares lzghidraswift.mangling.ThrowingSymbol with the classes that throwing_oracle.py wrote.
// A single-file program, run by check-throwing-symbols.sh:
//   java -cp build/classes/java/main devtools/CheckThrowingSymbols.java <oracle.tsv>
// A function or initializer, also static, its dispatch thunk, protocol witness, merged copy or
// specialization, must get the oracle's effect; every other symbol (accessors, method
// descriptors, closures, metadata) null or NONE. Prints each difference, then a summary line; exit status 1 if there is a difference.

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import lzghidraswift.mangling.ThrowingSymbol;
import lzghidraswift.mangling.ThrowingSymbol.Effect;

public class CheckThrowingSymbols {

	/** Wrapper and suffix nodes (throwing_oracle.py) with which the symbol keeps its effect. */
	private static final Set<String> WRAPPERS = Set.of("Static", "DispatchThunk",
		"ProtocolWitness", "MergedFunction", "GenericSpecialization",
		"GenericSpecializationNotReAbstracted", "GenericSpecializationPrespecialized",
		"InlinedGenericFunction", "GenericPartialSpecialization",
		"GenericPartialSpecializationNotReAbstracted", "FunctionSignatureSpecialization");
	private static final Map<String, Effect> CLASSES = Map.of("none", Effect.NONE, "async-none",
		Effect.NONE, "throws", Effect.THROWS, "typed", Effect.TYPED_THROWS, "async-throws",
		Effect.ASYNC_THROWS, "async-typed", Effect.ASYNC_TYPED_THROWS);

	public static void main(String[] args) throws IOException {
		List<String> lines = Files.readAllLines(Path.of(args[0]));
		Map<String, Integer> agree = new TreeMap<>();
		int differences = 0;
		int others = 0;
		for (String line : lines) {
			String[] f = line.split("\t", -1);
			boolean kept = f[2].isEmpty() ||
				Arrays.stream(f[2].split("/")).allMatch(WRAPPERS::contains);
			Effect expected = kept ? CLASSES.get(f[1]) : null;
			Effect actual = ThrowingSymbol.classify(f[0]);
			boolean ok = expected != null ? expected == actual
					: actual == null || actual == Effect.NONE;
			if (!ok) {
				differences++;
				System.out.println("%s\toracle %s (%s)\tclassify %s".formatted(f[0], f[1],
					f[2].isEmpty() ? "-" : f[2], actual));
			}
			else if (expected != null) {
				agree.merge(expected.toString(), 1, Integer::sum);
			}
			else {
				others++;
			}
		}
		System.out.println("%d symbols: functions agree %s, %d others without effect, %d differences"
				.formatted(lines.size(), agree, others, differences));
		System.exit(differences == 0 ? 0 : 1);
	}
}
