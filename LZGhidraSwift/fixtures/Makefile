# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Leon Zandman

BUILD := ../build/fixtures

all: $(BUILD)/libStrings.dylib $(BUILD)/libStrings-Onone.dylib $(BUILD)/libStrings-x86_64.dylib \
	layouts layouts-x86_64 methods arm64e throws runtime

# Swift Data Types: the library to analyse, and the expected layouts printed by an executable
# built from the same source with the same options. check_layouts.py checks that the expected
# file covers every type of the library.
layouts: $(BUILD)/libLayouts.dylib $(BUILD)/expected-layouts.txt
	python3 check_layouts.py $(BUILD)/libLayouts.dylib $(BUILD)/expected-layouts.txt

$(BUILD)/libLayouts.dylib: Layouts.swift | $(BUILD)
	swiftc -emit-library -module-name Layouts -O $< -o $@

$(BUILD)/DumpLayouts: Layouts.swift DumpLayouts.swift | $(BUILD)
	swiftc -parse-as-library -module-name Layouts -O Layouts.swift DumpLayouts.swift -o $@

$(BUILD)/expected-layouts.txt: $(BUILD)/DumpLayouts
	$< > $@

# The same for x86_64. DumpLayouts-x86_64 runs under Rosetta.
X86 := -target x86_64-apple-macos13

layouts-x86_64: $(BUILD)/libLayouts-x86_64.dylib $(BUILD)/expected-layouts-x86_64.txt
	python3 check_layouts.py $(BUILD)/libLayouts-x86_64.dylib $(BUILD)/expected-layouts-x86_64.txt

$(BUILD)/libLayouts-x86_64.dylib: Layouts.swift | $(BUILD)
	swiftc -emit-library -module-name Layouts -O $(X86) $< -o $@

$(BUILD)/DumpLayouts-x86_64: Layouts.swift DumpLayouts.swift | $(BUILD)
	swiftc -parse-as-library -module-name Layouts -O $(X86) Layouts.swift DumpLayouts.swift -o $@

$(BUILD)/expected-layouts-x86_64.txt: $(BUILD)/DumpLayouts-x86_64
	arch -x86_64 $< > $@

# Swift Self Types: methods whose self the analyzer types (expected-self.txt is hand-written).
methods: $(BUILD)/libMethods.dylib $(BUILD)/libMethods-x86_64.dylib

$(BUILD)/libMethods.dylib: Methods.swift | $(BUILD)
	swiftc -emit-library -module-name Methods -O $< -o $@

$(BUILD)/libMethods-x86_64.dylib: Methods.swift | $(BUILD)
	swiftc -emit-library -module-name Methods -O $(X86) $< -o $@

# Swift Error Register: throwing functions and their callers, arm64 and x86_64, also arm64e and
# arm64 -Onone. The stripped copies keep only the exported symbols (strip -x removes the local
# ones), so the analyzer finds the internal throwing functions from their callers. strip changes
# no code address.
throws: $(BUILD)/libThrows.dylib $(BUILD)/libThrows-x86_64.dylib \
		$(BUILD)/libThrows-stripped.dylib $(BUILD)/libThrows-x86_64-stripped.dylib \
		$(BUILD)/libThrows-arm64e.dylib $(BUILD)/libThrows-Onone.dylib

$(BUILD)/%-stripped.dylib: $(BUILD)/%.dylib
	strip -x -o $@ $<

$(BUILD)/libThrows.dylib: Throws.swift | $(BUILD)
	swiftc -emit-library -module-name Throws -O $< -o $@

$(BUILD)/libThrows-x86_64.dylib: Throws.swift | $(BUILD)
	swiftc -emit-library -module-name Throws -O $(X86) $< -o $@

$(BUILD)/libThrows-arm64e.dylib: Throws.swift | $(BUILD)
	swiftc -emit-library -module-name Throws -O $(ARM64E) $< -o $@

$(BUILD)/libThrows-Onone.dylib: Throws.swift | $(BUILD)
	swiftc -emit-library -module-name Throws -Onone $< -o $@

# Swift Runtime Prototypes: runtime calls with flag arguments and two-register results, arm64 -O
# and -Onone, x86_64, arm64e (expected-runtime.txt is hand-written).
runtime: $(BUILD)/libRuntime.dylib $(BUILD)/libRuntime-Onone.dylib \
		$(BUILD)/libRuntime-x86_64.dylib $(BUILD)/libRuntime-arm64e.dylib

$(BUILD)/libRuntime.dylib: Runtime.swift | $(BUILD)
	swiftc -emit-library -module-name Runtime -O $< -o $@

$(BUILD)/libRuntime-Onone.dylib: Runtime.swift | $(BUILD)
	swiftc -emit-library -module-name Runtime -Onone $< -o $@

$(BUILD)/libRuntime-x86_64.dylib: Runtime.swift | $(BUILD)
	swiftc -emit-library -module-name Runtime -O $(X86) $< -o $@

$(BUILD)/libRuntime-arm64e.dylib: Runtime.swift | $(BUILD)
	swiftc -emit-library -module-name Runtime -O $(ARM64E) $< -o $@

# arm64e builds of the three fixtures (pointer authentication in the code, as in the dyld shared
# cache). Their layouts are the arm64 ones, so there is no DumpLayouts-arm64e: running third-party
# arm64e code needs a boot-arg. Compare with expected-layouts.txt and expected-self.txt.
ARM64E := -target arm64e-apple-macos13

arm64e: $(BUILD)/libLayouts-arm64e.dylib $(BUILD)/libMethods-arm64e.dylib $(BUILD)/libStrings-arm64e.dylib \
		$(BUILD)/expected-layouts.txt
	python3 check_layouts.py $(BUILD)/libLayouts-arm64e.dylib $(BUILD)/expected-layouts.txt

$(BUILD)/libLayouts-arm64e.dylib: Layouts.swift | $(BUILD)
	swiftc -emit-library -module-name Layouts -O $(ARM64E) $< -o $@

$(BUILD)/libMethods-arm64e.dylib: Methods.swift | $(BUILD)
	swiftc -emit-library -module-name Methods -O $(ARM64E) $< -o $@

$(BUILD)/libStrings-arm64e.dylib: Strings.swift | $(BUILD)
	swiftc -emit-library -module-name Strings -O $(ARM64E) $< -o $@

$(BUILD):
	mkdir -p $@

$(BUILD)/libStrings.dylib: Strings.swift | $(BUILD)
	swiftc -emit-library -module-name Strings -O $< -o $@

$(BUILD)/libStrings-Onone.dylib: Strings.swift | $(BUILD)
	swiftc -emit-library -module-name Strings -Onone $< -o $@

$(BUILD)/libStrings-x86_64.dylib: Strings.swift | $(BUILD)
	swiftc -emit-library -module-name Strings -O -target x86_64-apple-macos13 $< -o $@

clean:
	rm -rf $(BUILD)

.PHONY: all arm64e clean layouts layouts-x86_64 methods runtime throws
