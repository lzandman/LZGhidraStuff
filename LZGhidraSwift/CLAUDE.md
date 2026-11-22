# CLAUDE.md

Rules and commands for LZGhidraSwift only. The repository rules (third-party binaries, memguard for headless analysis, public Ghidra API only) are in [../CLAUDE.md](../CLAUDE.md). The README describes the analyzers.

## Packages

`src/main/java/lzghidraswift/` holds the five analyzers (`SwiftDataTypesAnalyzer`, `SwiftSelfTypesAnalyzer`, `SwiftStringLiteralsAnalyzer`, `SwiftErrorRegisterAnalyzer`, `SwiftRuntimePrototypesAnalyzer`), `AnalysisLog` (their log lines), `Progress` (their phases on the task monitor) and `ExtractedSwiftSourceLanguage` (a Ghidra extension point like the analyzers: the Swift source language for images extracted from the dyld shared cache) directly. The subpackages below hold everything else. A package imports only those below it, and no subpackage imports the top level; `AnalyzerDependencyTest` checks the direction, on imports (also wildcard ones) and on full class names in the code. `ArchitectureTest` checks that every class is named in its package's row (a top-level class in this paragraph), so a new class needs a few words here; if its row then needs a second sentence, the package does two things.

| Package | Holds |
| --- | --- |
| `types` | Swift Data Types and Self Types: the types of `__swift5_types` (`SwiftTypeCatalog`, one `SwiftTypeInfo` each, with its `SwiftLayout` and the details of its log line), the Ghidra data types built for them (`SwiftTypeBuilder`), the mapping of field types to data types (`SwiftTypeMapper`), and the functions that may get `self` with their types (`SelfCandidates`) |
| `strings` | Swift String Literals: finding the instructions that may build a word (`CandidateFilter`), pairing the words (`RegisterPairFinder`, `FallbackPairer`, `LargeStringFinder` for the bytes), decoding them (`SwiftStringCodec`) into a `StringHit`, and marking the strings in the listing (`StringMarkup`, `StringBlock`) and the decompiler (`DecompilerEquates`, decompiled on worker threads by `DecompilerPool`, which also sets up the decompiler for Swift Self Types) |
| `throwing` | Swift Error Register: the throwing variants of the calling conventions (`ThrowingConventions`), `ErrorTestSites` with `CleanValues` (calls after which the error register is tested), `CallArguments` with `ArgumentValues` (the registers a caller sets up for an indirect call), `ThrowingCallOverride` (the call-site overrides), and `ThrowingCallees` (which functions and callees take the throwing variant, from names and facts) |
| `mangling` | Swift mangled names: the type names of the reflection metadata (`MangledName`, with `MangledIdentifiers`, read from a program by `MangledTypeReader` and parsed by `SwiftTypeName`) and the symbols of type members (`SwiftSymbol`) and throwing functions (`ThrowingSymbol`) |
| `flow` | The p-code data flow engines: `ValueFlow` with its steps (`PcodeStep`) and merges (`ValueMerger`), `ForwardFlow` (a work list over one function's instructions, for any lattice), `SelfRegisterUse` (whether a function reads a register's entry value); `PcodeOps`, the p-code tests they and `throwing` share (register overlap, stored values, saves) |
| `metadata` | Reading the Swift sections (`SwiftSections`), context descriptors (`ContextDescriptor`), the methods of class descriptors (`ClassMethods`) and the field descriptors of `__swift5_fieldmd` with their records (`FieldDescriptors`), both from the words of a `WordReader`; the static metadata found through the accessors (`MetadataLocator`, with `AccessorDecoder` and `X86AccessorDecoder`); `SymbolNames` (the symbol names at a function's entry, the imported name of an external or of the external reference from a pointer slot, a name without Mach-O's leading `_` or without every leading `_`, the body of a Swift symbol without `_$s` or `$s`, the function at a call target through thunks) |
| `runtime` | Swift Runtime Prototypes: the runtime functions and flag enums of the generated `data/swift-runtime-functions.txt` (`RuntimeTable`, also the entry of a function by its symbol names), the Ghidra data types for their IRGen type names and header pointees (`RuntimeTypes`), which functions get a signature and setting it (`RuntimePrototypes`), and the call-site overrides of the stack probe `___chkstk_darwin` with its convention (`StackProbes`) |
| `abi` | `CallingConventions`: the registers of the Swift calling convention on 64-bit AArch64 and x86_64, the check for those targets (`isSwiftTarget`), the program's Swift conventions by name (`swiftConvention`); `CallOverrides`, finding, comparing and writing the decompiler's call-site overrides (one `Status` and its `Counts` for both users) |

Tests sit in the package of the class they test, so they see package-private members. A member that another package needs is `public`; keep the rest package-private. The devtools scripts reach classes by their full names, such as `lzghidraswift.strings.RegisterPairFinder`.

## Code design

Each rule below comes from a problem that grew one step at a time while `gradle lint` passed.

- **`added()` only coordinates**: read, call the helper classes, log. The work is in classes that unit tests can run without a Ghidra program (as `AccessorDecoder` with its `Reader`).
- **Counters go into a `Counts` class from the first counter on**, with the summary lines as its methods (`summary()`, `layoutSummary()`). No `int[]` or `Object[]` whose indices mean different things. Keep each `formatted()` to a few arguments: split a long summary line into pieces.
- **Analyzers do not use each other.** Code that two analyzers need goes into its own class (`SwiftTypeCatalog`), never a static method of one analyzer called by the other. Helper classes do not use analyzers either. `AnalyzerDependencyTest` checks this; scripts may use analyzers.
- **A string that one class writes and another reads** (a marker in a data type's description, a log line format) is a constant of the writer, and the writer has the method that reads it (`SwiftTypeBuilder.DESCRIPTION_TAG` and `find`).
- **A member that a devtools script calls by reflection** (ProbeFlow reaches the package-private `ValueFlow.instructionsRun`) says so in its comment and has a lookup in `DevtoolsReflectionTest`. Nothing compiles the scripts against the extension, and unused-code inspections see no caller.
- **Extract when the second user comes**, in the same step, while the change is small; not before, when the boundary is a guess.
- **Search before writing a helper that reads from a `Program`** (symbols, registers, references, p-code inputs): grep the code for the Ghidra call it uses. If another class already makes it, use that class, or extract the call in the same step. `ArchitectureTest.OWNERS` lists the calls that have one owner; add a row when you find another duplicate.
- **A feature ends with a structure review**: read its whole diff (from the commit before its first change) against the rules in this file, and update the package table. Lint and tests can pass at every step while the structure drifts.
- A clean-up that should not change behaviour is checked with `devtools/run-fixtures.sh` on a zip built before and one built after, and `devtools/compare-fixtures.sh` (it prints nothing between "diffs against base" and "done").

## Commands

From `LZGhidraSwift/`:

```sh
gradle lint test buildExtension    # dist/ghidra_<version>_PUBLIC_<date>_LZGhidraSwift.zip
gradle spotlessApply               # format the Java files you touch
make -C fixtures                   # build/fixtures/*.dylib from the Swift sources (arm64 -O and -Onone, x86_64 -O, arm64e -O)
make -C fixtures layouts           # libLayouts.dylib and expected-layouts.txt (Swift Data Types)
make -C fixtures methods           # libMethods.dylib, arm64 and x86_64 (Swift Self Types)
make -C fixtures throws            # libThrows.dylib, arm64 and x86_64 and their strip -x copies, arm64e, arm64 -Onone (Swift Error Register)
make -C fixtures runtime           # libRuntime.dylib, arm64 -O and -Onone, x86_64, arm64e (Swift Runtime Prototypes)
OUT=<scratch dir> devtools/check-throwing-symbols.sh   # ThrowingSymbol vs swift-demangle on the macOS SDK; after gradle compileJava
python3 devtools/gen_runtime_functions.py <swift checkout>   # regenerates data/swift-runtime-functions.txt; then update the counts in RuntimeTableTest and RuntimePrototypesTest
devtools/test-fixtures.sh          # integration test: zip, fixtures, both runs, every checker; pass/fail, about 6½ minutes (CI: about 12½)
CHECK_ONLY=1 devtools/test-fixtures.sh             # the checks again, on the last run
devtools/run-fixtures.sh <out dir> dist/<zip>      # installs the zip, runs every fixture headless, about 5 minutes
devtools/compare-fixtures.sh <base out dir> <out dir>
STRING_BLOCK=1 devtools/run-fixtures.sh <out dir> dist/<zip>   # Strings fixtures only, option "String block" on
python3 fixtures/check_report.py <out dir>/Strings.txt fixtures/expected-strings.txt   # also checks the block
OUT=<scratch dir> devtools/headless-types.sh build/fixtures/libLayouts.dylib layouts
python3 fixtures/compare_layouts.py build/fixtures/expected-layouts.txt <scratch dir>/sdt/layouts.txt
```

Quit the Ghidra GUI before `install.sh` or `run-fixtures.sh` (not needed for `test-fixtures.sh`: it sets `XDG_CONFIG_HOME`, so Ghidra's user settings and the installed extension are in `build/test-fixtures/config`). Both unzip with `-DD`: the zip stores every file dated 1980, and Ghidra runs a script's class compiled earlier if the source is not newer, so without `-DD` an older compiled script would run silently in place of the new source. Heavy headless runs go through `../devtools/memguard.py`; the scripts already do.

Known fixture results are in `fixtures/known-differences/`, one file per check of `test-fixtures.sh`, with the cause: `self-x86_64` (1, `Methods.Sensor.record`), `strings`, `strings-log` and `block` (29 each, `waypointName`: Ghidra 12.2 does not recover its byte-offset jump table), `strings-x86_64` (2: "Sharp" and "Flat", a tag word computed at run time), `strings-arm64e` (19 missing and 19 unexpected); the dumps of `strings`, `block` and `strings-arm64e` also have 5 `decompiler pointer` lines (word 0 of a small string is an address in the image, and the decompiler shows it as a pointer: `String.str` is `char *`), and `strings-x86_64` has 4 of them, and 1 `decompiler none` ("×"); `throws-stripped` and `throws-x86_64-stripped` (2 each, functions reached only by tail calls), `throws-onone` (14, the expected file is written for `-O`, and 12.2 inverts 3 error tests), `runtime-onone` (6, `-Onone` tracks every access), `decompiler` (1, `$addTwice` on x86_64: Ghidra's demangler makes a function of an async function pointer record). Every other check has none. When a change adds or removes a difference on purpose, update the file and its explanation.

## Swift sources to read

Swift sources, if you have a local checkout of the Swift repository: string layout in `stdlib/public/core/StringObject.swift` and `SmallString.swift`, metadata in `include/swift/ABI/`.
