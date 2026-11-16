# LZGhidraSwift

A Ghidra extension with analyzers for Swift binaries on macOS (arm64 and x86_64 Mach-O). It uses only Ghidra's public API and parses the Swift sections itself.

| Analyzer | What it does | State |
| --- | --- | --- |
| [Swift String Literals](#swift-string-literals) | Decodes the Swift `String` literals that code builds from immediates, and marks them in the listing and the decompiler | done |
| [Swift Data Types](#swift-data-types) | Swift structs, classes and enums as data types in `/SwiftTypes/<Module>`, with the stored properties at their offsets from the type metadata | done |
| [Swift Self Types](#swift-self-types) | Gives the methods of those types a parameter `self` in x20 (r13 on x86_64), typed as a pointer to the type, so that the decompiler shows `self->field` | done |
| [Swift Error Register](#swift-error-register) | Gives throwing functions a calling convention in which a call changes the error register x21 (r12 on x86_64), so that the decompiler keeps the code that handles a thrown error | functions with symbols, functions without symbols found from their callers, indirect calls, typed throws; not async |
| [Swift Runtime Prototypes](#swift-runtime-prototypes) | Gives the imported Swift runtime functions (`swift_retain`, `swift_allocObject`, `swift_beginAccess`, ...) their signatures from the Swift source, with enums for flag arguments and structures for two-register results, so that calls show their arguments and results | done; not async functions |

In Analysis → Auto Analyze the analyzers carry the prefix `LZ` (`LZ Swift String Literals`, ...), so that they sort together; their log lines start with the same name.

Tested with Ghidra 12.2 (Homebrew, macOS on Apple silicon). Other versions are not tested: Ghidra 12.2 replaced the Swift compiler spec of 12.1.x with the conventions `__swift_stdcall` and `__swift_thiscall`, and the fixture expectations use 12.2's names. The zip only installs without a warning into the Ghidra version it was built against; for another version, build it with `GHIDRA_INSTALL_DIR` set to that Ghidra.

Images extracted from the dyld shared cache need the Mach-O Function Starts analyzer of [LZGhidraGeneric](../LZGhidraGeneric/README.md); without it, code that only a `swift_once`, a jump table or a tail branch reaches stays outside functions.

## Swift in images extracted from the dyld shared cache

Ghidra 12.2 finds Swift in a program at import (its "source languages"), but only in the format `Mac OS X Mach-O`. An image extracted from the dyld shared cache has the format `Extracted DYLD Component`, so it gets no Swift: Ghidra's Swift demangler and Swift Type Metadata analyzer do not run, the program has no `__swift_stdcall` or `__swift_thiscall`, and Swift Error Register adds no variants ("0 added"). Ghidra 12.1.4 found Swift by the section names alone.

The extension adds the class `ExtractedSwiftSourceLanguage`, which gives such an image Ghidra's `Swift` source language when it has a block whose name starts with `__swift` (Ghidra's own rule for Mach-O). It is not an analyzer and has no option. It stands down once Ghidra's `MachoSwiftSourceLanguage` accepts the format itself; it is meant to go when Ghidra fixes this.

On a small Swift framework of the macOS 27.0.1 arm64e cache (176 KB, 2,541 functions), imported with the extension installed, the first analysis gives what Ghidra 12.1.4 gave: 225 functions with a demangled signature, 19 still mangled, 48 types in `/SwiftTypeMetadata`, and Swift Error Register adds its four variants.

A program imported before the extension was installed has no Swift yet. Run Auto Analyze once ("Source Language Support" then finds Swift and adds the conventions), close and reopen the program, and run Auto Analyze again: Ghidra decides which analyzers can run when it opens a program. Not tested on projects made by Ghidra 12.1.x.

`devtools/ghidra_scripts/ProbeDyld.java <image file name>` prints Ghidra's view of an extracted image after auto-analysis: its Mach-O header and section sizes against the blocks, the pointers of the data sections by target, the symbolic references and parent pointers of the Swift sections, call targets, pointer authentication instructions, and decompiler warnings.

## Build and install

Ready-made zips are on the Releases page; see [Install a release](../README.md#install-a-release). To build it yourself:

You need Java 25, Gradle 9.1 or newer, and a Ghidra installation.

```sh
cd LZGhidraSwift
export GHIDRA_INSTALL_DIR=/opt/homebrew/opt/ghidra/libexec
export JAVA_HOME=/opt/homebrew/opt/openjdk@25
gradle buildExtension    # dist/ghidra_12.2_PUBLIC_<date>_LZGhidraSwift.zip
gradle test              # unit tests of the Ghidra-free parts
gradle lint              # javac -Xlint, Error Prone, Spotless, PMD, Checkstyle; fails on any finding
gradle spotlessApply     # formats the Java sources with Ghidra's Eclipse profile
```

The first build downloads the Spotless and Error Prone Gradle plugins and the check tools from the Gradle plugin portal and Maven Central. The checks are configured in `../buildconfig/quality.gradle`, `../buildconfig/pmd-rules.xml` and `../buildconfig/checkstyle.xml`, and none of them is part of `buildExtension`. Error Prone runs on every compile and reports warnings only; `gradle -Pstrict compileJava` turns them into errors.

Install it with File → Install Extensions → `+` → the zip in `dist/`, or unzip the zip into `~/Library/ghidra/ghidra_<version>_PUBLIC/Extensions/`. Restart Ghidra: a running Ghidra does not load new extensions.

### Fixture tests

`devtools/test-fixtures.sh` is the integration test. It builds the zip and the fixtures (Swift libraries compiled from `fixtures/*.swift`), analyses each fixture with headless Ghidra and the extension, and checks the results against the known answers. It prints one line per check and exits with status 1 if any check fails. A run takes about 6½ minutes (M-series Mac, Ghidra 12.2; about 12½ minutes on GitHub's macOS runner) and needs macOS, `swiftc`, Rosetta and a Ghidra with its native decompiler. The release zip has no macOS natives: build them first with `gradle buildNatives` in `<Ghidra>/support/gradle` (Ghidra's GettingStarted.md, "Building Native Components"). Homebrew's Ghidra has them. The `decompiler` check fails when they are missing. The extension is installed into a separate Ghidra settings directory under `build/test-fixtures/`, so your own Ghidra installation and settings stay as they are, and the Ghidra GUI may stay open.

A check passes when its differences are exactly those listed in `fixtures/known-differences/<check>.txt`; each file says why the differences occur. Addresses are not compared, because they change with the Swift compiler version. A known difference that no longer occurs also fails the check: remove its line. `CHECK_ONLY=1 devtools/test-fixtures.sh` repeats the checks on the last run without running Ghidra again.

The fixture workflow (`.github/workflows/fixtures.yaml`) runs the same test on a GitHub macOS runner (label `xcode-27`), started by hand (`gh workflow run fixtures.yaml`). The known differences were recorded with Xcode 27.0 (Swift 6.4); a different compiler version can produce different code, so a difference that occurs only in CI may come from the compiler. The job prints the Xcode and Swift versions.

## Swift Data Types

### What it creates

For each non-generic struct, class and enum in `__swift5_types` whose metadata is in the binary, a data type in `/SwiftTypes/<Module>/<Outer>/<Name>`:

| Swift | Data type |
| --- | --- |
| struct | A structure of the Swift size (not the stride) and alignment, each stored property at its offset |
| class | A structure of the instance size: `metadata` and `refCounts` (Swift root class), `isa` (Objective-C superclass) or `super` (a superclass of the binary), then the class's own stored properties |
| enum without payload | An enum data type with the case names, valued 0, 1, … in declaration order (the tag) |

The offsets come from the field offset vector of the static type metadata, which the analyzer finds by decoding the type's metadata accessor (arm64 and x86_64). Size and alignment come from the value witness table (structs, enums) or the class metadata. Field names come from `__swift5_fieldmd`. The analyzer parses these sections itself and does not use Ghidra's Swift classes.

A field's data type follows its mangled Swift type:

| Swift type | Data type |
| --- | --- |
| `Int`, `UInt`, `Int8` … `UInt64`, `Double`, `Float`, `Float16`, `Bool`, `CGFloat` | `longlong`, `ulonglong`, `schar` … `ulonglong`, `double`, `float`, `float2`, `bool`, `double` |
| `String`, `Character` | `/SwiftTypes/Swift/String` { `countAndFlags`, `object` } |
| `Array`, `Dictionary`, `Set`, classes of other modules, Objective-C classes, blocks, C function pointers, `AnyObject`, Objective-C protocols | `void *` |
| `UnsafePointer<T>`, raw pointers, `OpaquePointer` | `T *`, `void *` |
| `UnsafeBufferPointer<T>` and the other buffer pointers | { `start`, `count` } |
| a struct or enum of the binary | that data type, embedded |
| a class of the binary | a pointer to its structure |
| `T?` | `T` if T has a spare bit pattern for nil; else `Optional<T>` { `value`, `tag` } (9 bytes for `Double?`) |
| `any P` | `Existential` { `buffer`, `type`, `witnessTable` } (one witness table per Swift protocol); class-constrained: `ClassExistential` { `object`, `witnessTable` } |
| `any Error` (alone, or with marker protocols such as `Sendable`) | `void *` (a reference to a box) |
| `any P.Type` | `ExistentialMetatype` { `type`, `witnessTable` }; `Any.Type`, `AnyObject.Type` and Objective-C protocols: `void *` |
| `T.Type` | a class: `void *` (the metadata); a struct or enum: no component (a stored metatype of a struct is thin, 0 bytes) |
| `InlineArray<N, T>` | an array of N elements of T's type |
| an actor's `$defaultActor` | `/SwiftTypes/Swift/DefaultActorStorage`, 96 opaque bytes, alignment 16 |
| closure | `Closure` { `function`, `context` } |
| tuple | a structure named like `(Swift.Int, Swift.Float)` |
| `weak`, `unowned`, `unowned(unsafe)` | as the referenced type |

Fields of size 0 (an enum with one case, an empty struct, a struct's metatype) get no component; Swift puts them at the offset of the next field. Helper types are in `/SwiftTypes/Swift`. Anything else (generic types of other modules such as `SwiftUI.State<T>`, imported C structs, enums with payloads) becomes undefined bytes up to the next field. Every field's comment holds the Swift type as `String(reflecting:)` writes it, so a field without a type still says what it is. Two exceptions: Core Foundation types are named as in Swift source (`__C.SecKey`), where the runtime writes `__C.SecKeyRef`; and a binary built for an older deployment target can give a type only as a function that builds its metadata at run time (`@isolated(any)` and typed throws below macOS 15), which the comment shows as `<metadata accessor at …>`. A type that does not fit before the next field also becomes undefined bytes, with a `SWIFTDT-WARN` log line.

Ghidra's Swift demangler creates structures in `/Demangler/<Module>` for types that appear in demangled symbols: 1-byte placeholders, or a packed layout of the fields whose types it could demangle. Their sizes are often wrong (Layouts fixture: `Collections` 3 bytes, Swift 40; `Composite` 16, Swift 148). The analyzer replaces each with the new type of the same name, so that function signatures that use them get the real layout. For a struct or class it moves the demangler's structure to `/SwiftTypes` and fills it in, so the data type keeps its ID (and its universal ID) and every use follows. An enum data type cannot take the place of a structure, so for an enum the analyzer calls Ghidra's `replaceDataType`, which reads every defined data, symbol and function of the program once per call: about 0.7 s per enum in an arm64 app binary with 377,000 functions (Ghidra 12.2, M5 Mac with 24 GB).

Private types of different source files can have the same name. When names collide, the analyzer names them as Swift does, with the anonymous context: `Module.(unknown context at $187a20).TestSegmentedControl`.

Running the analyzer again changes nothing: a type is replaced only if it differs.

### Options

Analysis → Auto Analyze → LZ Swift Data Types. It is on by default for programs with `__swift5_types`, and can also run as Analysis → One Shot. It takes up to a few seconds and shows no progress. The summary is in the application log, in the lines that start with `LZ Swift Data Types`.

| Option | Default | Effect |
| --- | --- | --- |
| Replace demangler placeholders | on | Replace the demangler's structures of the same name, as above |

Log lines: `SWIFTTYPE` and `SWIFTFIELD` (every type and field record with its offset and mangled type), `SWIFTDT-SKIP` (a type without a data type, and why), `SWIFTDT-WARN`, `SWIFTDT-PLACEHOLDER`, and four summary lines.

### How it is tested

Against fixtures with known answers (`fixtures/Layouts.swift`, compared with the layouts the compiler printed) on arm64, arm64e and x86_64, and against the Swift runtime: `devtools/runtime-layouts.sh` loads a binary, lets the Swift runtime build each type's metadata and reads the layouts with the runtime's reflection; `devtools/compare_runtime.py` compares them with the analyzer's types. Size, stride, alignment and every field's offset and name agreed on the binaries it was run on (open-source Swift toolchain binaries); the remaining differences are names of imported C types (the binary has the Swift name, the runtime prints the C name: `__C.SecKey` and `__C.SecKeyRef`).

Running the analyzer a second time changes nothing. It takes a few seconds in auto-analysis on the binaries tested.

### What it misses

- Generic types (no static metadata) and types whose metadata is built at run time (singleton initialization, such as structs with fields of resilient types from other frameworks): no data type, logged with the reason.
- Enums with payloads, enums of size 0 (no cases, or one), and `@objc` enums (no case names in the binary): no data type.
- Swift classes whose superclass is an Objective-C class other than `NSObject` (`NSView`, `NSThread`, …), and their subclasses: no data type. The binary lays their fields out after an 8-byte `isa`; the Objective-C runtime moves them past the superclass's instance variables when it loads the class, and the superclass's size is not in the binary. Logged as `SWIFTDT-SKIP … Objective-C superclass NSThread: field offsets are slid at run time`.
- Field types whose size is only known to another framework: generic types of other modules, SwiftUI types, imported C structs. They stay undefined.
- Protocols of other binaries: the analyzer cannot read whether they are class-constrained and assumes not. A `weak var delegate: OtherModule.Delegate?` (16 bytes) then does not fit the 40-byte opaque existential and stays undefined.
- Constrained existentials (`any P<Int>`, mangled `Xj`) and other rare manglings: the type name in the comment shows the mangled text.
- Applying the types to code: only `self` of methods, by [Swift Self Types](#swift-self-types). Other parameters and variables are not typed.
- Tested only on Mach-O built for Apple platforms; a Swift binary without Objective-C interop was not available.

### Scripts and tests

- `ghidra_scripts/DumpSwiftTypes.java <output>` writes the types under `/SwiftTypes` in the format of `fixtures/DumpLayouts.swift`.
- `fixtures/Layouts.swift` declares one type per case of the mapping; `DumpLayouts.swift`, compiled with it, prints the layouts the compiler chose. `make -C fixtures layouts` (arm64) and `make -C fixtures layouts-x86_64` (needs Rosetta to run `DumpLayouts`) build the library and `build/fixtures/expected-layouts*.txt`.
- `devtools/headless-types.sh <binary> <name>` imports and analyses a binary headless, runs the analyzer a second time (it must change nothing) and the dump. `fixtures/compare_layouts.py` compares the dump with the expected layouts. The commands for the Layouts fixture are in `CLAUDE.md`.
- `devtools/runtime-layouts.sh <output> <binary>` writes the layouts of a binary's Swift types as the Swift runtime sees them, in the same format, for binaries without a fixture: a dylib (`devtools/runtime-layouts/`) loaded into the binary with `DYLD_INSERT_LIBRARIES` calls each type's metadata accessor and reads the runtime's reflection. Not for binaries with hardened runtime. `<binary>` may also be an image of the dyld shared cache, which has no file on disk: any path `dyld_info` resolves, such as `/System/Library/PrivateFrameworks/<F>.framework/<F>`; it is loaded with `dlopen`, so its own initializers run. `devtools/compare_runtime.py` compares it with a dump.

## Swift Self Types

### What it does

Swift passes `self` in the context register, x20 on arm64 and r13 on x86_64, when `self` is a class reference or is passed by address: every instance method, accessor, initializing `init` and `deinit` of a class, and the `mutating` methods, setters and `_modify` accessors of a struct or enum. The analyzer gives such a function a parameter `self` in that register, typed as a pointer to the data type that [Swift Data Types](#swift-data-types) built. For example, `*(float *)(unaff_x20 + 0x8c) == 1.0` becomes `(self->settings).temperature == 1.0`.

A class's allocating initializer (`__allocating_init`, symbol `…fC`) gets the metatype in that register: the class's metadata, which it passes to `swift_allocObject`. Its `self` is `Metadata *`, the structure of [Swift Runtime Prototypes](#swift-runtime-prototypes), so the call reads `_swift_allocObject(self,0x3d,7)` without a cast. This also covers generic classes, which have no data type.

It finds the methods in two places:

- The method table and the override table of each class descriptor (in `__TEXT`, after the descriptor). These list the class's overridable methods and overrides even when the binary has no symbols for them. Each entry is checked against the vtable in the class metadata. Initializers (`self` is the metatype there) and static methods are left out.
- Swift symbols of members of the types (`$s<type><member>…F`, `…vg`, `…vs`, `…vM`, `…fc`, `…fd`, `…fC`, …), which also reach final methods and the methods of structs and enums. A non-mutating struct method gets its value in the argument registers, and the mangled name does not say whether a method is mutating. So a struct or enum method is typed only if it reads the entry value of x20 before writing it.

A function found for more than one type, which happens when the linker folds identical code (`ret`, two classes' trivial `_modify`), is left alone. So are thunks, external functions and functions with a user-defined signature.

`self` gets custom storage: Ghidra has no calling convention that puts a parameter in x20 for every function. Custom storage locks the prototype, so for a function without a signature the analyzer first commits the parameters the decompiler finds (as Decompiler Parameter ID does, without types and without the return value). It does the same for a function with a parameter without storage: Ghidra's demangler leaves a parameter that it cannot place unassigned (the generic value of `Box<A>.init(A)`, the array of a property setter), and the decompiler ignores a locked prototype with such a parameter. Ghidra's Swift demangler gives demangled class methods and struct setters `__swift_thiscall` (Ghidra 12.2) with `void *this` in x20, and adds a second copy of `self` to some (a struct's value as the last parameter of a method, a pointer to the class as the last parameter of a property getter). The analyzer replaces `this` with `self` and removes that copy.

Running it again changes nothing.

### Options

Analysis → Auto Analyze → LZ Swift Self Types. It is on by default for programs with `__swift5_types` on arm64 and x86_64, runs after Swift Data Types, and can also run as Analysis → One Shot, for example after you have changed types or created functions. Swift String Literals runs after it, because its decompiler equates depend on the signatures. It has no options. The summary is in the application log, in the lines that start with `LZ Swift Self Types`; each changed function has a `SWIFTSELF` line, each folded function a `SWIFTSELF-CONFLICT` line, and each function whose decompile failed a `SWIFTSELF-DECOMP-FAILED` line. If the decompiler does not start at all, one `SWIFTSELF-DECOMP-NOSTART` line gives its message.

### Tests

The analyzer runs on the `Methods` fixture. Every vtable entry it types is checked against the class's method table.


The `Methods` fixture is checked function by function (`fixtures/check_self.py`): the type of `self`, no `self` where Swift does not pass it there, and field accesses in the decompiled C. The x86_64 build gives the same functions and types.

### What it misses

- Methods with neither a method table entry nor a symbol: methods of final classes, final and private methods, in stripped binaries.
- Methods of types without a data type (generic types, types whose metadata is built at run time, classes with an Objective-C superclass other than `NSObject`).
- A non-mutating method of a large struct gets a pointer to the value in an argument register, not x20; it is not typed. Neither are other parameters.
- Ghidra's demangler types the first argument of a `_modify` accessor as the property's value; it is the caller's buffer. Not changed.
- Async methods and callee-allocated coroutines in method tables are followed through their function pointer records, but no fixture has them.

### Scripts and tests

- `ghidra_scripts/DumpSwiftSelf.java <output> [all|none|<addresses>]` lists the functions with `self` and writes the decompiled C of the chosen ones.
- `fixtures/Methods.swift` (`make -C fixtures methods`, arm64 and x86_64) and the hand-written `fixtures/expected-self.txt`; `devtools/headless-types.sh` writes the dump as `<name>-self.txt` (`DECOMPILE=all`), and `fixtures/check_self.py <dylib> fixtures/expected-self.txt <dump>` compares (`--types-only` for x86_64, whose C differs in variable names).

## Swift Error Register

### What it does

A throwing Swift function returns its error in x21 on arm64 and r12 on x86_64. The caller sets the register to 0 before the call and tests it after the call. Ghidra's Swift calling conventions list the register as unaffected by a call. The decompiler then takes the caller's 0 from before the call as the error, finds that the test always goes the same way, and removes the catch path (`WARNING: Removing unreachable block`). `do { return try mayThrow(x) } catch { return -1 }` decompiles to `return _mayThrow(param_1);`.

The analyzer adds a variant of each Swift calling convention of the program, in which a call changes the error register (`__swift_stdcall_throws` and `__swift_thiscall_throws`; and a second one for indirect calls, see below), and gives it to every function whose Swift symbol has a throwing function type. The callers then test the register after the call:

```c
_Var1 = _mayThrow(param_1);
if (extraout_x21 != 0) {
  _swift_errorRelease(extraout_x21);
  _Var1 = -1;
}
```

- Typed throws (`throws(E)`) get the same variant. There the callee sets the error register to 1 as a flag and returns the error in the result registers (x0 to x3, RAX, RDX, RCX, R8) if it consists of integers and pointers only and is small enough; otherwise it writes it to a buffer whose address the caller passes after the other arguments (Swift's `IRGenSIL.cpp`, `visitThrowInst`). So the variant also kills the result registers (x0 to x3 and d0 to d3; RAX, RDX, RCX, R8 and XMM0 to XMM3), which Ghidra's Swift conventions leave out of both lists (x86_64 kills RAX, RDX and XMM0): the decompiler then shows the error words that the return type does not cover (`extraout_x1`) instead of the caller's own values from before the call (`in_x1`), and the `Double` result of a closure called through an override as `extraout_d0`. After an untyped throw these registers are undefined, and the decompiler now shows that too. Ghidra's own AArch64 conventions kill x0, x1 and q0 as well.
- The symbol must name a function, an initializer or a static method, or the dispatch thunk, protocol witness thunk, merged copy or specialization of one. Optimized code calls the specialized copies (`…Tg5`, `…Tf4nd_n`), so these matter in binaries with local symbols. The throws marker `K` is found in the mangled name with a small tokenizer, not a full demangler. `devtools/check-throwing-symbols.sh` compares it with `swift-demangle`: on the 461,165 Swift symbols of the `.tbd` files of the macOS 27.0 SDK (Xcode 27.0) and the local symbols of the fixtures, there were no differences.
- External functions get the convention too; the stubs that call them are thunks and use it. Checked on a library that calls Foundation's `Data(contentsOf:)` and `JSONEncoder.encode(_:)`.
- Functions without a symbol are found from their callers. A call is a throwing call if the error register is 0 before it on every path and the first instruction after it that reads the register is a test (`cbz x21`, `cbnz x21`; `cmp x21, #0` or `test r12, r12` followed by a conditional jump or a conditional select such as `csel` or `cmovne`, which optimized callers of typed throws and `try?` use). The 0 is set by the caller (`mov x21, #0`, `xor r12d, r12d`), or it is the caller's own entry value, which the ABI makes 0 in a throwing function; also through a copy in another callee-saved register (`mov x19, x21` … `mov x21, x19`) or a stack slot (`stur x21, [x29, #-0x80]` … `ldur x21, [x29, #-0x80]`). Code built with `-Onone` copies the register before the test (`mov x8, x21; str x8, [sp, #0x18]; cbnz x21`); such a copy into another register is passed over. Outside this protocol x21 is an ordinary callee-saved register: a test of it after a call is common (after `swift_release`, for example), but then the register holds another value before the call. The test must compare the register with 0: on x86_64, where r12 is also an ordinary callee-saved register, a loop counter set to 0 before a call to a runtime function and compared with a bound after it (`xor r12d, r12d` … `cmp r12, rcx`, `cmp r12, 0x7fffffffffffffe9`) looked like a throwing call until this rule. A callee whose own Swift symbol says that it does not throw is not changed; the call is logged in a `SWIFTERR-CONTRADICTION` line. An external function without a Swift symbol (a C or Objective-C function such as `swift_beginAccess`) is not changed either (`SWIFTERR-NOT-SWIFT`).
- An indirect call with that pattern (a throwing closure, a method called through a table) gets a call-site override with a throwing variant (`SWIFTERR-CALL` line). The decompiler takes the prototype of an override as fixed and uses only the inputs it names, so the override names the registers that the caller sets up for the call. A forward data flow over the caller finds them: a register holds an argument if the caller wrote it, or it is one of the caller's own parameters, and no instruction read it since (a value computed and then used is a temporary; a save to the stack is no read; the register that holds the call's target is no argument). The parameters, in this order:
  - `result`, a pointer, if the caller sets the indirect result register (x8, RAX): the buffer for a result too large for the result registers. Ghidra's Swift conventions have this register only as a hidden return pointer, which the decompiler uses for a large return type; a closure's return type is not known. So the analyzer adds a second variant of each convention in which the register is an ordinary first parameter (`__swift_stdcall_indirect_throws`, `__swift_thiscall_indirect_throws`), and the return type is `void`.
  - `context`, the self register (x20, r13), always: Swift passes a closure's context or a witness method's `self` there on every call of a function value, also when the caller copies it before the call (`-Onone`). The variant is that of `__swift_thiscall`.
  - `arg0`, `arg1`, … in the integer argument registers, up to the last one that holds an argument (the ones before it too): a pointer if the value is an address in the caller's stack frame (`mov x0, sp`, `add x1, sp, #0x18`, `lea rdi, [rbp - 0x20]`), else an 8-byte `undefined`. If all of them hold arguments, the stack arguments follow as 8-byte `undefined`: the slots that the caller wrote from the stack pointer on (`stp x10, x11, [sp]`, `push`; also through a copy, `mov x10, sp; str x11, [x10]`), without a gap; a store of a callee-saved register's entry value is a save, not an argument (`push rbx` in the prologue). Then `farg0`, … as `double` in the floating-point argument registers.

  The return type is an 8-byte `undefined`, so that a result in x0 or RAX stays; a result in other registers shows as the value the call leaves there (`extraout_d0`, `extraout_x1` for the second word of a `String`), because the variant kills the result registers. An override with a throwing variant and another signature is replaced (earlier versions of the analyzer wrote one with varargs and no parameters, which lost arguments); a call with an override with another convention is not changed.
- Only the calling convention changes. The parameters stay, also `self` from [Swift Self Types](#swift-self-types). Functions with a user-defined signature are not changed, nor functions with a convention that is not Swift's (logged in a `SWIFTERR-CONVENTION` line).
- The variants are specification extensions of the program (Edit → Options → Specification Extensions). They are added when the first throwing function or call is found, so a program without throwing functions gets none. Adding them needs an exclusive checkout in a shared project; without one the analyzer logs `SWIFTERR-WARN no exclusive checkout` and changes nothing (Ghidra 12.2 adds its Swift conventions as specification extensions too, so those are missing as well). Headless analysis of a `ghidra://` URL always checks out exclusively; a project in the GUI checks out exclusively only when asked to. They stay when the program is saved and opened again. A program that has the variants from an earlier version of the analyzer keeps them: the analyzer does not replace a variant that is present (the variants of versions without typed throws did not kill the result registers; remove the extensions to get the new ones). The variants with an indirect result parameter are added to such a program.

Running it again changes nothing.

### Options

Analysis → Auto Analyze → LZ Swift Error Register. It is on by default for programs with Swift sections on arm64 and x86_64, runs after Swift Self Types and before Swift String Literals (the catch paths it brings back can hold strings), and can also run as Analysis → One Shot. It has no options. The summary is in the application log, in the lines that start with `LZ Swift Error Register`: one for the functions, and one for the calls that test the error register (to callees with a throwing symbol, to callees found from their callers, indirect: how many with a context and with an indirect result, and the overrides added, replaced and present). Each changed function has a `SWIFTERR` line, each added or replaced override a `SWIFTERR-CALL` line.

### Tests

The `Throws` fixture (arm64, x86_64, arm64e, arm64 `-Onone`) is checked function by function (`fixtures/check_throws.py`): the throwing convention on the 26 throwing functions, specializations, protocol witness thunks and merged copies (8 with typed throws) and on no other function, async functions included, and in the decompiled C of 25 callers the test of the error register and the catch result, with no `Removing unreachable block` warning. Nine call a closure or a protocol witness through a call-site override: `callClosure` (context and argument), `callInout` (the address of an `inout` struct on the stack; the struct is read after the call), `callBig` (the buffer of a 40-byte result in x8 or RAX, and the caller's own first parameter passed on), `callDoubleClosure` (a `Double` in and out), `callStringClosure` (a `String` result in two registers), `callManyArgs` (ten arguments, two or four on the stack), `Holder.callWith`, `callWitness` and `callExistential`. With the varargs override of an earlier version, `callInout` on arm64 computed its result from the struct as it was before the call. The stripped copies (`strip -x`: exported symbols only) are checked against the same expected file: there the internal throwing functions and the specializations have no symbol, and the analyzer finds 7 of them from their callers; 2 that only tail calls reach are not found (`fixtures/known-differences/`). The `-Onone` build has 13 known differences, none of them a lost catch path: the expected file is written for `-O`. A second run changes nothing. The fixtures were also run on Ghidra master of 2026-10-07 (12.3 DEV, conventions `__swift_stdcall` and `__swift_thiscall`): the same results, apart from three differences in the form of the `-Onone` C.

On a 9.8 MB arm64 slice of a closed-source Swift framework (full analysis, Ghidra 12.1.4, the analyzer off and then on): 31 calls test the error register, in 28 functions (9 to callees with a throwing symbol, 17 to 12 callees found from their callers, 5 indirect). In the decompiled C of these 28 functions the `Removing unreachable block` warnings went from 23 in 16 functions to none, and 22 calls to `swift_errorRelease` came back. 9 functions had kept the test but read the register's value from before the call (`unaff_x21`); 3 had lost the test without a warning, because the catch path merged into another branch. All 5 indirect calls pass the closure's context in x20, 2 an indirect result buffer in x8. With their overrides the C shows every argument that the decompiler finds without the analyzer, the context, and at one call a stack address in x0 that the decompiler did not find without an override; checked against the disassembly. A `bool` argument becomes a `ulong` (the parameter is 8 bytes). The analyzer took 5.4 s of 350 s of analysis. With the rules added later (copies of the register before the test, comparison with 0), the same slice has 54 calls that test the register, all `cbz`/`cbnz`, and the C of their 44 functions has no `Removing unreachable block`.

On three more binaries of the same application (full analysis, off and then on): a 0.4 MB arm64 framework, 48 calls, warnings 24 in 15 functions → 0; a 2.1 MB arm64 framework, 3 calls, 2 → 0; the 10.4 MB x86_64 slice of the first framework, 50 calls, 27 in 15 functions → 0, `swift_errorRelease` 0 → 19 (analysis 1,276 s, the analyzer 4.7 s). On x86_64 the first version of the finder took 3 calls as throwing where r12 was a loop counter or a flag; that led to the rule that the test compares with 0.

### What it misses

- A throwing call whose 0 in the error register comes from somewhere the analysis does not follow: a stack slot addressed through another register, or memory. The analysis follows at most 100,000 instructions per function and looks for the test in the 8 instructions after the call.
- A function found from its callers keeps the parameters Ghidra gave it; the analyzer does not read its symbol-less signature.
- Async functions: counted in the summary, not changed. They do not use the error register: an async callee passes its error to the caller's continuation in x20 (r13), and the continuation tests that entry value, which the decompiler keeps.
- The buffer of a typed error that is not returned in registers (seen for an error of five words and for one with a `Double` field): the signature does not have the pointer parameter for it, so the caller's catch path reads stack variables that seem uninitialized, and the callee writes through `in_x1`. Adding the parameter needs the error type's layout.
- A throwing function without a symbol that is reached only by tail calls (`b`, `jmp`; a merged copy, a specialization called from its protocol witness thunk): no caller tests the register after it. A tail call alone is no evidence, since a throwing function may also end with a tail call to a function that does not throw.
- Throwing property getters and subscripts: the mangled name of an accessor does not say that it throws. Closures (`…fU_`) are not read either.
- The arguments of an indirect call are a heuristic. Missed: floating-point arguments on the stack; stack arguments stored through a register other than a copy of the stack pointer; a register that the caller reads before the call and passes as well; the result of the previous call passed on in its result register (a call ends every argument but the self register). Extra: a temporary in an argument register that is not read again, and every register before the last argument. A missing argument hides its computation, which the decompiler may then remove, as the varargs override of earlier versions did; an extra one shows as an argument the closure does not use. A pointer type needs the stack address to come from the stack or frame pointer through copies and constant offsets; an address from a dynamic stack allocation (`sub x22, x9, x8` after `__chkstk_darwin`) is an 8-byte `undefined`.
- The throwing function itself does not show the error it sets: the register is not an output of the convention.
- Not tested: a shared project with Ghidra 12.2 (tested with the server and client of Ghidra master of 2026-10-07, non-exclusive and exclusive).

### Scripts and tests

- `ghidra_scripts/DumpSwiftThrows.java <output> [all|none]` lists the calling convention of each function with a Swift symbol or a throwing convention, and the call-site overrides, and with `all` writes their decompiled C.
- `fixtures/Throws.swift` (`make -C fixtures throws`, arm64 and x86_64, both also stripped, arm64e, arm64 `-Onone`) and the hand-written `fixtures/expected-throws.txt`; `devtools/headless-types.sh` writes the dump as `<name>-throws.txt` (`DECOMPILE_THROWS=all`), and `fixtures/check_throws.py <dylib> fixtures/expected-throws.txt <dump>` compares.
- `OUT=<dir> devtools/check-throwing-symbols.sh [<symbols.txt>]` compares the symbol classification with `swift-demangle --tree-only` (`devtools/throwing_oracle.py`); without an argument on the macOS SDK. About 10 seconds; needs `gradle compileJava` first.
- `devtools/ghidra_scripts/InstallThrowingConventions.java [dump]` adds the variants without the analyzer and prints, for each convention, whether a call kills or keeps the error register.

## Swift Runtime Prototypes

### What it does

Ghidra has no prototypes for the Swift runtime functions: a binary's imports show as `undefined _swift_allocObject(void)`, and their calls show no arguments, arguments the decompiler guessed, and flags as bare numbers. The analyzer gives each imported runtime function (`swift_retain`, `swift_allocObject`, `swift_beginAccess`, `swift_getGenericMetadata`, ...) its signature from the Swift source: parameter names and types, return type and calling convention. The stubs that call an import are thunks, so every call shows it:

```c
ValueBuffer VStack_38;
_swift_beginAccess(&self->interactor,&VStack_38,Tracking|Modify,(void *)0x0);
...
_swift_endAccess(&VStack_38);
```

where the call was `_swift_beginAccess(&self->interactor,auStack_38,0x21,0);` before.

- **The table.** `data/swift-runtime-functions.txt` is generated from a Swift checkout by `devtools/gen_runtime_functions.py` and part of the zip. It holds 355 functions and 7 flag enums. The functions and their register-level types come from the compiler's own list, `include/swift/Runtime/RuntimeFunctions.def`, expanded with `clang -E` (the file builds some entries by token pasting); the parameter names, the flag enums and the pointee of an untyped pointer come from the declarations in the runtime headers (`include/swift/Runtime/*.h`, `include/swift/ABI/*.h`), when a declaration has the .def's number of parameters. The header line names the Swift commit.
- **Which functions.** The entries of the .def's modules `Swift` and `_Concurrency` (322 of 355). The others (`malloc`, `objc_msgSend`, `_Block_copy`, ...) are left to Ghidra's own archives, whose prototypes are better than the compiler's register-level types. On the current table, 314 entries get a signature; the 8 others are in "What it misses".
- **Types**, in the category `/SwiftRuntime`. Pointers to runtime objects point to empty structures with the runtime's names, so the decompiler shows their role and they do not mix: `HeapObject *`, `Metadata *`, `WitnessTable *`, `OpaqueValue *`, `BridgeObject *`, `SwiftError *`, `TypeContextDescriptor *`, `AsyncTask *`, and others. Raw pointers, code and blocks are `void *`. `size_t`, `int32_t` and `int64_t` are typedefs in the category, so they do not collide with an archive's `size_t`.
- **Header pointees.** Where the .def has an untyped pointer and the header names its pointee, the parameter gets that type if it is one of the structures above or `ValueBuffer`. `ValueBuffer` is the runtime's 24-byte buffer (`void *privateData[3]`), so the buffer a caller passes to `swift_beginAccess` and `swift_endAccess` becomes a variable of that type. `ClassMetadata`, `EnumMetadata`, `StructMetadata` and `HeapMetadata` become `Metadata`, so the decompiler adds no casts between metadata kinds. 22 other pointee names (`TypeLayout`, `TaskGroup`, `ProtocolRequirement`, `uint32_t`, ...) stay `void *`.
- **Flag enums.** A parameter that the header declares with a simple `enum class` gets that enum, and the decompiler prints its constants by name, or a value without a name as an OR of names: `Tracking|Modify` for `swift_beginAccess`'s 0x21, `DestroyOnFailure|TakeOnSuccess` for `swift_dynamicCast`'s 6. The enums: `ExclusivityFlags`, `DynamicCastFlags`, `StructLayoutFlags`, `ClassLayoutFlags`, `EnumLayoutFlags`, `RawLayoutFlags`, `ProtocolClassConstraint`. A value that repeats an earlier one is left out (`ExclusivityFlags.ActionMask`, equal to `Modify`), since the decompiler otherwise prints the later name and warns about the enum in every function.
- **Two-register returns** become structures, and the decompiler shows both values: `MetadataResponse { Metadata *value; size_t state; }` (`swift_getGenericMetadata`, `swift_checkMetadataState` and the other functions that return a metadata response), `BoxPair { HeapObject *object; OpaqueValue *buffer; }` (`swift_allocBox`, `swift_makeBoxUnique`), `ErrorBoxPair` (`swift_allocError`), `MetadataDependency`, `OffsetPair`, `SerialExecutorRef`, `AsyncTaskAndContext`. For example `BVar2 = _swift_allocBox(*(Metadata **)(param_1 + 0x18)); pOVar1 = BVar2.buffer; *(HeapObject **)param_1 = BVar2.object;`, where the decompiler had lost the box before.
- **Calling conventions.** The .def's `C_CC` becomes `default`, the program's C convention: `__cdecl` on AArch64, and on x86_64 the System V convention that `x86-64-gcc.cspec` names `__stdcall`. `SwiftCC` becomes the program's Swift convention, `__swift_stdcall`, or `default` on a program without one (counted as "swiftcc as default"); none of these functions uses the self, error or async register, and every return fits two registers.
- Also functions in memory with a runtime function's name, as in images of the dyld shared cache (`libswiftCore`); thunks are skipped. A signature that the user, an archive or the importer set is kept, and so is a function that [Swift Error Register](#swift-error-register) gave a throwing convention (runtime functions have no Swift symbol, so this is not expected).
- **One rule not from the sources.** The .def gives `swift_once` a third parameter, a context. Global variable accessors use `Builtin.once`, for which the compiler passes an undefined value (`lib/IRGen/GenBuiltin.cpp`), so x2 is whatever the caller left there. With the third parameter the decompiler took it as an input of every caller and added up to three parameters to most global accessors. The generator's `UNDEFINED_ARGS` drops it: `void _swift_once(void * predicate, void * fn)`.

- **Stack probe calls** (arm64). A function that reserves a stack buffer of a size known only at run time (a generic value) first calls `___chkstk_darwin`. The call loads the import from `__got` and branches to it (`blr x16`), so it takes the program's default convention, which kills x0, x1 and x8 to x18. The function keeps them: libsystem_pthread's (macOS 27.0.1) reads the size in x9 and writes only x9 and the flags. The analyzer installs a convention `__chkstk_darwin` (size in x9; x9, x16 and x17 killed; every other integer register, sp and q0 to q31 kept) as a specification extension, and gives each call the override `void (ulong size)` with it. The size then shows as the call's argument, the buffer is `auStack_170 + -(size + 0xf & 0xfffffffffffffff0)` instead of `auStack_170 + -(extraout_x8 + 0xfU & 0xfffffffffffffff0)`, and a value that lives in another register across the call stays: in the fixture's `makeAccumulator` closure, the box in x1 is the parameter `HeapObject *param_3` again instead of an unassigned local. An override with another convention is kept. Installing the convention needs exclusive access to the program.

Running it again changes nothing.

### Options

Analysis → Auto Analyze → LZ Swift Runtime Prototypes. It is on by default for programs with Swift sections on arm64 and x86_64, runs before Swift Data Types, Swift Self Types and Swift Error Register (so that their decompiler runs see the typed calls), and can also run as Analysis → One Shot.

| Option | Default | Effect |
| --- | --- | --- |
| Apply to defined functions | on | Also give the signatures to functions in the program with a runtime function's name (images of the dyld shared cache); imported functions get them either way |
| Override stack probe calls | on | On arm64, give each call to `___chkstk_darwin` the call-site override described above |

The summary is in the application log, in two lines, and a third on arm64 programs that call `___chkstk_darwin`:

- `LZ Swift Runtime Prototypes: N applied, N already set, N user signatures kept, N not in table, N async skipped, N swiftcc as default`
- `LZ Swift Runtime Prototypes: left unchanged: N imported signatures, N other modules, N PreserveMost, N Swift register parameters, N throwing variants, N failures; T s`
- `LZ Swift Runtime Prototypes: stack probes: N calls to ___chkstk_darwin, N overrides added, N replaced, N present, N other overrides kept, N failed; convention installed|present`

Each signature set has a `SWIFTRT-SET` line (address, name, convention). The runtime names not in the table are in a `SWIFTRT-MISSING` line at debug level. `SWIFTRT-WARN` reports a missing or broken table, a signature or override that Ghidra rejected, a convention that could not be installed, and a program without exclusive access.

### Tests

The `Runtime` fixture (arm64 `-O` and `-Onone`, x86_64, arm64e) uses each case: property reads and writes of a class (`swift_beginAccess` with `Read`, `Modify` and `Tracking|Modify`), a closure that captures a generic `var` (`swift_allocBox`), a generic class (`swift_getGenericMetadata`, `swift_checkMetadataState`), `as?` to a protocol (`swift_dynamicCast`), an `async` function (`swift_task_switch`, skipped), and an actor (`swift_defaultActor_initialize`) and a global (`swift_once`). `fixtures/check_runtime.py` checks the signature of each external (22 set on each build; `swift_task_switch`, `malloc` and `objc_opt_self` unchanged) and lines of the decompiled C of 16 functions. The `-Onone` build tracks every access (6 known differences). On the other fixtures the results of the other analyzers do not change; their decompiled C changes only in lines that call a runtime function or declare its buffer, and in callers that test the error register after a call (see below).

On two arm64 frameworks of a closed-source application (Ghidra 12.1.4, full analysis with and without the analyzer): 86 and 44 functions set, with 59,017 and 1,228 call sites; the analyzer took 0.27 s and 0.016 s, less than the run-to-run variation of the whole analysis (336 to 342 s, 36 s). Most called: `swift_release` (14,881 calls), `swift_retain`, `swift_bridgeObjectRelease`, `swift_getWitnessTable`.

### What it misses

- Async functions (`SwiftAsyncCC`: `swift_task_switch`, `swift_continuation_await`, `swift_asyncLet_finish`, `swift_deletedAsyncMethodError`): counted, not changed. They take the async context in x22, which no Ghidra convention has as a parameter.
- The `PreserveMost` retains and releases (`swift_retainDirect`, `swift_releaseDirect` and their bridge object forms): LLVM's `PreserveMost` keeps more registers than any Ghidra convention. Counted, not changed; the binaries tested import none.
- `swift_willThrow`: its arguments are in x20 and x21 (`SWIFT_CONTEXT`, `SWIFT_ERROR_RESULT`), which its convention would put in x0 and x1, so the calls would show wrong arguments. It gets `void swift_willThrow(void)` with the program's C convention (`default`), which kills x0 as the Swift function does: the C is `_swift_willThrow(); return extraout_x0;`. Ghidra 12.2's AArch64 `__swift_stdcall` keeps x0 across the call, so the thrower would seem to return the error object. Without a signature, the call showed an argument in x0 and returned a value. The arguments are not shown. `swift_willThrowTypedImpl` is not in the .def and keeps Ghidra's default signature.
- Imports that are not in the .def: the key path functions (`swift_getAtKeyPath`, `swift_readAtKeyPath`, `swift_modifyAtWritableKeyPath`, `swift_setAtWritableKeyPath`, implemented in Swift in the standard library), `swift_stdlib_isStackAllocationSafe`, `swift_stdlib_random`. Counted as "not in table". (Two more imports, `swift_runtimeSupportsNoncopyableTypes` and the data symbol `swift_isaMask`, are not functions in Ghidra.)
- `NoReturn` (`swift_unexpectedError`, `swift_onceClosureDestroyedError`) is not applied.
- The runtime types are opaque: `Metadata`, `HeapObject` and the others have no fields, and are not linked to the types of [Swift Data Types](#swift-data-types). The empty structures are 1 byte long, so a caller's buffer that reaches an `OpaqueValue *` or `HeapObject *` parameter becomes an array (`OpaqueValue aOStack_78 [32]`, `HeapObject aHStack_148 [232]`), and a dynamic stack buffer that reaches a `BridgeObject *` parameter shows pointer arithmetic on that type. `typedef void` instead of the empty structures removes the arrays, but the decompiler then casts to `long` for each offset from such a pointer (`*(undefined8 *)((long)object + 0x20)`): 927 lines on one arm64 framework of a closed-source application, against 13 arrays. So the structures stay.
- Header pointees other than the structures above stay `void *` (see "Header pointees"); so do integer pointers. `MetadataRequest` arguments (a bit field: state and a non-blocking flag) are plain `size_t`. Functions with no header declaration (75, such as the `*Typed` variants and `swift_getTypeByMangledNameInContext2`) have `param_N` names.
- Calls now show casts where a caller's variable has another type: `(Metadata *)this`, `(HeapObject *)self`, `(void *)0x0` for a `pc` of 0. A `bool` result is read through `CONCAT71` where the caller tests the 32-bit register.
- In callers that test the error register after a call, the decompiler names the register after `swift_errorRelease`'s parameter, `object`, instead of `extraout_x21`.
- Parameters that callers leave undefined, other than `swift_once`'s context, were not checked; on one framework 8 of 600 global accessors still gained a `code *` parameter, for a reason not found.
- Stack probe calls on x86_64: they call a stub, with the size in RAX; the program's convention there was not checked, and the analyzer leaves them alone. On arm64, a call through a `__stubs` thunk would get the override too, but none was seen.
- Not tested: a missing table, the GUI.

### Regenerating the table

After a Swift release, with a checkout of [swiftlang/swift](https://github.com/swiftlang/swift) and `clang`:

```sh
python3 devtools/gen_runtime_functions.py <swift checkout>
```

It prints its reports to standard error: parameter count mismatches between the .def and a header (the .def is used), entries without a declaration, enum values left out, and the `UNDEFINED_ARGS` rule. Then update the counts in `RuntimeTableTest` and `RuntimePrototypesTest`, and check `RuntimeTypesTest`: a new IRGen type name fails `everyNameMaps`, and a new header pointee fails `pointeesThatStayVoid` until it is listed as used or as `void *`.

### Scripts and tests

- `ghidra_scripts/DumpSwiftRuntime.java <output> [all|none]` lists each external function with its signature source, convention and prototype, and with `all` writes the decompiled C of every function in memory.
- `fixtures/Runtime.swift` (`make -C fixtures runtime`) and the hand-written `fixtures/expected-runtime.txt`; `devtools/headless-types.sh` writes the dump as `<name>-runtime.txt` (`DECOMPILE_RUNTIME=all`), and `fixtures/check_runtime.py <dylib> fixtures/expected-runtime.txt <dump>` compares.

## Swift String Literals

### What it finds

Swift passes and stores a `String` as two 64-bit words. For a literal, the compiler builds both words from immediates, so the text never appears as a string in the binary:

- **Small strings** (up to 15 UTF-8 bytes): the bytes are the words themselves. `"chord_change"` is `0x68635f64726f6863`, `0xec00000065676e61`; the top byte `0xEC` of word 1 is the tag (ASCII, small) and the count (12). Ghidra's string search does not find these, and the decompiler shows two hex constants.
- **Large strings** (16 bytes or more): the bytes are in `__cstring`, but word 1 is the address of the bytes minus 32, with bit 63 set, and word 0 is the count with flags (`0xD000…` | count for ASCII). Ghidra adds no reference from the code to the bytes.

The analyzer runs a value-set data flow over the p-code of each function that has a candidate constant (a tag-like value or bit 63 moved or ORed into a register). It pairs word 0 and word 1 where the string is used:

1. at a call or a tail branch, in two adjacent argument registers, or in the last argument register and the first stack slot, or in two stack slots (x0–x7 then `[sp]`; rdi, rsi, rdx, rcx, r8, r9 then `[rsp+8]`);
2. at a return, in two adjacent result registers;
3. at two stores, word 1 eight bytes after word 0 at the same base (dictionary literals, struct fields);
4. at a comparison with a literal, which the compiler inlines as a comparison of both words (`cmp`/`ccmp` on arm64; `xor`, `xor`, `or` on x86_64).

A tag word that pairs nowhere is paired by guess if exactly one other constant in its basic block decodes with it ("probable", count 1–8 only), or stands alone for the empty string (count 0).

A small string is accepted only if the count is at most 15, all bytes after the count are zero, the bytes are valid UTF-8, and the ASCII flag matches the bytes. A large string is accepted only if the address is in `__cstring` and holds a C string of exactly that count.

### What it creates

At the instruction that completes each string (the later of the two words):

| Markup | Example | Option |
| --- | --- | --- |
| EOL comment line (or PRE) | `Swift "chord_change"`; `Swift "C"?` (probable); `Swift "md5_ovs_blocklist" (large)` | Comment style |
| Bookmark, type Analysis, category `Swift string (small)` or `Swift string (large)` | text `"chord_change"` | Bookmarks |
| Equates on instruction operands that hold a whole word | `S"Flat"`, `S"Flat".hi` | always (certain small strings) |
| Equates on the decompiler's constants, by dynamic hash | `*(undefined8 *)(puVar1 + 0x20) = S"chord_change";` | Decompiler equates |
| PRE comment line at the use, for strings no equate shows | `/* Swift "json" */` above `String::_bridgeToObjectiveC()` | Decompiler equates |
| Data reference from the `orr` to the bytes of a large string | | Large strings |
| A UTF-8 string in the block `swift_strings`, defined as data, with a data reference from the completing instruction (small strings only) | `s_chord_change_swift_strings__00000006` | String block (off by default, a workaround) |

Search → Program Text (comments) finds a string, and the Bookmarks window, filtered on category `Swift string (small)` or `Swift string (large)`, lists them by kind.

The analyzer only replaces its own comment lines (those that start with `Swift "`), bookmarks and equates (names that start with `S"`), and keeps user text in the same comments. Running it again gives the same markup. Large-string references are not removed on a re-run, because they cannot be told apart from other references.

Equate names are `S` plus the string in double quotes, with C escapes. The `S` is needed: Ghidra reads an equate name that starts with a quote as a character format. Word 1 gets the suffix `.hi`, because an equate name has one value.

### Options

Analysis → Auto Analyze → LZ Swift String Literals. It is on by default for programs with `__swift5_*` sections and can also run as Analysis → One Shot. On a small framework One Shot takes a second or two; Ghidra only reports that the analysis is scheduled, and it is done before a progress bar shows. The summary is in the application log (`~/Library/ghidra/ghidra_<version>_PUBLIC/application.log` on macOS), in the lines that start with `LZ Swift String Literals`.

| Option | Default | Effect |
| --- | --- | --- |
| Comment style | EOL | EOL or PRE comment at the completing instruction. The decompiler shows PRE comments by default, EOL comments not |
| Bookmarks | on | One bookmark per completing instruction |
| Probable strings | on | Also mark strings paired by guess, with `?` |
| Large strings | on | Also mark large literals and add the reference to their bytes |
| Decompiler equates | on | Decompile each function with strings once, name the constants there, and add PRE comments for strings the decompiler does not show. This is the slow part (see Cost below) |
| String block | off | Workaround with side effects: write the small strings into an artificial memory block, so that the Defined Strings window lists them. See [String block](#string-block-workaround) |
| Decompiler threads | 0 | Functions decompiled at the same time for the decompiler equates, each in its own decompiler process. 0: automatic (see Cost below). 1: one at a time |
| Decompiler timeout (sec) | 60 | Seconds the decompiler may take for one function; a function that takes longer gets no decompiler equates (see Cost below) |

The decompiler equates depend on the callee's signature: a constant's hash changes when a callee's parameters change. After you change function signatures, run the analyzer again (One Shot).

The analyzer logs a summary line per run, and one line per string (`SWIFTSTR`), per unpaired tag word (`SWIFTSTR-UNPAIRED`), per decompiler failure (`SWIFTSTR-DECOMP-FAILED`) and per function whose data flow stopped at the work limit of 300,000 instructions (`SWIFTSTR-NOT-CONVERGED`; its strings then come from the states reached so far), in the application log. With String block on, the markup summary line ends with the number of block strings added and block references, and a block that cannot be written logs `SWIFTSTR-BLOCK` or `SWIFTSTR-BLOCK-LOCKED`.

### String block (workaround)

Small strings have no bytes in the binary, so Ghidra's Defined Strings window and Search → For Strings never list them. With the option **String block** on, the analyzer writes each distinct small string once, as UTF-8 bytes and a NUL, into a memory block of its own and defines it as `string-utf8` data. Each instruction that completes the string gets a data reference to it. The window then lists the strings, and a double-click shows the string in the Listing with its XREFs to the code.

This is a workaround with side effects, which is why it is off by default:

- The block holds bytes that are not in the binary. It is named `swift_strings`, an overlay on the OTHER space (addresses read `swift_strings::00000000`), read-only and marked Artificial in the Memory Map. It is initialized but not loaded.
- Search → Memory does not search it with its default region (Loaded Blocks), but does with "All Other Blocks".
- Search → For Strings lists the block's strings only with "All Blocks" and a minimum length low enough (the dialog's defaults, Loaded Blocks and 5, hide them).
- The Binary exporter writes it, because it writes every initialized block. The Original File exporter does not.
- A text that is also a defined string elsewhere in the program (a Swift field name in `__swift5_reflstr`, a C string in `__cstring`) shows twice in the window. Only the block's copy has the references to the code that builds the string.
- If the Defined Strings window was open during the analysis, it may not show the new strings until you press its Refresh button (highlighted when its list may be stale). Ghidra stops updating the window row by row when data types change, which they do throughout auto-analysis.
- Creating the block needs exclusive access: in a shared project, check the program out exclusively. Without it the analyzer logs `SWIFTSTR-BLOCK-LOCKED` and does the rest of its markup without the block.

The block only grows. A later run (more functions, One Shot on a selection) appends the new texts and joins them to the block, so the strings already there keep their addresses and references. A string whose last reference disappears stays in the block. Empty strings and strings with a NUL inside are left out.

Turning the option off does not remove the block. To remove it, delete the `swift_strings` block in Window → Memory Map; its data and the references to it go with it. Clear the Memory Map's filter first: in Ghidra 12.1.4 (not checked on 12.2), Delete Block on a filtered table deletes the block at the same row of the unfiltered table, not the selected one. The option is also the sixth argument of `SwiftStringLiteralsAnalyzer.setMarkupOptions` for scripts.

### Cost

Decompiler equates are the slow part: the analyzer decompiles every function that has a string, once. On a large SwiftUI binary this can be a noticeable share of the analysis time. Turn off **Decompiler equates** in the analysis options to save it; the comments and bookmarks stay.

The analyzer works in two passes. The first finds the strings of every function and marks them in the listing. The second decompiles the functions on several threads, each with its own decompiler process, and only reads the program; when all are decompiled, the analyzer adds the equates and PRE comments, in address order. So the result does not depend on the number of threads. With **Decompiler threads** at 0, the number is one per processor but one (for Ghidra's own thread), and no more than the memory outside the Java heap holds at 2 GB each. One decompiler process used up to 1.3 GB on a function that ran into the timeout; with 9 threads all of them together used up to 3.4 GB (a 5 MB app binary, 712 functions decompiled, M-series Mac with 10 cores and 24 GB). On that binary the decompiler pass took 107 s with 1 thread, 60 s with 2, 49 s with 4 and 41 s with 9. It cannot get shorter than its slowest function: one function there runs into the timeout (these figures with a 30 s timeout).

Each function may take **Decompiler timeout (sec)**, default 60 s, the same default as the option "Analysis Decompiler Timeout (sec)" of Ghidra's own decompiling analyzers (Decompiler Switch Analysis, Decompiler Parameter ID). It is a setting of this analyzer: the Decompiler window's timeout (Edit → Tool Options → Decompiler, 30 s) is a tool option, which analyzers do not get. A function that takes longer loses its decompiler equates; the `SWIFTSTR-DECOMP-FAILED` line names it. More threads put more load on the machine, so a function near the limit may time out with more threads, or on a slower or busier machine. On the binary above, the slowest function took 32 s alone and about 50 s with 9 threads: it timed out at 30 s and at 40 s; with a 300 s timeout it finished, and the pass took 57 s instead of 43 s (30 s) or 52 s (40 s). 60 s was not measured. Raise the timeout or lower **Decompiler threads** if such a function matters.

A function's decompiled code can run into the body of another function (the decompiler follows the flow where no function start stops it). Its equates on that code are kept. Up to the version that added the threads, the analyzer removed them again when it cleared the other function's old markup, if that function came later in the address order.

### Tests

The analyzer is checked against a fixture with known answers (`fixtures/Strings.swift`, `expected-strings.txt`), built for arm64 (`-O` and `-Onone`), arm64e and x86_64, and for idempotency: a second run changes nothing.


### What it misses

- Strings that are not built in code: array and dictionary literals in `__DATA_CONST,__const`, and word 0 loaded from such a table (`ldr x0, [x9, x8, lsl #3]` in an enum's `rawValue`).
- Tag words computed at run time, such as `(b & 1 | -0x1c) << 56` for `b ? "Sharp" : "Flat"` on x86_64 (arm64 uses `csel` between two constants, which the analyzer handles). Seen only in the test fixture.
- Words that reach their use through memory the data flow does not track: a heap object passed to another function before the store, and code reached only through a jump table (Ghidra's block model gives those blocks no predecessor).
- Switches over an enum without payloads that `-O` compiles to a table of byte offsets (`and x8, x0, #0xff; ldrb; add lsl 2; br`, arm64): Ghidra 12.2 does not recover the table (12.1.4 did, but read all 256 entries the mask allows, which gave false strings), so the cases after the branch are not in the function. In the fixture 29 of 30 literals are missed; on one arm64 app, 54 strings in 4 functions.
- More than 16 values meeting at one point (`ValueFlow.MAX_VALUES`): the merge keeps none of them, so a switch whose cases jump to one shared tail loses all its strings. Not seen; on one arm64 app limits 32 and 64 found no string that 16 missed.
- Code built with `-Onone`: every literal goes through `String(_builtinStringLiteral:utf8CodeUnitCount:isASCII:)` with the `__cstring` address, which Ghidra already shows as a reference.

Known display limits:

- The Swift demangler types word 0 of a `String` argument as `char *`, so the decompiler prints a short string's word 0 as the bytes at that address (`"\x19"` for `"-"` = 0x2d). The `.hi` equate on the same string still shows.
- Word 1 of a string of 8 bytes or fewer holds only the tag and the count, so all strings of the same length share it (`0xE100…` for every one-byte string). Where two such strings meet in one function, the `.hi` name can name the other one (`S" ".hi` for `"-"`). The comment lines and bookmarks are not affected.
- Code that the decompiler removes as unreachable shows neither equates nor comments.
- Probable and large strings, and strings passed to methods whose demangled signature has no parameters (`_bridgeToObjectiveC(void)`), show as PRE comments, not equates.

### Scripts and tests

`ghidra_scripts/` (add the directory in the Script Manager, or `-scriptPath` headless):

- `DumpSwiftStrings.java <output> [<C directory>]` writes the markup (bookmarks, comments, equates) and, per string, whether the decompiled C shows it, to a text file. With a `swift_strings` block it also writes the block's strings and their references (`BLOCK` lines) and the small strings whose reference is missing or extra (`BLOCKREF-MISSING`, `BLOCKREF-EXTRA`).
- `RerunSwiftStrings.java [EOL|PRE]` adds user lines to two comments and runs the analyzer again with the program's analysis options, for the idempotency test.

`fixtures/` has the test program `Strings.swift`, its expected literals (`expected-strings.txt`) and `check_report.py`. `make -C fixtures` builds it for arm64 (`-O` and `-Onone`) and x86_64 (`-O`) with `swiftc`. The x86_64 build needs no Rosetta: Ghidra only reads it. `devtools/headless.sh` and `devtools/run-fixtures.sh` run it headless.
