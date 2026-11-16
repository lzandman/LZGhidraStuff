# LZGhidraGeneric

A Ghidra extension with analyzers that are not tied to one language or platform.

| Analyzer | What it does | State |
| --- | --- | --- |
| [Mach-O Function Starts (Extracted DYLD)](#mach-o-function-starts-extracted-dyld) | Creates functions from `LC_FUNCTION_STARTS` in an image extracted from the dyld shared cache | done |

In Analysis → Auto Analyze the analyzer carries the prefix `LZ` (`LZ Mach-O Function Starts (Extracted DYLD)`), so that it sorts with the other LZ analyzers; its log lines start with the same name.

Tested with Ghidra 12.2 (Homebrew, macOS on Apple silicon). Other versions are not tested. The zip only installs without a warning into the Ghidra version it was built against; for another version, build it with `GHIDRA_INSTALL_DIR` set to that Ghidra.

## Build and install

Ready-made zips are on the Releases page; see [Install a release](../README.md#install-a-release). To build it yourself:

You need Java 25, Gradle 9.1 or newer, and a Ghidra installation.

```sh
cd LZGhidraGeneric
export GHIDRA_INSTALL_DIR=/opt/homebrew/opt/ghidra/libexec
export JAVA_HOME=/opt/homebrew/opt/openjdk@25
gradle buildExtension    # dist/ghidra_12.2_PUBLIC_<date>_LZGhidraGeneric.zip
gradle test              # the dependency test (no analyzer uses another)
gradle lint              # javac -Xlint, Error Prone, Spotless, PMD, Checkstyle; fails on any finding
gradle spotlessApply     # formats the Java sources with Ghidra's Eclipse profile
```

Install the zip in Ghidra with File → Install Extensions → +, then restart Ghidra. With the Ghidra GUI closed, `devtools/install.sh` builds and installs it into the user's extensions. The checks are configured in `../buildconfig/`.

## Mach-O Function Starts (Extracted DYLD)

Ghidra's "Mach-O Function Starts" analyzer creates functions at the addresses in a Mach-O's `LC_FUNCTION_STARTS`. It accepts only the formats "Mac OS X Mach-O" and the whole DYLD cache. An image extracted from the dyld shared cache (File System Browser, loader "Extracted DYLD Component") has its own `LC_FUNCTION_STARTS`, but the analyzer does not run on it (`MachoFunctionStartsAnalyzer.canAnalyze`, the same in Ghidra 12.1.3 to 12.2). Code that is reached only through a `swift_once`, a jump table or a tail branch, and has no symbol, then stays outside functions.

The bug was reported upstream with a fix in [PR #10137](https://github.com/NationalSecurityAgency/ghidra/pull/10137). Ghidra fixed it differently on master, for 12.3, in commit [`ede86a4a9f`](https://github.com/NationalSecurityAgency/ghidra/commit/ede86a4a9f): an extracted image now gets the format "Mac OS X Mach-O", so Ghidra's analyzer runs on it. This was not tested on a master build.

This analyzer runs Ghidra's on such a program, at the same priority and with its default options. It is on by default and does nothing on other formats, or once Ghidra's analyzer accepts the format itself. It logs one line, `LZ Mach-O Function Starts (Extracted DYLD): <n> functions added (<before> -> <after>)`. It has no options.

[LZGhidraSwift](../LZGhidraSwift/README.md) relies on it for dyld images: the Swift analyzers see only code inside functions.

## Tests

`gradle test` runs `AnalyzerDependencyTest` (the architecture rule: no class uses another analyzer). The analyzer itself needs a Ghidra `Program`, so it is checked headless instead:

```sh
OUT=<scratch dir> devtools/check-function-starts.sh <dyld shared cache file> <install name of an image>
```

The script imports the image, analyses it twice without saving, with and without the analyzer, and prints both function counts. The first must be higher. It needs a macOS dyld shared cache, the installed extension and about 6 GB of heap for the import.
