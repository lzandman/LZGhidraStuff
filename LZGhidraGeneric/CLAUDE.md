# CLAUDE.md

Rules and commands for LZGhidraGeneric only. The repository rules (third-party binaries, memguard for headless analysis, public Ghidra API only) are in [../CLAUDE.md](../CLAUDE.md). The README describes the analyzer.

## Code design

- **Analyzers are language-neutral.** Anything specific to one language or platform belongs in its own extension (Swift: LZGhidraSwift). Do not make this extension depend on another one.
- **The extensions do not share code.** `AnalysisLog` is a copy of the one in LZGhidraSwift (a package-private record, 20 lines); only its Javadoc differs, which describes this extension's log line. If a third copy is needed, think again about a shared library.
- **`added()` only coordinates**, as in LZGhidraSwift. Put logic that needs no `Program` in classes a unit test can run.
- **Analyzers do not use each other.** `AnalyzerDependencyTest` checks this.

## Commands

From `LZGhidraGeneric/`:

```sh
gradle lint test buildExtension    # dist/ghidra_<version>_PUBLIC_<date>_LZGhidraGeneric.zip
gradle spotlessApply               # format the Java files you touch
devtools/install.sh                # build and install; quit the Ghidra GUI first
OUT=<scratch dir> devtools/check-function-starts.sh <dyld shared cache file> <install name>
```

The headless check is the test of the analyzer. It runs through `devtools/memguard.py`. On macOS the dyld shared cache is at `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e`. Never commit the project or logs it writes.
