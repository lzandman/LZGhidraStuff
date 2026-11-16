# CLAUDE.md

Guidance for Claude Code in this repository: Ghidra extensions, analyzers, scripts and other reverse-engineering tools.

## Layout

| Path | What |
| --- | --- |
| `LZGhidraSwift/` | Extension: analyzers for Swift binaries. Own [CLAUDE.md](LZGhidraSwift/CLAUDE.md) |
| `LZGhidraGeneric/` | Extension: analyzers not tied to one language or platform. Own [CLAUDE.md](LZGhidraGeneric/CLAUDE.md) |
| `scripts/` | Stand-alone Ghidra scripts, see [scripts/README.md](scripts/README.md) |
| `buildconfig/` | Check configuration shared by the extensions (`quality.gradle`, PMD, Checkstyle, Ghidra's formatter profile) |
| `devtools/` | Development tools shared by the extensions, not in any zip, see below |
| `check.sh` | Every light check, see Commands |

`devtools/`:

- `memguard.py <GiB> -- <command>`: kills the command when its process tree's resident memory exceeds the limit; prints the peak. The devtools scripts take the limit from `MEMGUARD_GIB` (default 12).
- `deadline.py <seconds> -- <command>`: kills the command's whole process tree at the deadline (exit status 124).
- `java-home.sh`: sourced by the scripts that run Gradle, `analyzeHeadless` or `java`; sets `JAVA_HOME` to Homebrew's JDK for the Ghidra's `application.java.min` when it is unset.
- `ghidra_scripts/` (category `LZGhidraStuff`), language-neutral:
  - `ImportDyldImage.java <cache file> <install name> <program name> [<loader option> <value>]...` imports one image of a dyld shared cache in a headless run without `-import`.
  - `ProgramInfo.java` prints the program's path, MD5, instruction and function counts and Swift blocks.
  - `PrintPcode.java <address>...` prints the p-code of the instructions at the addresses.

Swift-specific development scripts are in `LZGhidraSwift/devtools/`.

Each extension is its own Gradle project (no multi-project build, no Gradle wrapper). It applies `../buildconfig/quality.gradle`.

## Hard rules

- **Never commit third-party binaries, dumps, Ghidra projects or extracted metadata.** Tests use fixtures compiled from Swift sources in this repository; only the sources and hand-written expected results are committed.
- **Headless analysis runs under memguard.** The Java heap cap (`GHIDRA_HEADLESS_MAXMEM`; 4G is enough for the fixtures) does not cover the decompiler processes, which run outside the JVM, so a large binary can take more memory than the machine has. The devtools scripts run each job through `devtools/memguard.py`; set `MEMGUARD_GIB` below the machine's free memory (default 12). Run your own headless commands the same way: `python3 devtools/memguard.py <GiB> -- <command>`.
- **CI stays on `gradle/actions/setup-gradle@v5`.** Do not upgrade it to v6 or later, also not when a tool or a deprecation warning suggests it: v6 brings closed-source caching under Gradle's Terms of Use. Ask the maintainer first; the reasons are in the comment in `.github/workflows/build.yaml`. `.github/dependabot.yaml` ignores its major updates; keep that rule.
- **Only the public Ghidra API** (`Program`, `Memory`, `Listing`, `DataTypeManager`, `AbstractAnalyzer`, ...). Ghidra's internal classes move between releases.

## Environment

- Ghidra 12.2 as a release install (not a source checkout). 12.2 is the only supported version. **Every Gradle command needs `GHIDRA_INSTALL_DIR`**, its directory, from the environment or from `~/.gradle/gradle.properties`. CI downloads the release zip.
- Java 25. A bare `gradle` or `analyzeHeadless` call needs `JAVA_HOME` set to it: with Java 21, javac reports every Ghidra class as "cannot find symbol"; on any version other than 25 the PMD tasks stop with a message. The scripts source `devtools/java-home.sh`, which sets `JAVA_HOME` from the Ghidra's `application.java.min` when it is unset.
- Gradle 9.1 or later (Ghidra 12.2 needs it; CI uses 9.8.1, the maintainer 9.9.1). `swiftc` from Xcode for the fixtures. ruff. `shellcheck` is optional.
- Default paths in the scripts are Homebrew's on macOS: Ghidra at `/opt/homebrew/opt/ghidra/libexec`, Java at `/opt/homebrew/opt/openjdk@<version>`; Ghidra's user settings and extensions at `~/Library/ghidra/ghidra_12.2_PUBLIC/`. `GHIDRA_INSTALL_DIR` and `JAVA_HOME` override them.
- Useful to read: the source of Ghidra and of the Swift compiler and runtime (`github.com/swiftlang/swift`).

## Commands

```sh
./check.sh                       # all light checks, stops at the first failure
cd LZGhidraSwift && gradle lint test buildExtension
gradle spotlessApply             # format the Java files you touch (in the extension's directory)
ruff check --fix <files> && ruff format <files>    # Python files you touch, and only those
```

The fixture runs and headless checks are in each extension's CLAUDE.md.

## Writing

Documents and comments use plain, precise English: short sentences, concrete figures (with units and the machine or binary they were measured on), no marketing tone. Record findings as facts with their evidence, and say what was not tested.
