# LZGhidraStuff

[![Release](https://img.shields.io/github/v/release/lzandman/LZGhidraStuff)](../../releases/latest)

A repo where I keep my Ghidra extensions, analyzers, scripts and other reverse-engineering tools.

| Part | What |
| --- | --- |
| [LZGhidraSwift](LZGhidraSwift/README.md) | Analyzers for Swift binaries: string literals, data types with field offsets, `self` types of methods, the error register of throwing calls, and the signatures of the Swift runtime functions |
| [LZGhidraGeneric](LZGhidraGeneric/README.md) | Analyzers that are not tied to one language or platform; first: function starts from the Mach-O function-starts table |
| [scripts/](scripts/README.md) | Stand-alone Ghidra scripts with no extension behind them (none yet) |

## Report a bug

Open an issue. Include the release or commit, the Ghidra and Java versions, the analyzer and its log lines from Ghidra's application log, and what you expected. If a binary is needed to show the problem, attach it, describe how to build one (Swift source and compiler command), or name a system binary and its OS version. Security issues go through [SECURITY.md](SECURITY.md).

## Install a release

The [Releases](../../releases) page has ready-made zips, one per extension and Ghidra version, named `<Extension>-<release>-ghidra_<version>.zip`. Use the one whose Ghidra version matches yours exactly. LZGhidraSwift is for Swift binaries; add LZGhidraGeneric when you analyse images extracted from the dyld shared cache. Both can be installed together. Each release also has a `SHA256SUMS` file, and each zip has a signed build provenance attestation: `gh attestation verify <zip> -R lzandman/LZGhidraStuff`.

1. In Ghidra's project window: File → Install Extensions → the green `+` (plus) button → the zip.
2. Restart Ghidra.

File → Install Extensions then lists the extension, with its release number at the end of the description. The analyzers are on by default. For a Ghidra version without a zip, build from source as below.

## Build requirements

Only for building from source:

- Ghidra 12.2 as a **release install** (the unpacked release zip, or a package that installs one, such as Homebrew's `ghidra`). A Ghidra source checkout does not work: the build needs the jars of a built release.
- Java 25, as Ghidra 12.2 requires (`application.java.min` in the Ghidra install).
- Gradle 9.1 or later (tested with 9.9.1). There is no Gradle wrapper.

**Every Gradle command needs `GHIDRA_INSTALL_DIR`**: the directory of the Ghidra release install, the one that contains `Ghidra/` and `support/`. Set it in the environment, or once for all builds in `~/.gradle/gradle.properties`:

```properties
GHIDRA_INSTALL_DIR=/opt/homebrew/opt/ghidra/libexec
```

A built extension zip installs without a warning only into the Ghidra version it was built for. For another version, build from source with that version's `GHIDRA_INSTALL_DIR`.

## Build and install

From an extension's directory:

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle buildExtension     # dist/ghidra_<version>_PUBLIC_<date>_<Extension>.zip
```

Install in Ghidra with File → Install Extensions → the green plus → the zip, then restart Ghidra. Or unzip the zip into `~/Library/ghidra/ghidra_<version>_PUBLIC/Extensions/` (macOS) and restart.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Tested on

macOS on Apple silicon with Ghidra 12.2, Java 25 and Gradle 9.9.1. Other platforms and Ghidra versions are not tested. The fixture and headless tools need macOS.

## Licence

Apache License 2.0, the same as Ghidra; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Each extension zip contains a copy of both. Two files come from other Apache-2.0 projects: Ghidra's formatter profile (a development file, not in any zip) and `LZGhidraSwift/data/swift-runtime-functions.txt`, derived from the Swift source (in the LZGhidraSwift zip).
