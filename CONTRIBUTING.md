# Contributing

To report a bug, see [Report a bug](README.md#report-a-bug) in the README. To build from source, see [Build requirements](README.md#build-requirements).

Contributions are licensed under the Apache License 2.0, the project's licence (see [LICENSE](LICENSE)). New source files start with the same two header lines as the existing ones: `SPDX-License-Identifier: Apache-2.0` and the copyright line.

## Making a change

Run `./check.sh` in the repository root before you send a change. It needs `GHIDRA_INSTALL_DIR` and stops at the first failure. Per extension it runs `gradle lint test buildExtension` (javac `-Xlint`, Error Prone, Spotless with Ghidra's Eclipse profile, PMD, Checkstyle, JUnit). Then it runs `ruff check` and `ruff format --check` on the Python files, `sh -n` on the shell scripts, and `shellcheck` when it is installed.

`gradle spotlessApply` in an extension's directory formats its Java files. The shared check configuration is in [buildconfig/](buildconfig/); development tools used by the extensions are in [devtools/](devtools/).

The fixture and headless checks of each extension are separate; see its README. For LZGhidraSwift, `LZGhidraSwift/devtools/test-fixtures.sh` runs them as one integration test with a pass or fail result. It needs macOS and takes about 6½ minutes on an M-series Mac.

## Dependency updates

Dependabot ([.github/dependabot.yaml](.github/dependabot.yaml)) proposes daily updates for the Gradle plugins, Error Prone, JUnit and the GitHub Actions. It does not see the PMD and Checkstyle versions (`toolVersion` in `buildconfig/quality.gradle`) or the Gradle version in the workflows; update those by hand.
