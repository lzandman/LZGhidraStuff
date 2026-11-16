# Security Policy

## Supported versions

Only the latest release gets fixes, and only for the Ghidra version it is built for (now 12.2). Older releases are not updated; install the latest one instead.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |
| Builds from source | Use the latest commit on `main` |

## What counts as a security issue

The extensions are analyzers that run inside Ghidra and read the binaries you open in it. They have no network code and store no credentials. Report as a security issue:

- code execution, or reading or writing files outside the Ghidra project, caused by a crafted binary;
- a release zip whose contents do not match its source or its `SHA256SUMS` entry.

A crash, hang or wrong output on a malformed binary is a normal bug. Open an issue for it.

## Reporting a vulnerability

Report it privately through [Report a vulnerability](../../security/advisories/new) on the Security tab. Do not open a public issue. Include the release or commit, the Ghidra and Java versions, and steps to reproduce. If the problem needs a binary to trigger it, attach it or describe how to build one.

This is a personal project maintained in spare time. Expect a first reply within two weeks. If the report is accepted, the fix goes into a new release and the advisory is published with it, crediting you unless you ask not to be named. If it is declined, the reply says why.
