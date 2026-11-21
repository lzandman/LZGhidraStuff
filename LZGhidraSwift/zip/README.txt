LZGhidraSwift
=============

Release @lzrelease@.

A Ghidra extension with analyzers for Swift binaries on macOS (arm64 and
x86_64 Mach-O):

- LZ Swift String Literals: decodes the Swift String literals that code builds
  from immediates, and marks them in the listing and the decompiler.
- LZ Swift Data Types: Swift structs, classes and enums as data types in
  /SwiftTypes/<Module>.
- LZ Swift Self Types: gives the methods of those types a typed parameter self.
- LZ Swift Error Register: gives throwing functions a calling convention that
  keeps their catch paths in the decompiler.
- LZ Swift Runtime Prototypes: gives the imported Swift runtime functions their
  signatures.

Install
-------

This zip is for the Ghidra version in its file name only.

1. In Ghidra's project window: File > Install Extensions > the green + > this
   zip.
2. Restart Ghidra.

The analyzers are on by default. They run in Auto Analyze on the programs they
apply to; their options are in Analysis > Auto Analyze, under the names above.
Each writes a summary to Ghidra's application log.

For images extracted from the dyld shared cache, also install LZGhidraGeneric
(a separate zip on the same release page).

The scripts in ghidra_scripts/ (category Swift in the Script Manager) write
the analyzers' results to text files.

More
----

Documentation, source and bug reports:
https://github.com/lzandman/LZGhidraStuff/blob/main/LZGhidraSwift/README.md
https://github.com/lzandman/LZGhidraStuff

Licensed under the Apache License 2.0; see LICENSE and NOTICE.
