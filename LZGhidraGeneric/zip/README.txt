LZGhidraGeneric
===============

Release @lzrelease@.

A Ghidra extension with analyzers that are not tied to one language or
platform:

- LZ Mach-O Function Starts (Extracted DYLD): creates functions from
  LC_FUNCTION_STARTS in an image extracted from the dyld shared cache. Without
  it, part of the code of such an image stays outside functions.

Install it together with LZGhidraSwift when you analyse Swift code in such
images.

Install
-------

This zip is for the Ghidra version in its file name only.

1. In Ghidra's project window: File > Install Extensions > the green + > this
   zip.
2. Restart Ghidra.

The analyzer is on by default. It runs in Auto Analyze on the programs it
applies to; its options are in Analysis > Auto Analyze, under the name above.
It writes a summary to Ghidra's application log.

More
----

Documentation, source and bug reports:
https://github.com/lzandman/LZGhidraStuff/blob/main/LZGhidraGeneric/README.md
https://github.com/lzandman/LZGhidraStuff

Licensed under the Apache License 2.0; see LICENSE and NOTICE.
