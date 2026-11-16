# scripts

Stand-alone Ghidra scripts (`.java` or `.py`) that have no extension behind them. No scripts yet.

## Use the folder in Ghidra

1. In the Script Manager, click **Manage Script Directories** (the list icon in the toolbar).
2. Click **Add** (the green plus), select this `scripts/` folder, and close the dialog.
3. The scripts appear under the category `LZGhidraStuff`.

## Header of a script

```java
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman
//@category LZGhidraStuff
```

A Python script uses `#` instead of `//` for the first two lines, and `#@category LZGhidraStuff` for the third.
