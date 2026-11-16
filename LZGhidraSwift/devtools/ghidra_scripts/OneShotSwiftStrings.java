// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Runs the Swift String Literals analyzer, with the program's options, on one function only, as
// a one-shot analysis of a selection does. The function: the argument (an entry address), else
// the one with the first small string in a bookmark. Run DumpSwiftStrings.java before and after:
// the dumps must be equal, so the markup of the other functions (string block references
// included) stays.
//@category Swift
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.*;
import lzghidraswift.SwiftStringLiteralsAnalyzer;

public class OneShotSwiftStrings extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Function f = null;
		if (getScriptArgs().length == 1) {
			f = getFunctionAt(toAddr(getScriptArgs()[0]));
		}
		else {
			Iterator<Bookmark> it =
				currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.ANALYSIS);
			while (it.hasNext() && f == null) {
				Bookmark b = it.next();
				if (b.getCategory().equals("Swift string (small)")) {
					f = getFunctionContaining(b.getAddress());
				}
			}
		}
		if (f == null) {
			println("OneShotSwiftStrings: no function with a small string; nothing run");
			return;
		}
		SwiftStringLiteralsAnalyzer analyzer = new SwiftStringLiteralsAnalyzer();
		Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
				.getOptions(analyzer.getName());
		analyzer.optionsChanged(options, currentProgram);
		println("OneShotSwiftStrings: %s at %s".formatted(f.getName(), f.getEntryPoint()));
		int tx = currentProgram.startTransaction("One-shot Swift String Literals");
		try {
			analyzer.added(currentProgram, f.getBody(), monitor, new MessageLog());
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
	}
}
