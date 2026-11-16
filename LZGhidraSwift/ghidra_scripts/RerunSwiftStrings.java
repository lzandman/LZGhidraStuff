// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Test of the Swift String Literals analyzer's idempotency. Adds a user line to the EOL and PRE
// comments of the first two bookmarked strings, then runs the analyzer again on every function.
// Run DumpSwiftStrings.java before and after; the dumps must differ only by the two user lines
// (and by the comment type, if a style is given). Optional argument: comment style, EOL or PRE.
// Without it the analyzer runs with the program's options; with it, with every markup option on
// in that style, and the program's String block option.
//@category Swift

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import lzghidraswift.SwiftStringLiteralsAnalyzer;

public class RerunSwiftStrings extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		List<Address> marked = new ArrayList<>();
		Iterator<Bookmark> it =
			currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.ANALYSIS);
		while (it.hasNext() && marked.size() < 2) {
			Bookmark b = it.next();
			String category = b.getCategory();
			if (category.equals("Swift string (small)") ||
				category.equals("Swift string (large)")) {
				marked.add(b.getAddress());
			}
		}
		int tx = currentProgram.startTransaction("Rerun Swift String Literals");
		try {
			Listing listing = currentProgram.getListing();
			CommentType[] types = { CommentType.EOL, CommentType.PRE };
			for (int i = 0; i < marked.size(); i++) {
				Address a = marked.get(i);
				String old = listing.getComment(types[i], a);
				listing.setComment(a, types[i], old == null ? "user note" : "user note\n" + old);
				println("RerunSwiftStrings: user %s comment at %s".formatted(types[i], a));
			}
			SwiftStringLiteralsAnalyzer analyzer = new SwiftStringLiteralsAnalyzer();
			// The program's options, as auto-analysis passes them (the String block option too).
			Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
					.getOptions(analyzer.getName());
			analyzer.optionsChanged(options, currentProgram);
			if (args.length == 1) {
				analyzer.setMarkupOptions(args[0], true, true, true, true,
					options.getBoolean("String block", false));
			}
			analyzer.added(currentProgram, currentProgram.getMemory(), monitor, new MessageLog());
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
	}
}
