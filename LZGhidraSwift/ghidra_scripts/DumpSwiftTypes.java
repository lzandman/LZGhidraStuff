// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Writes the data types of the Swift Data Types analyzer (/SwiftTypes, without the helper types
// in /SwiftTypes/Swift) in the format of fixtures/DumpLayouts.swift, for
// fixtures/check_layouts.py. Argument: the output file.
//
// Lines, tab-separated, types sorted by name:
//   STRUCT  name  size  stride  align            length, length rounded up to the alignment
//                                                (Ghidra's aligned length is the length for a
//                                                non-packed structure), alignment
//   CLASS   name  size  align  superclass        the length rounded up to 8 (the instance size,
//                                                as class_getInstanceSize); superclass from the
//                                                description, _TtCs12_SwiftObject for none
//   ENUM    name  size  stride  align
//   FIELD   offset  size  name  Swift type  Ghidra type   classes: own fields only (not the
//                                                       header, isa or super components)
//   CASE    value  name
//@category Swift

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Structure;

public class DumpSwiftTypes extends GhidraScript {

	private static final Pattern SUPERCLASS = Pattern.compile("; superclass (\\S+)");

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 1) {
			throw new IllegalArgumentException("usage: DumpSwiftTypes.java <output file>");
		}
		Category root =
			currentProgram.getDataTypeManager().getCategory(new CategoryPath("/SwiftTypes"));
		List<DataType> found = new ArrayList<>();
		if (root != null) {
			collect(root, "", found);
		}
		found.sort(Comparator.comparing(dt -> qualifiedName(dt)));
		int structs = 0, classes = 0, enums = 0, fields = 0, undefined = 0;
		try (PrintWriter out = new PrintWriter(args[0], StandardCharsets.UTF_8)) {
			out.println("# DumpSwiftTypes, " + currentProgram.getName());
			for (DataType dt : found) {
				String name = qualifiedName(dt);
				String description = dt.getDescription() == null ? "" : dt.getDescription();
				if (dt instanceof Structure s && description.startsWith("Swift struct ")) {
					structs++;
					// An empty structure (a Swift struct of size 0) reports length 1.
					out.println(
						String.join("\t", "STRUCT", name, str(s.isZeroLength() ? 0 : s.getLength()),
							str(stride(s)), str(s.getAlignment())));
				}
				else if (dt instanceof Structure s && description.startsWith("Swift class ")) {
					classes++;
					Matcher m = SUPERCLASS.matcher(description);
					String superclass = m.find() ? m.group(1) : "?";
					// class_getInstanceSize rounds to the word size, not to the class's alignment
					// (an actor: 120 bytes, alignment 16).
					out.println(String.join("\t", "CLASS", name, str((s.getLength() + 7) / 8 * 8),
						str(s.getAlignment()),
						superclass.equals("none") ? "_TtCs12_SwiftObject" : superclass));
				}
				else if (dt instanceof Enum e && description.startsWith("Swift enum ")) {
					enums++;
					out.println(String.join("\t", "ENUM", name, str(e.getLength()), str(stride(e)),
						str(e.getAlignment())));
					long[] values = e.getValues();
					Arrays.sort(values);
					for (long v : values) {
						for (String caseName : e.getNames(v)) {
							out.println(String.join("\t", "CASE", Long.toString(v), caseName));
						}
					}
					continue;
				}
				else {
					continue;
				}
				for (DataTypeComponent c : ((Structure) dt).getDefinedComponents()) {
					String comment = c.getComment() == null ? "" : c.getComment();
					if (comment.endsWith("object header") ||
						comment.startsWith("Swift object header") ||
						comment.startsWith("superclass ") && "super".equals(c.getFieldName())) {
						continue;
					}
					fields++;
					String ghidraType = c.getDataType().getName();
					if (ghidraType.startsWith("undefined")) {
						undefined++;
					}
					out.println(String.join("\t", "FIELD", str(c.getOffset()), str(c.getLength()),
						c.getFieldName(), comment, ghidraType));
				}
			}
		}
		println("DumpSwiftTypes: %d structs, %d classes, %d enums, %d fields (%d undefined)"
				.formatted(structs, classes, enums, fields, undefined));
	}

	/** The data types under /SwiftTypes, except the helper types in /SwiftTypes/Swift. */
	private static void collect(Category category, String prefix, List<DataType> found) {
		for (DataType dt : category.getDataTypes()) {
			found.add(dt);
		}
		for (Category sub : category.getCategories()) {
			if (prefix.isEmpty() && sub.getName().equals("Swift")) {
				continue;
			}
			collect(sub, prefix + sub.getName() + ".", found);
		}
	}

	/** {@code /SwiftTypes/Layouts/Outer/Inner} → {@code Layouts.Outer.Inner}. */
	private static String qualifiedName(DataType dt) {
		String path = dt.getCategoryPath().getPath();
		String module = path.substring("/SwiftTypes".length()).replace('/', '.');
		return (module.startsWith(".") ? module.substring(1) + "." : "") + dt.getName();
	}

	/** Swift's stride: the size rounded up to the alignment, at least 1. */
	private static long stride(DataType dt) {
		long a = dt.getAlignment();
		return Math.max(1, (dt.getLength() + a - 1) / a * a);
	}

	private static String str(long n) {
		return Long.toString(n);
	}
}
