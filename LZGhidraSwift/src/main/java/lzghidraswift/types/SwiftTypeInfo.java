// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.types;

import java.util.List;

import ghidra.program.model.address.Address;
import lzghidraswift.mangling.MangledName;
import lzghidraswift.metadata.ContextDescriptor;

/**
 * A type of {@code __swift5_types}: its descriptor and qualified name, its layout from the static
 * metadata (or the reason there is none), and the records of its field descriptor (empty if it
 * has none). {@code skip} is set when the layout is known but the Swift Data Types analyzer does
 * not build the type (enums with payloads). {@code fields} is filled while
 * {@code __swift5_fieldmd} is read.
 */
public record SwiftTypeInfo(ContextDescriptor descriptor, String name, Address metadata,
		SwiftLayout layout, String noLayout, List<Field> fields) {

	/**
	 * A field record: a stored property, or an enum case. {@code typeAt} and {@code type} are
	 * null for a record without type (an enum case without payload) or with an unreadable one.
	 */
	public record Field(Address record, String name, Address typeAt, MangledName type, int flags) {}

	/**
	 * The descriptor's details and layout for the {@code SWIFTTYPE} log line, space-separated.
	 * {@code superclass} is the superclass's rendered name ("?" if unreadable), null if the
	 * descriptor has none.
	 */
	public String describe(String superclass) {
		ContextDescriptor d = descriptor;
		StringBuilder sb = new StringBuilder(256);
		sb.append("descriptor=")
				.append(d.address())
				.append(' ')
				.append(d.kindName())
				.append(' ')
				.append(name);
		if (d.isGeneric()) {
			sb.append(" generic");
		}
		sb.append(" init=").append(d.initName()).append(" accessor=").append(d.accessor());
		switch (d.kind()) {
			case ContextDescriptor.KIND_ENUM -> sb.append(" payloadCases=")
					.append(d.payloadCases())
					.append(" emptyCases=")
					.append(d.emptyCases());
			case ContextDescriptor.KIND_STRUCT, ContextDescriptor.KIND_CLASS -> {
				sb.append(" numFields=")
						.append(d.numFields())
						.append(" fieldOffsetVectorOffset=")
						.append(d.fieldOffsetVectorOffset());
			}
			default -> {
			}
		}
		if (superclass != null) {
			sb.append(" superclass=").append(superclass);
		}
		if (metadata != null) {
			sb.append(" metadata=").append(metadata);
		}
		if (layout != null) {
			sb.append(" size=").append(layout.size());
			if (layout.stride() >= 0) {
				sb.append(" stride=").append(layout.stride());
			}
			sb.append(" align=").append(layout.alignment());
			if (layout.witnesses() != null) {
				sb.append(" witnesses=").append(layout.witnesses());
			}
		}
		if (noLayout != null) {
			sb.append(" layout=none: ").append(noLayout);
		}
		else if (skip() != null) {
			sb.append(" skip=").append(skip());
		}
		return sb.toString();
	}

	/** The reason the type gets no data type, or null. */
	public String skip() {
		if (layout != null && descriptor.kind() == ContextDescriptor.KIND_ENUM &&
			descriptor.payloadCases() > 0) {
			return "enum with payload";
		}
		return noLayout;
	}
}
