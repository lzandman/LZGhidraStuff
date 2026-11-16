// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.mangling;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import lzghidraswift.metadata.ContextDescriptor;
import lzghidraswift.metadata.SymbolNames;

/**
 * Reads mangled type names ({@link MangledName}) from a program and resolves their symbolic
 * references to qualified names: context descriptors of the program (direct, or indirect through
 * a pointer), imported types (indirect, through a GOT entry bound to the type's descriptor symbol)
 * and Objective-C protocols.
 */
public class MangledTypeReader {

	/** Longest mangled name read; real names are far shorter. */
	private static final int MAX_LENGTH = 4096;
	/** Bound on parent chains and extension contexts, against malformed metadata. */
	private static final int MAX_DEPTH = 16;

	private final Program program;
	private final Memory memory;
	private final Map<Address, String> qualifiedNames = new HashMap<>();

	public MangledTypeReader(Program program) {
		this.program = program;
		this.memory = program.getMemory();
	}

	/** Reads the mangled name at {@code at}. Throws if it is not NUL-terminated in its block. */
	public MangledName read(Address at) throws MemoryAccessException {
		MemoryBlock block = memory.getBlock(at);
		if (block == null || !block.isInitialized()) {
			throw new MemoryAccessException("no initialized memory at " + at);
		}
		long available = block.getEnd().subtract(at) + 1;
		byte[] bytes = new byte[(int) Math.min(available, MAX_LENGTH)];
		int n = memory.getBytes(at, bytes);
		MangledName name =
			MangledName.parse(n == bytes.length ? bytes : Arrays.copyOf(bytes, n), 0);
		if (name == null) {
			throw new MemoryAccessException("unterminated mangled name at " + at);
		}
		return name;
	}

	/** The name at {@code at} with each reference shown as {@code <qualified name>}, or {@code <?>}. */
	public String render(Address at, MangledName name) {
		return render(at, name, 0);
	}

	private String render(Address at, MangledName name, int depth) {
		return name.render(ref -> {
			String s = referenceName(at, ref, depth);
			return s != null ? s : "?";
		});
	}

	/** The qualified name that the reference points to, or null if it cannot be resolved. */
	public String referenceName(Address nameAt, MangledName.Reference ref) {
		return referenceName(nameAt, ref, 0);
	}

	/** Address of a relative reference's target. */
	public static Address target(Address nameAt, MangledName.Reference ref) {
		return nameAt.add(ref.targetOffset());
	}

	private String referenceName(Address nameAt, MangledName.Reference ref, int depth) {
		if (!ref.isRelative() || depth > MAX_DEPTH) {
			return null;
		}
		try {
			Address target = target(nameAt, ref);
			return switch (ref.kind()) {
				case MangledName.CONTEXT_DIRECT -> qualifiedName(target, depth + 1);
				case MangledName.CONTEXT_INDIRECT -> indirectName(target, depth + 1);
				case MangledName.OBJC_PROTOCOL -> {
					Address protoref = ContextDescriptor.relativeOrNull(memory, target);
					if (protoref == null) {
						yield null;
					}
					Address protocol = ContextDescriptor.pointer(memory, protoref);
					// protocol_t: isa, then the name pointer
					yield ContextDescriptor.cString(memory,
						ContextDescriptor.pointer(memory, protocol.add(8)));
				}
				// The type is known only at run time; name the function for the reader.
				case MangledName.ACCESSOR_FUNCTION -> "metadata accessor at " + target;
				default -> null;
			};
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * Name behind a pointer to a context descriptor. For an imported type the pointer is a GOT
	 * entry that dyld binds to the type's descriptor symbol ({@code _$s7SwiftUI5ColorVMn});
	 * Ghidra shows the binding as an external reference or a symbol at the pointer's target.
	 */
	private String indirectName(Address slot, int depth) throws MemoryAccessException {
		Object target = indirectTarget(slot);
		return switch (target) {
			case Address descriptor -> qualifiedName(descriptor, depth);
			case String symbol -> symbolName(symbol);
			case null, default -> null;
		};
	}

	/**
	 * What a pointer to a context descriptor points to: the descriptor's address if it is in the
	 * program, else the imported symbol (the mangled descriptor symbol if there is one, else the
	 * primary symbol), or null.
	 */
	private Object indirectTarget(Address slot) throws MemoryAccessException {
		String external = SymbolNames.importedFrom(program, slot);
		if (external != null) {
			return external;
		}
		Address target = ContextDescriptor.pointer(memory, slot);
		if (!memory.isExternalBlockAddress(target)) {
			MemoryBlock block = memory.getBlock(target);
			if (block != null && block.isInitialized()) {
				return target;
			}
		}
		// The imported symbol keeps the mangled name; the demangler adds its own label (__int8
		// for Swift.Int8), often as the primary symbol.
		Symbol primary = null;
		for (Symbol symbol : program.getSymbolTable().getSymbols(target)) {
			if (MangledName.nominalTypeName(symbol.getName()) != null) {
				return symbol.getName();
			}
			if (symbol.isPrimary()) {
				primary = symbol;
			}
		}
		return primary != null ? primary.getName() : null;
	}

	/**
	 * The nominal type that a symbolic reference points to, for {@link SwiftTypeName#parse}: a
	 * context descriptor of the program (its address is the target), an imported type (kind from
	 * its descriptor symbol, no target) or an Objective-C protocol. Null if it cannot be resolved.
	 */
	public SwiftTypeName.Nominal nominal(Address nameAt, MangledName.Reference ref) {
		String name = referenceName(nameAt, ref);
		if (name == null) {
			return null;
		}
		try {
			Address target = target(nameAt, ref);
			Object resolved = switch (ref.kind()) {
				case MangledName.CONTEXT_DIRECT -> target;
				case MangledName.CONTEXT_INDIRECT -> indirectTarget(target);
				default -> null;
			};
			if (ref.kind() == MangledName.OBJC_PROTOCOL) {
				// Swift shows Objective-C protocols with their module, __C.NSCopying (Layouts
				// fixture), unlike Objective-C classes.
				return new SwiftTypeName.Nominal(SwiftTypeName.CLANG_MODULE + "." + name, 'P',
					null, true);
			}
			if (resolved instanceof Address descriptor) {
				char kind = switch (ContextDescriptor.read(memory, descriptor).kind()) {
					case ContextDescriptor.KIND_CLASS -> 'C';
					case ContextDescriptor.KIND_STRUCT -> 'V';
					case ContextDescriptor.KIND_ENUM -> 'O';
					case ContextDescriptor.KIND_PROTOCOL -> 'P';
					default -> '?';
				};
				return new SwiftTypeName.Nominal(name, kind, descriptor, false);
			}
			if (resolved instanceof String symbol && MangledName.nominalTypeName(symbol) != null) {
				// ..._$s<name><kind>Mn or _$s<name>Mp; imported from C and Objective-C: _$sSo...
				char kind = MangledName.nominalTypeKind(symbol);
				// nominalTypeName accepted the symbol, so it has a Swift body.
				boolean imported = SymbolNames.swiftBody(symbol).startsWith("So");
				// Named with their module, as types in the mangling text (SwiftTypeName).
				String prefix = SwiftTypeName.CLANG_MODULE + ".";
				return new SwiftTypeName.Nominal(
					imported && !name.startsWith(prefix) ? prefix + name : name, kind, null,
					imported);
			}
			return null;
		}
		catch (MemoryAccessException | AddressOutOfBoundsException e) {
			return null;
		}
	}

	private static String symbolName(String symbol) {
		String name = MangledName.nominalTypeName(symbol);
		return name != null ? name : symbol;
	}

	/** Qualified name of a context descriptor of the program, such as {@code Layouts.Outer.Inner}. */
	public String qualifiedName(Address descriptor) throws MemoryAccessException {
		return qualifiedName(descriptor, 0, false);
	}

	/**
	 * The qualified name with anonymous contexts (private and local types) shown as Swift's
	 * {@code String(reflecting:)} shows them, {@code (unknown context at $46294)}, with the
	 * anonymous context descriptor's address. For types whose plain names collide.
	 */
	public String qualifiedNameWithAnonymousContexts(Address descriptor)
			throws MemoryAccessException {
		return qualifiedName(descriptor, 0, true);
	}

	private String qualifiedName(Address descriptor, int depth) throws MemoryAccessException {
		return qualifiedName(descriptor, depth, false);
	}

	private String qualifiedName(Address descriptor, int depth, boolean anonymous)
			throws MemoryAccessException {
		String cached = anonymous ? null : qualifiedNames.get(descriptor);
		if (cached != null) {
			return cached;
		}
		Deque<String> parts = new ArrayDeque<>();
		Address at = descriptor;
		for (int i = 0; at != null; i++) {
			if (i > MAX_DEPTH) {
				throw new MemoryAccessException("parent chain too long at " + descriptor);
			}
			ContextDescriptor d = ContextDescriptor.read(memory, at);
			switch (d.kind()) {
				case ContextDescriptor.KIND_ANONYMOUS -> {
					// private and local types; Swift shows "(unknown context at $...)"
					if (anonymous) {
						parts.addFirst("(unknown context at $%x)".formatted(at.getOffset()));
					}
				}
				case ContextDescriptor.KIND_EXTENSION -> {
					parts.addFirst(extensionName(at, d, depth));
					at = null;
					continue;
				}
				default -> parts.addFirst(d.name() != null ? d.name() : "?");
			}
			at = d.parent();
		}
		String name = String.join(".", parts);
		if (!anonymous) {
			qualifiedNames.put(descriptor, name);
		}
		return name;
	}

	/**
	 * The name of the extension context {@code d} at {@code at}: the extended type, as a mangled
	 * name; it already includes its module. Rendered as Swift does
	 * (SwiftDiagnostics.FixIt.MultiNodeChange in swift-format, an extension of another module's
	 * type); the mangled rendering shows symbolic references in angle brackets,
	 * {@code <SwiftDiagnostics.FixIt>}.
	 */
	private String extensionName(Address at, ContextDescriptor d, int depth)
			throws MemoryAccessException {
		Address extended = ContextDescriptor.relativeOrNull(memory, at.add(8));
		if (extended == null) {
			return "(extension)";
		}
		MangledName mangled = read(extended);
		SwiftTypeName type = depth < MAX_DEPTH
				? SwiftTypeName.parse(mangled, ref -> nominal(extended, ref))
				: null;
		String rendered = type != null ? type.render() : render(extended, mangled, depth + 1);
		// In another module than the extended type's, Swift names the type
		// "(extension in Layouts):Foundation.URL.Component" (Layouts fixture).
		String module = extensionModule(d);
		boolean otherModule = module != null && !rendered.startsWith(module + ".");
		return otherModule ? "(extension in " + module + "):" + rendered : rendered;
	}

	/** The module an extension context is declared in (its parent chain), or null. */
	private String extensionModule(ContextDescriptor extension) throws MemoryAccessException {
		Address at = extension.parent();
		for (int i = 0; at != null && i <= MAX_DEPTH; i++) {
			ContextDescriptor d = ContextDescriptor.read(memory, at);
			if (d.kind() == ContextDescriptor.KIND_MODULE) {
				return d.name();
			}
			at = d.parent();
		}
		return null;
	}
}
