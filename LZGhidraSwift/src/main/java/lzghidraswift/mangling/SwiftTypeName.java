// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.mangling;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A Swift type parsed from a mangled type name of the reflection metadata ({@link MangledName}),
 * and its readable form in the style of Swift's {@code String(reflecting:)}:
 * {@code Swift.Optional<Swift.Double>}, {@code (Swift.Int) throws -> Swift.Double},
 * {@code Layouts.Shape} for an existential. Plain Java.
 * <p>
 * The parser covers the subset of the type mangling (swift/docs/ABI/Mangling.rst) that stored
 * properties use: standard types ({@code Si}, {@code SS}, ...), module-qualified nominal types,
 * bound generics ({@code SaySdG}), the optional sugar {@code Sg}, tuples, function types,
 * protocol existentials and their metatypes ({@code Xp}), symbolic references and substitutions
 * ({@code AA}). Like Swift's demangler it works on a stack: the mangling is postfix. Identifiers
 * may use word substitutions. Anything else (punycode, other metatypes, generic parameters, ...)
 * makes {@link #parse} return null.
 */
public sealed interface SwiftTypeName {

	/** The readable type, as Swift writes it inside another type. */
	String render();

	/**
	 * The readable type of a stored property, as {@code String(reflecting:)} writes it: like
	 * {@link #render}, except that an Objective-C class on its own has no module, {@code NSString},
	 * where Swift writes {@code Swift.Optional<__C.NSString>} and {@code __C.CGSize} (measured,
	 * Swift 6.4). The ownership of a weak or unowned reference is not shown.
	 */
	static String renderField(SwiftTypeName type) {
		SwiftTypeName t = type instanceof Ownership o ? o.type() : type;
		if (t instanceof Nominal n && n.objc() && n.kind() == 'C' && n.args().isEmpty() &&
			n.name().startsWith(CLANG_MODULE + ".")) {
			return n.name().substring(CLANG_MODULE.length() + 1);
		}
		return type.render();
	}

	/**
	 * A nominal type: struct ({@code V}), class ({@code C}), enum ({@code O}), protocol
	 * ({@code P}) or type alias ({@code a}); {@code ?} if unknown. {@code target} identifies the
	 * context descriptor of a symbolic reference (an {@code Address} in the analyzer), null for
	 * types named in the mangling text. {@code objc}: a type imported from C or Objective-C
	 * (module {@code __C}), or an Objective-C protocol.
	 */
	record Nominal(String name, char kind, List<SwiftTypeName> args, Object target, boolean objc)
			implements SwiftTypeName {

		public Nominal(String name, char kind, Object target, boolean objc) {
			this(name, kind, List.of(), target, objc);
		}

		@Override
		public String render() {
			return args.isEmpty() ? name
					: name + args.stream()
							.map(SwiftTypeName::render)
							.collect(Collectors.joining(", ", "<", ">"));
		}
	}

	/** A tuple; {@code labels} has a null for each unlabelled element. */
	record Tuple(List<SwiftTypeName> elements, List<String> labels) implements SwiftTypeName {

		@Override
		public String render() {
			List<String> parts = new ArrayList<>();
			for (int i = 0; i < elements.size(); i++) {
				String label = labels.get(i);
				parts.add((label != null ? label + ": " : "") + elements.get(i).render());
			}
			return "(" + String.join(", ", parts) + ")";
		}
	}

	/**
	 * A function type. {@code convention}: {@code swift} (a thick closure, mangled {@code c}),
	 * {@code block} ({@code XB}), {@code c} ({@code XC}), {@code noescape} ({@code XE}).
	 * {@code isolation}: null, {@code @isolated(any)} ({@code YA}), {@code nonisolated(nonsending)}
	 * ({@code YC}) or a global actor, {@code @Swift.MainActor} ({@code <type>Yc}). {@code thrown}:
	 * the error type of {@code throws(E)} ({@code <type>YK}), else null.
	 */
	record FunctionType(SwiftTypeName params, SwiftTypeName result, String convention,
			boolean isAsync, boolean isThrows, String isolation, boolean sendable,
			SwiftTypeName thrown, boolean sendingResult) implements SwiftTypeName {

		/** In the order of Swift's NodePrinter::printFunctionType. */
		@Override
		public String render() {
			String p = params instanceof Tuple t && t.labels().stream().allMatch(Objects::isNull)
					? params.render()
					: "(" + params.render() + ")";
			String prefix = switch (convention) {
				case "block" -> "@convention(block) ";
				case "c" -> "@convention(c) ";
				default -> "";
			};
			boolean nonsending = "nonisolated(nonsending)".equals(isolation);
			return prefix + (isolation != null && !nonsending ? isolation + " " : "") +
				(nonsending ? isolation + " " : "") + (sendable ? "@Sendable " : "") + p +
				(isAsync ? " async" : "") +
				(thrown != null ? " throws(" + thrown.render() + ")" : isThrows ? " throws" : "") +
				" -> " + (sendingResult ? "sending " : "") + result.render();
		}
	}

	/**
	 * A protocol existential ({@code any P & Q}); {@code anyObject} if it is constrained to
	 * classes ({@code AnyObject}). No protocols: {@code Any} or {@code Swift.AnyObject}.
	 */
	record Existential(List<Nominal> protocols, boolean anyObject) implements SwiftTypeName {

		@Override
		public String render() {
			List<String> names = new ArrayList<>();
			if (anyObject) {
				names.add("Swift.AnyObject");
			}
			protocols.forEach(p -> names.add(p.render()));
			return names.isEmpty() ? "Any" : String.join(" & ", names);
		}
	}

	/**
	 * An existential metatype ({@code any P.Type}, mangled {@code <protocols>Xp}): the type
	 * metadata and one witness table per Swift protocol. Swift renders it as the existential
	 * followed by {@code .Type}, without parentheses ({@code M.P & M.Q.Type}).
	 */
	record ExistentialMetatype(Existential instance) implements SwiftTypeName {

		@Override
		public String render() {
			return instance.render() + ".Type";
		}
	}

	/** An integer generic argument ({@code $} INDEX): the 3 of {@code Swift.InlineArray<3, Swift.Int16>}. */
	record IntegerValue(long value) implements SwiftTypeName {

		@Override
		public String render() {
			return Long.toString(value);
		}
	}

	/**
	 * A metatype of a concrete type ({@code <type>m}): {@code Swift.Int.Type}. Stored, a metatype of
	 * a struct or enum is thin (0 bytes), of a class the metadata pointer (measured, Swift 6.4).
	 */
	record Metatype(SwiftTypeName instance) implements SwiftTypeName {

		@Override
		public String render() {
			return instance.render() + ".Type";
		}
	}

	/**
	 * A stored reference with an ownership: {@code weak} ({@code Xw}), {@code unowned}
	 * ({@code Xo}), {@code unowned(unsafe)} ({@code Xu}). Swift shows the referenced type only
	 * ({@code String(reflecting:)} of the property's type), so this renders as {@code type}.
	 */
	record Ownership(String ownership, SwiftTypeName type) implements SwiftTypeName {

		@Override
		public String render() {
			return type.render();
		}
	}

	/** A parameter with an ownership or {@code inout} marker: {@code inout Swift.Int}. */
	record Modified(String modifier, SwiftTypeName type) implements SwiftTypeName {

		@Override
		public String render() {
			return modifier + " " + type.render();
		}
	}

	/** Swift's standard type substitutions {@code S<c>} (swift/Demangling/StandardTypesMangling.def). */
	Map<Character, String> STANDARD_TYPES = Map.ofEntries(Map.entry('A',
		"VAutoreleasingUnsafeMutablePointer"), Map.entry('a', "VArray"), Map.entry('b', "VBool"),
		Map.entry('D', "VDictionary"), Map.entry('d', "VDouble"), Map.entry('f', "VFloat"),
		Map.entry('h', "VSet"), Map.entry('I', "VDefaultIndices"), Map.entry('i', "VInt"),
		Map.entry('J', "VCharacter"), Map.entry('N', "VClosedRange"), Map.entry('n', "VRange"),
		Map.entry('O', "VObjectIdentifier"), Map.entry('P', "VUnsafePointer"),
		Map.entry('p', "VUnsafeMutablePointer"), Map.entry('R', "VUnsafeBufferPointer"),
		Map.entry('r', "VUnsafeMutableBufferPointer"), Map.entry('S', "VString"),
		Map.entry('s', "VSubstring"), Map.entry('u', "VUInt"), Map.entry('V', "VUnsafeRawPointer"),
		Map.entry('v', "VUnsafeMutableRawPointer"), Map.entry('W', "VUnsafeRawBufferPointer"),
		Map.entry('w', "VUnsafeMutableRawBufferPointer"), Map.entry('q', "OOptional"),
		Map.entry('B', "PBinaryFloatingPoint"), Map.entry('E', "PEncodable"),
		Map.entry('e', "PDecodable"), Map.entry('F', "PFloatingPoint"),
		Map.entry('G', "PRandomNumberGenerator"), Map.entry('H', "PHashable"),
		Map.entry('j', "PNumeric"), Map.entry('K', "PBidirectionalCollection"),
		Map.entry('k', "PRandomAccessCollection"), Map.entry('L', "PComparable"),
		Map.entry('l', "PCollection"), Map.entry('M', "PMutableCollection"),
		Map.entry('m', "PRangeReplaceableCollection"), Map.entry('Q', "PEquatable"),
		Map.entry('T', "PSequence"), Map.entry('t', "PIteratorProtocol"),
		Map.entry('U', "PUnsignedInteger"), Map.entry('X', "PRangeExpression"),
		Map.entry('x', "PStrideable"), Map.entry('Y', "PRawRepresentable"),
		Map.entry('y', "PStringProtocol"), Map.entry('Z', "PSignedInteger"),
		Map.entry('z', "PBinaryInteger"));

	/**
	 * The concurrency substitutions {@code Sc<c>} (STANDARD_TYPE_CONCURRENCY in
	 * swift/Demangling/StandardTypesMangling.def), in the module Swift.
	 */
	Map<Character, String> CONCURRENCY_TYPES = Map.ofEntries(Map.entry('A', "PActor"),
		Map.entry('C', "VCheckedContinuation"), Map.entry('c', "VUnsafeContinuation"),
		Map.entry('E', "VCancellationError"), Map.entry('e', "VUnownedSerialExecutor"),
		Map.entry('F', "PExecutor"), Map.entry('f', "PSerialExecutor"),
		Map.entry('G', "VTaskGroup"),
		Map.entry('g', "VThrowingTaskGroup"), Map.entry('h', "PTaskExecutor"),
		Map.entry('I', "PAsyncIteratorProtocol"), Map.entry('i', "PAsyncSequence"),
		Map.entry('J', "VUnownedJob"), Map.entry('M', "CMainActor"),
		Map.entry('P', "VTaskPriority"),
		Map.entry('S', "VAsyncStream"), Map.entry('s', "VAsyncThrowingStream"),
		Map.entry('T', "VTask"),
		Map.entry('t', "VUnsafeCurrentTask"));

	/** {@code S<c>} or {@code Sc<c>} at {@code text[at]}: the table entry (kind, name), or null. */
	static String standardEntry(String text, int at) {
		if (at + 1 >= text.length() || text.charAt(at) != 'S') {
			return null;
		}
		if (text.charAt(at + 1) == 'c') {
			return at + 2 < text.length() ? CONCURRENCY_TYPES.get(text.charAt(at + 2)) : null;
		}
		return STANDARD_TYPES.get(text.charAt(at + 1));
	}

	/**
	 * A qualified name split at the dots that are not inside angle brackets or parentheses:
	 * {@code (extension in M):Swift.Array<M.T>.Package} has the parts
	 * {@code (extension in M):Swift}, {@code Array<M.T>}, {@code Package}.
	 */
	static List<String> nameParts(String qualified) {
		List<String> parts = new ArrayList<>();
		int depth = 0;
		int start = 0;
		for (int i = 0; i < qualified.length(); i++) {
			char c = qualified.charAt(i);
			if (c == '<' || c == '(') {
				depth++;
			}
			else if (c == '>' || c == ')') {
				depth--;
			}
			else if (c == '.' && depth == 0) {
				parts.add(qualified.substring(start, i));
				start = i + 1;
			}
		}
		parts.add(qualified.substring(start));
		return parts;
	}

	/** Module of types imported from C and Objective-C. */
	String CLANG_MODULE = "__C";

	/**
	 * Parses a mangled type. {@code resolve} turns a symbolic reference into a nominal type (null
	 * if it cannot be resolved). Returns null if the name is outside the supported subset or a
	 * reference does not resolve.
	 */
	static SwiftTypeName parse(MangledName name, Function<MangledName.Reference, Nominal> resolve) {
		return new Parser(name, resolve).parse();
	}

	/**
	 * The start of a member's symbol, up to its entity operator: the context type, then the
	 * member's name, labels and type ({@code 7Methods5GaugeV5raise2byySi_t} of
	 * {@code $s7Methods5GaugeV5raise2byySi_tF}). {@code member} is the first identifier after the
	 * context, or null if there is none (an initializer, a subscript, or the context alone).
	 */
	record Entity(Nominal context, String member) {}

	/**
	 * Parses the text of a symbol after {@code $s} and before its entity operator. Returns null if
	 * the text does not start with a nominal type or contains an operator outside the supported
	 * subset, which includes the operators of nested entities (functions, closures, local and
	 * private names, generic signatures).
	 */
	static Entity parseEntity(String text) {
		return new Parser(new MangledName(List.of(new MangledName.Text(text)), text.length()),
			ref -> null).entity();
	}

	/** The stack machine of {@link #parse}. Markers and names in progress share the stack. */
	final class Parser {

		private enum Marker {
			EMPTY_LIST,
			FIRST_ELEMENT,
			THROWS,
			ASYNC,
			SENDABLE,
			ISOLATED_ANY,
			NONSENDING,
			SENDING_RESULT
		}

		/** {@code <type>Yc}: a global actor; {@code <type>YK}: the error type of a typed throws. */
		private record GlobalActor(SwiftTypeName type) {}

		private record TypedThrows(SwiftTypeName type) {}

		private record Module(String name) {}

		private record Identifier(String text) {}

		private final MangledName name;
		private final Function<MangledName.Reference, Nominal> resolve;
		private final Deque<Object> stack = new ArrayDeque<>();
		/**
		 * The nodes a substitution can repeat, in the order Swift's demangler adds them:
		 * identifiers, nominal types (also from symbolic references), bound generics, {@code Sg}.
		 */
		private final List<Object> substitutions = new ArrayList<>();
		/** The words of the identifiers so far, for word substitutions. */
		private final MangledIdentifiers identifiers = new MangledIdentifiers();
		private String text = "";
		private int pos;

		private Parser(MangledName name, Function<MangledName.Reference, Nominal> resolve) {
			this.name = name;
			this.resolve = resolve;
		}

		SwiftTypeName parse() {
			return run() && stack.size() == 1 && stack.peek() instanceof SwiftTypeName t ? t : null;
		}

		Entity entity() {
			if (!run() || !(stack.peekLast() instanceof Nominal context)) {
				return null;
			}
			List<Object> nodes = new ArrayList<>(stack);
			Object next = nodes.size() > 1 ? nodes.get(nodes.size() - 2) : null;
			return new Entity(context, next instanceof Identifier id ? id.text() : null);
		}

		/** Runs the stack machine over the whole name; false if an operator is not supported. */
		private boolean run() {
			try {
				for (MangledName.Part part : name.parts()) {
					switch (part) {
						case MangledName.Reference ref -> {
							Nominal n = resolve.apply(ref);
							if (n == null) {
								return false;
							}
							push(n);
						}
						case MangledName.Text t -> {
							text = t.text();
							pos = 0;
							while (pos < text.length()) {
								if (!step()) {
									return false;
								}
							}
						}
					}
				}
			}
			catch (IllegalStateException e) {
				return false;
			}
			return true;
		}

		/** One operator of the mangling; false if it is not supported. */
		private boolean step() {
			char c = text.charAt(pos++);
			if (Character.isDigit(c)) {
				return identifier();
			}
			switch (c) {
				case 'S' -> {
					return standard();
				}
				case 'B' -> {
					return builtin();
				}
				case 'm' -> stack.push(new Metatype(popType()));
				case '$' -> {
					return integerValue();
				}
				case 's' -> stack.push(new Module("Swift"));
				case 'V', 'C', 'O', 'P', 'a' -> {
					return nominal(c);
				}
				case 'y' -> stack.push(Marker.EMPTY_LIST);
				case '_' -> stack.push(Marker.FIRST_ELEMENT);
				case 'G' -> {
					return boundGeneric();
				}
				case 't' -> {
					return tuple();
				}
				case 'p' -> {
					return protocolList(false);
				}
				case 'K' -> stack.push(Marker.THROWS);
				case 'c' -> {
					return function("swift");
				}
				case 'z' -> stack.push(new Modified("inout", popType()));
				case 'n' -> stack.push(new Modified("__owned", popType()));
				case 'h' -> stack.push(new Modified("__shared", popType()));
				case 'X' -> {
					return special();
				}
				case 'A' -> {
					return substitution();
				}
				case 'Y' -> {
					return annotation();
				}
				default -> {
					return false;
				}
			}
			return true;
		}

		/** {@code <length><characters>}, or {@code 0} and word substitutions. */
		private boolean identifier() {
			MangledIdentifiers.Parsed id = identifiers.parse(text, pos - 1);
			if (id == null) {
				return false;
			}
			push(new Identifier(id.text()));
			pos = id.end();
			return true;
		}

		/** Pushes a node that later substitutions can repeat. */
		private void push(Object node) {
			stack.push(node);
			substitutions.add(node);
		}

		/**
		 * Swift's demangleMultiSubstitutions: {@code A} then lowercase letters (each pushes the
		 * substitution with that index, a = 0) and a final uppercase letter (A = 0), each optionally
		 * preceded by a repeat count; or {@code A<n>_} for index n + 27.
		 */
		private boolean substitution() {
			int repeat = 1;
			while (pos < text.length()) {
				char c = text.charAt(pos++);
				if (Character.isDigit(c)) {
					int start = pos - 1;
					while (pos < text.length() && Character.isDigit(text.charAt(pos))) {
						pos++;
					}
					int n = Integer.parseInt(text.substring(start, pos));
					if (pos < text.length() && text.charAt(pos) == '_') {
						pos++;
						return repeat(n + 27, 1);
					}
					repeat = n;
				}
				else if (c == '_') {
					return repeat(26, 1);
				}
				else if (c >= 'a' && c <= 'z') {
					if (!repeat(c - 'a', repeat)) {
						return false;
					}
					repeat = 1;
				}
				else if (c >= 'A' && c <= 'Z') {
					return repeat(c - 'A', repeat);
				}
				else {
					return false;
				}
			}
			return false;
		}

		private boolean repeat(int index, int count) {
			if (index >= substitutions.size()) {
				return false;
			}
			for (int i = 0; i < count; i++) {
				stack.push(substitutions.get(index));
			}
			return true;
		}

		/** {@code S<c>}, or {@code S<n><c>}: n copies of the standard type (Sd_S2dt). */
		private boolean standard() {
			int copies = 1;
			int start = pos;
			while (pos < text.length() && Character.isDigit(text.charAt(pos))) {
				pos++;
			}
			if (pos > start) {
				copies = Integer.parseInt(text.substring(start, pos));
			}
			if (pos >= text.length()) {
				return false;
			}
			char c = text.charAt(pos++);
			if (copies > 1) {
				String entry = STANDARD_TYPES.get(c);
				if (entry == null) {
					return false;
				}
				for (int i = 0; i < copies; i++) {
					stack.push(new Nominal("Swift." + entry.substring(1), entry.charAt(0), null,
						false));
				}
				return true;
			}
			switch (c) {
				case 'g' -> {
					SwiftTypeName wrapped = popType();
					push(new Nominal("Swift.Optional", 'O', List.of(wrapped), null, false));
				}
				case 'o' -> stack.push(new Module(CLANG_MODULE));
				case 'c' -> {
					String entry = pos < text.length() ? CONCURRENCY_TYPES.get(text.charAt(pos++))
							: null;
					if (entry == null) {
						return false;
					}
					stack.push(new Nominal("Swift." + entry.substring(1), entry.charAt(0), null,
						false));
				}
				default -> {
					String entry = STANDARD_TYPES.get(c);
					if (entry == null) {
						return false;
					}
					stack.push(new Nominal("Swift." + entry.substring(1), entry.charAt(0), null,
						false));
				}
			}
			return true;
		}

		/** Pops the identifier and its context (a module or a nominal type). */
		private boolean nominal(char kind) {
			Nominal n = popNominal(kind);
			if (n == null) {
				return false;
			}
			push(n);
			return true;
		}

		/** The identifier and its context on the stack as a nominal type, or null. */
		private Nominal popNominal(char kind) {
			if (!(stack.poll() instanceof Identifier id)) {
				return null;
			}
			Object context = stack.poll();
			if (context instanceof Identifier module) { // 10Foundation3URLV
				context = new Module(module.text());
			}
			String qualified;
			boolean objc;
			if (context instanceof Module m) {
				objc = m.name().equals(CLANG_MODULE);
				// Always with the module, __C.NSString; renderField drops it where Swift does.
				qualified = m.name() + "." + id.text();
			}
			else if (context instanceof Nominal outer && outer.args().isEmpty()) {
				objc = outer.objc();
				qualified = outer.name() + "." + id.text();
			}
			else {
				return null;
			}
			return new Nominal(qualified, kind == 'a' ? '?' : kind, null, objc);
		}

		/**
		 * {@code <nominal> y <args> (_ <args>)* G}: one argument list per nesting level of the
		 * type, outermost first (Swift's demangleBoundGenerics); a level without arguments has an
		 * empty list ({@code <ARC.Credential>y_<H>G} is {@code ARC.Credential<H>},
		 * {@code <Swift.Dictionary.Index>y<K>SS_G} is {@code Swift.Dictionary<K, Swift.String>.Index}).
		 * The levels are the parts of the qualified name after the module. The arguments of outer
		 * levels become part of the name; the last level's are {@code args}.
		 */
		private boolean boundGeneric() {
			List<List<SwiftTypeName>> lists = new ArrayList<>(); // innermost first
			while (true) {
				List<SwiftTypeName> args = new ArrayList<>();
				while (stack.peek() instanceof SwiftTypeName) {
					args.add(popType());
				}
				Collections.reverse(args);
				lists.add(args);
				Object marker = stack.poll();
				if (marker == Marker.EMPTY_LIST) {
					break;
				}
				if (marker != Marker.FIRST_ELEMENT) {
					return false;
				}
			}
			if (!(stack.poll() instanceof Nominal n) || !n.args().isEmpty()) {
				return false;
			}
			Collections.reverse(lists);
			String name = n.name();
			if (lists.size() > 1) {
				List<String> parts = nameParts(name);
				if (parts.size() - 1 != lists.size()) {
					return false;
				}
				StringBuilder b = new StringBuilder(parts.getFirst());
				for (int i = 0; i < lists.size(); i++) {
					b.append('.').append(parts.get(i + 1));
					// A level that already has its arguments: a type in a constrained extension,
					// (extension in M):Swift.Array<M.T>.Package (swift-package).
					if (i < lists.size() - 1 && !lists.get(i).isEmpty() &&
						!parts.get(i + 1).endsWith(">")) {
						b.append(lists.get(i)
								.stream()
								.map(SwiftTypeName::render)
								.collect(Collectors.joining(", ", "<", ">")));
					}
				}
				name = b.toString();
			}
			push(new Nominal(name, n.kind(), List.copyOf(lists.getLast()), n.target(),
				n.objc()));
			return true;
		}

		/** Swift's popTuple: elements back to the first-element marker, each with its label. */
		private boolean tuple() {
			List<SwiftTypeName> elements = new ArrayList<>();
			List<String> labels = new ArrayList<>();
			if (stack.peek() == Marker.EMPTY_LIST) {
				stack.pop();
			}
			else {
				boolean first;
				do {
					first = stack.peek() == Marker.FIRST_ELEMENT;
					if (first) {
						stack.pop();
					}
					String label = stack.peek() instanceof Identifier id ? id.text() : null;
					if (label != null) {
						stack.pop();
					}
					elements.add(popType());
					labels.add(label);
				}
				while (!first);
				Collections.reverse(elements);
				Collections.reverse(labels);
			}
			stack.push(new Tuple(List.copyOf(elements), Collections.unmodifiableList(labels)));
			return true;
		}

		/** {@code <P> _ <Q> p}, {@code y p} (Any); with {@code Xl} constrained to classes. */
		private boolean protocolList(boolean anyObject) {
			List<Nominal> protocols = new ArrayList<>();
			if (stack.peek() == Marker.EMPTY_LIST) {
				stack.pop();
			}
			else {
				boolean first;
				do {
					first = stack.peek() == Marker.FIRST_ELEMENT;
					if (first) {
						stack.pop();
					}
					// Swift's popProtocol: in a list, a protocol named in the text has no P
					// (So9NSCopying_p); a symbolic reference is a nominal type already.
					Nominal p = stack.peek() instanceof Identifier ? popNominal('P')
							: stack.poll() instanceof Nominal n ? n : null;
					if (p == null || p.kind() != 'P') {
						return false;
					}
					protocols.add(p);
				}
				while (!first);
				Collections.reverse(protocols);
			}
			stack.push(new Existential(List.copyOf(protocols), anyObject));
			return true;
		}

		/** Swift's popFunctionType: markers, then the parameters, then the result. */
		private boolean function(String convention) {
			boolean isThrows = false;
			boolean isAsync = false;
			boolean sendable = false;
			boolean sendingResult = false;
			String isolation = null;
			SwiftTypeName thrown = null;
			while ((stack.peek() instanceof Marker m && m != Marker.EMPTY_LIST &&
				m != Marker.FIRST_ELEMENT) || stack.peek() instanceof GlobalActor ||
				stack.peek() instanceof TypedThrows) {
				switch (stack.pop()) {
					case GlobalActor g -> isolation = "@" + g.type().render();
					case TypedThrows t -> {
						isThrows = true;
						thrown = t.type();
					}
					case Marker m -> {
						isThrows |= m == Marker.THROWS;
						isAsync |= m == Marker.ASYNC;
						sendable |= m == Marker.SENDABLE;
						sendingResult |= m == Marker.SENDING_RESULT;
						if (m == Marker.ISOLATED_ANY) {
							isolation = "@isolated(any)";
						}
						else if (m == Marker.NONSENDING) {
							isolation = "nonisolated(nonsending)";
						}
					}
					default -> throw new IllegalStateException();
				}
			}
			SwiftTypeName params = popParams();
			SwiftTypeName result = popParams();
			stack.push(new FunctionType(params, result, convention, isAsync, isThrows, isolation,
				sendable, thrown, sendingResult));
			return true;
		}

		private SwiftTypeName popParams() {
			if (stack.peek() == Marker.EMPTY_LIST) {
				stack.pop();
				return new Tuple(List.of(), List.of());
			}
			return popType();
		}

		private boolean special() {
			if (pos >= text.length()) {
				return false;
			}
			return switch (text.charAt(pos++)) {
				case 'l' -> protocolList(true);
				case 'B' -> function("block");
				case 'C' -> function("c");
				case 'E' -> function("noescape");
				case 'w' -> ownership("weak");
				case 'o' -> ownership("unowned");
				case 'u' -> ownership("unowned(unsafe)");
				case 'p' -> {
					if (stack.poll() instanceof Existential e) {
						stack.push(new ExistentialMetatype(e));
						yield true;
					}
					yield false;
				}
				default -> false;
			};
		}

		/**
		 * The builtin types that stored properties use (actors' {@code $defaultActor}, standard
		 * library internals), as {@code Builtin.<Name>} nominal types; others are not supported.
		 */
		private boolean builtin() {
			if (pos >= text.length()) {
				return false;
			}
			String name = switch (text.charAt(pos++)) {
				case 'D' -> "DefaultActorStorage";
				case 'd' -> "NonDefaultDistributedActorStorage";
				case 'o' -> "NativeObject";
				case 'O' -> "UnknownObject";
				case 'b' -> "BridgeObject";
				case 'p' -> "RawPointer";
				case 'w' -> "Word";
				case 'B' -> "UnsafeValueBuffer";
				case 'i' -> {
					int end = text.indexOf('_', pos);
					if (end <= pos ||
						!text.substring(pos, end).chars().allMatch(Character::isDigit)) {
						yield null;
					}
					String bits = text.substring(pos, end);
					pos = end + 1;
					yield "Int" + bits;
				}
				default -> null;
			};
			if (name == null) {
				return false;
			}
			stack.push(new Nominal("Builtin." + name, 'V', null, false));
			return true;
		}

		/** {@code $ n? INDEX}: INDEX is {@code _} for 0, {@code <N>_} for N + 1; {@code n} negates. */
		private boolean integerValue() {
			boolean negative = pos < text.length() && text.charAt(pos) == 'n';
			if (negative) {
				pos++;
			}
			int start = pos;
			while (pos < text.length() && Character.isDigit(text.charAt(pos))) {
				pos++;
			}
			if (pos >= text.length() || text.charAt(pos) != '_') {
				return false;
			}
			long value = pos == start ? 0 : Long.parseLong(text.substring(start, pos)) + 1;
			pos++;
			stack.push(new IntegerValue(negative ? -value : value));
			return true;
		}

		private boolean ownership(String ownership) {
			stack.push(new Ownership(ownership, popType()));
			return true;
		}

		private boolean annotation() {
			if (pos >= text.length()) {
				return false;
			}
			switch (text.charAt(pos++)) {
				case 'a' -> stack.push(Marker.ASYNC);
				case 'b' -> stack.push(Marker.SENDABLE);
				case 'A' -> stack.push(Marker.ISOLATED_ANY);
				case 'C' -> stack.push(Marker.NONSENDING);
				case 'T' -> stack.push(Marker.SENDING_RESULT);
				case 'c' -> stack.push(new GlobalActor(popType()));
				case 'K' -> stack.push(new TypedThrows(popType()));
				default -> {
					return false;
				}
			}
			return true;
		}

		private SwiftTypeName popType() {
			if (stack.poll() instanceof SwiftTypeName t) {
				return t;
			}
			throw new IllegalStateException("type expected");
		}
	}
}
