// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

package lzghidraswift.throwing;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.framework.store.LockException;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.XmlEncode;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlParseException;
import lzghidraswift.abi.CallingConventions;

/**
 * Calling conventions for throwing Swift functions. A throwing function returns its error in
 * x21 (r12 on x86_64), which Ghidra's Swift conventions list as unaffected: the decompiler then
 * takes the register after a call as the caller's 0 from before it, and removes the catch path.
 * For each Swift convention of the program this class adds a variant, named with
 * {@link CallingConventions#VARIANT_SUFFIX}, in which a call kills the error register. The
 * variant is the program's own convention, encoded as XML, with that one register moved from
 * {@code <unaffected>} to {@code <killedbycall>}, and is installed as a specification extension
 * of the program.
 * <p>
 * The variant also kills the result registers of the convention's {@code <output>} (x0 to x3
 * and d0 to d3; RAX, RDX, RCX, R8 and XMM0 to XMM3 on x86_64). Ghidra's Swift conventions list
 * them neither as killed nor as unaffected (x86_64 kills RAX, RDX and XMM0), so the decompiler
 * takes those that the return type does not use as the caller's values from before the call. A
 * typed throw returns its error in the integer ones, also when the function returns
 * {@code Void} or a {@code Double}, and an untyped throw leaves them undefined (Swift's
 * {@code combineResultAndTypedErrorType}, {@code IRGenSIL.cpp} {@code visitThrowInst}). The
 * call-site override of a closure ({@link ThrowingCallOverride}) returns an integer, so a
 * {@code Double} result in d0 showed as the caller's d0 from before the call. Ghidra's own
 * AArch64 conventions kill x0, x1 and q0 too.
 * <p>
 * For the call-site overrides of indirect calls ({@link ThrowingCallOverride}) each variant has a
 * second one, named with {@link #INDIRECT} before the suffix, in which the indirect result
 * register (x8, RAX) is an ordinary first integer parameter instead of the {@code hiddenret}
 * entry. The decompiler uses a {@code hiddenret} entry only for a return type larger than the
 * result registers, which an override of a closure cannot know; as a parameter, the buffer shows
 * as the call's first argument.
 */
public final class ThrowingConventions {

	/**
	 * Before {@link CallingConventions#VARIANT_SUFFIX} in the name of a variant with an indirect
	 * result parameter.
	 */
	public static final String INDIRECT = "_indirect";

	private static final String PROTOTYPE = "prototype";
	private static final String UNAFFECTED = "unaffected";
	private static final String KILLED_BY_CALL = "killedbycall";
	private static final String RETURN_ADDRESS = "returnaddress";
	private static final String INPUT = "input";
	private static final String OUTPUT = "output";
	private static final String STORAGE = "storage";
	private static final String HIDDEN_RETURN = "hiddenret";
	private static final String PENTRY = "pentry";
	private static final String REGISTER = "register";
	private static final String VARNODE = "varnode";
	private static final String NAME = "name";
	private static final String SPACE = "space";
	private static final String OFFSET = "offset";
	private static final String SIZE = "size";
	private static final String FLOAT = "float";

	private ThrowingConventions() {
	}

	/**
	 * A register as the XML of a prototype names it: by name (the cspec form), or by space,
	 * offset and size (Ghidra's encoding). A register from the XML has only the one or the other:
	 * a null name, or a null space.
	 */
	record XmlRegister(String name, String space, long offset, int size) {

		static XmlRegister of(Register r) {
			return new XmlRegister(r.getName(), r.getAddress().getAddressSpace().getName(),
				r.getAddress().getOffset(), r.getMinimumByteSize());
		}

		/**
		 * The register of {@code location}, the {@code <register>}, {@code <addr>} or
		 * {@code <varnode>} of a {@code <pentry>} whose size is {@code entrySize}; null for
		 * another element.
		 */
		static XmlRegister ofLocation(Element location, int entrySize) {
			if (location.getTagName().equals(REGISTER)) {
				return new XmlRegister(location.getAttribute(NAME), null, 0, 0);
			}
			if (!location.hasAttribute(SPACE) || !location.hasAttribute(OFFSET)) {
				return null;
			}
			int size = location.hasAttribute(SIZE) ? (int) parseNumber(location.getAttribute(SIZE))
					: entrySize;
			return new XmlRegister(null, location.getAttribute(SPACE),
				parseNumber(location.getAttribute(OFFSET)), size);
		}

		/** Whether {@code e}, a child of {@code <unaffected>} or {@code <killedbycall>}, overlaps this register. */
		boolean matches(Element e) {
			if (e.getTagName().equals(REGISTER)) {
				return name != null && e.getAttribute(NAME).equalsIgnoreCase(name);
			}
			if (space == null || !e.getAttribute(SPACE).equals(space) || !e.hasAttribute(OFFSET)) {
				return false;
			}
			long start = parseNumber(e.getAttribute(OFFSET));
			int length = e.hasAttribute(SIZE) ? (int) parseNumber(e.getAttribute(SIZE)) : 1;
			return start < offset + size && offset < start + length;
		}

		/** This register as a child of {@code <killedbycall>}: by name if it has one. */
		Element toElement(Document doc) {
			if (name != null) {
				Element reg = doc.createElement(REGISTER);
				reg.setAttribute(NAME, name);
				return reg;
			}
			Element varnode = doc.createElement(VARNODE);
			varnode.setAttribute(SPACE, space);
			varnode.setAttribute(OFFSET, "0x" + Long.toHexString(offset));
			varnode.setAttribute(SIZE, Integer.toString(size));
			return varnode;
		}
	}

	/** What {@link #install} did, by convention name. */
	public static final class Result {
		/** Variants installed by this run. */
		public final List<String> added = new ArrayList<>();
		/** Variants the program already had. */
		public final List<String> present = new ArrayList<>();
		/** Swift conventions without the error register in their unaffected list. */
		public final List<String> skipped = new ArrayList<>();
		/** Variants that could not be built or installed, with the reason. */
		public final List<String> failed = new ArrayList<>();

		/** One line for the analysis log. */
		public String summary() {
			return "throwing conventions: " + String.join(", ", part(added, "added"),
				part(present, "present"), part(skipped, "skipped"), part(failed, "failed"));
		}

		private static String part(List<String> names, String what) {
			return "%d %s %s".formatted(names.size(), what, names);
		}
	}

	/** The name of the throwing variant of {@code convention}. */
	public static String variantName(String convention) {
		return convention + CallingConventions.VARIANT_SUFFIX;
	}

	/** The name of the throwing variant of {@code convention} with an indirect result parameter. */
	public static String indirectVariantName(String convention) {
		return convention + INDIRECT + CallingConventions.VARIANT_SUFFIX;
	}

	/**
	 * The throwing variant for an indirect call: of the Swift convention with a {@code this}
	 * parameter (x20, r13; {@code __swift_thiscall}) if the caller sets the self register, else of the
	 * one without ({@link CallingConventions#swiftConvention}); the one with an indirect result
	 * parameter if the caller sets that register. Null if the compiler spec has no such variant.
	 */
	public static String callVariant(CompilerSpec spec, boolean context, boolean indirectResult) {
		String base = CallingConventions.swiftConvention(spec, context);
		if (base == null) {
			return null;
		}
		String name = indirectResult ? indirectVariantName(base) : variantName(base);
		return spec.getCallingConvention(name) != null ? name : null;
	}

	/**
	 * The throwing variant for a function whose calling convention is {@code convention}:
	 * {@code convention} itself if it is a variant already; for {@code unknown} and
	 * {@code default}, the variant of the Swift convention without a {@code this} parameter
	 * ({@link CallingConventions#swiftConvention}); else the variant of {@code convention}. Null if
	 * the compiler spec has no such variant, as for a convention that is not Swift's.
	 */
	public static String variantFor(CompilerSpec spec, String convention) {
		String name = convention;
		if (name == null || name.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING) ||
			name.equals(Function.DEFAULT_CALLING_CONVENTION_STRING)) {
			name = CallingConventions.swiftConvention(spec, false);
			if (name == null) {
				return null;
			}
		}
		String variant =
			name.endsWith(CallingConventions.VARIANT_SUFFIX) ? name : variantName(name);
		return spec.getCallingConvention(variant) != null ? variant : null;
	}

	/**
	 * Adds the throwing variants of each Swift convention of the program (also the one with an
	 * indirect result parameter), unless the program has them already. Needs a transaction and exclusive access to the program. Installing an
	 * extension reloads the program's compiler spec.
	 */
	public static Result install(Program program, TaskMonitor monitor) {
		Result result = new Result();
		Register register = CallingConventions.errorRegister(program);
		if (register == null) {
			return result;
		}
		XmlRegister error = XmlRegister.of(register);
		CompilerSpec spec = program.getCompilerSpec();
		Map<String, String> variants = new LinkedHashMap<>();
		for (PrototypeModel model : spec.getCallingConventions()) {
			if (!model.isMerged() && CallingConventions.isSwiftConvention(model.getName())) {
				addVariants(model, spec, error, result, variants);
			}
		}
		SpecExtension extension = new SpecExtension(program);
		for (Map.Entry<String, String> v : variants.entrySet()) {
			try {
				extension.addReplaceCompilerSpecExtension(v.getValue(), monitor);
				result.added.add(v.getKey());
			}
			catch (LockException | SleighException | SAXException | XmlParseException e) {
				result.failed.add(v.getKey() + ": " + e.getMessage());
			}
		}
		return result;
	}

	/**
	 * Puts the XML of the variants of {@code model} that the compiler spec lacks into
	 * {@code variants}, by name; records the present ones and the failures in {@code result}.
	 */
	private static void addVariants(PrototypeModel model, CompilerSpec spec, XmlRegister error,
			Result result, Map<String, String> variants) {
		String name = variantName(model.getName());
		String indirect = indirectVariantName(model.getName());
		boolean hasVariant = spec.getCallingConvention(name) != null;
		boolean hasIndirect = spec.getCallingConvention(indirect) != null;
		if (hasVariant) {
			result.present.add(name);
		}
		if (hasIndirect) {
			result.present.add(indirect);
		}
		if (hasVariant && hasIndirect) {
			return;
		}
		try {
			String xml = variantXml(encode(model, spec), name, error);
			if (xml == null) {
				result.skipped.add(model.getName());
				return;
			}
			if (!hasVariant) {
				variants.put(name, xml);
			}
			String indirectXml = hasIndirect ? null : indirectVariantXml(xml, indirect);
			if (indirectXml != null) {
				variants.put(indirect, indirectXml);
			}
		}
		catch (IOException | SAXException e) {
			result.failed.add(name + ": " + e.getMessage());
		}
	}

	/** The model as the XML of a {@code <prototype>} element, as Ghidra writes it. */
	private static String encode(PrototypeModel model, CompilerSpec spec) throws IOException {
		XmlEncode encoder = new XmlEncode(false);
		model.encode(encoder, spec.getPcodeInjectLibrary());
		return encoder.toString();
	}

	/**
	 * The {@code <prototype>} in {@code xml} renamed to {@code name}, with {@code error} moved
	 * from {@code <unaffected>} to {@code <killedbycall>}, and the result registers added to
	 * {@code <killedbycall>}. Null if {@code xml} is not a prototype (a
	 * {@code <modelalias>}) or does not list the register as unaffected.
	 */
	static String variantXml(String xml, String name, XmlRegister error) throws SAXException {
		Document doc = parse(xml);
		Element root = doc.getDocumentElement();
		if (!root.getTagName().equals(PROTOTYPE)) {
			return null;
		}
		Element unaffected = child(root, UNAFFECTED);
		if (unaffected == null || !removeMatching(unaffected, error)) {
			return null;
		}
		root.setAttribute(NAME, name);
		// Ghidra 12.2 (as 12.1.4) encodes a model without a return address, such as the AArch64
		// Swift conventions, as <returnaddress/>, which its schema rejects (one or more varnodes). Without the element, the extension gets the
		// same empty list (ProgramCompilerSpec, setDefaultReturnAddressIfNeeded).
		Element returnAddress = child(root, RETURN_ADDRESS);
		if (returnAddress != null && !returnAddress.hasChildNodes()) {
			root.removeChild(returnAddress);
		}
		Element killed = child(root, KILLED_BY_CALL);
		if (killed == null) {
			killed = doc.createElement(KILLED_BY_CALL);
			root.insertBefore(killed, unaffected.getNextSibling());
		}
		if (!hasMatching(killed, error)) {
			Element reg = doc.createElement(REGISTER);
			reg.setAttribute(NAME, error.name());
			killed.appendChild(reg);
		}
		for (XmlRegister result : resultRegisters(child(root, OUTPUT))) {
			if (!hasMatching(killed, result)) {
				killed.appendChild(result.toElement(doc));
			}
		}
		return serialize(doc);
	}

	/**
	 * The variant {@code variantXml} (from {@link #variantXml}) renamed to {@code name}, with the
	 * {@code hiddenret} entry of its {@code <input>} made an ordinary entry and moved before the
	 * first integer entry: Ghidra wants the entries of one storage class together, and the
	 * floating-point entries come first. Null if there is no {@code hiddenret} entry or no integer
	 * entry.
	 */
	static String indirectVariantXml(String variantXml, String name) throws SAXException {
		Document doc = parse(variantXml);
		Element root = doc.getDocumentElement();
		Element input = child(root, INPUT);
		if (input == null) {
			return null;
		}
		Element hidden = null;
		Element firstInteger = null;
		for (Node n = input.getFirstChild(); n != null; n = n.getNextSibling()) {
			if (!(n instanceof Element entry) || !entry.getTagName().equals(PENTRY)) {
				continue;
			}
			if (HIDDEN_RETURN.equals(entry.getAttribute(STORAGE))) {
				if (hidden == null) {
					hidden = entry;
				}
			}
			else if (firstInteger == null && !isFloat(entry)) {
				firstInteger = entry;
			}
		}
		if (hidden == null || firstInteger == null) {
			return null;
		}
		root.setAttribute(NAME, name);
		hidden.removeAttribute(STORAGE);
		input.removeChild(hidden);
		input.insertBefore(hidden, firstInteger);
		return serialize(doc);
	}

	/** A {@code <pentry>} for floating-point values, in cspec or encoded form. */
	private static boolean isFloat(Element entry) {
		return FLOAT.equals(entry.getAttribute("metatype")) ||
			FLOAT.equals(entry.getAttribute(STORAGE));
	}

	/** The registers of the {@code <pentry>} elements of {@code output}. */
	private static List<XmlRegister> resultRegisters(Element output) {
		List<XmlRegister> registers = new ArrayList<>();
		if (output == null) {
			return registers;
		}
		for (Node n = output.getFirstChild(); n != null; n = n.getNextSibling()) {
			if (!(n instanceof Element entry) || !entry.getTagName().equals(PENTRY)) {
				continue;
			}
			Element location = firstElement(entry);
			int entrySize = entry.hasAttribute("maxsize")
					? (int) parseNumber(entry.getAttribute("maxsize"))
					: 1;
			XmlRegister r = location == null ? null
					: XmlRegister.ofLocation(location, entrySize);
			if (r != null && (r.name() != null || REGISTER.equals(r.space()))) {
				registers.add(r);
			}
		}
		return registers;
	}

	private static Element firstElement(Element parent) {
		for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
			if (n instanceof Element e) {
				return e;
			}
		}
		return null;
	}

	private static Element child(Element parent, String tag) {
		for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
			if (n instanceof Element e && e.getTagName().equals(tag)) {
				return e;
			}
		}
		return null;
	}

	private static boolean hasMatching(Element list, XmlRegister register) {
		for (Node n = list.getFirstChild(); n != null; n = n.getNextSibling()) {
			if (n instanceof Element e && register.matches(e)) {
				return true;
			}
		}
		return false;
	}

	private static boolean removeMatching(Element list, XmlRegister register) {
		boolean removed = false;
		Node n = list.getFirstChild();
		while (n != null) {
			Node next = n.getNextSibling();
			if (n instanceof Element e && register.matches(e)) {
				list.removeChild(e);
				removed = true;
			}
			n = next;
		}
		return removed;
	}

	private static long parseNumber(String text) {
		String t = text.trim().toLowerCase(Locale.ROOT);
		if (t.startsWith("0x")) {
			return Long.parseUnsignedLong(t.substring(2), 16);
		}
		return Long.parseLong(t);
	}

	private static Document parse(String xml) throws SAXException {
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
			factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document doc = builder.parse(new InputSource(new StringReader(xml)));
			removeWhitespace(doc.getDocumentElement());
			return doc;
		}
		catch (ParserConfigurationException | IOException e) {
			throw new SAXException(e);
		}
	}

	/** Drops the whitespace between elements, so that the output is indented afresh. */
	private static void removeWhitespace(Element e) {
		Node n = e.getFirstChild();
		while (n != null) {
			Node next = n.getNextSibling();
			if (n.getNodeType() == Node.TEXT_NODE && n.getTextContent().isBlank()) {
				e.removeChild(n);
			}
			else if (n instanceof Element child) {
				removeWhitespace(child);
			}
			n = next;
		}
	}

	private static String serialize(Document doc) throws SAXException {
		try {
			TransformerFactory factory = TransformerFactory.newInstance();
			factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			Transformer t = factory.newTransformer();
			t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			t.setOutputProperty(OutputKeys.INDENT, "yes");
			t.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
			StringWriter out = new StringWriter();
			t.transform(new DOMSource(doc), new StreamResult(out));
			return out.toString().strip() + "\n";
		}
		catch (TransformerException e) {
			throw new SAXException(e);
		}
	}
}
