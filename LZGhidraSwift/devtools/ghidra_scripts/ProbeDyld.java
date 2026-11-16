// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Ghidra's view of an image extracted from the dyld shared cache, after
// auto-analysis. Argument: the image's file name (the source name of its memory blocks). Prints:
// HDR and SECT, the Mach-O header in the image's __TEXT and its section sizes against the blocks;
// PTR, the 8-byte words of the data sections, by where they point (image, libobjc, the name of an
// added cache block, none) and whether bits 48-63 are set; SYMREF, the symbolic references in
// __swift5_typeref, for 0x02 (indirect) also where the slot is and where its value points;
// PARENT, the parent pointers of the descriptors in __swift5_types; CALL, the targets of the call
// instructions in __text; ARM64E, the pointer authentication instructions with the p-code of one of
// each; DECOMP and WARN, the decompiler on the functions of __text.
//@category Swift
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class ProbeDyld extends GhidraScript {
	private static final String PAC =
		"(pac|aut|xpac|retaa|retab|braa|brab|blraa|blrab|eretaa|ldraa|ldrab).*";

	private Memory memory;
	private String image;
	private long textStart;
	private long textEnd;

	@Override
	protected void run() throws Exception {
		image = getScriptArgs()[0];
		memory = currentProgram.getMemory();
		header();
		pointers();
		symbolicReferences();
		parents();
		calls();
		arm64e();
	}

	private MemoryBlock imageBlock(String name) {
		for (MemoryBlock b : memory.getBlocks()) {
			if (b.getName().equals(name) && image.equals(b.getSourceName())) {
				return b;
			}
		}
		return null;
	}

	/** Where a 64-bit value points; bits 48-63 are ignored. */
	private String where(long value) {
		Address a;
		try {
			a = toAddr(value & 0xffff_ffff_ffffL);
		}
		catch (Exception e) {
			return "bad";
		}
		MemoryBlock b = memory.getBlock(a);
		if (b == null) {
			return "none";
		}
		if (image.equals(b.getSourceName())) {
			return "image";
		}
		if (b.getSourceName().startsWith("libobjc")) {
			return "libobjc";
		}
		return b.getName().replaceAll("\\..*", "");
	}

	private static String name(Symbol s) {
		return s == null ? "-" : s.getName(true);
	}

	private void header() throws Exception {
		Address h = imageBlock("__TEXT").getStart();
		println(String.format("HDR imagebase=%s __TEXT=%s magic=%08x",
			currentProgram.getImageBase(), h, memory.getInt(h)));
		int ncmds = memory.getInt(h.add(16));
		Address cmd = h.add(32);
		for (int i = 0; i < ncmds; i++) {
			if (memory.getInt(cmd) == 0x19) {
				byte[] segname = new byte[16];
				memory.getBytes(cmd.add(8), segname);
				if (new String(segname).startsWith("__TEXT\0")) {
					textStart = memory.getLong(cmd.add(24));
					textEnd = textStart + memory.getLong(cmd.add(32));
				}
				int nsects = memory.getInt(cmd.add(64));
				for (int s = 0; s < nsects; s++) {
					Address sec = cmd.add(72 + 80L * s);
					byte[] sectname = new byte[16];
					memory.getBytes(sec, sectname);
					long addr = memory.getLong(sec.add(32));
					MemoryBlock b = memory.getBlock(toAddr(addr));
					println(String.format("SECT %-18s %x %7d block=%s %d",
						new String(sectname).replace("\0", ""), addr, memory.getLong(sec.add(40)),
						b == null ? "-" : b.getName(), b == null ? 0 : b.getSize()));
				}
			}
			cmd = cmd.add(memory.getInt(cmd.add(4)));
		}
	}

	private void pointers() throws Exception {
		for (MemoryBlock b : memory.getBlocks()) {
			long start = b.getStart().getOffset();
			if (!image.equals(b.getSourceName()) || !b.isInitialized() ||
				b.getStart().getAddressSpace().isOverlaySpace() ||
				b.getName().equals("__LINKEDIT") ||
				(start >= textStart && start < textEnd)) {
				continue;
			}
			Map<String, Integer> targets = new TreeMap<>();
			int high = 0;
			int refs = 0;
			int named = 0;
			List<String> samples = new ArrayList<>();
			for (Address a = b.getStart(); a.add(7).compareTo(b.getEnd()) <= 0; a = a.add(8)) {
				long v = memory.getLong(a);
				if (v == 0) {
					targets.merge("zero", 1, Integer::sum);
					continue;
				}
				high += (v >>> 48) != 0 ? 1 : 0;
				String w = where(v);
				targets.merge(w, 1, Integer::sum);
				refs += currentProgram.getReferenceManager().getReferencesFrom(a).length;
				Symbol s = w.equals("bad") ? null : getSymbolAt(toAddr(v & 0xffff_ffff_ffffL));
				named += s != null ? 1 : 0;
				if (samples.size() < 3 && !w.equals("image")) {
					samples.add(String.format("%s=%x(%s,%s)", a, v, w, name(s)));
				}
			}
			println(String.format("PTR %-16s %s words=%d high16=%d targets=%s refs=%d named=%d %s",
				b.getName(), b.getStart(), b.getSize() / 8, high, targets, refs, named, samples));
		}
	}

	private void symbolicReferences() throws Exception {
		MemoryBlock typeref = imageBlock("__swift5_typeref");
		Map<String, Integer> kinds = new TreeMap<>();
		List<String> samples = new ArrayList<>();
		Address a = typeref.getStart();
		while (a.compareTo(typeref.getEnd()) < 0) {
			int k = memory.getByte(a) & 0xff;
			if (k >= 0x18 && k <= 0x1f) {
				kinds.merge(String.format("%02x absolute", k), 1, Integer::sum);
				a = a.add(9);
				continue;
			}
			if (k < 1 || k > 0x17) {
				a = a.add(1);
				continue;
			}
			Address t = a.add(1).add(memory.getInt(a.add(1)));
			if (k == 2 && memory.contains(t)) {
				long v = memory.getLong(t);
				Reference[] refs = currentProgram.getReferenceManager().getReferencesFrom(t);
				kinds.merge(
					String.format("02 slot=%s value=%s refs=%d slotSym=%b", where(t.getOffset()),
						where(v), refs.length, getSymbolAt(t) != null),
					1, Integer::sum);
				if (samples.size() < 5) {
					samples.add(String.format("%s slot %s=%x slotSym=%s valueSym=%s", a, t, v,
						name(getSymbolAt(t)), where(v).equals("bad") ? "-"
								: name(getSymbolAt(toAddr(v & 0xffff_ffff_ffffL)))));
				}
			}
			else {
				kinds.merge(String.format("%02x target=%s", k, where(t.getOffset())), 1,
					Integer::sum);
			}
			a = a.add(5);
		}
		kinds.forEach((k, n) -> println("SYMREF " + k + ": " + n));
		samples.forEach(s -> println("SYMREF-SAMPLE " + s));
	}

	private void parents() throws Exception {
		MemoryBlock types = imageBlock("__swift5_types");
		Map<String, Integer> kinds = new TreeMap<>();
		for (Address a = types.getStart(); a.add(3).compareTo(types.getEnd()) <= 0; a = a.add(4)) {
			int rel = memory.getInt(a);
			Address d = a.add(rel & ~3);
			if (rel == 0 || !where(d.getOffset()).equals("image")) {
				kinds.merge(rel == 0 ? "entry 0" : "descriptor " + where(d.getOffset()), 1,
					Integer::sum);
				continue;
			}
			int parent = memory.getInt(d.add(4));
			Address p = d.add(4).add(parent & ~1);
			if ((parent & 1) != 0) {
				kinds.merge("indirect slot=" + where(p.getOffset()) + " value=" +
					(memory.contains(p) ? where(memory.getLong(p)) : "-"), 1, Integer::sum);
			}
			else {
				kinds.merge("direct " + where(p.getOffset()), 1, Integer::sum);
			}
		}
		kinds.forEach((k, n) -> println("PARENT " + k + ": " + n));
	}

	private void calls() {
		MemoryBlock text = imageBlock("__text");
		Map<String, Integer> kinds = new TreeMap<>();
		List<String> samples = new ArrayList<>();
		InstructionIterator it = currentProgram.getListing().getInstructions(text.getStart(), true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			if (ins.getAddress().compareTo(text.getEnd()) > 0) {
				break;
			}
			if (!ins.getFlowType().isCall()) {
				continue;
			}
			Address[] flows = ins.getFlows();
			if (flows.length == 0) {
				kinds.merge("indirect " + ins.getMnemonicString(), 1, Integer::sum);
				continue;
			}
			String w = where(flows[0].getOffset());
			Symbol s = getSymbolAt(flows[0]);
			Function f = getFunctionAt(flows[0]);
			String how = s == null ? "no symbol"
					: s.getSource() == SourceType.DEFAULT ? "default name" : "named";
			if (f != null && f.isThunk()) {
				how += ", thunk of " +
					(f.getThunkedFunction(true).isExternal() ? "external" : "memory");
			}
			kinds.merge(w + ", " + how, 1, Integer::sum);
			if (!w.equals("image") && samples.size() < 3) {
				samples.add(ins.getAddress() + " " + ins + " -> " + name(s) +
					(f != null && f.isThunk()
							? " thunk of " + name(f.getThunkedFunction(true).getSymbol())
							: ""));
			}
		}
		kinds.forEach((k, n) -> println("CALL " + k + ": " + n));
		samples.forEach(s -> println("CALL-SAMPLE " + s));
	}

	private void arm64e() throws Exception {
		MemoryBlock text = imageBlock("__text");
		Map<String, Integer> count = new TreeMap<>();
		Map<String, String> pcode = new TreeMap<>();
		Set<Function> functions = new LinkedHashSet<>();
		InstructionIterator it = currentProgram.getListing().getInstructions(text.getStart(), true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			if (ins.getAddress().compareTo(text.getEnd()) > 0) {
				break;
			}
			String m = ins.getMnemonicString().toLowerCase();
			if (!m.matches(PAC)) {
				continue;
			}
			count.merge(m, 1, Integer::sum);
			if (!pcode.containsKey(m)) {
				StringBuilder sb = new StringBuilder();
				for (PcodeOp op : ins.getPcode()) {
					sb.append(op).append("; ");
				}
				pcode.put(m, ins.getAddress() + " " + ins + " => " + sb);
			}
			Function f = getFunctionContaining(ins.getAddress());
			if (f != null) {
				functions.add(f);
			}
		}
		println("ARM64E functions with them: " + functions.size());
		count.forEach((k, n) -> println("ARM64E " + k + ": " + n));
		pcode.values().forEach(s -> println("PCODE " + s));
		decompile(text);
	}

	private void decompile(MemoryBlock text) {
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(currentProgram);
		Map<String, Integer> warnings = new TreeMap<>();
		int ok = 0;
		int failed = 0;
		int pac = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(text.getStart(), true)) {
			if (f.getEntryPoint().compareTo(text.getEnd()) > 0) {
				break;
			}
			DecompileResults r = decompiler.decompileFunction(f, 60, monitor);
			if (r == null || !r.decompileCompleted()) {
				failed++;
				continue;
			}
			ok++;
			String c = r.getDecompiledFunction().getC();
			pac += c.matches("(?s).*\\b(pac|aut|xpac)\\w*\\(.*") ? 1 : 0;
			for (String line : c.split("\n")) {
				int i = line.indexOf("WARNING: ");
				if (i >= 0) {
					warnings.merge(line.substring(i + 9)
							.replaceAll("\\*/.*", "")
							.replaceAll("0x[0-9a-f]+|[0-9a-f]{8,}", "#")
							.trim(),
						1, Integer::sum);
				}
			}
		}
		decompiler.dispose();
		println("DECOMP ok=" + ok + " failed=" + failed + " with pac/aut calls=" + pac);
		warnings.forEach((k, n) -> println("WARN " + n + " " + k));
	}
}
