// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Writes the layouts of a Mach-O image's Swift types as the Swift runtime sees them, in the
// format of ghidra_scripts/DumpSwiftTypes.java, as a reference for the Swift Data Types analyzer
// on binaries without a fixture (devtools/runtime-layouts.sh builds and runs it).
//
// Built as a dylib and loaded with DYLD_INSERT_LIBRARIES; its constructor does the work and
// exits, so the host program never runs. Environment:
//   RUNTIME_LAYOUTS_OUT    output file (required)
//   RUNTIME_LAYOUTS_LOAD   a dylib to dlopen first (to examine a dylib; any host will do)
//   RUNTIME_LAYOUTS_IMAGE  path suffix of the image to examine (default: the main executable)
//   RUNTIME_LAYOUTS_TRACE  if set, each descriptor's address (relative to the image) and
//                          mangled name go to stderr before it is examined (to find a crash)
//
// For each entry of __swift5_types that is not generic, it calls the type's metadata accessor
// (the runtime builds the metadata if it is not static) and writes
//   STRUCT/ENUM  name  size  stride  align      from the value witness table
//   CLASS        name  size  align  superclass  class_getInstanceSize, the metadata's alignment
//                                               mask, the superclass's name
//   FIELD        offset  size  name  Swift type the runtime's reflection, as _forEachField (classes:
//                                               own fields only)
//   SKIP         name  reason                   generic types (no accessor call), foreign
//                                               classes (CFString)
// No CASE lines: enum case names come only from the field descriptors, which the analyzer
// reads itself. Names, also in field types, are String(reflecting:) with "(unknown context at
// $…)." removed, as the analyzer names them; names that collide keep those parts, with the
// static addresses (DUPLICATE lines list them).
// Shares nothing with the analyzer but the format.

import Foundation
import MachO
import ObjectiveC

@_silgen_name("runtime_layouts_call_accessor")
func callAccessor(_ accessor: UnsafeRawPointer) -> UnsafeRawPointer

// The runtime functions behind the stdlib's _forEachField (ReflectionMirror.swift), which is SPI
// and not in the SDK's interface.
@_silgen_name("swift_reflectionMirror_recursiveCount")
func recursiveChildCount(_: Any.Type) -> Int

@_silgen_name("swift_reflectionMirror_recursiveChildOffset")
func childOffset(_: Any.Type, index: Int) -> Int

/// SwiftShims/Reflection.h
struct FieldReflectionMetadata {
	var name: UnsafePointer<CChar>? = nil
	var freeFunc: (@convention(c) (UnsafePointer<CChar>?) -> Void)? = nil
	var isStrong = false
	var isVar = false
}

@_silgen_name("swift_reflectionMirror_recursiveChildMetadata")
func childMetadata(_: Any.Type, index: Int, fieldMetadata: UnsafeMutablePointer<FieldReflectionMetadata>) -> Any.Type

/// Size, stride, alignment from the type's value witness table, which the runtime filled in
/// (metadata - 8; size at +64, stride at +72, flags at +80 with the alignment mask in the low
/// byte). MemoryLayout<T> reads the same table, but needs T statically.
func layout(_ type: Any.Type) -> (size: Int, stride: Int, align: Int) {
	let metadata = unsafeBitCast(type, to: UnsafeRawPointer.self)
	let witnesses = (metadata - 8).load(as: UnsafeRawPointer.self)
	let flags = (witnesses + 80).load(as: UInt32.self)
	return ((witnesses + 64).load(as: Int.self), (witnesses + 72).load(as: Int.self), Int(flags & 0xff) + 1)
}

func readableName(_ type: Any.Type) -> String {
	var name = String(reflecting: type)
	// Private and local types: "M.(unknown context at $1076e1ee4).Shape" -> "M.Shape", in type
	// names and in the generic arguments of field types.
	while let start = name.range(of: "(unknown context at $") {
		guard let end = name[start.upperBound...].range(of: ").") else { break }
		name.removeSubrange(start.lowerBound..<end.upperBound)
	}
	return name
}

/// String(reflecting:) with the addresses of "(unknown context at $…)" made static (minus the
/// ASLR slide), as the analyzer names types whose plain names collide.
func unslidName(_ type: Any.Type, slide: Int) -> String {
	var name = String(reflecting: type)
	var from = name.startIndex
	while let start = name.range(of: "(unknown context at $", range: from..<name.endIndex),
	      let end = name[start.upperBound...].firstIndex(of: ")"),
	      let address = Int(name[start.upperBound..<end], radix: 16) {
		let hex = String(address - slide, radix: 16)
		name.replaceSubrange(start.upperBound..<end, with: hex)
		from = name.index(start.upperBound, offsetBy: hex.count)
	}
	return name
}

/// The target of a relative pointer at `at`: signed 32-bit, relative to its own address.
func relative(_ at: UnsafeRawPointer) -> UnsafeRawPointer? {
	let offset = at.loadUnaligned(as: Int32.self)
	return offset == 0 ? nil : at + Int(offset)
}

/// The image to examine and its path: the main executable (MH_EXECUTE; inserted libraries can
/// come before it in dyld's list) or the one whose path ends with RUNTIME_LAYOUTS_IMAGE.
func findImage() -> (UnsafePointer<mach_header_64>, String, Int)? {
	let suffix = getenv("RUNTIME_LAYOUTS_IMAGE").map { String(cString: $0) }
	for i in 0..<_dyld_image_count() {
		guard let name = _dyld_get_image_name(i).map({ String(cString: $0) }),
		      let header = _dyld_get_image_header(i) else { continue }
		if suffix.map(name.hasSuffix) ?? (header.pointee.filetype == UInt32(MH_EXECUTE)) {
			return (UnsafeRawPointer(header).assumingMemoryBound(to: mach_header_64.self), name,
				_dyld_get_image_vmaddr_slide(i))
		}
	}
	return nil
}

@_cdecl("runtime_layouts_main")
func runtimeLayoutsMain() {
	guard let outPath = getenv("RUNTIME_LAYOUTS_OUT").map({ String(cString: $0) }) else { return }
	unsetenv("DYLD_INSERT_LIBRARIES")
	if let load = getenv("RUNTIME_LAYOUTS_LOAD"), dlopen(load, RTLD_NOW) == nil {
		fputs("RuntimeLayouts: \(String(cString: dlerror()))\n", stderr)
		exit(2)
	}
	guard let (header, imageName, slide) = findImage() else {
		fputs("RuntimeLayouts: image not found\n", stderr)
		exit(2)
	}
	var size: UInt = 0
	guard let section = getsectiondata(header, "__TEXT", "__swift5_types", &size) else {
		fputs("RuntimeLayouts: no __swift5_types\n", stderr)
		exit(2)
	}
	let trace = getenv("RUNTIME_LAYOUTS_TRACE") != nil
	var lines: [String: [String]] = [:]
	var seen = Set<UnsafeRawPointer>()
	var counts = [String: Int]()
	var duplicates = [String]()
	// Types by readable name; the names that collide are replaced by their full names below.
	var full: [String: [(name: String, out: [String])]] = [:]
	for entry in stride(from: 0, to: Int(size), by: 4) {
		let at = UnsafeRawPointer(section) + entry
		let raw = at.loadUnaligned(as: Int32.self)
		var descriptor = at + Int(raw & ~3)
		if raw & 3 == 1 {
			descriptor = descriptor.load(as: UnsafeRawPointer.self)
		}
		guard seen.insert(descriptor).inserted else { continue }
		// ContextDescriptorFlags: kind in bits 0-4, generic 0x80, TypeContextDescriptorFlags in
		// bits 16-31. lzghidraswift.metadata.ContextDescriptor reads the same bits in the analyzers.
		let flags = descriptor.load(as: UInt32.self)
		let kind = flags & 0x1f
		guard kind >= 16 && kind <= 18 else { continue }
		let mangledName = relative(descriptor + 8).map { String(cString: $0.assumingMemoryBound(to: CChar.self)) } ?? "?"
		if trace {
			fputs("\(String(descriptor - UnsafeRawPointer(header), radix: 16)) \(mangledName)\n", stderr)
		}
		if flags & 0x80 != 0 {
			lines["\0" + mangledName, default: []].append("SKIP\t\(mangledName)\tgeneric")
			counts["generic", default: 0] += 1
			continue
		}
		// Foreign classes (imported Core Foundation types such as CFString) have no Swift or
		// Objective-C class layout; TypeContextDescriptorFlags (flags bits 16-17) == 2.
		if kind == 16 && (flags >> 16) & 3 == 2 {
			lines["\0" + mangledName, default: []].append("SKIP\t\(mangledName)\tforeign class")
			counts["foreign class", default: 0] += 1
			continue
		}
		guard let accessor = relative(descriptor + 12) else {
			counts["no accessor", default: 0] += 1
			continue
		}
		let type = unsafeBitCast(callAccessor(accessor), to: Any.Type.self)
		let name = readableName(type)
		var out: [String] = []
		var inherited = 0
		switch kind {
		case 16:
			let cls: AnyClass = type as! AnyClass
			let metadata = unsafeBitCast(type, to: UnsafeRawPointer.self)
			// Class metadata (ABI/Metadata.h): word 6 holds the instance size (uint32) and the
			// instance alignment mask (uint16).
			let alignMask = Int((metadata + 48 + 4).load(as: UInt16.self))
			let superclass: String
			if let s = class_getSuperclass(cls) {
				let sName = String(cString: class_getName(s))
				// Swift classes have a mangled Objective-C name; name those as Swift does.
				superclass = sName.hasPrefix("_Tt") && sName != "_TtCs12_SwiftObject" ? readableName(s) : sName
				if sName != "_TtCs12_SwiftObject" {
					inherited = recursiveChildCount(s)
				}
			} else {
				superclass = "none"
			}
			let instanceSize = class_getInstanceSize(cls)
			out.append("CLASS\t\(name)\t\(instanceSize)\t\(alignMask + 1)\t\(superclass)")
		default:
			let l = layout(type)
			out.append("\(kind == 17 ? "STRUCT" : "ENUM")\t\(name)\t\(l.size)\t\(l.stride)\t\(l.align)")
		}
		counts[kind == 16 ? "classes" : kind == 17 ? "structs" : "enums", default: 0] += 1
		if kind != 18 {
			for index in inherited..<recursiveChildCount(type) {
				var field = FieldReflectionMetadata()
				let fieldType = childMetadata(type, index: index, fieldMetadata: &field)
				let fieldName = field.name.map { String(cString: $0) } ?? ""
				field.freeFunc?(field.name)
				let l = layout(fieldType)
				out.append("FIELD\t\(childOffset(type, index: index))\t\(l.size)\t\(fieldName)\t\(readableName(fieldType))")
			}
		}
		full[name, default: []].append((unslidName(type, slide: slide), out))
	}
	for (name, entries) in full {
		if entries.count == 1 {
			lines[name] = entries[0].out
			continue
		}
		duplicates.append(name)
		for entry in entries {
			var out = entry.out
			var head = out[0].split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
			head[1] = entry.name
			out[0] = head.joined(separator: "\t")
			lines[entry.name] = out
		}
	}
	var text = "# RuntimeLayouts, \(imageName)\n"
	for name in lines.keys.sorted() {
		text += lines[name]!.joined(separator: "\n") + "\n"
	}
	for name in duplicates {
		text += "# DUPLICATE\t\(name)\n"
	}
	text += "# counts: " + counts.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: ", ") + "\n"
	guard let file = fopen(outPath, "w") else { exit(2) }
	fputs(text, file)
	fclose(file)
	exit(0)
}
