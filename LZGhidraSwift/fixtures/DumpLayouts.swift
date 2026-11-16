// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Prints the layout of every type in Layouts.swift: the expected result of the Swift Data Types
// analyzer. Compiled together with Layouts.swift into one executable (same module, compiler,
// options and target as libLayouts.dylib, so the layouts are the same); see the Makefile.
//
// Lines, tab-separated, types in declaration order:
//   STRUCT  name  size  stride  align
//   CLASS   name  size  align  superclass       size from class_getInstanceSize, align from the
//                                                metadata's instance alignment mask
//   ENUM    name  size  stride  align
//   FIELD   offset  size  name  Swift type      structs: MemoryLayout.offset(of:); classes:
//                                                ivar_getOffset (own fields only)
//   CASE    value  name                          enums without payload, value = the tag byte
//   SKIP    name  reason                         types the analyzer does not build
//
// Each field list is checked against Mirror; a field missing here stops the program.

import Foundation
import ObjectiveC

func emit(_ columns: Any...) {
    print(columns.map { "\($0)" }.joined(separator: "\t"))
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(("DumpLayouts: " + message + "\n").data(using: .utf8)!)
    exit(1)
}

/// A field as a key path and its name; the key path gives the offset (structs) and the type.
struct Field<Root> {
    let name: String
    var offset: Int?
    var size: Int
    let type: String
    /// Not in the Objective-C ivar list (an actor's $defaultActor).
    var hidden = false

    init<Value>(_ keyPath: KeyPath<Root, Value>, _ name: String) {
        self.name = name
        offset = MemoryLayout<Root>.offset(of: keyPath)
        size = MemoryLayout<Value>.size
        type = String(reflecting: Value.self)
    }

    /// A field whose stored size differs from MemoryLayout<Value>.size here: a metatype of a
    /// struct is thin when stored (0 bytes; its Optional 1 byte, measured with a concrete struct),
    /// but thick (8 bytes) when abstracted as Value.
    init<Value>(_ keyPath: KeyPath<Root, Value>, _ name: String, storedSize: Int) {
        self.init(keyPath, name)
        size = storedSize
    }

    /// A field that no key path reaches (an actor's $defaultActor); the offset comes from the
    /// ivar list or the runtime.
    init(hidden name: String, size: Int, type: String) {
        self.name = name
        offset = nil
        self.size = size
        self.type = type
        hidden = true
    }

    /// For fields that MemoryLayout.offset(of:) does not resolve (closures: the key path
    /// reabstracts them). The offset is the first byte that `change` alters in `value`, rounded
    /// down to the field's alignment; `change` must alter the field's first word.
    init<Value>(_ keyPath: KeyPath<Root, Value>, _ name: String, in value: Root,
                change: (inout Root) -> Void) {
        self.init(keyPath, name)
        // Read the same variable before and after, in place: a copy need not keep padding bytes
        // or the payload bytes of a nil Optional.
        var changed = value
        let before = withUnsafeBytes(of: &changed) { Array($0) }
        change(&changed)
        let after = withUnsafeBytes(of: &changed) { Array($0) }
        guard let first = before.indices.first(where: { before[$0] != after[$0] }) else {
            fail("\(name): change alters no byte")
        }
        let alignment = MemoryLayout<Value>.alignment
        offset = first / alignment * alignment
    }
}

/// The runtime function behind Mirror's field offsets (stdlib ReflectionMirror.swift).
@_silgen_name("swift_reflectionMirror_recursiveChildOffset")
func childOffset(_: Any.Type, index: Int) -> Int

func checkMirror(_ subject: Any, _ names: [String], _ typeName: String) {
    let labels = Mirror(reflecting: subject).children.map { $0.label ?? "?" }
    if labels != names {
        fail("\(typeName): fields \(names) here, \(labels) in Mirror")
    }
}

func dumpStruct<T>(_ value: T, _ fields: [Field<T>]) {
    let name = String(reflecting: T.self)
    checkMirror(value, fields.map(\.name), name)
    emit("STRUCT", name, MemoryLayout<T>.size, MemoryLayout<T>.stride, MemoryLayout<T>.alignment)
    for (index, f) in fields.enumerated() {
        // Metatype fields: offset(of:) gives nil, and a thin metatype has no bytes to change.
        // The runtime's field offset vector has the offset (the order was checked against Mirror).
        let offset = f.offset ?? childOffset(T.self, index: index)
        emit("FIELD", offset, f.size, f.name, f.type)
    }
}

func dumpClass<T: AnyObject>(_ instance: T, _ fields: [Field<T>]) {
    let cls: AnyClass = T.self
    let name = String(reflecting: T.self)
    checkMirror(instance, fields.map(\.name), name)
    // Ivars of this class only, not of its superclasses (as in __swift5_fieldmd).
    var count: UInt32 = 0
    var offsets: [String: Int] = [:]
    if let ivars = class_copyIvarList(cls, &count) {
        for i in 0..<Int(count) {
            if let ivarName = ivar_getName(ivars[i]) {
                offsets[String(cString: ivarName)] = ivar_getOffset(ivars[i])
            }
        }
        free(ivars)
    }
    if offsets.count != fields.filter({ !$0.hidden }).count {
        fail("\(name): \(offsets.count) ivars, \(fields.count) fields")
    }
    // Swift class metadata, word 6: instance size (uint32), instance alignment mask (uint16).
    let metadata = unsafeBitCast(cls, to: UnsafeRawPointer.self)
    let alignMask = metadata.load(fromByteOffset: 52, as: UInt16.self)
    let superclass = class_getSuperclass(cls).map { NSStringFromClass($0) } ?? "-"
    emit("CLASS", name, class_getInstanceSize(cls), Int(alignMask) + 1, superclass)
    for (index, f) in fields.enumerated() {
        // Hidden fields: the runtime's field offset vector; the index is valid for a class whose
        // superclass has no fields (Counter's is the Swift root).
        guard let offset = f.hidden ? childOffset(T.self, index: index) : offsets[f.name] else {
            fail("\(name).\(f.name): no ivar")
        }
        emit("FIELD", offset, f.size, f.name, f.type)
    }
}

func dumpEnum<T: CaseIterable>(_: T.Type) {
    let name = String(reflecting: T.self)
    emit("ENUM", name, MemoryLayout<T>.size, MemoryLayout<T>.stride, MemoryLayout<T>.alignment)
    for c in T.allCases {
        let tag = withUnsafeBytes(of: c) { $0.isEmpty ? 0 : Int($0[0]) }
        emit("CASE", tag, String(describing: c))
    }
}

/// For MoreFields.weakDelegate: a value to change it to.
final class Listener: Delegate {
    static let shared = Listener()
    func notify() {}
}

/// For MoreFields' unowned fields: a value to change them to.
let otherNode = Node()

@main
enum DumpLayouts {
    static func main() {
        #if arch(arm64)
        print("# Layouts.swift, arm64")
        #elseif arch(x86_64)
        print("# Layouts.swift, x86_64")
        #endif

        dumpStruct(Scalars(), [
            Field(\.int, "int"),
            Field(\.uint, "uint"),
            Field(\.double, "double"),
            Field(\.float, "float"),
            Field(\.bool, "bool"),
            Field(\.string, "string"),
        ])
        dumpStruct(Collections(), [
            Field(\.doubles, "doubles"),
            Field(\.floats, "floats"),
            Field(\.nested, "nested"),
            Field(\.dictionary, "dictionary"),
            Field(\.set, "set"),
        ])
        dumpStruct(OptionalPadding(), [
            Field(\.flag, "flag"),
            Field(\.optionalDouble, "optionalDouble"),
            Field(\.afterOptional, "afterOptional"),
            Field(\.optionalInt, "optionalInt"),
            Field(\.small, "small"),
        ])
        dumpStruct(Point(), [
            Field(\.x, "x"),
            Field(\.y, "y"),
        ])
        dumpEnum(Direction.self)
        dumpClass(Node(), [
            Field(\.name, "name"),
            Field(\.weight, "weight"),
            Field(\.next, "next"),
        ])
        dumpClass(LeafNode(), [
            Field(\.value, "value"),
            Field(\.direction, "direction"),
        ])
        dumpClass(Observer(), [
            Field(\.count, "count"),
            Field(\.label, "label"),
            Field(\.handler, "handler"),
        ])
        let composite = Composite()
        dumpStruct(composite, [
            Field(\.origin, "origin"),
            Field(\.optionalPoint, "optionalPoint"),
            Field(\.direction, "direction"),
            Field(\.optionalDirection, "optionalDirection"),
            Field(\.node, "node"),
            Field(\.optionalNode, "optionalNode"),
            Field(\.shape, "shape"),
            Field(\.callback, "callback", in: composite) { $0.callback = { print("changed") } },
            Field(\.throwingCallback, "throwingCallback", in: composite) {
                $0.throwingCallback = { _ in throw CocoaError(.featureUnsupported) }
            },
            Field(\.object, "object"),
            Field(\.tuple, "tuple"),
        ])
        dumpStruct(Square(), [
            Field(\.side, "side"),
        ])
        dumpStruct(Outer(), [
            Field(\.inner, "inner"),
            Field(\.tag, "tag"),
        ])
        dumpStruct(Outer.Inner(), [
            Field(\.level, "level"),
            Field(\.scale, "scale"),
        ])
        let more = MoreFields()
        dumpStruct(more, [
            Field(\.delegate, "delegate"),
            Field(\.composition, "composition"),
            Field(\.anyObject, "anyObject"),
            Field(\.copying, "copying"),
            Field(\.block, "block"),
            Field(\.cFunction, "cFunction"),
            Field(\.labelled, "labelled"),
            Field(\.optionalInner, "optionalInner"),
            Field(\.optionalScalars, "optionalScalars"),
            Field(\.optionalSquare, "optionalSquare"),
            Field(\.buffer, "buffer"),
            Field(\.rawPointer, "rawPointer"),
            Field(\.weakNode, "weakNode", in: more) { $0.weakNode = sharedNode },
            Field(\.weakDelegate, "weakDelegate", in: more) { $0.weakDelegate = Listener.shared },
            Field(\.unownedNode, "unownedNode", in: more) { $0.unownedNode = otherNode },
            Field(\.unsafeNode, "unsafeNode", in: more) { $0.unsafeNode = otherNode },
            Field(\.tail, "tail"),
        ])
        emit("SKIP", String(reflecting: Single.self), "enum of size 0")
        dumpStruct(Empty(), [])
        dumpStruct(ZeroSized(), [
            Field(\.name, "name"),
            Field(\.single, "single"),
            Field(\.empty, "empty"),
            Field(\.generator, "generator"),
            Field(\.count, "count"),
            Field(\.optionalSingle, "optionalSingle"),
            Field(\.tailGenerator, "tailGenerator"),
        ])
        dumpStruct(Failure(), [])
        dumpStruct(Metatypes(), [
            Field(\.shapeType, "shapeType"),
            Field(\.optionalShapeType, "optionalShapeType"),
            Field(\.compositionType, "compositionType"),
            Field(\.anyType, "anyType"),
            Field(\.delegateType, "delegateType"),
            Field(\.error, "error"),
            Field(\.optionalError, "optionalError"),
            Field(\.tail, "tail"),
        ])
        dumpStruct(URL.Component(), [
            Field(\.index, "index"),
            Field(\.name, "name"),
        ])
        if #available(macOS 26, *) {
            let modern = Modern()
            // A closure that captures a value has a context, so its bytes differ from {}.
            let captured = String(Int.random(in: 1...9))
            dumpStruct(modern, [
                Field(\.intType, "intType", storedSize: 0),
                Field(\.optionalIntType, "optionalIntType", storedSize: 1),
                Field(\.nodeType, "nodeType"),
                Field(\.objectType, "objectType"),
                Field(\.mainActor, "mainActor", in: modern) { $0.mainActor = { print(captured) } },
                Field(\.sendable, "sendable", in: modern) { $0.sendable = { $0 } },
                Field(\.isolatedAny, "isolatedAny", in: modern) { $0.isolatedAny = { print(captured) } },
                Field(\.typedThrows, "typedThrows", in: modern) { $0.typedThrows = { print(captured) } },
                Field(\.asyncClosure, "asyncClosure", in: modern) { $0.asyncClosure = { print(captured) } },
                Field(\.tail, "tail"),
                Field(\.index, "index"),
            ])
            dumpStruct(Inline(), [
                Field(\.values, "values"),
                Field(\.tail, "tail"),
            ])
        }
        dumpClass(Counter(), [
            // 12 words (NumWords_DefaultActor, swift/ABI/MetadataValues.h)
            Field(hidden: "$defaultActor", size: 96, type: "Builtin.DefaultActorStorage"),
            Field(\.count, "count"),
        ])
        // Skipped: offsets slid at run time. The reason gives the run-time offset of the first own
        // field, which the binary has at 8 (Worker) and 32 (SubWorker).
        for (cls, field): (AnyClass, String) in [(Worker.self, "jobs"), (SubWorker.self, "extra")] {
            let ivar = class_getInstanceVariable(cls, field)!
            emit("SKIP", String(reflecting: cls),
                 "Objective-C superclass NSThread: \(field) at \(ivar_getOffset(ivar)) at run time")
        }
        emit("SKIP", String(reflecting: Box<Int>.self).replacingOccurrences(of: "<Swift.Int>", with: ""),
             "generic")
        emit("SKIP", String(reflecting: Measurement.self), "enum with payload")
    }
}
