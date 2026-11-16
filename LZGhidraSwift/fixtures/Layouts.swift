// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Fixture for the Swift Data Types analyzer.
// One type per case of the type mapping. DumpLayouts.swift prints the layout that the
// compiler chose; keep the two files in step when you add a type or a field.
//
// Every type is public, so that a library built without library evolution has fixed layouts and
// static metadata, and has an init() with defaults, so that DumpLayouts can check its field list
// against Mirror.

import Foundation

/// The standard library types of the mapping table, one field each.
public struct Scalars {
    public var int: Int = -1
    public var uint: UInt = 1
    public var double: Double = 2.5
    public var float: Float = 3.5
    public var bool: Bool = true
    public var string: String = "scalars"
    public init() {}
}

/// Arrays, dictionaries and sets are one pointer each.
public struct Collections {
    public var doubles: [Double] = [1]
    public var floats: [Float]? = nil
    public var nested: [[Float]] = []
    public var dictionary: [String: Int] = [:]
    public var set: Set<String> = []
    public init() {}
}

/// Optional<Double> is 9 bytes: the next field follows its size (8 + 9 = 17, so the Float is at
/// 20), not its stride (16, which would put it at 24).
public struct OptionalPadding {
    public var flag: Bool = false
    public var optionalDouble: Double? = nil
    public var afterOptional: Float = 1.5
    public var optionalInt: Int? = 7
    public var small: Int8 = 3
    public init() {}
}

/// Embedded in Composite, and optional there (Optional<Point> is 17 bytes).
public struct Point {
    public var x: Double = 0
    public var y: Double = 0
    public init() {}
}

/// An enum without payload: one byte, cases numbered in declaration order.
public enum Direction: CaseIterable {
    case north
    case east
    case south
    case west
}

public protocol Shape {
    func area() -> Double
}

/// A class of the module, the base of a class hierarchy.
public class Node {
    public var name: String = "node"
    public var weight: Float = 1
    public var next: Node? = nil
    public init() {}
}

/// A class with a Swift superclass: its own fields start after Node's.
public final class LeafNode: Node {
    public var value: Double = 4
    public var direction: Direction = .west
    public override init() {}
}

/// A class with an Objective-C superclass.
public final class Observer: NSObject {
    public var count: Int = 0
    public var label: NSString = "observer"
    public var handler: (() -> Void)? = nil
    public override init() {}
}

/// References to other types of the module, existentials, closures, an Objective-C class.
public struct Composite {
    public var origin: Point = Point()
    public var optionalPoint: Point? = nil
    public var direction: Direction = .east
    public var optionalDirection: Direction? = nil
    public var node: Node = Node()
    public var optionalNode: Node? = nil
    public var shape: any Shape = Square()
    public var callback: () -> Void = {}
    public var throwingCallback: (Int) throws -> Double = { Double($0) }
    public var object: NSString = "composite"
    public var tuple: (Int, Float) = (1, 2)
    public init() {}
}

/// Conforms to Shape, for Composite.shape.
public struct Square: Shape {
    public var side: Double = 2
    public init() {}
    public func area() -> Double { side * side }
}

/// A nested type: /SwiftTypes/Layouts/Outer/Inner.
public struct Outer {
    public struct Inner {
        public var level: Int32 = 2
        public var scale: Double = 0.5
        public init() {}
    }

    public var inner: Inner = Inner()
    public var tag: UInt16 = 9
    public init() {}
}

/// A class-constrained protocol: an existential of it is the object and one witness table.
public protocol Delegate: AnyObject {
    func notify()
}

/// A second Swift protocol, for a protocol composition.
public protocol Named {
    var label: String { get }
}

extension Square: Named {
    public var label: String { "square" }
}

/// The mappings that Composite does not cover.
public struct MoreFields {
    public var delegate: (any Delegate)? = nil
    public var composition: any Shape & Named = Square()
    public var anyObject: AnyObject = Node()
    public var copying: any NSCopying = NSString("copying")
    public var block: @convention(block) () -> Void = {}
    public var cFunction: @convention(c) (Int32) -> Int32 = { $0 }
    public var labelled: (count: Int, scale: Float) = (1, 2)
    /// No extra inhabitants (Int32 and Double): a tag byte after 16 bytes.
    public var optionalInner: Outer.Inner? = nil
    /// Extra inhabitants from the String: no tag byte.
    public var optionalScalars: Scalars? = nil
    /// Square's value witness table is the runtime's $sBi64_WV (no extra inhabitants): 9 bytes.
    public var optionalSquare: Square? = nil
    /// Buffer pointers have no extra inhabitants: 17 bytes.
    public var buffer: UnsafeBufferPointer<Float>? = nil
    /// Raw pointers have one extra inhabitant (null): Optional<Optional<...>> is 9 bytes.
    public var rawPointer: UnsafeMutableRawPointer?? = nil
    /// Weak and unowned references (Xw, Xo, Xu in the mangling): one reference each; to a
    /// class-constrained protocol, the reference and the witness table.
    public weak var weakNode: Node? = nil
    public weak var weakDelegate: (any Delegate)? = nil
    public unowned var unownedNode: Node = sharedNode
    public unowned(unsafe) var unsafeNode: Node = sharedNode
    public var tail: UInt8 = 5
    public init() {}
}

/// An enum with one case has size 0; the analyzer skips it (no Ghidra enum of size 0).
public enum Single: CaseIterable {
    case only
}

/// A struct without stored properties: size 0, stride 1.
public struct Empty {
    public init() {}
}

/// Fields of size 0 share their offset with the next field or sit at the end. In
/// libSwiftDriver.dylib, `SDKFailure { inputPath: String; kind: SDKFailureKind }` (a one-case
/// enum) lost inputPath to kind. SystemRandomNumberGenerator is a size-0 struct of the standard
/// library that the mapper does not know.
public struct ZeroSized {
    public var name: String = "zero"
    public var single: Single = .only
    public var empty: Empty = Empty()
    public var generator: SystemRandomNumberGenerator = SystemRandomNumberGenerator()
    public var count: Int = 3
    public var optionalSingle: Single? = nil
    public var tailGenerator: SystemRandomNumberGenerator = SystemRandomNumberGenerator()
    public init() {}
}

/// An Error, for Metatypes.error.
public struct Failure: Error {
    public init() {}
}

public typealias ShapeAndNamed = Shape & Named

/// Existential metatypes (Xp: the metadata and a witness table per Swift protocol) and Error
/// existentials (one reference to a box), seen first in swift-format (ArgumentParser).
public struct Metatypes {
    public var shapeType: any Shape.Type = Square.self
    public var optionalShapeType: (any Shape.Type)? = nil
    public var compositionType: any ShapeAndNamed.Type = Square.self
    public var anyType: Any.Type = Int.self
    public var delegateType: (any Delegate.Type)? = nil
    public var error: any Error = Failure()
    public var optionalError: (any Error)? = nil
    public var tail: UInt8 = 1
    public init() {}
}

/// A type in an extension of another module's type: its parent is an extension context whose
/// extended type is a symbolic reference (swift-format: SwiftDiagnostics.FixIt.MultiNodeChange).
extension URL {
    public struct Component {
        public var index: Int = 0
        public var name: String = "component"
        public init() {}
    }
}

/// Concrete metatypes (thin for a struct: 0 bytes), function attributes, and generic arguments of
/// an outer level (Dictionary<Int, String>.Index; last, so that its undefined bytes end at the
/// struct's size). Seen first in swift-package and in a test library (not in the repository). @isolated(any) and typed
/// throws need macOS 15; the x86_64 fixture is built for macOS 13.
@available(macOS 26, *)
public struct Modern {
    public var intType: Int.Type = Int.self
    public var optionalIntType: Int.Type? = nil
    public var nodeType: Node.Type = Node.self
    public var objectType: NSObject.Type = NSObject.self
    public var mainActor: @MainActor () -> Void = {}
    public var sendable: (@MainActor @Sendable (Int) -> Int)? = nil
    public var isolatedAny: @isolated(any) () -> Void = {}
    public var typedThrows: () throws(Failure) -> Void = {}
    public var asyncClosure: () async -> Void = {}
    public var tail: UInt8 = 1
    public var index: Dictionary<Int, String>.Index = [1: "one"].startIndex
    public init() {}
}

/// An integer generic argument (mangled $2_ for 3). InlineArray needs macOS 26; the x86_64
/// fixture is built for macOS 13.
@available(macOS 26, *)
public struct Inline {
    public var values: InlineArray<3, Int16> = [1, 2, 3]
    public var tail: UInt8 = 4
    public init() {}
}

/// An actor: Builtin.DefaultActorStorage ($defaultActor, 96 bytes) and alignment 16.
public actor Counter {
    /// A let: nonisolated, so DumpLayouts can form a key path to it.
    public let count: Int = 0
    public init() {}
}

/// A Swift class with an Objective-C superclass larger than NSObject (Thread is NSThread, as in
/// sourcekit-lsp's TSCBasic.ThreadImpl): the binary lays the own fields out from 8, after isa;
/// the Objective-C runtime slides them past NSThread's ivars at load time. The analyzer skips
/// it and its subclasses.
public class Worker: Thread {
    public var jobs: Int = 1
    public var label: String = "worker"
    public override init() {}
}

public final class SubWorker: Worker {
    public var extra: Double = 2
    public override init() {}
}

/// Referenced by MoreFields' unowned fields.
public let sharedNode = Node()

/// Generic: no static metadata, the analyzer skips it.
public struct Box<T> {
    public var value: T
    public var count: Int = 1
    public init(_ value: T) { self.value = value }
}

/// An enum with payload: the analyzer skips it (case names only).
public enum Measurement {
    case none
    case length(Double)
    case label(String)
}
