// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Fixture for the Swift Runtime Prototypes analyzer: functions whose code calls the Swift runtime
// with flag arguments (swift_beginAccess, swift_dynamicCast), with results in two registers
// (swift_allocBox, the generic metadata functions), and one async function (swift_task_switch,
// which the analyzer leaves alone). Every function is public and @inline(never), so each call
// stays a call.

import Darwin

// A stored property of a class that is not final: each access is checked at run time
// (swift_beginAccess). With -O the getter passes Read and the setter Modify, the modify coroutine
// Tracking|Modify and then calls swift_endAccess; with -Onone every access has Tracking.
open class Counter {
    public var value = 0

    public init() {}

    @inline(never)
    open func bump(by n: Int) {
        value += n
    }

    @inline(never)
    open func current() -> Int {
        value
    }
}

// An escaping closure that captures a var of generic type: the var lives in a box
// (swift_allocBox, which returns the box and the address of its value).
@inline(never)
public func makeAccumulator<T>(_ initial: T, _ combine: @escaping (T, T) -> T) -> (T) -> T {
    var total = initial
    return { x in
        total = combine(total, x)
        return total
    }
}

// The payload of an indirect case of a generic enum is in a box too.
public indirect enum Tree<T> {
    case leaf(T)
    case node(Tree, Tree)
}

@inline(never)
public func makeTree<T>(_ a: T, _ b: T) -> Tree<T> {
    .node(.leaf(a), .leaf(b))
}

// A generic class: its metadata accessor asks the runtime for the metadata of each
// instantiation (swift_getGenericMetadata, a MetadataResponse in two registers).
public final class Box<T> {
    public var item: T

    public init(_ item: T) {
        self.item = item
    }
}

@inline(never)
public func makeBox<T>(_ item: T) -> Box<T> {
    Box(item)
}

// A cast to a protocol (swift_dynamicCast with DynamicCastFlags).
public protocol Named {
    var name: String { get }
}

public struct Person: Named {
    public var name: String
}

@inline(never)
public func nameOf(_ x: Any) -> String? {
    (x as? Named)?.name
}

// Calls to an actor's methods switch to its executor (swift_task_switch, SwiftAsyncCC).
public actor Store {
    var count = 0

    public init() {}

    public func add() -> Int {
        count += 1
        return count
    }
}

@inline(never)
public func addTwice(_ store: Store) async -> Int {
    let a = await store.add()
    let b = await store.add()
    return a + b
}

// malloc: Ghidra's archives type it (source IMPORTED), the analyzer keeps that.
@inline(never)
public func rawBuffer(_ n: Int) -> UnsafeMutableRawPointer? {
    malloc(n)
}

// A global with an initial value computed at run time: its addressor runs the initialiser once
// (swift_once, whose context IRGen leaves undefined). The addressor takes no parameters.
public let processID = Int(getpid())
