// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Fixture for the Swift Self Types analyzer.
// Methods whose self the analyzer types, and some it must leave alone. expected-self.txt lists,
// for each function, the type of self (or "-") and text that the decompiled C must contain.
//
// Swift passes self in x20 (arm64) or r13 (x86_64) when self is a class reference, a metatype, or
// passed indirectly: a mutating method, a setter or modify accessor of a struct. A non-mutating
// method of a struct gets the value in the argument registers instead.
//
// @inline(never) keeps each method a function of its own; the fields are read and written so
// that the decompiled C shows them.

/// A struct: mutating methods and accessors get self in x20, the others do not.
public struct Gauge {
    public var level: Int = 0
    public var scale: Double = 1
    public var limit: Int32 = 10

    public init() {}

    /// Mutating: self (a pointer to the struct) in x20.
    @inline(never)
    public mutating func raise(by amount: Int) {
        level += amount
        if level > Int(limit) {
            level = Int(limit)
        }
    }

    /// Mutating, reads and writes the second field.
    @inline(never)
    public mutating func rescale(_ factor: Double) {
        scale *= factor
    }

    /// Not mutating: the fields arrive in x0, d0, x1; x20 is not self.
    @inline(never)
    public func scaled() -> Double {
        Double(level) * scale
    }

    /// A computed property with a setter: the setter is mutating.
    public var doubled: Int {
        @inline(never) get { level * 2 }
        @inline(never) set { level = newValue / 2 }
    }

    /// A static method: x20 holds no instance.
    @inline(never)
    public static func make(level: Int) -> Gauge {
        var g = Gauge()
        g.level = level
        return g
    }
}

/// An enum without payload, with a mutating method.
public enum Phase: CaseIterable {
    case idle
    case running
    case done

    @inline(never)
    public mutating func advance() {
        switch self {
        case .idle: self = .running
        case .running: self = .done
        case .done: self = .done
        }
    }
}

/// A class: its overridable methods are in the method table of its descriptor.
open class Engine {
    public var name: String = "engine"
    public var speed: Double = 0
    public var gauge: Gauge = Gauge()
    public var phase: Phase = .idle

    public init() {}

    @inline(never)
    open func accelerate(_ delta: Double) {
        speed += delta
        gauge.raise(by: Int(delta))
    }

    @inline(never)
    open func stop() {
        speed = 0
        phase = .done
    }

    /// final: not in the method table; found through its symbol.
    @inline(never)
    public final func describe() -> Double {
        speed * gauge.scale
    }
}

/// A subclass: an override (override table) and a new method (its own method table).
open class TurboEngine: Engine {
    public var boost: Double = 2
    public var spins: Int = 0

    @inline(never)
    open override func accelerate(_ delta: Double) {
        speed += delta * boost
        spins += 1
    }

    @inline(never)
    open func spool(_ amount: Int) {
        spins += amount
        boost = Double(spins) * 0.5
    }
}

/// A final class: no method table; its methods are found through their symbols.
public final class Sensor {
    public var reading: Float = 0
    public var count: Int = 0

    public init() {}

    @inline(never)
    public func record(_ value: Float) {
        reading = value
        count += 1
    }
}
