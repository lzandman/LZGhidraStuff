// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Fixture for the Swift error register (x21 on arm64, r12 on x86_64): throwing functions and
// their callers. A throwing function returns its error in x21; the caller sets x21 to 0 before
// the call and tests it after. Every function is public and @inline(never), so each call stays
// a call.

public struct ParseError: Error {
    public let code: Int
}

public enum Failure: Error {
    case empty
    case tooLarge(Int)
}

// Throws an existential error (any Error) or returns an Int.
@inline(never)
public func mayThrow(_ x: Int) throws -> Int {
    if x < 0 { throw ParseError(code: x) }
    if x > 1000 { throw Failure.tooLarge(x) }
    return x * 2
}

// Throws or returns a Double (result in d0, error in x21).
@inline(never)
public func mayThrowDouble(_ x: Double) throws -> Double {
    if x.isNaN { throw Failure.empty }
    return x / 3
}

// Throws or returns nothing.
@inline(never)
public func check(_ x: Int) throws {
    if x == 0 { throw Failure.empty }
}

// Typed throws (Swift 6): the error type is known.
@inline(never)
public func typedThrow(_ x: Int) throws(ParseError) -> Int {
    if x < 0 { throw ParseError(code: x) }
    return x + 7
}

// Typed throws with an error of two words: returned in the result registers x0 and x1 (rax and
// rdx), with x21 (r12) set to 1 as a flag.
public struct Span: Error {
    public let lo: Int
    public let hi: Int
}

@inline(never)
public func typedPair(_ x: Int) throws(Span) -> Int {
    if x < 0 { throw Span(lo: x, hi: x &* 2) }
    return x + 1
}

// Typed throws without a result: the error alone in x0 (rax). The code is a public variable, so
// the optimizer cannot fold it into the caller.
public var voidCode = 42

@inline(never)
public func typedVoid(_ x: Int) throws(ParseError) {
    if x == 0 { throw ParseError(code: voidCode) }
}

// An error of five words does not fit the result registers: the caller passes a buffer for it
// after the arguments (x1, rsi), which the signature does not show.
public struct Overflow: Error {
    public let a: Int, b: Int, c: Int, d: Int, e: Int
}

@inline(never)
public func typedLarge(_ x: Int) throws(Overflow) -> Int {
    if x < 0 { throw Overflow(a: x, b: 1, c: 2, d: 3, e: 4) }
    return x + 9
}

// do/catch: the catch path returns -1.
@inline(never)
public func callThrowing(_ x: Int) -> Int {
    do {
        return try mayThrow(x)
    } catch {
        return -1
    }
}

// Catch by type: different results per error.
@inline(never)
public func classify(_ x: Int) -> Int {
    do {
        return try mayThrow(x)
    } catch let e as ParseError {
        return e.code - 100
    } catch Failure.tooLarge(let n) {
        return n + 100
    } catch {
        return 0
    }
}

// try?: the error becomes nil.
@inline(never)
public func optionalTry(_ x: Int) -> Int? {
    try? mayThrow(x)
}

// Propagation: a throwing caller passes the error on.
@inline(never)
public func propagate(_ x: Int) throws -> Int {
    let a = try mayThrow(x)
    try check(a)
    return a + 1
}

@inline(never)
public func callDouble(_ x: Double) -> Double {
    (try? mayThrowDouble(x)) ?? -1.5
}

@inline(never)
public func callTyped(_ x: Int) -> Int {
    do {
        return try typedThrow(x)
    } catch {
        return error.code
    }
}

// The callers of typed throws test x21 (r12) with a conditional select, not a branch.
@inline(never)
public func callTypedPair(_ x: Int) -> Int {
    do {
        return try typedPair(x)
    } catch {
        return error.lo &* 3 &+ error.hi
    }
}

@inline(never)
public func callTypedVoid(_ x: Int) -> Int {
    do {
        try typedVoid(x)
        return 0
    } catch {
        return error.code &+ 1000
    }
}

@inline(never)
public func callTypedLarge(_ x: Int) -> Int {
    do {
        return try typedLarge(x)
    } catch {
        return error.e &* 5 &+ error.a
    }
}

// A throwing method of a class (self in x20, error in x21).
public final class Parser {
    public var limit: Int

    public init(limit: Int) { self.limit = limit }

    @inline(never)
    public func parse(_ x: Int) throws -> Int {
        if x > limit { throw Failure.tooLarge(x) }
        return x - limit
    }
}

@inline(never)
public func callMethod(_ p: Parser, _ x: Int) -> Int {
    do {
        return try p.parse(x)
    } catch {
        return -2
    }
}

// A throwing closure called through a function value (an indirect call).
@inline(never)
public func callClosure(_ f: (Int) throws -> Int, _ x: Int) -> Int {
    do {
        return try f(x)
    } catch {
        return -3
    }
}

// A throwing closure that takes an inout struct: the caller passes a stack address in x0 (rdi)
// and reads the struct after the call. The closure's context is in x20 (r13).
public struct Pair {
    public var a: Int
    public var b: Int
}

@inline(never)
public func callInout(_ f: (inout Pair) throws -> Void, _ x: Int) -> Int {
    var p = Pair(a: x, b: x &+ 1)
    do {
        try f(&p)
    } catch {
        return -8
    }
    return p.a &* 3 &+ p.b
}

// A throwing closure that returns a struct too large for the result registers: the caller passes
// a buffer for it in x8 (rax). x is the caller's own first argument and stays in x0 (rdi).
public struct Big {
    public var a: Int, b: Int, c: Int, d: Int, e: Int
}

@inline(never)
public func callBig(_ x: Int, _ f: (Int) throws -> Big) -> Int {
    do {
        let big = try f(x)
        return big.a &+ big.e
    } catch {
        return -9
    }
}

// A throwing initializer (symbol ...KcfC) and a static throwing method (...KFZ).
public struct Config {
    public let size: Int

    @inline(never)
    public init(size: Int) throws {
        if size < 0 { throw Failure.empty }
        self.size = size
    }

    @inline(never)
    public static func standard(_ x: Int) throws -> Config {
        try Config(size: x * 2)
    }
}

@inline(never)
public func callInit(_ x: Int) -> Int {
    do {
        return try Config(size: x).size
    } catch {
        return -4
    }
}

@inline(never)
public func callStatic(_ x: Int) -> Int {
    (try? Config.standard(x).size) ?? -5
}

// A generic throwing function (the symbol ends with the generic signature).
@inline(never)
public func firstMatch<T: Equatable>(_ items: [T], _ wanted: T) throws -> Int {
    guard let i = items.firstIndex(of: wanted) else { throw Failure.empty }
    return i
}

@inline(never)
public func callGeneric(_ items: [Int]) -> Int {
    do {
        return try firstMatch(items, 42)
    } catch {
        return -6
    }
}

// Throwing functions without an exported symbol: internal, so their symbols are local and
// strip -x removes them (libThrows-stripped.dylib), as in a binary that ships with its exported
// symbols only. The analyzer then finds them from their callers.
@inline(never)
func hiddenThrow(_ x: Int) throws -> Int {
    if x == 7 { throw Failure.tooLarge(x) }
    return x &* 3
}

// A hidden throwing caller that passes the error on: x21 is its entry value, not set to 0.
@inline(never)
func hiddenPropagate(_ x: Int) throws -> Int {
    try hiddenThrow(x) &+ hiddenThrow(x &+ 1)
}

@inline(never)
public func callHidden(_ x: Int) -> Int {
    do {
        return try hiddenPropagate(x)
    } catch {
        return -7
    }
}

// A hidden typed throw: found from its caller in the stripped copies, where the test is a
// conditional select.
@inline(never)
func hiddenTyped(_ x: Int) throws(ParseError) -> Int {
    if x == 3 { throw ParseError(code: x &* 11) }
    return x &+ 5
}

@inline(never)
public func callHiddenTyped(_ x: Int) -> Int {
    do {
        return try hiddenTyped(x)
    } catch {
        return error.code &* 7
    }
}

// Typed throws with an indirect result: the caller passes the result buffer in x8 (rax) and,
// because the result is indirect, a buffer for the error after the arguments (x1, rsi), which
// the signature does not show.
@inline(never)
public func typedBig(_ x: Int) throws(ParseError) -> Big {
    if x < 0 { throw ParseError(code: x) }
    return Big(a: x, b: 1, c: 2, d: 3, e: 4)
}

@inline(never)
public func callTypedBig(_ x: Int) -> Int {
    do {
        let big = try typedBig(x)
        return big.a &+ big.e
    } catch {
        return error.code &* 2
    }
}

// A generic error type: the unspecialized function takes a buffer for the error after its
// arguments; the caller calls the specialization for ParseError, which returns it in x0 (rax).
@inline(never)
public func genericTyped<E: Error>(_ x: Int, _ e: E) throws(E) -> Int {
    if x < 0 { throw e }
    return x &+ 4
}

@inline(never)
public func callGenericTyped(_ x: Int) -> Int {
    do {
        return try genericTyped(x, ParseError(code: 5))
    } catch {
        return error.code &+ 50
    }
}

// Throwing closures with other arguments and results: a Double in and out (d0, xmm0), a String
// result (x0 and x1, rax and rdx), and ten Int arguments, of which two go on the stack (eight
// argument registers on arm64, six on x86_64).
@inline(never)
public func callDoubleClosure(_ f: (Double) throws -> Double, _ x: Double) -> Double {
    do {
        return try f(x)
    } catch {
        return -11.5
    }
}

@inline(never)
public func callStringClosure(_ f: (Int) throws -> String, _ x: Int) -> Int {
    do {
        return try f(x).utf8.count
    } catch {
        return -12
    }
}

@inline(never)
public func callManyArgs(
    _ f: (Int, Int, Int, Int, Int, Int, Int, Int, Int, Int) throws -> Int, _ x: Int
) -> Int {
    do {
        return try f(x, x &+ 1, x &+ 2, x &+ 3, x &+ 4, x &+ 5, x &+ 6, x &+ 7, x &+ 8, x &+ 9)
    } catch {
        return -13
    }
}

// A method whose self is in x20 (r13) for a call of another method, before the closure's
// context replaces it.
public final class Holder {
    public var n: Int

    public init(n: Int) { self.n = n }

    @inline(never)
    public func bump() { n &+= 1 }

    @inline(never)
    public func callWith(_ f: (Int) throws -> Int) -> Int {
        bump()
        do {
            return try f(n)
        } catch {
            return -14
        }
    }
}

// A throwing protocol requirement: the protocol witness thunk (symbol ...TW) throws, and the
// callers call the witness through the witness table, with self in x20 (r13).
public protocol Loader {
    func load(_ x: Int) throws -> Int
}

public struct FileLoader: Loader {
    public init() {}

    @inline(never)
    public func load(_ x: Int) throws -> Int {
        if x == 0 { throw Failure.empty }
        return x &* 5
    }
}

@inline(never)
public func callWitness<L: Loader>(_ l: L, _ x: Int) -> Int {
    do {
        return try l.load(x)
    } catch {
        return -15
    }
}

@inline(never)
public func callExistential(_ l: any Loader, _ x: Int) -> Int {
    do {
        return try l.load(x)
    } catch {
        return -16
    }
}

// Two identical throwing functions: with -O the compiler merges their bodies into one copy
// (symbol ...Tm), and both entry points branch to it.
@inline(never)
public func mergeA(_ x: Int) throws -> Int {
    if x == 3 { throw Failure.empty }
    return x &* 9
}

@inline(never)
public func mergeB(_ x: Int) throws -> Int {
    if x == 3 { throw Failure.empty }
    return x &* 9
}

// Async throws: the error goes to the caller's continuation in x20 (r13), not in the error
// register, and the caller reaches the callee by a tail call. The analyzer counts these and
// leaves them alone; the continuation tests its entry x20, which the decompiler keeps.
@inline(never)
public func asyncThrow(_ x: Int) async throws -> Int {
    if x < 0 { throw Failure.empty }
    return x &* 2
}

@inline(never)
public func callAsync(_ x: Int) async -> Int {
    do {
        return try await asyncThrow(x)
    } catch {
        return -10
    }
}

@inline(never)
public func asyncTyped(_ x: Int) async throws(ParseError) -> Int {
    if x < 0 { throw ParseError(code: x) }
    return x &+ 3
}

@inline(never)
public func callAsyncTyped(_ x: Int) async -> Int {
    do {
        return try await asyncTyped(x)
    } catch {
        return error.code
    }
}
