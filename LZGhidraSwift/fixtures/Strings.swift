// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Fixture for the Swift String Literals analyzer. Each function uses string literals in one of the
// code shapes seen in Swift binaries; expected-strings.txt lists the literals per function.
// Build with the Makefile in this directory.

import Foundation

public var sunk: [String] = []

@inline(never)
public func sink(_ s: String) {
    sunk.append(s)
}

// Shape 1: argument pair in x0/x1. Every small length 0-15, and non-ASCII.
@inline(never)
public func argLengths() {
    sink("")
    sink("m")
    sink("Cb")
    sink("dim")
    sink("maj7")
    sink("Sharp")
    sink("chords")
    sink("mixolyd")
    sink("loudness")
    sink("framework")
    sink("resultType")
    sink("beatTracker")
    sink("tempo_change")
    sink("downbeatSnaps")
    sink("nonBeatBonuses")
    sink("harmonyAnalyzer")
}

@inline(never)
public func argNonASCII() {
    sink("é")
    sink("×")
    sink("Füße")
}

// Large literals: __cstring address - 32 with bit 63 set, count and flags in word 0.
@inline(never)
public func argLarge() {
    sink("0123456789abcdef")
    sink("configuration_key")
    sink("a literal of exactly forty bytes, padded")
    sink("Füße über Hände")
}

// Shape 2: stored pair. Dictionary keys with values that are not constants.
@inline(never)
public func features(_ a: Double, _ b: Double, _ c: Double, _ d: Double) -> [String: Double] {
    ["tempo_change": a, "beats": b, "attack": c, "loudness": d]
}

public final class Box {
    public var label = ""
    public var count = 0
    public init() {}
}

@inline(never)
public func fillBox(_ b: Box) {
    b.label = "framework"
}

// Shape 4: comparison with literals.
@inline(never)
public func chordQuality(_ s: String) -> Int {
    switch s {
    case "maj7": return 1
    case "sus2": return 2
    case "m": return 3
    case "dim": return 4
    default: return 0
    }
}

// Returned in x0/x1.
@inline(never)
public func noteName() -> String {
    "C"
}

@inline(never)
public func spelling(_ sharp: Bool) -> String {
    sharp ? "Sharp" : "Flat"
}

public enum Accidental: String {
    case flat = "Flat"
    case sharp = "Sharp"
    case natural = "Natural"
}

@inline(never)
public func accidentalName(_ a: Accidental) -> String {
    a.rawValue
}

// Strings passed to Objective-C (String._bridgeToObjectiveC).
@inline(never)
public func modelURL() -> URL? {
    Bundle.main.url(forResource: "chordModel", withExtension: "mlmodelc")
}

// Not strings: constants with the small-string tag nibble.
public var tagLike: UInt64 = 0
public var simdLike = SIMD2<UInt64>(0, 0)

@inline(never)
public func storeTagLike() {
    tagLike = 0xE400_0000_0000_0000
}

@inline(never)
public func divide(_ x: UInt64) -> UInt64 {
    x / 3 &+ x / 10
}

// Bytes and tag of "abcdefgh"; a reported string here cannot be told apart from a real one.
@inline(never)
public func storeSimd() {
    simdLike = SIMD2<UInt64>(0x6867_6665_6463_6261, 0xE800_0000_0000_0000)
}

// Shape 5: a switch over an enum without payloads, one literal per case. -O on arm64 compiles it to
// a jump through a table of byte offsets (and x8, x0, #0xff; ldrb; add lsl 2; br), with the mask as
// the only bound. Ghidra 12.2 does not recover that table (see known-differences/strings.txt).
public enum Waypoint: CaseIterable {
    case alpha, bravo, charlie, delta, echo, foxtrot, golf, hotel, india, juliett
    case kilo, lima, mike, november, oscar, papa, quebec, romeo, sierra, tango
    case uniform, victor, whiskey, xray, yankee, zulu, one, two, three, four
}

@inline(never)
public func waypointName(_ w: Waypoint) -> String {
    switch w {
    case .alpha: return "alpha"
    case .bravo: return "bravo"
    case .charlie: return "charlie"
    case .delta: return "delta"
    case .echo: return "echo"
    case .foxtrot: return "foxtrot"
    case .golf: return "golf"
    case .hotel: return "hotel"
    case .india: return "india"
    case .juliett: return "juliett"
    case .kilo: return "kilo"
    case .lima: return "lima"
    case .mike: return "mike"
    case .november: return "november"
    case .oscar: return "oscar"
    case .papa: return "papa"
    case .quebec: return "quebec"
    case .romeo: return "romeo"
    case .sierra: return "sierra"
    case .tango: return "tango"
    case .uniform: return "uniform"
    case .victor: return "victor"
    case .whiskey: return "whiskey"
    case .xray: return "xray"
    case .yankee: return "yankee"
    case .zulu: return "zulu"
    case .one: return "one"
    case .two: return "two"
    case .three: return "three"
    case .four: return "four"
    }
}
