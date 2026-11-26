import CoreGraphics
import Foundation
import os

/// Privacy of one interpolated value, like `OSLogPrivacy`. `.auto` follows os_log: strings and objects are
/// private, numbers and Bool are public. Private values are written as `<private>`.
public struct CipherLogPrivacy: Sendable, Equatable {
    enum Kind: Sendable { case `public`, `private`, auto }
    let kind: Kind

    public static let `public` = CipherLogPrivacy(kind: .public)
    public static let `private` = CipherLogPrivacy(kind: .private)
    public static let auto = CipherLogPrivacy(kind: .auto)
    /// Same as `.private` here.
    public static let sensitive = CipherLogPrivacy(kind: .private)

    /// Accepted for source compatibility with os.Logger call sites; the file gets `<private>` (no hash).
    public static func `private`(mask: Mask) -> CipherLogPrivacy { .private }
    public static func sensitive(mask: Mask) -> CipherLogPrivacy { .private }
    public static func auto(mask: Mask) -> CipherLogPrivacy { .auto }

    public struct Mask: Sendable, Equatable {
        let raw: UInt8
        public static let hash = Mask(raw: 1)
        public static let none = Mask(raw: 0)
    }

    func isPublic(defaultPublic: Bool) -> Bool {
        switch kind {
        case .public: return true
        case .private: return false
        case .auto: return defaultPublic
        }
    }
}

/// Integer formatting, like `OSLogIntegerFormatting`. Without a `format:` the value is written as `description`.
public struct CipherLogIntegerFormatting: Sendable {
    enum Radix: Sendable { case decimal, hex, octal }
    let radix: Radix
    let explicitPositiveSign: Bool
    let includePrefix: Bool
    let uppercase: Bool
    let minDigits: Int

    public static let decimal = CipherLogIntegerFormatting(radix: .decimal, explicitPositiveSign: false,
                                                           includePrefix: false, uppercase: false, minDigits: 0)
    public static let hex = CipherLogIntegerFormatting(radix: .hex, explicitPositiveSign: false,
                                                       includePrefix: false, uppercase: false, minDigits: 0)
    public static let octal = CipherLogIntegerFormatting(radix: .octal, explicitPositiveSign: false,
                                                         includePrefix: false, uppercase: false, minDigits: 0)

    public static func decimal(explicitPositiveSign: Bool = false,
                               minDigits: @autoclosure () -> Int = 0) -> CipherLogIntegerFormatting {
        .init(radix: .decimal, explicitPositiveSign: explicitPositiveSign, includePrefix: false, uppercase: false,
              minDigits: minDigits())
    }

    public static func hex(explicitPositiveSign: Bool = false, includePrefix: Bool = false, uppercase: Bool = false,
                           minDigits: @autoclosure () -> Int = 0) -> CipherLogIntegerFormatting {
        .init(radix: .hex, explicitPositiveSign: explicitPositiveSign, includePrefix: includePrefix,
              uppercase: uppercase, minDigits: minDigits())
    }

    public static func octal(explicitPositiveSign: Bool = false, includePrefix: Bool = false, uppercase: Bool = false,
                             minDigits: @autoclosure () -> Int = 0) -> CipherLogIntegerFormatting {
        .init(radix: .octal, explicitPositiveSign: explicitPositiveSign, includePrefix: includePrefix,
              uppercase: uppercase, minDigits: minDigits())
    }

    /// Like printf: hex and octal show a negative value as its two's complement bit pattern.
    func format<T: BinaryInteger>(_ value: T) -> String {
        var digits: String
        var sign = ""
        switch radix {
        case .decimal:
            digits = String(value.magnitude)
            if value < 0 { sign = "-" } else if explicitPositiveSign { sign = "+" }
        case .hex, .octal:
            let r = radix == .hex ? 16 : 8
            if value < 0 {
                let width = value.bitWidth
                let bits = UInt64(truncatingIfNeeded: value) & (width >= 64 ? .max : (UInt64(1) << UInt64(width)) - 1)
                digits = String(bits, radix: r, uppercase: uppercase)
            } else {
                digits = String(value, radix: r, uppercase: uppercase)
                if explicitPositiveSign { sign = "+" }
            }
        }
        if digits.count < minDigits { digits = String(repeating: "0", count: minDigits - digits.count) + digits }
        let prefix = !includePrefix ? "" : radix == .hex ? (uppercase ? "0X" : "0x") : radix == .octal ? "0" : ""
        return sign + prefix + digits
    }
}

/// Floating-point formatting, like `OSLogFloatFormatting`. Without a `format:` the value is written as `description`.
public struct CipherLogFloatFormatting: Sendable {
    enum Style: Sendable { case fixed, hex, exponential, hybrid }
    let style: Style
    let precision: Int?
    let explicitPositiveSign: Bool
    let uppercase: Bool

    public static let fixed = CipherLogFloatFormatting(style: .fixed, precision: nil, explicitPositiveSign: false, uppercase: false)
    public static let hex = CipherLogFloatFormatting(style: .hex, precision: nil, explicitPositiveSign: false, uppercase: false)
    public static let exponential = CipherLogFloatFormatting(style: .exponential, precision: nil, explicitPositiveSign: false, uppercase: false)
    public static let hybrid = CipherLogFloatFormatting(style: .hybrid, precision: nil, explicitPositiveSign: false, uppercase: false)

    public static func fixed(precision: @autoclosure () -> Int, explicitPositiveSign: Bool = false,
                             uppercase: Bool = false) -> CipherLogFloatFormatting {
        .init(style: .fixed, precision: precision(), explicitPositiveSign: explicitPositiveSign, uppercase: uppercase)
    }

    public static func fixed(explicitPositiveSign: Bool = false, uppercase: Bool = false) -> CipherLogFloatFormatting {
        .init(style: .fixed, precision: nil, explicitPositiveSign: explicitPositiveSign, uppercase: uppercase)
    }

    public static func hex(explicitPositiveSign: Bool = false, uppercase: Bool = false) -> CipherLogFloatFormatting {
        .init(style: .hex, precision: nil, explicitPositiveSign: explicitPositiveSign, uppercase: uppercase)
    }

    public static func exponential(precision: @autoclosure () -> Int, explicitPositiveSign: Bool = false,
                                   uppercase: Bool = false) -> CipherLogFloatFormatting {
        .init(style: .exponential, precision: precision(), explicitPositiveSign: explicitPositiveSign, uppercase: uppercase)
    }

    public static func exponential(explicitPositiveSign: Bool = false, uppercase: Bool = false) -> CipherLogFloatFormatting {
        .init(style: .exponential, precision: nil, explicitPositiveSign: explicitPositiveSign, uppercase: uppercase)
    }

    public static func hybrid(precision: @autoclosure () -> Int, explicitPositiveSign: Bool = false,
                              uppercase: Bool = false) -> CipherLogFloatFormatting {
        .init(style: .hybrid, precision: precision(), explicitPositiveSign: explicitPositiveSign, uppercase: uppercase)
    }

    public static func hybrid(explicitPositiveSign: Bool = false, uppercase: Bool = false) -> CipherLogFloatFormatting {
        .init(style: .hybrid, precision: nil, explicitPositiveSign: explicitPositiveSign, uppercase: uppercase)
    }

    func format(_ value: Double) -> String {
        let conversion: String
        switch style {
        case .fixed: conversion = uppercase ? "F" : "f"
        case .hex: conversion = uppercase ? "A" : "a"
        case .exponential: conversion = uppercase ? "E" : "e"
        case .hybrid: conversion = uppercase ? "G" : "g"
        }
        let spec = "%" + (explicitPositiveSign ? "+" : "") + (precision.map { ".\(max(0, min($0, 64)))" } ?? "") + conversion
        return String(format: spec, value)
    }
}

/// Bool formatting, like `OSLogBoolFormat`: `.truth` gives `true`/`false`, `.answer` gives `YES`/`NO`.
public struct CipherLogBoolFormat: Sendable, Equatable {
    let answer: Bool
    public static let truth = CipherLogBoolFormat(answer: false)
    public static let answer = CipherLogBoolFormat(answer: true)
}

/// Column alignment, like `OSLogStringAlignment`: pads the value with spaces to `columns` characters.
public struct CipherLogStringAlignment: Sendable {
    let columns: Int
    let left: Bool

    public static let none = CipherLogStringAlignment(columns: 0, left: false)

    public static func left(columns: @autoclosure () -> Int) -> CipherLogStringAlignment {
        .init(columns: columns(), left: true)
    }

    public static func right(columns: @autoclosure () -> Int) -> CipherLogStringAlignment {
        .init(columns: columns(), left: false)
    }

    func apply(_ s: String) -> String {
        let pad = columns - s.count
        guard pad > 0 else { return s }
        let spaces = String(repeating: " ", count: pad)
        return left ? s + spaces : spaces + s
    }
}

/// A log message built by string interpolation, like `OSLogMessage`. Holds the redacted text (for the file) and the
/// full text (for os.Logger in debug builds when `systemLogFullText` is on).
public struct CipherLogMessage: ExpressibleByStringInterpolation, ExpressibleByStringLiteral, Sendable {
    /// What goes to the file: non-public values replaced with `<private>`.
    public let redacted: String
    /// Every value in full.
    public let full: String

    public init(stringLiteral value: String) {
        redacted = value
        full = value
    }

    public init(stringInterpolation: StringInterpolation) {
        redacted = stringInterpolation.redacted
        full = stringInterpolation.full
    }

    /// The interpolation shapes of `OSLogInterpolation` (`privacy:`, `format:`, `align:` in that order), plus
    /// `Error`, `Optional` and `Substring`, which os.Logger does not take.
    public struct StringInterpolation: StringInterpolationProtocol {
        var redacted = ""
        var full = ""

        public init(literalCapacity: Int, interpolationCount: Int) {
            redacted.reserveCapacity(literalCapacity + interpolationCount * 9)
            full.reserveCapacity(literalCapacity + interpolationCount * 8)
        }

        public mutating func appendLiteral(_ literal: String) {
            redacted += literal
            full += literal
        }

        mutating func add(_ text: String, _ privacy: CipherLogPrivacy, defaultPublic: Bool,
                          align: CipherLogStringAlignment = .none) {
            full += align.apply(text)
            redacted += align.apply(privacy.isPublic(defaultPublic: defaultPublic) ? text : "<private>")
        }

        // Strings and objects: private by default.
        public mutating func appendInterpolation(_ value: String, align: CipherLogStringAlignment = .none,
                                                 privacy: CipherLogPrivacy = .auto) {
            add(value, privacy, defaultPublic: false, align: align)
        }

        public mutating func appendInterpolation(_ value: Substring, align: CipherLogStringAlignment = .none,
                                                 privacy: CipherLogPrivacy = .auto) {
            add(String(value), privacy, defaultPublic: false, align: align)
        }

        public mutating func appendInterpolation<T: CustomStringConvertible>(_ value: T,
                                                                             align: CipherLogStringAlignment = .none,
                                                                             privacy: CipherLogPrivacy = .auto) {
            add(value.description, privacy, defaultPublic: CipherLogMessage.isNumeric(value), align: align)
        }

        public mutating func appendInterpolation<E: Error>(_ value: E, privacy: CipherLogPrivacy = .auto) {
            add(String(describing: value), privacy, defaultPublic: false)
        }

        public mutating func appendInterpolation<E: Error & CustomStringConvertible>(_ value: E,
                                                                                     align: CipherLogStringAlignment = .none,
                                                                                     privacy: CipherLogPrivacy = .auto) {
            add(value.description, privacy, defaultPublic: false, align: align)
        }

        public mutating func appendInterpolation(_ value: any Error, privacy: CipherLogPrivacy = .auto) {
            add(String(describing: value), privacy, defaultPublic: false)
        }

        public mutating func appendInterpolation(_ value: Any.Type, align: CipherLogStringAlignment = .none,
                                                 privacy: CipherLogPrivacy = .auto) {
            add(String(describing: value), privacy, defaultPublic: false, align: align)
        }

        /// Optional values print `nil` or the value; numbers and Bool inside are public by default.
        public mutating func appendInterpolation<T>(_ value: T?, privacy: CipherLogPrivacy = .auto) {
            switch value {
            case .some(let v): add(String(describing: v), privacy, defaultPublic: CipherLogMessage.isNumeric(v))
            case .none: add("nil", privacy, defaultPublic: true)
            }
        }

        // Numbers and Bool: public by default.
        public mutating func appendInterpolation(_ value: Int, format: CipherLogIntegerFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            integer(value, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: Int8, format: CipherLogIntegerFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            integer(value, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: Int16, format: CipherLogIntegerFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            integer(value, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: Int32, format: CipherLogIntegerFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            integer(value, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: Int64, format: CipherLogIntegerFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            integer(value, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: UInt, format: CipherLogIntegerFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            integer(value, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: UInt8, format: CipherLogIntegerFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            integer(value, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: UInt16, format: CipherLogIntegerFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            integer(value, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: UInt32, format: CipherLogIntegerFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            integer(value, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: UInt64, format: CipherLogIntegerFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            integer(value, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: Double, format: CipherLogFloatFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            float(value, value.description, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: Float, format: CipherLogFloatFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            float(Double(value), value.description, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: CGFloat, format: CipherLogFloatFormatting? = nil,
                                                 align: CipherLogStringAlignment = .none, privacy: CipherLogPrivacy = .auto) {
            float(Double(value), value.description, format, align, privacy)
        }
        public mutating func appendInterpolation(_ value: Bool, format: CipherLogBoolFormat = .truth,
                                                 privacy: CipherLogPrivacy = .auto) {
            let text = format.answer ? (value ? "YES" : "NO") : (value ? "true" : "false")
            add(text, privacy, defaultPublic: true)
        }

        mutating func integer<T: BinaryInteger & CustomStringConvertible>(
            _ value: T, _ format: CipherLogIntegerFormatting?, _ align: CipherLogStringAlignment, _ privacy: CipherLogPrivacy
        ) {
            add(format?.format(value) ?? value.description, privacy, defaultPublic: true, align: align)
        }

        mutating func float(_ value: Double, _ description: String, _ format: CipherLogFloatFormatting?,
                            _ align: CipherLogStringAlignment, _ privacy: CipherLogPrivacy) {
            add(format?.format(value) ?? description, privacy, defaultPublic: true, align: align)
        }
    }

    static func isNumeric(_ value: Any) -> Bool {
        value is any BinaryInteger || value is any BinaryFloatingPoint || value is Bool
    }
}

/// Drop-in replacement for `os.Logger` (SPEC.md 7.1): `Logger(subsystem:category:)` →
/// `CipherLogger(subsystem:category:)` is the whole migration; the call sites stay. Every message goes to os.Logger
/// as one finished string and, once `CipherLog.start` has run, to the encrypted file, with non-public values as
/// `<private>`. Loggers may be created before the writer starts (for example as static properties): the writer is
/// looked up at every call.
///
/// Sendable: all stored properties are immutable; `os.Logger` is thread-safe.
public struct CipherLogger: @unchecked Sendable {
    public let subsystem: String
    public let category: String
    private let explicitLog: CipherLog?
    private let system: os.Logger

    /// `subsystem` defaults to the main bundle's identifier. Messages go to `CipherLog.shared` when it is started.
    public init(subsystem: String = Bundle.main.bundleIdentifier ?? "-", category: String) {
        self.init(subsystem: subsystem, category: category, log: nil)
    }

    /// Writes to `log` instead of `CipherLog.shared`; `log` nil means `CipherLog.shared`.
    public init(subsystem: String = Bundle.main.bundleIdentifier ?? "-", category: String, log: CipherLog?) {
        self.subsystem = subsystem
        self.category = category
        self.explicitLog = log
        self.system = os.Logger(subsystem: subsystem, category: category)
    }

    /// Like `os.Logger()`: the main bundle's identifier as subsystem, no category (`-` in the file).
    public init() {
        self.init(subsystem: Bundle.main.bundleIdentifier ?? "-", category: "")
    }

    public func log(_ message: CipherLogMessage) { write(.default, .notice, message) }

    public func log(level: OSLogType, _ message: CipherLogMessage) {
        let fileLevel: CipherLogLevel
        switch level {
        case .debug: fileLevel = .debug
        case .info: fileLevel = .info
        case .error: fileLevel = .error
        case .fault: fileLevel = .fault
        default: fileLevel = .notice
        }
        write(level, fileLevel, message)
    }

    public func trace(_ message: CipherLogMessage) { write(.debug, .debug, message) }
    public func debug(_ message: CipherLogMessage) { write(.debug, .debug, message) }
    public func info(_ message: CipherLogMessage) { write(.info, .info, message) }
    public func notice(_ message: CipherLogMessage) { write(.default, .notice, message) }
    public func warning(_ message: CipherLogMessage) { write(.error, .warning, message) }
    public func error(_ message: CipherLogMessage) { write(.error, .error, message) }
    public func critical(_ message: CipherLogMessage) { write(.fault, .fault, message) }
    public func fault(_ message: CipherLogMessage) { write(.fault, .fault, message) }

    private func write(_ type: OSLogType, _ level: CipherLogLevel, _ message: CipherLogMessage) {
        let target = explicitLog ?? CipherLog.shared
        if target?.config.systemLog ?? true {
            let text = target?.config.systemLogFullText == true ? message.full : message.redacted
            system.log(level: type, "\(text, privacy: .public)")
        }
        target?.log(level, category: category, message.redacted)
    }
}
