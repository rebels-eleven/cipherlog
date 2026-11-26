import Foundation

/// Log levels (SPEC.md 2.4).
public enum CipherLogLevel: Int, Sendable, Comparable, CaseIterable {
    case debug = 0, info, notice, warning, error, fault

    public var letter: String {
        switch self {
        case .debug: return "D"
        case .info: return "I"
        case .notice: return "N"
        case .warning: return "W"
        case .error: return "E"
        case .fault: return "F"
        }
    }

    public static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
}

/// Line formatting (SPEC.md 2.4). Pure functions.
enum LineFormat {
    /// `2026-11-26T10:00:00.123Z`
    static func time(_ ms: UInt64) -> String {
        var t = time_t(ms / 1000)
        var tm = tm()
        gmtime_r(&t, &tm)
        return String(format: "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                      Int(tm.tm_year) + 1900, Int(tm.tm_mon) + 1, Int(tm.tm_mday),
                      Int(tm.tm_hour), Int(tm.tm_min), Int(tm.tm_sec), Int(ms % 1000))
    }

    /// `yyyyMMdd-HHmm` in UTC, for export names.
    static func stamp(_ ms: UInt64) -> String {
        var t = time_t(ms / 1000)
        var tm = tm()
        gmtime_r(&t, &tm)
        return String(format: "%04d%02d%02d-%02d%02d", Int(tm.tm_year) + 1900, Int(tm.tm_mon) + 1,
                      Int(tm.tm_mday), Int(tm.tm_hour), Int(tm.tm_min))
    }

    /// Newlines (`\r\n`, `\r`, `\n`) become the two characters `\n`; other C0 controls except tab, DEL and C1
    /// controls become U+FFFD.
    static func field(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        var it = s.unicodeScalars.makeIterator()
        var pending: Unicode.Scalar? = it.next()
        while let c = pending {
            pending = it.next()
            switch c.value {
            case 0x0D:
                out.append("\\"); out.append("n")
                if pending == "\n" { pending = it.next() }
            case 0x0A:
                out.append("\\"); out.append("n")
            case 0x09:
                out.append(c)
            case 0x00...0x1F, 0x7F, 0x80...0x9F:
                out.append("\u{FFFD}")
            default:
                out.append(c)
            }
        }
        return String(out)
    }

    /// `[A-Za-z0-9._-]`, at most 32 characters, others become `_`.
    static func name(_ s: String, empty: String) -> String {
        if s.isEmpty { return empty }
        var out = ""
        for c in s.unicodeScalars.prefix(32) {
            switch c {
            case "A"..."Z", "a"..."z", "0"..."9", ".", "_", "-": out.unicodeScalars.append(c)
            default: out.append("_")
            }
        }
        return out
    }

    static func line(time ms: UInt64, level: CipherLogLevel, process: String, category: String, message: String) -> String {
        "\(time(ms)) \(level.letter) \(process) \(category): \(field(message))\n"
    }
}
