import Foundation

/// Armored bundles (SPEC.md 4.1): the bundle bytes as base64 text between BEGIN and END lines, so mail filters that
/// block encrypted attachments let them through.
public enum CipherLogArmor {
    public static let beginLine = "-----BEGIN CIPHERLOG BUNDLE-----"
    public static let endLine = "-----END CIPHERLOG BUNDLE-----"
    /// File extension of an armored bundle: `cipherlogs.txt`.
    public static let fileExtension = "cipherlogs.txt"
    static let lineLength = 76

    public enum Error: Swift.Error, Equatable, Sendable, CustomStringConvertible {
        case missingBegin
        case missingEnd
        /// `line` counts from 1 at the first line after BEGIN, blank lines included.
        case notBase64(line: Int)
        /// The base64 between the markers has a length that is not a multiple of 4 or `=` before its end.
        case badPadding

        public var description: String {
            switch self {
            case .missingBegin: return "armor: no \(CipherLogArmor.beginLine) line"
            case .missingEnd: return "armor: no \(CipherLogArmor.endLine) line"
            case .notBase64(let line): return "armor: line \(line) after BEGIN is not base64"
            case .badPadding: return "armor: base64 is cut or badly padded"
            }
        }
    }

    /// BEGIN line, base64 (standard alphabet, padded) in lines of 76 characters, END line; every line ends with `\n`.
    public static func armor(_ bundle: Data) -> String {
        let b64 = bundle.base64EncodedString()
        var out = beginLine + "\n"
        out.reserveCapacity(b64.count + b64.count / lineLength + 80)
        var i = b64.startIndex
        while i < b64.endIndex {
            let end = b64.index(i, offsetBy: lineLength, limitedBy: b64.endIndex) ?? b64.endIndex
            out += b64[i..<end]
            out += "\n"
            i = end
        }
        out += endLine + "\n"
        return out
    }

    /// Whether `data` holds a BEGIN line: a line that is exactly the marker once space, tab and `\r` around it are
    /// removed. One pass over the bytes in place; nothing is stored per line, so hostile input (megabytes of empty
    /// lines) costs no memory.
    public static func looksArmored(_ data: Data) -> Bool {
        data.withUnsafeBytes { afterBegin($0) != nil }
    }

    /// The bundle bytes of an armored text (SPEC.md 4.1). Lines end at `\n`; space, tab and `\r` around a line are
    /// ignored. The BEGIN line is the first line that is exactly the marker (text before it is a mail body and may be
    /// any bytes). Every line after it up to the END line is empty or base64; the base64 of all lines together must be
    /// padded correctly. Non-canonical padding bits are accepted. Lines are scanned in place, one at a time.
    public static func dearmor(_ data: Data) throws -> Data {
        try data.withUnsafeBytes { (p: UnsafeRawBufferPointer) throws -> Data in
            guard var pos = afterBegin(p) else { throw Error.missingBegin }
            let end = Array(endLine.utf8)
            var b64: [UInt8] = []
            b64.reserveCapacity(max(0, p.count - pos))
            var n = 0
            while pos <= p.count {
                n += 1
                let lineEnd = Self.lineEnd(p, from: pos)
                let line = trimmed(p, pos, lineEnd)
                if equals(p, line, end) {
                    guard paddedCorrectly(b64), let bytes = Data(base64Encoded: Data(b64)) else { throw Error.badPadding }
                    return bytes
                }
                for i in line where !isBase64(p[i]) { throw Error.notBase64(line: n) }
                b64.append(contentsOf: p[line])
                pos = lineEnd + 1
            }
            throw Error.missingEnd
        }
    }

    /// The offset just after the BEGIN line (after its `\n`, or `count + 1` when it is the last line), or nil. Lines
    /// are the pieces between `\n`s, the piece after the last one included.
    static func afterBegin(_ p: UnsafeRawBufferPointer) -> Int? {
        let begin = Array(beginLine.utf8)
        var pos = 0
        while pos <= p.count {
            let lineEnd = lineEnd(p, from: pos)
            if lineEnd - pos >= begin.count, equals(p, trimmed(p, pos, lineEnd), begin) { return lineEnd + 1 }
            pos = lineEnd + 1
        }
        return nil
    }

    /// The index of the next `\n` at or after `from`, or `p.count`.
    static func lineEnd(_ p: UnsafeRawBufferPointer, from: Int) -> Int {
        guard from < p.count, let base = p.baseAddress,
              let hit = memchr(base + from, 0x0A, p.count - from) else { return p.count }
        return base.distance(to: UnsafeRawPointer(hit))
    }

    /// `a..<b` without space, tab and `\r` at its ends.
    static func trimmed(_ p: UnsafeRawBufferPointer, _ a: Int, _ b: Int) -> Range<Int> {
        var a = a, b = b
        while a < b, isBlank(p[a]) { a += 1 }
        while b > a, isBlank(p[b - 1]) { b -= 1 }
        return a..<b
    }

    static func equals(_ p: UnsafeRawBufferPointer, _ line: Range<Int>, _ text: [UInt8]) -> Bool {
        line.count == text.count && zip(line, text).allSatisfy { p[$0] == $1 }
    }

    /// A length that is a multiple of 4 and `=` only as the last one or two characters.
    static func paddedCorrectly(_ b64: [UInt8]) -> Bool {
        let pad = UInt8(ascii: "=")
        guard b64.count % 4 == 0 else { return false }
        let padding = b64.reversed().prefix { $0 == pad }.count
        return padding <= 2 && !b64.dropLast(padding).contains(pad)
    }

    static func isBlank(_ c: UInt8) -> Bool { c == 0x20 || c == 0x09 || c == 0x0D }

    static func isBase64(_ c: UInt8) -> Bool {
        switch c {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "+"), UInt8(ascii: "/"), UInt8(ascii: "="):
            return true
        default: return false
        }
    }
}
