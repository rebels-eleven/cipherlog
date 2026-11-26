import CryptoKit
import Foundation

/// Why a key string (SPEC.md 1.1) was rejected. The messages never contain a private key or any part of it.
public enum CipherLogKeyError: Error, Equatable, Sendable, LocalizedError, CustomStringConvertible {
    /// Nothing but whitespace.
    case empty
    /// A private key string was given where the public key belongs. Ship only the public key in an app.
    case privateKeyGiven
    /// A public key string was given where the private key belongs.
    case publicKeyGiven
    /// The string does not start with the expected prefix (`cipherlog-pub-v1:` or `cipherlog-priv-v1:`).
    case wrongPrefix(expected: String)
    /// The part after the prefix is not 64 characters long.
    case wrongLength(expected: Int, got: Int)
    /// A character after the prefix is not a hex digit. `position` counts from 1 after the prefix. `character` is
    /// nil for private keys, which are never echoed.
    case notHex(position: Int, character: String?)
    /// 32 bytes that CryptoKit does not accept as an X25519 key.
    case invalidKey

    public var description: String {
        switch self {
        case .empty:
            return "cipherlog key: the key string is empty"
        case .privateKeyGiven:
            return "cipherlog key: this is a PRIVATE key (cipherlog-priv-v1:…); an app ships only the public key (cipherlog-pub-v1:…)"
        case .publicKeyGiven:
            return "cipherlog key: this is a public key (cipherlog-pub-v1:…); opening logs needs the private key (cipherlog-priv-v1:…)"
        case .wrongPrefix(let expected):
            return "cipherlog key: the key string must start with \(expected)"
        case .wrongLength(let expected, let got):
            return "cipherlog key: expected \(expected) hex characters after the prefix, got \(got)"
        case .notHex(let position, let character):
            if let character {
                return "cipherlog key: character \(position) after the prefix is not a hex digit (\(character))"
            }
            return "cipherlog key: character \(position) after the prefix is not a hex digit"
        case .invalidKey:
            return "cipherlog key: not a valid X25519 key"
        }
    }

    public var errorDescription: String? { description }
}

/// Key strings (SPEC.md 1.1): `cipherlog-pub-v1:<64 hex>` and `cipherlog-priv-v1:<64 hex>`.
enum KeyString {
    static let publicPrefix = "cipherlog-pub-v1:"
    static let privatePrefix = "cipherlog-priv-v1:"

    /// The 32 key bytes of `string`. Space, tab, CR and LF around the key are ignored; anything else around it is an
    /// error (SPEC.md 1.1).
    static func parse(_ string: String, isPrivate: Bool) throws -> Data {
        let s = trimmed(string)
        if s.isEmpty { throw CipherLogKeyError.empty }
        let prefix = isPrivate ? privatePrefix : publicPrefix
        let other = isPrivate ? publicPrefix : privatePrefix
        // Compared by Unicode scalars: String comparison would ignore some invisible characters (U+FEFF).
        guard s.unicodeScalars.starts(with: prefix.unicodeScalars) else {
            if s.unicodeScalars.starts(with: other.unicodeScalars) { throw isPrivate ? CipherLogKeyError.publicKeyGiven : CipherLogKeyError.privateKeyGiven }
            throw CipherLogKeyError.wrongPrefix(expected: prefix)
        }
        let body = Array(s.unicodeScalars.dropFirst(prefix.unicodeScalars.count))
        for (i, c) in body.enumerated() where !isHexDigit(c) {
            // Only a public key's character is echoed; it is not secret.
            throw CipherLogKeyError.notHex(position: i + 1, character: isPrivate ? nil : escaped(c))
        }
        guard body.count == 64 else { throw CipherLogKeyError.wrongLength(expected: 64, got: body.count) }
        guard let data = Data(hex: String(String.UnicodeScalarView(body))), data.count == 32 else {
            throw CipherLogKeyError.wrongLength(expected: 64, got: body.count)
        }
        return data
    }

    /// `string` without space, tab, CR and LF at its ends. Other whitespace (a no-break space, a byte order mark) stays
    /// and is reported like any other wrong character.
    static func trimmed(_ string: String) -> String {
        var scalars = Substring(string).unicodeScalars
        let blank: (Unicode.Scalar) -> Bool = { $0 == " " || $0 == "\t" || $0 == "\r" || $0 == "\n" }
        while let c = scalars.first, blank(c) { scalars = scalars.dropFirst() }
        while let c = scalars.last, blank(c) { scalars = scalars.dropLast() }
        return String(scalars)
    }

    static func isHexDigit(_ c: Unicode.Scalar) -> Bool {
        switch c {
        case "0"..."9", "a"..."f", "A"..."F": return true
        default: return false
        }
    }

    /// A printable form of one character for an error message (control and invisible characters as `U+XXXX`).
    static func escaped(_ c: Unicode.Scalar) -> String {
        if c.isASCII, c.value >= 0x21, c.value < 0x7F { return "\"\(Character(c))\"" }
        return String(format: "U+%04X", c.value)
    }
}

extension CipherLogKey {
    /// Parses a public key string `cipherlog-pub-v1:<64 hex>` (SPEC.md 1.1). Throws `CipherLogKeyError`, whose
    /// message names the problem.
    public init(string: String) throws {
        let raw = try KeyString.parse(string, isPrivate: false)
        do {
            try self.init(publicKey: raw)
        } catch {
            throw CipherLogKeyError.invalidKey
        }
    }

    /// `cipherlog-pub-v1:<64 lowercase hex>`.
    public var string: String { KeyString.publicPrefix + publicKey.hex }

    /// True for the test key of `vectors/test-key.json`. An app should have a test that fails when its key is the
    /// test key (SPEC.md 1).
    public var isTestKey: Bool { keyId == CipherLogKey.testKeyId }

    /// The `keyId` of `vectors/test-key.json` (anyone can read logs written to that key). The library embeds only
    /// this id, not the key; 64 bits of SHA-256 are plenty to tell the test key apart.
    static let testKeyId = Data(hex: "dacb47e7a1ba0cf1")!
}

extension CipherLogReader {
    /// Parses a private key string `cipherlog-priv-v1:<64 hex>` (SPEC.md 1.1) into the 32 raw bytes `open` takes.
    /// Errors never echo the key.
    public static func privateKey(string: String) throws -> Data {
        let raw = try KeyString.parse(string, isPrivate: true)
        guard (try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw)) != nil else {
            throw CipherLogKeyError.invalidKey
        }
        return raw
    }
}
