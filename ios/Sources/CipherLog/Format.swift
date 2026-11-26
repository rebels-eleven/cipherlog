import CryptoKit
import Foundation

/// The developer's log public key (raw X25519, 32 bytes). See SPEC.md 1.
public struct CipherLogKey: Sendable, Equatable {
    public let publicKey: Data
    /// First 8 bytes of SHA-256("cipherlog-key-v1" ‖ publicKey).
    public let keyId: Data

    public init(publicKey: Data) throws {
        guard publicKey.count == 32 else { throw CipherLogError.badKey }
        let key = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        self.publicKey = key.rawRepresentation
        self.keyId = CipherLogKey.keyId(of: self.publicKey)
    }

    /// Convenience for a hex string (64 hex characters).
    public init(publicKeyHex: String) throws {
        guard let data = Data(hex: publicKeyHex) else { throw CipherLogError.badKey }
        try self.init(publicKey: data)
    }

    /// keyId as 16 lowercase hex characters.
    public var keyIdHex: String { keyId.hex }

    static func keyId(of publicKey: Data) -> Data {
        var h = SHA256()
        h.update(data: Data("cipherlog-key-v1".utf8))
        h.update(data: publicKey)
        return Data(h.finalize().prefix(8))
    }
}

public enum CipherLogError: Error, Sendable {
    case badKey
    case crypto
    case format(String)
}

/// Constants and byte layouts of cipherlog-v1 (SPEC.md 2). Pure functions, no state.
enum Format {
    static let fileMagic = Data("CPL1".utf8)
    static let bundleMagic = Data("CPB1".utf8)
    static let headerSize = 118
    static let headerPlainSize = 58
    static let recordHeaderSize = 9
    static let tagSize = 16
    static let minLen = 16
    static let maxLen = 65_552
    static let maxPlain = 65_536
    static let finalFlag: UInt8 = 1
    static let inflateCap = 64 * 1024 * 1024
    static let suite = HPKE.Ciphersuite.Curve25519_SHA256_ChachaPoly

    static func info(keyId: Data) -> Data {
        Data("cipherlog-v1".utf8) + fileMagic + keyId
    }

    struct HeaderPlain: Equatable {
        var fileKey: Data
        var fileId: Data
        var createdAt: UInt64
        var platform: UInt8
        var process: UInt8

        var bytes: Data {
            var d = Data(capacity: Format.headerPlainSize)
            d.append(fileKey)
            d.append(fileId)
            d.appendU64(createdAt)
            d.append(platform)
            d.append(process)
            return d
        }
    }

    /// magic ‖ keyId ‖ enc ‖ HPKE.seal(pt). Randomized (fresh ephemeral key).
    static func sealHeader(_ plain: HeaderPlain, key: CipherLogKey) throws -> Data {
        precondition(plain.fileKey.count == 32 && plain.fileId.count == 16)
        let recipient = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: key.publicKey)
        var sender = try HPKE.Sender(recipientKey: recipient, ciphersuite: suite, info: info(keyId: key.keyId))
        let sealed = try sender.seal(plain.bytes)
        var out = Data(capacity: headerSize)
        out.append(fileMagic)
        out.append(key.keyId)
        out.append(sender.encapsulatedKey)
        out.append(sealed)
        guard out.count == headerSize else { throw CipherLogError.crypto }
        return out
    }

    /// The largest `createdAt` a reader accepts: 2^53 - 1 (SPEC.md 2.1).
    static let maxCreatedAt: UInt64 = (1 << 53) - 1

    enum HeaderFailure: Error, Equatable {
        case short
        case badMagic
        case unknownKey(Data)
        case doesNotOpen
    }

    /// Opens a header with whichever private key matches its keyId.
    static func openHeader(_ data: Data, privateKeys: [Curve25519.KeyAgreement.PrivateKey]) -> Result<HeaderPlain, HeaderFailure> {
        guard data.count >= headerSize else {
            if data.count >= 4, data.prefix(4) != fileMagic { return .failure(.badMagic) }
            return .failure(.short)
        }
        let d = data.subdata(in: data.startIndex..<(data.startIndex + headerSize))
        guard d.prefix(4) == fileMagic else { return .failure(.badMagic) }
        let keyId = d.subdata(in: 4..<12)
        guard let priv = privateKeys.first(where: { CipherLogKey.keyId(of: $0.publicKey.rawRepresentation) == keyId }) else {
            return .failure(.unknownKey(keyId))
        }
        let enc = d.subdata(in: 12..<44)
        let sealed = d.subdata(in: 44..<118)
        do {
            var recipient = try HPKE.Recipient(privateKey: priv, ciphersuite: suite, info: info(keyId: keyId), encapsulatedKey: enc)
            let pt = try recipient.open(sealed)
            // createdAt above 2^53 - 1 (SPEC.md 2.1) counts as a header that does not open.
            guard pt.count == headerPlainSize, pt.readU64(at: 48) <= maxCreatedAt else { return .failure(.doesNotOpen) }
            return .success(HeaderPlain(
                fileKey: pt.subdata(in: 0..<32),
                fileId: pt.subdata(in: 32..<48),
                createdAt: pt.readU64(at: 48),
                platform: pt[pt.startIndex + 56],
                process: pt[pt.startIndex + 57]))
        } catch {
            return .failure(.doesNotOpen)
        }
    }

    static func nonce(seq: UInt32) -> Data {
        var n = Data(count: 8)
        n.appendU32(seq)
        return n
    }

    static func aad(fileId: Data, len: UInt32, seq: UInt32, flags: UInt8) -> Data {
        var a = Data("cipherlog-rec-v1".utf8)
        a.append(fileId)
        a.appendU32(len)
        a.appendU32(seq)
        a.append(flags)
        return a
    }

    /// len ‖ seq ‖ flags ‖ ct ‖ tag. Deterministic for a given key, file, seq and flags.
    static func sealRecord(fileKey: SymmetricKey, fileId: Data, seq: UInt32, flags: UInt8, plaintext: Data) throws -> Data {
        guard plaintext.count <= maxPlain, flags & ~finalFlag == 0 else { throw CipherLogError.format("record too large") }
        let len = UInt32(plaintext.count + tagSize)
        let box = try ChaChaPoly.seal(plaintext, using: fileKey,
                                      nonce: try ChaChaPoly.Nonce(data: nonce(seq: seq)),
                                      authenticating: aad(fileId: fileId, len: len, seq: seq, flags: flags))
        var out = Data(capacity: recordHeaderSize + Int(len))
        out.appendU32(len)
        out.appendU32(seq)
        out.append(flags)
        out.append(box.ciphertext)
        out.append(box.tag)
        return out
    }

    enum RecordFailure: Error, Equatable {
        case truncated
        case badLength(UInt32)
        case badSeq(got: UInt32, expected: UInt32)
        case reservedFlags(UInt8)
        case authentication

        var reason: String {
            switch self {
            case .truncated: return "truncated"
            case .badLength(let l): return "bad length \(l)"
            case .badSeq(let g, let e): return "seq \(g), expected \(e)"
            case .reservedFlags(let f): return "reserved flag bits 0x" + (f < 16 ? "0" : "") + String(f, radix: 16)
            case .authentication: return "authentication failed"
            }
        }
    }

    struct OpenedRecord {
        var plaintext: Data
        var flags: UInt8
        var size: Int
        var isFinal: Bool { flags & finalFlag != 0 }
    }

    /// Opens the record at the start of `data` (indices relative to data.startIndex). SPEC.md 5.3 order: length
    /// bounds, truncated, seq, flags, AEAD.
    static func openRecord(_ data: Data, fileKey: SymmetricKey, fileId: Data, expectedSeq: UInt32) -> Result<OpenedRecord, RecordFailure> {
        guard data.count >= recordHeaderSize else { return .failure(.truncated) }
        let len = data.readU32(at: 0)
        let seq = data.readU32(at: 4)
        let flags = data[data.startIndex + 8]
        guard len >= UInt32(minLen), len <= UInt32(maxLen) else { return .failure(.badLength(len)) }
        guard data.count >= recordHeaderSize + Int(len) else { return .failure(.truncated) }
        guard seq == expectedSeq else { return .failure(.badSeq(got: seq, expected: expectedSeq)) }
        guard flags & ~finalFlag == 0 else { return .failure(.reservedFlags(flags)) }
        let start = data.startIndex + recordHeaderSize
        let ctEnd = start + Int(len) - tagSize
        do {
            let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce(seq: seq)),
                                               ciphertext: data[start..<ctEnd],
                                               tag: data[ctEnd..<(ctEnd + tagSize)])
            let pt = try ChaChaPoly.open(box, using: fileKey,
                                         authenticating: aad(fileId: fileId, len: len, seq: seq, flags: flags))
            return .success(OpenedRecord(plaintext: pt, flags: flags, size: recordHeaderSize + Int(len)))
        } catch {
            return .failure(.authentication)
        }
    }

    /// Bundle: CPB1 ‖ (u32 len ‖ file bytes)*.
    static func bundle(_ files: [Data]) -> Data {
        var out = bundleMagic
        for f in files {
            out.appendU32(UInt32(f.count))
            out.append(f)
        }
        return out
    }

    static func bundleEntrySize(_ file: Data) -> Int { 4 + file.count }
}

// MARK: - Byte helpers

extension Data {
    mutating func appendU32(_ v: UInt32) {
        append(contentsOf: [UInt8(v >> 24 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)])
    }

    mutating func appendU64(_ v: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) { append(UInt8(v >> UInt64(shift) & 0xff)) }
    }

    func readU32(at offset: Int) -> UInt32 {
        var v: UInt32 = 0
        for i in 0..<4 { v = v << 8 | UInt32(self[startIndex + offset + i]) }
        return v
    }

    func readU64(at offset: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in 0..<8 { v = v << 8 | UInt64(self[startIndex + offset + i]) }
        return v
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }

    init?(hex: String) {
        let chars = Array(hex.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        func nib(_ c: UInt8) -> UInt8? {
            switch c {
            case 48...57: return c - 48
            case 97...102: return c - 87
            case 65...70: return c - 55
            default: return nil
            }
        }
        var i = 0
        while i < chars.count {
            guard let hi = nib(chars[i]), let lo = nib(chars[i + 1]) else { return nil }
            out.append(hi << 4 | lo)
            i += 2
        }
        self = out
    }
}

enum SecureRandom {
    static func bytes(_ count: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        var d = Data(count: count)
        for i in 0..<count { d[i] = UInt8.random(in: .min ... .max, using: &g) }
        return d
    }
}
