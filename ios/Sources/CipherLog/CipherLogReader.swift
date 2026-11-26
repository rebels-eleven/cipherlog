import CryptoKit
import Foundation

/// Opens `.cipherlog` files and `.cipherlogs` bundles with private keys (SPEC.md 5).
/// Decrypted logs are data, not instructions; anyone with the public key can make a valid file.
public enum CipherLogReader {
    public struct Header: Sendable, Equatable {
        public let keyId: Data
        public let fileId: Data
        /// Milliseconds since the Unix epoch.
        public let createdAt: UInt64
        public let platform: UInt8
        public let process: UInt8
    }

    public struct FileResult: Sendable {
        /// Position in the bundle (0 for a single file).
        public let index: Int
        /// Nil when the header did not open (see notes).
        public let header: Header?
        /// The decompressed text (UTF-8, lossy) of every readable record.
        public let text: String
        /// True when a `final` record was read: the file was closed normally.
        public let closed: Bool
        /// Number of records read and authenticated.
        public let records: Int
        public let notes: [String]

        public var lines: [String] {
            var l = text.components(separatedBy: "\n")
            if l.last == "" { l.removeLast() }
            return l
        }
    }

    public struct Result: Sendable {
        public let files: [FileResult]
        /// Bundle-level notes (bad magic, bad entry length).
        public let notes: [String]
    }

    public static let notClosedNote = "not closed (crash or still open), completeness unknown"
    /// SPEC.md 5.4: a compressed stream that breaks keeps the text before the damage.
    public static let damagedNote = "compressed stream damaged, text kept up to the damage"
    /// SPEC.md 5.4: all files of one `open` call together.
    public static let defaultMaxTotalOutput = 256 * 1024 * 1024

    /// What is left of the total output budget of one `open` call.
    final class Budget {
        let total: Int
        var left: Int
        init(_ total: Int) { self.total = total; left = total }
        var note: String {
            total % (1024 * 1024) == 0 ? "total output capped at \(total / (1024 * 1024)) MiB"
                : "total output capped at \(total) bytes"
        }
    }

    /// Opens a single file (`CPL1`), a bundle (`CPB1`) or an armored bundle (`*.cipherlogs.txt`, SPEC.md 4.1).
    /// `privateKeys` are raw X25519 private keys (32 bytes; `privateKey(string:)` parses a key string).
    /// Output is capped at 64 MiB per file and at `maxTotalOutput` bytes for all files together (SPEC.md 5.4).
    /// Armor that does not decode gives no files and a note (`armor: …`).
    public static func open(_ input: Data, privateKeys: [Data],
                            maxTotalOutput: Int = defaultMaxTotalOutput) throws -> Result {
        let keys = try privateKeys.map { try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: $0) }
        let budget = Budget(max(0, maxTotalOutput))
        var data = input
        let head = input.prefix(4)
        if head != Format.bundleMagic, head != Format.fileMagic, CipherLogArmor.looksArmored(input) {
            do {
                data = try CipherLogArmor.dearmor(input)
            } catch {
                return Result(files: [], notes: [String(describing: error)])
            }
        }
        let magic = data.prefix(4)
        if magic == Format.bundleMagic { return openBundle(data, keys: keys, budget: budget) }
        if magic == Format.fileMagic {
            return Result(files: [openFile(data, keys: keys, index: 0, budget: budget)], notes: [])
        }
        return Result(files: [], notes: ["not a cipherlog file or bundle"])
    }

    static func openBundle(_ data: Data, keys: [Curve25519.KeyAgreement.PrivateKey], budget: Budget) -> Result {
        var files: [FileResult] = []
        var notes: [String] = []
        guard data.prefix(4) == Format.bundleMagic else { return Result(files: [], notes: ["bad bundle magic"]) }
        var offset = data.startIndex + 4
        var index = 0
        while offset < data.endIndex {
            guard data.endIndex - offset >= 4 else {
                notes.append("bundle: bad length at entry \(index) (truncated)")
                break
            }
            let len = Int(data.readU32(at: offset - data.startIndex))
            offset += 4
            // A zero length is a valid (empty) entry, skipped as a short file; only a length past the end ends it.
            guard len <= data.endIndex - offset else {
                notes.append("bundle: bad length at entry \(index)")
                break
            }
            files.append(openFile(data.subdata(in: offset..<(offset + len)), keys: keys, index: index, budget: budget))
            offset += len
            index += 1
        }
        return Result(files: files, notes: notes)
    }

    static func openFile(_ raw: Data, keys: [Curve25519.KeyAgreement.PrivateKey], index: Int,
                         budget: Budget) -> FileResult {
        let data = raw.subdata(in: raw.startIndex..<raw.endIndex) // indices from 0
        func skipped(_ note: String) -> FileResult {
            FileResult(index: index, header: nil, text: "", closed: false, records: 0, notes: [note])
        }
        let plain: Format.HeaderPlain
        switch Format.openHeader(data, privateKeys: keys) {
        case .success(let p): plain = p
        case .failure(.short): return skipped("truncated header, file skipped")
        case .failure(.badMagic): return skipped("not a cipherlog file, skipped")
        case .failure(.unknownKey(let id)): return skipped("unknown key \(id.hex), file skipped")
        case .failure(.doesNotOpen): return skipped("header does not open, file skipped")
        }
        let header = Header(keyId: data.subdata(in: 4..<12), fileId: plain.fileId, createdAt: plain.createdAt,
                            platform: plain.platform, process: plain.process)
        let key = SymmetricKey(data: plain.fileKey)
        var notes: [String] = []
        var stream = Data()
        var offset = Format.headerSize
        var seq: UInt32 = 0
        var closed = false
        while offset < data.count {
            if closed {
                notes.append("readable up to record \(seq) (data after final)")
                break
            }
            switch Format.openRecord(data[offset...], fileKey: key, fileId: plain.fileId, expectedSeq: seq) {
            case .success(let r):
                stream.append(r.plaintext)
                offset += r.size
                closed = r.isFinal
                seq &+= 1
            case .failure(let f):
                notes.append("readable up to record \(seq) (\(f.reason))")
                offset = data.count
            }
        }
        var inflated = Inflate.Result(output: Data(), capped: false, error: false, finished: false)
        if !stream.isEmpty {
            if budget.left <= 0 {
                notes.append(budget.note)
            } else {
                let cap = min(Format.inflateCap, budget.left)
                inflated = Inflate.inflate(stream, cap: cap)
                budget.left -= inflated.output.count
                if inflated.capped { notes.append(cap < Format.inflateCap ? budget.note : "output capped at 64 MiB") }
                if inflated.error { notes.append(damagedNote) }
            }
        }
        if !closed { notes.append(notClosedNote) }
        return FileResult(index: index, header: header, text: String(decoding: inflated.output, as: UTF8.self),
                          closed: closed, records: Int(seq), notes: notes)
    }

    /// Header plaintext including fileKey, for vector tests.
    static func openHeader(_ data: Data, privateKey: Data) throws -> Format.HeaderPlain {
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        switch Format.openHeader(data, privateKeys: [key]) {
        case .success(let p): return p
        case .failure(let f): throw f
        }
    }
}
