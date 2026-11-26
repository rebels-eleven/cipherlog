import CryptoKit
import Foundation
import XCTest
@testable import CipherLog

final class VectorTests: XCTestCase {
    var header: [String: Any] { Fixtures.records["header"] as! [String: Any] }
    var fileKey: SymmetricKey { SymmetricKey(data: Data(hex: header["fileKey"] as! String)!) }
    var fileId: Data { Data(hex: header["fileId"] as! String)! }

    func testKeyId() throws {
        XCTAssertEqual(Fixtures.key.keyIdHex, Fixtures.testKeyJSON["keyId"] as? String)
        XCTAssertEqual(Fixtures.key.keyIdHex, Fixtures.records["keyId"] as? String)
    }

    func testInfo() {
        XCTAssertEqual(Format.info(keyId: Fixtures.key.keyId).hex, header["info"] as? String)
    }

    func testHeaderOpens() throws {
        let data = Data(hex: header["hex"] as! String)!
        XCTAssertEqual(data.count, 118)
        let p = try CipherLogReader.openHeader(data, privateKey: Fixtures.privateKey)
        XCTAssertEqual(p.fileKey.hex, header["fileKey"] as? String)
        XCTAssertEqual(p.fileId.hex, header["fileId"] as? String)
        XCTAssertEqual(p.createdAt, (header["createdAt"] as! NSNumber).uint64Value)
        XCTAssertEqual(Int(p.platform), header["platform"] as? Int)
        XCTAssertEqual(Int(p.process), header["process"] as? Int)
    }

    func testHeaderSealsAndOpensBack() throws {
        let plain = Format.HeaderPlain(fileKey: Data(repeating: 7, count: 32), fileId: Data(repeating: 9, count: 16),
                                       createdAt: 1_795_000_000_123, platform: 1, process: 2)
        let h = try Format.sealHeader(plain, key: Fixtures.key)
        XCTAssertEqual(h.count, 118)
        XCTAssertEqual(h.prefix(4), Data("CPL1".utf8))
        XCTAssertEqual(h.subdata(in: 4..<12), Fixtures.key.keyId)
        XCTAssertEqual(try CipherLogReader.openHeader(h, privateKey: Fixtures.privateKey), plain)
        // Tampered header does not open.
        var bad = h
        bad[60] ^= 1
        XCTAssertThrowsError(try CipherLogReader.openHeader(bad, privateKey: Fixtures.privateKey))
    }

    /// SPEC.md 2.1: a createdAt above 2^53 - 1 counts as a header that does not open.
    func testCreatedAtAboveTwoToThe53DoesNotOpen() throws {
        for createdAt: UInt64 in [(1 << 53) - 1, 1 << 53, .max] {
            let plain = Format.HeaderPlain(fileKey: Data(repeating: 7, count: 32), fileId: Data(repeating: 9, count: 16),
                                           createdAt: createdAt, platform: 1, process: 2)
            let h = try Format.sealHeader(plain, key: Fixtures.key)
            let opened = try? CipherLogReader.openHeader(h, privateKey: Fixtures.privateKey)
            XCTAssertEqual(opened != nil, createdAt == (1 << 53) - 1, "\(createdAt)")
        }
    }

    func testRecordsEncryptByteExact() throws {
        for case let r as [String: Any] in Fixtures.records["records"] as! [Any] {
            let sealed = try Format.sealRecord(fileKey: fileKey, fileId: fileId, seq: UInt32(r["seq"] as! Int),
                                               flags: UInt8(r["flags"] as! Int),
                                               plaintext: Data(hex: r["plaintext"] as! String)!)
            XCTAssertEqual(sealed.hex, r["record"] as? String, r["name"] as! String)
        }
    }

    func testRecordsDecrypt() throws {
        for case let r as [String: Any] in Fixtures.records["records"] as! [Any] {
            let data = Data(hex: r["record"] as! String)!
            switch Format.openRecord(data, fileKey: fileKey, fileId: fileId, expectedSeq: UInt32(r["seq"] as! Int)) {
            case .success(let o):
                XCTAssertEqual(o.plaintext.hex, r["plaintext"] as? String)
                XCTAssertEqual(Int(o.flags), r["flags"] as? Int)
                XCTAssertEqual(o.size, data.count)
            case .failure(let f):
                XCTFail("\(r["name"]!): \(f)")
            }
        }
    }

    func testRejections() throws {
        let cases = Fixtures.records["rejections"] as! [[String: Any]]
        XCTAssertGreaterThanOrEqual(cases.count, 9)
        for r in cases {
            let data = Data(hex: r["record"] as! String)!
            if case .success = Format.openRecord(data, fileKey: fileKey, fileId: fileId,
                                                 expectedSeq: UInt32(r["seq"] as! Int)) {
                XCTFail("accepted: \(r["name"]!)")
            }
        }
    }

    func testRejectionReasons() throws {
        let cases = Dictionary(uniqueKeysWithValues: (Fixtures.records["rejections"] as! [[String: Any]])
            .map { ($0["name"] as! String, $0) })
        func reason(_ name: String) -> Format.RecordFailure? {
            let r = cases[name]!
            if case .failure(let f) = Format.openRecord(Data(hex: r["record"] as! String)!, fileKey: fileKey,
                                                        fileId: fileId, expectedSeq: UInt32(r["seq"] as! Int)) {
                return f
            }
            return nil
        }
        // SPEC.md 5.3 pins the order, so every reader gives the vector's exact reason text.
        for (name, r) in cases {
            XCTAssertEqual(reason(name)?.reason, r["reason"] as? String, name)
        }
        XCTAssertEqual(reason("reserved flag bit"), .reservedFlags(2))
        XCTAssertEqual(reason("wrong expected seq"), .badSeq(got: 0, expected: 1))
        XCTAssertEqual(reason("tag changed"), .authentication)
        XCTAssertEqual(reason("seq changed"), .badSeq(got: 1, expected: 0))
    }

    func testLengthBounds() {
        var tooShort = Data()
        tooShort.appendU32(15); tooShort.appendU32(0); tooShort.append(0); tooShort.append(Data(count: 15))
        XCTAssertEqual(failure(tooShort), .badLength(15))
        var tooLong = Data()
        tooLong.appendU32(65_553); tooLong.appendU32(0); tooLong.append(0)
        XCTAssertEqual(failure(tooLong), .badLength(65_553))
        XCTAssertThrowsError(try Format.sealRecord(fileKey: fileKey, fileId: fileId, seq: 0, flags: 0,
                                                   plaintext: Data(count: 65_537)))
        XCTAssertNoThrow(try Format.sealRecord(fileKey: fileKey, fileId: fileId, seq: 0, flags: 0,
                                               plaintext: Data(count: 65_536)))
        XCTAssertThrowsError(try Format.sealRecord(fileKey: fileKey, fileId: fileId, seq: 0, flags: 2, plaintext: Data()))
    }

    private func failure(_ d: Data) -> Format.RecordFailure? {
        if case .failure(let f) = Format.openRecord(d, fileKey: fileKey, fileId: fileId, expectedSeq: 0) { return f }
        return nil
    }

    func testWholeFileVector() throws {
        let file = Fixtures.records["file"] as! [String: Any]
        let r = try CipherLogReader.open(Data(hex: file["hex"] as! String)!, privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.files.count, 1)
        let f = r.files[0]
        XCTAssertEqual(f.text, file["text"] as? String)
        XCTAssertEqual(f.closed, file["final"] as? Bool)
        XCTAssertEqual(f.records, 3)
        XCTAssertEqual(f.notes, [])
        XCTAssertEqual(f.header?.createdAt, 1_795_000_000_123)
        XCTAssertEqual(f.header?.platform, 1)
        XCTAssertEqual(f.header?.process, 2)
    }

    func testDeflateMatchesVectorPlaintexts() throws {
        // Our zlib with level 6 / -15 / memLevel 8 reproduces the vector pieces (informational: bytes may differ
        // between zlib builds, only records are compared byte for byte).
        let d = try Deflater()
        try d.write(Data("hello cipherlog\n".utf8))
        let p0 = try d.sync()
        try d.write(Data("bye\n".utf8))
        let p1 = try d.finish()
        let recs = Fixtures.records["records"] as! [[String: Any]]
        XCTAssertEqual(p0.hex, recs[0]["plaintext"] as? String)
        XCTAssertEqual(p1.hex, recs[2]["plaintext"] as? String)
    }
}
