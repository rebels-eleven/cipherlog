import CryptoKit
import Foundation
import XCTest
@testable import CipherLog

final class ReaderTests: XCTestCase {
    /// A closed file with one record per line (flush after every log).
    private func writtenFile(lines: Int = 6) throws -> (Data, String) {
        let dir = tempDir()
        let tap = TextTap()
        let log = CipherLog(makeConfig(dir, tap: tap))
        for i in 0..<lines {
            log.log(.info, category: "t", "line \(i)")
            XCTAssertTrue(log.flush(timeout: 5))
        }
        log.close()
        let url = try XCTUnwrap(logFiles(dir).first)
        return (try Data(contentsOf: url), tap.text.get)
    }

    private func read(_ d: Data) throws -> CipherLogReader.FileResult {
        try CipherLogReader.open(d, privateKeys: [Fixtures.privateKey]).files[0]
    }

    func testTruncationAtEveryByteOfLastRecord() throws {
        let (data, _) = try writtenFile()
        let recs = recordOffsets(data)
        XCTAssertGreaterThanOrEqual(recs.count, 4)
        let last = recs[recs.count - 1]
        let before = try read(data.prefix(last.lowerBound))
        XCTAssertFalse(before.closed)
        XCTAssertEqual(before.records, recs.count - 1)
        for cut in last.lowerBound..<last.upperBound {
            let r = try read(Data(data.prefix(cut)))
            XCTAssertFalse(r.closed, "cut \(cut)")
            XCTAssertEqual(r.records, recs.count - 1)
            XCTAssertEqual(r.text, before.text)
            XCTAssertTrue(r.notes.contains(CipherLogReader.notClosedNote))
            if cut > last.lowerBound {
                XCTAssertTrue(r.notes.contains("readable up to record \(recs.count - 1) (truncated)"), "\(cut) \(r.notes)")
            }
        }
        let full = try read(data)
        XCTAssertTrue(full.closed)
        XCTAssertEqual(full.notes, [])
        XCTAssertTrue(full.text.hasPrefix(before.text))
    }

    func testCorruptionInTheMiddleStopsThere() throws {
        let (data, _) = try writtenFile()
        let recs = recordOffsets(data)
        let k = 3
        var bad = data
        bad[recs[k].lowerBound + 12] ^= 0x40
        let r = try read(bad)
        let upTo = try read(Data(data.prefix(recs[k].lowerBound)))
        XCTAssertEqual(r.records, k)
        XCTAssertEqual(r.text, upTo.text)
        XCTAssertFalse(r.closed)
        XCTAssertTrue(r.notes.contains("readable up to record \(k) (authentication failed)"), "\(r.notes)")
        // Header length corruption in the middle: bad length.
        var bad2 = data
        bad2[recs[k].lowerBound] = 0xff
        XCTAssertTrue(try read(bad2).notes.contains { $0.hasPrefix("readable up to record \(k) (bad length") })
        // Swapped records: seq.
        var swapped = data.prefix(recs[k].lowerBound)
        swapped.append(data[recs[k + 1]])
        XCTAssertTrue(try read(swapped).notes.contains("readable up to record \(k) (seq \(k + 1), expected \(k))"))
    }

    func testFileWithoutFinalIsNotClosed() throws {
        let (data, _) = try writtenFile()
        let recs = recordOffsets(data)
        let r = try read(Data(data.prefix(recs[recs.count - 1].lowerBound)))
        XCTAssertFalse(r.closed)
        XCTAssertEqual(r.notes, [CipherLogReader.notClosedNote])
    }

    func testDataAfterFinalIsRejected() throws {
        let (data, text) = try writtenFile(lines: 2)
        var extended = data
        extended.append(data[recordOffsets(data)[0]])
        let r = try read(extended)
        XCTAssertTrue(r.closed)
        XCTAssertEqual(r.text, text)
        XCTAssertTrue(r.notes.contains { $0.contains("(data after final)") })
    }

    func testUnknownKeyIdIsSkippedWithNote() throws {
        let other = Curve25519.KeyAgreement.PrivateKey()
        let otherKey = try CipherLogKey(publicKey: other.publicKey.rawRepresentation)
        let enc = try FileEncoder(key: otherKey, createdAt: 1, platform: 1, process: 1, memLevel: 8, cryptoFault: nil)
        try enc.write("secret\n")
        let file = enc.header + (try enc.finishRecords())
        let r = try CipherLogReader.open(Format.bundle([file]), privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.files.count, 1)
        XCTAssertNil(r.files[0].header)
        XCTAssertEqual(r.files[0].notes, ["unknown key \(otherKey.keyIdHex), file skipped"])
        // With both keys it opens.
        let r2 = try CipherLogReader.open(file, privateKeys: [Fixtures.privateKey, other.rawRepresentation])
        XCTAssertEqual(r2.files[0].text, "secret\n")
        XCTAssertTrue(r2.files[0].closed)
    }

    func testBundleBadLengthEndsWithNote() throws {
        let (data, text) = try writtenFile(lines: 1)
        var b = Format.bundle([data, data])
        b.appendU32(1_000_000)
        b.append(Data(count: 10))
        let r = try CipherLogReader.open(b, privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.files.count, 2)
        XCTAssertEqual(r.files.map(\.text), [text, text])
        XCTAssertEqual(r.notes, ["bundle: bad length at entry 2"])
    }

    func testGarbage() throws {
        XCTAssertEqual(try CipherLogReader.open(Data("hello".utf8), privateKeys: [Fixtures.privateKey]).notes,
                       ["not a cipherlog file or bundle"])
        let r = try CipherLogReader.open(Data("CPL1abc".utf8), privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.files[0].notes, ["truncated header, file skipped"])
    }

    func testInflateCap() {
        let d = try! Deflater()
        try! d.write(Data(count: 3_000_000))
        let c = try! d.finish()
        let r = Inflate.inflate(c, cap: 1_000_000)
        XCTAssertTrue(r.capped)
        XCTAssertEqual(r.output.count, 1_000_000)
        let full = Inflate.inflate(c)
        XCTAssertFalse(full.capped)
        XCTAssertEqual(full.output.count, 3_000_000)
        XCTAssertTrue(full.finished)
    }
}
