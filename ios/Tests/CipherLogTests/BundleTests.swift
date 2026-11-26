import Foundation
import XCTest
@testable import CipherLog

final class BundleTests: XCTestCase {
    func testExportRoundTrip() throws {
        let dir = tempDir()
        let clock = TestClock(1_795_000_000_000, step: 1)
        let log = CipherLog(makeConfig(dir, clock: clock, collectors: [CipherLogCollector(name: "c") { ["v"] }]))
        log.log(.info, category: "a", "hello export")
        let widget = CipherLog(makeConfig(dir, clock: clock, processName: "widget", process: 2))
        widget.log(.info, category: "w", "from widget")
        widget.close()
        let url = try log.exportBundle(armored: false)
        XCTAssertEqual(url.pathExtension, "cipherlogs")
        XCTAssertTrue(url.lastPathComponent.hasPrefix("cipherlog-20261118-1106"), url.lastPathComponent)
        XCTAssertEqual(url.deletingLastPathComponent().deletingLastPathComponent().lastPathComponent, "exports")
        let data = try Data(contentsOf: url)
        XCTAssertEqual(data.prefix(4), Data("CPB1".utf8))
        let r = try CipherLogReader.open(data, privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.notes, [])
        XCTAssertEqual(r.files.count, 3)
        let texts = r.files.map(\.text)
        XCTAssertTrue(texts.contains { $0.contains("hello export") })
        XCTAssertTrue(texts.contains { $0.contains("from widget") })
        // The device-now file: device block only, closed with final, last in the bundle.
        let now = r.files.last!
        XCTAssertTrue(now.closed)
        XCTAssertEqual(now.lines.count, 2)
        XCTAssertTrue(now.lines[1].hasSuffix("device: c · v"))
        // The current file is still open.
        let current = r.files.first { $0.text.contains("hello export") }!
        XCTAssertFalse(current.closed)
        log.close()
    }

    func testExportCapDropsOldest() throws {
        let dir = tempDir()
        let now = TestClock.realNow()
        var fakes: [URL] = []
        for i in 0..<5 {
            let u = dir.appendingPathComponent(FileName.make(process: "other", createdAt: now - 100_000 + UInt64(i),
                                                             fileId: SecureRandom.bytes(16)))
            FileManager.default.createFile(atPath: u.path, contents: Data(repeating: UInt8(i), count: 1_000_000))
            fakes.append(u)
        }
        let log = CipherLog(makeConfig(dir, clock: TestClock(now)))
        log.log(.info, category: "a", "x")
        let url = try log.exportBundle(armored: false)
        let data = try Data(contentsOf: url)
        XCTAssertLessThanOrEqual(data.count, 4 * 1024 * 1024)
        let r = try CipherLogReader.open(data, privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.files.count, 6) // 4 newest fakes + current + device now
        // Fake files are garbage: entries carry the first byte of each fake (its index).
        var o = 4
        var firstBytes: [UInt8] = []
        while o < data.count {
            let len = Int(data.readU32(at: o))
            firstBytes.append(data[o + 4])
            o += 4 + len
        }
        XCTAssertEqual(Array(firstBytes.prefix(4)), [1, 2, 3, 4], "oldest (0) dropped, oldest first in the bundle")
        log.close()
    }

    func testOldExportFoldersDeleted() throws {
        let dir = tempDir()
        let clock = TestClock(TestClock.realNow())
        let log = CipherLog(makeConfig(dir, clock: clock))
        let first = try log.exportBundle()
        try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(-8 * 24 * 3600)],
                                              ofItemAtPath: first.path)
        let second = try log.exportBundle()
        XCTAssertFalse(FileManager.default.fileExists(atPath: first.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: second.path))
        log.close()
    }

    func testRecentBundleAndPreviousRun() throws {
        let dir = tempDir()
        let first = CipherLog(makeConfig(dir))
        first.log(.info, category: "a", "first run")
        first.close()
        XCTAssertNil(CipherLog(makeConfig(tempDir())).previousRunBundle().flatMap { _ in 1 }, "no previous run")

        // A later run starts in a later millisecond (same-millisecond runs would sort by their random fileId).
        let second = CipherLog(makeConfig(dir, clock: TestClock(TestClock.realNow() + 1000)))
        second.log(.info, category: "a", "second run")
        // Current < 4 KiB: current + previous.
        let recent = try XCTUnwrap(second.recentBundle())
        var r = try CipherLogReader.open(recent, privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.files.count, 2)
        XCTAssertTrue(r.files[0].text.contains("first run"))
        XCTAssertTrue(r.files[1].text.contains("second run"), "current file after a flush")

        let prev = try XCTUnwrap(second.previousRunBundle())
        r = try CipherLogReader.open(prev, privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.files.count, 1)
        XCTAssertTrue(r.files[0].text.contains("first run"))
        XCTAssertTrue(r.files[0].closed)

        // Current >= 4 KiB: current only.
        for _ in 0..<80 { second.log(.info, category: "a", SecureRandom.bytes(40).hex) }
        let big = try XCTUnwrap(second.recentBundle())
        r = try CipherLogReader.open(big, privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.files.count, 1)
        XCTAssertTrue(r.files[0].text.contains("second run"))
        second.close()
    }
}
