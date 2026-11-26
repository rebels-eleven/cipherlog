import Foundation
import XCTest
@testable import CipherLog

/// vectors/samples/<impl>/: real files written by each implementation plus the text a reader must produce.
/// The Swift samples are (re)written when absent or when CIPHERLOG_WRITE_SAMPLES=1.
final class SampleTests: XCTestCase {
    static let samples = Fixtures.vectors.appendingPathComponent("samples")
    static let swiftDir = samples.appendingPathComponent("swift")

    static let script: [(CipherLogLevel, String, String)] = [
        (.info, "app", "launch"),
        (.debug, "net", "GET /v1/items 200 in 84 ms"),
        (.info, "net", "connected to wss://example.invalid"),
        (.notice, "ui", "screen home"),
        (.debug, "cache", "hit ratio 0.93"),
        (.info, "i18n", "Привет, мир · こんにちは · مرحبا · 👋🏽"),
        (.warning, "net", "retry 1 after timeout"),
        (.info, "db", "migrated to schema 4"),
        (.error, "sync", "DecodingError: keyNotFound(\"id\")"),
        (.debug, "ui", "tab\tseparated\tvalues"),
        (.notice, "push", "token refreshed"),
        (.info, "multi", "first line\nsecond line\r\nthird"),
        (.debug, "ctrl", "bell \u{7} escape \u{1b}[0m del \u{7f}"),
        (.fault, "store", "write failed: disk I/O"),
        (.info, "", "no category"),
        (.info, "weird category!", "category sanitised"),
        (.warning, "mem", "memory warning level 2"),
        (.debug, "emoji", "🦭🎉✓ ünïcødé"),
        (.info, "app", "background"),
        (.notice, "app", "foreground"),
        (.error, "auth", "401 on refresh"),
        (.info, "app", "done"),
    ]

    private func write(close: Bool) throws -> (Data, String) {
        let dir = tempDir("sample\(close)")
        let tap = TextTap()
        var config = makeConfig(dir, clock: TestClock(close ? 1_795_000_000_000 : 1_795_000_100_000, step: 3),
                                processName: "sample", process: 1,
                                collectors: [CipherLogCollector(name: "sample") { ["collector line · ok"] }],
                                tap: tap)
        config.flushDelay = 60 // only explicit flushes and warnings
        let log = CipherLog(config)
        for (i, (level, cat, msg)) in SampleTests.script.enumerated() {
            log.log(level, category: cat, msg)
            if i % 5 == 4 { XCTAssertTrue(log.flush(timeout: 5)) }
        }
        XCTAssertTrue(log.flush(timeout: 5))
        let url = try XCTUnwrap(logFiles(dir).first)
        if close { log.close() }
        let data = try Data(contentsOf: url)
        if !close { log.close() }
        return (data, tap.text.get)
    }

    func test1WriteSwiftSamples() throws {
        let fm = FileManager.default
        let force = ProcessInfo.processInfo.environment["CIPHERLOG_WRITE_SAMPLES"] == "1"
        guard force || !fm.fileExists(atPath: SampleTests.swiftDir.appendingPathComponent("sample.cipherlogs").path) else {
            throw XCTSkip("samples exist; set CIPHERLOG_WRITE_SAMPLES=1 to rewrite")
        }
        try fm.createDirectory(at: SampleTests.swiftDir, withIntermediateDirectories: true)
        let (closed, closedText) = try write(close: true)
        let (open, openText) = try write(close: false)
        XCTAssertGreaterThanOrEqual(recordOffsets(closed).count, 3)
        XCTAssertGreaterThanOrEqual(closedText.split(separator: "\n").count, 20)
        try closed.write(to: SampleTests.swiftDir.appendingPathComponent("sample.cipherlog"))
        try Data(closedText.utf8).write(to: SampleTests.swiftDir.appendingPathComponent("expected.txt"))
        try open.write(to: SampleTests.swiftDir.appendingPathComponent("unclosed.cipherlog"))
        try Data(openText.utf8).write(to: SampleTests.swiftDir.appendingPathComponent("unclosed.expected.txt"))
        try Format.bundle([closed, open]).write(to: SampleTests.swiftDir.appendingPathComponent("sample.cipherlogs"))
        try writeArmoredSample()
    }

    /// `sample.cipherlogs.txt`: the bundle above, armored (SPEC.md 4.1). Written from the existing bundle when absent,
    /// so adding it does not change the other samples.
    func test1bWriteSwiftArmoredSample() throws {
        let path = SampleTests.swiftDir.appendingPathComponent("sample.cipherlogs.txt").path
        guard !FileManager.default.fileExists(atPath: path) else { throw XCTSkip("armored sample exists") }
        try writeArmoredSample()
    }

    private func writeArmoredSample() throws {
        let bundle = try Data(contentsOf: SampleTests.swiftDir.appendingPathComponent("sample.cipherlogs"))
        try Data(CipherLogArmor.armor(bundle).utf8)
            .write(to: SampleTests.swiftDir.appendingPathComponent("sample.cipherlogs.txt"))
    }

    func test2ReadAllSamples() throws {
        let fm = FileManager.default
        let dirs = ((try? fm.contentsOfDirectory(at: SampleTests.samples, includingPropertiesForKeys: [.isDirectoryKey])) ?? [])
            .filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true }
        XCTAssertTrue(dirs.contains { $0.lastPathComponent == "swift" }, "own samples must exist")
        for dir in dirs {
            let impl = dir.lastPathComponent
            func file(_ n: String) -> URL { dir.appendingPathComponent(n) }
            var expectations: [(text: String, closed: Bool)] = []
            for (name, exp, closed) in [("sample.cipherlog", "expected.txt", true),
                                        ("unclosed.cipherlog", "unclosed.expected.txt", false)] {
                guard fm.fileExists(atPath: file(name).path) else {
                    XCTAssertNotEqual(impl, "swift", "\(impl)/\(name) missing")
                    continue
                }
                let expected = try String(contentsOf: file(exp), encoding: .utf8)
                let r = try CipherLogReader.open(try Data(contentsOf: file(name)), privateKeys: [Fixtures.privateKey])
                XCTAssertEqual(r.files.count, 1, "\(impl)/\(name)")
                guard let f = r.files.first else { continue }
                XCTAssertEqual(f.text, expected, "\(impl)/\(name) text")
                XCTAssertEqual(f.closed, closed, "\(impl)/\(name) closed")
                XCTAssertEqual(f.notes, closed ? [] : [CipherLogReader.notClosedNote], "\(impl)/\(name) notes")
                XCTAssertNotNil(f.header)
                expectations.append((expected, closed))
            }
            // The binary bundle and, where an implementation wrote one, the armored bundle (SPEC.md 4.1).
            for name in ["sample.cipherlogs", "sample.cipherlogs.txt"] {
                if fm.fileExists(atPath: file(name).path) {
                    let r = try CipherLogReader.open(try Data(contentsOf: file(name)), privateKeys: [Fixtures.privateKey])
                    XCTAssertEqual(r.notes, [], "\(impl)/\(name)")
                    XCTAssertEqual(r.files.map(\.text), expectations.map(\.text), "\(impl)/\(name) texts")
                    XCTAssertEqual(r.files.map(\.closed), expectations.map(\.closed), "\(impl)/\(name) status")
                } else {
                    XCTAssertNotEqual(impl, "swift", "\(impl)/\(name) missing")
                }
            }
        }
    }
}
