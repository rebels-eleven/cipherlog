import CryptoKit
import Foundation
import XCTest
@testable import CipherLog

final class WriterTests: XCTestCase {
    func testRoundTrip() throws {
        let dir = tempDir()
        let clock = TestClock(1_795_000_000_000, step: 1)
        let tap = TextTap()
        let log = CipherLog(makeConfig(dir, clock: clock, processName: "main", tap: tap))
        log.log(.info, category: "net", "connect")
        log.log(.debug, category: "", "no category")
        log.log(.fault, category: "x", "ünïcødé ✓ 🦭")
        XCTAssertTrue(log.flush(timeout: 5))
        log.close()
        XCTAssertFalse(log.isOn)
        let files = logFiles(dir)
        XCTAssertEqual(files.count, 1)
        let r = try readFile(files[0])
        XCTAssertTrue(r.closed)
        XCTAssertEqual(r.notes, [])
        XCTAssertEqual(r.text, tap.text.get)
        XCTAssertEqual(r.header?.platform, 1)
        XCTAssertEqual(r.header?.process, 1)
        XCTAssertEqual(r.header?.createdAt, 1_795_000_000_000)
        let lines = r.lines
        XCTAssertEqual(lines.count, 4)
        XCTAssertEqual(lines[0], "2026-11-18T11:06:40.000Z I main device: cipherlog \(CipherLog.version) · file \(r.header!.fileId.prefix(4).hex) · platform 1 · process 1")
        XCTAssertEqual(lines[1], "2026-11-18T11:06:40.001Z I main net: connect")
        XCTAssertEqual(lines[2], "2026-11-18T11:06:40.002Z D main -: no category")
        XCTAssertEqual(lines[3], "2026-11-18T11:06:40.003Z F main x: ünïcødé ✓ 🦭")
        // File name format.
        let name = files[0].lastPathComponent
        XCTAssertEqual(name, "main-1795000000000-\(r.header!.fileId.prefix(4).hex).cipherlog")
        // Lines after close are dropped.
        log.log(.error, category: "x", "late")
        XCTAssertEqual(try readFile(files[0]).lines.count, 4)
    }

    func testNewFilePerStartWithNewKeyAndSeqZero() throws {
        let dir = tempDir()
        var keys: [Data] = []
        var ids: [Data] = []
        for i in 0..<3 {
            let log = CipherLog(makeConfig(dir))
            log.log(.info, category: "run", "run \(i)")
            log.close()
        }
        let files = logFiles(dir)
        XCTAssertEqual(files.count, 3)
        for f in files {
            let data = try Data(contentsOf: f)
            let h = try CipherLogReader.openHeader(data, privateKey: Fixtures.privateKey)
            keys.append(h.fileKey)
            ids.append(h.fileId)
            XCTAssertEqual(data.readU32(at: Format.headerSize + 4), 0, "first seq is 0")
            XCTAssertTrue(try readFile(f).closed)
        }
        XCTAssertEqual(Set(keys).count, 3)
        XCTAssertEqual(Set(ids).count, 3)
    }

    func testRotationAtMaxFileBytes() throws {
        let dir = tempDir()
        var config = makeConfig(dir)
        config.maxFileBytes = 2048
        let tap = TextTap()
        config.textTap = tap.callback
        let log = CipherLog(config)
        var expected: [String] = []
        for i in 0..<100 {
            let msg = "line \(i) " + SecureRandom.bytes(40).hex // incompressible
            expected.append(msg)
            log.log(.info, category: "r", msg)
            if i % 3 == 0 { log.flush(timeout: 5) }
        }
        log.flush(timeout: 5)
        let files = logFiles(dir)
        XCTAssertGreaterThanOrEqual(files.count, 4)
        var all: [String] = []
        var fileIds = Set<Data>()
        for (i, f) in files.enumerated() {
            let data = try Data(contentsOf: f)
            let r = try readFile(f)
            XCTAssertEqual(data.readU32(at: Format.headerSize + 4), 0)
            fileIds.insert(r.header!.fileId)
            if i < files.count - 1 {
                XCTAssertTrue(r.closed, "old file \(i) has final")
                XCTAssertEqual(r.notes, [])
                // Rotated close to the limit: one flush past it at most.
                XCTAssertGreaterThanOrEqual(data.count, 2048)
                XCTAssertLessThan(data.count, 2048 + 1200)
            } else {
                XCTAssertFalse(r.closed, "current file is open")
            }
            XCTAssertTrue(r.lines.first!.contains("device: cipherlog"), "device block first in every file")
            all += r.lines.filter { $0.contains(" r: ") }.map { String($0.split(separator: ":", maxSplits: 3)[3].dropFirst()) }
        }
        XCTAssertEqual(fileIds.count, files.count)
        XCTAssertEqual(all, expected)
        log.close()
    }

    func testRetention() throws {
        let dir = tempDir()
        let now = TestClock.realNow()
        let old = Date(timeIntervalSince1970: TimeInterval(now) / 1000 - 3600)
        func fake(_ process: String, _ ms: UInt64, size: Int, modified: Date) -> URL {
            let url = dir.appendingPathComponent(FileName.make(process: process, createdAt: ms, fileId: SecureRandom.bytes(16)))
            FileManager.default.createFile(atPath: url.path, contents: Data(count: size))
            try! FileManager.default.setAttributes([.modificationDate: modified], ofItemAtPath: url.path)
            return url
        }
        // Oldest by name but modified just now (another live process may write it): never deleted.
        let fresh = fake("app", now - 10_000_000, size: 3000, modified: Date())
        let olds = (1...4).map { fake("app", now - 5_000_000 + UInt64($0), size: 3000, modified: old) }
        let other = fake("widget", now - 9_000_000, size: 50_000, modified: old)
        var config = makeConfig(dir, clock: TestClock(now))
        config.maxProcessBytes = 6200
        let log = CipherLog(config)
        log.flush(timeout: 5)
        log.close()
        let left = Set(logFiles(dir).map(\.lastPathComponent))
        XCTAssertTrue(left.contains(fresh.lastPathComponent))
        XCTAssertTrue(left.contains(other.lastPathComponent), "other processes are not touched")
        XCTAssertFalse(left.contains(olds[0].lastPathComponent))
        XCTAssertFalse(left.contains(olds[1].lastPathComponent))
        XCTAssertFalse(left.contains(olds[2].lastPathComponent))
        XCTAssertTrue(left.contains(olds[3].lastPathComponent))
        XCTAssertEqual(logFiles(dir, process: "app").count, 3) // fresh, newest old, current
        let total = logFiles(dir, process: "app").reduce(0) { $0 + ((try? Data(contentsOf: $1).count) ?? 0) }
        XCTAssertLessThanOrEqual(total, 6000 + 1000)

        // All fresh: nothing deleted even over the limit.
        let dir2 = tempDir()
        for i in 0..<5 {
            let u = dir2.appendingPathComponent(FileName.make(process: "app", createdAt: now - 100 + UInt64(i), fileId: SecureRandom.bytes(16)))
            FileManager.default.createFile(atPath: u.path, contents: Data(count: 3000))
        }
        var c2 = makeConfig(dir2, clock: TestClock(now))
        c2.maxProcessBytes = 6000
        let log2 = CipherLog(c2)
        log2.close()
        XCTAssertEqual(logFiles(dir2).count, 6)
    }

    func testWipe() throws {
        let dir = tempDir()
        let log = CipherLog(makeConfig(dir))
        log.log(.info, category: "a", "before wipe")
        let export = try log.exportBundle()
        XCTAssertTrue(FileManager.default.fileExists(atPath: export.path))
        // Another process's file and an unrelated file next to the exports.
        let other = dir.appendingPathComponent(FileName.make(process: "widget", createdAt: 1, fileId: SecureRandom.bytes(16)))
        FileManager.default.createFile(atPath: other.path, contents: Data(count: 10))
        let keep = dir.appendingPathComponent("exports/keep.txt")
        FileManager.default.createFile(atPath: keep.path, contents: Data(count: 1))
        let beforeNames = Set(logFiles(dir).map(\.lastPathComponent))
        log.wipe()
        XCTAssertTrue(log.isOn)
        XCTAssertFalse(FileManager.default.fileExists(atPath: export.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: export.deletingLastPathComponent().path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: keep.path), "only export folders are deleted")
        let after = logFiles(dir)
        XCTAssertEqual(after.count, 1)
        XCTAssertFalse(beforeNames.contains(after[0].lastPathComponent), "a new file")
        log.log(.info, category: "a", "after wipe")
        log.flush(timeout: 5)
        let r = try readFile(after[0])
        XCTAssertFalse(r.text.contains("before wipe"))
        XCTAssertTrue(r.text.contains("after wipe"))
        XCTAssertTrue(r.text.contains("device: cipherlog"))
        log.close()
    }

    func testDiskFullTurnsOffWithOneDiagnosticsLine() throws {
        let dir = tempDir()
        let fs = FaultyFileSystem()
        let diag = Diagnostics()
        let log = CipherLog(makeConfig(dir, diagnostics: diag, fs: fs))
        log.log(.info, category: "a", "ok")
        XCTAssertTrue(log.flush(timeout: 5))
        fs.writeError.set(POSIXError(.ENOSPC))
        log.log(.info, category: "a", "fails")
        XCTAssertTrue(log.flush(timeout: 5))
        XCTAssertFalse(log.isOn)
        for i in 0..<5 { log.log(.error, category: "a", "dropped \(i)") }
        log.flush(timeout: 5)
        fs.writeError.set(nil)
        log.log(.error, category: "a", "still off")
        log.flush(timeout: 5)
        log.close()
        XCTAssertEqual(diag.lines.get, ["cipherlog off: disk full"])
        let r = try readFile(logFiles(dir)[0])
        XCTAssertTrue(r.text.contains("ok"))
        XCTAssertFalse(r.text.contains("still off"))
        XCTAssertFalse(r.closed)
    }

    func testDiskFullAtOpenTurnsOff() throws {
        let fs = FaultyFileSystem()
        fs.createError.set(NSError(domain: NSCocoaErrorDomain, code: NSFileWriteOutOfSpaceError))
        let diag = Diagnostics()
        let log = CipherLog(makeConfig(tempDir(), diagnostics: diag, fs: fs))
        log.log(.info, category: "a", "x")
        log.flush(timeout: 5)
        XCTAssertFalse(log.isOn)
        XCTAssertEqual(diag.lines.get, ["cipherlog off: disk full"])
    }

    func testCryptoFailureTurnsOff() throws {
        let dir = tempDir()
        let diag = Diagnostics()
        let fault = Locked(false)
        var config = makeConfig(dir, diagnostics: diag)
        config.cryptoFault = { fault.get }
        let log = CipherLog(config)
        log.log(.info, category: "a", "ok")
        log.flush(timeout: 5)
        fault.set(true)
        log.log(.warning, category: "a", "fails")
        log.flush(timeout: 5)
        log.log(.warning, category: "a", "again")
        log.flush(timeout: 5)
        XCTAssertFalse(log.isOn)
        XCTAssertEqual(diag.lines.get, ["cipherlog off: crypto error"])
    }

    func testOpenFailureRetriesOnceAMinuteAndCountsDroppedLines() throws {
        let dir = tempDir()
        let fs = FaultyFileSystem()
        fs.createError.set(NSError(domain: NSCocoaErrorDomain, code: NSFileWriteNoPermissionError))
        let clock = TestClock(1_795_000_000_000)
        let diag = Diagnostics()
        let log = CipherLog(makeConfig(dir, clock: clock, diagnostics: diag, fs: fs))
        for i in 0..<3 { log.log(.info, category: "a", "lost \(i)") }
        log.flush(timeout: 5)
        XCTAssertEqual(fs.createAttempts.get, 1)
        clock.advance(30_000)
        log.log(.info, category: "a", "lost 3")
        fs.createError.set(nil)
        clock.advance(29_000) // 59 s after the failed attempt: no retry yet
        log.log(.info, category: "a", "lost 4")
        log.flush(timeout: 5)
        XCTAssertEqual(fs.createAttempts.get, 1)
        XCTAssertTrue(log.isOn)
        XCTAssertTrue(logFiles(dir).isEmpty)
        clock.advance(1_000) // 60 s
        log.log(.info, category: "a", "kept")
        log.flush(timeout: 5)
        XCTAssertEqual(fs.createAttempts.get, 2)
        log.close()
        let r = try readFile(logFiles(dir)[0])
        let lines = r.lines
        XCTAssertEqual(lines.count, 3)
        XCTAssertTrue(lines[0].contains(" I app device: cipherlog "))
        XCTAssertEqual(lines[1], "2026-11-18T11:07:40.000Z W app cipherlog: not written 5 lines")
        XCTAssertEqual(lines[2], "2026-11-18T11:07:40.000Z I app a: kept")
        XCTAssertEqual(diag.lines.get, [], "an open failure is retried silently; only `cipherlog off` reaches diagnostics")
    }

    func testOtherWriteErrorTurnsOff() throws {
        let dir = tempDir()
        let fs = FaultyFileSystem()
        let diag = Diagnostics()
        let log = CipherLog(makeConfig(dir, diagnostics: diag, fs: fs))
        log.log(.info, category: "a", "ok")
        XCTAssertTrue(log.flush(timeout: 5))
        fs.writeError.set(POSIXError(.EIO))
        log.log(.warning, category: "a", "fails")
        log.flush(timeout: 5)
        fs.writeError.set(nil)
        log.log(.warning, category: "a", "still off")
        log.flush(timeout: 5)
        XCTAssertFalse(log.isOn)
        XCTAssertEqual(diag.lines.get.count, 1)
        XCTAssertEqual(diag.lines.get[0], "cipherlog off: write failed (EIO)")
        XCTAssertEqual(logFiles(dir).count, 1, "no new file after a write failure")
    }

    func testCollectors() throws {
        let dir = tempDir()
        struct Weird: Error {}
        let log = CipherLog(makeConfig(dir, collectors: [
            CipherLogCollector(name: "ok") { ["first", "second\nline"] },
            CipherLogCollector(name: "bad") { throw Boom() },
            CipherLogCollector(name: "none") { [] },
            CipherLogCollector(name: "after") { ["still runs"] },
            .system,
        ]))
        log.close()
        let lines = try readFile(logFiles(dir)[0]).lines
        XCTAssertEqual(lines.count, 6)
        XCTAssertTrue(lines[1].hasSuffix(" I app device: ok · first"))
        XCTAssertTrue(lines[2].hasSuffix(" I app device: ok · second\\nline"))
        XCTAssertTrue(lines[3].hasSuffix(" I app device: bad · failed Boom"))
        XCTAssertTrue(lines[4].hasSuffix(" I app device: after · still runs"))
        XCTAssertTrue(lines[5].contains(" I app device: system · "))
        XCTAssertTrue(lines[5].contains("macOS"))
    }

    func testLineSanitising() throws {
        XCTAssertEqual(LineFormat.field("a\r\nb\rc\nd\te\u{1}f\u{7f}g\u{85}h\u{9f}i\u{a0}j"),
                       "a\\nb\\nc\\nd\te\u{FFFD}f\u{FFFD}g\u{FFFD}h\u{FFFD}i\u{a0}j")
        XCTAssertEqual(LineFormat.field("\r\r\n\n"), "\\n\\n\\n")
        XCTAssertEqual(LineFormat.field("\u{1b}[31mred"), "\u{FFFD}[31mred")
        XCTAssertEqual(LineFormat.name("héllo world/x:y", empty: "-"), "h_llo_world_x_y")
        XCTAssertEqual(LineFormat.name("Ok.name_1-2", empty: "-"), "Ok.name_1-2")
        XCTAssertEqual(LineFormat.name(String(repeating: "a", count: 40), empty: "-"), String(repeating: "a", count: 32))
        XCTAssertEqual(LineFormat.name("", empty: "-"), "-")
        XCTAssertEqual(LineFormat.time(0), "1970-01-01T00:00:00.000Z")
        XCTAssertEqual(LineFormat.time(1_795_000_000_123), "2026-11-18T11:06:40.123Z")

        let dir = tempDir()
        var config = makeConfig(dir, clock: TestClock(1_795_000_000_000), processName: "my app!")
        config.scrub = { $0.replacingOccurrences(of: "secret", with: "***") }
        let log = CipherLog(config)
        log.log(.notice, category: "cat/egory", "multi\nline secret\u{0}")
        log.log(.error, category: "err", error: Boom())
        log.log(category: "err", error: NSError(domain: "Dom", code: 7, userInfo: [NSLocalizedDescriptionKey: "bad\nthing"]))
        log.close()
        let lines = try readFile(logFiles(dir)[0]).lines
        XCTAssertEqual(lines[1], "2026-11-18T11:06:40.000Z N my_app_ cat_egory: multi\\nline ***\u{FFFD}")
        XCTAssertEqual(lines[2], "2026-11-18T11:06:40.000Z E my_app_ err: Boom: Boom()")
        XCTAssertEqual(lines[3], "2026-11-18T11:06:40.000Z E my_app_ err: NSError: Dom 7 bad\\nthing")
        XCTAssertTrue(logFiles(dir)[0].lastPathComponent.hasPrefix("my_app_-1795000000000-"))
    }

    func testDebouncedFlushAndImmediateWarning() throws {
        let dir = tempDir()
        var config = makeConfig(dir)
        config.flushDelay = 0.3
        let log = CipherLog(config)
        log.flush(timeout: 5) // device block written
        let url = logFiles(dir)[0]
        let afterOpen = try Data(contentsOf: url).count
        log.log(.info, category: "a", "later")
        Thread.sleep(forTimeInterval: 0.1)
        XCTAssertEqual(try Data(contentsOf: url).count, afterOpen, "info waits for the debounce")
        Thread.sleep(forTimeInterval: 0.5)
        let afterDebounce = try Data(contentsOf: url).count
        XCTAssertGreaterThan(afterDebounce, afterOpen)
        log.log(.warning, category: "a", "now")
        let deadline = Date().addingTimeInterval(0.25)
        while try Data(contentsOf: url).count == afterDebounce, Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
        XCTAssertGreaterThan(try Data(contentsOf: url).count, afterDebounce, "warning flushes at once")
        log.close()
    }

    func testFlushInlineOnQueueAndManyThreads() throws {
        let dir = tempDir()
        let log = CipherLog(makeConfig(dir, collectors: [CipherLogCollector(name: "c") { ["x"] }]))
        DispatchQueue.concurrentPerform(iterations: 200) { i in
            log.log(.info, category: "t\(i % 4)", "message \(i)")
        }
        XCTAssertTrue(log.flush(timeout: 5))
        log.close()
        let r = try readFile(logFiles(dir)[0])
        XCTAssertEqual(r.lines.filter { $0.contains("message ") }.count, 200)
    }

    func testDeflateMemLevel6() throws {
        let dir = tempDir()
        var config = makeConfig(dir)
        config.deflateMemLevel = 6
        let log = CipherLog(config)
        log.log(.info, category: "m", "low memory")
        log.close()
        XCTAssertTrue(try readFile(logFiles(dir)[0]).text.contains("low memory"))
    }

    func testTestKeyIsNotEmbedded() throws {
        // The library embeds no key: a sanity check over the sources.
        let src = Fixtures.repoRoot.appendingPathComponent("ios/Sources/CipherLog")
        for f in try FileManager.default.contentsOfDirectory(at: src, includingPropertiesForKeys: nil) {
            let s = try String(contentsOf: f, encoding: .utf8)
            XCTAssertFalse(s.contains(Fixtures.testKeyJSON["publicKey"] as! String), f.lastPathComponent)
            XCTAssertFalse(s.contains(Fixtures.testKeyJSON["privateKey"] as! String), f.lastPathComponent)
        }
    }
}
