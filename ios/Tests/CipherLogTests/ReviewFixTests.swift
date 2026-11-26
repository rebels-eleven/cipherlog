import Foundation
import XCTest
@testable import CipherLog

/// Writer threading, diagnostics reasons, protection default, wipes by other processes and reader limits.
final class ReviewFixTests: XCTestCase {
    // MARK: Calls that wait for the writer never run app callbacks on the caller's thread

    func testCollectorsRunOffTheMainThreadDuringExportAndWipe() throws {
        XCTAssertTrue(Thread.isMainThread)
        let dir = tempDir()
        let onMain = Locked<[Bool]>([])
        let log = CipherLog(makeConfig(dir, collectors: [
            CipherLogCollector(name: "thread") {
                onMain.mutate { $0.append(Thread.isMainThread) }
                return ["checked"]
            },
        ]))
        log.log(.info, category: "a", "x")
        _ = try log.exportBundle()
        XCTAssertTrue(log.wipe())
        log.close()
        XCTAssertGreaterThanOrEqual(onMain.get.count, 3)
        XCTAssertEqual(onMain.get.filter { $0 }, [], "a collector ran on the main thread")
    }

    func testACollectorThatHopsToMainTimesOutInsteadOfCrashing() throws {
        let dir = tempDir()
        let hop = Locked(false)
        let log = CipherLog(makeConfig(dir, collectors: [
            CipherLogCollector(name: "ui") {
                guard hop.get else { return ["start"] }
                var s = ""
                DispatchQueue.main.sync { s = "main" }
                return [s]
            },
        ]))
        XCTAssertTrue(log.flush(timeout: 5))
        hop.set(true)
        // Before the fix this trapped (queue.sync ran the collector on main, which then called main.sync).
        XCTAssertThrowsError(try log.exportBundle(timeout: 0.3)) { error in
            XCTAssertEqual(error as? CipherLog.WaitError, .timedOut)
        }
        // The main queue runs the collector's block; the writer then finishes and stays usable.
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))
        hop.set(false)
        XCTAssertTrue(log.flush(timeout: 5))
        XCTAssertNotNil(try log.exportBundle(timeout: 5))
        log.close()
    }

    func testDiagnosticsRunOnTheWriterQueue() throws {
        let dir = tempDir()
        let fs = FaultyFileSystem()
        let onMain = Locked<[Bool]>([])
        var config = makeConfig(dir, fs: fs)
        config.diagnostics = { _ in onMain.mutate { $0.append(Thread.isMainThread) } }
        let log = CipherLog(config)
        log.log(.info, category: "a", "x")
        XCTAssertTrue(log.flush(timeout: 5))
        fs.writeError.set(POSIXError(.EIO))
        log.log(.info, category: "a", "y")
        log.close()
        XCTAssertEqual(onMain.get, [false])
    }

    // MARK: Diagnostics reason carries the errno

    func testWriteFailureReasonNamesTheErrno() throws {
        func reason(after error: Error) -> String? {
            let dir = tempDir()
            let fs = FaultyFileSystem()
            let diag = Diagnostics()
            let log = CipherLog(makeConfig(dir, diagnostics: diag, fs: fs))
            log.log(.info, category: "a", "ok")
            XCTAssertTrue(log.flush(timeout: 5))
            fs.writeError.set(error)
            log.log(.warning, category: "a", "fails")
            log.flush(timeout: 5)
            log.close()
            return diag.lines.get.first
        }
        XCTAssertEqual(reason(after: POSIXError(.EPERM)), "cipherlog off: write failed (EPERM)")
        let wrapped = NSError(domain: NSCocoaErrorDomain, code: NSFileWriteUnknownError,
                              userInfo: [NSUnderlyingErrorKey: NSError(domain: NSPOSIXErrorDomain, code: Int(EIO))])
        XCTAssertEqual(reason(after: wrapped), "cipherlog off: write failed (EIO)")
        XCTAssertEqual(reason(after: NSError(domain: "Other", code: 7)), "cipherlog off: write failed (Other 7)")
    }

    func testRealDescriptorWriteErrorsCarryTheErrno() throws {
        let url = tempDir().appendingPathComponent("x")
        let h = try DefaultFileSystem().createFile(url, initial: Data([1]), protection: nil)
        h.close()
        XCTAssertThrowsError(try h.write(Data([2]))) { error in
            XCTAssertEqual(FileErrors.reason(error), "EBADF")
        }
    }

    // MARK: File protection

    func testDefaultFileProtectionIsAppliedToEveryFile() throws {
        let config = CipherLog.Config(directory: tempDir(), key: Fixtures.key, process: 1, processName: "app")
        XCTAssertEqual(config.fileProtection, CipherLog.Config.defaultFileProtection)
        #if os(iOS) || os(watchOS) || os(tvOS) || os(visionOS)
        XCTAssertEqual(config.fileProtection, .completeUntilFirstUserAuthentication)
        #else
        XCTAssertNil(config.fileProtection)
        #endif
        let fs = FaultyFileSystem()
        var c = makeConfig(tempDir(), fs: fs)
        c.fileProtection = .completeUntilFirstUserAuthentication
        let log = CipherLog(c)
        XCTAssertTrue(log.flush(timeout: 5))
        log.close()
        XCTAssertEqual(fs.protections.get, [.completeUntilFirstUserAuthentication])
        // The directory gets the class too, so files are born in it rather than inheriting a `complete` default.
        XCTAssertFalse(fs.directoryProtections.get.isEmpty)
        XCTAssertEqual(Set(fs.directoryProtections.get.map { $0 }), [.completeUntilFirstUserAuthentication])
    }

    /// With a class asked for, the real file system creates the file in that class (one exclusive create that carries
    /// the class) instead of creating it and changing the class afterwards. Data Protection classes are not enforced
    /// on macOS, so this checks the rest of the contract: exclusive, 0600, header written, appends, and a file that was
    /// already there is neither overwritten nor removed.
    func testProtectedCreateIsExclusiveAndAppends() throws {
        let fs = DefaultFileSystem()
        let dir = tempDir().appendingPathComponent("logs/cipherlog", isDirectory: true)
        try fs.createDirectory(dir, protection: .completeUntilFirstUserAuthentication)
        try fs.createDirectory(dir, protection: .completeUntilFirstUserAuthentication) // an existing one is fine
        let url = dir.appendingPathComponent("a.cipherlog")
        let h = try fs.createFile(url, initial: Data([1, 2]), protection: .completeUntilFirstUserAuthentication)
        try h.write(Data([3]))
        h.close()
        XCTAssertEqual(try Data(contentsOf: url), Data([1, 2, 3]))
        let mode = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600)
        XCTAssertThrowsError(try fs.createFile(url, initial: Data([9]), protection: .completeUntilFirstUserAuthentication))
        XCTAssertEqual(try Data(contentsOf: url), Data([1, 2, 3]), "an existing file must stay as it was")
        XCTAssertEqual(DefaultFileSystem.writingOption(.complete), .completeFileProtection)
        XCTAssertEqual(DefaultFileSystem.writingOption(.completeUnlessOpen), .completeFileProtectionUnlessOpen)
        XCTAssertEqual(DefaultFileSystem.writingOption(.completeUntilFirstUserAuthentication),
                       .completeFileProtectionUntilFirstUserAuthentication)
        XCTAssertEqual(DefaultFileSystem.writingOption(.none), .noFileProtection)
    }

    // MARK: A wipe by another process

    func testAWipeByAnotherProcessMakesTheWriterOpenANewFile() throws {
        let dir = tempDir()
        let widget = CipherLog(makeConfig(dir, processName: "widget", process: 2))
        widget.log(.info, category: "a", "before the wipe")
        XCTAssertTrue(widget.flush(timeout: 5))
        let before = try XCTUnwrap(logFiles(dir, process: "widget").first)
        let app = CipherLog(makeConfig(dir))
        XCTAssertTrue(app.wipe())
        XCTAssertFalse(FileManager.default.fileExists(atPath: before.path))
        widget.log(.info, category: "a", "after the wipe")
        let recent = try XCTUnwrap(widget.recentBundle(), "recentBundle after a wipe by another process")
        let files = try CipherLogReader.open(recent, privateKeys: [Fixtures.privateKey]).files
        XCTAssertTrue(files.contains { $0.text.contains("after the wipe") })
        widget.close()
        app.close()
        let now = try XCTUnwrap(logFiles(dir, process: "widget").first)
        XCTAssertNotEqual(now, before)
        let text = try readFile(now).text
        XCTAssertTrue(text.contains("after the wipe"))
        XCTAssertFalse(text.contains("before the wipe"))
    }

    // MARK: Exports skip files shorter than a header

    func testExportSkipsEmptyFiles() throws {
        let dir = tempDir()
        let log = CipherLog(makeConfig(dir))
        log.log(.info, category: "a", "x")
        XCTAssertTrue(log.flush(timeout: 5))
        let empty = dir.appendingPathComponent("other-1795000000000-00000000.cipherlog")
        XCTAssertTrue(FileManager.default.createFile(atPath: empty.path, contents: Data()))
        let url = try log.exportBundle()
        log.close()
        let r = try CipherLogReader.open(try Data(contentsOf: url), privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.files.count, 2, "own file + device now; the empty file is not exported")
        XCTAssertEqual(r.notes, [])
    }

    // MARK: Reader

    private func fileBytes(_ lines: [String]) throws -> Data {
        let dir = tempDir()
        let log = CipherLog(makeConfig(dir))
        for l in lines { log.log(.info, category: "t", l) }
        log.close()
        return try Data(contentsOf: try XCTUnwrap(logFiles(dir).first))
    }

    func testZeroLengthBundleEntryIsSkippedNotTheEnd() throws {
        let a = try fileBytes(["first"])
        let b = try fileBytes(["second"])
        let r = try CipherLogReader.open(Format.bundle([a, Data(), b]), privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.notes, [])
        XCTAssertEqual(r.files.count, 3)
        XCTAssertTrue(r.files[0].text.contains("first"))
        XCTAssertEqual(r.files[1].notes, ["truncated header, file skipped"])
        XCTAssertTrue(r.files[2].text.contains("second"))
    }

    func testTotalOutputIsCappedAcrossFiles() throws {
        let f = try fileBytes([String(repeating: "x", count: 600)])
        let one = try CipherLogReader.open(f, privateKeys: [Fixtures.privateKey]).files[0].text.utf8.count
        let r = try CipherLogReader.open(Format.bundle([f, f, f]), privateKeys: [Fixtures.privateKey],
                                         maxTotalOutput: one + 100)
        XCTAssertEqual(r.files[0].text.utf8.count, one)
        XCTAssertEqual(r.files[1].text.utf8.count, 100)
        XCTAssertTrue(r.files[1].notes.contains("total output capped at \(one + 100) bytes"), "\(r.files[1].notes)")
        XCTAssertEqual(r.files[2].text, "")
        XCTAssertTrue(r.files[2].notes.contains("total output capped at \(one + 100) bytes"))
        XCTAssertEqual(CipherLogReader.defaultMaxTotalOutput, 256 * 1024 * 1024)
    }

    func testDamagedStreamKeepsTextAndNotes() throws {
        let d = try Deflater()
        try d.write(Data("kept\n".utf8))
        var stream = try d.sync()
        stream.append(contentsOf: [0x07, 0, 0])
        let r = Inflate.inflate(stream)
        XCTAssertTrue(r.error)
        XCTAssertEqual(String(decoding: r.output, as: UTF8.self), "kept\n")
        XCTAssertEqual(CipherLogReader.damagedNote, "compressed stream damaged, text kept up to the damage")
    }

    // MARK: Version

    /// The release job checks the tag against the same four places (.github/workflows/release.yml).
    func testVersionMatchesTheOtherImplementations() throws {
        /// The value after `=` on the first line starting with `key`, without quotes and spaces.
        func value(_ path: String, _ key: String) throws -> String? {
            let text = try String(contentsOf: Fixtures.repoRoot.appendingPathComponent(path), encoding: .utf8)
            let line = text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
                .first { $0.hasPrefix(key + " ") || $0.hasPrefix(key + "=") }
            return line?.split(separator: "=", maxSplits: 1).last?
                .trimmingCharacters(in: CharacterSet(charactersIn: " '\""))
        }
        XCTAssertEqual(try value("android/gradle.properties", "VERSION_NAME"), CipherLog.version)
        XCTAssertEqual(try value("cli/Cargo.toml", "version"), CipherLog.version)
        XCTAssertEqual(try value("CipherLog.podspec", "s.version"), CipherLog.version)
    }
}
