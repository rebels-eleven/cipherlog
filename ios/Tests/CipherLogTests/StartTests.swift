import Foundation
import XCTest
@testable import CipherLog

/// The integration API (SPEC.md 7.1): start, shared, process detection, defaults, test-key warning.
final class StartTests: XCTestCase {
    static let pub = "cipherlog-pub-v1:" + (Fixtures.testKeyJSON["publicKey"] as! String)

    override func tearDown() {
        CipherLog.replaceShared(nil)
        super.tearDown()
    }

    func testStartWritesThroughCipherLogger() throws {
        let dir = tempDir()
        let logger = CipherLogger(category: "boot") // created before start, like a static property
        let log = try XCTUnwrap(CipherLog.start(key: Self.pub, options: .init(directory: dir)))
        XCTAssertTrue(CipherLog.shared === log)
        XCTAssertEqual(log.config.process, 1)
        XCTAssertEqual(log.config.processName, "app")
        XCTAssertEqual(log.config.fileProtection, CipherLog.Config.defaultFileProtection)
        XCTAssertTrue(log.config.excludeFromBackup)
        logger.notice("started \(42) for \("alice")")
        // A second start returns the same writer and ignores its arguments.
        XCTAssertTrue(CipherLog.start(key: "garbage") === log)
        XCTAssertTrue(CipherLog.start(key: Self.pub, options: .init(directory: tempDir())) === log)
        log.close()

        let lines = try readFile(logFiles(dir)[0]).lines
        XCTAssertTrue(lines.contains { $0.hasSuffix(" N app boot: started 42 for <private>") }, lines.joined(separator: "\n"))
        // Built-in collectors: app, system, locale, disk.
        let device = lines.filter { $0.contains(" device: ") }
        XCTAssertEqual(device.count, 5, device.joined(separator: "\n"))
        XCTAssertTrue(device[1].contains(" device: app · "))
        XCTAssertTrue(device[1].hasSuffix(" · development") || device[1].hasSuffix(" · App Store")
                      || device[1].hasSuffix(" · TestFlight"), device[1])
        XCTAssertTrue(device[2].contains(" device: system · "))
        XCTAssertTrue(device[2].contains(" · macOS "))
        XCTAssertTrue(device[3].contains(" device: locale · "))
        XCTAssertTrue(device[4].contains(" device: disk · "))
        XCTAssertTrue(device[4].hasSuffix(" GB free"), device[4])
        // Never the user-assigned computer name.
        let host = ProcessInfo.processInfo.hostName.split(separator: ".").first.map(String.init) ?? ""
        if host.count > 3, host != "localhost" {
            XCTAssertFalse(lines.joined().contains(host), "device block names the computer")
        }
        // The directory is excluded from backup.
        let values = try dir.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true)
    }

    func testStartFailsWithoutCrashing() {
        let diagnostics = Diagnostics()
        XCTAssertNil(CipherLog.start(key: "ecd8b29e", options: .init(directory: tempDir(), diagnostics: diagnostics.callback)))
        XCTAssertNil(CipherLog.shared)
        XCTAssertNil(CipherLog.start(key: "cipherlog-priv-v1:" + String(repeating: "ab", count: 32),
                                     options: .init(directory: tempDir(), diagnostics: diagnostics.callback)))
        XCTAssertNil(CipherLog.shared)
        // Without a writer, CipherLogger only forwards to os.Logger.
        CipherLogger(category: "x").error("nothing to write to")
        let deadline = Date().addingTimeInterval(5)
        while diagnostics.lines.get.count < 2, Date() < deadline { usleep(10_000) }
        let lines = diagnostics.lines.get
        XCTAssertEqual(lines.count, 2)
        XCTAssertTrue(lines.contains { $0.hasPrefix("cipherlog not started: cipherlog key: the key string must start with cipherlog-pub-v1:") }, "\(lines)")
        XCTAssertTrue(lines.contains { $0.contains("PRIVATE") && !$0.contains("abab") }, "\(lines)")
    }

    func testProcessDetection() {
        let app = CipherLog.detectProcess(bundleURL: URL(fileURLWithPath: "/x/My.app"), bundleName: "My")
        XCTAssertEqual(app.process, 1)
        XCTAssertEqual(app.name, "app")
        let widget = CipherLog.detectProcess(bundleURL: URL(fileURLWithPath: "/x/My.app/PlugIns/Widget.appex"),
                                             bundleName: "WidgetExtension")
        XCTAssertEqual(widget.process, 2)
        XCTAssertEqual(widget.name, "WidgetExtension")
        let unnamed = CipherLog.detectProcess(bundleURL: URL(fileURLWithPath: "/x/My.app/PlugIns/Share.appex"),
                                              bundleName: nil)
        XCTAssertEqual(unnamed.name, "Share")
        // The name in file names and lines is sanitised by the writer.
        let log = CipherLog(makeConfig(tempDir(), processName: "Notification Service"))
        XCTAssertEqual(log.processName, "Notification_Service")
        log.close()
    }

    func testDefaultDirectory() throws {
        let dir = try XCTUnwrap(CipherLog.defaultDirectory(appGroup: nil))
        XCTAssertEqual(dir.lastPathComponent, "cipherlog")
        XCTAssertTrue(dir.path.contains("/Application Support/"), dir.path)
    }

    func testTestKeyWarningInReleaseBuilds() throws {
        // The test helper's config uses the test key. Debug build (this test run): no warning.
        let quiet = Diagnostics()
        var config = makeConfig(tempDir(), diagnostics: quiet)
        XCTAssertNil(CipherLog.testKeyWarning(config))
        // A build compiled without DEBUG warns at every start, to diagnostics and the system log.
        config.releaseBuild = true
        XCTAssertEqual(CipherLog.testKeyWarning(config), CipherLog.testKeyWarningText)
        let loud = Diagnostics()
        var release = makeConfig(tempDir(), diagnostics: loud)
        release.releaseBuild = true
        for _ in 0..<2 {
            let log = CipherLog(release)
            log.log(.info, category: "a", "x")
            log.close()
        }
        XCTAssertEqual(loud.lines.get, [CipherLog.testKeyWarningText, CipherLog.testKeyWarningText])
        // Another key in a release build: no warning.
        release.key = try CipherLogKey(string: "cipherlog-pub-v1:" + String(repeating: "09", count: 32))
        release.diagnostics = quiet.callback
        CipherLog(release).close()
        XCTAssertEqual(quiet.lines.get, [])
        XCTAssertEqual(CipherLog.compiledWithoutDebug, Self.compiledWithoutDebug)
    }

    static var compiledWithoutDebug: Bool {
        #if DEBUG
        return false
        #else
        return true
        #endif
    }

    func testSystemLogSwitchStillWritesTheFile() throws {
        let dir = tempDir()
        var config = makeConfig(dir)
        config.systemLog = false
        let log = CipherLog.start(config)
        CipherLogger(subsystem: "s", category: "quiet").info("only in the file \(1)")
        log.close()
        XCTAssertTrue(try readFile(logFiles(dir)[0]).text.contains("I app quiet: only in the file 1"))
    }

    func testCollectorHelpers() {
        XCTAssertEqual(CipherLogCollector.roundedSize(23_400_000_000), "23 GB")
        XCTAssertEqual(CipherLogCollector.roundedSize(1_000_000_000), "1 GB")
        XCTAssertEqual(CipherLogCollector.roundedSize(340_000_000), "0.3 GB")
        XCTAssertEqual(CipherLogCollector.roundedSize(-5), "0.0 GB")
        XCTAssertFalse(CipherLogCollector.modelIdentifier().isEmpty)
        XCTAssertNotEqual(CipherLogCollector.modelIdentifier(), ProcessInfo.processInfo.hostName)
    }
}
