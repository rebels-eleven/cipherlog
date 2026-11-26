import Foundation
import os
import XCTest
@testable import CipherLog

// Replacing `os.Logger` with this alias must leave existing call sites compiling.
private typealias Logger = CipherLogger

final class LoggerTests: XCTestCase {
    struct Item: CustomStringConvertible { var description: String { "item-7" } }
    enum Failure: Error { case notFound }
    struct DescribedFailure: Error, CustomStringConvertible { var description: String { "described" } }

    func testCallSitesAndPrivacy() throws {
        let dir = tempDir()
        let log = CipherLog(makeConfig(dir, clock: TestClock(1_795_000_000_000)))
        let logger = Logger(subsystem: "com.example.app", category: "net", log: log)
        let name = "alice"
        let count = 3
        let ratio = 0.5
        let flag = true
        let optional: String? = nil
        let optionalNumber: Int? = 42
        let error: any Error = Failure.notFound
        let sub = "substring".prefix(3)

        logger.notice("user \(name, privacy: .public) has \(count) items")
        logger.info("user \(name) ratio \(ratio) flag \(flag)")
        logger.debug("private number \(count, privacy: .private) hash \(name, privacy: .private(mask: .hash))")
        logger.error("failed: \(error) / \(error, privacy: .public) / \(Failure.notFound, privacy: .public)")
        logger.warning("item \(Item()) \(Item(), privacy: .public) \(sub, privacy: .public)")
        logger.fault("opt \(optional) \(optionalNumber) \(optional, privacy: .public)")
        logger.critical("type \(String.self, privacy: .public) \(UInt8(7)) \(Int64(-2)) \(Float(1.5)) \(CGFloat(2))")
        logger.trace("trace \(DescribedFailure(), privacy: .public)")
        logger.log("plain literal")
        logger.log(level: .error, "level \(count)")
        logger.log(level: .debug, "debug level")
        logger.notice("sensitive \(name, privacy: .sensitive) auto \(name, privacy: .auto)")
        log.close()

        let lines = try readFile(logFiles(dir)[0]).lines.dropFirst().map {
            String($0.dropFirst("2026-11-18T11:06:40.000Z ".count))
        }
        XCTAssertEqual(lines, [
            "N app net: user alice has 3 items",
            "I app net: user <private> ratio 0.5 flag true",
            "D app net: private number <private> hash <private>",
            "E app net: failed: <private> / notFound / notFound",
            "W app net: item <private> item-7 sub",
            "F app net: opt nil 42 nil",
            "F app net: type String 7 -2 1.5 2.0",
            "D app net: trace described",
            "N app net: plain literal",
            "E app net: level 3",
            "D app net: debug level",
            "N app net: sensitive <private> auto <private>",
        ])
    }

    func testMessageTexts() {
        let secret = "s3cr3t"
        let m: CipherLogMessage = "a \(secret) b \(secret, privacy: .public) \(1)"
        XCTAssertEqual(m.redacted, "a <private> b s3cr3t 1")
        XCTAssertEqual(m.full, "a s3cr3t b s3cr3t 1")
    }

    func testSharedLog() throws {
        let dir = tempDir()
        let logger = CipherLogger(subsystem: "s", category: "early") // created before the writer starts
        logger.info("dropped: no writer yet")
        let log = CipherLog.start(makeConfig(dir))
        defer { CipherLog.replaceShared(nil) }
        XCTAssertTrue(CipherLog.shared === log)
        logger.info("to default")
        log.close()
        let text = try readFile(logFiles(dir)[0]).text
        XCTAssertTrue(text.contains("I app early: to default"))
        XCTAssertFalse(text.contains("dropped"))
        XCTAssertTrue(CipherLogger(category: "c").subsystem == (Bundle.main.bundleIdentifier ?? "-"))
    }

    func testScrubAppliesToLoggerMessages() throws {
        let dir = tempDir()
        var config = makeConfig(dir)
        config.scrub = { $0.replacingOccurrences(of: "token=abc", with: "token=…") }
        let log = CipherLog(config)
        CipherLogger(subsystem: "s", category: "c", log: log).notice("url \("x?token=abc", privacy: .public)")
        log.close()
        XCTAssertTrue(try readFile(logFiles(dir)[0]).text.contains("url x?token=…"))
    }
}
