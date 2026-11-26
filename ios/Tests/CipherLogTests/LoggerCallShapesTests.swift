// Generated from one body: the same call sites must compile against os.Logger and CipherLogger.
// When you add a shape, add it to both functions (or regenerate both from one body).
import CoreGraphics
import Foundation
import os
import XCTest
@testable import CipherLog

/// The exact call shapes of `os.Logger`. If a line here stops compiling against `os.Logger`, it is not an os.Logger
/// shape; if it stops compiling against `CipherLogger`, the drop-in promise of SPEC.md 7.1 is broken.
enum LoggerCallShapes {
    static func osLogger(_ logger: os.Logger) {
        let s = "text"
        let i = 7
        let i8: Int8 = -1
        let i16: Int16 = 300
        let i32: Int32 = -40
        let i64: Int64 = 1 << 40
        let u: UInt = 9
        let u8: UInt8 = 200
        let u16: UInt16 = 65_000
        let u32: UInt32 = 70_000
        let u64: UInt64 = 255
        let d = 0.25
        let f: Float = 1.5
        let cg: CGFloat = 2
        let b = true
        let object = NSURL(string: "https://example.invalid")!
        let url = URL(string: "https://example.invalid/a")!
        let nsError = NSError(domain: "d", code: 1)

        logger.log("literal")
        logger.log("string \(s)")
        logger.log(level: .default, "default \(s)")
        logger.log(level: .info, "info \(i)")
        logger.log(level: .debug, "debug \(d)")
        logger.log(level: .error, "error \(b)")
        logger.log(level: .fault, "fault \(s, privacy: .public)")
        logger.trace("trace \(s)")
        logger.debug("debug \(s)")
        logger.info("info \(s)")
        logger.notice("notice \(s)")
        logger.warning("warning \(s)")
        logger.error("error \(s)")
        logger.critical("critical \(s)")
        logger.fault("fault \(s)")

        // Privacy.
        logger.info("\(s, privacy: .public) \(s, privacy: .private) \(s, privacy: .private(mask: .hash))")
        logger.info("\(s, privacy: .sensitive) \(s, privacy: .sensitive(mask: .hash)) \(s, privacy: .auto)")
        logger.info("\(s, privacy: .auto(mask: .hash)) \(i, privacy: .private) \(i, privacy: .private(mask: .hash))")

        // Alignment.
        logger.info("[\(s, align: .left(columns: 10))] [\(s, align: .right(columns: 10), privacy: .public)]")
        logger.info("[\(url, align: .left(columns: 4))] [\(String.self, align: .right(columns: 8))]")

        // Integers.
        logger.info("\(i) \(i8) \(i16) \(i32) \(i64) \(u) \(u8) \(u16) \(u32) \(u64)")
        logger.info("\(u, format: .hex) \(u, format: .octal) \(i, format: .decimal)")
        logger.info("\(u, format: .hex(includePrefix: true, uppercase: true)) \(i, format: .decimal(minDigits: 4))")
        logger.info("\(u, format: .octal(includePrefix: true)) \(i, format: .decimal(explicitPositiveSign: true))")
        logger.info("\(u64, format: .hex(explicitPositiveSign: false, includePrefix: true, uppercase: false, minDigits: 8))")
        logger.info("\(u, format: .hex, align: .right(columns: 6), privacy: .public) \(i32, align: .left(columns: 4))")
        logger.info("\(i64, privacy: .public) \(u8, format: .hex(minDigits: 2), privacy: .private)")

        // Floating point.
        logger.info("\(d) \(f) \(cg)")
        logger.info("\(d, format: .fixed(precision: 2)) \(d, format: .exponential) \(d, format: .hybrid(precision: 3))")
        logger.info("\(f, format: .fixed) \(cg, format: .hybrid) \(d, format: .fixed(precision: 1, explicitPositiveSign: true))")
        logger.info("\(d, format: .fixed(precision: 1), align: .left(columns: 8), privacy: .private)")
        logger.info("\(d, format: .exponential(precision: 2, explicitPositiveSign: false, uppercase: true))")

        // Bool.
        logger.info("\(b) \(b, format: .answer) \(b, format: .truth, privacy: .public)")

        // Objects, CustomStringConvertible, metatypes.
        logger.info("\(object) \(object, privacy: .public) \(url) \(url.absoluteString, privacy: .public)")
        logger.error("\(nsError) \(nsError.localizedDescription, privacy: .public)")
        logger.info("\(String.self) \(Int.self, privacy: .public)")
    }

    static func cipherLogger(_ logger: CipherLogger) {
        let s = "text"
        let i = 7
        let i8: Int8 = -1
        let i16: Int16 = 300
        let i32: Int32 = -40
        let i64: Int64 = 1 << 40
        let u: UInt = 9
        let u8: UInt8 = 200
        let u16: UInt16 = 65_000
        let u32: UInt32 = 70_000
        let u64: UInt64 = 255
        let d = 0.25
        let f: Float = 1.5
        let cg: CGFloat = 2
        let b = true
        let object = NSURL(string: "https://example.invalid")!
        let url = URL(string: "https://example.invalid/a")!
        let nsError = NSError(domain: "d", code: 1)

        logger.log("literal")
        logger.log("string \(s)")
        logger.log(level: .default, "default \(s)")
        logger.log(level: .info, "info \(i)")
        logger.log(level: .debug, "debug \(d)")
        logger.log(level: .error, "error \(b)")
        logger.log(level: .fault, "fault \(s, privacy: .public)")
        logger.trace("trace \(s)")
        logger.debug("debug \(s)")
        logger.info("info \(s)")
        logger.notice("notice \(s)")
        logger.warning("warning \(s)")
        logger.error("error \(s)")
        logger.critical("critical \(s)")
        logger.fault("fault \(s)")

        // Privacy.
        logger.info("\(s, privacy: .public) \(s, privacy: .private) \(s, privacy: .private(mask: .hash))")
        logger.info("\(s, privacy: .sensitive) \(s, privacy: .sensitive(mask: .hash)) \(s, privacy: .auto)")
        logger.info("\(s, privacy: .auto(mask: .hash)) \(i, privacy: .private) \(i, privacy: .private(mask: .hash))")

        // Alignment.
        logger.info("[\(s, align: .left(columns: 10))] [\(s, align: .right(columns: 10), privacy: .public)]")
        logger.info("[\(url, align: .left(columns: 4))] [\(String.self, align: .right(columns: 8))]")

        // Integers.
        logger.info("\(i) \(i8) \(i16) \(i32) \(i64) \(u) \(u8) \(u16) \(u32) \(u64)")
        logger.info("\(u, format: .hex) \(u, format: .octal) \(i, format: .decimal)")
        logger.info("\(u, format: .hex(includePrefix: true, uppercase: true)) \(i, format: .decimal(minDigits: 4))")
        logger.info("\(u, format: .octal(includePrefix: true)) \(i, format: .decimal(explicitPositiveSign: true))")
        logger.info("\(u64, format: .hex(explicitPositiveSign: false, includePrefix: true, uppercase: false, minDigits: 8))")
        logger.info("\(u, format: .hex, align: .right(columns: 6), privacy: .public) \(i32, align: .left(columns: 4))")
        logger.info("\(i64, privacy: .public) \(u8, format: .hex(minDigits: 2), privacy: .private)")

        // Floating point.
        logger.info("\(d) \(f) \(cg)")
        logger.info("\(d, format: .fixed(precision: 2)) \(d, format: .exponential) \(d, format: .hybrid(precision: 3))")
        logger.info("\(f, format: .fixed) \(cg, format: .hybrid) \(d, format: .fixed(precision: 1, explicitPositiveSign: true))")
        logger.info("\(d, format: .fixed(precision: 1), align: .left(columns: 8), privacy: .private)")
        logger.info("\(d, format: .exponential(precision: 2, explicitPositiveSign: false, uppercase: true))")

        // Bool.
        logger.info("\(b) \(b, format: .answer) \(b, format: .truth, privacy: .public)")

        // Objects, CustomStringConvertible, metatypes.
        logger.info("\(object) \(object, privacy: .public) \(url) \(url.absoluteString, privacy: .public)")
        logger.error("\(nsError) \(nsError.localizedDescription, privacy: .public)")
        logger.info("\(String.self) \(Int.self, privacy: .public)")
    }
}

final class LoggerCallShapesTests: XCTestCase {
    func testEveryShapeRunsAndWrites() throws {
        LoggerCallShapes.osLogger(os.Logger(subsystem: "com.rebels11.cipherlog.tests", category: "shapes"))
        let dir = tempDir()
        let log = CipherLog(makeConfig(dir))
        LoggerCallShapes.cipherLogger(CipherLogger(subsystem: "com.rebels11.cipherlog.tests", category: "shapes", log: log))
        log.close()
        let lines = try readFile(logFiles(dir)[0]).lines.dropFirst().map { String($0.split(separator: " ", maxSplits: 4)[4]) }
        XCTAssertEqual(lines.count, 36)
        XCTAssertEqual(lines[0], "literal")
        XCTAssertEqual(lines[15], "text <private> <private>")
        XCTAssertEqual(lines[18], "[<private> ] [      text]")
        XCTAssertEqual(lines[19], "[<private>] [<private>]")
        XCTAssertEqual(lines[20], "7 -1 300 -40 1099511627776 9 200 65000 70000 255")
        XCTAssertEqual(lines[21], "9 11 7")
        XCTAssertEqual(lines[22], "0X9 0007")
        XCTAssertEqual(lines[23], "011 +7")
        XCTAssertEqual(lines[24], "0x000000ff")
        XCTAssertEqual(lines[25], "     9 -40 ")
        XCTAssertEqual(lines[26], "1099511627776 <private>")
        XCTAssertEqual(lines[27], "0.25 1.5 2.0")
        XCTAssertEqual(lines[28], "0.25 2.500000e-01 0.25")
        XCTAssertEqual(lines[29], "1.500000 2 +0.2")
        XCTAssertEqual(lines[30], "<private>")
        XCTAssertEqual(lines[31], "2.50E-01")
        XCTAssertEqual(lines[32], "true YES true")
        XCTAssertEqual(lines[33], "<private> https://example.invalid <private> https://example.invalid/a")
        XCTAssertEqual(lines[34], "<private> The operation couldn’t be completed. (d error 1.)")
        XCTAssertEqual(lines[35], "<private> Int")
    }

    func testNegativeHexIsTwosComplement() {
        let i8: Int8 = -1
        let i = -2
        let m: CipherLogMessage = "\(i8, format: .hex) \(i, format: .hex) \(i, format: .decimal(minDigits: 3))"
        XCTAssertEqual(m.redacted, "ff fffffffffffffffe -002")
    }
}
