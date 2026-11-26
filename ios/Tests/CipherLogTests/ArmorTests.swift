import Foundation
import XCTest
@testable import CipherLog

/// Armored bundles (SPEC.md 4.1).
final class ArmorTests: XCTestCase {
    private func bundle() throws -> Data {
        let dir = tempDir()
        let log = CipherLog(makeConfig(dir))
        log.log(.info, category: "armor", "inside the armor")
        log.close()
        return Format.bundle([try Data(contentsOf: logFiles(dir)[0])])
    }

    func testLayout() {
        let data = Data((0..<200).map { UInt8($0) })
        let text = CipherLogArmor.armor(data)
        XCTAssertTrue(text.hasSuffix("\n"))
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).dropLast().map(String.init)
        XCTAssertEqual(lines.first, "-----BEGIN CIPHERLOG BUNDLE-----")
        XCTAssertEqual(lines.last, "-----END CIPHERLOG BUNDLE-----")
        let body = lines.dropFirst().dropLast()
        XCTAssertEqual(body.count, 4) // 200 bytes = 268 base64 characters = 76 + 76 + 76 + 40
        XCTAssertEqual(body.map(\.count), [76, 76, 76, 40])
        XCTAssertEqual(body.joined(), data.base64EncodedString())
        XCTAssertEqual(try CipherLogArmor.dearmor(Data(text.utf8)), data)
        // Empty bundle body and exact multiples of a line.
        XCTAssertEqual(CipherLogArmor.armor(Data()), "-----BEGIN CIPHERLOG BUNDLE-----\n-----END CIPHERLOG BUNDLE-----\n")
        XCTAssertEqual(try CipherLogArmor.dearmor(Data(CipherLogArmor.armor(Data()).utf8)), Data())
        let exact = Data(repeating: 7, count: 57) // 76 base64 characters
        XCTAssertEqual(CipherLogArmor.armor(exact).split(separator: "\n").count, 3)
        XCTAssertEqual(try CipherLogArmor.dearmor(Data(CipherLogArmor.armor(exact).utf8)), exact)
    }

    func testReaderOpensArmorAsMailDeliversIt() throws {
        let b = try bundle()
        let armored = CipherLogArmor.armor(b)
        let variants = [
            armored,
            armored.replacingOccurrences(of: "\n", with: "\r\n"),
            "Hi, here are my logs.\r\n\r\n" + armored + "\n-- \nSent from my phone\n",
            "  \n" + armored.split(separator: "\n").map { "  \($0)\t" }.joined(separator: "\n") + "\n\n",
            "> quoted:\n" + armored, // text before the BEGIN line
        ]
        for (i, v) in variants.enumerated() {
            let r = try CipherLogReader.open(Data(v.utf8), privateKeys: [Fixtures.privateKey])
            XCTAssertEqual(r.notes, [], "variant \(i)")
            XCTAssertEqual(r.files.count, 1, "variant \(i)")
            XCTAssertTrue(r.files.first?.text.contains("inside the armor") == true, "variant \(i)")
        }
        // Bytes that are not UTF-8 before the BEGIN line do not matter.
        var junk = Data([0xff, 0xfe, 0x00, 0x80, 0x0a])
        junk.append(Data(armored.utf8))
        XCTAssertEqual(try CipherLogReader.open(junk, privateKeys: [Fixtures.privateKey]).files.count, 1)
    }

    func testRejections() throws {
        let armored = CipherLogArmor.armor(try bundle())
        var lines = armored.split(separator: "\n").map(String.init)
        func open(_ text: String) throws -> CipherLogReader.Result {
            try CipherLogReader.open(Data(text.utf8), privateKeys: [Fixtures.privateKey])
        }
        // Missing END line.
        var r = try open(lines.dropLast().joined(separator: "\n"))
        XCTAssertEqual(r.files.count, 0)
        XCTAssertEqual(r.notes, ["armor: no -----END CIPHERLOG BUNDLE----- line"])
        // Something between the markers that is not base64.
        var bad = lines
        bad.insert("Content-Type: text/plain", at: 2)
        r = try open(bad.joined(separator: "\n"))
        XCTAssertEqual(r.notes, ["armor: line 2 after BEGIN is not base64"])
        bad = lines
        bad[1] = String(bad[1].dropLast()) + "*"
        XCTAssertEqual(try open(bad.joined(separator: "\n")).notes, ["armor: line 1 after BEGIN is not base64"])
        // Base64 characters but broken padding (a character lost).
        bad = lines
        bad[1] = String(bad[1].dropLast())
        XCTAssertEqual(try open(bad.joined(separator: "\n")).files.count, 0)
        XCTAssertEqual(try open(bad.joined(separator: "\n")).notes.first?.hasPrefix("armor: "), true)
        // Text after BEGIN on its line: that line is not the BEGIN line, so the input is not armored.
        lines[0] += " extra"
        XCTAssertEqual(try open(lines.joined(separator: "\n")).notes, ["not a cipherlog file or bundle"])
        XCTAssertThrowsError(try CipherLogArmor.dearmor(Data(lines.joined(separator: "\n").utf8))) {
            XCTAssertEqual($0 as? CipherLogArmor.Error, .missingBegin)
        }
        // Plain text without armor.
        XCTAssertEqual(try open("hello").notes, ["not a cipherlog file or bundle"])
    }

    /// vectors/armor.json: the cases every implementation shares.
    func testSharedVectors() throws {
        // JSONDecoder, not JSONSerialization: the latter drops a leading U+FEFF from strings.
        struct Case: Decodable { let name, text: String; let bytes, error: String? }
        struct File: Decodable { let cases: [Case] }
        let data = try Data(contentsOf: Fixtures.vectors.appendingPathComponent("armor.json"))
        let cases = try JSONDecoder().decode(File.self, from: data).cases
        XCTAssertGreaterThan(cases.count, 20)
        for c in cases {
            let name = c.name
            let input = Data(c.text.utf8)
            if let hex = c.bytes {
                XCTAssertEqual(try CipherLogArmor.dearmor(input), Data(hex: hex), name)
                XCTAssertTrue(CipherLogArmor.looksArmored(input), name)
            } else {
                XCTAssertThrowsError(try CipherLogArmor.dearmor(input), name) { error in
                    XCTAssertEqual(String(describing: error), c.error, name)
                }
            }
        }
    }

    func testArmoredSingleFileIsAccepted() throws {
        let dir = tempDir()
        let log = CipherLog(makeConfig(dir))
        log.log(.info, category: "a", "single")
        log.close()
        let text = CipherLogArmor.armor(try Data(contentsOf: logFiles(dir)[0]))
        let r = try CipherLogReader.open(Data(text.utf8), privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.files.count, 1)
        XCTAssertTrue(r.files[0].text.contains("single"))
    }

    /// Hostile input: 16 MiB of empty lines, with and without a BEGIN line in front. Detection and dearmor scan lines
    /// in place. A version that split the input into arrays of lines needed about 1 GiB here (32 bytes per line, in two
    /// arrays); the peak resident size of the test process may grow by far less than that.
    func testManyEmptyLinesCostNoMemory() throws {
        func maxResident() -> Int {
            var usage = rusage()
            getrusage(RUSAGE_SELF, &usage)
            return Int(usage.ru_maxrss) // bytes on Darwin
        }
        var input = Data(repeating: UInt8(ascii: "\n"), count: 16 << 20)
        let before = maxResident()
        XCTAssertFalse(CipherLogArmor.looksArmored(input))
        XCTAssertThrowsError(try CipherLogArmor.dearmor(input)) { XCTAssertEqual($0 as? CipherLogArmor.Error, .missingBegin) }
        XCTAssertEqual(try CipherLogReader.open(input, privateKeys: [Fixtures.privateKey]).notes,
                       ["not a cipherlog file or bundle"])
        input.replaceSubrange(0..<CipherLogArmor.beginLine.utf8.count, with: Data(CipherLogArmor.beginLine.utf8))
        XCTAssertTrue(CipherLogArmor.looksArmored(input))
        XCTAssertEqual(try CipherLogReader.open(input, privateKeys: [Fixtures.privateKey]).notes,
                       ["armor: no -----END CIPHERLOG BUNDLE----- line"])
        let grown = maxResident() - before
        XCTAssertLessThan(grown, 256 << 20, "armor detection used \(grown >> 20) MiB for 16 MiB of empty lines")
    }

    func testArmorInsideArmorIsNotUnwrappedTwice() throws {
        let inner = Data(CipherLogArmor.armor(try bundle()).utf8)
        let outer = CipherLogArmor.armor(inner)
        let r = try CipherLogReader.open(Data(outer.utf8), privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.files.count, 0)
        XCTAssertEqual(r.notes, ["not a cipherlog file or bundle"])
    }

    func testExportIsArmoredByDefault() throws {
        let dir = tempDir()
        let log = CipherLog(makeConfig(dir, clock: TestClock(1_795_000_000_000, step: 1)))
        log.log(.info, category: "a", "for the mail")
        let url = try log.exportBundle()
        XCTAssertTrue(url.lastPathComponent.hasSuffix(".cipherlogs.txt"), url.lastPathComponent)
        XCTAssertTrue(url.lastPathComponent.hasPrefix("cipherlog-20261118-1106"), url.lastPathComponent)
        let text = try String(contentsOf: url, encoding: .utf8)
        XCTAssertTrue(text.hasPrefix(CipherLogArmor.beginLine + "\n"))
        XCTAssertTrue(text.hasSuffix(CipherLogArmor.endLine + "\n"))
        XCTAssertTrue(text.split(separator: "\n").allSatisfy { $0.count <= 76 || $0.hasPrefix("-----") })
        let r = try CipherLogReader.open(try Data(contentsOf: url), privateKeys: [Fixtures.privateKey])
        XCTAssertEqual(r.notes, [])
        XCTAssertEqual(r.files.count, 2)
        XCTAssertTrue(r.files[0].text.contains("for the mail"))

        let binary = try log.exportBundle(armored: false)
        XCTAssertEqual(binary.pathExtension, "cipherlogs")
        XCTAssertEqual(try Data(contentsOf: binary).prefix(4), Data("CPB1".utf8))

        // Wipe removes armored exports like binary ones.
        XCTAssertTrue(log.wipe())
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.deletingLastPathComponent().path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: binary.path))
        log.close()
    }
}

#if canImport(CoreTransferable)
import CoreTransferable
import UniformTypeIdentifiers

final class ExportTransferableTests: XCTestCase {
    func testShareLinkItemExportsTheArmoredBundle() async throws {
        guard #available(macOS 15.2, iOS 18.2, *) else { throw XCTSkip("exported(as:) needs macOS 15.2") }
        let dir = tempDir()
        let log = CipherLog(makeConfig(dir))
        log.log(.info, category: "share", "shared through ShareLink")
        let data = try await CipherLogExport(log).exported(as: .plainText)
        log.close()
        XCTAssertTrue(String(decoding: data, as: UTF8.self).hasPrefix(CipherLogArmor.beginLine))
        let r = try CipherLogReader.open(data, privateKeys: [Fixtures.privateKey])
        XCTAssertTrue(r.files.contains { $0.text.contains("shared through ShareLink") })
    }

    func testWithoutWriterSharingFails() async throws {
        guard #available(macOS 15.2, iOS 18.2, *) else { throw XCTSkip("exported(as:) needs macOS 15.2") }
        CipherLog.replaceShared(nil)
        do {
            _ = try await CipherLogExport().exported(as: .plainText)
            XCTFail("exported without a writer")
        } catch {
            // CoreTransferable wraps the error (`notStarted`) in its own.
        }
    }
}
#endif
