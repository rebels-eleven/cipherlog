import Foundation
import XCTest
@testable import CipherLog

/// Key strings (SPEC.md 1.1). Only the test key of vectors/test-key.json is used.
final class KeyStringTests: XCTestCase {
    static let pubHex = Fixtures.testKeyJSON["publicKey"] as! String
    static let privHex = Fixtures.testKeyJSON["privateKey"] as! String
    static let pub = "cipherlog-pub-v1:" + pubHex
    static let priv = "cipherlog-priv-v1:" + privHex

    private func pubError(_ s: String, file: StaticString = #filePath, line: UInt = #line) -> CipherLogKeyError? {
        do {
            _ = try CipherLogKey(string: s)
            XCTFail("accepted \(s)", file: file, line: line)
            return nil
        } catch let e as CipherLogKeyError {
            return e
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
            return nil
        }
    }

    private func privError(_ s: String, file: StaticString = #filePath, line: UInt = #line) -> CipherLogKeyError? {
        do {
            _ = try CipherLogReader.privateKey(string: s)
            XCTFail("accepted a private key string", file: file, line: line)
            return nil
        } catch let e as CipherLogKeyError {
            return e
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
            return nil
        }
    }

    /// vectors/keys.json: the cases every implementation shares.
    func testSharedVectors() throws {
        // JSONDecoder, not JSONSerialization: the latter drops a leading U+FEFF from strings.
        struct Case: Decodable { let name, kind, input: String; let key, error: String? }
        struct File: Decodable { let cases: [Case] }
        let data = try Data(contentsOf: Fixtures.vectors.appendingPathComponent("keys.json"))
        let cases = try JSONDecoder().decode(File.self, from: data).cases
        XCTAssertGreaterThan(cases.count, 20)
        for c in cases {
            let name = c.name
            let input = c.input
            let isPrivate = c.kind == "private"
            do {
                let raw = isPrivate
                    ? try CipherLogReader.privateKey(string: input) : try CipherLogKey(string: input).publicKey
                XCTAssertEqual(raw, Data(hex: c.key ?? ""), name)
            } catch {
                XCTAssertEqual(String(describing: error), "cipherlog key: " + (c.error ?? "(accepted)"), name)
                XCTAssertFalse(String(describing: error).lowercased().contains(Self.privHex.prefix(8)), name)
            }
        }
    }

    func testPublicKeyString() throws {
        let key = try CipherLogKey(string: Self.pub)
        XCTAssertEqual(key.publicKey, Fixtures.publicKey)
        XCTAssertEqual(key.keyIdHex, Fixtures.testKeyJSON["keyId"] as? String)
        XCTAssertEqual(key.string, Self.pub)
        XCTAssertTrue(key.isTestKey)
        // Uppercase hex and surrounding whitespace are accepted; the string form is lowercase.
        let upper = try CipherLogKey(string: "  \n\t cipherlog-pub-v1:" + Self.pubHex.uppercased() + " \r\n")
        XCTAssertEqual(upper, key)
        XCTAssertEqual(upper.string, Self.pub)
        let other = try CipherLogKey(string: "cipherlog-pub-v1:" + String(repeating: "09", count: 32))
        XCTAssertFalse(other.isTestKey)
    }

    func testPublicKeyRejections() {
        XCTAssertEqual(pubError(""), .empty)
        XCTAssertEqual(pubError(" \n "), .empty)
        XCTAssertEqual(pubError(Self.pubHex), .wrongPrefix(expected: "cipherlog-pub-v1:"))
        XCTAssertEqual(pubError("cipherlog-pub-v2:" + Self.pubHex), .wrongPrefix(expected: "cipherlog-pub-v1:"))
        XCTAssertEqual(pubError("CIPHERLOG-PUB-V1:" + Self.pubHex), .wrongPrefix(expected: "cipherlog-pub-v1:"))
        XCTAssertEqual(pubError("key = " + Self.pub), .wrongPrefix(expected: "cipherlog-pub-v1:"))
        XCTAssertEqual(pubError("\"" + Self.pub + "\""), .wrongPrefix(expected: "cipherlog-pub-v1:"))
        XCTAssertEqual(pubError(Self.pub + "\""), .notHex(position: 65, character: "\"\"\""))
        XCTAssertEqual(pubError(Self.pub + " trailing"), .notHex(position: 65, character: "U+0020"))
        XCTAssertEqual(pubError(String(Self.pub.dropLast())), .wrongLength(expected: 64, got: 63))
        XCTAssertEqual(pubError(Self.pub + "00"), .wrongLength(expected: 64, got: 66))
        XCTAssertEqual(pubError("cipherlog-pub-v1:"), .wrongLength(expected: 64, got: 0))
        XCTAssertEqual(pubError("cipherlog-pub-v1:g" + Self.pubHex.dropFirst()), .notHex(position: 1, character: "\"g\""))
        XCTAssertEqual(pubError("cipherlog-pub-v1: " + Self.pubHex), .notHex(position: 1, character: "U+0020"))
        // Zero-width and other invisible characters pasted from a web page are named by code point.
        XCTAssertEqual(pubError(String(Self.pub.prefix(30)) + "\u{200B}" + String(Self.pub.dropFirst(30))),
                       .notHex(position: 14, character: "U+200B"))
    }

    func testPrivateKeyInsteadOfPublicIsNamedAndNotEchoed() {
        let e = pubError(Self.priv)
        XCTAssertEqual(e, .privateKeyGiven)
        let text = String(describing: e!)
        XCTAssertTrue(text.contains("PRIVATE"), text)
        XCTAssertFalse(text.lowercased().contains(Self.privHex.prefix(8)))
        XCTAssertEqual((e! as LocalizedError).errorDescription, text)
    }

    func testPrivateKeyString() throws {
        XCTAssertEqual(try CipherLogReader.privateKey(string: Self.priv), Fixtures.privateKey)
        XCTAssertEqual(try CipherLogReader.privateKey(string: "\n" + Self.priv.uppercased()
                .replacingOccurrences(of: "CIPHERLOG-PRIV-V1:", with: "cipherlog-priv-v1:") + "\n"), Fixtures.privateKey)
        // Opens what the writer wrote.
        let dir = tempDir()
        let log = CipherLog(makeConfig(dir))
        log.log(.info, category: "k", "via key string")
        log.close()
        let r = try CipherLogReader.open(try Data(contentsOf: logFiles(dir)[0]),
                                         privateKeys: [try CipherLogReader.privateKey(string: Self.priv)])
        XCTAssertTrue(r.files[0].text.contains("via key string"))
    }

    func testPrivateKeyRejectionsNeverEchoTheKey() {
        let cases: [(String, CipherLogKeyError)] = [
            ("", .empty),
            (Self.pub, .publicKeyGiven),
            (Self.privHex, .wrongPrefix(expected: "cipherlog-priv-v1:")),
            (String(Self.priv.dropLast()), .wrongLength(expected: 64, got: 63)),
            (Self.priv + "a", .wrongLength(expected: 64, got: 65)),
            ("cipherlog-priv-v1:z" + Self.privHex.dropFirst(), .notHex(position: 1, character: nil)),
            (Self.priv + "#", .notHex(position: 65, character: nil)),
        ]
        for (n, (input, expected)) in cases.enumerated() {
            let e = privError(input)
            XCTAssertEqual(e, expected, "case \(n)")
            let text = e.map { String(describing: $0) } ?? ""
            // No 6-character piece of the private key appears in the message.
            for start in stride(from: 0, to: Self.privHex.count - 6, by: 1) {
                let i = Self.privHex.index(Self.privHex.startIndex, offsetBy: start)
                let piece = String(Self.privHex[i..<Self.privHex.index(i, offsetBy: 6)])
                XCTAssertFalse(text.lowercased().contains(piece), "message echoes the private key: \(expected)")
            }
        }
    }
}
