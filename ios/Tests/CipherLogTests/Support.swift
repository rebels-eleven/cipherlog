import CryptoKit
import Foundation
import XCTest
@testable import CipherLog

enum Fixtures {
    static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    static let vectors = repoRoot.appendingPathComponent("vectors")

    static let testKeyJSON: [String: Any] = {
        let data = try! Data(contentsOf: vectors.appendingPathComponent("test-key.json"))
        return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    }()

    static let publicKey = Data(hex: testKeyJSON["publicKey"] as! String)!
    static let privateKey = Data(hex: testKeyJSON["privateKey"] as! String)!
    static let key = try! CipherLogKey(publicKey: publicKey)

    static let records: [String: Any] = {
        let data = try! Data(contentsOf: vectors.appendingPathComponent("records.json"))
        return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    }()
}

final class Locked<T>: @unchecked Sendable {
    private var value: T
    private let lock = NSLock()
    init(_ value: T) { self.value = value }
    var get: T { lock.withLock { value } }
    func set(_ v: T) { lock.withLock { value = v } }
    func mutate(_ f: (inout T) -> Void) { lock.withLock { f(&value) } }
}

/// Manual clock in ms; `step` is added after every read so lines get distinct times.
final class TestClock: @unchecked Sendable {
    private let state: Locked<UInt64>
    let step: UInt64
    init(_ start: UInt64, step: UInt64 = 0) {
        state = Locked(start)
        self.step = step
    }
    func now() -> UInt64 {
        var v: UInt64 = 0
        state.mutate { v = $0; $0 += step }
        return v
    }
    func advance(_ ms: UInt64) { state.mutate { $0 += ms } }
    var peek: UInt64 { state.get }
    static func realNow() -> UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }
}

/// Real file system with switchable failures.
final class FaultyFileSystem: LogFileSystem, @unchecked Sendable {
    let base = DefaultFileSystem()
    let createError = Locked<Error?>(nil)
    let writeError = Locked<Error?>(nil)
    let createAttempts = Locked(0)
    let protections = Locked<[FileProtectionType?]>([])
    let directoryProtections = Locked<[FileProtectionType?]>([])

    func createDirectory(_ url: URL, protection: FileProtectionType?) throws {
        directoryProtections.mutate { $0.append(protection) }
        try base.createDirectory(url, protection: protection)
    }

    func createFile(_ url: URL, initial: Data, protection: FileProtectionType?) throws -> LogFileHandle {
        createAttempts.mutate { $0 += 1 }
        protections.mutate { $0.append(protection) }
        if let e = createError.get { throw e }
        return Handle(try base.createFile(url, initial: initial, protection: protection), owner: self)
    }

    func list(_ directory: URL) -> [LogFileInfo] { base.list(directory) }
    func read(_ url: URL) throws -> Data { try base.read(url) }
    func remove(_ url: URL) throws { try base.remove(url) }
    func exists(_ url: URL) -> Bool { base.exists(url) }

    final class Handle: LogFileHandle {
        let inner: LogFileHandle
        let owner: FaultyFileSystem
        init(_ inner: LogFileHandle, owner: FaultyFileSystem) {
            self.inner = inner
            self.owner = owner
        }
        func write(_ data: Data) throws {
            if let e = owner.writeError.get { throw e }
            try inner.write(data)
        }
        func close() { inner.close() }
    }
}

final class Diagnostics: @unchecked Sendable {
    let lines = Locked<[String]>([])
    var callback: @Sendable (String) -> Void { { [lines] l in lines.mutate { $0.append(l) } } }
}

final class TextTap: @unchecked Sendable {
    let text = Locked("")
    var callback: @Sendable (String) -> Void { { [text] l in text.mutate { $0 += l } } }
}

func tempDir(_ name: String = #function) -> URL {
    let safe = name.filter { $0.isLetter || $0.isNumber }
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("cipherlog-tests-\(safe)-\(UUID().uuidString.prefix(8))", isDirectory: true)
    try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

func makeConfig(_ dir: URL, clock: TestClock? = nil, processName: String = "app", process: UInt8 = 1,
                collectors: [CipherLogCollector] = [], diagnostics: Diagnostics? = nil,
                fs: LogFileSystem? = nil, tap: TextTap? = nil) -> CipherLog.Config {
    let c = clock ?? TestClock(TestClock.realNow())
    var config = CipherLog.Config(directory: dir, key: Fixtures.key, process: process, processName: processName,
                                  collectors: collectors,
                                  diagnostics: diagnostics?.callback ?? { _ in },
                                  exportRoot: dir.appendingPathComponent("exports"),
                                  clock: { c.now() })
    if let fs { config.fileSystem = fs }
    config.textTap = tap?.callback
    return config
}

func logFiles(_ dir: URL, process: String? = nil) -> [URL] {
    ((try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [])
        .filter { $0.pathExtension == "cipherlog" }
        .filter { process == nil || FileName.parse($0.lastPathComponent)?.process == process }
        .sorted { $0.lastPathComponent < $1.lastPathComponent }
}

func readFile(_ url: URL) throws -> CipherLogReader.FileResult {
    let r = try CipherLogReader.open(try Data(contentsOf: url), privateKeys: [Fixtures.privateKey])
    return r.files[0]
}

/// Byte offsets of each record in a file.
func recordOffsets(_ data: Data) -> [Range<Int>] {
    var out: [Range<Int>] = []
    var o = Format.headerSize
    while o + 9 <= data.count {
        let len = Int(data.readU32(at: o))
        let end = o + 9 + len
        guard end <= data.count else { break }
        out.append(o..<end)
        o = end
    }
    return out
}

struct Boom: Error {}
