import CryptoKit
import Foundation
import os

/// Writes log lines to files encrypted to the developer's public key (SPEC.md 3).
///
/// The writer never throws into the app and never crashes it: failures go to `Config.diagnostics`.
/// `log` only enqueues; one serial queue per instance formats, compresses, encrypts and writes.
///
/// The calls that wait for the writer (`flush`, `close`, `wipe`, `exportBundle`, `recentBundle`, `previousRunBundle`)
/// always run their work on that queue, never on the caller's thread, and wait at most their `timeout`. Collectors,
/// `scrub` inside the device block and `diagnostics` therefore run on the writer queue only; they must never wait for
/// the main thread (the main thread may be the one waiting for the writer, and the call then times out).
///
/// Sendable: all mutable state below is touched only on `queue` (a serial queue); `onFlag` is guarded by its own
/// unfair lock; `config` is immutable.
public final class CipherLog: @unchecked Sendable {
    public static let version = "0.1.0-alpha.1"

    public struct Config: Sendable {
        /// Directory for this app's log files; may be an App Group container shared by several processes.
        public var directory: URL
        public var key: CipherLogKey
        /// 0 unknown, 1 Apple, 2 Android, 3 JVM.
        public var platform: UInt8
        /// Chosen by the app, for example 1 main app, 2 widget extension.
        public var process: UInt8
        /// Written in every line and in file names; `[A-Za-z0-9._-]`, at most 32 characters.
        public var processName: String
        public var collectors: [CipherLogCollector]
        /// Runs over every message before it is queued (on the caller's thread). Masking is the app's job.
        public var scrub: @Sendable (String) -> String
        /// Called on the writer queue with `cipherlog off: <reason>` (SPEC.md 3.6) and, in a build compiled without
        /// DEBUG that uses the test key, with the test-key warning at every start (SPEC.md 7.1). Must not wait for the main thread
        /// (`DispatchQueue.main.sync`): the main thread may be waiting for the writer.
        public var diagnostics: @Sendable (String) -> Void
        public var maxFileBytes: Int
        public var maxProcessBytes: Int
        /// Files modified less than this many seconds ago are never deleted by retention.
        public var keepFreshFor: TimeInterval
        /// Seconds between a line and its flush (lines at warning and above flush at once).
        public var flushDelay: TimeInterval
        /// zlib memLevel: 8 by default; an app extension under memory pressure may use 6.
        public var deflateMemLevel: Int32
        /// Applied to every created file. The default on iOS, watchOS, tvOS and visionOS is
        /// `.completeUntilFirstUserAuthentication`: files stay writable while the phone is locked, even in an app whose
        /// Data Protection entitlement makes `.complete` the container's default (with `.complete`, the first write
        /// about 10 s after the lock fails and the writer turns itself off until relaunch). nil leaves the container's
        /// default class; the default on macOS.
        public var fileProtection: FileProtectionType?
        /// Default root for `exportBundle(root:)`; `wipe()` deletes exports in it.
        public var exportRoot: URL
        /// `CipherLogger` also writes every message to os.Logger when true (the default).
        public var systemLog: Bool
        /// `CipherLogger` hands the full text (marked public) to os.Logger when true. Meant for debug builds.
        public var systemLogFullText: Bool
        /// Marks `directory` as excluded from iCloud and device backups when the writer creates or opens it.
        public var excludeFromBackup: Bool
        /// Milliseconds since the Unix epoch.
        public var clock: @Sendable () -> UInt64

        // Test seams (internal).
        var fileSystem: LogFileSystem = DefaultFileSystem()
        var cryptoFault: (@Sendable () -> Bool)?
        var textTap: (@Sendable (String) -> Void)?
        /// Whether the test-key warning applies (SPEC.md 7.1): true when the package was compiled without DEBUG.
        var releaseBuild = CipherLog.compiledWithoutDebug

        public init(directory: URL,
                    key: CipherLogKey,
                    platform: UInt8 = 1,
                    process: UInt8,
                    processName: String,
                    collectors: [CipherLogCollector] = [],
                    scrub: @escaping @Sendable (String) -> String = { $0 },
                    diagnostics: @escaping @Sendable (String) -> Void = { _ in },
                    maxFileBytes: Int = 256 * 1024,
                    maxProcessBytes: Int = 2 * 1024 * 1024,
                    keepFreshFor: TimeInterval = 600,
                    flushDelay: TimeInterval = 0.1,
                    deflateMemLevel: Int32 = 8,
                    fileProtection: FileProtectionType? = Config.defaultFileProtection,
                    exportRoot: URL? = nil,
                    systemLog: Bool = true,
                    systemLogFullText: Bool = false,
                    excludeFromBackup: Bool = false,
                    clock: @escaping @Sendable () -> UInt64 = { UInt64(max(0, Date().timeIntervalSince1970 * 1000)) }) {
            self.directory = directory
            self.key = key
            self.platform = platform
            self.process = process
            self.processName = processName
            self.collectors = collectors
            self.scrub = scrub
            self.diagnostics = diagnostics
            self.maxFileBytes = maxFileBytes
            self.maxProcessBytes = maxProcessBytes
            self.keepFreshFor = keepFreshFor
            self.flushDelay = flushDelay
            self.deflateMemLevel = deflateMemLevel
            self.fileProtection = fileProtection
            self.exportRoot = exportRoot
                ?? FileManager.default.temporaryDirectory.appendingPathComponent("cipherlog-exports", isDirectory: true)
            self.systemLog = systemLog
            self.systemLogFullText = systemLogFullText
            self.excludeFromBackup = excludeFromBackup
            self.clock = clock
        }
    }

    public let config: Config
    let processName: String

    /// Errors of the calls that wait for the writer.
    public enum WaitError: Error, Equatable {
        /// The writer did not finish within the timeout (it goes on in the background).
        case timedOut
    }
    private let fs: LogFileSystem
    private let queue: DispatchQueue
    private let queueKey = DispatchSpecificKey<UInt8>()
    private let onFlag = OSAllocatedUnfairLock(initialState: true)

    // Queue-confined state.
    private enum State { case on, off, closed }
    private var state = State.on
    private var file: OpenFile?
    private var linesSinceFlush = 0
    private var flushScheduled = false
    private var dropped = 0
    private var lastOpenAttempt: UInt64?
    private var createdNames = Set<String>()
    private var lastCreatedAt: UInt64?
    private var usedExportRoots = Set<URL>()
    private var directoryExcluded = false

    static let retryOpenAfterMs: UInt64 = 60_000
    static let recentSmallFile = 4 * 1024
    static let bundleCap = 4 * 1024 * 1024
    static let exportMaxAge: TimeInterval = 7 * 24 * 3600

    /// Starts the writer and opens a new file in the background. Never throws; failures go to diagnostics.
    public init(_ config: Config) {
        self.config = config
        self.processName = LineFormat.name(config.processName, empty: "-")
        self.fs = config.fileSystem
        self.queue = DispatchQueue(label: "cipherlog.\(processName)", qos: .utility)
        queue.setSpecific(key: queueKey, value: 1)
        let start = config.clock()
        let warning = CipherLog.testKeyWarning(config)
        if let warning {
            CipherLog.systemLogger.fault("\(warning, privacy: .public)")
        }
        queue.async {
            if let warning { self.config.diagnostics(warning) }
            _ = self.ensureFile(now: start)
        }
    }

    /// True when this package was compiled without the DEBUG condition (a release build).
    static var compiledWithoutDebug: Bool {
        #if DEBUG
        return false
        #else
        return true
        #endif
    }

    static let testKeyWarningText = "cipherlog: started with the TEST key from vectors/test-key.json in a release build; anyone can read these logs. Ship your own public key."

    /// The warning of SPEC.md 7.1, or nil: the test key in a build compiled without DEBUG.
    static func testKeyWarning(_ config: Config) -> String? {
        config.releaseBuild && config.key.isTestKey ? testKeyWarningText : nil
    }

    /// cipherlog's own messages to the system log (start failures, the test-key warning).
    static let systemLogger = os.Logger(subsystem: "cipherlog", category: "cipherlog")

    /// False after a disk-full or crypto failure (until the process restarts) and after `close()`.
    public var isOn: Bool { onFlag.withLock { $0 } }

    // MARK: Public API

    /// Enqueues one line. Non-blocking; dropped without queueing when the writer is off.
    public func log(_ level: CipherLogLevel, category: String, _ message: String) {
        guard isOn else { return }
        let time = config.clock()
        let text = config.scrub(message)
        queue.async { self.append(time: time, level: level, category: category, message: text) }
    }

    /// Writes `<type name>: <message>` (scrubbed), never a stack trace.
    public func log(_ level: CipherLogLevel = .error, category: String, error: Error) {
        log(level, category: category, CipherLog.describe(error))
    }

    /// Writes everything queued so far. Waits at most `timeout` seconds; runs inline on the writer queue.
    @discardableResult
    public func flush(timeout: TimeInterval = 1) -> Bool {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            flushNow()
            return true
        }
        let done = DispatchSemaphore(value: 0)
        queue.async {
            self.flushNow()
            done.signal()
        }
        return done.wait(timeout: .now() + timeout) == .success
    }

    /// Closes the current file with a `final` record. Later lines are dropped. Waits at most `timeout` seconds;
    /// true when it finished in time.
    @discardableResult
    public func close(timeout: TimeInterval = 2) -> Bool {
        setOn(false)
        return (try? onQueue(timeout: timeout) { () -> Void in
            if self.state == .on, self.file != nil {
                do { try self.closeFile() } catch { self.fail(error) }
            }
            if self.state == .on { self.state = .closed }
            self.setOn(false)
        }) != nil
    }

    /// Sign out / account deletion: closes the current file, deletes every cipherlog file of every process in the
    /// directory and all exports, then opens a new file (when the writer is on). Waits at most `timeout` seconds;
    /// true when it finished in time.
    @discardableResult
    public func wipe(timeout: TimeInterval = 5) -> Bool {
        (try? onQueue(timeout: timeout) { () -> Void in
            if self.state == .on, self.file != nil {
                do { try self.closeFile() } catch { self.fail(error) }
            }
            for f in self.fs.list(self.config.directory) where !f.isDirectory && FileName.parse(f.name) != nil {
                try? self.fs.remove(f.url)
            }
            for root in self.usedExportRoots.union([self.config.exportRoot]) {
                for folder in self.exportFolders(in: root) { try? self.fs.remove(folder.url) }
            }
            if self.state == .on {
                self.lastOpenAttempt = nil
                _ = self.ensureFile(now: self.config.clock())
            }
        }) != nil
    }

    /// Support export: all files of all processes (newest first up to 4 MiB) plus a fresh `device now` file.
    /// Written to `<root>/<random id>/cipherlog-<UTC yyyyMMdd-HHmm>.cipherlogs.txt` as armored text (SPEC.md 4.1),
    /// which mail filters let through, or as binary `….cipherlogs` with `armored: false`. Export folders older than
    /// 7 days are deleted first. Throws `WaitError.timedOut` when the writer does not finish within `timeout` seconds.
    public func exportBundle(root: URL? = nil, armored: Bool = true, timeout: TimeInterval = 10) throws -> URL {
        try onQueue(timeout: timeout) { () throws -> URL in
            self.flushNow()
            let root = root ?? self.config.exportRoot
            self.usedExportRoots.insert(root)
            let now = self.config.clock()
            let nowDate = Date(timeIntervalSince1970: TimeInterval(now) / 1000)
            for folder in self.exportFolders(in: root) where nowDate.timeIntervalSince(folder.modified) > CipherLog.exportMaxAge {
                try? self.fs.remove(folder.url)
            }
            let deviceNow = try self.deviceNowFile(now: now)
            let all = self.fs.list(self.config.directory)
                .compactMap { f -> (LogFileInfo, FileName.Parsed)? in
                    guard !f.isDirectory, let p = FileName.parse(f.name) else { return nil }
                    return (f, p)
                }
                .sorted { ($0.1.createdAt, $0.0.name) > ($1.1.createdAt, $1.0.name) }
            let files = self.selectNewest(all.map(\.0), reserved: Format.bundleEntrySize(deviceNow))
            let data = Format.bundle(files + [deviceNow])
            let folder = root.appendingPathComponent(SecureRandom.bytes(16).hex, isDirectory: true)
            try self.fs.createDirectory(folder, protection: self.config.fileProtection)
            let ext = armored ? CipherLogArmor.fileExtension : FileName.bundleExtension
            let url = folder.appendingPathComponent("cipherlog-\(LineFormat.stamp(now)).\(ext)")
            let bytes = armored ? Data(CipherLogArmor.armor(data).utf8) : data
            let h = try self.fs.createFile(url, initial: bytes, protection: self.config.fileProtection)
            h.close()
            return url
        }
    }

    /// Crash/failure report: the current file of this process after a flush, plus the previous one when the
    /// current one is under 4 KiB. A bundle (`CPB1`), or nil when there is no file or on timeout.
    public func recentBundle(timeout: TimeInterval = 2) -> Data? {
        (try? onQueue(timeout: timeout) { () -> Data? in
            self.replaceIfVanished()
            self.flushNow()
            let own = self.ownFiles()
            guard let currentName = self.file?.name ?? own.last?.name,
                  let idx = own.firstIndex(where: { $0.name == currentName }),
                  let current = try? self.fs.read(own[idx].url) else { return nil }
            var entries = [current]
            if current.count < CipherLog.recentSmallFile, idx > 0, let prev = try? self.fs.read(own[idx - 1].url) {
                entries.insert(prev, at: 0)
            }
            return Format.bundle(entries)
        }) ?? nil
    }

    /// The newest file of the previous run of this process, as a bundle; nil when there is none or on timeout.
    public func previousRunBundle(timeout: TimeInterval = 2) -> Data? {
        (try? onQueue(timeout: timeout) { () -> Data? in
            guard let prev = self.ownFiles().last(where: {
                      !self.createdNames.contains($0.name) && $0.size >= Format.headerSize
                  }),
                  let data = try? self.fs.read(prev.url) else { return nil }
            return Format.bundle([data])
        }) ?? nil
    }

    // MARK: Helpers for callers

    static func describe(_ error: Error) -> String {
        let type = String(describing: Swift.type(of: error))
        let message: String
        if let le = error as? LocalizedError, let d = le.errorDescription {
            message = d
        } else if Swift.type(of: error) is NSError.Type {
            let ns = error as NSError
            message = "\(ns.domain) \(ns.code) \(ns.localizedDescription)"
        } else {
            message = String(describing: error)
        }
        return "\(type): \(message)"
    }

    // MARK: Queue work

    /// Runs `body` on the writer queue (inline when already there) and waits at most `timeout` seconds.
    /// Never `queue.sync`: libdispatch would run the body, and with it the app's collectors and diagnostics, on the
    /// caller's thread, so a collector that hops to the main thread would trap or deadlock when called from main.
    private func onQueue<T>(timeout: TimeInterval, _ body: @escaping () throws -> T) throws -> T {
        if DispatchQueue.getSpecific(key: queueKey) != nil { return try body() }
        let box = ResultBox<T>()
        let done = DispatchSemaphore(value: 0)
        queue.async {
            box.result = Result { try body() }
            done.signal()
        }
        guard done.wait(timeout: .now() + max(0, timeout)) == .success, let result = box.result else {
            throw WaitError.timedOut
        }
        return try result.get()
    }

    private func setOn(_ on: Bool) { onFlag.withLock { $0 = on } }

    private func append(time: UInt64, level: CipherLogLevel, category: String, message: String) {
        guard state == .on else { return }
        // At the start of a batch (one check per batch), a file deleted by another process's wipe is replaced.
        if file != nil, linesSinceFlush == 0 { replaceIfVanished() }
        guard ensureFile(now: time) else {
            if state == .on { dropped += 1 }
            return
        }
        let cat = LineFormat.name(category, empty: "-")
        let line = LineFormat.line(time: time, level: level, process: processName, category: cat, message: message)
        do {
            try writeText(line)
        } catch {
            fail(error)
            return
        }
        guard let f = file else { return }
        f.hasAppLines = true
        if level >= .warning || f.bytes + f.encoder.pendingCompressed >= config.maxFileBytes {
            flushNow()
        } else {
            scheduleFlush()
        }
    }

    private func writeText(_ line: String) throws {
        guard let f = file else { return }
        try f.encoder.write(line)
        linesSinceFlush += 1
        config.textTap?(line)
    }

    private func scheduleFlush() {
        guard !flushScheduled else { return }
        flushScheduled = true
        queue.asyncAfter(deadline: .now() + config.flushDelay) {
            self.flushScheduled = false
            self.flushNow()
        }
    }

    private func flushNow() {
        guard state == .on, let f = file, linesSinceFlush > 0 else { return }
        do {
            let records = try f.encoder.flushRecords()
            try f.write(records)
            linesSinceFlush = 0
            // Rotate only a file that holds app lines, so a tiny limit cannot loop on device blocks.
            if f.bytes >= config.maxFileBytes, f.hasAppLines { try rotate() }
        } catch {
            fail(error)
        }
    }

    /// Another process's wipe (SPEC.md 3.7) may have deleted the open file; lines written to it would be lost for
    /// good, so it is dropped (no `final`) and a new file opens.
    private func replaceIfVanished() {
        guard state == .on, let f = file, !fs.exists(f.url) else { return }
        f.handle.close()
        file = nil
        linesSinceFlush = 0
        lastOpenAttempt = nil
        _ = ensureFile(now: config.clock())
    }

    private func rotate() throws {
        try closeFile()
        _ = ensureFile(now: config.clock())
    }

    /// Writes the `final` record(s) and closes the handle.
    private func closeFile() throws {
        guard let f = file else { return }
        let records = try f.encoder.finishRecords()
        try f.write(records)
        f.handle.close()
        file = nil
        linesSinceFlush = 0
    }

    /// Opens a file if none is open, at most once a minute after a failure. Returns whether a file is open.
    private func ensureFile(now: UInt64) -> Bool {
        guard state == .on else { return false }
        if file != nil { return true }
        if let last = lastOpenAttempt, now >= last, now - last < CipherLog.retryOpenAfterMs { return false }
        lastOpenAttempt = now
        do {
            try openFile(now: now)
        } catch {
            // Disk full and crypto errors turn the writer off; any other open failure is retried (SPEC.md 3.6).
            if FileErrors.isDiskFull(error) || error is CryptoFailure || error is Deflater.DeflateError {
                fail(error)
            }
            return false
        }
        lastOpenAttempt = nil
        retention(now: now)
        // The device block reaches the disk soon even if nothing else is logged; a `not written` warning at once.
        if file?.hasWarning == true { flushNow() } else { scheduleFlush() }
        return file != nil
    }

    private func openFile(now clockNow: UInt64) throws {
        // createdAt strictly increases per writer, so name order is creation order even within one millisecond.
        let now = lastCreatedAt.map { max(clockNow, $0 + 1) } ?? clockNow
        try fs.createDirectory(config.directory, protection: config.fileProtection)
        if config.excludeFromBackup, !directoryExcluded {
            // Best effort: a directory that cannot be marked still takes logs.
            var dir = config.directory
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            directoryExcluded = (try? dir.setResourceValues(values)) != nil
        }
        let encoder = try FileEncoder(key: config.key, createdAt: now, platform: config.platform,
                                      process: config.process, memLevel: config.deflateMemLevel,
                                      cryptoFault: config.cryptoFault)
        let name = FileName.make(process: processName, createdAt: now, fileId: encoder.fileId)
        let url = config.directory.appendingPathComponent(name)
        let handle = try fs.createFile(url, initial: encoder.header, protection: config.fileProtection)
        file = OpenFile(name: name, url: url, handle: handle, encoder: encoder, bytes: encoder.header.count)
        createdNames.insert(name)
        lastCreatedAt = now
        linesSinceFlush = 0
        for line in deviceBlock(fileId: encoder.fileId, time: now) { try writeText(line) }
        if dropped > 0 {
            try writeText(LineFormat.line(time: now, level: .warning, process: processName,
                                          category: "cipherlog", message: "not written \(dropped) lines"))
            dropped = 0
            file?.hasWarning = true
        }
    }

    /// Device block lines, all stamped with the file's creation time.
    private func deviceBlock(fileId: Data, time: UInt64) -> [String] {
        func line(_ message: String) -> String {
            LineFormat.line(time: time, level: .info, process: processName, category: "device", message: message)
        }
        var lines = [line("cipherlog \(CipherLog.version) · file \(fileId.prefix(4).hex) · platform \(config.platform) · process \(config.process)")]
        for c in config.collectors {
            do {
                for text in try c.collect() { lines.append(line(config.scrub("\(c.name) · \(text)"))) }
            } catch {
                lines.append(line("\(c.name) · failed \(String(describing: type(of: error)))"))
            }
        }
        return lines
    }

    private func deviceNowFile(now: UInt64) throws -> Data {
        let encoder = try FileEncoder(key: config.key, createdAt: now, platform: config.platform,
                                      process: config.process, memLevel: config.deflateMemLevel,
                                      cryptoFault: config.cryptoFault)
        for line in deviceBlock(fileId: encoder.fileId, time: now) { try encoder.write(line) }
        return encoder.header + (try encoder.finishRecords())
    }

    /// Any failure after a file opened (SPEC.md 3.6): off until restart, one diagnostics line.
    private func fail(_ error: Error) {
        if FileErrors.isDiskFull(error) {
            turnOff("disk full")
        } else if error is CryptoFailure {
            turnOff("crypto error")
        } else if error is Deflater.DeflateError {
            turnOff("compression error")
        } else {
            turnOff("write failed (\(FileErrors.reason(error)))")
        }
    }

    private func turnOff(_ reason: String) {
        guard state == .on else { return }
        state = .off
        setOn(false)
        file?.handle.close()
        file = nil
        linesSinceFlush = 0
        config.diagnostics("cipherlog off: \(reason)")
    }

    /// Own process's files, oldest first (name order is time order).
    private func ownFiles() -> [LogFileInfo] {
        fs.list(config.directory)
            .filter { !$0.isDirectory && FileName.parse($0.name)?.process == processName }
            .sorted { $0.name < $1.name }
    }

    /// Keeps this process's files under maxProcessBytes, oldest first, never deleting fresh files or the open one.
    private func retention(now: UInt64) {
        let files = ownFiles()
        var total = files.reduce(0) { $0 + $1.size }
        guard total > config.maxProcessBytes else { return }
        let nowDate = Date(timeIntervalSince1970: TimeInterval(now) / 1000)
        for f in files where total > config.maxProcessBytes {
            if f.name == file?.name { continue }
            if nowDate.timeIntervalSince(f.modified) < config.keepFreshFor { continue }
            if (try? fs.remove(f.url)) != nil { total -= f.size }
        }
    }

    private func selectNewest(_ newestFirst: [LogFileInfo], reserved: Int) -> [Data] {
        var budget = CipherLog.bundleCap - Format.bundleMagic.count - reserved
        var picked: [Data] = []
        for f in newestFirst {
            // A file shorter than a header (another process between create and header write) carries nothing.
            guard let data = try? fs.read(f.url), data.count >= Format.headerSize else { continue }
            let size = Format.bundleEntrySize(data)
            if size > budget { break }
            budget -= size
            picked.append(data)
        }
        return picked.reversed()
    }

    /// Export folders: direct subfolders of `root` named with 32 lowercase hex digits (SPEC.md 4).
    private func exportFolders(in root: URL) -> [LogFileInfo] {
        fs.list(root).compactMap { folder -> LogFileInfo? in
            guard folder.isDirectory, folder.name.count == 32,
                  folder.name.allSatisfy({ ("0"..."9").contains($0) || ("a"..."f").contains($0) }) else { return nil }
            // Age: the newest file inside, or the folder itself when it is empty.
            let newest = fs.list(folder.url).map(\.modified).max() ?? folder.modified
            return LogFileInfo(url: folder.url, size: 0, modified: newest, isDirectory: true)
        }
    }
}

struct CryptoFailure: Error {}

/// The result of one `onQueue` call; written on the writer queue before the semaphore is signalled, read after.
private final class ResultBox<T>: @unchecked Sendable {
    var result: Result<T, Error>?
}

extension CipherLog.Config {
    /// `.completeUntilFirstUserAuthentication` where files carry a Data Protection class (iOS and its relatives),
    /// nil on macOS.
    public static var defaultFileProtection: FileProtectionType? {
        #if os(iOS) || os(watchOS) || os(tvOS) || os(visionOS)
        return .completeUntilFirstUserAuthentication
        #else
        return nil
        #endif
    }
}

/// One open file: handle plus its encoder. Queue-confined.
final class OpenFile {
    let name: String
    let url: URL
    let handle: LogFileHandle
    let encoder: FileEncoder
    var bytes: Int
    var hasAppLines = false
    var hasWarning = false

    init(name: String, url: URL, handle: LogFileHandle, encoder: FileEncoder, bytes: Int) {
        self.name = name
        self.url = url
        self.handle = handle
        self.encoder = encoder
        self.bytes = bytes
    }

    func write(_ records: Data) throws {
        guard !records.isEmpty else { return }
        try handle.write(records)
        bytes += records.count
    }
}

/// Header, compression stream and record sealing of one file. Fresh fileKey and fileId from the system CSPRNG.
final class FileEncoder {
    let fileKey: SymmetricKey
    let fileId: Data
    let createdAt: UInt64
    let header: Data
    private let deflater: Deflater
    private let cryptoFault: (@Sendable () -> Bool)?
    private(set) var seq: UInt32 = 0
    private var finished = false

    init(key: CipherLogKey, createdAt: UInt64, platform: UInt8, process: UInt8, memLevel: Int32,
         cryptoFault: (@Sendable () -> Bool)?) throws {
        let keyBytes = SecureRandom.bytes(32)
        fileKey = SymmetricKey(data: keyBytes)
        fileId = SecureRandom.bytes(16)
        self.createdAt = createdAt
        self.cryptoFault = cryptoFault
        if cryptoFault?() == true { throw CryptoFailure() }
        do {
            header = try Format.sealHeader(.init(fileKey: keyBytes, fileId: fileId, createdAt: createdAt,
                                                 platform: platform, process: process), key: key)
        } catch {
            throw CryptoFailure()
        }
        deflater = try Deflater(level: 6, memLevel: memLevel)
    }

    var pendingCompressed: Int { deflater.pendingOutputCount }

    func write(_ text: String) throws { try deflater.write(Data(text.utf8)) }

    /// Z_SYNC_FLUSH, then records (none when nothing new was produced).
    func flushRecords() throws -> Data { try records(try deflater.sync(), final: false) }

    /// Z_FINISH, then records; the last one carries `final` (an empty final record when nothing is left).
    func finishRecords() throws -> Data {
        guard !finished else { return Data() }
        finished = true
        return try records(try deflater.finish(), final: true)
    }

    private func records(_ plain: Data, final: Bool) throws -> Data {
        var out = Data()
        var offset = plain.startIndex
        repeat {
            let end = min(offset + Format.maxPlain, plain.endIndex)
            let isLast = end == plain.endIndex
            let flags: UInt8 = final && isLast ? Format.finalFlag : 0
            if plain.isEmpty && !final { break }
            if cryptoFault?() == true { throw CryptoFailure() }
            guard seq < UInt32.max else { throw CryptoFailure() }
            do {
                out.append(try Format.sealRecord(fileKey: fileKey, fileId: fileId, seq: seq, flags: flags,
                                                 plaintext: Data(plain[offset..<end])))
            } catch {
                throw CryptoFailure()
            }
            seq += 1
            offset = end
        } while offset < plain.endIndex
        return out
    }
}
