import Foundation

/// File operations the writer uses. Internal seam so tests can inject failures (disk full, files that do not open).
protocol LogFileSystem: Sendable {
    /// Creates the directory (and its parents) in the data protection class `protection`, and gives an existing one
    /// that class: files created in it inherit the class of their directory.
    func createDirectory(_ url: URL, protection: FileProtectionType?) throws
    /// Creates a new file exclusively (fails if it exists: never append to an old file), in the data protection class
    /// `protection` from its creation on, and writes `initial`.
    func createFile(_ url: URL, initial: Data, protection: FileProtectionType?) throws -> LogFileHandle
    func list(_ directory: URL) -> [LogFileInfo]
    func read(_ url: URL) throws -> Data
    func remove(_ url: URL) throws
    /// Whether the file still exists (another process may have wiped the directory).
    func exists(_ url: URL) -> Bool
}

protocol LogFileHandle: AnyObject {
    func write(_ data: Data) throws
    func close()
}

struct LogFileInfo: Sendable {
    var url: URL
    var name: String { url.lastPathComponent }
    var size: Int
    var modified: Date
    var isDirectory: Bool
}

struct DefaultFileSystem: LogFileSystem {
    func createDirectory(_ url: URL, protection: FileProtectionType?) throws {
        let attributes: [FileAttributeKey: Any]? = protection.map { [.protectionKey: $0] }
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: attributes)
        // A directory that already existed keeps the class it was made with, for example `complete` from the
        // entitlement of another process of the App Group. Best effort: if it cannot change now (phone locked), the
        // file below is still created in its own class.
        if let protection {
            try? FileManager.default.setAttributes([.protectionKey: protection], ofItemAtPath: url.path)
        }
    }

    func createFile(_ url: URL, initial: Data, protection: FileProtectionType?) throws -> LogFileHandle {
        guard let protection else { return try createPlain(url, initial: initial) }
        // The file is born in its class (Foundation creates it with open_dprotected_np). Creating it in the inherited
        // class and changing the class afterwards fails while the phone is locked when the inherited class is
        // `complete`: neither step can run without the class A key (SPEC.md 3.6).
        do {
            try initial.write(to: url, options: [.withoutOverwriting, Self.writingOption(protection)])
        } catch {
            // Never remove a file that was there before: that is the "fail if it exists" case.
            if !Self.isExists(error) { try? FileManager.default.removeItem(at: url) }
            throw error
        }
        let fd = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return open(path, O_WRONLY | O_APPEND | O_CLOEXEC)
        }
        guard fd >= 0 else {
            let code = POSIXErrorCode(rawValue: errno) ?? .EIO
            try? FileManager.default.removeItem(at: url)
            throw POSIXError(code)
        }
        _ = fchmod(fd, 0o600)
        return Handle(fd: fd)
    }

    /// No class asked for: the file takes the class of its directory.
    private func createPlain(_ url: URL, initial: Data) throws -> LogFileHandle {
        let fd = url.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        }
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let h = Handle(fd: fd)
        do {
            try h.write(initial)
        } catch {
            h.close()
            try? FileManager.default.removeItem(at: url)
            throw error
        }
        return h
    }

    static func writingOption(_ protection: FileProtectionType) -> Data.WritingOptions {
        switch protection {
        case .complete: return .completeFileProtection
        case .completeUnlessOpen: return .completeFileProtectionUnlessOpen
        case .completeUntilFirstUserAuthentication: return .completeFileProtectionUntilFirstUserAuthentication
        case .none: return .noFileProtection
        default: return .completeFileProtectionUntilFirstUserAuthentication
        }
    }

    static func isExists(_ error: Error) -> Bool {
        if (error as? CocoaError)?.code == .fileWriteFileExists { return true }
        return FileErrors.posixCode(error) == EEXIST
    }

    func list(_ directory: URL) -> [LogFileInfo] {
        let keys: [URLResourceKey] = [.fileSizeKey, .contentModificationDateKey, .isDirectoryKey]
        guard let urls = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: keys) else {
            return []
        }
        return urls.compactMap { u in
            guard let v = try? u.resourceValues(forKeys: Set(keys)) else { return nil }
            return LogFileInfo(url: u, size: v.fileSize ?? 0, modified: v.contentModificationDate ?? .distantPast,
                               isDirectory: v.isDirectory ?? false)
        }
    }

    func read(_ url: URL) throws -> Data { try Data(contentsOf: url) }

    func remove(_ url: URL) throws { try FileManager.default.removeItem(at: url) }

    func exists(_ url: URL) -> Bool { FileManager.default.fileExists(atPath: url.path) }

    /// A plain file descriptor: `write(2)` errors come back as `POSIXError` with their errno (EPERM for a
    /// Data Protection lock, EIO, ENOSPC), which `FileErrors.reason` turns into the diagnostics reason.
    final class Handle: LogFileHandle {
        private var fd: Int32
        init(fd: Int32) { self.fd = fd }
        deinit { close() }

        func write(_ data: Data) throws {
            guard fd >= 0 else { throw POSIXError(.EBADF) }
            try data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
                guard var p = buf.baseAddress else { return }
                var left = buf.count
                while left > 0 {
                    let n = Darwin.write(fd, p, left)
                    if n < 0 {
                        if errno == EINTR { continue }
                        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                    }
                    p += n
                    left -= n
                }
            }
        }

        func close() {
            guard fd >= 0 else { return }
            _ = Darwin.close(fd)
            fd = -1
        }
    }
}

enum FileErrors {
    /// The diagnostics reason of a write or open failure: the errno's symbolic name (`EPERM`, `EIO`, …) when one is
    /// found in the error or its underlying errors, otherwise `<domain> <code>`.
    static func reason(_ error: Error) -> String {
        if let code = posixCode(error) { return errnoName(code) }
        let ns = error as NSError
        return "\(ns.domain) \(ns.code)"
    }

    static func posixCode(_ error: Error) -> Int32? {
        if let p = error as? POSIXError { return p.code.rawValue }
        let ns = error as NSError
        if ns.domain == NSPOSIXErrorDomain { return Int32(ns.code) }
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? Error { return posixCode(underlying) }
        return nil
    }

    static func errnoName(_ code: Int32) -> String {
        let names: [Int32: String] = [
            EPERM: "EPERM", ENOENT: "ENOENT", EINTR: "EINTR", EIO: "EIO", ENXIO: "ENXIO", EBADF: "EBADF",
            EAGAIN: "EAGAIN", ENOMEM: "ENOMEM", EACCES: "EACCES", EFAULT: "EFAULT", EBUSY: "EBUSY", EEXIST: "EEXIST",
            ENOTDIR: "ENOTDIR", EISDIR: "EISDIR", EINVAL: "EINVAL", ENFILE: "ENFILE", EMFILE: "EMFILE",
            EFBIG: "EFBIG", ENOSPC: "ENOSPC", ESPIPE: "ESPIPE", EROFS: "EROFS", EPIPE: "EPIPE",
            ENAMETOOLONG: "ENAMETOOLONG", EDQUOT: "EDQUOT", ESTALE: "ESTALE", EDEADLK: "EDEADLK",
            ENOTSUP: "ENOTSUP", ETIMEDOUT: "ETIMEDOUT",
        ]
        return names[code] ?? "errno \(code)"
    }

    /// Disk full: ENOSPC / EDQUOT in any of the usual wrappings.
    static func isDiskFull(_ error: Error) -> Bool {
        let ns = error as NSError
        if ns.domain == NSPOSIXErrorDomain, ns.code == Int(ENOSPC) || ns.code == Int(EDQUOT) { return true }
        if ns.domain == NSCocoaErrorDomain, ns.code == NSFileWriteOutOfSpaceError { return true }
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? Error { return isDiskFull(underlying) }
        return false
    }
}

/// File names (SPEC.md 2 rule 5): `<process name>-<createdAt ms, 13 digits>-<fileId hex 8>.cipherlog`.
enum FileName {
    static let fileExtension = "cipherlog"
    static let bundleExtension = "cipherlogs"

    static func make(process: String, createdAt: UInt64, fileId: Data) -> String {
        let ms = String(createdAt)
        let padded = String(repeating: "0", count: max(0, 13 - ms.count)) + ms
        return "\(process)-\(padded)-\(fileId.prefix(4).hex).\(fileExtension)"
    }

    struct Parsed: Equatable {
        var process: String
        var createdAt: UInt64
    }

    static func parse(_ name: String) -> Parsed? {
        guard name.hasSuffix("." + fileExtension) else { return nil }
        let base = name.dropLast(fileExtension.count + 1)
        let parts = base.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count >= 3 else { return nil }
        let idPart = parts[parts.count - 1], msPart = parts[parts.count - 2]
        guard idPart.count == 8, idPart.allSatisfy(\.isHexDigit),
              msPart.count >= 13, msPart.allSatisfy(\.isASCII), let ms = UInt64(msPart) else { return nil }
        return Parsed(process: parts[0..<(parts.count - 2)].joined(separator: "-"), createdAt: ms)
    }
}
