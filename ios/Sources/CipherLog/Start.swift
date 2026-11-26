import Foundation
import os

/// The integration API of SPEC.md 7.1: one `CipherLog.start(key:appGroup:)` per process, then `CipherLogger` at the
/// call sites.
extension CipherLog {
    /// What `start(key:appGroup:options:)` lets an app change. Every value has a default.
    public struct Options: Sendable {
        /// Log directory. Default: `Library/Application Support/cipherlog` in the App Group container, or in the
        /// app's own container without a group (macOS: `Application Support/<bundle id>/cipherlog`).
        public var directory: URL?
        /// Default: 1 for the app, 2 for an app extension.
        public var process: UInt8?
        /// Default: `app`, or the extension's bundle name (`CFBundleName`).
        public var processName: String?
        /// Default: `CipherLogCollector.defaults` (app version and install source, model and OS, locale, free space).
        public var collectors: [CipherLogCollector]
        public var scrub: @Sendable (String) -> String
        /// Writer failures (`cipherlog off: …`), the test-key warning and start failures.
        public var diagnostics: @Sendable (String) -> Void
        /// Default: `.completeUntilFirstUserAuthentication` on iOS, nil (the container's default) on macOS.
        public var fileProtection: FileProtectionType?
        /// Default: `cipherlog-exports` in the process's temporary directory.
        public var exportRoot: URL?
        /// `CipherLogger` also writes to os.Logger. Default true.
        public var systemLog: Bool
        /// `CipherLogger` hands the full text, private values included, to os.Logger. Default false.
        public var systemLogFullText: Bool
        /// Excludes the log directory from backups. Default true.
        public var excludeFromBackup: Bool

        public init(directory: URL? = nil,
                    process: UInt8? = nil,
                    processName: String? = nil,
                    collectors: [CipherLogCollector] = CipherLogCollector.defaults,
                    scrub: @escaping @Sendable (String) -> String = { $0 },
                    diagnostics: @escaping @Sendable (String) -> Void = { _ in },
                    fileProtection: FileProtectionType? = Config.defaultFileProtection,
                    exportRoot: URL? = nil,
                    systemLog: Bool = true,
                    systemLogFullText: Bool = false,
                    excludeFromBackup: Bool = true) {
            self.directory = directory
            self.process = process
            self.processName = processName
            self.collectors = collectors
            self.scrub = scrub
            self.diagnostics = diagnostics
            self.fileProtection = fileProtection
            self.exportRoot = exportRoot
            self.systemLog = systemLog
            self.systemLogFullText = systemLogFullText
            self.excludeFromBackup = excludeFromBackup
        }
    }

    private static let sharedLock = OSAllocatedUnfairLock<CipherLog?>(initialState: nil)

    /// The writer of this process, set by the first `start`; nil before. `CipherLogger` writes to it.
    public static var shared: CipherLog? { sharedLock.withLock { $0 } }

    /// Starts the writer of this process once (app and each extension) and returns it; later calls return the same
    /// writer and ignore their arguments. `key` is the public key string `cipherlog-pub-v1:…` (SPEC.md 1.1).
    /// `appGroup` puts the files in the App Group container so the app can export the extensions' logs too.
    ///
    /// Returns nil, without crashing, only when it cannot start: the key string is wrong or the App Group has no
    /// container (missing entitlement). The reason goes to the system log (subsystem `cipherlog`) and to
    /// `options.diagnostics`.
    @discardableResult
    public static func start(key: String, appGroup: String? = nil, options: Options = Options()) -> CipherLog? {
        if let existing = shared { return existing }
        let parsed: CipherLogKey
        do {
            parsed = try CipherLogKey(string: key)
        } catch {
            // CipherLogKeyError never echoes a private key.
            reportStartFailure("cipherlog not started: \(error)", options.diagnostics)
            return nil
        }
        guard let directory = options.directory ?? defaultDirectory(appGroup: appGroup) else {
            reportStartFailure("cipherlog not started: App Group \(appGroup ?? "-") has no container; "
                + "add it to this target's App Groups entitlement", options.diagnostics)
            return nil
        }
        let detected = detectProcess(bundleURL: Bundle.main.bundleURL,
                                     bundleName: Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String)
        let config = Config(directory: directory,
                            key: parsed,
                            process: options.process ?? detected.process,
                            processName: options.processName ?? detected.name,
                            collectors: options.collectors,
                            scrub: options.scrub,
                            diagnostics: options.diagnostics,
                            fileProtection: options.fileProtection,
                            exportRoot: options.exportRoot,
                            systemLog: options.systemLog,
                            systemLogFullText: options.systemLogFullText,
                            excludeFromBackup: options.excludeFromBackup)
        return start(config)
    }

    /// Starts a writer with a full `Config` as the shared one (`CipherLogger` writes to it). Like the other `start`,
    /// only the first call of a process starts a writer; later calls return it.
    @discardableResult
    public static func start(_ config: Config) -> CipherLog {
        sharedLock.withLock { shared in
            if let shared { return shared }
            let log = CipherLog(config)
            shared = log
            return log
        }
    }

    /// Tests only: closes and forgets the shared writer, or installs one.
    static func replaceShared(_ log: CipherLog?) {
        let old = sharedLock.withLock { shared -> CipherLog? in
            let old = shared
            shared = log
            return old
        }
        if let old, old !== log { old.close() }
    }

    /// An app extension (bundle ending in `.appex`) is process 2 named after its bundle name; anything else is the
    /// app, process 1, named `app`.
    static func detectProcess(bundleURL: URL, bundleName: String?) -> (process: UInt8, name: String) {
        guard bundleURL.pathExtension == "appex" else { return (1, "app") }
        let name = bundleName.flatMap { $0.isEmpty ? nil : $0 } ?? bundleURL.deletingPathExtension().lastPathComponent
        return (2, name)
    }

    /// `Library/Application Support/cipherlog` in the App Group container, or in the app's own container.
    static func defaultDirectory(appGroup: String?, fileManager: FileManager = .default) -> URL? {
        let support: URL
        if let appGroup {
            guard let container = fileManager.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else {
                return nil
            }
            support = container.appendingPathComponent("Library/Application Support", isDirectory: true)
        } else {
            guard let own = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
                return nil
            }
            #if os(macOS)
            // Outside the sandbox Application Support is shared by every app of the user.
            support = own.appendingPathComponent(Bundle.main.bundleIdentifier ?? "cipherlog", isDirectory: true)
            #else
            support = own
            #endif
        }
        return support.appendingPathComponent("cipherlog", isDirectory: true)
    }

    private static func reportStartFailure(_ message: String, _ diagnostics: @escaping @Sendable (String) -> Void) {
        systemLogger.error("\(message, privacy: .public)")
        // Off the caller's thread, like every other diagnostics call (SPEC.md 7).
        DispatchQueue.global(qos: .utility).async { diagnostics(message) }
    }
}
