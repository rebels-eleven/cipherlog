import Foundation

/// Gives lines for the device block at the top of every file (SPEC.md 2.5): each line is written as
/// `<name> · <text>`; a collector that throws gives `<name> · failed <error type name>`.
/// Collectors run on the writer's background queue only (also during `wipe` and `exportBundle` called from the main
/// thread), so they must be thread-safe and fast, and must never wait for the main thread: no
/// `DispatchQueue.main.sync`, no hop to the main actor. The main thread may be the one waiting for the writer; such a
/// collector makes that call time out. Read UI state on the main thread beforehand and hand the values over instead.
public struct CipherLogCollector: Sendable {
    public let name: String
    let collect: @Sendable () throws -> [String]

    public init(name: String, collect: @escaping @Sendable () throws -> [String]) {
        self.name = name
        self.collect = collect
    }

    /// `system · <model identifier> · <OS name> <version>`, for example `system · iPhone12,1 · iOS 26.1`.
    public static let system = CipherLogCollector(name: "system") {
        [modelIdentifier() + " · " + osName() + " " + osVersion()]
    }

    /// `app · <bundle id> · <short version> (<build>) · <install source>` of the main bundle; the install source is
    /// `App Store`, `TestFlight` or `development` (see `installSource()`).
    public static let app = CipherLogCollector(name: "app") {
        let info = Bundle.main.infoDictionary ?? [:]
        let id = Bundle.main.bundleIdentifier ?? "-"
        let version = info["CFBundleShortVersionString"] as? String ?? "-"
        let build = info["CFBundleVersion"] as? String ?? "-"
        return ["\(id) · \(version) (\(build)) · \(installSource())"]
    }

    /// `locale · <locale identifier> · <first preferred language>`, for example `locale · en_GB · en-GB`.
    public static let locale = CipherLogCollector(name: "locale") {
        [Locale.current.identifier + " · " + (Locale.preferredLanguages.first ?? "-")]
    }

    /// `disk · <free space> free`, rounded (whole GB from 1 GB on, tenths below): `disk · 23 GB free`.
    public static let freeSpace = CipherLogCollector(name: "disk") {
        let home = URL(fileURLWithPath: NSHomeDirectory())
        let values = try home.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        guard let bytes = values.volumeAvailableCapacityForImportantUsage else { return ["unknown"] }
        return [roundedSize(bytes) + " free"]
    }

    /// The built-in collectors `CipherLog.start` registers: app, system, locale, disk. They never collect names,
    /// accounts, advertising ids, location or the user-assigned device name.
    public static let defaults: [CipherLogCollector] = [.app, .system, .locale, .freeSpace]

    static func roundedSize(_ bytes: Int64) -> String {
        let gb = Double(max(0, bytes)) / 1_000_000_000
        if gb >= 1 { return "\(Int(gb.rounded())) GB" }
        return String(format: "%.1f GB", gb)
    }

    /// `App Store`, `TestFlight` (the App Store receipt is a sandbox receipt) or `development` (simulator, a build
    /// with an embedded provisioning profile: Xcode, ad hoc, enterprise; on macOS any build without an App Store
    /// receipt).
    static func installSource() -> String {
        #if targetEnvironment(simulator)
        return "development"
        #else
        if Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision") != nil { return "development" }
        guard let receipt = Bundle.main.appStoreReceiptURL else { return "development" }
        if receipt.lastPathComponent == "sandboxReceipt" { return "TestFlight" }
        #if os(macOS)
        return FileManager.default.fileExists(atPath: receipt.path) ? "App Store" : "development"
        #else
        return "App Store"
        #endif
        #endif
    }

    /// The hardware model identifier (`iPhone12,1`, `Mac14,2`), never the user-assigned device name: `uname`'s
    /// machine field on iOS and its relatives, `hw.model` on macOS (where `uname` gives only the CPU architecture).
    static func modelIdentifier() -> String {
        if let sim = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] { return sim + " simulator" }
        #if os(macOS)
        var size = 0
        guard sysctlbyname("hw.model", nil, &size, nil, 0) == 0, size > 0 else { return "unknown" }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname("hw.model", &buf, &size, nil, 0) == 0 else { return "unknown" }
        return String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        #else
        var info = utsname()
        guard uname(&info) == 0 else { return "unknown" }
        return withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        #endif
    }

    static func osName() -> String {
        #if os(iOS)
        return "iOS"
        #elseif os(macOS)
        return "macOS"
        #elseif os(watchOS)
        return "watchOS"
        #elseif os(tvOS)
        return "tvOS"
        #elseif os(visionOS)
        return "visionOS"
        #else
        return "unknown"
        #endif
    }

    static func osVersion() -> String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return v.patchVersion == 0 ? "\(v.majorVersion).\(v.minorVersion)" : "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }
}
