import Foundation
import os

/// Optional device collectors (SPEC.md 7.1). None of them is in `defaults`; an app opts in with one line:
///
/// ```swift
/// CipherLog.start(key: key, options: .init(collectors: CipherLogCollector.defaults + CipherLogCollector.optional()))
/// ```
///
/// Like the defaults they describe the build and the device only: no names, accounts, ad ids, location, network
/// names or addresses, carrier, file names or the user-assigned device name.
extension CipherLogCollector {
    /// All six optional collectors: versionHistory, installDates, memory, screen, network, storageUsage. Call it on the
    /// main thread (`screen()` reads UIKit there); `appGroup` adds the App Group container to `storageUsage`.
    public static func optional(appGroup: String? = nil, defaults: UserDefaults = .standard) -> [CipherLogCollector] {
        [.versionHistory(defaults: defaults), .installDates, .memory, .screen(), .network(),
         .storageUsage(appGroup: appGroup)]
    }

    // MARK: - versionHistory

    /// `versionHistory · 1.4.1 (16) since 2026-11-20 · 1.4 (15) since 2026-11-12`: every app version and build first
    /// seen on this device with the UTC day it was first seen, newest first, at most 20. Kept in `defaults` (key
    /// `cipherlog.versionHistory`). The running version is recorded when this is called, and again when a file opens.
    /// With an App Group suite the app's own privacy manifest needs the reason `1C8F.1`; `.standard` is covered by the
    /// library's manifest (`CA92.1`).
    public static func versionHistory(defaults: UserDefaults = .standard) -> CipherLogCollector {
        let info = Bundle.main.infoDictionary ?? [:]
        return versionHistory(store: defaults,
                              version: info["CFBundleShortVersionString"] as? String ?? "-",
                              build: info["CFBundleVersion"] as? String ?? "-",
                              now: { Date() })
    }

    static let versionHistoryKey = "cipherlog.versionHistory"
    static let versionHistoryLimit = 20

    struct VersionEntry: Equatable {
        let version: String
        let build: String
        let since: String
    }

    static func versionHistory(store: VersionHistoryStore, version: String, build: String,
                               now: @escaping @Sendable () -> Date) -> CipherLogCollector {
        let box = StoreBox(store)
        _ = recordVersion(store: store, version: version, build: build, day: utcDay(now()))
        return CipherLogCollector(name: "versionHistory") {
            let entries = recordVersion(store: box.store, version: version, build: build, day: utcDay(now()))
            return [historyLine(entries)]
        }
    }

    /// Adds the running version when it is new and returns the stored history, newest first.
    @discardableResult
    static func recordVersion(store: VersionHistoryStore, version: String, build: String, day: String) -> [VersionEntry] {
        let old = decodeHistory(store.object(forKey: versionHistoryKey))
        let merged = mergeHistory(old, version: version, build: build, day: day)
        if merged != old { store.set(encodeHistory(merged), forKey: versionHistoryKey) }
        return merged
    }

    static func mergeHistory(_ entries: [VersionEntry], version: String, build: String, day: String) -> [VersionEntry] {
        var out = entries
        if !out.contains(where: { $0.version == version && $0.build == build }) {
            out.insert(VersionEntry(version: version, build: build, since: day), at: 0)
        }
        return Array(out.prefix(versionHistoryLimit))
    }

    /// Stored as an array of `<version>\t<build>\t<yyyy-MM-dd>`; anything else is skipped.
    static func decodeHistory(_ object: Any?) -> [VersionEntry] {
        guard let items = object as? [String] else { return [] }
        return items.compactMap { item in
            let parts = item.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 3 else { return nil }
            return VersionEntry(version: parts[0], build: parts[1], since: parts[2])
        }
    }

    static func encodeHistory(_ entries: [VersionEntry]) -> [String] {
        entries.map { "\(clean($0.version))\t\(clean($0.build))\t\($0.since)" }
    }

    static func historyLine(_ entries: [VersionEntry]) -> String {
        entries.isEmpty ? "none" : entries.map { "\($0.version) (\($0.build)) since \($0.since)" }.joined(separator: " · ")
    }

    private static func clean(_ s: String) -> String {
        s.replacingOccurrences(of: "\t", with: " ").replacingOccurrences(of: "\n", with: " ")
    }

    // MARK: - installDates

    /// `installDates · installed 2026-11-12 · updated 2026-11-20` (UTC days). Both are approximations: iOS has no API
    /// for them. Installed is the creation date of the app container's Library folder (made at the first install, kept
    /// by updates; a restore from backup or a device transfer resets it). Updated is the UTC day the running version
    /// and build was first seen, kept in `UserDefaults.standard` (key `cipherlog.installDates.build`), recorded when
    /// the collector is first used and when a file opens; in the first build that adds the collector it is that first
    /// day, not the real update day. Only files inside the app's data container are read (privacy reason `C617.1`).
    /// `unknown` when not readable (and installed on macOS outside the sandbox, where Library is the user's).
    public static let installDates: CipherLogCollector = {
        let info = Bundle.main.infoDictionary ?? [:]
        return installDates(store: UserDefaults.standard,
                            version: info["CFBundleShortVersionString"] as? String ?? "-",
                            build: info["CFBundleVersion"] as? String ?? "-",
                            now: { Date() }, installed: { installDate() })
    }()

    static let installDatesKey = "cipherlog.installDates.build"

    static func installDates(store: VersionHistoryStore, version: String, build: String,
                             now: @escaping @Sendable () -> Date,
                             installed: @escaping @Sendable () -> Date?) -> CipherLogCollector {
        let box = StoreBox(store)
        _ = recordBuildDay(store: store, version: version, build: build, day: utcDay(now()))
        return CipherLogCollector(name: "installDates") {
            let updated = recordBuildDay(store: box.store, version: version, build: build, day: utcDay(now()))
            return [installDatesLine(installed: installed().map(utcDay) ?? "unknown", updated: updated)]
        }
    }

    /// The day the running build was first seen: the stored one when it is this build, else `day` (and stored).
    @discardableResult
    static func recordBuildDay(store: VersionHistoryStore, version: String, build: String, day: String) -> String {
        let parts = (store.object(forKey: installDatesKey) as? String)?
            .split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
        if let parts, parts.count == 3, parts[0] == clean(version), parts[1] == clean(build) { return parts[2] }
        store.set("\(clean(version))\t\(clean(build))\t\(day)", forKey: installDatesKey)
        return day
    }

    static func installDatesLine(installed: String, updated: String) -> String {
        "installed \(installed) · updated \(updated)"
    }

    static func installDatesLine(installed: Date?, updated: Date?) -> String {
        installDatesLine(installed: installed.map(utcDay) ?? "unknown", updated: updated.map(utcDay) ?? "unknown")
    }

    static func installDate(fileManager: FileManager = .default) -> Date? {
        #if os(macOS)
        guard isSandboxed else { return nil }
        #endif
        for dir in [FileManager.SearchPathDirectory.libraryDirectory, .documentDirectory] {
            if let url = fileManager.urls(for: dir, in: .userDomainMask).first,
               let date = try? url.resourceValues(forKeys: [.creationDateKey]).creationDate {
                return date
            }
        }
        return nil
    }

    // MARK: - memory

    /// `memory · RAM 3.5 GB · app can use 2140 MB · low power off · thermal nominal`: physical memory rounded to 0.5 GB
    /// (binary GB, as on Android: a "4 GB" phone reads 3.5 GB),
    /// the memory this process may still allocate before the system ends it (`os_proc_available_memory`, iOS and its
    /// relatives only), Low Power Mode and the thermal state.
    public static let memory = CipherLogCollector(name: "memory") {
        let info = ProcessInfo.processInfo
        var available: UInt64?
        #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        available = UInt64(os_proc_available_memory())
        #endif
        return [memoryLine(physical: info.physicalMemory, available: available,
                           lowPower: info.isLowPowerModeEnabled, thermal: info.thermalState)]
    }

    static func memoryLine(physical: UInt64, available: UInt64?, lowPower: Bool,
                           thermal: ProcessInfo.ThermalState) -> String {
        var parts = ["RAM " + roundedRAM(physical)]
        // 0 where the process has no limit (the simulator).
        if let available { parts.append("app can use " + (available == 0 ? "unknown" : "\(available / 1_000_000) MB")) }
        parts.append("low power " + (lowPower ? "on" : "off"))
        parts.append("thermal " + thermalName(thermal))
        return parts.joined(separator: " · ")
    }

    /// Rounded to 0.5 GB (binary): `4 GB`, `5.5 GB`; `unknown` for 0.
    static func roundedRAM(_ bytes: UInt64) -> String {
        if bytes == 0 { return "unknown" }
        let halves = (Double(bytes) / 536_870_912).rounded()
        let gb = halves / 2
        return gb == gb.rounded() ? "\(Int(gb)) GB" : String(format: "%.1f GB", gb)
    }

    static func thermalName(_ state: ProcessInfo.ThermalState) -> String {
        switch state {
        case .nominal: return "nominal"
        case .fair: return "fair"
        case .serious: return "serious"
        case .critical: return "critical"
        @unknown default: return "unknown"
        }
    }

    // MARK: - storageUsage

    /// `storageUsage · Documents 12 KB · Caches 3.4 MB · Application Support 1.2 MB · tmp 0 KB · group 5.1 MB`: the
    /// logical size (sum of file lengths, as on Android) of the app's own folders, never file names. The walk stops after 50 000 entries or 200 ms in all; a
    /// folder cut short shows `≥` and what was counted, a folder not reached `not counted`, a missing one `none`.
    /// `appGroup` adds the App Group container (`group`). On macOS outside the sandbox only the app's own
    /// `Caches/<bundle id>` and `Application Support/<bundle id>` are measured.
    public static func storageUsage(appGroup: String? = nil) -> CipherLogCollector {
        CipherLogCollector(name: "storageUsage") {
            [storageLine(folders: storageFolders(appGroup: appGroup))]
        }
    }

    struct WalkBudget {
        var entriesLeft: Int
        let deadline: Date
        var exhausted: Bool { entriesLeft <= 0 || Date() >= deadline }
    }

    static func storageFolders(appGroup: String?, fileManager: FileManager = .default) -> [(String, URL?)] {
        func dir(_ d: FileManager.SearchPathDirectory) -> URL? { fileManager.urls(for: d, in: .userDomainMask).first }
        var out: [(String, URL?)] = []
        #if os(macOS)
        if isSandboxed {
            out = [("Documents", dir(.documentDirectory)), ("Caches", dir(.cachesDirectory)),
                   ("Application Support", dir(.applicationSupportDirectory)),
                   ("tmp", URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true))]
        } else {
            let id = Bundle.main.bundleIdentifier ?? "cipherlog"
            out = [("Caches", dir(.cachesDirectory)?.appendingPathComponent(id, isDirectory: true)),
                   ("Application Support", dir(.applicationSupportDirectory)?.appendingPathComponent(id, isDirectory: true))]
        }
        #else
        out = [("Documents", dir(.documentDirectory)), ("Caches", dir(.cachesDirectory)),
               ("Application Support", dir(.applicationSupportDirectory)),
               ("tmp", URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true))]
        #endif
        if let appGroup {
            out.append(("group", fileManager.containerURL(forSecurityApplicationGroupIdentifier: appGroup)))
        }
        return out
    }

    static func storageLine(folders: [(String, URL?)], maxEntries: Int = 50_000, maxTime: TimeInterval = 0.2,
                            fileManager: FileManager = .default) -> String {
        var budget = WalkBudget(entriesLeft: maxEntries, deadline: Date().addingTimeInterval(maxTime))
        return folders.map { label, url -> String in
            guard let url, fileManager.fileExists(atPath: url.path) else { return "\(label) none" }
            if budget.exhausted { return "\(label) not counted" }
            let (bytes, complete) = folderSize(url, budget: &budget, fileManager: fileManager)
            return "\(label) \(complete ? "" : "≥ ")\(sizeText(bytes))"
        }.joined(separator: " · ")
    }

    /// Logical bytes (file lengths, not allocated blocks, so iOS and Android agree) under `url` (symbolic links not followed) and whether the walk finished within the budget.
    static func folderSize(_ url: URL, budget: inout WalkBudget,
                           fileManager: FileManager = .default) -> (bytes: Int64, complete: Bool) {
        let keys: [URLResourceKey] = [.isRegularFileKey, .fileSizeKey]
        guard let walker = fileManager.enumerator(at: url, includingPropertiesForKeys: keys, options: [],
                                                  errorHandler: { _, _ in true }) else { return (0, true) }
        var total: Int64 = 0
        while let item = walker.nextObject() as? URL {
            if budget.exhausted { return (total, false) }
            budget.entriesLeft -= 1
            guard let values = try? item.resourceValues(forKeys: Set(keys)), values.isRegularFile == true else { continue }
            total += Int64(values.fileSize ?? 0)
        }
        return (total, true)
    }

    /// KB (whole) under 1 MB, then MB and GB with one decimal; decimal units.
    static func sizeText(_ bytes: Int64) -> String {
        let b = Double(max(0, bytes))
        let kb = (b / 1_000).rounded()
        if kb < 1_000 { return "\(Int(kb)) KB" }
        let mb = b / 1_000_000
        if (mb * 10).rounded() / 10 < 1_000 { return String(format: "%.1f MB", mb) }
        return String(format: "%.1f GB", b / 1_000_000_000)
    }

    // MARK: - shared

    /// `yyyy-MM-dd` in UTC.
    static func utcDay(_ date: Date) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }

    #if os(macOS)
    static var isSandboxed: Bool { ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] != nil }
    #endif
}

/// Where `versionHistory` keeps its entries; `UserDefaults` in apps, a fake in tests.
protocol VersionHistoryStore: AnyObject {
    func object(forKey defaultName: String) -> Any?
    func set(_ value: Any?, forKey defaultName: String)
}

extension UserDefaults: VersionHistoryStore {}

/// UserDefaults is thread-safe; the box only carries it into the collector's closure.
final class StoreBox: @unchecked Sendable {
    let store: VersionHistoryStore
    init(_ store: VersionHistoryStore) { self.store = store }
}
