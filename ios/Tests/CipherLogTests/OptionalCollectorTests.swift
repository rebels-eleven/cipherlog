import Foundation
import XCTest
@testable import CipherLog

final class FakeStore: VersionHistoryStore {
    var values: [String: Any] = [:]
    var writes = 0
    func object(forKey defaultName: String) -> Any? { values[defaultName] }
    func set(_ value: Any?, forKey defaultName: String) {
        writes += 1
        values[defaultName] = value
    }
}

/// A settable clock the collectors' `@Sendable` closures can read.
private final class Clock: @unchecked Sendable {
    var now: Date
    init(_ now: Date) { self.now = now }
}

final class OptionalCollectorTests: XCTestCase {
    typealias C = CipherLogCollector

    // MARK: versionHistory

    func testHistoryRecordsOnCreateNewestFirstAndOnce() throws {
        let store = FakeStore()
        let day1 = Date(timeIntervalSince1970: 1_794_744_000)   // 2026-11-15 UTC
        _ = C.versionHistory(store: store, version: "1.4", build: "15", now: { day1 })
        XCTAssertEqual(store.values[C.versionHistoryKey] as? [String], ["1.4\t15\t2026-11-15"], "recorded at creation")

        let day2 = day1.addingTimeInterval(5 * 86_400)
        let c = C.versionHistory(store: store, version: "1.4.1", build: "16", now: { day2 })
        XCTAssertEqual(try c.collect(), ["1.4.1 (16) since 2026-11-20 · 1.4 (15) since 2026-11-15"])
        let writes = store.writes
        XCTAssertEqual(try c.collect(), ["1.4.1 (16) since 2026-11-20 · 1.4 (15) since 2026-11-15"])
        XCTAssertEqual(store.writes, writes, "an unchanged history is not written again")

        // Going back to an old build keeps its first-seen day and order.
        let back = C.versionHistory(store: store, version: "1.4", build: "15", now: { day2 })
        XCTAssertEqual(try back.collect(), ["1.4.1 (16) since 2026-11-20 · 1.4 (15) since 2026-11-15"])
    }

    func testHistoryLimitAndBadEntries() {
        var entries: [C.VersionEntry] = []
        for i in 0..<25 { entries = C.mergeHistory(entries, version: "1.\(i)", build: "\(i)", day: "2026-11-01") }
        XCTAssertEqual(entries.count, 20)
        XCTAssertEqual(entries.first?.version, "1.24")
        XCTAssertEqual(entries.last?.version, "1.5")

        XCTAssertEqual(C.decodeHistory(["1.0\t1\t2026-01-01", "garbage", "a\tb"]),
                       [C.VersionEntry(version: "1.0", build: "1", since: "2026-01-01")])
        XCTAssertEqual(C.decodeHistory(42), [])
        XCTAssertEqual(C.decodeHistory(nil), [])
        XCTAssertEqual(C.encodeHistory([C.VersionEntry(version: "1\t2", build: "3\n", since: "2026-01-01")]),
                       ["1 2\t3 \t2026-01-01"])
        XCTAssertEqual(C.historyLine([]), "none")
    }

    func testHistoryInRealUserDefaultsSuite() throws {
        let suite = "cipherlog.tests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let c = C.versionHistory(defaults: defaults)
        XCTAssertEqual(c.name, "versionHistory")
        XCTAssertNotNil(defaults.array(forKey: C.versionHistoryKey))
        let line = try XCTUnwrap(c.collect().first)
        XCTAssertTrue(line.contains(" since 20"), line)
    }

    // MARK: installDates, memory

    func testInstallDatesLine() {
        let d = Date(timeIntervalSince1970: 1_794_744_000)
        XCTAssertEqual(C.installDatesLine(installed: d, updated: d.addingTimeInterval(86_400)),
                       "installed 2026-11-15 · updated 2026-11-16")
        XCTAssertEqual(C.installDatesLine(installed: nil, updated: nil), "installed unknown · updated unknown")
        XCTAssertEqual(C.utcDay(Date(timeIntervalSince1970: 0)), "1970-01-01")
        XCTAssertEqual(try C.installDates.collect().count, 1)
    }

    func testInstallDatesUpdatedIsTheFirstDayOfTheRunningBuild() throws {
        let store = FakeStore()
        let day = 86_400.0
        let start = Date(timeIntervalSince1970: 1_794_744_000) // 2026-11-15
        let clock = Clock(start)
        let installed = Date(timeIntervalSince1970: 1_794_744_000 - 10 * day)
        // Recorded on create, kept on later days for the same build.
        let c = C.installDates(store: store, version: "1.4", build: "15", now: { clock.now }, installed: { installed })
        XCTAssertEqual(store.values[C.installDatesKey] as? String, "1.4\t15\t2026-11-15")
        clock.now = start.addingTimeInterval(3 * day)
        XCTAssertEqual(try c.collect(), ["installed 2026-11-05 · updated 2026-11-15"])
        XCTAssertEqual(store.writes, 1)
        // A new build replaces it with the day it was first seen.
        let next = C.installDates(store: store, version: "1.4.1", build: "16", now: { clock.now },
                                  installed: { nil })
        clock.now = start.addingTimeInterval(9 * day)
        XCTAssertEqual(try next.collect(), ["installed unknown · updated 2026-11-18"])
        XCTAssertEqual(store.writes, 2)
        // Garbage in the store is replaced, never trusted.
        store.values[C.installDatesKey] = 42
        XCTAssertEqual(C.recordBuildDay(store: store, version: "1.4.1", build: "16", day: "2026-11-30"), "2026-11-30")
    }

    func testInstallDatesReadsNoBundleTimestamp() throws {
        // Only the data container (privacy reason C617.1): the source must not read the app bundle's dates.
        let source = try String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../Sources/CipherLog/OptionalCollectors.swift").standardizedFileURL,
            encoding: .utf8)
        XCTAssertFalse(source.contains("bundleURL"))
        XCTAssertFalse(source.contains("contentModificationDateKey"))
    }

    func testMemoryLineAndRounding() throws {
        let gib: UInt64 = 1 << 30
        XCTAssertEqual(C.roundedRAM(3_951_165_440), "3.5 GB", "a 4 GB iPhone")
        XCTAssertEqual(C.roundedRAM(5 * gib + gib / 3), "5.5 GB")
        XCTAssertEqual(C.roundedRAM(6 * gib - gib / 5), "6 GB")
        XCTAssertEqual(C.roundedRAM(0), "unknown")
        XCTAssertEqual(C.memoryLine(physical: 8 * gib, available: 2_140_500_000, lowPower: true, thermal: .serious),
                       "RAM 8 GB · app can use 2140 MB · low power on · thermal serious")
        XCTAssertEqual(C.memoryLine(physical: 16 * gib, available: nil, lowPower: false, thermal: .nominal),
                       "RAM 16 GB · low power off · thermal nominal")
        // The simulator has no per-process limit and answers 0.
        XCTAssertEqual(C.memoryLine(physical: 4 * gib, available: 0, lowPower: false, thermal: .fair),
                       "RAM 4 GB · app can use unknown · low power off · thermal fair")
        let line = try XCTUnwrap(C.memory.collect().first)
        XCTAssertTrue(line.hasPrefix("RAM ") && line.contains(" GB · "), line)
    }

    // MARK: screen

    func testScreenFormatting() {
        let s = C.ScreenSnapshot(width: 390, height: 844, scale: 3, textSize: C.textSizeName("UICTContentSizeCategoryL"),
                                 dark: false)
        XCTAssertEqual(C.screenLine(s), "390×844 pt @3x · text L · dark no")
        XCTAssertEqual(C.screenLine(.init(width: 1366, height: 1024, scale: 2.5, textSize: "AccessibilityM", dark: true)),
                       "1366×1024 pt @2.5x · text AccessibilityM · dark yes")
        XCTAssertEqual(C.textSizeName("UICTContentSizeCategoryAccessibilityXXXL"), "AccessibilityXXXL")
        XCTAssertEqual(C.textSizeName("UICTContentSizeCategory"), "unknown")
    }

    func testScreenReadsOnMainAndRefreshesFromNotifications() throws {
        XCTAssertTrue(Thread.isMainThread)
        let center = NotificationCenter()
        let reads = Locked(0)
        let dark = Locked(false)
        let name = Notification.Name("test.didBecomeActive")
        var state: ScreenState? = ScreenState(read: {
            XCTAssertTrue(Thread.isMainThread)
            reads.mutate { $0 += 1 }
            return .init(width: 390, height: 844, scale: 3, textSize: "L", dark: dark.get)
        }, notifications: [name], center: center)
        let c = C.screen(state: state!)
        XCTAssertEqual(reads.get, 1)
        XCTAssertEqual(try c.collect(), ["390×844 pt @3x · text L · dark no"])
        dark.set(true)
        center.post(name: name, object: nil)
        XCTAssertEqual(reads.get, 2)
        XCTAssertEqual(try c.collect(), ["390×844 pt @3x · text L · dark yes"])

        // The collector keeps its state (and with it the observer) alive.
        weak var weakState = state
        state = nil
        XCTAssertNotNil(weakState, "the collector keeps its state")
        center.post(name: name, object: nil)
        XCTAssertEqual(reads.get, 3)
        withExtendedLifetime(c) {}
    }

    func testScreenObserverRemovedWhenCollectorReleased() {
        let center = NotificationCenter()
        let reads = Locked(0)
        let name = Notification.Name("test.change")
        weak var weakState: ScreenState?
        do {
            let state = ScreenState(read: { reads.mutate { $0 += 1 }; return nil }, notifications: [name], center: center)
            weakState = state
            let c = C.screen(state: state)
            XCTAssertEqual(try? c.collect(), ["unavailable on this platform"])
        }
        XCTAssertNil(weakState)
        center.post(name: name, object: nil)
        XCTAssertEqual(reads.get, 1, "no refresh after the collector is gone")
    }

    func testScreenCreatedOffMainNeverReadsUIKitThere() throws {
        let center = NotificationCenter()
        let reads = Locked(0)
        let lines = Locked<[String]>([])
        let done = expectation(description: "background")
        DispatchQueue.global().async {
            let c = C.screen(state: ScreenState(read: { reads.mutate { $0 += 1 }; return nil },
                                                notifications: [], center: center))
            lines.set((try? c.collect()) ?? [])
            done.fulfill()
        }
        wait(for: [done], timeout: 5)
        XCTAssertEqual(reads.get, 0)
        XCTAssertEqual(lines.get, ["not read yet (CipherLogCollector.screen() was called off the main thread)"])
    }

    func testScreenFactoryOnThisPlatform() throws {
        let line = try XCTUnwrap(C.screen().collect().first)
        #if os(macOS)
        XCTAssertEqual(line, "unavailable on this platform")
        #else
        XCTAssertTrue(line.contains(" pt @"), line)
        #endif
    }

    // MARK: network

    func testNetworkLine() {
        XCTAssertEqual(C.networkLine(nil), "unknown (no answer yet)")
        XCTAssertEqual(C.networkLine(.init(kind: "none", expensive: false, constrained: false)), "none")
        XCTAssertEqual(C.networkLine(.init(kind: "cellular", expensive: true, constrained: true)),
                       "cellular · expensive yes · constrained yes")
        XCTAssertEqual(C.networkLine(.init(kind: "wifi", expensive: false, constrained: false)),
                       "wifi · expensive no · constrained no")
    }

    func testNetworkMonitorAnswersAndStopsWithItsCollector() throws {
        weak var weakState: NetworkState?
        do {
            let state = NetworkState()
            weakState = state
            let snapshot = try XCTUnwrap(state.current(wait: 2))
            XCTAssertTrue(["wifi", "cellular", "ethernet", "none", "other"].contains(snapshot.kind), snapshot.kind)
        }
        XCTAssertNil(weakState, "the monitor's handler does not keep its state alive")
        let line = try XCTUnwrap(C.network().collect().first)
        XCTAssertFalse(line.contains("."), "no addresses: \(line)")
    }

    // MARK: storageUsage

    func testSizeText() {
        XCTAssertEqual(C.sizeText(0), "0 KB")
        XCTAssertEqual(C.sizeText(-3), "0 KB")
        XCTAssertEqual(C.sizeText(12_400), "12 KB")
        XCTAssertEqual(C.sizeText(999_400), "999 KB")
        XCTAssertEqual(C.sizeText(999_600), "1.0 MB")
        XCTAssertEqual(C.sizeText(3_440_000), "3.4 MB")
        XCTAssertEqual(C.sizeText(999_960_000), "1.0 GB")
        XCTAssertEqual(C.sizeText(5_120_000_000), "5.1 GB")
    }

    func testStorageWalkCountsCapsAndNeverNamesFiles() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cl-storage-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let a = root.appendingPathComponent("a/secret-name", isDirectory: true)
        try FileManager.default.createDirectory(at: a, withIntermediateDirectories: true)
        for i in 0..<10 { try Data(repeating: 7, count: 5_000).write(to: a.appendingPathComponent("f\(i)")) }
        let b = root.appendingPathComponent("b", isDirectory: true)
        try FileManager.default.createDirectory(at: b, withIntermediateDirectories: true)
        let missing = root.appendingPathComponent("missing")

        let full = C.storageLine(folders: [("A", root.appendingPathComponent("a")), ("B", b), ("C", missing), ("D", nil)])
        XCTAssertTrue(full.hasPrefix("A "), full)
        XCTAssertFalse(full.contains("≥"), full)
        XCTAssertTrue(full.hasSuffix(" · B 0 KB · C none · D none"), full)
        XCTAssertFalse(full.contains("secret") || full.contains("f1"), full)

        var budget = C.WalkBudget(entriesLeft: 4, deadline: .distantFuture)
        let cut = C.folderSize(root.appendingPathComponent("a"), budget: &budget)
        XCTAssertFalse(cut.complete)
        XCTAssertEqual(budget.entriesLeft, 0)

        let capped = C.storageLine(folders: [("A", root.appendingPathComponent("a")), ("B", b)], maxEntries: 4)
        XCTAssertTrue(capped.hasPrefix("A ≥ "), capped)
        XCTAssertTrue(capped.hasSuffix(" · B not counted"), capped)

        let timedOut = C.storageLine(folders: [("A", root.appendingPathComponent("a"))], maxTime: -1)
        XCTAssertEqual(timedOut, "A not counted")
    }

    func testStorageCountsLogicalBytesLikeAndroid() throws {
        // 20 files of 200 bytes: 4 KB of lengths (allocated blocks would be ~80 KB).
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cl-logical-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        for i in 0..<20 { try Data(repeating: 1, count: 200).write(to: root.appendingPathComponent("f\(i)")) }
        var budget = C.WalkBudget(entriesLeft: 100, deadline: .distantFuture)
        let size = C.folderSize(root, budget: &budget)
        XCTAssertTrue(size.complete)
        XCTAssertEqual(size.bytes, 4_000)
    }

    func testStorageUsageCollectorAndOptionalSet() throws {
        let line = try XCTUnwrap(C.storageUsage().collect().first)
        XCTAssertFalse(line.isEmpty)
        let suite = "cipherlog.tests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let all = C.optional(appGroup: "group.cipherlog.tests.none", defaults: defaults)
        XCTAssertEqual(all.map(\.name), ["versionHistory", "installDates", "memory", "screen", "network", "storageUsage"])
        XCTAssertEqual(C.defaults.map(\.name), ["app", "system", "locale", "disk"], "the defaults do not change")
        // macOS has no container for an unknown group ("group none"); the simulator makes one.
        let storage = try XCTUnwrap(all.last?.collect().first)
        XCTAssertTrue(storage.contains(" · group "), storage)
    }

    // MARK: in a file

    func testOptionalCollectorsInTheDeviceBlock() throws {
        let dir = tempDir()
        let suite = "cipherlog.tests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let log = CipherLog(makeConfig(dir, collectors: C.optional(defaults: defaults)))
        log.log(.info, category: "t", "hello")
        log.close()
        let text = try logFiles(dir).map { try readFile($0).text }.joined(separator: "\n")
        for name in ["versionHistory", "installDates", "memory", "screen", "network", "storageUsage"] {
            XCTAssertTrue(text.contains("device: \(name) · "), "\(name) missing in\n\(text)")
        }
        XCTAssertFalse(text.contains("failed"), text)
    }
}
