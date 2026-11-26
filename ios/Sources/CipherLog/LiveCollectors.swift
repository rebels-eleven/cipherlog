import Foundation
#if canImport(Network)
import Network
#endif
#if canImport(UIKit)
import UIKit
#endif

/// The two optional collectors that keep state between files: `screen` (a main-thread snapshot of UIKit values) and
/// `network` (one path monitor per collector). Each factory call makes one state object, which lives as long as the
/// collector and stops its observers or monitor when the collector is released.
extension CipherLogCollector {
    // MARK: - screen

    /// `screen · 390×844 pt @3x · text L · dark no`: screen size in points and scale, the preferred content size
    /// category (`L` is the default; `AccessibilityM` and up are the larger accessibility sizes) and dark mode.
    ///
    /// Call it on the main thread: UIKit is read there and then, and again on the main thread when the app becomes
    /// active or the text size changes. Collectors run on the writer's queue and never touch UIKit; created off the
    /// main thread, the line says so until the next refresh. On macOS the line is `unavailable on this platform`.
    public static func screen() -> CipherLogCollector {
        #if os(iOS) || os(tvOS)
        let state = ScreenState(read: { readUIKitScreen() }, notifications: [
            UIApplication.didBecomeActiveNotification, UIContentSizeCategory.didChangeNotification,
        ])
        #else
        let state = ScreenState(read: { nil }, notifications: [])
        #endif
        return screen(state: state)
    }

    static func screen(state: ScreenState) -> CipherLogCollector {
        CipherLogCollector(name: "screen") { [state.line()] }
    }

    struct ScreenSnapshot: Equatable, Sendable {
        var width: Double
        var height: Double
        var scale: Double
        var textSize: String
        var dark: Bool
    }

    static func screenLine(_ s: ScreenSnapshot) -> String {
        "\(number(s.width))×\(number(s.height)) pt @\(number(s.scale))x · text \(s.textSize) · dark \(s.dark ? "yes" : "no")"
    }

    /// `UICTContentSizeCategoryXL` → `XL`, `UICTContentSizeCategoryAccessibilityM` → `AccessibilityM`.
    static func textSizeName(_ raw: String) -> String {
        let prefix = "UICTContentSizeCategory"
        let short = raw.hasPrefix(prefix) ? String(raw.dropFirst(prefix.count)) : raw
        return short.isEmpty ? "unknown" : short
    }

    private static func number(_ v: Double) -> String {
        v == v.rounded() ? "\(Int(v))" : String(format: "%.1f", v)
    }

    #if os(iOS) || os(tvOS)
    @MainActor
    static func readUIKitScreen() -> ScreenSnapshot {
        let screen = (UIScreen.self as MainScreenAccess.Type).mainScreen
        let traits = screen.traitCollection
        return ScreenSnapshot(width: Double(screen.bounds.width), height: Double(screen.bounds.height),
                              scale: Double(screen.scale),
                              textSize: textSizeName(traits.preferredContentSizeCategory.rawValue),
                              dark: traits.userInterfaceStyle == .dark)
    }
    #endif

    // MARK: - network

    /// `network · wifi · expensive no · constrained no`: the connection type only (`wifi`, `cellular`, `ethernet`,
    /// `none`, `other`), whether the system treats it as expensive (metered, a hotspot) and as constrained (Low Data
    /// Mode). Never the network name, addresses or the carrier. One `NWPathMonitor` per collector, started here and
    /// cancelled when the collector is released; the first file waits at most 0.25 s for its first answer.
    public static func network() -> CipherLogCollector {
        #if canImport(Network)
        let state = NetworkState()
        return CipherLogCollector(name: "network") { [networkLine(state.current(wait: 0.25))] }
        #else
        return CipherLogCollector(name: "network") { ["unavailable on this platform"] }
        #endif
    }

    struct NetworkSnapshot: Equatable, Sendable {
        /// `wifi`, `cellular`, `ethernet`, `none` or `other`.
        var kind: String
        var expensive: Bool
        var constrained: Bool
    }

    static func networkLine(_ s: NetworkSnapshot?) -> String {
        guard let s else { return "unknown (no answer yet)" }
        if s.kind == "none" { return "none" }
        return "\(s.kind) · expensive \(s.expensive ? "yes" : "no") · constrained \(s.constrained ? "yes" : "no")"
    }
}

/// The screen snapshot behind one `screen` collector. Read only on the main thread; the collector reads the stored
/// copy under a lock and never waits for the main thread.
final class ScreenState: @unchecked Sendable {
    typealias Snapshot = CipherLogCollector.ScreenSnapshot

    private let lock = NSLock()
    private var snapshot: Snapshot?
    private var unavailable = false
    private var createdOffMain = false
    private var observers: [NSObjectProtocol] = []
    private let center: NotificationCenter
    private let read: @MainActor () -> Snapshot?

    init(read: @escaping @MainActor () -> Snapshot?, notifications: [Notification.Name],
         center: NotificationCenter = .default) {
        self.read = read
        self.center = center
        if Thread.isMainThread {
            MainActor.assumeIsolated { refreshOnMain() }
        } else {
            createdOffMain = true
        }
        // Delivered on the main queue, so the refresh runs on the main thread.
        observers = notifications.map { name in
            center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.refreshOnMain() }
            }
        }
    }

    deinit {
        for o in observers { center.removeObserver(o) }
    }

    @MainActor
    func refreshOnMain() {
        let value = read()
        lock.withLock {
            if let value {
                snapshot = value
            } else {
                unavailable = true
            }
        }
    }

    func line() -> String {
        lock.withLock {
            if let snapshot { return CipherLogCollector.screenLine(snapshot) }
            if unavailable { return "unavailable on this platform" }
            if createdOffMain { return "not read yet (CipherLogCollector.screen() was called off the main thread)" }
            return "not read yet"
        }
    }
}

#if os(iOS) || os(tvOS)
/// `UIScreen.main` is deprecated in favour of a window scene's screen, which a library cannot reach in an app
/// extension (`UIApplication.shared` is unavailable there). The main screen is still the right one for the device
/// block; the protocol only keeps the deprecation warning out of the build.
@MainActor
protocol MainScreenAccess {
    static var main: UIScreen { get }
}

extension MainScreenAccess {
    static var mainScreen: UIScreen { main }
}

extension UIScreen: MainScreenAccess {}
#endif

#if canImport(Network)
/// One `NWPathMonitor` and its latest path, readable from any thread.
final class NetworkState: @unchecked Sendable {
    private let monitor = NWPathMonitor()
    private let condition = NSCondition()
    private var latest: CipherLogCollector.NetworkSnapshot?

    init() {
        monitor.pathUpdateHandler = { [weak self] path in self?.update(Self.snapshot(path)) }
        monitor.start(queue: DispatchQueue(label: "cipherlog.network", qos: .utility))
    }

    deinit {
        monitor.cancel()
    }

    func update(_ value: CipherLogCollector.NetworkSnapshot) {
        condition.lock()
        latest = value
        condition.broadcast()
        condition.unlock()
    }

    /// The latest path, waiting at most `wait` seconds for the first one.
    func current(wait: TimeInterval) -> CipherLogCollector.NetworkSnapshot? {
        condition.lock()
        defer { condition.unlock() }
        let deadline = Date().addingTimeInterval(wait)
        while latest == nil && condition.wait(until: deadline) {}
        return latest
    }

    static func snapshot(_ path: NWPath) -> CipherLogCollector.NetworkSnapshot {
        let kind: String
        if path.status != .satisfied {
            kind = "none"
        } else if path.usesInterfaceType(.wifi) {
            kind = "wifi"
        } else if path.usesInterfaceType(.cellular) {
            kind = "cellular"
        } else if path.usesInterfaceType(.wiredEthernet) {
            kind = "ethernet"
        } else {
            kind = "other"
        }
        return CipherLogCollector.NetworkSnapshot(kind: kind, expensive: path.isExpensive,
                                                  constrained: path.isConstrained)
    }
}
#endif
