import CipherLog
import SwiftUI

/// TEST public key from vectors/test-key.json. Its private half is in the repository, so anyone can read logs
/// written with it. A real app ships its own key (`cipherlog keygen` prints the string) and has a unit test that
/// fails when `try CipherLogKey(string: key).isTestKey` is true.
let testLogKey = "cipherlog-pub-v1:ecd8b29e913351f6a28fda6e663ad350273ed38a9b44fe8f1b8116a236154170"

@main
struct ExampleApp: App {
    init() {
        // 1. Once per process (the app here; each extension calls it too). With an App Group, pass
        //    `appGroup: "group.…"` so the app's export carries the extensions' logs as well.
        //    The sample also opts into the six optional device collectors (version history, install dates, memory,
        //    screen, network type, folder sizes); `optional()` is called here, on the main thread, for `screen`.
        CipherLog.start(key: testLogKey,
                        options: .init(collectors: CipherLogCollector.defaults + CipherLogCollector.optional()))
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    // 2. Instead of `Logger(subsystem:category:)`; the call sites stay as they are.
    private let logger = CipherLogger(category: "ui")
    @State private var taps = 0
    @State private var status = "Ready"

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("This sample encrypts logs to the TEST public key from vectors/test-key.json. Anyone with the repository can read them. Never ship this key.")
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
                Section("Log") {
                    Button("Log info") { tap("info") }
                    Button("Log warning") { tap("warning") }
                    Button("Log error") { tap("error") }
                }
                Section("Send") {
                    // 3. The armored bundle (`*.cipherlogs.txt`), written when the person shares it.
                    ShareLink(item: CipherLogExport(), preview: SharePreview("App logs")) {
                        Label("Send logs", systemImage: "square.and.arrow.up")
                    }
                    Button("Wipe all logs", role: .destructive) {
                        CipherLog.shared?.wipe()
                        status = "Wiped"
                    }
                }
                Section("Status") {
                    Text(status)
                    Text("Writer on: \(CipherLog.shared?.isOn == true ? "yes" : "no")")
                }
            }
            .navigationTitle("CipherLog")
        }
        .onAppear { logger.notice("screen home") }
    }

    private func tap(_ level: String) {
        taps += 1
        let user = "user-\(taps)"
        switch level {
        case "warning": logger.warning("tap \(taps) by \(user)")
        case "error": logger.error("tap \(taps) by \(user, privacy: .public)")
        default: logger.info("tap \(taps) by \(user)")
        }
        status = "Logged \(level) #\(taps)"
    }
}
