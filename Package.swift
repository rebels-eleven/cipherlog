// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CipherLog",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "CipherLog", targets: ["CipherLog"]),
    ],
    targets: [
        .target(
            name: "CipherLog",
            path: "ios/Sources/CipherLog",
            // The privacy manifest: the required-reason APIs the library calls (file timestamps, disk space).
            resources: [.copy("PrivacyInfo.xcprivacy")],
            linkerSettings: [.linkedLibrary("z")]
        ),
        .testTarget(name: "CipherLogTests", dependencies: ["CipherLog"], path: "ios/Tests/CipherLogTests"),
    ]
)
