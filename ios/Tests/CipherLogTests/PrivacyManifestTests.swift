import Foundation
import XCTest
@testable import CipherLog

/// The privacy manifest ships with the library and declares every required-reason API the sources call. Without it an
/// app upload that adds CipherLog gets ITMS-91053 ("Missing API declaration").
final class PrivacyManifestTests: XCTestCase {
    /// Symbols of Apple's required-reason API list, by category, as they appear in Swift sources.
    private static let categories: [String: [String]] = [
        "NSPrivacyAccessedAPICategoryFileTimestamp": [
            "creationDate", "modificationDate", "contentModificationDate", "creationDateKey", "fileModificationDate",
            "contentModificationDateKey", "contentAccessDate", "attributeModificationDate", "getattrlist", "fstat(",
            " stat(", "lstat(", "fstatat(",
        ],
        "NSPrivacyAccessedAPICategoryDiskSpace": [
            "volumeAvailableCapacity", "volumeTotalCapacity", "systemFreeSize", "systemSize", "statfs(", "fstatfs(",
            "statvfs(",
        ],
        "NSPrivacyAccessedAPICategorySystemBootTime": ["systemUptime", "mach_absolute_time"],
        "NSPrivacyAccessedAPICategoryUserDefaults": ["UserDefaults"],
        "NSPrivacyAccessedAPICategoryActiveKeyboards": ["activeInputModes"],
    ]

    private func manifest() throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "PrivacyInfo", withExtension: "xcprivacy"),
                                "PrivacyInfo.xcprivacy is not in the library's resource bundle")
        let plist = try PropertyListSerialization.propertyList(from: Data(contentsOf: url), format: nil)
        return try XCTUnwrap(plist as? [String: Any])
    }

    func testManifestShipsAndTracksNothing() throws {
        let m = try manifest()
        XCTAssertEqual(m["NSPrivacyTracking"] as? Bool, false)
        XCTAssertEqual((m["NSPrivacyCollectedDataTypes"] as? [Any])?.count, 0)
    }

    func testEveryRequiredReasonAPIInTheSourcesIsDeclared() throws {
        let entries = try XCTUnwrap(manifest()["NSPrivacyAccessedAPITypes"] as? [[String: Any]])
        var declared: [String: [String]] = [:]
        for e in entries {
            let type = try XCTUnwrap(e["NSPrivacyAccessedAPIType"] as? String)
            declared[type] = try XCTUnwrap(e["NSPrivacyAccessedAPITypeReasons"] as? [String])
        }
        let sources = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../Sources/CipherLog").standardized
        let files = try FileManager.default.contentsOfDirectory(at: sources, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "swift" }
        XCTAssertFalse(files.isEmpty)
        var used = Set<String>()
        for file in files {
            let text = try String(contentsOf: file, encoding: .utf8)
            for (category, symbols) in Self.categories where symbols.contains(where: text.contains) {
                used.insert(category)
                XCTAssertFalse(declared[category]?.isEmpty ?? true,
                               "\(file.lastPathComponent) calls a \(category) API that PrivacyInfo.xcprivacy does not declare")
            }
        }
        // The three the library is known to use; a change that drops one should update the manifest too.
        XCTAssertEqual(used, ["NSPrivacyAccessedAPICategoryFileTimestamp", "NSPrivacyAccessedAPICategoryDiskSpace",
                              "NSPrivacyAccessedAPICategoryUserDefaults"])
        XCTAssertEqual(declared["NSPrivacyAccessedAPICategoryUserDefaults"], ["CA92.1"])
        XCTAssertEqual(Set(declared.keys), used, "the manifest declares a category the sources no longer use")
    }
}
