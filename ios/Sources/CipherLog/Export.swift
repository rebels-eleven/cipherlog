#if canImport(CoreTransferable) && canImport(UniformTypeIdentifiers)
import CoreTransferable
import Foundation
import UniformTypeIdentifiers

/// The support export as a `Transferable`, for SwiftUI's `ShareLink`:
///
/// ```swift
/// ShareLink(item: CipherLogExport(), preview: SharePreview("App logs"))
/// ```
///
/// The bundle is written when the person shares it (not when the view appears): an armored `*.cipherlogs.txt`
/// (SPEC.md 4.1), plain text that mail filters let through. Sharing fails when no writer has started.
public struct CipherLogExport: Transferable, Sendable {
    /// Nil means `CipherLog.shared`.
    public let log: CipherLog?

    public init(_ log: CipherLog? = nil) {
        self.log = log
    }

    public enum ExportError: Error, Sendable {
        /// `CipherLog.start` has not run (or failed) in this process.
        case notStarted
    }

    public static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .plainText) { item in
            guard let log = item.log ?? CipherLog.shared else { throw ExportError.notStarted }
            return SentTransferredFile(try log.exportBundle(armored: true))
        }
    }
}
#endif
