// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation

enum ApplicationMoveError: Error, Equatable {
    case copyFailed(String)
}

struct ApplicationMover {
    private static let quarantineAttribute = "com.apple.quarantine"
    private static let installedBundleName = "MacDNS.app"

    let applicationsDirectory: URL
    let recycle: (URL) async throws -> Void

    /// Copies `bundle` to `applicationsDirectory/MacDNS.app` whatever the
    /// download was named, replacing an existing copy by recycling it first,
    /// and removes `com.apple.quarantine` from every item of the copy so macOS
    /// does not translocate it again. Never touches `bundle`, which may sit on
    /// a read-only disk image.
    func install(_ bundle: URL) async throws -> URL {
        let fileManager = FileManager.default
        let destination = applicationsDirectory.appendingPathComponent(Self.installedBundleName, isDirectory: true)
        guard
            bundle.resolvingSymlinksInPath().standardizedFileURL.path
                != destination.resolvingSymlinksInPath().standardizedFileURL.path
        else {
            throw ApplicationMoveError.copyFailed(
                "\(bundle.lastPathComponent) already runs from the Applications folder")
        }
        do {
            if fileManager.fileExists(atPath: destination.path) {
                try await recycle(destination)
            }
            try fileManager.copyItem(at: bundle, to: destination)
            try removeQuarantine(from: destination, fileManager: fileManager)
        } catch {
            throw ApplicationMoveError.copyFailed(error.localizedDescription)
        }
        return destination
    }

    private func removeQuarantine(from copy: URL, fileManager: FileManager) throws {
        var items = [copy]
        if let enumerator = fileManager.enumerator(at: copy, includingPropertiesForKeys: nil) {
            items += enumerator.compactMap { $0 as? URL }
        }
        for item in items where removexattr(item.path, Self.quarantineAttribute, XATTR_NOFOLLOW) != 0 {
            guard errno == ENOATTR else {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }
        }
    }
}
