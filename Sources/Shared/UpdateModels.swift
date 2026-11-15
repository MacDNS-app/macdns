// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

// MARK: - Update Info

public struct UpdateInfo: Codable, Sendable {
    public let currentVersion: String
    public let latestVersion: String
    public let isUpdateAvailable: Bool

    public init(currentVersion: String, latestVersion: String) {
        self.currentVersion = currentVersion
        self.latestVersion = latestVersion
        self.isUpdateAvailable = latestVersion.compare(currentVersion, options: .numeric) == .orderedDescending
    }
}
