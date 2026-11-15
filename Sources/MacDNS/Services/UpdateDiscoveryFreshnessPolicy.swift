// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

enum UpdateDiscoveryFreshnessPolicy {
    static let interval: TimeInterval = 3600

    static func shouldCheck(lastCompletedAt: Date?, now: Date = Date()) -> Bool {
        guard let lastCompletedAt else { return true }
        let elapsed = now.timeIntervalSince(lastCompletedAt)
        return elapsed < 0 || elapsed >= interval
    }
}
