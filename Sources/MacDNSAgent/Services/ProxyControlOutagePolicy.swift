// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Decides when repeated proxy-control bootstrap failures stop looking like a
/// transient provider restart and start looking like the launchd Mach-endpoint
/// loss that follows a sysext replacement race. The caller supplies the clock
/// so the policy stays pure and testable.
struct ProxyControlOutagePolicy {
    let resolverRunning: Bool
    let consecutiveFailures: Int
    let firstFailureAt: Date?
    let now: Date

    static let minimumFailures = 4
    static let minimumOutageDuration: TimeInterval = 30

    var isPersistentOutage: Bool {
        guard resolverRunning, let firstFailureAt else { return false }
        return consecutiveFailures >= Self.minimumFailures
            && now.timeIntervalSince(firstFailureAt) >= Self.minimumOutageDuration
    }
}
