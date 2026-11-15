// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Collapses re-entrant service-status checks.
///
/// Exclusion and cooldown are separate concerns: a check that outlives a fixed
/// timer must keep excluding new checks, and a finished check must still be
/// followed by a quiet period. A single timer-cleared flag conflates both and
/// lets a slow check overlap itself with stale results.
struct ServiceStatusCheckGatePolicy: Equatable {
    let cooldown: TimeInterval

    static let `default` = ServiceStatusCheckGatePolicy(cooldown: 2.0)

    func shouldStart(
        isInFlight: Bool,
        lastCompletedAt: TimeInterval?,
        now: TimeInterval
    ) -> Bool {
        guard !isInFlight else { return false }
        guard let lastCompletedAt else { return true }
        return now - lastCompletedAt >= cooldown
    }
}
