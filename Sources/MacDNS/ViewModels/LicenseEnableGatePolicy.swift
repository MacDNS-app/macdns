// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared

/// Decides whether the App may refuse an explicit Enable before asking the Agent.
///
/// The Agent owns every license decision: `startResolver` registers a missing
/// trial and revalidates an existing license. The App only short-circuits a
/// definitive verdict the Agent already served, so an unknown or transiently
/// denied license always reaches the Agent instead of blocking every retry.
/// Without a running Agent nothing is refused: Enable is the only path that
/// installs it, and activating a purchased key needs it.
enum LicenseEnableGatePolicy {
    static func blocksEnable(_ info: LicenseInfo?, agentInstalled: Bool) -> Bool {
        guard agentInstalled, let info, !info.isServiceAllowed else { return false }
        switch info.status {
        case .trialExpired, .expired, .invalid:
            return true
        case .trial, .valid, .unknown:
            return false
        }
    }
}
