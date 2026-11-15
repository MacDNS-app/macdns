// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

enum ProxyControlRecoveryAction: Equatable {
    case none
    case bounce
    case surfaceRestartRequired
}

/// Decides how the App reacts to the Agent reporting a persistent
/// proxy-control outage. A bounce (proxy disable → provider exit → enable)
/// forces launchd to resubmit the provider job with its MachServices entry,
/// the only non-reboot fix for the replacement endpoint race. Pure. The
/// caller supplies the clock and attempt history.
struct ProxyBounceRecoveryPolicy {
    let outageReported: Bool?
    let runtimeDNSDesired: Bool
    let servicesRunning: Bool
    let proxyEnabled: Bool
    let activationInProgress: Bool
    /// A replacement drain owns the proxy configuration. The activation flag
    /// drops before the drain disables the proxy, so without this input a
    /// bounce started in that window is swallowed by the drain guard and burns
    /// a recovery attempt as a no-op.
    let replacementDrainActive: Bool
    /// A replacement that went ahead without a confirmed drain can leave the
    /// old provider owning the proxy-control endpoint, which strips
    /// MachServices from the new job record. That record survives process
    /// exits, so a bounce cannot repair it. Only a new build label or a
    /// reboot does. Skip straight to the restart notice instead of spending
    /// both attempts on a no-op.
    let drainUnconfirmed: Bool
    let bounceInProgress: Bool
    let attemptsMade: Int
    let lastAttemptAt: Date?
    let now: Date

    static let maxAttempts = 2
    static let attemptCooldown: TimeInterval = 120

    var action: ProxyControlRecoveryAction {
        guard outageReported == true,
            runtimeDNSDesired,
            servicesRunning,
            proxyEnabled,
            !activationInProgress,
            !replacementDrainActive,
            !bounceInProgress
        else { return .none }
        if drainUnconfirmed { return .surfaceRestartRequired }
        if attemptsMade >= Self.maxAttempts { return .surfaceRestartRequired }
        if let lastAttemptAt, now.timeIntervalSince(lastAttemptAt) < Self.attemptCooldown {
            return .none
        }
        return .bounce
    }
}
