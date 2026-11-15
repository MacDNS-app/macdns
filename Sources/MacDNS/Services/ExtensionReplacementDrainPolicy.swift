// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

enum ReplacementDrainState: Equatable {
    case idle
    case draining
    case drained
}

/// Decides how to answer sysextd's actionForReplacingExtension. Cancel once to
/// disable a running old provider, wait for it to exit and resubmit. After one
/// drain always replace because holding back the bundled extension would fail
/// the upgrade. An unconfirmed drain is reported by
/// `ReplacementDrainConfirmationPolicy` instead of being swallowed.
struct ExtensionReplacementDrainPolicy {
    let providerRunning: Bool
    let drainState: ReplacementDrainState

    enum Decision: Equatable {
        case replaceNow
        case cancelAndDrain
    }

    var decision: Decision {
        guard providerRunning, drainState == .idle else { return .replaceNow }
        return .cancelAndDrain
    }
}

/// Reports whether a drain confirmed proxy disable and the provider exit before
/// replacement is submitted.
///
/// The replacement is submitted either way: the bundled extension is always the
/// newer one and holding it back would fail the upgrade. A failed disable leaves
/// the handoff uncertain. A provider that misses the exit deadline can leave
/// the proxy-control Mach endpoint occupied when launchd registers the
/// replacement job. An unconfirmed drain is therefore reported immediately.
struct ReplacementDrainConfirmationPolicy: Equatable {
    let proxyDisableConfirmed: Bool
    let providerExited: Bool

    var isConfirmed: Bool { proxyDisableConfirmed && providerExited }

    /// What to log and surface, or nil when the drain is confirmed.
    var unconfirmedReason: String? {
        switch (proxyDisableConfirmed, providerExited) {
        case (true, true):
            return nil
        case (false, true):
            return "proxy disable failed"
        case (true, false):
            return "the old provider did not exit within the drain timeout"
        case (false, false):
            return "proxy disable failed and the old provider did not exit within the drain timeout"
        }
    }
}
