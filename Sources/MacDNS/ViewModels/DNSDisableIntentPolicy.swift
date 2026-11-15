// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// Ordered steps of an explicit user request to stop DNS protection.
enum DNSDisableStep: Equatable {
    /// Records `isEnabled = false` and hands it to the revision-guarded save.
    case persistDisabledIntent
    case disableDNSProxy
    case disableContentFilter
}

/// Sequences a user-requested disable so persisted intent always precedes
/// runtime teardown.
///
/// The disabled preference is the user's explicit intent and `state.json` is its
/// only authority. Persisting it first means a teardown failure can leave
/// runtime cleanup incomplete, but it can never resurrect the enabled preference
/// on the next startup.
enum DNSDisableIntentPolicy {
    enum Outcome: Equatable {
        case completed
        case abortedAfter(DNSDisableStep)
    }

    static let orderedSteps: [DNSDisableStep] = [
        .persistDisabledIntent,
        .disableDNSProxy,
        .disableContentFilter,
    ]

    /// Runs the steps in order, aborting at the first one that fails.
    static func execute(
        _ perform: (DNSDisableStep) async -> Bool
    ) async -> Outcome {
        for step in orderedSteps {
            guard await perform(step) else { return .abortedAfter(step) }
        }
        return .completed
    }
}
