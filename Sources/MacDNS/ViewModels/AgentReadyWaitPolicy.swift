// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Bounds a poll loop that waits for the Agent to answer XPC.
///
/// Every probe receives the budget still left in the overall deadline, so a
/// single hung XPC call cannot outlive the wait: the probe is forced to
/// return, the loop re-evaluates the deadline and the caller is released.
struct AgentReadyWaitPolicy: Equatable {
    /// Total budget for the whole wait, probes included.
    let timeout: TimeInterval
    /// Delay between two failed probes.
    let pollInterval: TimeInterval
    /// Below this remaining budget a probe cannot produce a useful answer.
    let minimumProbeBudget: TimeInterval

    init(
        timeout: TimeInterval,
        pollInterval: TimeInterval,
        minimumProbeBudget: TimeInterval = 0.05
    ) {
        self.timeout = timeout
        self.pollInterval = pollInterval
        self.minimumProbeBudget = minimumProbeBudget
    }

    enum Step: Equatable {
        case probe(budget: TimeInterval)
        case expired
    }

    func step(elapsed: TimeInterval) -> Step {
        let remaining = timeout - elapsed
        guard remaining >= minimumProbeBudget else { return .expired }
        return .probe(budget: remaining)
    }

    /// Runs `probe` until it reports readiness or the deadline expires.
    /// Returns `false` when the deadline expired without a ready answer.
    @MainActor
    static func waitUntilReady(
        policy: AgentReadyWaitPolicy,
        elapsed: () -> TimeInterval,
        probe: (TimeInterval) async -> Bool,
        sleep: (TimeInterval) async -> Void
    ) async -> Bool {
        while true {
            switch policy.step(elapsed: elapsed()) {
            case .expired:
                return false
            case .probe(let budget):
                if await probe(budget) { return true }
                guard case .probe = policy.step(elapsed: elapsed()) else {
                    return false
                }
                await sleep(policy.pollInterval)
            }
        }
    }
}
