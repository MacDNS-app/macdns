// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// Caps how long the App polls the Agent while it reports a lifecycle
/// transition. Without a cap a single wake polls at a fixed 50 ms forever,
/// which is roughly 20 XPC round-trips per second for as long as the transition
/// lasts. Retries back off exponentially and stop at an overall deadline. The
/// caller then displays a transitioning state and reconciles later.
struct ServiceTransitionRetryPolicy: Equatable {
    let maximumRetries: Int
    let initialDelayNanoseconds: UInt64
    let maximumDelayNanoseconds: UInt64
    /// Overall budget for one transition wait, backoff included.
    let deadlineNanoseconds: UInt64

    static let `default` = ServiceTransitionRetryPolicy(
        maximumRetries: 8,
        initialDelayNanoseconds: 50_000_000,
        maximumDelayNanoseconds: 1_000_000_000,
        deadlineNanoseconds: 5_000_000_000
    )

    enum Decision: Equatable {
        case retry(afterNanoseconds: UInt64)
        case exhausted
    }

    func decision(
        retryCount: Int,
        elapsedNanoseconds: UInt64
    ) -> Decision {
        guard retryCount < maximumRetries else { return .exhausted }
        let delay = delayNanoseconds(retryCount: retryCount)
        guard elapsedNanoseconds + delay <= deadlineNanoseconds else {
            return .exhausted
        }
        return .retry(afterNanoseconds: delay)
    }

    func delayNanoseconds(retryCount: Int) -> UInt64 {
        let shift = UInt64(min(max(retryCount, 0), 32))
        let scaled = initialDelayNanoseconds << shift
        guard scaled >= initialDelayNanoseconds else {
            return maximumDelayNanoseconds
        }
        return min(scaled, maximumDelayNanoseconds)
    }
}
