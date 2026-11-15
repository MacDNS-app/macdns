// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Exponential backoff for license-owned retries.
///
/// The default keeps retrying at most every `maxDelay` while attempts keep
/// failing for retryable reasons, so an outage of any length recovers without
/// a manual Enable. `maxAttempts` bounds the loop only when set.
struct LicenseRetryPolicy: Sendable {
    var baseDelay: TimeInterval = 30
    var multiplier: Double = 2
    var maxDelay: TimeInterval = 15 * 60
    var maxAttempts: Int? = nil
    var sleep: @Sendable (TimeInterval) async -> Void = { seconds in
        try? await Task.sleep(
            nanoseconds: UInt64(max(0, seconds) * 1_000_000_000)
        )
    }

    func delay(forAttempt attempt: Int) -> TimeInterval {
        let exponent = Double(max(0, attempt - 1))
        return min(maxDelay, baseDelay * pow(multiplier, exponent))
    }
}

/// Owns the license retry loop.
///
/// A retryable startup failure, including an engaged `networkGraceExpired`
/// latch, must recover on its own once connectivity returns, without depending
/// on the resolver lifecycle or on `NetworkMonitor` callbacks that are not yet
/// accepted at that point. The retry only re-runs `ensureValidLicense()`. It
/// never clears the fail-closed latch and never admits service by itself.
actor LicenseRetryController {
    private let policy: LicenseRetryPolicy
    private var task: Task<Void, Never>?
    private var retryRequested = false

    init(policy: LicenseRetryPolicy = LicenseRetryPolicy()) {
        self.policy = policy
    }

    /// Arms the retry loop. A loop already in flight is kept as-is so repeated
    /// failures cannot restart the backoff from zero. Arming during an attempt
    /// asks that loop for one more attempt. A failed attempt that did not ask
    /// reached a verdict, which ends the loop.
    func arm(_ attempt: @escaping @Sendable () async -> Bool) {
        guard task == nil else {
            retryRequested = true
            return
        }
        task = Task { [policy] in
            var attemptNumber = 1
            while policy.maxAttempts.map({ attemptNumber <= $0 }) ?? true {
                await policy.sleep(policy.delay(forAttempt: attemptNumber))
                if Task.isCancelled { break }
                self.retryRequested = false
                if await attempt() { break }
                guard self.retryRequested else { break }
                attemptNumber += 1
            }
            self.didFinish()
        }
    }

    func cancel() {
        task?.cancel()
        task = nil
    }

    var isArmed: Bool { task != nil }

    /// Awaits the in-flight retry loop, if any.
    func waitForCompletion() async {
        let inFlight = task
        await inFlight?.value
    }

    private func didFinish() {
        task = nil
        retryRequested = false
    }
}
