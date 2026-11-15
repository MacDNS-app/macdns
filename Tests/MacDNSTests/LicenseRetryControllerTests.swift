// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent

final class LicenseRetryControllerTests: XCTestCase {
    /// An outage longer than any fixed attempt budget must not leave the Mac
    /// without a license verdict until the next manual Enable or reboot.
    func testDefaultPolicyKeepsRetryingWhileAttemptsAskForAnotherRetry() async {
        let controller = LicenseRetryController(policy: immediatePolicy())
        let attempts = LockedAttemptCounter()

        await armRetryingUntil(controller, attempts: attempts) { $0 >= 50 }
        await controller.waitForCompletion()

        XCTAssertEqual(attempts.value, 50)
        let isArmed = await controller.isArmed
        XCTAssertFalse(isArmed)
    }

    /// A failed attempt that did not ask for another retry reached a verdict,
    /// such as an ended trial. Polling it forever would only load the API.
    func testAttemptThatReachesAVerdictEndsTheLoop() async {
        let controller = LicenseRetryController(policy: immediatePolicy())
        let attempts = LockedAttemptCounter()

        await controller.arm {
            _ = attempts.increment()
            return false
        }
        await controller.waitForCompletion()

        XCTAssertEqual(attempts.value, 1)
    }

    func testBackoffIsCappedAtFifteenMinutes() {
        let policy = LicenseRetryPolicy()

        XCTAssertEqual(policy.delay(forAttempt: 1), 30)
        XCTAssertEqual(policy.delay(forAttempt: 100), 15 * 60)
    }

    func testAttemptBudgetStillBoundsTheLoopWhenSet() async {
        let controller = LicenseRetryController(
            policy: LicenseRetryPolicy(maxAttempts: 3, sleep: { _ in })
        )
        let attempts = LockedAttemptCounter()

        await armRetryingUntil(controller, attempts: attempts) { _ in false }
        await controller.waitForCompletion()

        XCTAssertEqual(attempts.value, 3)
    }

    private func immediatePolicy() -> LicenseRetryPolicy {
        var policy = LicenseRetryPolicy()
        policy.sleep = { _ in }
        return policy
    }

    /// Mirrors `LicenseManager`: a retryable failure inside an attempt arms the
    /// retry again, which the in-flight loop records as a request to continue.
    private func armRetryingUntil(
        _ controller: LicenseRetryController,
        attempts: LockedAttemptCounter,
        succeeds: @escaping @Sendable (Int) -> Bool
    ) async {
        let attempt: @Sendable () async -> Bool = {
            if succeeds(attempts.increment()) { return true }
            await controller.arm { false }
            return false
        }
        await controller.arm(attempt)
    }
}

private final class LockedAttemptCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    func increment() -> Int {
        lock.lock()
        defer { lock.unlock() }
        count += 1
        return count
    }

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }
}
