// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class ServiceStatusCheckGatePolicyTests: XCTestCase {
    func testFailureClearsInFlightAndCooldownNeverClearsRunningOperation() {
        let gate = ServiceStatusCheckGatePolicy.default
        var isInFlight = false
        var lastCompletedAt: TimeInterval?
        var now: TimeInterval = 100

        XCTAssertTrue(
            gate.shouldStart(
                isInFlight: isInFlight,
                lastCompletedAt: lastCompletedAt,
                now: now
            )
        )
        isInFlight = true

        // A check slower than the cooldown keeps excluding new checks.
        now += gate.cooldown * 5
        XCTAssertFalse(
            gate.shouldStart(
                isInFlight: isInFlight,
                lastCompletedAt: lastCompletedAt,
                now: now
            )
        )

        // The check fails, and the `defer` clears the flag and stamps completion.
        isInFlight = false
        lastCompletedAt = now

        XCTAssertFalse(
            gate.shouldStart(
                isInFlight: isInFlight,
                lastCompletedAt: lastCompletedAt,
                now: now
            )
        )
        now += gate.cooldown
        XCTAssertTrue(
            gate.shouldStart(
                isInFlight: isInFlight,
                lastCompletedAt: lastCompletedAt,
                now: now
            )
        )
    }

    func testCooldownBlocksAnImmediateSecondCheck() {
        let gate = ServiceStatusCheckGatePolicy(cooldown: 2.0)

        XCTAssertFalse(
            gate.shouldStart(isInFlight: false, lastCompletedAt: 10, now: 11.5)
        )
        XCTAssertTrue(
            gate.shouldStart(isInFlight: false, lastCompletedAt: 10, now: 12)
        )
    }

    func testFirstCheckIsNeverGated() {
        let gate = ServiceStatusCheckGatePolicy.default

        XCTAssertTrue(
            gate.shouldStart(isInFlight: false, lastCompletedAt: nil, now: 0)
        )
    }
}
