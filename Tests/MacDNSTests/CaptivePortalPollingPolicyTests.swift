// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent

/// Mirrors the detector's intensive-polling cycle: the timer records one
/// attempt per tick and every second probe re-confirms `.captive`.
final class CaptivePortalPollingPolicyTests: XCTestCase {
    private let maxAttempts = 30
    private let tickLimit = 200

    func testPersistentCaptiveReachesPollingTimeout() {
        var polling = CaptivePollingPhase(maxAttempts: maxAttempts)

        XCTAssertEqual(
            polling.confirmCaptive(statusChanged: true, isPolling: false),
            .enterIntensivePolling
        )

        var tick = 0
        var timedOut = false
        while tick < tickLimit {
            tick += 1
            guard polling.recordAttempt() else {
                timedOut = true
                break
            }
            if tick % 2 == 0 {
                XCTAssertEqual(
                    polling.confirmCaptive(statusChanged: false, isPolling: true),
                    .continueIntensivePolling
                )
            }
        }

        XCTAssertTrue(timedOut, "A stable captive portal must reach the polling timeout")
        XCTAssertEqual(tick, maxAttempts + 1)
        XCTAssertTrue(polling.isExhausted)
    }

    func testExhaustedPollingStaysInHealthCheckOnRepeatedCaptive() {
        var polling = exhaustedPhase()

        XCTAssertEqual(
            polling.confirmCaptive(statusChanged: false, isPolling: false),
            .remainInHealthCheck
        )
        XCTAssertEqual(
            polling.confirmCaptive(statusChanged: false, isPolling: false),
            .remainInHealthCheck
        )
        XCTAssertTrue(polling.isExhausted)
    }

    func testStatusChangeReentersIntensivePolling() {
        var polling = exhaustedPhase()

        XCTAssertEqual(
            polling.confirmCaptive(statusChanged: true, isPolling: false),
            .enterIntensivePolling
        )
        XCTAssertFalse(polling.isExhausted)
        XCTAssertEqual(polling.attempts, 0)
    }

    func testExplicitRecheckReentersIntensivePolling() {
        var polling = exhaustedPhase()
        polling.reset()

        XCTAssertEqual(
            polling.confirmCaptive(statusChanged: false, isPolling: false),
            .enterIntensivePolling
        )
        XCTAssertFalse(polling.isExhausted)
        XCTAssertEqual(polling.attempts, 0)
    }

    func testReconfirmationWhilePollingPreservesTheAttemptBudget() {
        var polling = CaptivePollingPhase(maxAttempts: maxAttempts)
        _ = polling.confirmCaptive(statusChanged: true, isPolling: false)
        XCTAssertTrue(polling.recordAttempt())
        XCTAssertTrue(polling.recordAttempt())

        XCTAssertEqual(
            polling.confirmCaptive(statusChanged: false, isPolling: true),
            .continueIntensivePolling
        )
        XCTAssertEqual(polling.attempts, 2)
    }

    private func exhaustedPhase() -> CaptivePollingPhase {
        var polling = CaptivePollingPhase(maxAttempts: maxAttempts)
        _ = polling.confirmCaptive(statusChanged: true, isPolling: false)
        for _ in 0...maxAttempts {
            _ = polling.recordAttempt()
        }
        XCTAssertTrue(polling.isExhausted)
        return polling
    }
}
