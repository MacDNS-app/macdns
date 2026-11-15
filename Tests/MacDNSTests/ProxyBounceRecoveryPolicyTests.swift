// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class ProxyBounceRecoveryPolicyTests: XCTestCase {
    private let epoch = Date(timeIntervalSinceReferenceDate: 800_000_000)

    private func policy(
        outageReported: Bool? = true,
        runtimeDNSDesired: Bool = true,
        servicesRunning: Bool = true,
        proxyEnabled: Bool = true,
        activationInProgress: Bool = false,
        replacementDrainActive: Bool = false,
        drainUnconfirmed: Bool = false,
        bounceInProgress: Bool = false,
        attemptsMade: Int = 0,
        lastAttemptElapsed: TimeInterval? = nil
    ) -> ProxyBounceRecoveryPolicy {
        ProxyBounceRecoveryPolicy(
            outageReported: outageReported,
            runtimeDNSDesired: runtimeDNSDesired,
            servicesRunning: servicesRunning,
            proxyEnabled: proxyEnabled,
            activationInProgress: activationInProgress,
            replacementDrainActive: replacementDrainActive,
            drainUnconfirmed: drainUnconfirmed,
            bounceInProgress: bounceInProgress,
            attemptsMade: attemptsMade,
            lastAttemptAt: lastAttemptElapsed.map { epoch.addingTimeInterval(-$0) },
            now: epoch
        )
    }

    func testBouncesOnReportedOutage() {
        XCTAssertEqual(policy().action, .bounce)
    }

    func testUnconfirmedDrainSkipsBouncingStraightToRestartRequired() {
        XCTAssertEqual(policy(drainUnconfirmed: true).action, .surfaceRestartRequired)
        XCTAssertEqual(
            policy(drainUnconfirmed: true, attemptsMade: 0, lastAttemptElapsed: nil).action,
            .surfaceRestartRequired
        )
    }

    func testUnconfirmedDrainStillRespectsTheEntryGuards() {
        XCTAssertEqual(policy(outageReported: false, drainUnconfirmed: true).action, .none)
        XCTAssertEqual(policy(drainUnconfirmed: true, bounceInProgress: true).action, .none)
    }

    func testNoActionWhenOutageNotReported() {
        XCTAssertEqual(policy(outageReported: false).action, .none)
        XCTAssertEqual(policy(outageReported: nil).action, .none)
    }

    func testNoActionWhenProtectionNotDesiredOrNotRunning() {
        XCTAssertEqual(policy(runtimeDNSDesired: false).action, .none)
        XCTAssertEqual(policy(servicesRunning: false).action, .none)
        XCTAssertEqual(policy(proxyEnabled: false).action, .none)
    }

    func testNoActionDuringActivationOrOngoingBounce() {
        XCTAssertEqual(policy(activationInProgress: true).action, .none)
        XCTAssertEqual(policy(bounceInProgress: true).action, .none)
    }

    /// A replacement drain owns the proxy configuration: between cancellation
    /// and disable the activation flag is already false while the proxy still
    /// reads enabled, so a bounce here is swallowed by the drain guard and
    /// burns one of the two recovery attempts as a no-op.
    func testNoActionDuringReplacementDrain() {
        XCTAssertEqual(policy(replacementDrainActive: true).action, .none)
        XCTAssertEqual(
            policy(
                replacementDrainActive: true,
                attemptsMade: ProxyBounceRecoveryPolicy.maxAttempts,
                lastAttemptElapsed: 300
            ).action,
            .none
        )
    }

    func testCooldownBlocksBackToBackBounces() {
        XCTAssertEqual(policy(attemptsMade: 1, lastAttemptElapsed: 30).action, .none)
        XCTAssertEqual(policy(attemptsMade: 1, lastAttemptElapsed: 130).action, .bounce)
    }

    func testCooldownBoundaryAtExactlyAttemptCooldownBounces() {
        XCTAssertEqual(
            policy(attemptsMade: 1, lastAttemptElapsed: ProxyBounceRecoveryPolicy.attemptCooldown).action,
            .bounce
        )
    }

    func testExhaustedAttemptsSurfaceRestartRequired() {
        XCTAssertEqual(
            policy(attemptsMade: ProxyBounceRecoveryPolicy.maxAttempts, lastAttemptElapsed: 300)
                .action,
            .surfaceRestartRequired
        )
    }
}
