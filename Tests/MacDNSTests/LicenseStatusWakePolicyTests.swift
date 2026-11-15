// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS
@testable import Shared

final class LicenseStatusWakePolicyTests: XCTestCase {
    func testAuthoritativeAllowedResponseReconcilesEnabledServices() {
        let policy = responsePolicy(
            info: licenseInfo(status: .valid, isServiceAllowed: true)
        )

        XCTAssertTrue(policy.shouldApply)
        XCTAssertEqual(policy.lifecycleAction, .reconcile)
    }

    func testAuthoritativeBlockedResponseDisablesServices() {
        let policy = responsePolicy(
            info: licenseInfo(status: .expired, isServiceAllowed: false)
        )

        XCTAssertTrue(policy.shouldApply)
        XCTAssertEqual(policy.lifecycleAction, .disable)
    }

    func testValidLicenseDoesNotReconcileBeforePersistedStateLoads() {
        let policy = responsePolicy(
            info: licenseInfo(status: .valid, isServiceAllowed: true),
            persistedStateAvailability: .unavailable
        )

        XCTAssertEqual(policy.lifecycleAction, .none)
    }

    func testInvalidLicenseDisablesBeforePersistedStateLoads() {
        let policy = responsePolicy(
            info: licenseInfo(status: .expired, isServiceAllowed: false),
            persistedStateAvailability: .loading
        )

        XCTAssertEqual(policy.lifecycleAction, .disable)
    }

    func testNewWakeGenerationInvalidatesEarlierResponseAndError() {
        let stale = responsePolicy(
            info: licenseInfo(status: .expired, isServiceAllowed: false),
            capturedWakeGeneration: 4,
            currentWakeGeneration: 5
        )

        XCTAssertFalse(stale.shouldApply)
        XCTAssertEqual(stale.lifecycleAction, .none)
        XCTAssertNil(stale.agentRespondingUpdate(forXPCSucceeded: true))
        XCTAssertNil(stale.agentRespondingUpdate(forXPCSucceeded: false))
    }

    func testLifecycleGenerationChangeInvalidatesResponseBeforeSideEffects() {
        let stale = responsePolicy(
            info: licenseInfo(status: .valid, isServiceAllowed: true),
            capturedLifecycleGeneration: 8,
            currentLifecycleGeneration: 9
        )

        XCTAssertFalse(stale.shouldApply)
        XCTAssertEqual(stale.lifecycleAction, .none)
    }

    func testStoppingLifecycleCannotApplyResponse() {
        let policy = responsePolicy(
            info: licenseInfo(status: .expired, isServiceAllowed: false),
            isStoppingDNS: true
        )

        XCTAssertFalse(policy.shouldApply)
        XCTAssertEqual(policy.lifecycleAction, .none)
    }

    func testLicenseWakeupGateCoalescesConcurrentSignalsWhileAdvancingGeneration() {
        let gate = ServiceWakeupGate()
        let countLock = NSLock()
        var acceptedSignals = 0

        DispatchQueue.concurrentPerform(iterations: 1_000) { _ in
            if gate.begin() {
                countLock.withLock { acceptedSignals += 1 }
            }
        }

        XCTAssertEqual(acceptedSignals, 1)
        XCTAssertEqual(gate.currentGeneration, 1_000)
        XCTAssertEqual(gate.complete(), 1_000)
    }

    private func responsePolicy(
        info: LicenseInfo,
        isEnabled: Bool = true,
        isStoppingDNS: Bool = false,
        capturedWakeGeneration: UInt64 = 1,
        currentWakeGeneration: UInt64 = 1,
        capturedLifecycleGeneration: UInt64 = 1,
        currentLifecycleGeneration: UInt64 = 1,
        persistedStateAvailability: PersistedStateAvailability = .loaded
    ) -> LicenseStatusWakeResponsePolicy {
        LicenseStatusWakeResponsePolicy(
            authoritativeInfo: info,
            isEnabled: isEnabled,
            isStoppingDNS: isStoppingDNS,
            capturedWakeGeneration: capturedWakeGeneration,
            currentWakeGeneration: currentWakeGeneration,
            capturedLifecycleGeneration: capturedLifecycleGeneration,
            currentLifecycleGeneration: currentLifecycleGeneration,
            persistedStateAvailability: persistedStateAvailability
        )
    }

    private func licenseInfo(
        status: LicenseStatus,
        isServiceAllowed: Bool
    ) -> LicenseInfo {
        LicenseInfo(
            from: LicenseState(
                licenseKey: status == .valid ? "paid-key" : nil,
                licenseId: "license-1",
                status: status,
                expiresAt: status == .valid
                    ? Date().addingTimeInterval(3_600)
                    : Date().addingTimeInterval(-3_600)
            ),
            isServiceAllowed: isServiceAllowed
        )
    }
}
