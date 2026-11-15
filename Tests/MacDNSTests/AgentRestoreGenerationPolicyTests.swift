// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent

final class AgentRestoreGenerationPolicyTests: XCTestCase {

    private func decision(
        isEnabledAfterLicenseCheck: Bool = true,
        currentLifecycle: UInt64 = 7,
        currentStop: UInt64 = 3,
        transitionInProgress: Bool = false
    ) -> Bool {
        AgentLifecycleGenerationPolicy.canRestoreAfterLicenseCheck(
            isEnabledAfterLicenseCheck: isEnabledAfterLicenseCheck,
            currentLifecycleGeneration: currentLifecycle,
            currentStopGeneration: currentStop,
            capturedLifecycleGeneration: 7,
            capturedStopGeneration: 3,
            transitionInProgress: transitionInProgress
        )
    }

    func testRestoreAllowedWhenNothingChanged() {
        XCTAssertTrue(decision())
    }

    func testRestoreRejectedWhenStopGenerationAdvanced() {
        XCTAssertFalse(decision(currentStop: 4))
    }

    func testRestoreRejectedWhenLifecycleGenerationAdvanced() {
        XCTAssertFalse(decision(currentLifecycle: 8))
    }

    func testRestoreRejectedWhenUserDisabledDuringLicenseCheck() {
        XCTAssertFalse(decision(isEnabledAfterLicenseCheck: false))
    }

    func testRestoreRejectedWhileTransitionInProgress() {
        XCTAssertTrue(decision(transitionInProgress: false))
        XCTAssertFalse(decision(transitionInProgress: true))
    }

    func testRunningResolverNeedsReconciliationAfterFailedStop() {
        XCTAssertTrue(
            AgentLifecycleGenerationPolicy.shouldReconcileRunningResolver(
                resolverRunning: true,
                acceptingCallbacks: false
            )
        )
        XCTAssertFalse(
            AgentLifecycleGenerationPolicy.shouldReconcileRunningResolver(
                resolverRunning: true,
                acceptingCallbacks: true
            )
        )
    }

    func testDeniedLicenseStopsServices() {
        XCTAssertEqual(
            LicenseStatusChangePolicy.action(
                allowed: false,
                isRestoringServices: true,
                resolverRunning: true
            ),
            .stopServices
        )
    }

    func testAllowedLicenseRestoresStoppedServices() {
        XCTAssertEqual(
            LicenseStatusChangePolicy.action(
                allowed: true,
                isRestoringServices: false,
                resolverRunning: false
            ),
            .restoreServices
        )
    }

    func testAllowedLicenseDoesNothingDuringRestore() {
        XCTAssertEqual(
            LicenseStatusChangePolicy.action(
                allowed: true,
                isRestoringServices: true,
                resolverRunning: false
            ),
            .none
        )
    }

    func testAllowedLicenseDoesNothingWhenResolverIsRunning() {
        XCTAssertEqual(
            LicenseStatusChangePolicy.action(
                allowed: true,
                isRestoringServices: false,
                resolverRunning: true
            ),
            .none
        )
    }
}
