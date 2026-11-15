// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class ServiceRecoveryProxyPolicyTests: XCTestCase {
    func testAutoStartDoesNotDisableProxyBeforeResolverRecoveryRuns() {
        let policy = ServiceRecoveryProxyPolicy(
            isEnabled: true,
            isUpdatingAgent: false,
            isStoppingServices: false,
            dnsProxyEnabled: true,
            persistedStateAvailability: .loaded
        )

        XCTAssertTrue(policy.shouldAttemptAutoStart)
        XCTAssertFalse(policy.shouldDisableProxyBeforeAutoStart)
        XCTAssertTrue(policy.shouldDisableProxyAfterAutoStartFailure)
    }

    func testProxyDisablesImmediatelyWhenNoAutoStartWillRun() {
        let policy = ServiceRecoveryProxyPolicy(
            isEnabled: false,
            isUpdatingAgent: false,
            isStoppingServices: false,
            dnsProxyEnabled: true,
            persistedStateAvailability: .loaded
        )

        XCTAssertFalse(policy.shouldAttemptAutoStart)
        XCTAssertTrue(policy.shouldDisableProxyBeforeAutoStart)
        XCTAssertFalse(policy.shouldDisableProxyAfterAutoStartFailure)
    }

    func testShutdownPreservesEnabledIntentWithoutRestartingResolver() {
        let policy = ServiceRecoveryProxyPolicy(
            isEnabled: true,
            isUpdatingAgent: false,
            isStoppingServices: true,
            dnsProxyEnabled: true,
            persistedStateAvailability: .loaded
        )

        XCTAssertFalse(policy.shouldAttemptAutoStart)
        XCTAssertTrue(policy.shouldDisableProxyBeforeAutoStart)
        XCTAssertFalse(policy.shouldDisableProxyAfterAutoStartFailure)
    }

    func testUnknownPersistedStateDoesNotChangeProxyOrStartResolver() {
        for availability: PersistedStateAvailability in [
            .loading,
            .unavailable,
            .invalidConfiguration,
        ] {
            let policy = ServiceRecoveryProxyPolicy(
                isEnabled: true,
                isUpdatingAgent: false,
                isStoppingServices: false,
                dnsProxyEnabled: true,
                persistedStateAvailability: availability
            )

            XCTAssertFalse(policy.shouldAttemptAutoStart)
            XCTAssertFalse(policy.shouldDisableProxyBeforeAutoStart)
            XCTAssertFalse(policy.shouldDisableProxyAfterAutoStartFailure)
        }
    }
}
