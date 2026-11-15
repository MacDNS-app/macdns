// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent

final class ProxyControlOutagePolicyTests: XCTestCase {
    private let epoch = Date(timeIntervalSinceReferenceDate: 800_000_000)

    private func policy(
        resolverRunning: Bool = true,
        consecutiveFailures: Int = 5,
        firstFailureElapsed: TimeInterval? = 45
    ) -> ProxyControlOutagePolicy {
        ProxyControlOutagePolicy(
            resolverRunning: resolverRunning,
            consecutiveFailures: consecutiveFailures,
            firstFailureAt: firstFailureElapsed.map { epoch.addingTimeInterval(-$0) },
            now: epoch
        )
    }

    func testPersistentOutageWhenFailuresAndDurationExceedThresholds() {
        XCTAssertTrue(policy().isPersistentOutage)
    }

    func testNoOutageWhenResolverStopped() {
        XCTAssertFalse(policy(resolverRunning: false).isPersistentOutage)
    }

    func testNoOutageBelowFailureCount() {
        XCTAssertFalse(policy(consecutiveFailures: 3).isPersistentOutage)
    }

    func testNoOutageBeforeMinimumDuration() {
        XCTAssertFalse(policy(firstFailureElapsed: 10).isPersistentOutage)
    }

    func testNoOutageWithoutFirstFailureTimestamp() {
        XCTAssertFalse(policy(firstFailureElapsed: nil).isPersistentOutage)
    }

    func testOutageAtExactThresholds() {
        XCTAssertTrue(
            policy(
                consecutiveFailures: ProxyControlOutagePolicy.minimumFailures,
                firstFailureElapsed: ProxyControlOutagePolicy.minimumOutageDuration
            ).isPersistentOutage)
    }
}
