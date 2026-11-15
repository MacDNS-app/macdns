// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNS

final class UpdateDiscoveryFreshnessPolicyTests: XCTestCase {
    func testNoCompletedDiscoveryAllowsForegroundCheck() {
        XCTAssertTrue(
            UpdateDiscoveryFreshnessPolicy.shouldCheck(
                lastCompletedAt: nil,
                now: Date(timeIntervalSince1970: 10_000)
            )
        )
    }

    func testRecentDiscoveryAvoidsRedundantForegroundChecks() {
        let completedAt = Date(timeIntervalSince1970: 10_000)

        XCTAssertFalse(
            UpdateDiscoveryFreshnessPolicy.shouldCheck(
                lastCompletedAt: completedAt,
                now: completedAt
            )
        )
        XCTAssertFalse(
            UpdateDiscoveryFreshnessPolicy.shouldCheck(
                lastCompletedAt: completedAt,
                now: completedAt.addingTimeInterval(3599)
            )
        )
    }

    func testDiscoveryBecomesStaleAtOneHour() {
        let completedAt = Date(timeIntervalSince1970: 10_000)

        XCTAssertTrue(
            UpdateDiscoveryFreshnessPolicy.shouldCheck(
                lastCompletedAt: completedAt,
                now: completedAt.addingTimeInterval(3600)
            )
        )
        XCTAssertTrue(
            UpdateDiscoveryFreshnessPolicy.shouldCheck(
                lastCompletedAt: completedAt,
                now: completedAt.addingTimeInterval(28_800)
            )
        )
    }

    func testClockRollbackDoesNotSuppressDiscovery() {
        let completedAt = Date(timeIntervalSince1970: 10_000)

        XCTAssertTrue(
            UpdateDiscoveryFreshnessPolicy.shouldCheck(
                lastCompletedAt: completedAt,
                now: completedAt.addingTimeInterval(-3600)
            )
        )
    }
}
