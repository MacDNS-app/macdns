// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS
@testable import Shared

final class LicenseExpirationNotificationPlanTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    func testNilAndPerpetualLicensesRemoveAllIDsAndScheduleNothing() {
        let nilPlan = LicenseExpirationNotificationPlan.make(
            for: nil,
            now: now
        )
        let perpetualPlan = LicenseExpirationNotificationPlan.make(
            for: licenseInfo(status: .valid, expiresAt: nil),
            now: now
        )

        XCTAssertEqual(Set(nilPlan.identifiersToRemove), expectedAllIdentifiers)
        XCTAssertTrue(nilPlan.notifications.isEmpty)
        XCTAssertEqual(Set(perpetualPlan.identifiersToRemove), expectedAllIdentifiers)
        XCTAssertTrue(perpetualPlan.notifications.isEmpty)
    }

    func testTrialUsesOnlyTrialNotificationIDs() {
        let plan = LicenseExpirationNotificationPlan.make(
            for: licenseInfo(
                status: .trial,
                expiresAt: now.addingTimeInterval(48 * 60 * 60)
            ),
            now: now
        )

        XCTAssertEqual(
            Set(plan.notifications.map(\.id)),
            expectedIdentifiers(prefix: "trial")
        )
    }

    func testPaidLicenseUsesOnlyPaidNotificationIDs() {
        let plan = LicenseExpirationNotificationPlan.make(
            for: licenseInfo(
                status: .valid,
                expiresAt: now.addingTimeInterval(48 * 60 * 60)
            ),
            now: now
        )

        XCTAssertEqual(
            Set(plan.notifications.map(\.id)),
            expectedIdentifiers(prefix: "license")
        )
    }

    func testLicenseTypeSwitchAlwaysRemovesPreviousIdentifiers() {
        let trialPlan = LicenseExpirationNotificationPlan.make(
            for: licenseInfo(
                status: .trial,
                expiresAt: now.addingTimeInterval(48 * 60 * 60)
            ),
            now: now
        )
        let paidPlan = LicenseExpirationNotificationPlan.make(
            for: licenseInfo(
                status: .valid,
                expiresAt: now.addingTimeInterval(48 * 60 * 60)
            ),
            now: now
        )

        XCTAssertEqual(Set(trialPlan.identifiersToRemove), expectedAllIdentifiers)
        XCTAssertEqual(Set(paidPlan.identifiersToRemove), expectedAllIdentifiers)
    }

    private var expectedAllIdentifiers: Set<String> {
        expectedIdentifiers(prefix: "trial")
            .union(expectedIdentifiers(prefix: "license"))
    }

    private func expectedIdentifiers(prefix: String) -> Set<String> {
        Set(
            ["24h", "12h", "2h", "now"].map {
                "\(prefix)-expiring-\($0)"
            }
        )
    }

    private func licenseInfo(
        status: LicenseStatus,
        expiresAt: Date?
    ) -> LicenseInfo {
        LicenseInfo(
            from: LicenseState(
                licenseKey: status == .valid ? "paid-key" : nil,
                licenseId: "license-1",
                status: status,
                expiresAt: expiresAt
            ),
            isServiceAllowed: true
        )
    }
}
