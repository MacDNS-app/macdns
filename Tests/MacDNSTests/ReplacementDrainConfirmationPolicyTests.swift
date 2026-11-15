// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class ReplacementDrainConfirmationPolicyTests: XCTestCase {
    /// The replacement must still be submitted when the drain fails,
    /// and the failure must be reported at that moment instead of silently.
    func testFailedDrainStillReplacesAndReportsItIsUnconfirmed() {
        let confirmation = ReplacementDrainConfirmationPolicy(
            proxyDisableConfirmed: false,
            providerExited: false
        )

        XCTAssertEqual(
            ExtensionReplacementDrainPolicy(
                providerRunning: true,
                drainState: .drained
            ).decision,
            .replaceNow
        )
        XCTAssertFalse(confirmation.isConfirmed)
        XCTAssertEqual(
            confirmation.unconfirmedReason,
            "proxy disable failed and the old provider did not exit within the drain timeout"
        )
    }

    func testDisableFailureAloneLeavesTheDrainUnconfirmed() {
        let confirmation = ReplacementDrainConfirmationPolicy(
            proxyDisableConfirmed: false,
            providerExited: true
        )

        XCTAssertFalse(confirmation.isConfirmed)
        XCTAssertEqual(confirmation.unconfirmedReason, "proxy disable failed")
    }

    func testLingeringProviderAloneLeavesTheDrainUnconfirmed() {
        let confirmation = ReplacementDrainConfirmationPolicy(
            proxyDisableConfirmed: true,
            providerExited: false
        )

        XCTAssertFalse(confirmation.isConfirmed)
        XCTAssertEqual(
            confirmation.unconfirmedReason,
            "the old provider did not exit within the drain timeout"
        )
    }

    func testConfirmedDrainReportsNothing() {
        let confirmation = ReplacementDrainConfirmationPolicy(
            proxyDisableConfirmed: true,
            providerExited: true
        )

        XCTAssertTrue(confirmation.isConfirmed)
        XCTAssertNil(confirmation.unconfirmedReason)
    }
}
