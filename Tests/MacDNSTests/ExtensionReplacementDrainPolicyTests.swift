// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class ExtensionReplacementDrainPolicyTests: XCTestCase {
    func testCancelsAndDrainsWhenTheProviderStillRuns() {
        XCTAssertEqual(
            ExtensionReplacementDrainPolicy(
                providerRunning: true,
                drainState: .idle
            ).decision,
            .cancelAndDrain
        )
    }

    func testReplacesImmediatelyWhenNoProviderRunning() {
        XCTAssertEqual(
            ExtensionReplacementDrainPolicy(
                providerRunning: false,
                drainState: .idle
            ).decision,
            .replaceNow
        )
    }

    func testReplacesAfterDrainEvenIfProviderLingered() {
        XCTAssertEqual(
            ExtensionReplacementDrainPolicy(
                providerRunning: true,
                drainState: .drained
            ).decision,
            .replaceNow
        )
    }

    func testNeverCancelsTwiceWhileDraining() {
        XCTAssertEqual(
            ExtensionReplacementDrainPolicy(
                providerRunning: true,
                drainState: .draining
            ).decision,
            .replaceNow
        )
    }
}
