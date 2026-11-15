// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class PersistedStateResponsePolicyTests: XCTestCase {
    func testAppliesCurrentResponseWhenCoordinatorIsIdle() {
        XCTAssertTrue(
            PersistedStateResponsePolicy.canApply(
                requestGeneration: 3,
                currentGeneration: 3,
                coordinatorIsIdle: true
            )
        )
    }

    func testRejectsResponseAfterNewerMutation() {
        XCTAssertFalse(
            PersistedStateResponsePolicy.canApply(
                requestGeneration: 3,
                currentGeneration: 4,
                coordinatorIsIdle: true
            )
        )
    }

    func testRejectsResponseWhileSaveIsInFlight() {
        XCTAssertFalse(
            PersistedStateResponsePolicy.canApply(
                requestGeneration: 3,
                currentGeneration: 3,
                coordinatorIsIdle: false
            )
        )
    }
}
