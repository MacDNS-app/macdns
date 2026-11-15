// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import XCTest

final class ActivationRequestProgressPolicyTests: XCTestCase {
    func testClearsInProgressWhenNoWaitersRemain() {
        let policy = ActivationRequestProgressPolicy(pendingContinuations: 0)

        XCTAssertTrue(policy.shouldClearInProgressAfterWaiterRemoval)
    }

    func testKeepsInProgressWhenOtherWaitersRemain() {
        let policy = ActivationRequestProgressPolicy(pendingContinuations: 1)

        XCTAssertFalse(policy.shouldClearInProgressAfterWaiterRemoval)
    }
}
