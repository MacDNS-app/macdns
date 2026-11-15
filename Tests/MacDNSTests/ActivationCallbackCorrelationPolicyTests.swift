// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import XCTest

final class ActivationCallbackCorrelationPolicyTests: XCTestCase {
    func testAppliesCallbackForCurrentActivationRequest() {
        let policy = ActivationCallbackCorrelationPolicy(
            callbackGeneration: 2,
            activeGeneration: 2
        )

        XCTAssertTrue(policy.shouldApplyCallback)
    }

    func testIgnoresStaleCallbackAfterRetryStartedNewRequest() {
        let policy = ActivationCallbackCorrelationPolicy(
            callbackGeneration: 1,
            activeGeneration: 2
        )

        XCTAssertFalse(policy.shouldApplyCallback)
    }

    func testIgnoresUnknownCallbackWithoutTrackedRequest() {
        let policy = ActivationCallbackCorrelationPolicy(
            callbackGeneration: nil,
            activeGeneration: 2
        )

        XCTAssertFalse(policy.shouldApplyCallback)
    }
}
