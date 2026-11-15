// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent

/// Only the return-valued v3 setter can confirm that Rust accepted the
/// resolver options. The legacy void setters cannot, so a missing v3 symbol
/// must fail closed instead of acknowledging a rejected transaction.
final class ResolverOptionsBackendResultTests: XCTestCase {
    func testOnlyOneIsASuccessfulResolverOptionsResult() {
        XCTAssertTrue(
            ResolverModule.confirmedResolverOptionsApplySucceeded(1)
        )
        XCTAssertFalse(
            ResolverModule.confirmedResolverOptionsApplySucceeded(0)
        )
        XCTAssertFalse(
            ResolverModule.confirmedResolverOptionsApplySucceeded(-1)
        )
    }

    func testMissingV3SetterIsNeverAnAcknowledgedSuccess() {
        XCTAssertFalse(
            ResolverModule.confirmedResolverOptionsApplySucceeded(nil)
        )
    }
}
