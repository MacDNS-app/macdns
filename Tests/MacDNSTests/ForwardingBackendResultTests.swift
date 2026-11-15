// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest
@testable import MacDNSAgent

final class ForwardingBackendResultTests: XCTestCase {
    func testOnlyOneIsASuccessfulForwardingResult() {
        XCTAssertTrue(ResolverModule.forwardingCallSucceeded(1))
        XCTAssertFalse(ResolverModule.forwardingCallSucceeded(0))
        XCTAssertFalse(ResolverModule.forwardingCallSucceeded(-1))
    }

    func testDisableRequiresReturnValuedV2Result() {
        XCTAssertTrue(
            ResolverModule.confirmedForwardingDisableSucceeded(1)
        )
        XCTAssertFalse(
            ResolverModule.confirmedForwardingDisableSucceeded(0)
        )
        XCTAssertFalse(
            ResolverModule.confirmedForwardingDisableSucceeded(nil)
        )
    }
}
