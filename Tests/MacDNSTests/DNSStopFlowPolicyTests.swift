// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import XCTest

final class DNSStopFlowPolicyTests: XCTestCase {
    func testStopDisablesEnabledContentFilter() {
        let policy = DNSStopFlowPolicy(contentFilterEnabled: true)

        XCTAssertTrue(policy.shouldDisableContentFilter)
    }

    func testStopSkipsContentFilterDisableWhenAlreadyDisabled() {
        let policy = DNSStopFlowPolicy(contentFilterEnabled: false)

        XCTAssertFalse(policy.shouldDisableContentFilter)
    }
}
