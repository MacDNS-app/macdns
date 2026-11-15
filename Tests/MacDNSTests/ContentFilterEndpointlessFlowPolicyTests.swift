// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import ContentFilterExtension

final class ContentFilterEndpointlessFlowPolicyTests: XCTestCase {
    func testValidatedMacDNSBinaryKeepsTheFastAllowPath() {
        XCTAssertEqual(
            ContentFilterEndpointlessFlowPolicy.newFlowDecision(sourceTrusted: true),
            .allow
        )
        XCTAssertEqual(
            ContentFilterEndpointlessFlowPolicy.finalFlowDecision(sourceTrusted: true),
            .allow
        )
    }

    func testUntrustedSourceNeverReceivesAFinalAllow() {
        let newFlow = ContentFilterEndpointlessFlowPolicy.newFlowDecision(
            sourceTrusted: false
        )

        XCTAssertNotEqual(newFlow, .allow)
        XCTAssertEqual(newFlow, .inspect)
    }

    func testUntrustedSourceIsDroppedWhenTheDestinationNeverShowsUp() {
        XCTAssertEqual(
            ContentFilterEndpointlessFlowPolicy.finalFlowDecision(sourceTrusted: false),
            .drop
        )
    }
}
