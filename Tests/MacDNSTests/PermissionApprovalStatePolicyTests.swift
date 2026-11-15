// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import XCTest

final class PermissionApprovalStatePolicyTests: XCTestCase {
    func testAgentApprovalSurvivesResolvedExtensionApproval() {
        let policy = PermissionApprovalStatePolicy(
            agentNeedsApproval: true,
            proxyNeedsApproval: false,
            filterNeedsApproval: false
        )

        XCTAssertTrue(policy.needsPermissionApproval)
    }

    func testExtensionApprovalStillRequestsPermissionWhenAgentDoesNot() {
        let policy = PermissionApprovalStatePolicy(
            agentNeedsApproval: false,
            proxyNeedsApproval: false,
            filterNeedsApproval: true
        )

        XCTAssertTrue(policy.needsPermissionApproval)
    }

    func testPermissionApprovalClearsOnlyWhenAgentAndExtensionsAreResolved() {
        let policy = PermissionApprovalStatePolicy(
            agentNeedsApproval: false,
            proxyNeedsApproval: false,
            filterNeedsApproval: false
        )

        XCTAssertFalse(policy.needsPermissionApproval)
    }
}
