// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

final class CaptivePortalDecisionPolicyTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_000_000)
    private let network = "svc-A|en0||"
    private let otherNetwork = "svc-B|en1||"

    private func decision(
        portalSuspected: Bool = true,
        networkIdentity: String?,
        approval: CaptivePortalFullBypassApproval? = nil,
        at instant: Date? = nil
    ) -> CaptivePortalCompatibilityMode {
        CaptivePortalDecisionPolicy(
            portalSuspected: portalSuspected,
            networkIdentity: networkIdentity,
            approval: approval,
            now: instant ?? now
        ).mode
    }

    func testForgedProbeConfirmationsSelectScopedForwardingNotFullBypass() {
        XCTAssertEqual(
            decision(networkIdentity: network),
            .scopedForwarding
        )
    }

    func testNoSuspicionKeepsFullProtection() {
        XCTAssertEqual(
            decision(portalSuspected: false, networkIdentity: network),
            .none
        )
    }

    func testFullBypassRequiresAnApprovalForTheCurrentNetwork() {
        let approval = CaptivePortalFullBypassApproval.grant(
            networkIdentity: network,
            at: now
        )

        XCTAssertEqual(
            decision(networkIdentity: network, approval: approval),
            .approvedFullBypass
        )
        XCTAssertEqual(
            decision(networkIdentity: otherNetwork, approval: approval),
            .scopedForwarding
        )
        XCTAssertEqual(
            decision(networkIdentity: nil, approval: approval),
            .scopedForwarding
        )
    }

    func testApprovalExpiresOnItsFixedWindow() {
        let approval = CaptivePortalFullBypassApproval.grant(
            networkIdentity: network,
            at: now
        )

        XCTAssertEqual(
            decision(
                networkIdentity: network,
                approval: approval,
                at: now.addingTimeInterval(
                    CaptivePortalFullBypassApproval.window - 1
                )
            ),
            .approvedFullBypass
        )
        XCTAssertEqual(
            decision(
                networkIdentity: network,
                approval: approval,
                at: now.addingTimeInterval(
                    CaptivePortalFullBypassApproval.window
                )
            ),
            .scopedForwarding
        )
    }

    func testProbeResultsCannotRenewAnExpiredApproval() {
        let approval = CaptivePortalFullBypassApproval.grant(
            networkIdentity: network,
            at: now
        )
        let afterExpiry = now.addingTimeInterval(
            CaptivePortalFullBypassApproval.window + 1
        )

        // Repeated confirmations are exactly what an on-path attacker can
        // produce. None of them may extend the granted window.
        for _ in 0..<5 {
            XCTAssertEqual(
                decision(
                    networkIdentity: network,
                    approval: approval,
                    at: afterExpiry
                ),
                .scopedForwarding
            )
        }
        XCTAssertEqual(approval.expiresAt, now.addingTimeInterval(CaptivePortalFullBypassApproval.window))
    }

    // MARK: - Continuation of an already active bypass

    private func continuation(
        fullBypassActive: Bool = true,
        networkIdentity: String?,
        approval: CaptivePortalFullBypassApproval?,
        at instant: Date? = nil
    ) -> CaptiveFullBypassContinuation {
        CaptivePortalDecisionPolicy.continuation(
            fullBypassActive: fullBypassActive,
            networkIdentity: networkIdentity,
            approval: approval,
            now: instant ?? now
        )
    }

    /// The window has to end the bypass on its own. The detector only reports
    /// status *changes*, so an attacker who keeps answering `.captive` produces
    /// no callback that would re-check the authorization.
    func testActiveBypassIsRevokedOnceTheWindowLapses() {
        let approval = CaptivePortalFullBypassApproval.grant(
            networkIdentity: network,
            at: now
        )

        XCTAssertEqual(
            continuation(
                networkIdentity: network,
                approval: approval,
                at: now.addingTimeInterval(
                    CaptivePortalFullBypassApproval.window - 1
                )
            ),
            .keepBypass
        )
        XCTAssertEqual(
            continuation(
                networkIdentity: network,
                approval: approval,
                at: now.addingTimeInterval(
                    CaptivePortalFullBypassApproval.window
                )
            ),
            .revokeBypass
        )
        XCTAssertEqual(
            continuation(
                networkIdentity: network,
                approval: approval,
                at: now.addingTimeInterval(
                    CaptivePortalFullBypassApproval.window * 10
                )
            ),
            .revokeBypass
        )
    }

    func testActiveBypassIsRevokedWhenTheHostMovesToAnotherNetwork() {
        let approval = CaptivePortalFullBypassApproval.grant(
            networkIdentity: network,
            at: now
        )

        XCTAssertEqual(
            continuation(networkIdentity: otherNetwork, approval: approval),
            .revokeBypass
        )
        XCTAssertEqual(
            continuation(networkIdentity: nil, approval: approval),
            .revokeBypass
        )
    }

    func testActiveBypassWithoutAnyApprovalIsRevoked() {
        XCTAssertEqual(
            continuation(networkIdentity: network, approval: nil),
            .revokeBypass
        )
    }

    func testLapsedApprovalIsDroppedEvenWithoutAnActiveBypass() {
        let approval = CaptivePortalFullBypassApproval.grant(
            networkIdentity: network,
            at: now
        )

        XCTAssertEqual(
            continuation(
                fullBypassActive: false,
                networkIdentity: network,
                approval: approval,
                at: now.addingTimeInterval(
                    CaptivePortalFullBypassApproval.window
                )
            ),
            .dropApproval
        )
        XCTAssertEqual(
            continuation(
                fullBypassActive: false,
                networkIdentity: otherNetwork,
                approval: approval
            ),
            .dropApproval
        )
        XCTAssertEqual(
            continuation(
                fullBypassActive: false,
                networkIdentity: network,
                approval: approval
            ),
            .none
        )
        XCTAssertEqual(
            continuation(
                fullBypassActive: false,
                networkIdentity: network,
                approval: nil
            ),
            .none
        )
    }

    func testRuntimeFlagsMapToTheCompatibilityMode() {
        XCTAssertEqual(
            CaptivePortalCompatibilityMode.from(
                fullBypassActive: true,
                forwarding: false
            ),
            .approvedFullBypass
        )
        XCTAssertEqual(
            CaptivePortalCompatibilityMode.from(
                fullBypassActive: false,
                forwarding: true
            ),
            .scopedForwarding
        )
        XCTAssertEqual(
            CaptivePortalCompatibilityMode.from(
                fullBypassActive: false,
                forwarding: false
            ),
            .none
        )
    }
}
