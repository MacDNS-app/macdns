// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class ReplacementDrainGenerationPolicyTests: XCTestCase {
    func testBeginIssuesMonotonicTokensAndEntersDraining() {
        var policy = ReplacementDrainGenerationPolicy()
        XCTAssertFalse(policy.isActive)

        let first = policy.begin()
        XCTAssertEqual(policy.state, .draining)
        XCTAssertTrue(policy.isActive)
        XCTAssertTrue(policy.owns(first))

        policy.closeActive()
        let second = policy.begin()
        XCTAssertGreaterThan(second, first)
        XCTAssertFalse(policy.owns(first))
    }

    func testOwningTokenWalksTheWholeDrainLifecycle() {
        var policy = ReplacementDrainGenerationPolicy()
        let token = policy.begin()

        XCTAssertTrue(policy.markDrained(token))
        XCTAssertEqual(policy.state, .drained)
        XCTAssertTrue(policy.close(token))
        XCTAssertEqual(policy.state, .idle)
        XCTAssertFalse(policy.isActive)
        XCTAssertNil(policy.activeToken)
    }

    func testSupersededTokenCannotTransitionToDrained() {
        var policy = ReplacementDrainGenerationPolicy()
        let stale = policy.begin()

        // A newer activation request took over the extension lifecycle.
        policy.closeActive()

        XCTAssertFalse(policy.markDrained(stale))
        XCTAssertEqual(policy.state, .idle)
        XCTAssertNil(policy.activeToken)
    }

    func testSupersededTokenCannotCloseANewerDrain() {
        var policy = ReplacementDrainGenerationPolicy()
        let stale = policy.begin()
        policy.closeActive()
        let current = policy.begin()

        XCTAssertFalse(policy.close(stale))
        XCTAssertEqual(policy.state, .draining)
        XCTAssertEqual(policy.activeToken, current)
    }

    func testTokenIsStaleAfterItsOwnDrainClosed() {
        var policy = ReplacementDrainGenerationPolicy()
        let token = policy.begin()
        XCTAssertTrue(policy.close(token))

        XCTAssertFalse(policy.owns(token))
        XCTAssertFalse(policy.markDrained(token))
        XCTAssertFalse(policy.close(token))
        XCTAssertEqual(policy.state, .idle)
    }
}
