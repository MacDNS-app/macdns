// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import DNSProxyExtension

final class ProxyIdleDeadlineTests: XCTestCase {

    private let second: UInt64 = 1_000_000_000

    func testAFreshConnectionIsNotIdle() {
        let deadline = ProxyIdleDeadline(timeout: 120, startedAt: 0)

        XCTAssertFalse(deadline.isExpired(at: 0))
        XCTAssertFalse(deadline.isExpired(at: 119 * second))
    }

    func testTheDeadlineExpiresOnceTheWindowElapses() {
        let deadline = ProxyIdleDeadline(timeout: 120, startedAt: 0)

        XCTAssertTrue(deadline.isExpired(at: 120 * second))
        XCTAssertTrue(deadline.isExpired(at: 600 * second))
    }

    func testIOProgressRenewsTheDeadline() {
        var deadline = ProxyIdleDeadline(timeout: 120, startedAt: 0)

        deadline.noteProgress(at: 119 * second)

        XCTAssertFalse(deadline.isExpired(at: 200 * second))
        XCTAssertTrue(deadline.isExpired(at: 239 * second))
    }

    func testCheckingTheDeadlineIsNotProgress() {
        let deadline = ProxyIdleDeadline(timeout: 120, startedAt: 0)

        // A sweeper tick must not keep a silent connection alive.
        XCTAssertFalse(deadline.isExpired(at: 60 * second))
        XCTAssertFalse(deadline.isExpired(at: 119 * second))
        XCTAssertTrue(deadline.isExpired(at: 120 * second))
    }

    func testEveryProgressPointPushesTheDeadlineFurtherOut() {
        var deadline = ProxyIdleDeadline(timeout: 10, startedAt: 0)

        for tick in 1...20 {
            deadline.noteProgress(at: UInt64(tick) * 5 * second)
            XCTAssertFalse(deadline.isExpired(at: UInt64(tick) * 5 * second + 9 * second))
        }

        XCTAssertTrue(deadline.isExpired(at: 110 * second))
    }
}
