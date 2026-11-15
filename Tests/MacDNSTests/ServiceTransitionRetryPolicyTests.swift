// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class ServiceTransitionRetryPolicyTests: XCTestCase {
    func testRetriesAreCappedAndBackedOff() {
        let policy = ServiceTransitionRetryPolicy.default
        var delays: [UInt64] = []
        var retryCount = 0
        var elapsed: UInt64 = 0

        while case .retry(let delay) = policy.decision(
            retryCount: retryCount,
            elapsedNanoseconds: elapsed
        ) {
            delays.append(delay)
            retryCount += 1
            elapsed += delay
            XCTAssertLessThanOrEqual(retryCount, policy.maximumRetries)
        }

        XCTAssertLessThanOrEqual(retryCount, policy.maximumRetries)
        XCTAssertLessThanOrEqual(elapsed, policy.deadlineNanoseconds)
        XCTAssertEqual(
            delays,
            [
                50_000_000,
                100_000_000,
                200_000_000,
                400_000_000,
                800_000_000,
                1_000_000_000,
                1_000_000_000,
                1_000_000_000,
            ]
        )
        XCTAssertEqual(
            policy.decision(retryCount: retryCount, elapsedNanoseconds: elapsed),
            .exhausted
        )
    }

    func testDelayNeverExceedsTheMaximum() {
        let policy = ServiceTransitionRetryPolicy.default

        for retryCount in 0...64 {
            XCTAssertLessThanOrEqual(
                policy.delayNanoseconds(retryCount: retryCount),
                policy.maximumDelayNanoseconds
            )
            XCTAssertGreaterThanOrEqual(
                policy.delayNanoseconds(retryCount: retryCount),
                policy.initialDelayNanoseconds
            )
        }
    }

    func testDeadlineExhaustsBeforeTheRetryCap() {
        let policy = ServiceTransitionRetryPolicy(
            maximumRetries: 100,
            initialDelayNanoseconds: 50_000_000,
            maximumDelayNanoseconds: 50_000_000,
            deadlineNanoseconds: 120_000_000
        )

        XCTAssertEqual(
            policy.decision(retryCount: 0, elapsedNanoseconds: 0),
            .retry(afterNanoseconds: 50_000_000)
        )
        XCTAssertEqual(
            policy.decision(retryCount: 1, elapsedNanoseconds: 50_000_000),
            .retry(afterNanoseconds: 50_000_000)
        )
        XCTAssertEqual(
            policy.decision(retryCount: 2, elapsedNanoseconds: 100_000_000),
            .exhausted
        )
    }

    func testExhaustedTransitionIsPresentedAsUnknown() {
        let presentation = RuntimeStatePresentationPolicy.transitioning

        XCTAssertEqual(presentation.providerState, .unknown)
        XCTAssertFalse(presentation.forwarding)
        XCTAssertEqual(presentation.resolverMode, "Starting or stopping")
    }
}
