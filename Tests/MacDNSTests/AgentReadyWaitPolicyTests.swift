// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

@MainActor
final class AgentReadyWaitPolicyTests: XCTestCase {
    func testHungProbeTerminatesAtOverallDeadlineAndReleasesCaller() async {
        var now: TimeInterval = 0
        var probeBudgets: [TimeInterval] = []
        var sleeps = 0

        let isReady = await AgentReadyWaitPolicy.waitUntilReady(
            policy: AgentReadyWaitPolicy(timeout: 5.0, pollInterval: 0.1),
            elapsed: { now },
            probe: { budget in
                probeBudgets.append(budget)
                // A hung XPC call burns the entire budget it was granted.
                now += budget
                return false
            },
            sleep: { seconds in
                sleeps += 1
                now += seconds
            }
        )

        XCTAssertFalse(isReady)
        XCTAssertEqual(probeBudgets, [5.0])
        XCTAssertEqual(sleeps, 0)
        XCTAssertEqual(now, 5.0)
    }

    func testEveryProbeIsCappedByTheRemainingBudget() async {
        var now: TimeInterval = 0
        var probeBudgets: [TimeInterval] = []

        let isReady = await AgentReadyWaitPolicy.waitUntilReady(
            policy: AgentReadyWaitPolicy(timeout: 10.0, pollInterval: 1.0),
            elapsed: { now },
            probe: { budget in
                probeBudgets.append(budget)
                now += 2.0
                return false
            },
            sleep: { seconds in
                now += seconds
            }
        )

        XCTAssertFalse(isReady)
        XCTAssertEqual(probeBudgets, [10.0, 7.0, 4.0, 1.0])
        XCTAssertTrue(probeBudgets.allSatisfy { $0 <= 10.0 })
    }

    func testReadyProbeStopsTheWaitImmediately() async {
        var now: TimeInterval = 0
        var probeCalls = 0
        var sleeps = 0

        let isReady = await AgentReadyWaitPolicy.waitUntilReady(
            policy: AgentReadyWaitPolicy(timeout: 5.0, pollInterval: 0.1),
            elapsed: { now },
            probe: { _ in
                probeCalls += 1
                now += 0.01
                return probeCalls == 2
            },
            sleep: { seconds in
                sleeps += 1
                now += seconds
            }
        )

        XCTAssertTrue(isReady)
        XCTAssertEqual(probeCalls, 2)
        XCTAssertEqual(sleeps, 1)
    }

    func testExpiredBudgetNeverProbes() {
        let policy = AgentReadyWaitPolicy(timeout: 5.0, pollInterval: 0.1)

        XCTAssertEqual(policy.step(elapsed: 0), .probe(budget: 5.0))
        XCTAssertEqual(policy.step(elapsed: 5.0), .expired)
        XCTAssertEqual(policy.step(elapsed: 6.0), .expired)
    }
}
