// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class BoundedCallbackTests: XCTestCase {
    func testLateMutationReplyRequestsOneReconciliationWithoutRepeatingCompletion() {
        var deadline: (() -> Void)?
        var reply: ((Bool) -> Void)?
        var agentEnabled = true
        var displayedEnabled = true
        var completions = 0
        var reloads = 0
        BoundedCallback.run(
            seconds: 30, timeoutValue: false,
            schedule: { _, action in deadline = action },
            completion: { _ in
                completions += 1
                displayedEnabled = agentEnabled
            },
            onLateReply: { _ in
                reloads += 1
                displayedEnabled = agentEnabled
            },
            operation: { reply = $0 }
        )
        deadline?()
        XCTAssertTrue(displayedEnabled)
        agentEnabled = false
        reply?(false)
        reply?(false)
        XCTAssertEqual(completions, 1)
        XCTAssertEqual(reloads, 1)
        XCTAssertFalse(displayedEnabled)
    }

    func testReplyBeforeDeadlineNeverTriggersLateReconciliation() {
        var deadline: (() -> Void)?
        var reply: ((Bool) -> Void)?
        var completions = 0
        var reloads = 0
        BoundedCallback.run(
            seconds: 30, timeoutValue: false,
            schedule: { _, action in deadline = action },
            completion: { _ in completions += 1 },
            onLateReply: { _ in reloads += 1 },
            operation: { reply = $0 }
        )
        reply?(true)
        deadline?()
        reply?(true)
        XCTAssertEqual(completions, 1)
        XCTAssertEqual(reloads, 0)
    }

    func testNoReplyCompletesAtDeadlineAndIgnoresLateReplies() {
        var deadline: (() -> Void)?
        var reply: ((Bool) -> Void)?
        var values: [Bool] = []
        BoundedCallback.run(
            seconds: 5, timeoutValue: false,
            schedule: { seconds, action in
                XCTAssertEqual(seconds, 5)
                deadline = action
            }, completion: { values.append($0) }, operation: { reply = $0 })
        XCTAssertTrue(values.isEmpty)
        deadline?()
        reply?(true)
        reply?(false)
        XCTAssertEqual(values, [false])
    }

    func testReplyWinsOverDuplicateAndDeadline() {
        var deadline: (() -> Void)?
        var values: [Bool] = []
        BoundedCallback.run(
            seconds: 30, timeoutValue: false,
            schedule: { _, action in deadline = action },
            completion: { values.append($0) },
            operation: { reply in
                reply(true)
                reply(false)
            })
        deadline?()
        XCTAssertEqual(values, [true])
    }
}
