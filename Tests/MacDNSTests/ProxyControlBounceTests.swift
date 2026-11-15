// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class ProxyControlBounceTests: XCTestCase {
    @MainActor
    func testChangedIntentAfterEnableCommitsAndThrowsRollsBack() async {
        var current = true
        var enabled = false
        let failure = NSError(domain: "reload", code: 1)
        do {
            try await ProxyControlBounce.run(
                isCurrent: { current }, disable: {}, waitForExit: {},
                enable: {
                    enabled = true
                    current = false
                    throw failure
                },
                rollbackStaleEnable: { enabled = false }
            )
            XCTFail("The reload failure must propagate")
        } catch {
            XCTAssertEqual(error as NSError, failure)
        }
        XCTAssertFalse(enabled)
    }

    @MainActor
    func testChangedIntentAfterSuccessfulEnableRollsBack() async throws {
        var current = true
        var enabled = false
        try await ProxyControlBounce.run(
            isCurrent: { current }, disable: {}, waitForExit: {},
            enable: {
                enabled = true
                current = false
            },
            rollbackStaleEnable: { enabled = false }
        )
        XCTAssertFalse(enabled)
    }

    @MainActor
    func testCurrentEnableFailureDoesNotRollBackNewIntent() async {
        var rollbacks = 0
        do {
            try await ProxyControlBounce.run(
                isCurrent: { true }, disable: {}, waitForExit: {},
                enable: { throw NSError(domain: "reload", code: 1) },
                rollbackStaleEnable: { rollbacks += 1 }
            )
            XCTFail("The reload failure must propagate")
        } catch {}
        XCTAssertEqual(rollbacks, 0)
    }

    @MainActor
    func testCurrentIntentCompletesBounceInOrder() async throws {
        var steps: [String] = []
        try await ProxyControlBounce.run(
            isCurrent: { true }, disable: { steps.append("disable") },
            waitForExit: { steps.append("wait") }, enable: { steps.append("enable") })
        XCTAssertEqual(steps, ["disable", "wait", "enable"])
    }

    @MainActor
    func testIntentChangedDuringDisablePreventsWait() async throws {
        var current = true
        var steps: [String] = []
        try await ProxyControlBounce.run(
            isCurrent: { current }, disable: { current = false },
            waitForExit: { steps.append("wait") }, enable: { steps.append("enable") })
        XCTAssertTrue(steps.isEmpty)
    }

    @MainActor
    func testChangedIntentDuringExitWaitPreventsEnable() async throws {
        var current = true
        var enabled = false
        try await ProxyControlBounce.run(
            isCurrent: { current }, disable: {},
            waitForExit: { current = false }, enable: { enabled = true })
        XCTAssertFalse(enabled)
    }

    @MainActor
    func testCancellationDuringDisablePreventsWaitAndEnable() async throws {
        var waited = false
        var enabled = false
        let task = Task {
            try await ProxyControlBounce.run(
                isCurrent: { true },
                disable: { withUnsafeCurrentTask { $0?.cancel() } },
                waitForExit: { waited = true }, enable: { enabled = true })
        }
        try await task.value
        XCTAssertFalse(waited)
        XCTAssertFalse(enabled)
    }
}
