// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNSAgent

private final class SnapshotRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    private var sawMainThread = false

    var callCount: Int { lock.withLock { calls } }
    var ranOnMainThread: Bool { lock.withLock { sawMainThread } }

    func record() {
        lock.withLock {
            calls += 1
            if Thread.isMainThread {
                sawMainThread = true
            }
        }
    }
}

final class MaintenanceSchedulingPolicyTests: XCTestCase {

    func testSnapshotNeverRunsOnTheMainQueue() {
        let recorder = SnapshotRecorder()
        let finished = expectation(description: "tick finished")
        let runner = MaintenanceTickRunner(
            enqueue: { work in
                DispatchQueue(label: "app.macdns.tests.maintenance").async(execute: work)
            },
            isResolverRunning: { true },
            snapshot: {
                recorder.record()
                return .wrote(entries: 7)
            }
        )

        XCTAssertTrue(Thread.isMainThread, "the timer fires on the main queue")
        runner.tick { outcome in
            XCTAssertEqual(outcome, .snapshot(.wrote(entries: 7)))
            finished.fulfill()
        }
        wait(for: [finished], timeout: 2.0)

        XCTAssertEqual(recorder.callCount, 1)
        XCTAssertFalse(
            recorder.ranOnMainThread,
            "the blocking cache snapshot must never stall the agent main queue"
        )
    }

    func testOverlappingTicksCoalesceIntoTheRunningSnapshot() {
        var pending: [() -> Void] = []
        var outcomes: [MaintenanceTickOutcome] = []
        let recorder = SnapshotRecorder()
        let runner = MaintenanceTickRunner(
            enqueue: { pending.append($0) },
            isResolverRunning: { true },
            snapshot: {
                recorder.record()
                return .wrote(entries: 1)
            }
        )

        runner.tick { outcomes.append($0) }
        runner.tick { outcomes.append($0) }

        XCTAssertEqual(pending.count, 1, "a second tick must not queue another blocking snapshot")
        XCTAssertEqual(outcomes, [.coalesced])

        pending.removeFirst()()

        XCTAssertEqual(recorder.callCount, 1)
        XCTAssertEqual(outcomes, [.coalesced, .snapshot(.wrote(entries: 1))])

        runner.tick { outcomes.append($0) }
        XCTAssertEqual(pending.count, 1, "the in-flight guard must release once the snapshot returns")
    }

    func testBackendTimeoutIsSurfacedInsteadOfLookingLikeSuccess() {
        var pending: [() -> Void] = []
        var outcome: MaintenanceTickOutcome?
        let runner = MaintenanceTickRunner(
            enqueue: { pending.append($0) },
            isResolverRunning: { true },
            snapshot: { .timedOut }
        )

        runner.tick { outcome = $0 }
        pending.removeFirst()()

        XCTAssertEqual(outcome, .snapshot(.timedOut))
    }

    func testFailedSnapshotStillReleasesTheInFlightGuard() {
        var pending: [() -> Void] = []
        var outcomes: [MaintenanceTickOutcome] = []
        let runner = MaintenanceTickRunner(
            enqueue: { pending.append($0) },
            isResolverRunning: { true },
            snapshot: { .failed }
        )

        runner.tick { outcomes.append($0) }
        pending.removeFirst()()
        runner.tick { outcomes.append($0) }
        pending.removeFirst()()

        XCTAssertEqual(outcomes, [.snapshot(.failed), .snapshot(.failed)])
    }

    func testStoppedResolverSkipsTheSnapshotEntirely() {
        var pending: [() -> Void] = []
        var outcome: MaintenanceTickOutcome?
        let recorder = SnapshotRecorder()
        let runner = MaintenanceTickRunner(
            enqueue: { pending.append($0) },
            isResolverRunning: { false },
            snapshot: {
                recorder.record()
                return .wrote(entries: 0)
            }
        )

        runner.tick { outcome = $0 }
        pending.removeFirst()()

        XCTAssertEqual(outcome, .skippedResolverStopped)
        XCTAssertEqual(recorder.callCount, 0)
    }

    /// The Swift in-flight guard releases when the FFI call returns, so a later
    /// tick can reach a resolver whose previous writer is still running. That
    /// answer must arrive as its own state, not as a failure, and it must not
    /// wedge the guard for the ticks after it.
    func testResolverBusySnapshotIsAnOutcomeOfItsOwnAndNotAFailure() {
        var pending: [() -> Void] = []
        var outcomes: [MaintenanceTickOutcome] = []
        let runner = MaintenanceTickRunner(
            enqueue: { pending.append($0) },
            isResolverRunning: { true },
            snapshot: { .busy }
        )

        runner.tick { outcomes.append($0) }
        pending.removeFirst()()
        runner.tick { outcomes.append($0) }
        pending.removeFirst()()

        XCTAssertEqual(
            outcomes, [.snapshot(.busy), .snapshot(.busy)],
            "a coalesced write is expected state, not a failed snapshot, and it must not wedge the guard"
        )
    }

    func testCacheSnapshotResultMapsBackendReturnCodes() {
        XCTAssertEqual(ResolverModule.cacheSnapshotResult(12), .wrote(entries: 12))
        XCTAssertEqual(ResolverModule.cacheSnapshotResult(0), .wrote(entries: 0))
        XCTAssertEqual(
            ResolverModule.cacheSnapshotResult(-2), .timedOut,
            "the periodic snapshot deadline must stay distinguishable from a plain failure"
        )
        XCTAssertEqual(
            ResolverModule.cacheSnapshotResult(-3), .busy,
            "a coalesced write must not reach the agent as a failure"
        )
        XCTAssertEqual(ResolverModule.cacheSnapshotResult(-1), .failed)
        XCTAssertEqual(ResolverModule.cacheSnapshotResult(-99), .failed)
    }
}
