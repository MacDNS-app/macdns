// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

@MainActor
final class SoftwareUpdateLifecycleTests: XCTestCase {
    func testMissingBlockedEventTimesOutAndCanBeReleased() async {
        let gate = SoftwareUpdateTestGate()
        defer { gate.release() }
        let completed = expectation(description: "missing blocked wait ended")
        let waiting = Task { () -> SoftwareUpdateGateError? in
            defer { completed.fulfill() }
            do {
                try await gate.waitUntilBlocked(timeout: 0.02)
                return nil
            } catch let error as SoftwareUpdateGateError {
                return error
            } catch {
                XCTFail("Unexpected gate wait error: \(error)")
                return nil
            }
        }
        defer { waiting.cancel() }
        let result = await XCTWaiter.fulfillment(of: [completed], timeout: 1)
        gate.release()
        guard result == .completed else {
            return XCTFail("A missing blocked event must terminate its wait")
        }
        let error = await waiting.value
        XCTAssertEqual(error, .timedOutWaitingForPreparation)
    }

    func testReleaseBeforeBlockingDoesNotLeaveAPendingContinuation() async {
        let gate = SoftwareUpdateTestGate()
        gate.release()
        let completed = expectation(description: "released gate does not block")
        let waiting = Task {
            await gate.wait()
            completed.fulfill()
        }
        defer {
            waiting.cancel()
            gate.release()
        }
        let result = await XCTWaiter.fulfillment(of: [completed], timeout: 1)

        XCTAssertEqual(result, .completed)
    }

    func testInstallationWaitsForTrafficReleaseAndAgentExit() async {
        var steps: [SoftwareUpdateLifecycle.StopStep] = []
        let lifecycle = SoftwareUpdateLifecycle(
            stop: { step in
                steps.append(step)
                return true
            },
            restore: { XCTFail("A successful preparation must stay stopped until relaunch") }
        )

        let ready = await lifecycle.prepare()

        XCTAssertTrue(ready)
        XCTAssertEqual(steps, [.disableDNSProxy, .disableContentFilter, .unregisterAgent])
        XCTAssertEqual(lifecycle.state, .prepared)
        XCTAssertTrue(lifecycle.mayRelaunch)
        let repeated = await lifecycle.prepare()
        XCTAssertTrue(repeated)
        XCTAssertEqual(steps.count, 3, "Termination must reuse the completed Sparkle preparation")
    }

    func testFailedStepBlocksInstallationAndRestoresOnceWhenCycleEnds() async {
        for failedStep in SoftwareUpdateLifecycle.StopStep.allCases {
            var steps: [SoftwareUpdateLifecycle.StopStep] = []
            var restorations = 0
            let lifecycle = SoftwareUpdateLifecycle(
                stop: { step in
                    steps.append(step)
                    return step != failedStep
                },
                restore: { restorations += 1 }
            )

            let ready = await lifecycle.prepare()
            XCTAssertFalse(ready)
            XCTAssertEqual(steps.last, failedStep)
            XCTAssertFalse(lifecycle.mayRelaunch)
            await lifecycle.finishCycle()
            await lifecycle.finishCycle()
            XCTAssertEqual(restorations, 1)
            XCTAssertEqual(lifecycle.state, .idle)
        }
    }

    func testCancellationDuringAgentExitCannotResumeInstallation() async throws {
        let gate = SoftwareUpdateTestGate()
        defer { gate.release() }
        var restorations = 0
        let lifecycle = SoftwareUpdateLifecycle(
            stop: { step in
                if step == .unregisterAgent { await gate.wait() }
                return true
            },
            restore: { restorations += 1 }
        )
        let preparing = Task { await lifecycle.prepare() }
        defer { preparing.cancel() }
        try await gate.waitUntilBlocked()
        let cancelling = Task { await lifecycle.finishCycle() }
        await Task.yield()
        XCTAssertFalse(lifecycle.mayRelaunch)
        gate.release()

        let ready = await preparing.value
        await cancelling.value
        XCTAssertFalse(ready, "A late preparation result must not call Sparkle's install handler")
        XCTAssertEqual(restorations, 1)
        XCTAssertEqual(lifecycle.state, .idle)
    }

    func testFailedInstallationRestoresAndAllowsAnotherAttempt() async {
        var stops = 0
        var restorations = 0
        let lifecycle = SoftwareUpdateLifecycle(
            stop: { _ in
                stops += 1
                return true
            },
            restore: { restorations += 1 }
        )
        _ = await lifecycle.prepare()
        await lifecycle.finishCycle()
        let ready = await lifecycle.prepare()

        XCTAssertTrue(ready)
        XCTAssertEqual(stops, 6)
        XCTAssertEqual(restorations, 1)
    }

    func testConcurrentPreparationWaitersShareTheSameResult() async throws {
        let gate = SoftwareUpdateTestGate()
        defer { gate.release() }
        var stops = 0
        let lifecycle = SoftwareUpdateLifecycle(
            stop: { step in
                stops += 1
                if step == .unregisterAgent { await gate.wait() }
                return true
            },
            restore: {}
        )
        let first = Task { await lifecycle.prepare() }
        defer { first.cancel() }
        try await gate.waitUntilBlocked()
        let second = Task { await lifecycle.prepare() }
        await Task.yield()
        gate.release()
        let firstReady = await first.value
        let secondReady = await second.value

        XCTAssertTrue(firstReady)
        XCTAssertTrue(secondReady)
        XCTAssertEqual(stops, 3)
    }

    func testOrdinaryUpdateCheckDoesNotStopOrRestoreServices() async {
        let lifecycle = SoftwareUpdateLifecycle(
            stop: { _ in
                XCTFail("Discovery must not stop the Agent")
                return false
            },
            restore: { XCTFail("Discovery must not restart the Agent") }
        )
        await lifecycle.finishCycle()
        XCTAssertEqual(lifecycle.state, .idle)
        XCTAssertTrue(lifecycle.mayRelaunch)
    }

    func testDiscoveryCompletionDoesNotCancelPendingApplicationTermination() async throws {
        let gate = SoftwareUpdateTestGate()
        defer { gate.release() }
        var restorations = 0
        let lifecycle = SoftwareUpdateLifecycle(
            stop: { step in
                if step == .unregisterAgent { await gate.wait() }
                return true
            },
            restore: { restorations += 1 }
        )
        let termination = Task { await lifecycle.prepare(for: .applicationTermination) }
        defer { termination.cancel() }
        try await gate.waitUntilBlocked()
        let discovery = Task { await lifecycle.finishUpdateCycle(for: lifecycle.attemptID) }
        await Task.yield()
        gate.release()
        await discovery.value
        let ready = await termination.value

        XCTAssertTrue(ready)
        XCTAssertEqual(restorations, 0)
        XCTAssertEqual(lifecycle.state, .prepared)
    }

    func testLateCompletionFromPreviousAttemptCannotStopTheNextInstallation() async {
        var restorations = 0
        let lifecycle = SoftwareUpdateLifecycle(
            stop: { _ in true },
            restore: { restorations += 1 }
        )
        _ = await lifecycle.prepare()
        let firstAttempt = lifecycle.attemptID
        await lifecycle.finishCycle()
        _ = await lifecycle.prepare()
        await lifecycle.finishUpdateCycle(for: firstAttempt)

        XCTAssertEqual(lifecycle.state, .prepared)
        XCTAssertEqual(restorations, 1)
    }
}

private enum SoftwareUpdateGateError: Error, Equatable {
    case timedOutWaitingForPreparation
}

@MainActor
private final class SoftwareUpdateTestGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var observers: [UUID: XCTestExpectation] = [:]
    private var isReleased = false

    func wait() async {
        guard !isReleased else { return }
        await withCheckedContinuation { continuation in
            self.continuation = continuation
            observers.values.forEach { $0.fulfill() }
            observers.removeAll()
        }
    }

    func waitUntilBlocked(timeout: TimeInterval = 2) async throws {
        try Task.checkCancellation()
        if continuation != nil { return }
        let id = UUID()
        let expectation = XCTestExpectation(description: "software update preparation reaches the gate")
        observers[id] = expectation
        defer { observers.removeValue(forKey: id) }
        let result = await XCTWaiter.fulfillment(of: [expectation], timeout: timeout)
        try Task.checkCancellation()
        guard result == .completed else {
            throw SoftwareUpdateGateError.timedOutWaitingForPreparation
        }
    }

    func release() {
        isReleased = true
        let pending = continuation
        continuation = nil
        pending?.resume()
    }
}
