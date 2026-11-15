// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

@MainActor
final class FirstRunContinueGateTests: XCTestCase {

    func testAnOpenWindowWaitsForAStepThatIsNotDoneOrApproved() {
        XCTAssertTrue(FirstRunContinueGate.waits(stepDone: false, windowOpen: true, approved: false))
    }

    /// Nothing could open the gate without the window, so setup goes on.
    func testAClosedWindowNeverWaits() {
        for stepDone in [false, true] {
            for approved in [false, true] {
                XCTAssertFalse(FirstRunContinueGate.waits(stepDone: stepDone, windowOpen: false, approved: approved))
            }
        }
    }

    /// A finished step needs no macOS request, so there is nothing to wait for.
    func testADoneStepNeverWaits() {
        XCTAssertFalse(FirstRunContinueGate.waits(stepDone: true, windowOpen: true, approved: false))
        XCTAssertFalse(FirstRunContinueGate.waits(stepDone: true, windowOpen: true, approved: true))
    }

    /// The click that started setup already answered the step current then.
    func testTheApprovedStepNeverWaits() {
        XCTAssertFalse(FirstRunContinueGate.waits(stepDone: false, windowOpen: true, approved: true))
    }

    func testWaitReturnsAfterOpen() async {
        let gate = FirstRunContinueGate()
        var returned = false
        let waiter = Task { @MainActor in
            await gate.wait()
            returned = true
        }
        for _ in 0..<10 { await Task.yield() }
        XCTAssertFalse(returned, "the gate must hold until it opens")

        gate.open()

        await waiter.value
        XCTAssertTrue(returned)
    }

    func testWaitAfterOpenReturnsAtOnce() async {
        let gate = FirstRunContinueGate()
        gate.open()

        await gate.wait()
    }

    func testASecondOpenDoesNothing() async {
        let gate = FirstRunContinueGate()
        let waiter = Task { @MainActor in await gate.wait() }
        for _ in 0..<10 { await Task.yield() }

        gate.open()
        // Resuming the wait twice would trap.
        gate.open()

        await waiter.value
    }
}
