// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

@MainActor
final class FirstRunNotificationWaitTests: XCTestCase {

    func testWaitReturnsWhenTheAnswerReturns() async {
        let wait = FirstRunNotificationWait()
        var answered = false

        await wait.wait { answered = true }

        XCTAssertTrue(answered)
    }

    func testEndReturnsTheWaitWhileTheAnswerNeverReturns() async {
        let wait = FirstRunNotificationWait()
        let asked = expectation(description: "answer started")
        let waiter = Task { @MainActor in
            await wait.wait {
                asked.fulfill()
                await Self.neverReturn()
            }
        }
        await fulfillment(of: [asked], timeout: 5)

        wait.end()

        await waiter.value
    }

    func testASecondEndDoesNothing() async {
        let wait = FirstRunNotificationWait()
        let asked = expectation(description: "answer started")
        let waiter = Task { @MainActor in
            await wait.wait {
                asked.fulfill()
                await Self.neverReturn()
            }
        }
        await fulfillment(of: [asked], timeout: 5)

        wait.end()
        // Resuming the wait twice would trap.
        wait.end()

        await waiter.value
    }

    func testWaitAfterEndReturnsAtOnce() async {
        let wait = FirstRunNotificationWait()
        wait.end()
        var asked = false

        await wait.wait {
            asked = true
            await Self.neverReturn()
        }

        XCTAssertFalse(asked, "an ended wait must not ask again")
    }

    func testTheSetupAsksBeforeTheResolverOnlyForAnOpenWindowAndAnOpenQuestion() {
        XCTAssertEqual(request(notificationsDecided: false, skipped: false, windowOpen: true), .beforeResolver)
    }

    /// Nothing could end the wait without the window. The request then stays
    /// after protection starts, as for every other Enable.
    func testAClosedWindowAsksAfterProtectionStarts() {
        XCTAssertEqual(request(notificationsDecided: false, skipped: false, windowOpen: false), .afterProtectionStarts)
    }

    /// A decided question returns the stored answer without a macOS request.
    func testADecidedQuestionAsksAfterProtectionStarts() {
        XCTAssertEqual(request(notificationsDecided: true, skipped: false, windowOpen: true), .afterProtectionStarts)
    }

    /// "Skip" can come before the wait starts. Asking after protection starts
    /// would put the request on screen with the local network request.
    func testASkippedQuestionIsNeverAskedDuringTheSetup() {
        XCTAssertEqual(request(notificationsDecided: false, skipped: true, windowOpen: true), .skipped)
        XCTAssertEqual(request(notificationsDecided: false, skipped: true, windowOpen: false), .skipped)
        XCTAssertEqual(request(notificationsDecided: true, skipped: true, windowOpen: true), .skipped)
    }

    /// Closing the window opens the notifications gate. The setup then decides
    /// with the window closed: no request now, the request after protection starts.
    func testClosingTheWindowDuringTheGateAsksAfterProtectionStarts() async {
        let gate = FirstRunContinueGate()
        var windowOpen = true
        XCTAssertTrue(FirstRunContinueGate.waits(stepDone: false, windowOpen: windowOpen, approved: false))
        let waiter = Task { @MainActor in await gate.wait() }

        windowOpen = false
        gate.open()
        await waiter.value

        XCTAssertEqual(
            request(notificationsDecided: false, skipped: false, windowOpen: windowOpen), .afterProtectionStarts)
    }

    /// "Skip" opens the notifications gate. The setup then asks neither now
    /// nor after protection starts.
    func testSkippingDuringTheGateNeverAsksDuringTheSetup() async {
        let gate = FirstRunContinueGate()
        var skipped = false
        XCTAssertTrue(FirstRunContinueGate.waits(stepDone: skipped, windowOpen: true, approved: false))
        let waiter = Task { @MainActor in await gate.wait() }

        skipped = true
        gate.open()
        await waiter.value

        XCTAssertEqual(request(notificationsDecided: false, skipped: skipped, windowOpen: true), .skipped)
    }

    private func request(
        notificationsDecided: Bool,
        skipped: Bool,
        windowOpen: Bool
    ) -> FirstRunNotificationWait.Request {
        FirstRunNotificationWait.request(
            notificationsDecided: notificationsDecided,
            skipped: skipped,
            windowOpen: windowOpen
        )
    }

    /// Stands in for a notification request the user never answers.
    private static func neverReturn() async {
        try? await Task.sleep(nanoseconds: 3_600 * 1_000_000_000)
    }
}
