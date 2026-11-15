// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import DNSProxyExtension

final class ProviderStartWatchdogTests: XCTestCase {

    private func makeQueue() -> DispatchQueue {
        DispatchQueue(label: "app.macdns.tests.provider-start-watchdog")
    }

    func testTerminatesWhenNoProxyStartArrives() {
        let watchdog = ProviderStartWatchdog()
        let terminated = expectation(description: "terminate")

        watchdog.arm(deadline: 0.05, queue: makeQueue()) { terminated.fulfill() }

        wait(for: [terminated], timeout: 2)
    }

    func testDoesNotTerminateWhenProxyStartedBeforeDeadline() {
        let watchdog = ProviderStartWatchdog()
        let terminated = expectation(description: "terminate")
        terminated.isInverted = true
        let queue = makeQueue()

        watchdog.arm(deadline: 0.2, queue: queue) { terminated.fulfill() }
        queue.asyncAfter(deadline: .now() + 0.05) { watchdog.noteProxyStarted() }

        wait(for: [terminated], timeout: 1)
        XCTAssertTrue(watchdog.hasStartedProxy)
    }

    func testStartIsRecordedOnceAndSticks() {
        let watchdog = ProviderStartWatchdog()
        XCTAssertFalse(watchdog.hasStartedProxy)

        watchdog.noteProxyStarted()
        watchdog.noteProxyStarted()

        XCTAssertTrue(watchdog.hasStartedProxy)
    }

    func testDeadlineIsShorterThanTheReplacementDrainTimeout() {
        // The provider must release its launchd job while the App's replacement
        // drain is still waiting, otherwise the drain times out and submits the
        // replacement against a job that still owns the proxy-control endpoint.
        XCTAssertLessThan(ProviderStartWatchdog.defaultDeadline, 30)
    }
}
