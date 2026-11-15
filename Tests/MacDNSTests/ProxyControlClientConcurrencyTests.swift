// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent
@testable import Shared

/// Reproduces the hand-off shape of `currentProviderStateReport`: the bounded
/// wait times out, then a late XPC reply writes the result slot while the caller
/// is reading it. Run under Thread Sanitizer this reports the race on an
/// unprotected `var result: ProxyControlStateReport?` and is clean once the slot
/// is lock-protected.
final class ProxyControlClientConcurrencyTests: XCTestCase {
    private let waitTimeout: TimeInterval = 0.01

    private func report(_ index: Int) -> ProxyControlStateReport {
        ProxyControlStateReport(
            state: "bypass", reason: "probeFailed", providerVersion: "\(index)")
    }

    func testLateReplyDoesNotRaceThePostTimeoutRead() {
        for index in 0..<100 {
            let box = ProxyControlStateReportBox()
            let semaphore = DispatchSemaphore(value: 0)
            let expected = report(index)
            let replyReady = DispatchSemaphore(value: 0)
            let waitExpired = DispatchSemaphore(value: 0)

            // The reply is held back until the bounded wait has already expired,
            // then lands concurrently with the caller's read of the slot.
            DispatchQueue.global().async {
                replyReady.signal()
                waitExpired.wait()
                box.store(expected)
                semaphore.signal()
            }
            XCTAssertEqual(replyReady.wait(timeout: .now() + 5), .success)

            XCTAssertEqual(
                semaphore.wait(timeout: .now() + waitTimeout), .timedOut,
                "the reply must still be outstanding when the bounded wait expires")
            waitExpired.signal()
            if let observed = box.value {
                XCTAssertEqual(observed, expected)
            }

            XCTAssertEqual(semaphore.wait(timeout: .now() + 5), .success)
            XCTAssertEqual(box.value, expected)
        }
    }

    func testConcurrentStoresAndReadsKeepTheSlotConsistent() {
        let box = ProxyControlStateReportBox()
        let expected = report(7)
        let writers = DispatchQueue(label: "writers", attributes: .concurrent)
        let group = DispatchGroup()

        for _ in 0..<8 {
            group.enter()
            writers.async {
                for _ in 0..<500 {
                    box.store(expected)
                    box.store(nil)
                }
                group.leave()
            }
        }
        for _ in 0..<4 {
            group.enter()
            writers.async {
                for _ in 0..<500 {
                    if let observed = box.value {
                        XCTAssertEqual(observed, expected)
                    }
                }
                group.leave()
            }
        }

        XCTAssertEqual(group.wait(timeout: .now() + 30), .success)
    }

    func testTimedOutWaitReturnsWhateverIsStoredWithoutBlocking() {
        let box = ProxyControlStateReportBox()
        let semaphore = DispatchSemaphore(value: 0)

        // Nothing ever signals: the caller must fall through on the timeout.
        XCTAssertEqual(semaphore.wait(timeout: .now() + waitTimeout), .timedOut)
        XCTAssertNil(box.value)

        box.store(report(1))
        XCTAssertEqual(box.value, report(1))
    }
}
