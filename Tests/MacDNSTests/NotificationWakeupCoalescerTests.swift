// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import DNSProxyExtension

final class NotificationWakeupCoalescerTests: XCTestCase {

    func testFloodProducesBoundedEnqueues() {
        var enqueueCount = 0
        let coalescer = NotificationWakeupCoalescer { work in
            enqueueCount += 1
            work()
        }

        for _ in 0..<10_000 {
            coalescer.signal()
        }

        // Each signal completes its work synchronously here, so the coalescer
        // must enqueue exactly once per drained signal, never build a backlog.
        XCTAssertEqual(enqueueCount, 10_000)
        XCTAssertEqual(coalescer.pendingDepth, 0)
    }

    func testSignalsDuringExecutionCollapseIntoOnePendingRerun() {
        var pendingWork: [() -> Void] = []
        var ranCount = 0
        var coalescer: NotificationWakeupCoalescer!
        coalescer = NotificationWakeupCoalescer(
            enqueue: { work in pendingWork.append(work) },
            handler: {
                ranCount += 1
                if ranCount == 1 {
                    for _ in 0..<5_000 {
                        coalescer.signal()
                    }
                }
            }
        )

        coalescer.signal()
        XCTAssertEqual(pendingWork.count, 1)
        XCTAssertEqual(coalescer.pendingDepth, 1)

        pendingWork.removeFirst()()
        XCTAssertEqual(ranCount, 1)
        XCTAssertEqual(pendingWork.count, 1)
        XCTAssertEqual(coalescer.pendingDepth, 1)

        pendingWork.removeFirst()()
        XCTAssertEqual(ranCount, 2)
        XCTAssertEqual(coalescer.pendingDepth, 0)
    }

    func testCancelPreventsPendingWorkFromRunning() {
        var ranCount = 0
        var pendingWork: (() -> Void)?
        let coalescer = NotificationWakeupCoalescer(
            enqueue: { work in pendingWork = work },
            handler: { ranCount += 1 }
        )

        coalescer.signal()
        coalescer.cancel()
        pendingWork?()

        XCTAssertEqual(ranCount, 0)
        XCTAssertEqual(coalescer.pendingDepth, 0)
    }

    func testHandlerRunsForEachDrainedSignal() {
        var ranCount = 0
        let coalescer = NotificationWakeupCoalescer(
            enqueue: { work in work() },
            handler: { ranCount += 1 }
        )

        coalescer.signal()
        coalescer.signal()

        XCTAssertEqual(ranCount, 2)
    }

    func testSignalAfterCancelIsIgnored() {
        var enqueueCount = 0
        let coalescer = NotificationWakeupCoalescer { work in
            enqueueCount += 1
            work()
        }

        coalescer.cancel()
        coalescer.signal()

        XCTAssertEqual(enqueueCount, 0)
    }

    func testResetAllowsSignalsAfterProviderRestart() {
        var ranCount = 0
        let coalescer = NotificationWakeupCoalescer(
            enqueue: { work in work() },
            handler: { ranCount += 1 }
        )

        coalescer.cancel()
        coalescer.reset()
        coalescer.signal()

        XCTAssertEqual(ranCount, 1)
    }

    func testOldGenerationBlockCannotConsumeNewPendingRun() {
        var ranCount = 0
        var pendingWork: [() -> Void] = []
        let coalescer = NotificationWakeupCoalescer(
            enqueue: { work in pendingWork.append(work) },
            handler: { ranCount += 1 }
        )

        coalescer.signal()
        coalescer.cancel()
        coalescer.reset()
        coalescer.signal()

        XCTAssertEqual(pendingWork.count, 2)
        XCTAssertEqual(coalescer.pendingDepth, 1)

        pendingWork[0]()
        XCTAssertEqual(ranCount, 0)
        XCTAssertEqual(coalescer.pendingDepth, 1)

        pendingWork[1]()
        XCTAssertEqual(ranCount, 1)
        XCTAssertEqual(coalescer.pendingDepth, 0)
    }
}
