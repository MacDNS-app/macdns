// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import DNSProxyExtension

final class ProxyDescriptorLifecycleTests: XCTestCase {
    private final class CloseRecorder {
        private let lock = NSLock()
        private(set) var closedDescriptors: [Int32] = []
        private(set) var events: [String] = []

        func recordClose(_ fd: Int32) {
            lock.withLock {
                closedDescriptors.append(fd)
                events.append("close")
            }
        }

        func recordOnClosed() {
            lock.withLock { events.append("onClosed") }
        }

        var onClosedCount: Int {
            lock.withLock { events.filter { $0 == "onClosed" }.count }
        }
    }

    private func makeLifecycle(fd: Int32 = 42) -> (ProxyDescriptorLifecycle, CloseRecorder) {
        let recorder = CloseRecorder()
        let lifecycle = ProxyDescriptorLifecycle(
            fd: fd,
            closeDescriptor: { recorder.recordClose($0) },
            onClosed: { recorder.recordOnClosed() })
        return (lifecycle, recorder)
    }

    func testCloseWithoutSourcesHappensImmediately() {
        let (lifecycle, recorder) = makeLifecycle(fd: 7)

        lifecycle.requestClose()

        XCTAssertEqual(recorder.closedDescriptors, [7])
        XCTAssertEqual(recorder.onClosedCount, 1)
    }

    func testCloseWaitsForEverySourceToCancel() {
        let (lifecycle, recorder) = makeLifecycle()
        lifecycle.addSource()
        lifecycle.addSource()

        lifecycle.requestClose()
        XCTAssertTrue(recorder.closedDescriptors.isEmpty)

        lifecycle.sourceCancelled()
        XCTAssertTrue(recorder.closedDescriptors.isEmpty)
        XCTAssertEqual(recorder.onClosedCount, 0)

        lifecycle.sourceCancelled()
        XCTAssertEqual(recorder.closedDescriptors, [42])
        XCTAssertEqual(recorder.onClosedCount, 1)
    }

    func testCancelledSourceWithoutCloseRequestKeepsDescriptorOpen() {
        let (lifecycle, recorder) = makeLifecycle()
        lifecycle.addSource()

        lifecycle.sourceCancelled()

        XCTAssertTrue(recorder.closedDescriptors.isEmpty)
        XCTAssertEqual(recorder.onClosedCount, 0)
    }

    func testRepeatedCloseRequestsCloseAndNotifyExactlyOnce() {
        let (lifecycle, recorder) = makeLifecycle()
        lifecycle.addSource()

        lifecycle.requestClose()
        lifecycle.sourceCancelled()
        lifecycle.requestClose()
        lifecycle.requestClose()

        XCTAssertEqual(recorder.closedDescriptors, [42])
        XCTAssertEqual(recorder.onClosedCount, 1)
    }

    func testOnClosedRunsAfterTheDescriptorIsClosed() {
        let (lifecycle, recorder) = makeLifecycle()

        lifecycle.requestClose()

        XCTAssertEqual(recorder.events, ["close", "onClosed"])
    }

    func testConcurrentCloseRequestsAndCancellationsCloseExactlyOnce() {
        let (lifecycle, recorder) = makeLifecycle()
        let sourceCount = 8
        for _ in 0..<sourceCount { lifecycle.addSource() }

        DispatchQueue.concurrentPerform(iterations: sourceCount * 2) { index in
            if index < sourceCount {
                lifecycle.sourceCancelled()
            } else {
                lifecycle.requestClose()
            }
        }

        XCTAssertEqual(recorder.closedDescriptors, [42])
        XCTAssertEqual(recorder.onClosedCount, 1)
    }
}
