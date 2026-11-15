// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import XCTest

@testable import MacDNSAgent

private final class RecordingWakeDelegate: SystemWakeMonitorDelegate {
    private let lock = NSLock()
    private(set) var generations: [UInt64] = []
    var onWake: (() -> Void)?

    func systemDidWake(callbackLifecycleGeneration: UInt64) {
        lock.withLock { generations.append(callbackLifecycleGeneration) }
        onWake?()
    }

    var recordedGenerations: [UInt64] {
        lock.withLock { generations }
    }
}

final class SystemWakeMonitorTests: XCTestCase {
    func testWakeBurstIsCoalescedIntoOneCurrentRecheck() {
        let center = NotificationCenter()
        let monitor = SystemWakeMonitor(
            notificationCenter: center,
            debounceDelay: 0.02
        )
        let delegate = RecordingWakeDelegate()
        let delivered = expectation(description: "wake delivered")
        delegate.onWake = { delivered.fulfill() }
        monitor.delegate = delegate
        monitor.start(callbackLifecycleGeneration: 7)
        defer { monitor.stop() }

        for _ in 0..<5 {
            center.post(name: NSWorkspace.didWakeNotification, object: nil)
        }

        wait(for: [delivered], timeout: 1.0)
        XCTAssertEqual(delegate.recordedGenerations, [7])
    }

    func testRebindRejectsPendingWakeFromPreviousLifecycle() {
        let center = NotificationCenter()
        let monitor = SystemWakeMonitor(
            notificationCenter: center,
            debounceDelay: 0.05
        )
        let delegate = RecordingWakeDelegate()
        monitor.delegate = delegate
        monitor.start(callbackLifecycleGeneration: 7)
        defer { monitor.stop() }

        center.post(name: NSWorkspace.didWakeNotification, object: nil)
        monitor.start(callbackLifecycleGeneration: 8)

        let staleWindow = expectation(description: "stale wake window elapsed")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            staleWindow.fulfill()
        }
        wait(for: [staleWindow], timeout: 1.0)
        XCTAssertTrue(delegate.recordedGenerations.isEmpty)
    }

    func testStopRemovesObserverAndPendingDelivery() {
        let center = NotificationCenter()
        let monitor = SystemWakeMonitor(
            notificationCenter: center,
            debounceDelay: 0.05
        )
        let delegate = RecordingWakeDelegate()
        monitor.delegate = delegate
        monitor.start(callbackLifecycleGeneration: 7)

        center.post(name: NSWorkspace.didWakeNotification, object: nil)
        monitor.stop()
        center.post(name: NSWorkspace.didWakeNotification, object: nil)

        let stoppedWindow = expectation(description: "stopped wake window elapsed")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            stoppedWindow.fulfill()
        }
        wait(for: [stoppedWindow], timeout: 1.0)
        XCTAssertTrue(delegate.recordedGenerations.isEmpty)
    }
}
