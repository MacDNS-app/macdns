// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import SwiftUI
import XCTest

@testable import MacDNS

@MainActor
final class QueriesRefreshTests: XCTestCase {
    func testRetainedSettingsWindowStopsHistoryRequestsWhenClosedAndResumesOnReopen() async throws {
        let app = NSApplication.shared
        let previousPolicy = app.activationPolicy()
        app.setActivationPolicy(.accessory)
        app.finishLaunching()
        defer { app.setActivationPolicy(previousPolicy) }
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 200, height: 100),
            styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.identifier = NSUserInterfaceItemIdentifier("com_apple_SwiftUI_Settings_window")
        defer { window.close() }

        var requests: [Bool] = []
        func page(_ key: Int, interval: Duration?) -> some View {
            Text("Queries")
                .frame(width: 200, height: 100)
                .background {
                    QueriesRefreshTasks(reloadKey: key, interval: interval) { automatic in
                        requests.append(automatic)
                    }
                }
        }
        let host = NSHostingView(rootView: page(1, interval: .milliseconds(50)))
        window.contentView = host

        window.orderFrontRegardless()
        try await waitUntil { requests.contains(true) }
        XCTAssertEqual(requests.first, false)

        window.close()
        try await waitUntil { !window.occlusionState.contains(.visible) }
        let countOnClose = requests.count
        try await Task.sleep(for: .milliseconds(300))
        XCTAssertEqual(requests.count, countOnClose)

        window.orderFrontRegardless()
        try await waitUntil { requests.count >= countOnClose + 2 }
        XCTAssertTrue(requests.dropFirst(countOnClose).allSatisfy { $0 }, "Reopening keeps older log pages")

        host.rootView = page(2, interval: nil)
        try await waitUntil { requests.filter { !$0 }.count == 2 }
        let countAfterZoom = requests.count
        try await Task.sleep(for: .milliseconds(200))
        XCTAssertEqual(requests.count, countAfterZoom, "A zoomed range loads once")
    }

    private func waitUntil(
        file: StaticString = #filePath, line: UInt = #line, _ condition: () -> Bool
    ) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now + .seconds(3)
        while !condition(), clock.now < deadline {
            // swift test has no NSApplication.run() to deliver WindowServer occlusion events.
            while let event = NSApp.nextEvent(matching: .any, until: .distantPast, inMode: .default, dequeue: true) {
                NSApp.sendEvent(event)
            }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertTrue(condition(), file: file, line: line)
    }
}
