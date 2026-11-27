// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import Shared
import SwiftUI
import XCTest

@testable import MacDNS

@MainActor
final class ActivityRefreshTests: XCTestCase {
    private final class RowsModel: ObservableObject {
        @Published var stats: [BlockedDomain]

        init(stats: [BlockedDomain]) {
            self.stats = stats
        }
    }

    private struct RowsHost: View {
        @ObservedObject var model: RowsModel

        var body: some View {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    ActivityBlockedDomainList(
                        stats: model.stats,
                        canAllow: true,
                        onAllow: { _ in }
                    )
                }
            }
            .frame(width: 600, height: 400)
        }
    }

    private var window: NSWindow?

    override func tearDown() {
        window?.close()
        window = nil
        super.tearDown()
    }

    /// Rebuilding `BlockedDomain` on every refresh produces new `UUID`s.
    /// Keying rows by `domain` keeps AppKit subviews alive across refreshes
    /// instead of tearing down and leaking `NSKeyValueDependency` entries.
    func testActivityRowsReuseAppKitSubviewsWhenBlockedDomainsGetFreshUUIDs() {
        let domains = (0..<12).map { "tracker-\($0).example.com" }
        let model = RowsModel(
            stats: domains.enumerated().map { idx, domain in
                BlockedDomain(domain: domain, category: .adsTracking, blockCount: 100 - idx)
            }
        )

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 600, height: 400),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: RowsHost(model: model))
        window.orderFrontRegardless()
        self.window = window
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))

        let initialSubviews = Set(Self.descendantViews(in: window.contentView!).map(ObjectIdentifier.init))
        XCTAssertGreaterThanOrEqual(initialSubviews.count, domains.count)

        for tick in 1...5 {
            model.stats = domains.enumerated().map { idx, domain in
                BlockedDomain(
                    domain: domain,
                    category: .adsTracking,
                    blockCount: 100 - idx + tick
                )
            }
            RunLoop.main.run(until: Date().addingTimeInterval(0.1))

            let currentSubviews = Set(Self.descendantViews(in: window.contentView!).map(ObjectIdentifier.init))
            XCTAssertEqual(
                currentSubviews, initialSubviews,
                "tick \(tick) recreated row AppKit subviews instead of updating them in place"
            )
        }
    }

    func testActivityRefreshSuspendsWhenSettingsWindowClosesAndResumesOnReopen() async throws {
        let app = NSApplication.shared
        let previousPolicy = app.activationPolicy()
        app.setActivationPolicy(.accessory)
        app.finishLaunching()
        defer { app.setActivationPolicy(previousPolicy) }

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 200, height: 100),
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.identifier = NSUserInterfaceItemIdentifier("com_apple_SwiftUI_Settings_window")
        self.window = window

        var refreshes: [Bool] = []
        func page(range: QueryHistoryRange, clears: Int) -> some View {
            Text("Blocked")
                .frame(width: 200, height: 100)
                .background {
                    QueriesRefreshTasks(
                        reloadKey: ActivitySection.ReloadKey(range: range, clears: clears),
                        interval: .milliseconds(50)
                    ) { automatic in
                        refreshes.append(automatic)
                    }
                }
        }
        let host = NSHostingView(rootView: page(range: .day, clears: 0))
        window.contentView = host

        window.orderFrontRegardless()
        try await waitUntil { refreshes.contains(true) }
        XCTAssertEqual(refreshes.first, false)

        window.close()
        try await waitUntil { !window.occlusionState.contains(.visible) }
        let countOnClose = refreshes.count
        try await Task.sleep(for: .milliseconds(250))
        XCTAssertEqual(refreshes.count, countOnClose, "Closed Settings window must not keep polling")

        window.orderFrontRegardless()
        try await waitUntil { refreshes.count >= countOnClose + 2 }
        XCTAssertTrue(refreshes.dropFirst(countOnClose).allSatisfy { $0 })

        let manualBefore = refreshes.filter { !$0 }.count
        host.rootView = page(range: .week, clears: 0)
        try await waitUntil { refreshes.filter { !$0 }.count == manualBefore + 1 }

        // Drain the close occlusion event before the next test shares SettingsWindowController.shared.
        window.close()
        try await waitUntil { !SettingsWindowController.shared.isOnScreen }
        self.window = nil
    }

    func testAutomaticRefreshSkipsSpinnerAndUnchangedPayloadsWhileManualRefreshSupersedes() throws {
        var state = ActivityStatsRefreshState()

        // Automatic refresh stays quiet and blocks overlapping automatic ticks.
        let autoGen = try XCTUnwrap(state.begin(isAutomatic: true))
        XCTAssertFalse(state.isLoading)
        XCTAssertNil(state.begin(isAutomatic: true))

        // First payload populates rows.
        let first = [
            BlockedDomain(domain: "ads.example", matchedRule: "example", category: .adsTracking, blockCount: 5)
        ]
        XCTAssertTrue(state.finish(.loaded(first), for: autoGen))
        XCTAssertEqual(state.domains.map(\.domain), ["ads.example"])
        XCTAssertNil(state.issue)

        // Same displayed content with a fresh UUID must not report a change.
        let secondAuto = try XCTUnwrap(state.begin(isAutomatic: true))
        let sameWithNewUUID = [
            BlockedDomain(domain: "ads.example", matchedRule: "example", category: .adsTracking, blockCount: 5)
        ]
        XCTAssertNotEqual(first[0].id, sameWithNewUUID[0].id)
        XCTAssertFalse(state.finish(.loaded(sameWithNewUUID), for: secondAuto))
        XCTAssertEqual(state.domains[0].id, first[0].id)

        // Manual refresh shows the spinner and supersedes an in-flight automatic load.
        let supersededAuto = try XCTUnwrap(state.begin(isAutomatic: true))
        let manualGen = try XCTUnwrap(state.begin(isAutomatic: false))
        XCTAssertTrue(state.isLoading)

        let stalePayload = [
            BlockedDomain(domain: "stale.example", matchedRule: "stale.example", category: .adsTracking, blockCount: 1)
        ]
        XCTAssertFalse(state.finish(.loaded(stalePayload), for: supersededAuto))
        XCTAssertTrue(state.isLoading, "Stale generation must not clear an in-flight manual load")
        XCTAssertEqual(state.domains.map(\.domain), ["ads.example"])

        let updated = [
            BlockedDomain(domain: "ads.example", matchedRule: "example", category: .adsTracking, blockCount: 8)
        ]
        XCTAssertTrue(state.finish(.loaded(updated), for: manualGen))
        XCTAssertFalse(state.isLoading)
        XCTAssertEqual(state.domains.map(\.blockCount), [8])

        // Error/disabled responses clear rows and publish the issue, then recover cleanly.
        let issueGen = try XCTUnwrap(state.begin(isAutomatic: true))
        XCTAssertTrue(state.finish(.disabled, for: issueGen))
        XCTAssertTrue(state.domains.isEmpty)
        XCTAssertEqual(state.issue, .disabled)

        let recoverGen = try XCTUnwrap(state.begin(isAutomatic: true))
        XCTAssertTrue(state.finish(.loaded(updated), for: recoverGen))
        XCTAssertEqual(state.domains.map(\.domain), ["ads.example"])
        XCTAssertNil(state.issue)
    }

    private static func descendantViews(in view: NSView) -> [NSView] {
        var result: [NSView] = [view]
        for subview in view.subviews {
            result.append(contentsOf: descendantViews(in: subview))
        }
        return result
    }

    private func waitUntil(
        file: StaticString = #filePath, line: UInt = #line, _ condition: () -> Bool
    ) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now + .seconds(3)
        while !condition(), clock.now < deadline {
            while let event = NSApp.nextEvent(matching: .any, until: .distantPast, inMode: .default, dequeue: true) {
                NSApp.sendEvent(event)
            }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertTrue(condition(), file: file, line: line)
    }
}
