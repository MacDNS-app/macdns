// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import OSLog
import SwiftUI
import XCTest

@testable import MacDNS

/// Clicks the segmented control AppKit draws and reads this process's log,
/// because the defect is a SwiftUI runtime issue, not a wrong value.
@MainActor
final class SegmentedPickerTests: XCTestCase {
    private final class Model: ObservableObject {
        @Published var value = 0
    }

    private struct Host: View {
        @ObservedObject var model: Model
        let useSegmentedPicker: Bool

        var body: some View {
            if useSegmentedPicker {
                SegmentedPicker("Value", selection: $model.value) { segments }
            } else {
                Picker("Value", selection: $model.value) { segments }
                    .pickerStyle(.segmented)
            }
        }

        private var segments: some View {
            ForEach(0..<3, id: \.self) { Text("S\($0)").tag($0) }
        }
    }

    private static let runtimeIssue = "Publishing changes from within view updates"

    private var window: NSWindow?

    override func tearDown() {
        window?.close()
        window = nil
        super.tearDown()
    }

    private func spin() {
        RunLoop.main.run(until: Date().addingTimeInterval(0.3))
    }

    private func host(_ model: Model, useSegmentedPicker: Bool) throws -> NSSegmentedControl {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 300, height: 80), styleMask: [.titled],
            backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: Host(model: model, useSegmentedPicker: useSegmentedPicker))
        window.orderFrontRegardless()
        self.window = window
        spin()
        return try XCTUnwrap(Self.segmentedControl(in: window.contentView!), "no segmented control was drawn")
    }

    private static func segmentedControl(in view: NSView) -> NSSegmentedControl? {
        if let control = view as? NSSegmentedControl { return control }
        return view.subviews.lazy.compactMap { segmentedControl(in: $0) }.first
    }

    /// What AppKit does when a click ends on a segment.
    private func click(_ control: NSSegmentedControl, segment: Int) {
        control.selectedSegment = segment
        control.sendAction(control.action, to: control.target)
        spin()
    }

    private func runtimeIssues(since start: Date) throws -> [String] {
        let store = try OSLogStore(scope: .currentProcessIdentifier)
        return try store.getEntries(at: store.position(date: start))
            .compactMap { $0 as? OSLogEntryLog }
            .map(\.composedMessage)
            .filter { $0.contains(Self.runtimeIssue) }
    }

    func testClickingASegmentUpdatesThePublishedValueOutsideTheViewUpdate() throws {
        let model = Model()
        let control = try host(model, useSegmentedPicker: true)
        let start = Date()

        click(control, segment: 2)
        click(control, segment: 1)

        XCTAssertEqual(model.value, 1)
        XCTAssertEqual(try runtimeIssues(since: start), [])
    }

    func testAChangeFromTheModelMovesTheSelectedSegment() throws {
        let model = Model()
        let control = try host(model, useSegmentedPicker: true)

        model.value = 2
        spin()

        XCTAssertEqual(control.selectedSegment, 2)
    }

    /// Guards the guard: the plain segmented Picker must still trip the
    /// runtime issue here, or the test above would pass for the wrong reason.
    func testThePlainSegmentedPickerStillPublishesInsideTheViewUpdate() throws {
        let model = Model()
        let control = try host(model, useSegmentedPicker: false)
        let start = Date()

        click(control, segment: 2)

        XCTAssertEqual(model.value, 2)
        XCTAssertFalse(try runtimeIssues(since: start).isEmpty)
    }
}
