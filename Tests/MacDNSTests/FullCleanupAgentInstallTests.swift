// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNS

/// Uninstall can start while the first-run trial step or an Enable is still
/// registering the Agent. An install that finishes after the uninstall
/// registers the Agent again, so the cleanup waits for it first, as quit
/// does. `AppViewModel` cannot be instantiated in a test process, so the
/// wiring is pinned here.
final class FullCleanupAgentInstallTests: XCTestCase {

    func testFullCleanupWaitsForARunningAgentInstallBeforeUninstalling() throws {
        let body = try performFullCleanupBody()
        let wait = try XCTUnwrap(
            body.range(of: "await runningAgentInstall?.value"),
            "performFullCleanup must wait for a running Agent install"
        )
        let uninstall = try XCTUnwrap(
            body.range(of: "agentInstaller.uninstall()"),
            "performFullCleanup no longer uninstalls the Agent"
        )
        XCTAssertLessThan(wait.lowerBound, uninstall.lowerBound)
    }

    func testFullCleanupMarksTheServicesRemoved() throws {
        XCTAssertTrue(
            try performFullCleanupBody().contains("servicesRemoved = true"),
            "Uninstall must keep the first-run exit from registering the Agent again"
        )
    }

    /// The runtime snapshot is refreshed only while protection is wanted, so a
    /// stop that kept it would show the provider intercepting while it is off,
    /// and a later Enable would start from that stale state.
    func testStopPathsDropTheProviderSnapshot() throws {
        for signature in ["func disableDNS(", "func performFullCleanup("] {
            XCTAssertTrue(
                try functionBody(signature).contains("invalidateProviderStateAfterUnreadableRuntimeState()"),
                "\(signature) must drop the provider snapshot"
            )
        }
    }

    /// No API revokes the notification permission, so Uninstall at least
    /// removes every notification MacDNS delivered or scheduled.
    func testFullCleanupRemovesTheAppNotifications() throws {
        let body = try performFullCleanupBody()
        XCTAssertTrue(body.contains("removeAllPendingNotificationRequests()"))
        XCTAssertTrue(body.contains("removeAllDeliveredNotifications()"))
    }

    /// Closing the window or clicking Enable queues the install behind a
    /// Uninstall that already passed its wait. The install must not start
    /// while services stop.
    func testNoAgentInstallStartsWhileServicesStop() throws {
        let body = try functionBody("private func installAgent(")
        let refusal = try XCTUnwrap(
            body.range(of: "guard !isStoppingDNS else { throw AgentError.servicesStopping }"),
            "installAgent must refuse to start while services stop"
        )
        let start = try XCTUnwrap(body.range(of: "performAgentInstall()"))
        XCTAssertLessThan(refusal.lowerBound, start.lowerBound)
    }

    /// A restart or restore that registers the Agent while the replacement
    /// unregisters it would leave the old binary registered. Joining an install
    /// in flight would skip the unregistration, so the replacement waits for
    /// it and then runs as one serialized install.
    func testAgentReplacementUnregistersInsideTheInstallSerializer() throws {
        let body = try functionBody("private func replaceRegisteredAgent(")
        let wait = try XCTUnwrap(
            body.range(of: "while let running = agentInstallSerializer.running"),
            "replaceRegisteredAgent must wait for a running Agent install"
        )
        let serialized = try XCTUnwrap(
            body.range(of: "agentInstallSerializer.run"),
            "replaceRegisteredAgent must run inside the install serializer"
        )
        let uninstall = try XCTUnwrap(body.range(of: "agentInstaller.uninstall()"))
        let install = try XCTUnwrap(body.range(of: "agentInstaller.install()"))
        XCTAssertLessThan(wait.lowerBound, serialized.lowerBound)
        XCTAssertLessThan(serialized.lowerBound, uninstall.lowerBound)
        XCTAssertLessThan(uninstall.lowerBound, install.lowerBound)
    }

    /// An exit trial step queued before Uninstall runs after it began.
    func testQueuedExitTrialStepSkipsAfterARemoval() throws {
        let body = try functionBody("func dismissFirstRun(")
        let skip = try XCTUnwrap(
            body.range(of: "guard !servicesRemovalRequested, !servicesRemoved else"),
            "dismissFirstRun must skip once services were removed"
        )
        let step = try XCTUnwrap(body.range(of: "makeFirstRunTrialStep("))
        XCTAssertLessThan(skip.lowerBound, step.lowerBound)
    }

    private func performFullCleanupBody() throws -> String {
        try functionBody("func performFullCleanup(")
    }

    private func functionBody(_ signature: String, from filePath: String = #filePath) throws -> String {
        var directory = URL(fileURLWithPath: filePath).deletingLastPathComponent()
        var contents: String?
        while directory.path != "/" {
            let candidate = directory.appendingPathComponent("Sources/MacDNS/ViewModels/AppViewModel.swift")
            if FileManager.default.fileExists(atPath: candidate.path) {
                contents = try String(contentsOf: candidate, encoding: .utf8)
                break
            }
            directory = directory.deletingLastPathComponent()
        }
        let source = try XCTUnwrap(contents, "AppViewModel.swift not found above the test source path")
        let start = try XCTUnwrap(
            source.range(of: signature),
            "\(signature) not found in AppViewModel.swift"
        )
        let remainder = source[start.upperBound...]
        guard let end = remainder.range(of: "\n    }") else { return String(remainder) }
        return String(remainder[..<end.lowerBound])
    }
}
