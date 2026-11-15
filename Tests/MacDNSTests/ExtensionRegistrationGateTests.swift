// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNS

/// Saving the DNS Proxy configuration raises the macOS 27 network filter
/// request, so the first-run window must be able to hold it. `ExtensionManager`
/// talks to the system extension framework and cannot run in a test process,
/// so the wiring is pinned here.
final class ExtensionRegistrationGateTests: XCTestCase {

    private let extensionManagerPath = "Sources/MacDNS/Services/ExtensionManager.swift"

    func testWaitingOnARequestInProgressRunsTheGateBeforeRegistering() throws {
        let body = try functionBody("func activate(", in: extensionManagerPath)
        let branch = try XCTUnwrap(body.range(of: "if extensionRequestInProgress {"))
        let wait = try XCTUnwrap(
            body.range(of: "try await waitForActivationCompletion()", range: branch.upperBound..<body.endIndex))
        let gate = try XCTUnwrap(
            body.range(of: "try await beforeRegistering?()", range: wait.upperBound..<body.endIndex),
            "the wait on a request in progress must run the gate"
        )
        let register = try XCTUnwrap(
            body.range(of: "try await registerProxyProvider()", range: wait.upperBound..<body.endIndex))
        let branchReturn = try XCTUnwrap(
            body.range(of: "return", range: wait.upperBound..<body.endIndex))
        XCTAssertLessThan(gate.lowerBound, register.lowerBound)
        XCTAssertLessThan(register.lowerBound, branchReturn.lowerBound)
    }

    func testANewRequestRunsTheGateBeforeRegistering() throws {
        let body = try functionBody("func activate(", in: extensionManagerPath)
        let submit = try XCTUnwrap(body.range(of: "self.submitActivationRequest(request)"))
        let gate = try XCTUnwrap(
            body.range(of: "try await beforeRegistering?()", range: submit.upperBound..<body.endIndex),
            "a new activation request must run the gate"
        )
        let register = try XCTUnwrap(
            body.range(of: "try await registerProxyProvider()", range: submit.upperBound..<body.endIndex))
        XCTAssertLessThan(gate.lowerBound, register.lowerBound)
    }

    func testTheGateIsOptionalForExistingCallers() throws {
        let body = try functionBody("func activate(", in: extensionManagerPath)
        XCTAssertTrue(
            body.hasPrefix("beforeRegistering: (@MainActor () async throws -> Void)? = nil) async throws {"))
    }

    func testACompletedRequestMarksTheExtensionActivatedAndHonoursTheDeferral() throws {
        let handler = try completedHandler()
        let activated = try XCTUnwrap(handler.range(of: "self.systemExtensionActivated = true"))
        let policy = try XCTUnwrap(handler.range(of: "ExtensionActivationCompletionPolicy("))
        XCTAssertLessThan(activated.lowerBound, policy.lowerBound)
        XCTAssertTrue(handler.contains("registrationDeferred: self.defersLateProviderRegistration"))
    }

    /// Uninstall deactivates the extension outside `ExtensionManager`. Every
    /// attempt resets the flag, so the first-run window never shows the
    /// extension step as done after it.
    func testRemoveAllResetsTheActivationAfterTheDNSProxyDeactivation() throws {
        let body = try functionBody("func performFullCleanup(")
        let deactivation = try XCTUnwrap(
            body.range(of: "deactivateSystemExtension(identifier: \"app.macdns.dnsproxy\")"))
        let reset = try XCTUnwrap(
            body.range(of: "extensionManager.markSystemExtensionDeactivated()"),
            "Uninstall must reset the activation flag"
        )
        let filterDeactivation = try XCTUnwrap(
            body.range(of: "deactivateSystemExtension(identifier: \"app.macdns.contentfilter\")"))
        XCTAssertLessThan(deactivation.lowerBound, reset.lowerBound)
        XCTAssertLessThan(reset.lowerBound, filterDeactivation.lowerBound)
        let afterCatch = try XCTUnwrap(
            body.range(of: "\n        }\n", range: deactivation.upperBound..<reset.lowerBound),
            "the reset must follow the whole do/catch so errors also reset"
        )
        XCTAssertFalse(body[afterCatch.upperBound..<reset.lowerBound].contains("}"))
    }

    private func completedHandler() throws -> String {
        let source = try sourceFile(extensionManagerPath)
        let start = try XCTUnwrap(source.range(of: "case .completed:"))
        let end = try XCTUnwrap(
            source.range(of: "case .willCompleteAfterReboot:", range: start.upperBound..<source.endIndex))
        return String(source[start.upperBound..<end.lowerBound])
    }

    private func functionBody(
        _ signature: String,
        in relativePath: String = "Sources/MacDNS/ViewModels/AppViewModel.swift"
    ) throws -> String {
        let source = try sourceFile(relativePath)
        let start = try XCTUnwrap(source.range(of: signature), "\(signature) not found in \(relativePath)")
        let remainder = source[start.upperBound...]
        guard let end = remainder.range(of: "\n    }") else { return String(remainder) }
        return String(remainder[..<end.lowerBound])
    }

    private func sourceFile(_ relativePath: String, from filePath: String = #filePath) throws -> String {
        var directory = URL(fileURLWithPath: filePath).deletingLastPathComponent()
        while directory.path != "/" {
            let candidate = directory.appendingPathComponent(relativePath)
            if FileManager.default.fileExists(atPath: candidate.path) {
                return try String(contentsOf: candidate, encoding: .utf8)
            }
            directory = directory.deletingLastPathComponent()
        }
        return try XCTUnwrap(nil as String?, "\(relativePath) not found above the test source path")
    }
}
