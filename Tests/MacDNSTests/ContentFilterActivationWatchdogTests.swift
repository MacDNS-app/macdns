// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import SystemExtensions
import XCTest

@testable import MacDNS

/// The Content Filter activation submission is watchdogged like the DNS Proxy
/// one: without it the submission's generation stays active forever, so a
/// callback arriving after the caller gave up is still applied.
final class ContentFilterActivationWatchdogTests: XCTestCase {

    @MainActor
    func testContentFilterSubmissionWithoutTerminalCallbackExpires() async {
        var failure: Error?
        let coordinator = ActivationRequestCoordinator(
            timeoutNanoseconds: 20_000_000,
            timeoutError: { FilterError.activationFailed("Content Filter approval timed out") },
            submit: { _ in }
        )
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: "app.macdns.contentfilter",
            queue: .main
        )

        coordinator.submitRequest(request) {
            failure = FilterError.activationFailed(FilterManager.activationTimeoutMessage)
        }
        try? await Task.sleep(nanoseconds: 300_000_000)

        XCTAssertTrue(failure is FilterError)
        XCTAssertEqual(
            failure?.localizedDescription,
            FilterError.activationFailed(FilterManager.activationTimeoutMessage).localizedDescription
        )
        // The expired generation is invalidated, so a late callback is ignored.
        XCTAssertFalse(coordinator.shouldApplyStatusUpdate(for: request))
        XCTAssertFalse(coordinator.shouldHandleCallback(for: request))
    }

    @MainActor
    func testContentFilterTimeoutIsDistinguishableFromTheProxyTimeout() {
        XCTAssertNotEqual(
            FilterManager.activationTimeoutMessage,
            ExtensionManager.activationTimeoutMessage
        )
        XCTAssertEqual(
            FilterError.activationFailed(FilterManager.activationTimeoutMessage).errorDescription,
            "Failed to activate Content Filter: \(FilterManager.activationTimeoutMessage)"
        )
    }
}
