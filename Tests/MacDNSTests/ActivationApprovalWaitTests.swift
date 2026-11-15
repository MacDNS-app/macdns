// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import SystemExtensions
import XCTest

@testable import MacDNS

/// A request that macOS reports as waiting for user approval is still alive, so
/// neither the request watchdog nor the caller's timeout may abandon it.
@MainActor
final class ActivationApprovalWaitTests: XCTestCase {

    private struct TimeoutError: Error {}

    private func makeCoordinator() -> ActivationRequestCoordinator {
        ActivationRequestCoordinator(
            timeoutNanoseconds: 20_000_000,
            timeoutError: { TimeoutError() },
            submit: { _ in }
        )
    }

    private func makeRequest() -> OSSystemExtensionRequest {
        OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: "app.macdns.dnsproxy",
            queue: .main
        )
    }

    func testApprovalPendingRequestDoesNotExpire() async {
        let coordinator = makeCoordinator()
        let request = makeRequest()
        var timedOut = false

        coordinator.submitRequest(request) { timedOut = true }
        coordinator.markAwaitingApproval(request)
        try? await Task.sleep(nanoseconds: 300_000_000)

        XCTAssertFalse(timedOut)
        XCTAssertTrue(coordinator.shouldHandleCallback(for: request))
    }

    func testCallerTimeoutKeepsAnApprovalPendingRequestInProgress() async {
        let coordinator = makeCoordinator()
        let request = makeRequest()
        var becameIdle = false

        do {
            try await coordinator.waitForCompletion(
                submitRequest: {
                    coordinator.submitRequest(request) {}
                    coordinator.markAwaitingApproval(request)
                },
                onIdle: { becameIdle = true }
            )
            XCTFail("The caller's wait should time out")
        } catch {
            XCTAssertTrue(error is TimeoutError)
        }

        XCTAssertFalse(becameIdle)
        XCTAssertTrue(coordinator.isAwaitingApproval)
    }

    func testTerminalCallbackEndsTheApprovalWait() {
        let coordinator = makeCoordinator()
        let request = makeRequest()

        coordinator.submitRequest(request) {}
        coordinator.markAwaitingApproval(request)
        XCTAssertTrue(coordinator.isAwaitingApproval)

        XCTAssertTrue(coordinator.shouldHandleCallback(for: request))
        XCTAssertFalse(coordinator.isAwaitingApproval)
    }

    func testRequestWithoutApprovalStillExpires() async {
        let coordinator = makeCoordinator()
        let request = makeRequest()
        var timedOut = false

        coordinator.submitRequest(request) { timedOut = true }
        try? await Task.sleep(nanoseconds: 300_000_000)

        XCTAssertTrue(timedOut)
        XCTAssertFalse(coordinator.shouldHandleCallback(for: request))
    }

    func testMarkingAStaleRequestDoesNothing() async {
        let coordinator = makeCoordinator()
        let staleRequest = makeRequest()
        let activeRequest = makeRequest()
        var activeTimedOut = false

        coordinator.submitRequest(staleRequest) {}
        coordinator.submitRequest(activeRequest) { activeTimedOut = true }
        coordinator.markAwaitingApproval(staleRequest)

        XCTAssertFalse(coordinator.isAwaitingApproval)
        try? await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertTrue(activeTimedOut)
    }

    // MARK: - A drained proxy comes back while the request waits for approval

    func testDrainResubmissionAwaitingApprovalRestoresTheProxyOnce() {
        var generation = ReplacementDrainGenerationPolicy()
        var recovery = ReplacementDrainRecoveryPolicy()
        let token = generation.begin()
        recovery.reenableProxyAfterReplacement = true
        XCTAssertTrue(generation.markDrained(token))

        // The resubmitted request reaches the approval stage.
        XCTAssertTrue(
            ReplacementDrainApprovalPolicy(drainState: generation.state, recovery: recovery)
                .shouldRestoreProxy
        )
        generation.closeActive()
        XCTAssertEqual(recovery.recordRestoreResult(.succeeded), .restored)

        // A repeated approval report or the later terminal callback finds
        // nothing left to re-enable.
        XCTAssertFalse(
            ReplacementDrainApprovalPolicy(drainState: generation.state, recovery: recovery)
                .shouldRestoreProxy
        )
        XCTAssertFalse(recovery.shouldReenableProxy)
    }

    func testDrainStillWaitingOnTheOldProviderIsNotRestoredAtApproval() {
        var generation = ReplacementDrainGenerationPolicy()
        var recovery = ReplacementDrainRecoveryPolicy()
        _ = generation.begin()
        recovery.reenableProxyAfterReplacement = true

        XCTAssertFalse(
            ReplacementDrainApprovalPolicy(drainState: generation.state, recovery: recovery)
                .shouldRestoreProxy
        )
    }

    func testApprovalWithoutADrainRestoresNothing() {
        XCTAssertFalse(
            ReplacementDrainApprovalPolicy(drainState: .idle, recovery: ReplacementDrainRecoveryPolicy())
                .shouldRestoreProxy
        )
    }

    func testApprovalAfterASupersededDrainRestoresItsPendingIntent() {
        var recovery = ReplacementDrainRecoveryPolicy()
        recovery.reenableProxyAfterReplacement = true

        XCTAssertTrue(
            ReplacementDrainApprovalPolicy(drainState: .idle, recovery: recovery).shouldRestoreProxy
        )
    }
}
