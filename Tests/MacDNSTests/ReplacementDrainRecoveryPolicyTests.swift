// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import SystemExtensions
import XCTest

@testable import MacDNS

final class ReplacementDrainRecoveryPolicyTests: XCTestCase {

    // MARK: - Intent survives a failed restore

    func testRestoreFailureKeepsRecoveryPendingAndSurfacesFailure() {
        var recovery = ReplacementDrainRecoveryPolicy()
        recovery.reenableProxyAfterReplacement = true

        let outcome = recovery.recordRestoreResult(.failed("DNS Proxy remained disabled"))

        XCTAssertEqual(outcome, .restoreFailed("DNS Proxy remained disabled"))
        XCTAssertTrue(recovery.shouldReenableProxy)
        XCTAssertTrue(recovery.reenableProxyAfterReplacement)

        // A later reconciliation retries and only then is the intent cleared.
        XCTAssertEqual(recovery.recordRestoreResult(.succeeded), .restored)
        XCTAssertFalse(recovery.shouldReenableProxy)
    }

    func testEnableRequestedDuringDrainSurvivesFailedRestore() {
        var recovery = ReplacementDrainRecoveryPolicy()
        recovery.enableRequestedDuringDrain = true

        XCTAssertEqual(recovery.recordRestoreResult(.failed("boom")), .restoreFailed("boom"))
        XCTAssertTrue(recovery.enableRequestedDuringDrain)
        XCTAssertTrue(recovery.shouldReenableProxy)
    }

    func testNoIntentMeansNothingToRestore() {
        let recovery = ReplacementDrainRecoveryPolicy()
        XCTAssertFalse(recovery.shouldReenableProxy)
    }

    // MARK: - The resubmitted activation is watchdogged

    func testResubmittedActivationTimeoutRestoresIdleAndReenableIntent() {
        var generation = ReplacementDrainGenerationPolicy()
        var recovery = ReplacementDrainRecoveryPolicy()

        // Drain disables the proxy, waits out the old provider, resubmits.
        let token = generation.begin()
        recovery.reenableProxyAfterReplacement = true
        XCTAssertTrue(generation.markDrained(token))

        // The resubmitted activation never answers, so the watchdog expires.
        generation.closeActive()

        XCTAssertEqual(generation.state, .idle)
        XCTAssertFalse(generation.isActive)
        XCTAssertTrue(recovery.shouldReenableProxy)
        XCTAssertEqual(recovery.recordRestoreResult(.succeeded), .restored)
        XCTAssertFalse(recovery.shouldReenableProxy)
    }

    @MainActor
    func testSubmittedRequestWithoutTerminalCallbackFiresWatchdog() async {
        let expired = Expectation()
        let coordinator = ActivationRequestCoordinator(
            timeoutNanoseconds: 20_000_000,
            timeoutError: { ExtensionError.activationFailed("timed out") },
            submit: { _ in }
        )
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: "app.macdns.dnsproxy",
            queue: .main
        )

        coordinator.submitRequest(request) { expired.fulfill() }
        await Self.settle()

        XCTAssertTrue(expired.isFulfilled)
        // The expired generation is invalidated, so a late callback is ignored.
        XCTAssertFalse(coordinator.shouldApplyStatusUpdate(for: request))
        XCTAssertFalse(coordinator.shouldHandleCallback(for: request))
    }

    @MainActor
    func testTerminalCallbackCancelsTheWatchdog() async {
        let expired = Expectation()
        let coordinator = ActivationRequestCoordinator(
            timeoutNanoseconds: 20_000_000,
            timeoutError: { ExtensionError.activationFailed("timed out") },
            submit: { _ in }
        )
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: "app.macdns.dnsproxy",
            queue: .main
        )

        coordinator.submitRequest(request) { expired.fulfill() }
        XCTAssertTrue(coordinator.shouldHandleCallback(for: request))
        await Self.settle()

        XCTAssertFalse(expired.isFulfilled)
    }

    // MARK: - Every drain outcome reaches App reconciliation

    func testEveryTerminalDrainOutcomeRequestsReconciliation() {
        var reasons: Set<String> = []

        for outcome in ReplacementDrainOutcome.everyOutcome {
            let policy = ReplacementDrainReconciliationPolicy(outcome: outcome)
            XCTAssertTrue(
                policy.shouldScheduleReconciliation,
                "\(outcome) would leave the Content Filter off until a lossy Darwin wake"
            )
            reasons.insert(policy.reason)
        }

        XCTAssertEqual(
            Set(ReplacementDrainOutcome.everyOutcome.map(\.kind)),
            Set(ReplacementDrainOutcome.Kind.allCases),
            "every outcome case needs an instance in everyOutcome"
        )
        XCTAssertEqual(reasons.count, ReplacementDrainOutcome.Kind.allCases.count)
    }

    private static func settle() async {
        try? await Task.sleep(nanoseconds: 300_000_000)
    }
}

/// Test-side mirror of `ReplacementDrainOutcome`. A new outcome case breaks the
/// `kind` switch at compile time and then fails the coverage assertion until an
/// instance is listed in `everyOutcome`, so no outcome can silently skip
/// reconciliation.
extension ReplacementDrainOutcome {
    enum Kind: Hashable, CaseIterable {
        case nothingToRestore
        case restored
        case restoreFailed
        case superseded
    }

    static let everyOutcome: [ReplacementDrainOutcome] = [
        .nothingToRestore,
        .restored,
        .restoreFailed("DNS Proxy remained disabled"),
        .superseded,
    ]

    var kind: Kind {
        switch self {
        case .nothingToRestore: return .nothingToRestore
        case .restored: return .restored
        case .restoreFailed: return .restoreFailed
        case .superseded: return .superseded
        }
    }
}

private final class Expectation {
    private(set) var isFulfilled = false
    func fulfill() { isFulfilled = true }
}
