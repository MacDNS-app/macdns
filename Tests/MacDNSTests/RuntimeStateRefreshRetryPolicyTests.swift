// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class RuntimeStateRefreshRetryPolicyTests: XCTestCase {
    func testProbeRecoveryAfterThirtySixSecondsIsObservedWithoutAnotherWake() {
        var retry = RuntimeStateRefreshRetryPolicy()
        var elapsed: UInt64 = 0
        var refreshes = 0
        var state = runtimeState(providerState: "bypass", reason: "probeFailed")

        while let delay = nextDelay(&retry, state: state) {
            elapsed += delay
            refreshes += 1
            state =
                elapsed >= 36_000_000_000
                ? runtimeState(providerState: "intercepting")
                : runtimeState(providerState: "bypass", reason: "probeFailed")
        }

        XCTAssertEqual(refreshes, 6)
        XCTAssertEqual(elapsed, 47_000_000_000)
        XCTAssertEqual(
            RuntimeStatePresentationPolicy.presentation(for: state).providerState,
            .intercepting
        )
    }

    func testUnreadableRuntimeExhaustsItsBudgetInsteadOfPollingForever() {
        var retry = RuntimeStateRefreshRetryPolicy()
        var delays: [UInt64] = []

        for _ in 0..<20 {
            guard let delay = nextDelay(&retry, state: nil) else { break }
            delays.append(delay)
        }

        XCTAssertEqual(
            delays,
            [
                1_000_000_000, 2_000_000_000, 4_000_000_000,
                8_000_000_000, 16_000_000_000, 16_000_000_000,
            ]
        )
        XCTAssertNil(nextDelay(&retry, state: nil))
    }

    func testMissingOrUnknownProviderReportRequiresAnotherAuthoritativeSnapshot() {
        for providerState: String? in [nil, "unknown", "unexpected"] {
            var retry = RuntimeStateRefreshRetryPolicy()
            XCTAssertNotNil(nextDelay(&retry, state: runtimeState(providerState: providerState)))
        }
    }

    func testStartupAndSessionRecoveryAreObservedWithoutAnotherWake() {
        var retry = RuntimeStateRefreshRetryPolicy()
        let states = [
            runtimeState(providerState: "bypass", reason: "starting"),
            runtimeState(providerState: "bypass", reason: "sessionUnavailable"),
            runtimeState(providerState: "bypass", reason: "resolverNotReady"),
            runtimeState(providerState: "intercepting"),
        ]
        var observedStates = [states[0]]
        var elapsed: UInt64 = 0

        for state in states.dropFirst() {
            guard let delay = nextDelay(&retry, state: observedStates.last) else { break }
            elapsed += delay
            observedStates.append(state)
        }

        XCTAssertEqual(observedStates.count, 4)
        XCTAssertEqual(elapsed, 7_000_000_000)
        XCTAssertEqual(observedStates.last?.proxyInterceptionState, "intercepting")
        XCTAssertNil(nextDelay(&retry, state: observedStates.last))
    }

    func testUnavailableAndUnrecognizedBypassReasonsAreRetried() {
        let reasons: [String?] = [
            "agentUnavailable", "dnsDestinationsUnavailable", nil, "unexpected",
        ]

        for reason in reasons {
            var retry = RuntimeStateRefreshRetryPolicy()
            let state = runtimeState(providerState: "bypass", reason: reason)

            XCTAssertEqual(nextDelay(&retry, state: state), 1_000_000_000)
        }
    }

    func testStableInterceptionAndIntentionalBypassStopRetries() {
        let stableStates = [
            runtimeState(providerState: "intercepting"),
            runtimeState(providerState: "bypass", reason: "stopping"),
            runtimeState(providerState: "bypass", reason: "probeFailed", running: false),
            runtimeState(providerState: "bypass", reason: "probeFailed", captive: true),
        ]

        for state in stableStates {
            var retry = RuntimeStateRefreshRetryPolicy()
            XCTAssertNil(nextDelay(&retry, state: state))
        }
    }

    func testPersistentTransitionCannotRenewTheRetryBudget() {
        var retry = RuntimeStateRefreshRetryPolicy()
        let state = runtimeState(providerState: nil, running: false, transitioning: true)
        var refreshes = 0

        for _ in 0..<20 {
            guard nextDelay(&retry, state: state) != nil else { break }
            refreshes += 1
        }

        XCTAssertEqual(refreshes, 6)
        XCTAssertNil(nextDelay(&retry, state: state))
    }

    func testStopUpdateAndStaleGenerationPreventRetriesWithoutSpendingBudget() {
        var retry = RuntimeStateRefreshRetryPolicy()

        XCTAssertNil(nextDelay(&retry, state: nil, desired: false))
        XCTAssertNil(nextDelay(&retry, state: nil, stopping: true))
        XCTAssertNil(nextDelay(&retry, state: nil, updating: true))
        XCTAssertNil(nextDelay(&retry, state: nil, current: false))
        XCTAssertEqual(nextDelay(&retry, state: nil), 1_000_000_000)
    }

    func testFreshForegroundRequestCanRetryAfterAnExhaustedCycle() {
        var retry = RuntimeStateRefreshRetryPolicy()
        for _ in 0..<6 {
            XCTAssertNotNil(nextDelay(&retry, state: nil))
        }
        XCTAssertNil(nextDelay(&retry, state: nil))

        retry.reset()

        XCTAssertEqual(nextDelay(&retry, state: nil), 1_000_000_000)
    }

    private func nextDelay(
        _ retry: inout RuntimeStateRefreshRetryPolicy,
        state: AgentRuntimeState?,
        desired: Bool = true,
        stopping: Bool = false,
        updating: Bool = false,
        current: Bool = true
    ) -> UInt64? {
        retry.nextDelay(
            for: state,
            runtimeDNSDesired: desired,
            isStoppingDNS: stopping,
            softwareUpdateSuspended: updating,
            generationsAreCurrent: current
        )
    }

    private func runtimeState(
        providerState: String?,
        reason: String? = nil,
        running: Bool = true,
        captive: Bool = false,
        transitioning: Bool = false
    ) -> AgentRuntimeState {
        AgentRuntimeState(
            servicesRunning: running,
            captivePortalDetected: captive,
            forwarding: false,
            lifecycleGeneration: 1,
            transitionInProgress: transitioning,
            proxyInterceptionState: providerState,
            proxyInterceptionReason: reason,
            proxyProviderVersion: "1.0.0",
            proxyControlUnreachable: false
        )
    }
}
