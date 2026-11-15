// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class ServiceWakeReconciliationPolicyTests: XCTestCase {
    func testEnablesProxyOnlyFromAuthoritativeRunningState() {
        let policy = ServiceWakeReconciliationPolicy(
            runtimeState: AgentRuntimeState(
                servicesRunning: true,
                captivePortalDetected: false,
                forwarding: false
            ),
            runtimeDNSDesired: true,
            isStoppingDNS: false,
            capturedWakeGeneration: 7,
            currentWakeGeneration: 7,
            capturedLifecycleGeneration: 4,
            currentLifecycleGeneration: 4,
            authoritativeProxyEnabled: false,
            authoritativeFilterEnabled: false,
            shouldKeepContentFilterEnabled: true,
            persistedStateAvailability: .loaded
        )

        XCTAssertTrue(policy.shouldApply)
        XCTAssertTrue(policy.shouldEnableProxy)
        XCTAssertEqual(policy.proxyAction, .enable)
        XCTAssertEqual(policy.contentFilterAction, .enable)
    }

    func testDisablesProxyForStoppedCaptiveOrUndesiredState() {
        XCTAssertFalse(policy(servicesRunning: false).shouldEnableProxy)
        XCTAssertFalse(policy(captivePortalDetected: true).shouldEnableProxy)
        XCTAssertFalse(policy(runtimeDNSDesired: false).shouldEnableProxy)
        XCTAssertFalse(policy(isStoppingDNS: true).shouldEnableProxy)
    }

    func testForwardingRemainsAUsableResolverPath() {
        let policy = policy(forwarding: true, proxyInterceptionState: "intercepting")

        XCTAssertTrue(policy.shouldEnableProxy)
        XCTAssertEqual(
            policy.resolverModeText,
            "This network's DNS"
        )
    }

    func testStaleLifecycleGenerationCannotApply() {
        let policy = policy(
            capturedLifecycleGeneration: 3,
            currentLifecycleGeneration: 4
        )

        XCTAssertFalse(policy.shouldApply)
        XCTAssertFalse(policy.shouldEnableProxy)
    }

    func testNewWakeGenerationInvalidatesEarlierXPCResponse() {
        let policy = policy(
            capturedWakeGeneration: 8,
            currentWakeGeneration: 9
        )

        XCTAssertFalse(policy.shouldApply)
        XCTAssertNil(policy.agentRespondingUpdate(forXPCSucceeded: true))
    }

    func testStaleXPCErrorDoesNotChangeAgentResponding() {
        let policy = policy(
            capturedWakeGeneration: 8,
            currentWakeGeneration: 9
        )

        XCTAssertNil(policy.agentRespondingUpdate(forXPCSucceeded: false))
    }

    func testStaleRefreshCannotProduceExtensionSideEffects() {
        let policy = policy(
            runtimeDNSDesired: false,
            capturedWakeGeneration: 8,
            currentWakeGeneration: 9,
            authoritativeProxyEnabled: true,
            authoritativeFilterEnabled: true,
            shouldKeepContentFilterEnabled: false
        )

        XCTAssertEqual(policy.proxyAction, .none)
        XCTAssertEqual(policy.contentFilterAction, .none)
    }

    func testAuthoritativeExtensionStatesDetermineActions() {
        let enablePolicy = policy(
            authoritativeProxyEnabled: false,
            authoritativeFilterEnabled: false,
            shouldKeepContentFilterEnabled: true
        )
        XCTAssertEqual(enablePolicy.proxyAction, .enable)
        XCTAssertEqual(enablePolicy.contentFilterAction, .enable)

        let filterEnablePolicy = policy(
            authoritativeProxyEnabled: true,
            authoritativeFilterEnabled: false,
            shouldKeepContentFilterEnabled: true
        )
        XCTAssertEqual(filterEnablePolicy.proxyAction, .none)
        XCTAssertEqual(filterEnablePolicy.contentFilterAction, .enable)

        let proxyEnablePolicy = policy(
            authoritativeProxyEnabled: false,
            authoritativeFilterEnabled: true,
            shouldKeepContentFilterEnabled: true
        )
        XCTAssertEqual(proxyEnablePolicy.proxyAction, .enable)
        XCTAssertEqual(proxyEnablePolicy.contentFilterAction, .none)

        let noOpPolicy = policy(
            authoritativeProxyEnabled: true,
            authoritativeFilterEnabled: true,
            shouldKeepContentFilterEnabled: true
        )
        XCTAssertEqual(noOpPolicy.proxyAction, .none)
        XCTAssertEqual(noOpPolicy.contentFilterAction, .none)

        let disablePolicy = policy(
            runtimeDNSDesired: false,
            authoritativeProxyEnabled: true,
            authoritativeFilterEnabled: true,
            shouldKeepContentFilterEnabled: false
        )
        XCTAssertEqual(disablePolicy.proxyAction, .disable)
        XCTAssertEqual(disablePolicy.contentFilterAction, .disable)
    }

    func testTransitionSnapshotCannotApply() {
        let policy = policy(transitionInProgress: true)

        XCTAssertFalse(policy.shouldApply)
        XCTAssertFalse(policy.shouldEnableProxy)
        XCTAssertEqual(policy.proxyAction, .none)
        XCTAssertEqual(policy.contentFilterAction, .none)
    }

    func testLoadedStateStopsUnexpectedRunningResolver() {
        let policy = policy(runtimeDNSDesired: false)

        XCTAssertTrue(policy.shouldStopUnexpectedResolver)
    }

    func testUnknownPersistedStateDoesNotApplyLifecycleReconciliation() {
        for availability: PersistedStateAvailability in [
            .loading,
            .unavailable,
            .invalidConfiguration,
        ] {
            let policy = policy(
                runtimeDNSDesired: false,
                authoritativeProxyEnabled: true,
                authoritativeFilterEnabled: true,
                shouldKeepContentFilterEnabled: false,
                persistedStateAvailability: availability
            )

            XCTAssertFalse(policy.shouldApply)
            XCTAssertFalse(policy.shouldEnableProxy)
            XCTAssertFalse(policy.shouldStopUnexpectedResolver)
            XCTAssertEqual(policy.proxyAction, .none)
            XCTAssertEqual(policy.contentFilterAction, .none)
        }
    }

    func testResolverModeReflectsProviderInterceptionState() {
        XCTAssertEqual(
            policy(proxyInterceptionState: "intercepting").resolverModeText,
            "Encrypted"
        )
        XCTAssertEqual(
            policy(forwarding: true, proxyInterceptionState: "intercepting").resolverModeText,
            "This network's DNS"
        )
        XCTAssertEqual(
            policy(proxyInterceptionState: "bypass", proxyInterceptionReason: "probeFailed")
                .resolverModeText,
            "Paused: self-check failed"
        )
        // Absent provider state (old Agent / provider unreachable) → unknown.
        XCTAssertEqual(
            policy().resolverModeText,
            "Protection state unknown"
        )
    }

    func testWakeupGateCoalescesSignalsWhileAdvancingGeneration() {
        let gate = ServiceWakeupGate()
        let countLock = NSLock()
        var acceptedSignals = 0

        DispatchQueue.concurrentPerform(iterations: 1_000) { _ in
            if gate.begin() {
                countLock.withLock { acceptedSignals += 1 }
            }
        }

        XCTAssertEqual(acceptedSignals, 1)
        XCTAssertEqual(gate.currentGeneration, 1_000)
        gate.complete()
        XCTAssertTrue(gate.begin())
        XCTAssertEqual(gate.currentGeneration, 1_001)
        XCTAssertEqual(gate.advanceGeneration(), 1_002)
    }

    private func policy(
        servicesRunning: Bool = true,
        captivePortalDetected: Bool = false,
        forwarding: Bool = false,
        transitionInProgress: Bool = false,
        runtimeDNSDesired: Bool = true,
        isStoppingDNS: Bool = false,
        capturedWakeGeneration: UInt64 = 1,
        currentWakeGeneration: UInt64 = 1,
        capturedLifecycleGeneration: UInt64 = 1,
        currentLifecycleGeneration: UInt64 = 1,
        authoritativeProxyEnabled: Bool = false,
        authoritativeFilterEnabled: Bool = false,
        shouldKeepContentFilterEnabled: Bool = true,
        persistedStateAvailability: PersistedStateAvailability = .loaded,
        proxyInterceptionState: String? = nil,
        proxyInterceptionReason: String? = nil
    ) -> ServiceWakeReconciliationPolicy {
        ServiceWakeReconciliationPolicy(
            runtimeState: AgentRuntimeState(
                servicesRunning: servicesRunning,
                captivePortalDetected: captivePortalDetected,
                forwarding: forwarding,
                transitionInProgress: transitionInProgress,
                proxyInterceptionState: proxyInterceptionState,
                proxyInterceptionReason: proxyInterceptionReason
            ),
            runtimeDNSDesired: runtimeDNSDesired,
            isStoppingDNS: isStoppingDNS,
            capturedWakeGeneration: capturedWakeGeneration,
            currentWakeGeneration: currentWakeGeneration,
            capturedLifecycleGeneration: capturedLifecycleGeneration,
            currentLifecycleGeneration: currentLifecycleGeneration,
            authoritativeProxyEnabled: authoritativeProxyEnabled,
            authoritativeFilterEnabled: authoritativeFilterEnabled,
            shouldKeepContentFilterEnabled: shouldKeepContentFilterEnabled,
            persistedStateAvailability: persistedStateAvailability
        )
    }
}
