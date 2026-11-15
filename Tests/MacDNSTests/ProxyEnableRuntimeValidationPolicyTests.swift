// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

@testable import MacDNS

final class ProxyEnableRuntimeValidationPolicyTests: XCTestCase {

    private func snapshot(
        servicesRunning: Bool = true,
        captivePortalDetected: Bool = false,
        forwarding: Bool = false,
        lifecycleGeneration: UInt64 = 12,
        transitionInProgress: Bool = false
    ) -> AgentRuntimeState {
        AgentRuntimeState(
            servicesRunning: servicesRunning,
            captivePortalDetected: captivePortalDetected,
            forwarding: forwarding,
            lifecycleGeneration: lifecycleGeneration,
            transitionInProgress: transitionInProgress
        )
    }

    private func keepsProxy(
        postEnable: AgentRuntimeState?,
        expectedAgentLifecycleGeneration: UInt64 = 12,
        appLifecycleIsCurrent: Bool = true,
        runtimeDNSDesired: Bool = true,
        isStopping: Bool = false
    ) -> Bool {
        ProxyEnableRuntimeValidationPolicy.shouldKeepProxyEnabled(
            postEnableRuntimeState: postEnable,
            expectedAgentLifecycleGeneration: expectedAgentLifecycleGeneration,
            appLifecycleIsCurrent: appLifecycleIsCurrent,
            runtimeDNSDesired: runtimeDNSDesired,
            isStopping: isStopping
        )
    }

    func testKeepsProxyWhenNothingChanged() {
        XCTAssertTrue(keepsProxy(postEnable: snapshot()))
    }

    func testDoesNotStartProxyEnableWithoutAuthoritativeRuntimeState() {
        XCTAssertFalse(
            ProxyEnableRuntimeValidationPolicy.canStartProxyEnable(
                preEnableRuntimeState: nil,
                appLifecycleIsCurrent: true,
                runtimeDNSDesired: true,
                isStopping: false
            )
        )
    }

    func testRejectedEnableRollsBackOnlyWithinSameAppLifecycle() {
        XCTAssertTrue(
            ProxyEnableRuntimeValidationPolicy.shouldRollbackRejectedEnable(
                attemptLifecycleGeneration: 12,
                currentLifecycleGeneration: 12
            )
        )
        XCTAssertFalse(
            ProxyEnableRuntimeValidationPolicy.shouldRollbackRejectedEnable(
                attemptLifecycleGeneration: 12,
                currentLifecycleGeneration: 13
            )
        )
    }

    func testRollsBackWhenAgentLifecycleGenerationAdvanced() {
        XCTAssertFalse(
            keepsProxy(postEnable: snapshot(lifecycleGeneration: 13))
        )
    }

    func testRollsBackWhenAgentIsTransitioning() {
        XCTAssertFalse(
            keepsProxy(postEnable: snapshot(transitionInProgress: true))
        )
    }

    func testRollsBackWhenResolverStoppedDuringEnable() {
        XCTAssertFalse(keepsProxy(postEnable: snapshot(servicesRunning: false)))
    }

    func testRollsBackWhenCaptiveBypassBecameActive() {
        XCTAssertFalse(
            keepsProxy(postEnable: snapshot(captivePortalDetected: true))
        )
    }

    func testRollsBackWhenRuntimeStateIsUnavailable() {
        XCTAssertFalse(keepsProxy(postEnable: nil))
    }

    func testRollsBackWhenAppLifecycleAdvanced() {
        XCTAssertFalse(
            keepsProxy(postEnable: snapshot(), appLifecycleIsCurrent: false)
        )
    }

    func testRollsBackWhenUserNoLongerWantsDNS() {
        XCTAssertFalse(
            keepsProxy(postEnable: snapshot(), runtimeDNSDesired: false)
        )
    }

    func testRollsBackWhileAppIsStopping() {
        XCTAssertFalse(keepsProxy(postEnable: snapshot(), isStopping: true))
    }
}
