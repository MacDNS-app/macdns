// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS
@testable import Shared

final class RuntimeStatePresentationPolicyTests: XCTestCase {
    private func runtimeState(
        forwarding: Bool = false,
        proxyInterceptionState: String? = "intercepting",
        proxyInterceptionReason: String? = nil
    ) -> AgentRuntimeState {
        AgentRuntimeState(
            servicesRunning: true,
            captivePortalDetected: false,
            forwarding: forwarding,
            proxyInterceptionState: proxyInterceptionState,
            proxyInterceptionReason: proxyInterceptionReason
        )
    }

    func testXPCFailureInvalidatesPreviouslyInterceptingState() {
        let intercepting = RuntimeStatePresentationPolicy.presentation(
            for: runtimeState()
        )
        XCTAssertEqual(intercepting.providerState, .intercepting)

        let unreadable = RuntimeStatePresentationPolicy.unavailable

        XCTAssertEqual(unreadable.providerState, .unknown)
        XCTAssertFalse(unreadable.forwarding)
        XCTAssertEqual(unreadable.resolverMode, "Protection state unknown")

        // The provider view is invalidated without inferring that the resolver
        // stopped: servicesRunning is not part of this presentation at all.
        let displayed = ProtectionDisplayState(
            isEnabled: true,
            servicesRunning: true,
            dnsProxyEnabled: true,
            providerState: unreadable.providerState,
            forwarding: unreadable.forwarding
        )
        XCTAssertTrue(displayed.servicesRunning)
        XCTAssertFalse(displayed.providerIntercepting)
        XCTAssertNotEqual(displayed.statusPolicy.statusMessage, "Active")
    }

    func testBypassPresentationCarriesReason() {
        let presentation = RuntimeStatePresentationPolicy.presentation(
            for: runtimeState(
                proxyInterceptionState: "bypass",
                proxyInterceptionReason: "resolverNotReady"
            )
        )

        XCTAssertEqual(presentation.providerState, .bypass(reason: "resolverNotReady"))
        XCTAssertEqual(presentation.resolverMode, "Paused: getting ready")
    }

    func testMissingInterceptionStateIsUnknownNotIntercepting() {
        let presentation = RuntimeStatePresentationPolicy.presentation(
            for: runtimeState(proxyInterceptionState: nil)
        )

        XCTAssertEqual(presentation.providerState, .unknown)
        XCTAssertEqual(presentation.resolverMode, "Protection state unknown")
    }

    func testForwardingInterceptionIsReportedAsForwardingMode() {
        let presentation = RuntimeStatePresentationPolicy.presentation(
            for: runtimeState(forwarding: true)
        )

        XCTAssertEqual(presentation.providerState, .intercepting)
        XCTAssertTrue(presentation.forwarding)
        XCTAssertEqual(
            presentation.resolverMode,
            "This network's DNS"
        )
    }
}
