// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

final class ProtectionStatusPolicyTests: XCTestCase {
    private func state(
        isEnabled: Bool = true,
        servicesRunning: Bool = true,
        dnsProxyEnabled: Bool = true,
        providerState: ProviderInterceptionDisplayState = .intercepting,
        forwarding: Bool = false,
        captivePortalDetected: Bool = false
    ) -> ProtectionDisplayState {
        ProtectionDisplayState(
            isEnabled: isEnabled,
            servicesRunning: servicesRunning,
            dnsProxyEnabled: dnsProxyEnabled,
            providerState: providerState,
            forwarding: forwarding,
            captivePortalDetected: captivePortalDetected
        )
    }

    func testEnabledProxyInBypassCannotReportActive() {
        let bypassing = ProtectionStatusPolicy(
            state: state(providerState: .bypass(reason: "resolverNotReady"))
        )

        XCTAssertNotEqual(bypassing.statusMessage, "Active")
        XCTAssertEqual(bypassing.statusMessage, "Paused: getting ready")
        XCTAssertEqual(bypassing.headline, "Protection Inactive")
        XCTAssertFalse(bypassing.isProtectionActive)
        XCTAssertEqual(bypassing.iconName, "StatusOff")
    }

    func testEnabledProxyWithUnknownProviderCannotReportActive() {
        let unknown = ProtectionStatusPolicy(state: state(providerState: .unknown))

        XCTAssertNotEqual(unknown.statusMessage, "Active")
        XCTAssertEqual(unknown.statusMessage, "Protection state unknown")
        XCTAssertEqual(unknown.headline, "Protection Inactive")
        XCTAssertFalse(unknown.isProtectionActive)
    }

    func testForwardingReportsDegradedDespiteActiveInterception() {
        let forwarding = ProtectionStatusPolicy(state: state(forwarding: true))

        XCTAssertTrue(forwarding.isProtectionActive)
        XCTAssertNotEqual(forwarding.statusMessage, "Active")
        XCTAssertEqual(forwarding.statusMessage, "Using this network's DNS, unencrypted")
        XCTAssertEqual(forwarding.headline, "Limited Protection")
    }

    func testHeadlineAndStatusMessageNeverContradictEachOther() {
        let providerStates: [ProviderInterceptionDisplayState] = [
            .intercepting, .bypass(reason: "agentUnavailable"), .bypass(reason: nil),
            .unknown,
        ]
        for isEnabled in [true, false] {
            for servicesRunning in [true, false] {
                for dnsProxyEnabled in [true, false] {
                    for providerState in providerStates {
                        for forwarding in [true, false] {
                            for captive in [true, false] {
                                let policy = ProtectionStatusPolicy(
                                    state: state(
                                        isEnabled: isEnabled,
                                        servicesRunning: servicesRunning,
                                        dnsProxyEnabled: dnsProxyEnabled,
                                        providerState: providerState,
                                        forwarding: forwarding,
                                        captivePortalDetected: captive
                                    )
                                )
                                if policy.statusMessage == "Active" {
                                    XCTAssertEqual(
                                        policy.headline,
                                        "Protection Active",
                                        "\"Active\" must never accompany an inactive headline"
                                    )
                                    XCTAssertTrue(policy.isProtectionActive)
                                }
                                if policy.headline == "Protection Active" {
                                    XCTAssertEqual(policy.statusMessage, "Active")
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    func testActiveRequiresEveryLayer() {
        XCTAssertEqual(ProtectionStatusPolicy(state: state()).statusMessage, "Active")
        XCTAssertEqual(
            ProtectionStatusPolicy(state: state(isEnabled: false)).statusMessage,
            "Ready"
        )
        XCTAssertEqual(
            ProtectionStatusPolicy(state: state(servicesRunning: false)).statusMessage,
            "Starting..."
        )
        XCTAssertEqual(
            ProtectionStatusPolicy(state: state(dnsProxyEnabled: false)).statusMessage,
            "MacDNS isn't receiving lookups"
        )
        XCTAssertEqual(
            ProtectionStatusPolicy(state: state(captivePortalDetected: true))
                .statusMessage,
            "Paused for Wi-Fi sign-in"
        )
    }

    func testPauseReasonsReadAsPlainWords() {
        XCTAssertEqual(
            ProxyInterceptionReason.allCases.map { ProtectionStatusPolicy.pausedMessage(reason: $0.rawValue) },
            [
                "Paused: starting", "Paused: MacDNS service not running", "Paused: connecting to MacDNS",
                "Paused: getting ready", "Paused: self-check failed", "Paused: no network DNS",
                "Paused: stopping",
            ])
        XCTAssertEqual(ProtectionStatusPolicy.pausedMessage(reason: nil), "Paused: unknown reason")
        XCTAssertEqual(ProtectionStatusPolicy.pausedMessage(reason: "fromANewerExtension"), "Paused: unknown reason")
    }
}
