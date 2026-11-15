// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

final class ProtectionDisplayStateTests: XCTestCase {
    func testProtectionIsNotActiveWhenResolverRunsWithoutDNSProxy() {
        let state = ProtectionDisplayState(
            isEnabled: true,
            servicesRunning: true,
            dnsProxyEnabled: false,
            providerState: .unknown
        )

        XCTAssertFalse(state.isProtectionActive)
        XCTAssertEqual(state.headline, "Protection Inactive")
    }

    func testProtectionIsNotActiveWhenProxyEnabledButProviderBypassing() {
        // Manager enabled but the provider retained bypass: must not read Active.
        let state = ProtectionDisplayState(
            isEnabled: true,
            servicesRunning: true,
            dnsProxyEnabled: true,
            providerState: .bypass(reason: "agentUnavailable")
        )

        XCTAssertFalse(state.isProtectionActive)
        XCTAssertEqual(state.headline, "Protection Inactive")
    }

    func testProtectionIsActiveOnlyWhenProviderIsIntercepting() {
        let state = ProtectionDisplayState(
            isEnabled: true,
            servicesRunning: true,
            dnsProxyEnabled: true,
            providerState: .intercepting
        )

        XCTAssertTrue(state.isProtectionActive)
        XCTAssertEqual(state.headline, "Protection Active")
    }

    func testStatusIconReflectsProtectionStateInsteadOfEnabledIntent() {
        XCTAssertEqual(
            ProtectionDisplayState(
                isEnabled: true, servicesRunning: true, dnsProxyEnabled: false,
                providerState: .unknown
            ).iconName,
            "StatusOff"
        )
        XCTAssertEqual(
            ProtectionDisplayState(
                isEnabled: true, servicesRunning: true, dnsProxyEnabled: true,
                providerState: .intercepting
            ).iconName,
            "StatusOn"
        )
    }
}
