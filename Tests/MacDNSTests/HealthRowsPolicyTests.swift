// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import Shared
import XCTest

final class HealthRowsPolicyTests: XCTestCase {
    private func state(
        enabled: Bool = true, running: Bool = true, proxyOn: Bool = true,
        provider: ProviderInterceptionDisplayState = .intercepting
    ) -> ProtectionDisplayState {
        ProtectionDisplayState(
            isEnabled: enabled, servicesRunning: running, dnsProxyEnabled: proxyOn, providerState: provider)
    }

    /// Turning protection off leaves the last snapshot behind. With the DNS Proxy
    /// off, macOS sends the provider nothing, so the row must not say intercepting.
    func testInterceptionIsOffWhenTheDNSProxyIsOff() {
        let off = state(enabled: false, running: false, proxyOn: false, provider: .intercepting)
        XCTAssertEqual(HealthRowsPolicy.interception(off), .off)
    }

    func testInterceptionFollowsTheProviderWhileTheDNSProxyIsOn() {
        XCTAssertEqual(HealthRowsPolicy.interception(state(provider: .intercepting)), .intercepting)
        XCTAssertEqual(
            HealthRowsPolicy.interception(state(provider: .bypass(reason: "captive"))), .bypass(reason: "captive"))
        XCTAssertEqual(HealthRowsPolicy.interception(state(provider: .unknown)), .unknown)
    }

    func testResolverModeIsStoppedWhileTheResolverIsNotRunning() {
        XCTAssertEqual(
            HealthRowsPolicy.resolverMode(state(running: false), reported: "Encrypted"), "Stopped")
        XCTAssertEqual(
            HealthRowsPolicy.resolverMode(state(), reported: "Encrypted"), "Encrypted")
    }

    /// Turning protection off keeps the extension installed. It is not doing anything, so it
    /// must not read as active.
    func testSystemExtensionIsInstalledWhileTheDNSProxyIsOff() {
        XCTAssertEqual(
            HealthRowsPolicy.systemExtension(extensionActive: true, state(enabled: false, running: false, proxyOn: false)),
            .installed)
        XCTAssertEqual(HealthRowsPolicy.systemExtension(extensionActive: true, state()), .extensionActive)
        XCTAssertEqual(HealthRowsPolicy.systemExtension(extensionActive: false, state()), .inactive)
    }
}
