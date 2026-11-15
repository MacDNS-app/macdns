// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import XCTest

final class DNSProxyRegistrationPolicyTests: XCTestCase {
    func testProxyRegistrationStartsDisabledUntilResolverIsRunning() {
        let policy = DNSProxyRegistrationPolicy()

        XCTAssertFalse(policy.shouldEnableProxyDuringRegistration)
    }

    func testLateRegistrationCanPreserveExistingEnabledProxy() {
        let policy = DNSProxyRegistrationPolicy(
            preserveExistingEnabledState: true,
            existingProxyEnabled: true
        )

        XCTAssertTrue(policy.shouldEnableProxyDuringRegistration)
    }

    func testStartOrderDisablesStaleProxyBeforeResolverStarts() {
        let policy = DNSProxyStartOrderPolicy(dnsProxyEnabledBeforeResolverStart: true)

        XCTAssertTrue(policy.shouldDisableProxyBeforeResolverStart)
    }

    /// With nothing saved, macOS 27 loads an empty provider protocol with no
    /// provider bundle identifier. A fresh install must not count as configured,
    /// or the first-run window never shows.
    func testEmptyProviderProtocolIsNotAConfiguration() {
        XCTAssertFalse(DNSProxyConfigurationPolicy.isConfigured(providerBundleIdentifier: nil))
        XCTAssertFalse(DNSProxyConfigurationPolicy.isConfigured(providerBundleIdentifier: ""))
    }

    func testOnlyTheMacDNSProviderCountsAsConfigured() {
        XCTAssertTrue(DNSProxyConfigurationPolicy.isConfigured(providerBundleIdentifier: "app.macdns.dnsproxy"))
        XCTAssertFalse(DNSProxyConfigurationPolicy.isConfigured(providerBundleIdentifier: "com.example.dnsproxy"))
    }
}
