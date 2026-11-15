// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

@testable import MacDNS

final class ContentFilterActivationPolicyTests: XCTestCase {
    func testKeepsFilterEnabledOnlyWhenDNSProtectionIsFullyActive() {
        XCTAssertTrue(
            ContentFilterActivationPolicy(
                blockDohDotEnabled: true,
                isEnabled: true,
                servicesRunning: true,
                dnsProxyEnabled: true,
                captiveMode: .none,
                licenseValid: true
            ).shouldKeepEnabled
        )
    }

    func testDoesNotKeepFilterEnabledWhenDNSProxyIsInactive() {
        XCTAssertFalse(
            ContentFilterActivationPolicy(
                blockDohDotEnabled: true,
                isEnabled: true,
                servicesRunning: true,
                dnsProxyEnabled: false,
                captiveMode: .none,
                licenseValid: true
            ).shouldKeepEnabled
        )
    }

    func testDoesNotKeepFilterEnabledWhenResolverIsStopped() {
        XCTAssertFalse(
            ContentFilterActivationPolicy(
                blockDohDotEnabled: true,
                isEnabled: true,
                servicesRunning: false,
                dnsProxyEnabled: true,
                captiveMode: .none,
                licenseValid: true
            ).shouldKeepEnabled
        )
    }

    func testDoesNotKeepFilterEnabledDuringApprovedBypassOrInvalidLicense() {
        XCTAssertFalse(
            ContentFilterActivationPolicy(
                blockDohDotEnabled: true,
                isEnabled: true,
                servicesRunning: true,
                dnsProxyEnabled: true,
                captiveMode: .approvedFullBypass,
                licenseValid: true
            ).shouldKeepEnabled
        )

        XCTAssertFalse(
            ContentFilterActivationPolicy(
                blockDohDotEnabled: true,
                isEnabled: true,
                servicesRunning: true,
                dnsProxyEnabled: true,
                captiveMode: .none,
                licenseValid: false
            ).shouldKeepEnabled
        )
    }

    /// The constrained captive-compatibility mode still routes every query
    /// through the DNS Proxy, so DoH/DoT must stay blocked. Only an explicitly
    /// approved full bypass may switch the Content Filter off.
    func testCaptiveCompatibilityRetainsDoHDoTBlocking() {
        XCTAssertTrue(
            ContentFilterActivationPolicy(
                blockDohDotEnabled: true,
                isEnabled: true,
                servicesRunning: true,
                dnsProxyEnabled: true,
                captiveMode: .scopedForwarding,
                licenseValid: true,
                filterEnabled: true
            ).shouldKeepEnabled
        )
        XCTAssertFalse(
            ContentFilterActivationPolicy(
                blockDohDotEnabled: true,
                isEnabled: true,
                servicesRunning: true,
                dnsProxyEnabled: true,
                captiveMode: .scopedForwarding,
                licenseValid: true,
                filterEnabled: true
            ).shouldDisableEnabledFilter
        )
    }

    func testDisablesEnabledFilterWhenDNSProtectionIsNotActive() {
        XCTAssertTrue(
            ContentFilterActivationPolicy(
                blockDohDotEnabled: true,
                isEnabled: true,
                servicesRunning: true,
                dnsProxyEnabled: false,
                captiveMode: .none,
                licenseValid: true,
                filterEnabled: true
            ).shouldDisableEnabledFilter
        )
    }

    func testDoesNotDisableFilterWhenAlreadyDisabled() {
        XCTAssertFalse(
            ContentFilterActivationPolicy(
                blockDohDotEnabled: true,
                isEnabled: true,
                servicesRunning: true,
                dnsProxyEnabled: false,
                captiveMode: .none,
                licenseValid: true,
                filterEnabled: false
            ).shouldDisableEnabledFilter
        )
    }

    func testEnablesDisabledFilterWhenDNSProtectionIsFullyActive() {
        XCTAssertTrue(
            ContentFilterActivationPolicy(
                blockDohDotEnabled: true,
                isEnabled: true,
                servicesRunning: true,
                dnsProxyEnabled: true,
                captiveMode: .none,
                licenseValid: true,
                filterEnabled: false
            ).shouldEnableDisabledFilter
        )
    }

    func testDoesNotEnableFilterWhenAlreadyEnabledOrProtectionInactive() {
        XCTAssertFalse(
            ContentFilterActivationPolicy(
                blockDohDotEnabled: true,
                isEnabled: true,
                servicesRunning: true,
                dnsProxyEnabled: true,
                captiveMode: .none,
                licenseValid: true,
                filterEnabled: true
            ).shouldEnableDisabledFilter
        )

        XCTAssertFalse(
            ContentFilterActivationPolicy(
                blockDohDotEnabled: true,
                isEnabled: true,
                servicesRunning: false,
                dnsProxyEnabled: true,
                captiveMode: .none,
                licenseValid: true,
                filterEnabled: false
            ).shouldEnableDisabledFilter
        )
    }

    func testRetriesFilterEnableWhenApprovalClearsAndFilterShouldBeEnabled() {
        let policy = ContentFilterApprovalRecoveryPolicy(
            proxyNeedsApproval: false,
            filterNeedsApproval: false,
            shouldEnableContentFilter: true
        )

        XCTAssertTrue(policy.shouldRetryContentFilterEnable)
    }

    func testDoesNotRetryFilterEnableWhileApprovalStillPendingOrFilterNotNeeded() {
        XCTAssertFalse(
            ContentFilterApprovalRecoveryPolicy(
                proxyNeedsApproval: false,
                filterNeedsApproval: true,
                shouldEnableContentFilter: true
            ).shouldRetryContentFilterEnable
        )

        XCTAssertFalse(
            ContentFilterApprovalRecoveryPolicy(
                proxyNeedsApproval: false,
                filterNeedsApproval: false,
                shouldEnableContentFilter: false
            ).shouldRetryContentFilterEnable
        )
    }

    func testDoesNotRetryFilterEnableWhenRestartIsRequired() {
        let policy = ContentFilterApprovalRecoveryPolicy(
            proxyNeedsApproval: false,
            filterNeedsApproval: false,
            shouldEnableContentFilter: true,
            restartRequired: true
        )

        XCTAssertFalse(policy.shouldRetryContentFilterEnable)
    }

    func testResumesPersistedDNSIntentAfterLateProxyApproval() {
        let policy = DNSProxyApprovalRecoveryPolicy(
            resumeRequested: true,
            proxyNeedsApproval: false,
            restartRequired: false,
            runtimeDNSDesired: true,
            protectionActive: false,
            isEnablingDNS: false,
            isStoppingDNS: false
        )

        XCTAssertTrue(policy.shouldResumeDNS)
    }

    func testDoesNotResumeDNSWhileApprovalOrLifecycleOperationIsPending() {
        XCTAssertFalse(
            DNSProxyApprovalRecoveryPolicy(
                resumeRequested: true,
                proxyNeedsApproval: true,
                restartRequired: false,
                runtimeDNSDesired: true,
                protectionActive: false,
                isEnablingDNS: false,
                isStoppingDNS: false
            ).shouldResumeDNS
        )

        XCTAssertFalse(
            DNSProxyApprovalRecoveryPolicy(
                resumeRequested: true,
                proxyNeedsApproval: false,
                restartRequired: false,
                runtimeDNSDesired: false,
                protectionActive: false,
                isEnablingDNS: false,
                isStoppingDNS: true
            ).shouldResumeDNS
        )

        XCTAssertFalse(
            DNSProxyApprovalRecoveryPolicy(
                resumeRequested: true,
                proxyNeedsApproval: false,
                restartRequired: false,
                runtimeDNSDesired: true,
                protectionActive: true,
                isEnablingDNS: false,
                isStoppingDNS: false
            ).shouldResumeDNS
        )
    }
}
