// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared

struct ContentFilterActivationPolicy: Equatable {
    let blockDohDotEnabled: Bool
    let isEnabled: Bool
    let servicesRunning: Bool
    let dnsProxyEnabled: Bool
    let captiveMode: CaptivePortalCompatibilityMode
    let licenseValid: Bool
    let filterEnabled: Bool

    init(
        blockDohDotEnabled: Bool,
        isEnabled: Bool,
        servicesRunning: Bool,
        dnsProxyEnabled: Bool,
        captiveMode: CaptivePortalCompatibilityMode,
        licenseValid: Bool,
        filterEnabled: Bool = false
    ) {
        self.blockDohDotEnabled = blockDohDotEnabled
        self.isEnabled = isEnabled
        self.servicesRunning = servicesRunning
        self.dnsProxyEnabled = dnsProxyEnabled
        self.captiveMode = captiveMode
        self.licenseValid = licenseValid
        self.filterEnabled = filterEnabled
    }

    /// Scoped captive forwarding still routes every query through the DNS
    /// Proxy, so DoH/DoT must stay blocked. Only an explicitly approved full
    /// bypass releases the Content Filter.
    var shouldKeepEnabled: Bool {
        blockDohDotEnabled
            && isEnabled
            && servicesRunning
            && dnsProxyEnabled
            && captiveMode != .approvedFullBypass
            && licenseValid
    }

    var shouldDisableEnabledFilter: Bool {
        filterEnabled && !shouldKeepEnabled
    }

    var shouldEnableDisabledFilter: Bool {
        !filterEnabled && shouldKeepEnabled
    }
}

struct ContentFilterApprovalRecoveryPolicy: Equatable {
    let proxyNeedsApproval: Bool
    let filterNeedsApproval: Bool
    let shouldEnableContentFilter: Bool
    var restartRequired: Bool = false

    var shouldRetryContentFilterEnable: Bool {
        !restartRequired && !proxyNeedsApproval && !filterNeedsApproval && shouldEnableContentFilter
    }
}

struct DNSProxyApprovalRecoveryPolicy: Equatable {
    let resumeRequested: Bool
    let proxyNeedsApproval: Bool
    let restartRequired: Bool
    let runtimeDNSDesired: Bool
    let protectionActive: Bool
    let isEnablingDNS: Bool
    let isStoppingDNS: Bool

    var shouldResumeDNS: Bool {
        resumeRequested
            && !proxyNeedsApproval
            && !restartRequired
            && runtimeDNSDesired
            && !protectionActive
            && !isEnablingDNS
            && !isStoppingDNS
    }
}
