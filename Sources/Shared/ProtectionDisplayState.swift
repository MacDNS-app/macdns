// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// Authenticated interception state of the DNS Proxy provider, as reported by
/// the Agent's runtime snapshot. `unknown` is the only honest value when the
/// provider cannot be queried. It is never inferred from manager state.
public enum ProviderInterceptionDisplayState: Equatable, Sendable {
    case intercepting
    case bypass(reason: String?)
    case unknown
}

/// Every input the UI is allowed to use when describing protection status.
/// Both the headline and the status message are derived from this one value
/// through `ProtectionStatusPolicy`, so the UI cannot show two contradictory
/// security statuses.
public struct ProtectionDisplayState: Equatable {
    public let isEnabled: Bool
    public let servicesRunning: Bool
    public let dnsProxyEnabled: Bool
    public let providerState: ProviderInterceptionDisplayState
    public let forwarding: Bool
    public let captivePortalDetected: Bool

    public init(
        isEnabled: Bool,
        servicesRunning: Bool,
        dnsProxyEnabled: Bool,
        providerState: ProviderInterceptionDisplayState,
        forwarding: Bool = false,
        captivePortalDetected: Bool = false
    ) {
        self.isEnabled = isEnabled
        self.servicesRunning = servicesRunning
        self.dnsProxyEnabled = dnsProxyEnabled
        self.providerState = providerState
        self.forwarding = forwarding
        self.captivePortalDetected = captivePortalDetected
    }

    public var providerIntercepting: Bool {
        providerState == .intercepting
    }

    public var statusPolicy: ProtectionStatusPolicy {
        ProtectionStatusPolicy(state: self)
    }

    public var isProtectionActive: Bool {
        statusPolicy.isProtectionActive
    }

    public var headline: String {
        statusPolicy.headline
    }

    public var iconName: String {
        statusPolicy.iconName
    }
}
