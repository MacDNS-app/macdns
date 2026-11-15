// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// Single owner of the user-visible protection status.
///
/// The headline, the status message and the status icon are all derived from
/// one `ProtectionDisplayState`. Provider bypass and provider `unknown` can
/// never render "Active", and plaintext forwarding is surfaced as a degraded
/// state instead of being hidden in a low-emphasis subtitle.
public struct ProtectionStatusPolicy: Equatable {
    public enum Status: Equatable, Sendable {
        /// The user preference is off.
        case ready
        /// Enabled, resolver not running yet.
        case starting
        /// Resolver running without the DNS Proxy manager enabled.
        case dnsProxyInactive
        /// Captive-portal compatibility bypass.
        case captiveBypass
        /// The provider answered and is deliberately bypassing.
        case providerBypass(reason: String?)
        /// The provider could not be queried.
        case providerUnknown
        /// Intercepting, but resolving through plaintext forwarding.
        case degradedForwarding
        /// Intercepting with the full recursive/DoH path.
        case active
    }

    public static let unknownStatusMessage = "Protection state unknown"
    public static let degradedForwardingHeadline = "Limited Protection"
    public static let degradedForwardingMessage = "Using this network's DNS, unencrypted"
    public static let encryptedModeMessage = "Encrypted"
    public static let forwardingModeMessage = "This network's DNS"
    public static let dnsProxyInactiveMessage = "MacDNS isn't receiving lookups"
    public static let captiveBypassMessage = "Paused for Wi-Fi sign-in"

    /// `reason` is the provider's raw `ProxyInterceptionReason`. A reason this build
    /// doesn't know, from a newer extension, reads as unknown.
    public static func pausedMessage(reason: String?) -> String {
        let detail: String
        switch reason.flatMap(ProxyInterceptionReason.init(rawValue:)) {
        case .starting: detail = "starting"
        case .agentUnavailable: detail = "MacDNS service not running"
        case .sessionUnavailable: detail = "connecting to MacDNS"
        case .resolverNotReady: detail = "getting ready"
        case .probeFailed: detail = "self-check failed"
        case .dnsDestinationsUnavailable: detail = "no network DNS"
        case .stopping: detail = "stopping"
        case nil: detail = "unknown reason"
        }
        return "Paused: \(detail)"
    }

    public let state: ProtectionDisplayState

    public init(state: ProtectionDisplayState) {
        self.state = state
    }

    public var status: Status {
        guard state.isEnabled else { return .ready }
        if state.captivePortalDetected { return .captiveBypass }
        guard state.servicesRunning else { return .starting }
        guard state.dnsProxyEnabled else { return .dnsProxyInactive }

        switch state.providerState {
        case .unknown:
            return .providerUnknown
        case .bypass(let reason):
            return .providerBypass(reason: reason)
        case .intercepting:
            return state.forwarding ? .degradedForwarding : .active
        }
    }

    public var isProtectionActive: Bool {
        switch status {
        case .active, .degradedForwarding:
            return true
        default:
            return false
        }
    }

    public var statusMessage: String {
        switch status {
        case .ready:
            return "Ready"
        case .starting:
            return "Starting..."
        case .dnsProxyInactive:
            return Self.dnsProxyInactiveMessage
        case .captiveBypass:
            return Self.captiveBypassMessage
        case .providerBypass(let reason):
            return Self.pausedMessage(reason: reason)
        case .providerUnknown:
            return Self.unknownStatusMessage
        case .degradedForwarding:
            return Self.degradedForwardingMessage
        case .active:
            return "Active"
        }
    }

    public var headline: String {
        switch status {
        case .active:
            return "Protection Active"
        case .degradedForwarding:
            return Self.degradedForwardingHeadline
        default:
            return "Protection Inactive"
        }
    }

    public var iconName: String {
        isProtectionActive ? "StatusOn" : "StatusOff"
    }
}
