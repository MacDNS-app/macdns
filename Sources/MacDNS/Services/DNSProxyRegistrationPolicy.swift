// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

struct DNSProxyRegistrationPolicy: Equatable {
    let preserveExistingEnabledState: Bool
    let existingProxyEnabled: Bool

    init(preserveExistingEnabledState: Bool = false, existingProxyEnabled: Bool = false) {
        self.preserveExistingEnabledState = preserveExistingEnabledState
        self.existingProxyEnabled = existingProxyEnabled
    }

    var shouldEnableProxyDuringRegistration: Bool {
        preserveExistingEnabledState && existingProxyEnabled
    }
}

/// Whether a loaded `NEDNSProxyManager` holds the MacDNS configuration. With
/// nothing saved, macOS loads an empty provider protocol with no provider
/// bundle identifier, so a non-nil protocol alone does not mean configured.
enum DNSProxyConfigurationPolicy {
    static let providerBundleIdentifier = "app.macdns.dnsproxy"

    static func isConfigured(providerBundleIdentifier: String?) -> Bool {
        providerBundleIdentifier == Self.providerBundleIdentifier
    }
}

struct DNSProxyStartOrderPolicy: Equatable {
    let dnsProxyEnabledBeforeResolverStart: Bool

    var shouldDisableProxyBeforeResolverStart: Bool {
        dnsProxyEnabledBeforeResolverStart
    }
}
