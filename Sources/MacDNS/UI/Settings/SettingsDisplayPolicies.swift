// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared

enum SettingsStatusTone: Equatable {
    case active, degraded, inactive, waiting, configurationError

    static func tone(
        availability: PersistedStateAvailability,
        status: ProtectionStatusPolicy.Status
    ) -> SettingsStatusTone {
        switch availability {
        case .loading, .unavailable:
            return .waiting
        case .invalidConfiguration:
            return .configurationError
        case .loaded, .agentSetupRequired:
            switch status {
            case .active: return .active
            case .degradedForwarding: return .degraded
            default: return .inactive
            }
        }
    }
}

struct ActivitySummary: Equatable {
    let domainCount: Int
    let totalBlocks: Int
    let topCategory: BlocklistCategory?

    init(domains: [BlockedDomain]) {
        domainCount = domains.count
        totalBlocks = domains.reduce(0) { $0 + $1.blockCount }
        var perCategory: [BlocklistCategory: Int] = [:]
        for domain in domains {
            perCategory[domain.category, default: 0] += domain.blockCount
        }
        // allCases order breaks ties. Strict > keeps the earlier category.
        var best: (category: BlocklistCategory, count: Int)?
        for category in BlocklistCategory.allCases {
            guard let count = perCategory[category] else { continue }
            if best.map({ count > $0.count }) ?? true {
                best = (category, count)
            }
        }
        topCategory = best?.category
    }
}

enum LicenseAttentionPolicy {
    static func needsAttention(_ status: LicenseStatus?) -> Bool {
        switch status {
        case .expired, .trialExpired, .invalid: return true
        case .trial, .valid, .unknown, nil: return false
        }
    }

    static func badge(licenseStatus: LicenseStatus?, updateAvailable: Bool) -> String? {
        if needsAttention(licenseStatus) { return "!" }
        return updateAvailable ? "1" : nil
    }
}

/// What the Overview health rows report. The agent's snapshot describes the provider only
/// while the DNS Proxy is on. With it off, macOS sends the provider no DNS at all.
enum HealthRowsPolicy {
    enum Interception: Equatable {
        case off, intercepting, unknown
        case bypass(reason: String?)
    }

    static func interception(_ state: ProtectionDisplayState) -> Interception {
        guard state.dnsProxyEnabled else { return .off }
        switch state.providerState {
        case .intercepting: return .intercepting
        case .bypass(let reason): return .bypass(reason: reason)
        case .unknown: return .unknown
        }
    }

    enum SystemExtension: Equatable {
        case extensionActive, installed, inactive
    }

    static func systemExtension(extensionActive: Bool, _ state: ProtectionDisplayState) -> SystemExtension {
        guard extensionActive else { return .inactive }
        return state.dnsProxyEnabled ? .extensionActive : .installed
    }

    static func resolverMode(_ state: ProtectionDisplayState, reported: String) -> String {
        state.servicesRunning ? reported : "Stopped"
    }
}
