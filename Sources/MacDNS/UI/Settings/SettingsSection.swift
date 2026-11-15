// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

enum SettingsSectionGroup: CaseIterable {
    case dns, filtering, insights, macdns

    var title: String {
        switch self {
        case .dns: return "DNS"
        case .filtering: return "Filtering"
        case .insights: return "Insights"
        case .macdns: return "MacDNS"
        }
    }
}

enum SettingsSection: String, CaseIterable, Identifiable, Hashable {
    case overview
    case resolver
    case forwardZones
    case overrides
    case blocklist
    case allowlist
    case queries
    case activity
    case advanced
    case licenseUpdates

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: return "Overview"
        case .resolver: return "DNS Providers"
        case .forwardZones: return "Forward Zones"
        case .overrides: return "Local Records"
        case .blocklist: return "Blocklist"
        case .allowlist: return "Allowlist"
        case .queries: return "Queries"
        case .activity: return "Blocked"
        case .advanced: return "Advanced"
        case .licenseUpdates: return "License & Updates"
        }
    }

    var symbolName: String {
        switch self {
        case .overview: return "lock.shield.fill"
        case .resolver: return "server.rack"
        case .forwardZones: return "globe"
        case .overrides: return "arrow.triangle.swap"
        case .blocklist: return "nosign"
        case .allowlist: return "checkmark.shield.fill"
        case .queries: return "chart.bar.xaxis"
        case .activity: return "hand.raised"
        case .advanced: return "slider.horizontal.3"
        case .licenseUpdates: return "key.fill"
        }
    }

    /// `nil` only for Overview, which sits above the groups.
    var group: SettingsSectionGroup? {
        switch self {
        case .overview: return nil
        case .resolver, .forwardZones, .overrides: return .dns
        case .blocklist, .allowlist: return .filtering
        case .queries, .activity: return .insights
        case .advanced, .licenseUpdates: return .macdns
        }
    }

    var keywords: [String] {
        switch self {
        case .overview:
            return ["status", "protection", "flush", "clear", "cache", "extension", "lookups"]
        case .resolver:
            return [
                "resolver", "doh", "cloudflare", "google", "quad9", "query mode", "dispatch",
                "dnssec", "refinement", "prefetch", "serve expired", "dot", "encrypted",
            ]
        case .forwardZones:
            return ["zone", "forward", "split", "internal", "vpn"]
        case .overrides:
            return ["overrides", "local", "record", "a", "aaaa", "cname", "mx", "txt", "ptr", "ns", "hosts"]
        case .blocklist:
            return ["ads", "tracking", "malware", "adult", "gambling", "social", "category"]
        case .allowlist:
            return ["allow", "exception", "whitelist"]
        case .queries:
            return ["queries", "lookups", "history", "hosts", "log"]
        case .activity:
            return ["stats", "blocked", "top", "statistics", "activity"]
        case .advanced:
            return ["log", "queries", "replies", "remove", "uninstall"]
        case .licenseUpdates:
            return ["license", "trial", "key", "activate", "update", "version", "about"]
        }
    }

    func matches(_ query: String) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return true }
        return title.localizedCaseInsensitiveContains(needle)
            || group?.title.lowercased().hasPrefix(needle.lowercased()) == true
            || keywords.contains { $0.localizedCaseInsensitiveContains(needle) }
    }

    static func sections(in group: SettingsSectionGroup) -> [SettingsSection] {
        allCases.filter { $0.group == group }
    }

    /// The section above this one in the sidebar, which lists `allCases` in order.
    var previous: SettingsSection? {
        let index = Self.allCases.firstIndex(of: self)!
        return index > Self.allCases.startIndex ? Self.allCases[index - 1] : nil
    }

    /// The section below this one in the sidebar.
    var next: SettingsSection? {
        let index = Self.allCases.firstIndex(of: self)!
        return index + 1 < Self.allCases.endIndex ? Self.allCases[index + 1] : nil
    }
}

/// Last visited section, kept for the app's lifetime only so `state.json` stays the single config store.
@MainActor
enum SettingsNavigationMemory {
    static var lastSection: SettingsSection = .overview
}
