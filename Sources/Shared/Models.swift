// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import CoreFoundation
import Foundation

public enum DoHProviderID: String, Codable, CaseIterable, Equatable, Hashable {
    case cloudflare
    case google
    case quad9

    public var displayName: String {
        switch self {
        case .cloudflare: return "Cloudflare"
        case .google: return "Google"
        case .quad9: return "Quad9"
        }
    }

    public static var defaultProviders: [DoHProviderID] {
        allCases
    }

    public static func canonicalized(_ rawValues: [String]) -> [DoHProviderID] {
        let rawSet = Set(rawValues)
        let providers = allCases.filter { rawSet.contains($0.rawValue) }
        return providers.isEmpty ? defaultProviders : providers
    }
}

public enum DoHDispatchMode: String, Codable, CaseIterable, Equatable, Hashable {
    case parallel
    case staggeredParallel
    case sequentialTimeout

    public var displayName: String {
        switch self {
        case .parallel: return "Parallel"
        case .staggeredParallel: return "Staggered"
        case .sequentialTimeout: return "Sequential"
        }
    }

    public var ffiValue: Int32 {
        switch self {
        case .parallel: return 0
        case .staggeredParallel: return 1
        case .sequentialTimeout: return 2
        }
    }

    public static let defaultMode: DoHDispatchMode = .staggeredParallel
}

// MARK: - Forward Zone Model
public struct ForwardZone: Identifiable, Codable, Equatable {
    public let id: UUID
    public var domain: String
    public var forwardIP: String
    public var enabled: Bool

    public init(id: UUID = UUID(), domain: String, forwardIP: String, enabled: Bool = true) {
        self.id = id
        self.domain = domain
        self.forwardIP = forwardIP
        self.enabled = enabled
    }
}

// MARK: - DNS Override Model
public struct DNSOverride: Identifiable, Codable, Equatable {
    public let id: UUID
    public var domain: String
    public var value: String
    public var qtype: String
    public var enabled: Bool

    public init(id: UUID = UUID(), domain: String, value: String, qtype: String, enabled: Bool = true) {
        self.id = id
        self.domain = domain
        self.value = value
        self.qtype = qtype
        self.enabled = enabled
    }

    public var isWildcard: Bool {
        domain.hasPrefix("*.")
    }

    public var baseDomain: String {
        if domain.hasPrefix("*.") {
            return String(domain.dropFirst(2))
        }
        return domain
    }

    public static func valuePlaceholder(for qtype: String) -> String {
        switch qtype {
        case "A": return "192.0.2.1"
        case "AAAA": return "2001:db8::1"
        case "CNAME": return "target.example.com"
        case "MX": return "mail.example.com"
        case "TXT": return "v=spf1 include:example.com ~all"
        case "PTR": return "host.example.com"
        case "NS": return "ns1.example.com"
        default: return "value"
        }
    }
}

// MARK: - Configuration State Model
public struct ConfigState: Codable, Equatable {
    public var dnssecEnabled: Bool
    public var logQueriesEnabled: Bool
    public var logRepliesEnabled: Bool
    public var prefetchEnabled: Bool
    public var serveExpiredEnabled: Bool
    public var blockDohDotEnabled: Bool
    public var dohProviders: [DoHProviderID]
    public var dohDispatchMode: DoHDispatchMode
    public var dnsAnswerRefinementEnabled: Bool
    public var queryHistoryEnabled: Bool
    public var queryHistoryRetentionDays: Int
    public var popularPrefetchCount: Int
    public var popularPrefetchDays: Int

    private enum CodingKeys: String, CodingKey {
        case dnssecEnabled
        case logQueriesEnabled
        case logRepliesEnabled
        case prefetchEnabled
        case serveExpiredEnabled
        case blockDohDotEnabled
        case dohProviders
        case dohDispatchMode
        case dnsAnswerRefinementEnabled
        case queryHistoryEnabled
        case queryHistoryRetentionDays
        case popularPrefetchCount
        case popularPrefetchDays
    }

    public init(
        dnssecEnabled: Bool = true,
        logQueriesEnabled: Bool = false,
        logRepliesEnabled: Bool = false,
        prefetchEnabled: Bool = true,
        serveExpiredEnabled: Bool = true,
        blockDohDotEnabled: Bool = false,
        dohProviders: [DoHProviderID] = DoHProviderID.defaultProviders,
        dohDispatchMode: DoHDispatchMode = DoHDispatchMode.defaultMode,
        dnsAnswerRefinementEnabled: Bool = true,
        queryHistoryEnabled: Bool = QueryHistorySettings.default.enabled,
        queryHistoryRetentionDays: Int = QueryHistorySettings.default.retentionDays,
        popularPrefetchCount: Int = QueryHistorySettings.default.popularCount,
        popularPrefetchDays: Int = QueryHistorySettings.default.popularDays
    ) {
        self.dnssecEnabled = dnssecEnabled
        self.logQueriesEnabled = logQueriesEnabled
        self.logRepliesEnabled = logRepliesEnabled
        self.prefetchEnabled = prefetchEnabled
        self.serveExpiredEnabled = serveExpiredEnabled
        self.blockDohDotEnabled = blockDohDotEnabled
        self.dohProviders = DoHProviderID.canonicalized(dohProviders.map(\.rawValue))
        self.dohDispatchMode = dohDispatchMode
        self.dnsAnswerRefinementEnabled = dnsAnswerRefinementEnabled
        self.queryHistoryEnabled = queryHistoryEnabled
        self.queryHistoryRetentionDays = queryHistoryRetentionDays
        self.popularPrefetchCount = popularPrefetchCount
        self.popularPrefetchDays = popularPrefetchDays
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        dnssecEnabled = try container.decodeIfPresent(Bool.self, forKey: .dnssecEnabled) ?? true
        logQueriesEnabled = try container.decodeIfPresent(Bool.self, forKey: .logQueriesEnabled) ?? false
        logRepliesEnabled = try container.decodeIfPresent(Bool.self, forKey: .logRepliesEnabled) ?? false
        prefetchEnabled = try container.decodeIfPresent(Bool.self, forKey: .prefetchEnabled) ?? true
        serveExpiredEnabled = try container.decodeIfPresent(Bool.self, forKey: .serveExpiredEnabled) ?? true
        blockDohDotEnabled = try container.decodeIfPresent(Bool.self, forKey: .blockDohDotEnabled) ?? false

        let rawProviders = try container.decodeIfPresent([String].self, forKey: .dohProviders)
        dohProviders = DoHProviderID.canonicalized(rawProviders ?? DoHProviderID.defaultProviders.map(\.rawValue))

        let rawMode = try container.decodeIfPresent(String.self, forKey: .dohDispatchMode)
        dohDispatchMode = rawMode.flatMap(DoHDispatchMode.init(rawValue:)) ?? .defaultMode
        dnsAnswerRefinementEnabled =
            try container.decodeIfPresent(Bool.self, forKey: .dnsAnswerRefinementEnabled) ?? true
        let history = QueryHistorySettings.default
        queryHistoryEnabled =
            try container.decodeIfPresent(Bool.self, forKey: .queryHistoryEnabled) ?? history.enabled
        queryHistoryRetentionDays =
            try container.decodeIfPresent(Int.self, forKey: .queryHistoryRetentionDays) ?? history.retentionDays
        popularPrefetchCount =
            try container.decodeIfPresent(Int.self, forKey: .popularPrefetchCount) ?? history.popularCount
        popularPrefetchDays =
            try container.decodeIfPresent(Int.self, forKey: .popularPrefetchDays) ?? history.popularDays
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(dnssecEnabled, forKey: .dnssecEnabled)
        try container.encode(logQueriesEnabled, forKey: .logQueriesEnabled)
        try container.encode(logRepliesEnabled, forKey: .logRepliesEnabled)
        try container.encode(prefetchEnabled, forKey: .prefetchEnabled)
        try container.encode(serveExpiredEnabled, forKey: .serveExpiredEnabled)
        try container.encode(blockDohDotEnabled, forKey: .blockDohDotEnabled)
        try container.encode(dohProviders.map(\.rawValue), forKey: .dohProviders)
        try container.encode(dohDispatchMode.rawValue, forKey: .dohDispatchMode)
        try container.encode(dnsAnswerRefinementEnabled, forKey: .dnsAnswerRefinementEnabled)
        try container.encode(queryHistoryEnabled, forKey: .queryHistoryEnabled)
        try container.encode(queryHistoryRetentionDays, forKey: .queryHistoryRetentionDays)
        try container.encode(popularPrefetchCount, forKey: .popularPrefetchCount)
        try container.encode(popularPrefetchDays, forKey: .popularPrefetchDays)
    }

    public static var `default`: ConfigState {
        return ConfigState()
    }
}

// MARK: - Blocklist Models

public enum BlocklistCategory: String, Codable, CaseIterable, Equatable, Sendable {
    case adsTracking = "Ads & Tracking"
    case malwareSecurity = "Malware & Security"
    case adultContent = "Adult Content"
    case gambling = "Gambling"
    case socialMedia = "Social Media"
    case miscellaneous = "Miscellaneous"

    public var identifier: String {
        switch self {
        case .adsTracking: return "ads_tracking"
        case .malwareSecurity: return "malware_security"
        case .adultContent: return "adult"
        case .gambling: return "gambling"
        case .socialMedia: return "social"
        case .miscellaneous: return "misc"
        }
    }

    /// Matches by prefix because the identifier may carry a level suffix, as in
    /// `ads_tracking_pro`.
    public static func fromIdentifier(_ identifier: String) -> BlocklistCategory? {
        switch true {
        case identifier.hasPrefix("ads_tracking"): return .adsTracking
        case identifier.hasPrefix("malware_security"): return .malwareSecurity
        case identifier.hasPrefix("adult"): return .adultContent
        case identifier.hasPrefix("gambling"): return .gambling
        case identifier.hasPrefix("social"): return .socialMedia
        case identifier.hasPrefix("misc"): return .miscellaneous
        default: return nil
        }
    }

    public var description: String {
        switch self {
        case .adsTracking:
            return "Blocks ads, trackers, and apps reporting how you use them"
        case .malwareSecurity:
            return "Blocks malware, scams, and security threats"
        case .adultContent:
            return "Blocks adult and pornographic sites"
        case .gambling:
            return "Blocks gambling sites"
        case .socialMedia:
            return "Blocks Facebook, Instagram, TikTok, X, Snapchat"
        case .miscellaneous:
            return "Blocks pop-ups, link shorteners, and services apps use to skip MacDNS"
        }
    }
}

public enum CategoryLevel: String, Codable, CaseIterable, Equatable, Sendable {
    case disabled = "Disabled"
    case light = "Light"
    case normal = "Normal"
    case pro = "Pro"
    case proPlus = "Pro+"
    case ultimate = "Ultimate"

    public func isValidFor(category: BlocklistCategory) -> Bool {
        switch category {
        case .adsTracking:
            return true
        case .malwareSecurity:
            return self != .proPlus
        case .gambling, .miscellaneous:
            return [.disabled, .light, .normal, .pro].contains(self)
        case .adultContent, .socialMedia:
            return [.disabled, .light].contains(self)  // Light means enabled.
        }
    }

    public static func availableLevels(for category: BlocklistCategory) -> [CategoryLevel] {
        return allCases.filter { $0.isValidFor(category: category) }
    }

    public func toLevelString(for category: BlocklistCategory) -> (levelStr: String, displayName: String) {
        switch (category, self) {
        case (_, .disabled):
            return ("", "")

        case (.adsTracking, .light):
            return ("light", "Light")
        case (.adsTracking, .normal):
            return ("multi", "Normal")
        case (.adsTracking, .pro):
            return ("pro", "Pro")
        case (.adsTracking, .proPlus):
            return ("pro.plus", "Pro Plus")
        case (.adsTracking, .ultimate):
            return ("ultimate", "Ultimate")

        case (.malwareSecurity, .light):
            return ("fake", "Light")
        case (.malwareSecurity, .normal):
            return ("tif.mini", "Normal")
        case (.malwareSecurity, .pro):
            return ("tif.medium", "Pro")
        case (.malwareSecurity, .ultimate):
            return ("tif", "Ultimate")

        case (.adultContent, .light):
            return ("nsfw", "")

        case (.gambling, .light):
            return ("gambling.mini", "Light")
        case (.gambling, .normal):
            return ("gambling.medium", "Normal")
        case (.gambling, .pro):
            return ("gambling", "Pro")

        case (.socialMedia, .light):
            return ("social", "")

        case (.miscellaneous, .light):
            return ("popupads", "Light")
        case (.miscellaneous, .normal):
            return ("urlshortener", "Normal")
        case (.miscellaneous, .pro):
            return ("doh", "Pro")

        default:
            return ("", "")
        }
    }

    public static func from(levelString: String, category: BlocklistCategory) -> CategoryLevel {
        switch (category, levelString) {
        case (.adsTracking, "light"):
            return .light
        case (.adsTracking, "multi"):
            return .normal
        case (.adsTracking, "pro"):
            return .pro
        case (.adsTracking, "pro.plus"):
            return .proPlus
        case (.adsTracking, "ultimate"):
            return .ultimate

        case (.malwareSecurity, "fake"):
            return .light
        case (.malwareSecurity, "tif.mini"):
            return .normal
        case (.malwareSecurity, "tif.medium"):
            return .pro
        case (.malwareSecurity, "tif"):
            return .ultimate

        case (.adultContent, "nsfw"):
            return .light

        case (.gambling, "gambling.mini"):
            return .light
        case (.gambling, "gambling.medium"):
            return .normal
        case (.gambling, "gambling"):
            return .pro

        case (.socialMedia, "social"):
            return .light

        case (.miscellaneous, "popupads"):
            return .light
        case (.miscellaneous, "urlshortener"):
            return .normal
        case (.miscellaneous, "doh"):
            return .pro

        default:
            return .disabled
        }
    }
}

// Matches the Rust `CategoryConfig` format.
public struct CategoryConfig: Codable, Equatable, Sendable {
    public var name: String
    public var identifier: String
    public var level: String
    public var action: String
    public var enabled: Bool

    public init(name: String, identifier: String, level: String, action: String = "null", enabled: Bool = true) {
        self.name = name
        self.identifier = identifier
        self.level = level
        self.action = action
        self.enabled = enabled
    }
}

// Matches the Rust `BlocklistConfig` format.
public struct BlocklistSettings: Codable, Equatable, Sendable {
    public var enabled: Bool
    public var categories: [CategoryConfig]
    public var dbBasePath: String
    public var lastUpdated: Date?

    private enum CodingKeys: String, CodingKey {
        case enabled
        case categories
        case dbBasePath = "db_base_path"
        case lastUpdated = "last_updated"
    }

    public init(
        enabled: Bool = true,
        categories: [CategoryConfig]? = nil,
        dbBasePath: String = PathResolver.blocklistsDir.path,
        lastUpdated: Date? = nil
    ) {
        self.enabled = enabled
        self.dbBasePath = dbBasePath
        self.lastUpdated = lastUpdated

        if let categories = categories {
            self.categories = categories
        } else {
            self.categories = [
                CategoryConfig(name: "Ads & Tracking Normal", identifier: "ads_tracking", level: "multi"),
                CategoryConfig(name: "Malware & Security Pro", identifier: "malware_security", level: "tif.medium"),
                CategoryConfig(name: "Adult Content", identifier: "adult", level: "nsfw"),
                CategoryConfig(name: "Gambling Pro", identifier: "gambling", level: "gambling"),
                CategoryConfig(name: "Miscellaneous Light", identifier: "misc", level: "popupads"),
            ]
        }
    }

    public func level(for category: BlocklistCategory) -> CategoryLevel {
        guard let config = categories.first(where: { $0.identifier == category.identifier }) else {
            return .disabled
        }

        return CategoryLevel.from(levelString: config.level, category: category)
    }

    public mutating func setLevel(_ level: CategoryLevel, for category: BlocklistCategory) {
        categories.removeAll(where: { $0.identifier == category.identifier })

        if level != .disabled {
            let (levelStr, displayName) = level.toLevelString(for: category)
            let name = displayName.isEmpty ? category.rawValue : "\(category.rawValue) \(displayName)"
            categories.append(CategoryConfig(name: name, identifier: category.identifier, level: levelStr))
        }
    }
}

// MARK: - Blocklist Settings Persistence

/// Blocklist settings are user configuration, so they are persisted in
/// `state.json` under `blocklist` and travel through the same revision-guarded,
/// flock-serialized transaction as every other field.
/// `blocklist_settings.json` is a derived projection the agent emits for the
/// Rust scheduler. It is never an input.
public enum BlocklistSettingsTransactionPolicy {
    public static let stateKey = "blocklist"

    public enum PersistedSettings: Equatable {
        case missing
        case valid(BlocklistSettings)
        case malformed
    }

    /// The `state.json` fragment for a settings value. `db_base_path` is a
    /// machine path the agent derives when it emits the projection, so it is
    /// not persisted as user configuration.
    public static func fragment(for settings: BlocklistSettings) -> [String: Any] {
        var fragment: [String: Any] = [
            "enabled": settings.enabled,
            "categories": settings.categories.map { category in
                [
                    "name": category.name,
                    "identifier": category.identifier,
                    "level": category.level,
                    "action": category.action,
                    "enabled": category.enabled,
                ] as [String: Any]
            },
        ]
        if let lastUpdated = settings.lastUpdated {
            fragment["last_updated"] = lastUpdated.timeIntervalSinceReferenceDate
        }
        return fragment
    }

    public static func persisted(
        in config: [String: Any],
        dbBasePath: String
    ) -> PersistedSettings {
        guard let rawFragment = config[stateKey] else { return .missing }
        guard
            let fragment = rawFragment as? [String: Any],
            let enabled = parseBool(fragment["enabled"]),
            let rawCategories = fragment["categories"] as? [Any]
        else {
            return .malformed
        }

        var categories: [CategoryConfig] = []
        categories.reserveCapacity(rawCategories.count)
        for rawCategory in rawCategories {
            guard
                let category = rawCategory as? [String: Any],
                let name = category["name"] as? String,
                let identifier = category["identifier"] as? String,
                let level = category["level"] as? String,
                let action = category["action"] as? String,
                let categoryEnabled = parseBool(category["enabled"])
            else {
                return .malformed
            }
            categories.append(
                CategoryConfig(
                    name: name,
                    identifier: identifier,
                    level: level,
                    action: action,
                    enabled: categoryEnabled
                )
            )
        }

        var lastUpdated: Date?
        if let rawLastUpdated = fragment["last_updated"] {
            guard
                let seconds = rawLastUpdated as? NSNumber,
                CFGetTypeID(seconds as CFTypeRef) != CFBooleanGetTypeID()
            else {
                return .malformed
            }
            lastUpdated = Date(
                timeIntervalSinceReferenceDate: seconds.doubleValue
            )
        }

        return .valid(
            BlocklistSettings(
                enabled: enabled,
                categories: categories,
                dbBasePath: dbBasePath,
                lastUpdated: lastUpdated
            )
        )
    }

    public static func config(
        _ config: [String: Any],
        settings: BlocklistSettings
    ) -> [String: Any] {
        var updated = config
        updated[stateKey] = fragment(for: settings)
        return updated
    }

    /// Strips the persisted-only blocklist fragment. Callers that compare a
    /// client snapshot against the authoritative document must use this, the
    /// same way `timestamp` and `schemaVersion` are kept out of the comparison.
    public static func configWithoutSettings(
        _ config: [String: Any]
    ) -> [String: Any] {
        var stripped = config
        stripped.removeValue(forKey: stateKey)
        return stripped
    }

    private static func parseBool(_ rawValue: Any?) -> Bool? {
        guard
            let rawValue,
            CFGetTypeID(rawValue as CFTypeRef) == CFBooleanGetTypeID()
        else {
            return nil
        }
        return rawValue as? Bool
    }
}

// MARK: - Blocklist Statistics Model
public struct BlockedDomain: Codable, Equatable, Identifiable {
    public let id: UUID
    public var domain: String
    /// The rule that matched, which may be a parent domain of `domain`.
    public var matchedRule: String
    public var category: BlocklistCategory
    public var blockCount: Int

    public init(
        id: UUID = UUID(),
        domain: String,
        matchedRule: String? = nil,
        category: BlocklistCategory,
        blockCount: Int = 1
    ) {
        self.id = id
        self.domain = domain
        self.matchedRule = matchedRule ?? domain
        self.category = category
        self.blockCount = blockCount
    }
}

// MARK: - Allowlist Model
public struct AllowedDomain: Codable, Equatable, Identifiable, Hashable {
    public let id: UUID
    public var domain: String
    public var enabled: Bool

    public init(id: UUID = UUID(), domain: String, enabled: Bool = true) {
        self.id = id
        self.domain = domain
        self.enabled = enabled
    }
}

// MARK: - JSON Coding Helpers

public enum JSONCoding {
    /// Dates use the default strategy, seconds since the reference date.
    public static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        return encoder
    }

    public static var decoder: JSONDecoder {
        return JSONDecoder()
    }
}

// MARK: - Dictionary Parsing Extensions

extension ForwardZone {
    /// Parses the XPC/`state.json` dictionary form. Nil when a required field
    /// is missing. A missing or malformed `id` gets a fresh UUID.
    public init?(from dict: [String: Any]) {
        guard let domain = dict["domain"] as? String,
            let forwardIP = dict["forwardIP"] as? String
        else { return nil }

        let id = (dict["id"] as? String).flatMap { UUID(uuidString: $0) } ?? UUID()
        let enabled = dict["enabled"] as? Bool ?? true

        self.init(id: id, domain: domain, forwardIP: forwardIP, enabled: enabled)
    }

    public func toDictionary() -> [String: Any] {
        return [
            "id": id.uuidString,
            "domain": domain,
            "forwardIP": forwardIP,
            "enabled": enabled,
        ]
    }

    public static func parseArray(_ dicts: [[String: Any]]) -> [ForwardZone] {
        return dicts.compactMap { ForwardZone(from: $0) }
    }
}

extension DNSOverride {
    /// Parses the XPC/`state.json` dictionary form. Nil when a required field
    /// is missing. A missing or malformed `id` gets a fresh UUID.
    public init?(from dict: [String: Any]) {
        guard let domain = dict["domain"] as? String,
            let value = dict["value"] as? String,
            let qtype = dict["qtype"] as? String
        else { return nil }

        let id = (dict["id"] as? String).flatMap { UUID(uuidString: $0) } ?? UUID()
        let enabled = dict["enabled"] as? Bool ?? true

        self.init(id: id, domain: domain, value: value, qtype: qtype, enabled: enabled)
    }

    public func toDictionary() -> [String: Any] {
        return [
            "id": id.uuidString,
            "domain": domain,
            "value": value,
            "qtype": qtype,
            "enabled": enabled,
        ]
    }

    public static func parseArray(_ dicts: [[String: Any]]) -> [DNSOverride] {
        return dicts.compactMap { DNSOverride(from: $0) }
    }
}

extension AllowedDomain {
    /// Parses the XPC/`state.json` dictionary form. Nil when a required field
    /// is missing. A missing or malformed `id` gets a fresh UUID.
    public init?(from dict: [String: Any]) {
        guard let domain = dict["domain"] as? String else { return nil }

        let id = (dict["id"] as? String).flatMap { UUID(uuidString: $0) } ?? UUID()
        let enabled = dict["enabled"] as? Bool ?? true

        self.init(id: id, domain: domain, enabled: enabled)
    }

    public func toDictionary() -> [String: Any] {
        return [
            "id": id.uuidString,
            "domain": domain,
            "enabled": enabled,
        ]
    }

    public static func parseArray(_ dicts: [[String: Any]]) -> [AllowedDomain] {
        return dicts.compactMap { AllowedDomain(from: $0) }
    }
}
