// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

// MARK: - Settings

/// The lookup-history keys in `state.json`. They are optional, so a document
/// written before history existed reads as `default`. The resolver enforces
/// the same allowed choices in `dns_configure_history`.
public struct QueryHistorySettings: Equatable, Sendable {
    public static let enabledKey = "queryHistoryEnabled"
    public static let retentionDaysKey = "queryHistoryRetentionDays"
    public static let popularCountKey = "popularPrefetchCount"
    public static let popularDaysKey = "popularPrefetchDays"

    public static let retentionDayChoices = [7, 14, 30, 90]
    /// 0 turns popular-host prefetch off.
    public static let popularCountChoices = [0, 100, 250, 500, 1000, 2000]
    /// Never longer than the retention.
    public static let popularDayChoices = [1, 7, 14, 30]

    public static let `default` = QueryHistorySettings(
        enabled: true,
        retentionDays: 30,
        popularCount: 0,
        popularDays: 7
    )

    public var enabled: Bool
    public var retentionDays: Int
    public var popularCount: Int
    public var popularDays: Int

    public init(enabled: Bool, retentionDays: Int, popularCount: Int, popularDays: Int) {
        self.enabled = enabled
        self.retentionDays = retentionDays
        self.popularCount = popularCount
        self.popularDays = popularDays
    }

    public enum ValidationError: LocalizedError, Equatable, Sendable {
        case wrongType(key: String)
        case retentionDays(Int)
        case popularCount(Int)
        case popularDays(Int)
        case popularDaysExceedRetention(days: Int, retentionDays: Int)

        public var errorDescription: String? {
            switch self {
            case .wrongType(let key):
                return "\(key) has the wrong type"
            case .retentionDays(let value):
                return Self.notAChoice(retentionDaysKey, value, retentionDayChoices)
            case .popularCount(let value):
                return Self.notAChoice(popularCountKey, value, popularCountChoices)
            case .popularDays(let value):
                return Self.notAChoice(popularDaysKey, value, popularDayChoices)
            case .popularDaysExceedRetention(let days, let retentionDays):
                return "\(popularDaysKey) \(days) is longer than \(retentionDaysKey) \(retentionDays)"
            }
        }

        private static func notAChoice(_ key: String, _ value: Int, _ choices: [Int]) -> String {
            "\(key) \(value) is not one of \(choices.map(String.init).joined(separator: ", "))"
        }
    }

    /// Reads the keys from a `state.json` document. Missing keys take the
    /// defaults. A present value that is not allowed is rejected, never adjusted.
    public init(config: [String: Any]) throws {
        let fallback = Self.default
        enabled = try Self.bool(config, Self.enabledKey) ?? fallback.enabled
        retentionDays = try Self.int(config, Self.retentionDaysKey) ?? fallback.retentionDays
        popularCount = try Self.int(config, Self.popularCountKey) ?? fallback.popularCount
        popularDays = try Self.int(config, Self.popularDaysKey) ?? fallback.popularDays

        guard Self.retentionDayChoices.contains(retentionDays) else {
            throw ValidationError.retentionDays(retentionDays)
        }
        guard Self.popularCountChoices.contains(popularCount) else {
            throw ValidationError.popularCount(popularCount)
        }
        guard Self.popularDayChoices.contains(popularDays) else {
            throw ValidationError.popularDays(popularDays)
        }
        guard popularDays <= retentionDays else {
            throw ValidationError.popularDaysExceedRetention(days: popularDays, retentionDays: retentionDays)
        }
    }

    public var stateDictionary: [String: Any] {
        [
            Self.enabledKey: enabled,
            Self.retentionDaysKey: retentionDays,
            Self.popularCountKey: popularCount,
            Self.popularDaysKey: popularDays,
        ]
    }

    // `JSONSerialization` stores JSON booleans and numbers as `NSNumber`, and
    // Swift bridges either one to `Bool` and `Int`, so the type is checked on
    // the CF object.
    private static func bool(_ config: [String: Any], _ key: String) throws -> Bool? {
        guard let raw = config[key] else { return nil }
        guard CFGetTypeID(raw as CFTypeRef) == CFBooleanGetTypeID(), let value = raw as? Bool else {
            throw ValidationError.wrongType(key: key)
        }
        return value
    }

    private static func int(_ config: [String: Any], _ key: String) throws -> Int? {
        guard let raw = config[key] else { return nil }
        guard
            CFGetTypeID(raw as CFTypeRef) == CFNumberGetTypeID(),
            let number = raw as? NSNumber,
            !CFNumberIsFloatType(number),
            let value = raw as? Int
        else {
            throw ValidationError.wrongType(key: key)
        }
        return value
    }
}

// MARK: - Requests

/// `range` of a history request: 12 five-minute buckets, 24 hourly, 7 or 30
/// daily, aligned to the local time zone.
public enum QueryHistoryRange: String, Codable, CaseIterable, Sendable {
    case hour = "1h"
    case day = "24h"
    case week = "7d"
    case month = "30d"
}

/// One bar of the Lookups Over Time chart, zoomed in: a day as 24 hourly
/// buckets from a local midnight, or an hour as 12 five-minute buckets from a
/// local hour. The resolver rejects any other `start`.
public struct QueryHistoryZoom: Encodable, Hashable, Sendable {
    public enum Span: String, Encodable, Sendable {
        case hour = "1h"
        case day = "24h"
    }

    public let span: Span
    public let start: Int

    public init(span: Span, start: Int) {
        self.span = span
        self.start = start
    }
}

/// `range` of a history request: the last `QueryHistoryRange` up to now, sent
/// as its string, or a zoomed bar, sent as `{"span", "start"}`.
public enum QueryHistoryPeriod: Encodable, Hashable, Sendable {
    case last(QueryHistoryRange)
    case zoomed(QueryHistoryZoom)

    public func encode(to encoder: Encoder) throws {
        switch self {
        case .last(let range):
            var container = encoder.singleValueContainer()
            try container.encode(range)
        case .zoomed(let zoom):
            try zoom.encode(to: encoder)
        }
    }
}

/// `result` filter. `answered` is NOERROR, `notFound` NXDOMAIN, `failed` a
/// MacDNS SERVFAIL, an invalid request, or SERVFAIL/REFUSED from upstream.
public enum QueryHistoryResultFilter: String, Codable, CaseIterable, Sendable {
    case all
    case answered
    case blocked
    case notFound
    case failed
}

/// One `dns_history_query` request. `utcOffsetSecs` places bucket boundaries in
/// the Mac's time zone.
public struct QueryHistoryRequest: Encodable, Equatable, Sendable {
    /// The largest `limit` the resolver accepts. A larger one is rejected.
    public static let maxLimit = 1000

    public enum Kind: Equatable, Sendable {
        case summary(range: QueryHistoryPeriod)
        case topHosts(range: QueryHistoryPeriod, result: QueryHistoryResultFilter, query: String, limit: Int)
        case hostDetail(range: QueryHistoryPeriod, name: String)
        /// Newest first. The next page passes the last entry's `id` as `beforeId`.
        /// With a `zoom`, only the lookups in that bar. Otherwise every kept one.
        case log(
            result: QueryHistoryResultFilter, query: String, limit: Int, beforeId: Int?, zoom: QueryHistoryZoom? = nil)
        /// `category` is the blocklist tag. `nil` means every category.
        case topBlocked(range: QueryHistoryPeriod, category: String?, limit: Int)
        case status
    }

    public let kind: Kind
    public let utcOffsetSecs: Int

    public init(_ kind: Kind, utcOffsetSecs: Int = TimeZone.current.secondsFromGMT()) {
        self.kind = kind
        self.utcOffsetSecs = utcOffsetSecs
    }

    private enum CodingKeys: String, CodingKey {
        case kind, range, result, query, limit, name, beforeId, category, utcOffsetSecs
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(utcOffsetSecs, forKey: .utcOffsetSecs)
        switch kind {
        case .summary(let range):
            try container.encode("summary", forKey: .kind)
            try container.encode(range, forKey: .range)
        case .topHosts(let range, let result, let query, let limit):
            try container.encode("topHosts", forKey: .kind)
            try container.encode(range, forKey: .range)
            try container.encode(result, forKey: .result)
            try container.encode(query, forKey: .query)
            try container.encode(limit, forKey: .limit)
        case .hostDetail(let range, let name):
            try container.encode("hostDetail", forKey: .kind)
            try container.encode(range, forKey: .range)
            try container.encode(name, forKey: .name)
        case .log(let result, let query, let limit, let beforeId, let zoom):
            try container.encode("log", forKey: .kind)
            try container.encode(result, forKey: .result)
            try container.encode(query, forKey: .query)
            try container.encode(limit, forKey: .limit)
            try container.encode(beforeId, forKey: .beforeId)
            try container.encodeIfPresent(zoom, forKey: .range)
        case .topBlocked(let range, let category, let limit):
            try container.encode("topBlocked", forKey: .kind)
            try container.encode(range, forKey: .range)
            try container.encode(category, forKey: .category)
            try container.encode(limit, forKey: .limit)
        case .status:
            try container.encode("status", forKey: .kind)
        }
    }

    public func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }
}

// MARK: - Responses

/// Every answer carries a `status`. `error` is a bug in the request.
/// `unavailable` is a store fault that may clear up on its own.
public enum QueryHistoryResponse<Payload: Decodable & Equatable>: Decodable, Equatable {
    case ok(Payload)
    case disabled
    case unavailable(reason: String)
    case error(reason: String)

    private enum CodingKeys: String, CodingKey {
        case status, reason
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let status = try container.decode(String.self, forKey: .status)
        switch status {
        case "ok":
            self = .ok(try Payload(from: decoder))
        case "disabled":
            self = .disabled
        case "unavailable":
            self = .unavailable(reason: try container.decode(String.self, forKey: .reason))
        case "error":
            self = .error(reason: try container.decode(String.self, forKey: .reason))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .status,
                in: container,
                debugDescription: "unknown history status \(status)"
            )
        }
    }
}

extension QueryHistoryResponse: Sendable where Payload: Sendable {}

public struct QueryHistorySummary: Decodable, Equatable, Sendable {
    public struct Bucket: Decodable, Equatable, Sendable {
        public let start: Int
        public let cache: Int
        public let provider: Int
        public let blocked: Int
        public let other: Int

        public init(start: Int, cache: Int, provider: Int, blocked: Int, other: Int) {
            self.start = start
            self.cache = cache
            self.provider = provider
            self.blocked = blocked
            self.other = other
        }
    }

    public struct Provider: Decodable, Equatable, Sendable {
        public let name: String
        public let answers: Int
        public let avgLatencyMs: Double

        public init(name: String, answers: Int, avgLatencyMs: Double) {
            self.name = name
            self.answers = answers
            self.avgLatencyMs = avgLatencyMs
        }
    }

    public struct Answers: Decodable, Equatable, Sendable {
        public let answered: Int
        public let blocked: Int
        public let notFound: Int
        public let failed: Int

        public init(answered: Int, blocked: Int, notFound: Int, failed: Int) {
            self.answered = answered
            self.blocked = blocked
            self.notFound = notFound
            self.failed = failed
        }
    }

    public struct FirstSeen: Decodable, Equatable, Sendable {
        public let name: String
        public let firstSeen: Int
        public let count: Int
        public let blocked: Bool

        public init(name: String, firstSeen: Int, count: Int, blocked: Bool) {
            self.name = name
            self.firstSeen = firstSeen
            self.count = count
            self.blocked = blocked
        }
    }

    public struct KeptFresh: Decodable, Equatable, Sendable {
        public let popularCount: Int
        public let inCache: Int
        public let cacheAnswers: Int
        public let refreshesPerSecond: Double

        public init(popularCount: Int, inCache: Int, cacheAnswers: Int, refreshesPerSecond: Double) {
            self.popularCount = popularCount
            self.inCache = inCache
            self.cacheAnswers = cacheAnswers
            self.refreshesPerSecond = refreshesPerSecond
        }
    }

    public let total: Int
    /// `nil` when the previous period is older than the kept history, so there is nothing to compare.
    public let previousTotal: Int?
    public let blocked: Int
    public let cache: Int
    public let provider: Int
    public let avgLatencyMs: Double
    public let avgProviderLatencyMs: Double
    public let series: [Bucket]
    public let providers: [Provider]
    public let answers: Answers
    public let firstSeen: [FirstSeen]
    /// `nil` when popular-host prefetch or Prefetch itself is off.
    public let keptFresh: KeptFresh?
}

public struct QueryHistoryTopHosts: Decodable, Equatable, Sendable {
    public struct Host: Decodable, Equatable, Sendable {
        public let name: String
        public let count: Int
        public let cache: Int
        public let provider: Int
        public let blocked: Int
        public let notFound: Int
        public let failed: Int
        public let lastSeen: Int
        /// Empty unless the host was blocked in the range.
        public let blockRule: String
        public let blockCategory: String

        public init(
            name: String, count: Int, cache: Int, provider: Int, blocked: Int, notFound: Int,
            failed: Int, lastSeen: Int, blockRule: String, blockCategory: String
        ) {
            self.name = name
            self.count = count
            self.cache = cache
            self.provider = provider
            self.blocked = blocked
            self.notFound = notFound
            self.failed = failed
            self.lastSeen = lastSeen
            self.blockRule = blockRule
            self.blockCategory = blockCategory
        }
    }

    /// Hosts matching the filters, before `limit`.
    public let totalHosts: Int
    public let hosts: [Host]
}

public struct QueryHistoryHostDetail: Decodable, Equatable, Sendable {
    public struct Bucket: Decodable, Equatable, Sendable {
        public let start: Int
        public let count: Int

        public init(start: Int, count: Int) {
            self.start = start
            self.count = count
        }
    }

    public struct ProviderCount: Decodable, Equatable, Sendable {
        public let name: String
        public let count: Int

        public init(name: String, count: Int) {
            self.name = name
            self.count = count
        }
    }

    public struct QTypeCount: Decodable, Equatable, Sendable {
        public let qtype: Int
        public let count: Int

        public init(qtype: Int, count: Int) {
            self.qtype = qtype
            self.count = count
        }
    }

    public let name: String
    /// `nil` when the name has no sighting left in the retention.
    public let firstSeen: Int?
    public let lastSeen: Int?
    public let series: [Bucket]
    /// Lookup count per route (`cache`, `provider`, `blocked`, ...).
    public let routes: [String: Int]
    public let providers: [ProviderCount]
    public let qtypes: [QTypeCount]
    public let blockRule: String
    public let blockCategory: String
}

public struct QueryHistoryLog: Decodable, Equatable, Sendable {
    public struct Entry: Decodable, Equatable, Sendable, Identifiable {
        /// Row id, the paging cursor.
        public let id: Int
        public let ts: Int
        public let name: String
        public let qtype: Int
        public let rcode: Int
        public let route: String
        public let provider: String
        public let latencyMs: Double
        public let blockRule: String
        public let blockCategory: String

        public init(
            id: Int, ts: Int, name: String, qtype: Int, rcode: Int, route: String,
            provider: String, latencyMs: Double, blockRule: String, blockCategory: String
        ) {
            self.id = id
            self.ts = ts
            self.name = name
            self.qtype = qtype
            self.rcode = rcode
            self.route = route
            self.provider = provider
            self.latencyMs = latencyMs
            self.blockRule = blockRule
            self.blockCategory = blockCategory
        }
    }

    public let entries: [Entry]
}

public struct QueryHistoryTopBlocked: Decodable, Equatable, Sendable {
    public struct Domain: Decodable, Equatable, Sendable {
        public let domain: String
        public let matchedRule: String
        /// The blocklist tag, decoded with `BlocklistCategory.fromIdentifier`.
        public let category: String
        public let blockCount: Int

        public init(domain: String, matchedRule: String, category: String, blockCount: Int) {
            self.domain = domain
            self.matchedRule = matchedRule
            self.category = category
            self.blockCount = blockCount
        }
    }

    public let domains: [Domain]

    public init(domains: [Domain]) {
        self.domains = domains
    }

    /// Activity rows. A tag no category recognizes is skipped.
    public var blockedDomains: [BlockedDomain] {
        domains.compactMap { entry in
            BlocklistCategory.fromIdentifier(entry.category).map {
                BlockedDomain(
                    domain: entry.domain,
                    matchedRule: entry.matchedRule,
                    category: $0,
                    blockCount: entry.blockCount
                )
            }
        }
    }
}

public struct QueryHistoryStatus: Decodable, Equatable, Sendable {
    public let enabled: Bool
    public let sizeBytes: Int
    public let droppedEvents: Int
    public let retentionDays: Int

    public init(enabled: Bool, sizeBytes: Int, droppedEvents: Int, retentionDays: Int) {
        self.enabled = enabled
        self.sizeBytes = sizeBytes
        self.droppedEvents = droppedEvents
        self.retentionDays = retentionDays
    }
}
