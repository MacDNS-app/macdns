// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

extension QueryHistorySettings {
    /// Reads the keys the way the agent's `loadResolverOptions` does. A stored
    /// value is shown as it is. The agent rejects an invalid save, so nothing
    /// here adjusts it.
    static func persisted(in config: [String: Any]) -> QueryHistorySettings {
        QueryHistorySettings(
            enabled: config[enabledKey] as? Bool ?? Self.default.enabled,
            retentionDays: config[retentionDaysKey] as? Int ?? Self.default.retentionDays,
            popularCount: config[popularCountKey] as? Int ?? Self.default.popularCount,
            popularDays: config[popularDaysKey] as? Int ?? Self.default.popularDays
        )
    }

    /// The look-back can never be longer than the retention.
    var popularDayChoicesWithinRetention: [Int] {
        Self.popularDayChoices.filter { $0 <= retentionDays }
    }

    /// A shorter retention also shortens a look-back that no longer fits, to the
    /// longest one that does, so both change in one save and the pair stays valid.
    func withRetentionDays(_ days: Int) -> QueryHistorySettings {
        var changed = self
        changed.retentionDays = days
        if changed.popularDays > days {
            changed.popularDays = changed.popularDayChoicesWithinRetention.last ?? popularDays
        }
        return changed
    }
}

/// What a page shows for one history request.
enum QueryHistoryLoad<Payload: Equatable>: Equatable {
    case loaded(Payload)
    /// History is off in Advanced.
    case disabled
    /// The store cannot be read. The reason comes from the resolver.
    case unavailable(reason: String)
    /// The agent did not answer, or rejected the request. A rejection is a bug
    /// in the App, so the page shows a generic failure and the log has the reason.
    case failed

    init(_ result: Result<QueryHistoryResponse<Payload>, XPCError>) where Payload: Decodable {
        let logger = AppLogger.shared.viewModel
        switch result {
        case .success(.ok(let payload)):
            self = .loaded(payload)
        case .success(.disabled):
            self = .disabled
        case .success(.unavailable(let reason)):
            self = .unavailable(reason: reason)
        case .success(.error(let reason)):
            logger.error("Lookup history rejected the request: \(reason, privacy: .public)")
            self = .failed
        case .failure(let error):
            logger.error("Lookup history request failed: \(error.localizedDescription, privacy: .public)")
            self = .failed
        }
    }

    var payload: Payload? {
        if case .loaded(let payload) = self { return payload }
        return nil
    }

    func map<Other: Equatable>(_ transform: (Payload) -> Other) -> QueryHistoryLoad<Other> {
        switch self {
        case .loaded(let payload): return .loaded(transform(payload))
        case .disabled: return .disabled
        case .unavailable(let reason): return .unavailable(reason: reason)
        case .failed: return .failed
        }
    }
}

/// How the Queries page asks for more rows.
enum QueriesPaging {
    static let hostStep = 50

    /// The Top Hosts limit after Show More, or `nil` when every host is shown
    /// or the limit is already the most the resolver accepts.
    static func nextHostLimit(shown: Int, totalHosts: Int) -> Int? {
        guard shown < totalHosts, shown < QueryHistoryRequest.maxLimit else { return nil }
        return min(shown + hostStep, QueryHistoryRequest.maxLimit)
    }

    /// The loaded log with the lookups from `newest` that came after it on top.
    /// `nil` when `newest` does not reach the loaded rows, so lookups between
    /// them would be missing. The caller then keeps what it has.
    static func mergingNewestLog(
        _ newest: [QueryHistoryLog.Entry], into loaded: [QueryHistoryLog.Entry]
    ) -> [QueryHistoryLog.Entry]? {
        guard let loadedNewest = loaded.first else { return newest }
        let newer = newest.prefix { $0.id > loadedNewest.id }
        guard newer.count < newest.count else { return nil }
        return Array(newer) + loaded
    }

    /// Whether an automatic refresh adds newer lookups on top of the loaded log
    /// instead of reloading its first page. Only older pages the user loaded are
    /// worth keeping, and only while they match the filters on screen.
    static func addsNewerLog(
        isAutomatic: Bool, loadedCount: Int, pageSize: Int, loadedWith: QueriesLogFilter?, current: QueriesLogFilter
    ) -> Bool {
        isAutomatic && loadedCount > pageSize && loadedWith == current
    }

    /// The next page of older lookups, asked with the filters the list came from.
    /// `nil` while the filters on screen differ, because a reload for them is
    /// coming and older rows from either filter would not belong to it.
    static func olderLogRequest(
        beforeId: Int, pageSize: Int, loadedWith: QueriesLogFilter?, current: QueriesLogFilter
    ) -> QueryHistoryRequest? {
        guard let loadedWith, loadedWith == current else { return nil }
        return loadedWith.request(limit: pageSize, beforeId: beforeId)
    }
}

/// The filters a list of lookups is loaded with.
struct QueriesLogFilter: Equatable {
    var result: QueryHistoryResultFilter
    var query: String
    var zoom: QueryHistoryZoom? = nil

    func request(limit: Int, beforeId: Int? = nil) -> QueryHistoryRequest {
        QueryHistoryRequest(.log(result: result, query: query, limit: limit, beforeId: beforeId, zoom: zoom))
    }
}

/// The period the Queries page shows: the last `range`, or one bar of the
/// chart zoomed in.
struct QueriesPeriod: Equatable {
    /// The resolver keeps single lookups, and so five-minute detail, this long.
    static let singleLookupDays = 7

    let range: QueryHistoryRange
    let zoom: QueryHistoryZoom?

    init(range: QueryHistoryRange, zoom: QueryHistoryZoom? = nil) {
        self.range = range
        self.zoom = zoom
    }

    var request: QueryHistoryPeriod {
        zoom.map(QueryHistoryPeriod.zoomed) ?? .last(range)
    }

    /// The range with the same buckets: a zoomed day has hourly ones like
    /// 24H, a zoomed hour five-minute ones like 1H.
    var bucketRange: QueryHistoryRange {
        switch zoom?.span {
        case nil: return range
        case .day: return .day
        case .hour: return .hour
        }
    }

    /// What a click on the bar starting at `bucketStart` zooms into: a day of
    /// 7D or 30D, or an hour of 24H or of a zoomed day. `nil` for a
    /// five-minute bar, a bar that has not started, and an hour whose single
    /// lookups are already gone.
    func zoom(into bucketStart: Int, now: Int) -> QueryHistoryZoom? {
        guard bucketStart <= now else { return nil }
        switch bucketRange {
        case .week, .month:
            return QueryHistoryZoom(span: .day, start: bucketStart)
        case .day:
            guard bucketStart >= now - Self.singleLookupDays * 86_400 else { return nil }
            return QueryHistoryZoom(span: .hour, start: bucketStart)
        case .hour:
            return nil
        }
    }
}

/// How often the Queries page reloads itself while it is on screen. The choice
/// lasts for the app run and is never saved.
enum QueriesAutoRefresh {
    static let intervalChoices = [1, 2, 5, 10, 30, 60]
    static let defaultInterval = 5
}

/// Clear History, shared by Queries, Activity and Advanced.
struct QueryHistoryClearState: Equatable {
    private(set) var isClearing = false
    private(set) var failureMessage: String?
    /// Counts finished clears, whatever the outcome, so visible pages reload what the agent now has.
    private(set) var finishedCount = 0

    mutating func begin() -> Bool {
        guard !isClearing else { return false }
        isClearing = true
        failureMessage = nil
        return true
    }

    mutating func finish(_ result: Result<Bool, XPCError>) {
        isClearing = false
        finishedCount += 1
        switch result {
        case .success(true):
            failureMessage = nil
        case .success(false):
            failureMessage = "MacDNS couldn't delete the lookup history. Try again in a moment."
        case .failure:
            failureMessage = "MacDNS didn't respond, so the lookup history may not be deleted. Try again in a moment."
        }
    }

    mutating func dismissFailure() {
        failureMessage = nil
    }
}

/// Tracks Activity's top-blocked loads so automatic ticks neither overlap nor
/// toggle the toolbar spinner, and unchanged rows do not republish.
struct ActivityStatsRefreshState: Equatable {
    private(set) var domains: [BlockedDomain] = []
    private(set) var isLoading = false
    private(set) var issue: QueryHistoryLoad<[BlockedDomain]>?
    private var inFlight = false
    private var generation: UInt64 = 0

    /// Starts a load and returns its generation, or `nil` when an automatic
    /// tick finds another load already running.
    mutating func begin(isAutomatic: Bool) -> UInt64? {
        if isAutomatic && inFlight { return nil }
        inFlight = true
        if !isAutomatic { isLoading = true }
        generation &+= 1
        return generation
    }

    /// Applies `load` when `loadGeneration` is still current. Returns whether
    /// `domains` changed in displayed content.
    @discardableResult
    mutating func finish(
        _ load: QueryHistoryLoad<[BlockedDomain]>,
        for loadGeneration: UInt64
    ) -> Bool {
        guard loadGeneration == generation else { return false }
        inFlight = false
        isLoading = false
        let nextDomains = load.payload ?? []
        let nextIssue = load.payload == nil ? load : nil
        let domainsChanged = !Self.sameRows(domains, nextDomains)
        if domainsChanged {
            domains = nextDomains
        }
        if issue != nextIssue {
            issue = nextIssue
        }
        return domainsChanged
    }

    private static func sameRows(_ lhs: [BlockedDomain], _ rhs: [BlockedDomain]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return zip(lhs, rhs).allSatisfy { left, right in
            left.domain == right.domain
                && left.matchedRule == right.matchedRule
                && left.category == right.category
                && left.blockCount == right.blockCount
        }
    }
}
