// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

/// What the Queries page has loaded from the lookup history. Every request goes
/// through the agent, and an answer to a superseded request is dropped.
@MainActor
final class QueriesModel: ObservableObject {
    enum Mode: String, CaseIterable {
        case summary = "Summary"
        case log = "Log"
    }

    static let hostPageSize = 10
    static let logPageSize = 200

    @Published var mode: Mode = .summary
    @Published var range: QueryHistoryRange = .day {
        didSet { if range != oldValue { zoom = nil } }
    }
    /// The chart bar the page is zoomed into, for Summary and Log alike.
    @Published var zoom: QueryHistoryZoom?

    @Published private(set) var summary: QueryHistoryLoad<QueryHistorySummary>?
    @Published private(set) var hosts: QueryHistoryLoad<QueryHistoryTopHosts>?
    @Published private(set) var hostDetail: QueryHistoryLoad<QueryHistoryHostDetail>?
    @Published private(set) var log: QueryHistoryLoad<[QueryHistoryLog.Entry]>?
    @Published private(set) var logHasMore = false

    @Published var hostQuery = "" {
        didSet { if hostQuery != oldValue { scheduleHostsReload() } }
    }
    @Published var hostResult: QueryHistoryResultFilter = .all {
        didSet { if hostResult != oldValue { scheduleHostsReload() } }
    }
    @Published var hostLimit = QueriesModel.hostPageSize {
        didSet { if hostLimit != oldValue { scheduleHostsReload() } }
    }
    @Published var expandedHost: String? {
        didSet {
            guard expandedHost != oldValue else { return }
            hostDetail = nil
            Task { await loadHostDetail() }
        }
    }
    @Published var logQuery = "" {
        didSet { if logQuery != oldValue { scheduleLogReload() } }
    }
    @Published var logResult: QueryHistoryResultFilter = .all {
        didSet { if logResult != oldValue { scheduleLogReload() } }
    }

    private enum Slot { case summary, hosts, detail, log }
    private var tokens: [Slot: Int] = [:]
    private var requestsInFlight = 0
    private var logLoadedWith: QueriesLogFilter?
    private var hostsReload: Task<Void, Never>?
    private var logReload: Task<Void, Never>?

    /// True while any history request of this page runs, so an automatic
    /// refresh can skip a tick instead of starting a second one.
    var isLoading: Bool { requestsInFlight > 0 }

    var period: QueriesPeriod { QueriesPeriod(range: range, zoom: zoom) }

    private var logFilter: QueriesLogFilter { QueriesLogFilter(result: logResult, query: logQuery, zoom: zoom) }

    /// Zooms into the chart bar starting at `bucketStart` when it has a finer view.
    func zoomIn(at bucketStart: Int) {
        if let next = period.zoom(into: bucketStart, now: Int(Date().timeIntervalSince1970)) { zoom = next }
    }

    /// Reloads what the current mode shows. An automatic refresh keeps older
    /// log pages the user loaded and only adds newer lookups on top.
    func refresh(isAutomatic: Bool) async {
        switch mode {
        case .summary:
            async let summary: Void = loadSummary()
            async let hosts: Void = loadHosts()
            async let detail: Void = loadHostDetail()
            _ = await (summary, hosts, detail)
        case .log:
            let addsNewer = QueriesPaging.addsNewerLog(
                isAutomatic: isAutomatic, loadedCount: log?.payload?.count ?? 0, pageSize: Self.logPageSize,
                loadedWith: logLoadedWith, current: logFilter)
            if addsNewer {
                await addNewerLog()
            } else {
                await loadLog(limit: Self.logPageSize)
            }
        }
    }

    func loadMoreLog() async {
        guard case .loaded(let entries) = log, let last = entries.last,
            let request = QueriesPaging.olderLogRequest(
                beforeId: last.id, pageSize: Self.logPageSize, loadedWith: logLoadedWith, current: logFilter)
        else { return }
        guard let page = await fetch(.log, request, as: QueryHistoryLog.self) else { return }
        switch page {
        case .loaded(let next):
            log = .loaded(entries + next.entries)
            logHasMore = next.entries.count == Self.logPageSize
        default:
            log = page.map(\.entries)
            logHasMore = false
        }
    }

    /// Older pages stay as they are. When even the largest newest page does not
    /// reach the loaded rows, the list is kept until the next reload from the top.
    private func addNewerLog() async {
        let request = logFilter.request(limit: QueryHistoryRequest.maxLimit)
        guard let load = await fetch(.log, request, as: QueryHistoryLog.self) else { return }
        guard case .loaded(let newest) = load, case .loaded(let loaded) = log else {
            log = load.map(\.entries)
            logHasMore = false
            return
        }
        if let merged = QueriesPaging.mergingNewestLog(newest.entries, into: loaded) {
            log = .loaded(merged)
        }
    }

    private func loadSummary() async {
        let request = QueryHistoryRequest(.summary(range: period.request))
        if let load = await fetch(.summary, request, as: QueryHistorySummary.self) { summary = load }
    }

    private func loadHosts() async {
        let request = QueryHistoryRequest(
            .topHosts(range: period.request, result: hostResult, query: hostQuery, limit: hostLimit))
        if let load = await fetch(.hosts, request, as: QueryHistoryTopHosts.self) { hosts = load }
    }

    private func loadHostDetail() async {
        guard let name = expandedHost else { return }
        let request = QueryHistoryRequest(.hostDetail(range: period.request, name: name))
        if let load = await fetch(.detail, request, as: QueryHistoryHostDetail.self) { hostDetail = load }
    }

    private func loadLog(limit: Int) async {
        let filter = logFilter
        guard let load = await fetch(.log, filter.request(limit: limit), as: QueryHistoryLog.self) else { return }
        log = load.map(\.entries)
        logLoadedWith = filter
        logHasMore = load.payload?.entries.count == limit
    }

    /// Typing in a filter field waits for a short pause before asking again.
    private func scheduleHostsReload() {
        hostsReload?.cancel()
        hostsReload = Task {
            try? await Task.sleep(for: .milliseconds(250))
            guard !Task.isCancelled else { return }
            await loadHosts()
        }
    }

    private func scheduleLogReload() {
        logReload?.cancel()
        logReload = Task {
            try? await Task.sleep(for: .milliseconds(250))
            guard !Task.isCancelled else { return }
            await loadLog(limit: Self.logPageSize)
        }
    }

    /// `nil` when a newer request for the same slot started while this one ran.
    private func fetch<Payload: Decodable & Equatable & Sendable>(
        _ slot: Slot, _ request: QueryHistoryRequest, as type: Payload.Type
    ) async -> QueryHistoryLoad<Payload>? {
        let token = (tokens[slot] ?? 0) + 1
        tokens[slot] = token
        requestsInFlight += 1
        defer { requestsInFlight -= 1 }
        let result = await XPCClient.shared.queryHistory(request, as: type)
        guard tokens[slot] == token else { return nil }
        return QueryHistoryLoad(result)
    }
}
