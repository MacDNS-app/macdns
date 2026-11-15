// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNS

/// The App side of lookup history: how the settings change together, how a
/// history answer becomes what a page shows, and how Clear History reports.
final class QueryHistoryViewModelTests: XCTestCase {

    // MARK: - Retention and look-back

    func testLoweringRetentionBelowTheLookBackShortensTheLookBackInTheSameValue() throws {
        let settings = QueryHistorySettings(enabled: true, retentionDays: 30, popularCount: 500, popularDays: 14)

        let changed = settings.withRetentionDays(7)

        XCTAssertEqual(
            changed,
            QueryHistorySettings(enabled: true, retentionDays: 7, popularCount: 500, popularDays: 7)
        )
        XCTAssertEqual(try QueryHistorySettings(config: changed.stateDictionary), changed)
    }

    func testLoweringRetentionKeepsALookBackThatStillFits() {
        let settings = QueryHistorySettings(enabled: true, retentionDays: 90, popularCount: 100, popularDays: 7)

        XCTAssertEqual(settings.withRetentionDays(14).popularDays, 7)
        XCTAssertEqual(settings.withRetentionDays(14).retentionDays, 14)
    }

    func testRaisingRetentionKeepsTheLookBack() {
        let settings = QueryHistorySettings(enabled: true, retentionDays: 7, popularCount: 0, popularDays: 7)

        XCTAssertEqual(settings.withRetentionDays(90).popularDays, 7)
    }

    func testEveryRetentionChangeFromAValidValueStaysValid() throws {
        for retention in QueryHistorySettings.retentionDayChoices {
            for days in QueryHistorySettings.popularDayChoices where days <= retention {
                let settings = QueryHistorySettings(
                    enabled: true, retentionDays: retention, popularCount: 250, popularDays: days)
                for newRetention in QueryHistorySettings.retentionDayChoices {
                    let changed = settings.withRetentionDays(newRetention)
                    XCTAssertEqual(
                        try QueryHistorySettings(config: changed.stateDictionary), changed,
                        "\(retention)/\(days) -> \(newRetention)")
                    XCTAssertEqual(changed.retentionDays, newRetention)
                    XCTAssertEqual(changed.popularCount, 250)
                }
            }
        }
    }

    func testLookBackMenuOffersOnlyChoicesWithinTheRetention() {
        func choices(_ retention: Int) -> [Int] {
            QueryHistorySettings(enabled: true, retentionDays: retention, popularCount: 0, popularDays: 1)
                .popularDayChoicesWithinRetention
        }

        XCTAssertEqual(choices(7), [1, 7])
        XCTAssertEqual(choices(14), [1, 7, 14])
        XCTAssertEqual(choices(30), [1, 7, 14, 30])
        XCTAssertEqual(choices(90), [1, 7, 14, 30])
    }

    func testPersistedReadTakesDefaultsForMissingKeys() {
        XCTAssertEqual(QueryHistorySettings.persisted(in: ["prefetchEnabled": true]), .default)
    }

    func testPersistedReadKeepsStoredValuesVerbatim() {
        let config: [String: Any] = [
            "queryHistoryEnabled": false,
            "queryHistoryRetentionDays": 14,
            "popularPrefetchCount": 1000,
            "popularPrefetchDays": 14,
        ]

        XCTAssertEqual(
            QueryHistorySettings.persisted(in: config),
            QueryHistorySettings(enabled: false, retentionDays: 14, popularCount: 1000, popularDays: 14)
        )
    }

    // MARK: - Loading

    func testOkAnswerIsLoaded() {
        let status = QueryHistoryStatus(enabled: true, sizeBytes: 10, droppedEvents: 0, retentionDays: 30)

        XCTAssertEqual(QueryHistoryLoad(.success(.ok(status))), .loaded(status))
    }

    func testDisabledAndUnavailableAnswersKeepTheirMeaning() {
        XCTAssertEqual(
            QueryHistoryLoad<QueryHistoryStatus>(.success(.disabled)),
            .disabled
        )
        XCTAssertEqual(
            QueryHistoryLoad<QueryHistoryStatus>(.success(.unavailable(reason: "disk full"))),
            .unavailable(reason: "disk full")
        )
    }

    func testCallerErrorAndTransportFailureAreAGenericFailure() {
        XCTAssertEqual(
            QueryHistoryLoad<QueryHistoryStatus>(.success(.error(reason: "unknown kind"))),
            .failed
        )
        XCTAssertEqual(QueryHistoryLoad<QueryHistoryStatus>(.failure(.timeout)), .failed)
        XCTAssertEqual(QueryHistoryLoad<QueryHistoryStatus>(.failure(.agentNotResponding)), .failed)
    }

    // MARK: - Paging

    func testShowMoreHostsStepsByFiftyAndStopsAtTheRequestCap() {
        var limits: [Int] = []
        var shown = 10
        while let next = QueriesPaging.nextHostLimit(shown: shown, totalHosts: 5000) {
            XCTAssertLessThanOrEqual(next, QueryHistoryRequest.maxLimit)
            limits.append(next)
            shown = next
        }

        XCTAssertEqual(limits.first, 60)
        XCTAssertEqual(limits.suffix(2), [960, 1000])
        XCTAssertEqual(shown, QueryHistoryRequest.maxLimit)
    }

    func testShowMoreHostsEndsWhenEveryHostIsShown() {
        XCTAssertEqual(QueriesPaging.nextHostLimit(shown: 10, totalHosts: 35), 60)
        XCTAssertNil(QueriesPaging.nextHostLimit(shown: 35, totalHosts: 35))
        XCTAssertNil(QueriesPaging.nextHostLimit(shown: 1000, totalHosts: 1284))
    }

    func testNewerLookupsArePrependedToTheLoadedLog() {
        let loaded = entries(ids: [8, 7, 6, 5, 4])

        let merged = QueriesPaging.mergingNewestLog(entries(ids: [10, 9, 8, 7]), into: loaded)

        XCTAssertEqual(merged?.map(\.id), [10, 9, 8, 7, 6, 5, 4])
    }

    func testRefreshWithoutNewLookupsKeepsTheLoadedLog() {
        let loaded = entries(ids: [8, 7, 6, 5, 4])

        XCTAssertEqual(QueriesPaging.mergingNewestLog(entries(ids: [8, 7, 6]), into: loaded), loaded)
    }

    func testNewestPageThatDoesNotReachTheLoadedLogIsNotMerged() {
        let loaded = entries(ids: [8, 7, 6])

        XCTAssertNil(QueriesPaging.mergingNewestLog(entries(ids: [12, 11, 10]), into: loaded))
        XCTAssertNil(QueriesPaging.mergingNewestLog([], into: loaded))
    }

    func testNewestPageFillsAnEmptyLog() {
        XCTAssertEqual(QueriesPaging.mergingNewestLog(entries(ids: [3, 2]), into: [])?.map(\.id), [3, 2])
    }

    func testShortIntervalRefreshesStackNewerLookupsOnTopAndKeepOlderPages() throws {
        // Two pages loaded, then three one-second ticks: two new lookups, none, one.
        var loaded = entries(ids: Array((1...400).reversed()))

        for newestId in [402, 402, 403] {
            let newest = entries(ids: Array((newestId - QueryHistoryRequest.maxLimit + 1...newestId).reversed()))
            loaded = try XCTUnwrap(QueriesPaging.mergingNewestLog(newest, into: loaded))
        }

        XCTAssertEqual(loaded.prefix(4).map(\.id), [403, 402, 401, 400])
        XCTAssertEqual(loaded.count, 403)
        XCTAssertEqual(loaded.last?.id, 1)
    }

    func testOlderLookupsAreAskedWithTheFiltersTheListCameFrom() {
        let filter = QueriesLogFilter(result: .blocked, query: "ads")

        XCTAssertEqual(
            QueriesPaging.olderLogRequest(beforeId: 42, pageSize: 200, loadedWith: filter, current: filter),
            QueryHistoryRequest(.log(result: .blocked, query: "ads", limit: 200, beforeId: 42)))
    }

    func testOlderLookupsWaitWhileTheListIsStillFromOtherFilters() {
        let loadedWith = QueriesLogFilter(result: .all, query: "")

        for current in [
            QueriesLogFilter(result: .blocked, query: ""), QueriesLogFilter(result: .all, query: "ads"),
        ] {
            XCTAssertNil(
                QueriesPaging.olderLogRequest(beforeId: 42, pageSize: 200, loadedWith: loadedWith, current: current))
        }
        XCTAssertNil(QueriesPaging.olderLogRequest(beforeId: 42, pageSize: 200, loadedWith: nil, current: loadedWith))
    }

    func testOlderLookupsOfAZoomedPeriodStayInThatPeriod() {
        let zoom = QueryHistoryZoom(span: .hour, start: 1_762_506_000)
        let filter = QueriesLogFilter(result: .all, query: "", zoom: zoom)

        XCTAssertEqual(
            QueriesPaging.olderLogRequest(beforeId: 42, pageSize: 200, loadedWith: filter, current: filter),
            QueryHistoryRequest(.log(result: .all, query: "", limit: 200, beforeId: 42, zoom: zoom)))
    }

    func testZoomingInOrResettingReloadsTheLogFromTheTop() {
        let unzoomed = QueriesLogFilter(result: .all, query: "")
        let zoomed = QueriesLogFilter(result: .all, query: "", zoom: QueryHistoryZoom(span: .day, start: 0))

        for (loadedWith, current) in [(unzoomed, zoomed), (zoomed, unzoomed)] {
            XCTAssertFalse(
                QueriesPaging.addsNewerLog(
                    isAutomatic: true, loadedCount: 400, pageSize: 200, loadedWith: loadedWith, current: current))
            XCTAssertNil(
                QueriesPaging.olderLogRequest(beforeId: 42, pageSize: 200, loadedWith: loadedWith, current: current))
        }
    }

    // MARK: - Automatic refresh

    func testRefreshIntervalChoicesRunFromOneToSixtySeconds() {
        XCTAssertEqual(QueriesAutoRefresh.intervalChoices, [1, 2, 5, 10, 30, 60])
    }

    func testDefaultRefreshIntervalIsFiveSeconds() {
        XCTAssertEqual(QueriesAutoRefresh.defaultInterval, 5)
        XCTAssertTrue(QueriesAutoRefresh.intervalChoices.contains(QueriesAutoRefresh.defaultInterval))
    }

    func testLogRequestCarriesTheFilters() {
        let filter = QueriesLogFilter(result: .blocked, query: "ads")

        XCTAssertEqual(
            filter.request(limit: 200, beforeId: 42),
            QueryHistoryRequest(.log(result: .blocked, query: "ads", limit: 200, beforeId: 42)))
        XCTAssertEqual(
            filter.request(limit: QueryHistoryRequest.maxLimit),
            QueryHistoryRequest(.log(result: .blocked, query: "ads", limit: QueryHistoryRequest.maxLimit, beforeId: nil)))
    }

    func testAutomaticRefreshAddsNewerLookupsOnTopOfOlderPagesLoadedWithTheCurrentFilters() {
        let filter = QueriesLogFilter(result: .blocked, query: "ads")

        XCTAssertTrue(
            QueriesPaging.addsNewerLog(
                isAutomatic: true, loadedCount: 400, pageSize: 200, loadedWith: filter, current: filter))
    }

    func testAutomaticRefreshReloadsTheFirstPageWhenTheFiltersChanged() {
        let loadedWith = QueriesLogFilter(result: .all, query: "")

        for current in [
            QueriesLogFilter(result: .blocked, query: ""), QueriesLogFilter(result: .all, query: "ads"),
        ] {
            XCTAssertFalse(
                QueriesPaging.addsNewerLog(
                    isAutomatic: true, loadedCount: 400, pageSize: 200, loadedWith: loadedWith, current: current))
        }
    }

    func testRefreshReloadsTheFirstPageWithoutOlderPagesOrWhenNotAutomatic() {
        let filter = QueriesLogFilter(result: .all, query: "")

        XCTAssertFalse(
            QueriesPaging.addsNewerLog(
                isAutomatic: true, loadedCount: 200, pageSize: 200, loadedWith: filter, current: filter))
        XCTAssertFalse(
            QueriesPaging.addsNewerLog(
                isAutomatic: false, loadedCount: 400, pageSize: 200, loadedWith: filter, current: filter))
        XCTAssertFalse(
            QueriesPaging.addsNewerLog(
                isAutomatic: true, loadedCount: 400, pageSize: 200, loadedWith: nil, current: filter))
    }

    // MARK: - Clear History

    func testSuccessfulClearReportsNoFailureAndAsksPagesToReload() {
        var state = QueryHistoryClearState()

        XCTAssertTrue(state.begin())
        XCTAssertTrue(state.isClearing)
        state.finish(.success(true))

        XCTAssertFalse(state.isClearing)
        XCTAssertNil(state.failureMessage)
        XCTAssertEqual(state.finishedCount, 1)
    }

    func testRefusedClearIsReported() {
        var state = QueryHistoryClearState()

        _ = state.begin()
        state.finish(.success(false))

        XCTAssertFalse(state.isClearing)
        XCTAssertNotNil(state.failureMessage)
        XCTAssertEqual(state.finishedCount, 1, "pages reload so they show what is really left")
    }

    func testUnansweredClearIsReported() {
        var state = QueryHistoryClearState()

        _ = state.begin()
        state.finish(.failure(.timeout))

        XCTAssertFalse(state.isClearing)
        XCTAssertNotNil(state.failureMessage)
    }

    func testSecondClearWhileOneRunsIsRefused() {
        var state = QueryHistoryClearState()

        XCTAssertTrue(state.begin())
        XCTAssertFalse(state.begin())
    }

    func testNewClearDropsThePreviousFailure() {
        var state = QueryHistoryClearState()
        _ = state.begin()
        state.finish(.success(false))

        XCTAssertTrue(state.begin())

        XCTAssertNil(state.failureMessage)
    }

    func testDismissingTheFailureKeepsTheCount() {
        var state = QueryHistoryClearState()
        _ = state.begin()
        state.finish(.failure(.agentNotResponding))

        state.dismissFailure()

        XCTAssertNil(state.failureMessage)
        XCTAssertEqual(state.finishedCount, 1)
    }

    private func entries(ids: [Int]) -> [QueryHistoryLog.Entry] {
        ids.map {
            QueryHistoryLog.Entry(
                id: $0, ts: 1_762_500_000 + $0, name: "host\($0).example", qtype: 1, rcode: 0, route: "cache",
                provider: "", latencyMs: 0.2, blockRule: "", blockCategory: "")
        }
    }
}
