// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI
import XCTest

@testable import MacDNS

/// How Queries turns history rows into words. The result rules follow the
/// `result` filter of the history contract, so a row and its filter agree.
final class QueriesPresentationTests: XCTestCase {
    func testOutcomeFollowsTheResultFilterRules() {
        XCTAssertEqual(QueryOutcome(route: "cache", rcode: 0), .answered)
        XCTAssertEqual(QueryOutcome(route: "provider", rcode: 0), .answered)
        XCTAssertEqual(QueryOutcome(route: "blocked", rcode: 0), .blocked)
        XCTAssertEqual(QueryOutcome(route: "blocked", rcode: 3), .blocked)
        XCTAssertEqual(QueryOutcome(route: "provider", rcode: 3), .notFound)
        XCTAssertEqual(QueryOutcome(route: "local", rcode: 3), .notFound)
        XCTAssertEqual(QueryOutcome(route: "failed", rcode: 2), .failed)
        XCTAssertEqual(QueryOutcome(route: "invalid", rcode: 1), .failed)
        XCTAssertEqual(QueryOutcome(route: "forward", rcode: 2), .failed)
        XCTAssertEqual(QueryOutcome(route: "provider", rcode: 5), .failed)
    }

    func testHostOutcomeIsTheMostCommonResult() {
        XCTAssertEqual(QueryOutcome.dominant(in: host(count: 10, blocked: 0, notFound: 0, failed: 0)), .answered)
        XCTAssertEqual(QueryOutcome.dominant(in: host(count: 10, blocked: 10, notFound: 0, failed: 0)), .blocked)
        XCTAssertEqual(QueryOutcome.dominant(in: host(count: 10, blocked: 0, notFound: 7, failed: 0)), .notFound)
        XCTAssertEqual(QueryOutcome.dominant(in: host(count: 10, blocked: 0, notFound: 2, failed: 6)), .failed)
    }

    func testAnsweredByNamesTheSourceInPlainWords() {
        XCTAssertEqual(QueriesFormat.answeredBy(route: "cache", provider: "Cloudflare"), "Cache")
        XCTAssertEqual(QueriesFormat.answeredBy(route: "provider", provider: "Quad9"), "Quad9")
        XCTAssertEqual(QueriesFormat.answeredBy(route: "provider", provider: ""), "Provider")
        XCTAssertEqual(QueriesFormat.answeredBy(route: "blocked", provider: ""), "Blocklist")
        XCTAssertEqual(QueriesFormat.answeredBy(route: "override", provider: ""), "Local Record")
        XCTAssertEqual(QueriesFormat.answeredBy(route: "forward", provider: ""), "Forward Zone")
        XCTAssertEqual(QueriesFormat.answeredBy(route: "somethingNew", provider: ""), "somethingNew")
    }

    func testAnswerSourcesNameProvidersAndKeepTheBiggestThree() {
        let text = QueriesFormat.answerSources(
            routes: ["cache": 60, "provider": 30, "stale": 6, "blocked": 4],
            providers: [.init(name: "Cloudflare", count: 20), .init(name: "Quad9", count: 10)]
        )

        XCTAssertEqual(text, "Cache 60% · Cloudflare 20% · Quad9 10%")
    }

    func testRecordTypeNames() {
        XCTAssertEqual(QueriesFormat.recordType(1), "A")
        XCTAssertEqual(QueriesFormat.recordType(28), "AAAA")
        XCTAssertEqual(QueriesFormat.recordType(65), "HTTPS")
        XCTAssertEqual(QueriesFormat.recordType(999), "TYPE999")
    }

    func testPeriodChangeComparesWithThePreviousPeriod() {
        let day = QueriesPeriod(range: .day)
        XCTAssertEqual(QueriesFormat.periodChange(total: 106, previous: 100, period: day), "↑ 6% vs previous")
        XCTAssertEqual(QueriesFormat.periodChange(total: 97, previous: 100, period: day), "↓ 3% vs previous")
        XCTAssertEqual(QueriesFormat.periodChange(total: 100, previous: 100, period: day), "Same as previous")
        XCTAssertEqual(QueriesFormat.periodChange(total: 40, previous: 0, period: day), "None in previous")
    }

    func testPeriodChangeWithoutAPreviousPeriodNamesThePeriod() {
        XCTAssertEqual(QueriesFormat.periodChange(total: 40, previous: nil, period: .init(range: .month)), "last 30 days")
        XCTAssertEqual(QueriesFormat.periodChange(total: 40, previous: nil, period: .init(range: .hour)), "last hour")
        let zoomedDay = QueriesPeriod(range: .month, zoom: QueryHistoryZoom(span: .day, start: 0))
        XCTAssertEqual(QueriesFormat.periodChange(total: 40, previous: nil, period: zoomedDay), "this day")
    }

    func testAverageResponseSwitchesToSecondsFromOneSecond() {
        XCTAssertEqual(QueriesFormat.milliseconds(7.44), "7.4 ms")
        XCTAssertEqual(QueriesFormat.milliseconds(24.4), "24 ms")
        XCTAssertEqual(QueriesFormat.milliseconds(999.4), "999 ms")
        XCTAssertEqual(QueriesFormat.milliseconds(999.6), "1.0 s")
        XCTAssertEqual(QueriesFormat.milliseconds(5012), "5.0 s")
        XCTAssertEqual(QueriesFormat.milliseconds(12_345), "12.3 s")
    }

    func testLogLatencyNeverGroupsDigits() {
        XCTAssertEqual(QueriesFormat.logLatency(0.4), "<1")
        XCTAssertEqual(QueriesFormat.logLatency(1), "1")
        XCTAssertEqual(QueriesFormat.logLatency(21.4), "21")
        XCTAssertEqual(QueriesFormat.logLatency(999.4), "999")
        XCTAssertEqual(QueriesFormat.logLatency(999.6), "1.0 s")
        XCTAssertEqual(QueriesFormat.logLatency(5012), "5.0 s")
    }

    func testFailedHasItsOwnColor() {
        XCTAssertNotEqual(QueryOutcome.failed.color, QueryOutcome.blocked.color)
        XCTAssertEqual(QueryOutcome.failed.color, Color.historyFailed)
        XCTAssertEqual(QueryOutcome.blocked.color, Color.statusCritical)
    }

    func testShareRoundsButNeverHidesASmallPart() {
        XCTAssertEqual(QueriesFormat.share(71, of: 100), "71%")
        XCTAssertEqual(QueriesFormat.share(1, of: 1000), "<1%")
        XCTAssertEqual(QueriesFormat.share(0, of: 1000), "0%")
        XCTAssertEqual(QueriesFormat.share(0, of: 0), "0%")
    }

    func testPopularPrefetchImpactEstimate() {
        XCTAssertEqual(
            QueriesFormat.popularPrefetchImpact(count: 0),
            "Off: only answers used in the last few hours are renewed."
        )
        XCTAssertEqual(
            QueriesFormat.popularPrefetchImpact(count: 500),
            "Adds about 1.7 lookups per second to your providers while this Mac is awake."
        )
    }

    private func host(count: Int, blocked: Int, notFound: Int, failed: Int) -> QueryHistoryTopHosts.Host {
        QueryHistoryTopHosts.Host(
            name: "example.com", count: count, cache: 0, provider: 0, blocked: blocked, notFound: notFound,
            failed: failed, lastSeen: 0, blockRule: "", blockCategory: "")
    }
}
