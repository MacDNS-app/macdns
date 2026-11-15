// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

/// The App and the resolver talk through the JSON contract of
/// `dns_history_query` (`rust-resolver/crates/macdns-resolver/src/history/query.rs`).
/// The fixtures below are the exact shapes that module renders.
final class QueryHistoryContractTests: XCTestCase {

    // MARK: - Requests

    func testSummaryRequestCarriesRangeAndOffset() throws {
        let json = try encoded(QueryHistoryRequest(.summary(range: .last(.day)), utcOffsetSecs: -10_800))

        XCTAssertEqual(json["kind"] as? String, "summary")
        XCTAssertEqual(json["range"] as? String, "24h")
        XCTAssertEqual(json["utcOffsetSecs"] as? Int, -10_800)
        XCTAssertEqual(json.count, 3)
    }

    func testTopHostsRequestCarriesEveryFilter() throws {
        let json = try encoded(
            QueryHistoryRequest(
                .topHosts(range: .last(.hour), result: .notFound, query: "figma", limit: 10),
                utcOffsetSecs: 0
            )
        )

        XCTAssertEqual(json["kind"] as? String, "topHosts")
        XCTAssertEqual(json["range"] as? String, "1h")
        XCTAssertEqual(json["result"] as? String, "notFound")
        XCTAssertEqual(json["query"] as? String, "figma")
        XCTAssertEqual(json["limit"] as? Int, 10)
        XCTAssertEqual(json["utcOffsetSecs"] as? Int, 0)
    }

    func testHostDetailRequestNamesTheHost() throws {
        let json = try encoded(
            QueryHistoryRequest(.hostDetail(range: .last(.week), name: "www.google.com"), utcOffsetSecs: 3600)
        )

        XCTAssertEqual(json["kind"] as? String, "hostDetail")
        XCTAssertEqual(json["range"] as? String, "7d")
        XCTAssertEqual(json["name"] as? String, "www.google.com")
        XCTAssertEqual(json["utcOffsetSecs"] as? Int, 3600)
    }

    func testFirstLogPageSendsANullCursor() throws {
        let json = try encoded(
            QueryHistoryRequest(
                .log(result: .blocked, query: "", limit: 200, beforeId: nil),
                utcOffsetSecs: 0
            )
        )

        XCTAssertEqual(json["kind"] as? String, "log")
        XCTAssertEqual(json["result"] as? String, "blocked")
        XCTAssertEqual(json["query"] as? String, "")
        XCTAssertEqual(json["limit"] as? Int, 200)
        XCTAssertTrue(json["beforeId"] is NSNull)
        XCTAssertNil(json["range"])
    }

    func testNextLogPageSendsTheLastRowID() throws {
        let json = try encoded(
            QueryHistoryRequest(
                .log(result: .all, query: "", limit: 200, beforeId: 48_211),
                utcOffsetSecs: 0
            )
        )

        XCTAssertEqual(json["beforeId"] as? Int, 48_211)
    }

    func testTopBlockedRequestWithoutCategorySendsNull() throws {
        let json = try encoded(
            QueryHistoryRequest(.topBlocked(range: .last(.month), category: nil, limit: 100), utcOffsetSecs: 0)
        )

        XCTAssertEqual(json["kind"] as? String, "topBlocked")
        XCTAssertEqual(json["range"] as? String, "30d")
        XCTAssertTrue(json["category"] is NSNull)
        XCTAssertEqual(json["limit"] as? Int, 100)
    }

    func testZoomedRequestSendsTheSpanAndStart() throws {
        let zoom = QueryHistoryZoom(span: .day, start: 1_762_473_600)
        let json = try encoded(QueryHistoryRequest(.summary(range: .zoomed(zoom)), utcOffsetSecs: 0))

        XCTAssertEqual(json["range"] as? NSDictionary, ["span": "24h", "start": 1_762_473_600] as NSDictionary)
    }

    func testZoomedLogSendsTheZoomAsItsRange() throws {
        let zoom = QueryHistoryZoom(span: .hour, start: 1_762_506_000)
        let json = try encoded(
            QueryHistoryRequest(
                .log(result: .all, query: "", limit: 200, beforeId: nil, zoom: zoom), utcOffsetSecs: -10_800))

        XCTAssertEqual(json["range"] as? NSDictionary, ["span": "1h", "start": 1_762_506_000] as NSDictionary)
        XCTAssertEqual(json["utcOffsetSecs"] as? Int, -10_800)
    }

    func testStatusRequestCarriesOnlyKindAndOffset() throws {
        let json = try encoded(QueryHistoryRequest(.status, utcOffsetSecs: 0))

        XCTAssertEqual(json as NSDictionary, ["kind": "status", "utcOffsetSecs": 0] as NSDictionary)
    }

    // MARK: - Responses

    func testSummaryDecodes() throws {
        let response = try decode(
            QueryHistorySummary.self,
            #"""
            {"status":"ok","total":18413,"previousTotal":17370,"blocked":1197,"cache":12210,"provider":4800,
             "avgLatencyMs":3.1,"avgProviderLatencyMs":16.4,
             "series":[{"start":1762500000,"cache":510,"provider":200,"blocked":40,"other":12}],
             "providers":[{"name":"Cloudflare","answers":2930,"avgLatencyMs":14.2}],
             "answers":{"answered":15853,"blocked":1197,"notFound":1142,"failed":221},
             "firstSeen":[{"name":"cdn.figma.com","firstSeen":1762510000,"count":212,"blocked":false}],
             "keptFresh":{"popularCount":500,"inCache":463,"cacheAnswers":2099,"refreshesPerSecond":1.6}}
            """#
        )

        guard case .ok(let summary) = response else { return XCTFail("expected ok, got \(response)") }
        XCTAssertEqual(summary.total, 18_413)
        XCTAssertEqual(summary.previousTotal, 17_370)
        XCTAssertEqual(summary.blocked, 1197)
        XCTAssertEqual(summary.cache, 12_210)
        XCTAssertEqual(summary.provider, 4800)
        XCTAssertEqual(summary.avgLatencyMs, 3.1)
        XCTAssertEqual(summary.avgProviderLatencyMs, 16.4)
        XCTAssertEqual(
            summary.series,
            [.init(start: 1_762_500_000, cache: 510, provider: 200, blocked: 40, other: 12)]
        )
        XCTAssertEqual(summary.providers, [.init(name: "Cloudflare", answers: 2930, avgLatencyMs: 14.2)])
        XCTAssertEqual(summary.answers, .init(answered: 15_853, blocked: 1197, notFound: 1142, failed: 221))
        XCTAssertEqual(
            summary.firstSeen,
            [.init(name: "cdn.figma.com", firstSeen: 1_762_510_000, count: 212, blocked: false)]
        )
        XCTAssertEqual(
            summary.keptFresh,
            .init(popularCount: 500, inCache: 463, cacheAnswers: 2099, refreshesPerSecond: 1.6)
        )
    }

    func testSummaryWithoutPopularPrefetchHasNoKeptFresh() throws {
        let response = try decode(
            QueryHistorySummary.self,
            #"""
            {"status":"ok","total":0,"previousTotal":0,"blocked":0,"cache":0,"provider":0,
             "avgLatencyMs":0.0,"avgProviderLatencyMs":0.0,"series":[],"providers":[],
             "answers":{"answered":0,"blocked":0,"notFound":0,"failed":0},"firstSeen":[],"keptFresh":null}
            """#
        )

        guard case .ok(let summary) = response else { return XCTFail("expected ok, got \(response)") }
        XCTAssertNil(summary.keptFresh)
    }

    func testSummaryWithPreviousPeriodOutsideTheHistoryHasNoPreviousTotal() throws {
        let body = #"""
            {"status":"ok","total":5,"previousTotal":null,"blocked":0,"cache":0,"provider":5,
             "avgLatencyMs":9.0,"avgProviderLatencyMs":9.0,"series":[],"providers":[],
             "answers":{"answered":5,"blocked":0,"notFound":0,"failed":0},"firstSeen":[],"keptFresh":null}
            """#
        let response = try decode(QueryHistorySummary.self, body)

        guard case .ok(let summary) = response else { return XCTFail("expected ok, got \(response)") }
        XCTAssertNil(summary.previousTotal)
        XCTAssertEqual(summary.total, 5)
    }

    func testSummaryWithoutPreviousTotalKeyHasNoPreviousTotal() throws {
        let response = try decode(
            QueryHistorySummary.self,
            #"""
            {"status":"ok","total":5,"blocked":0,"cache":0,"provider":5,
             "avgLatencyMs":9.0,"avgProviderLatencyMs":9.0,"series":[],"providers":[],
             "answers":{"answered":5,"blocked":0,"notFound":0,"failed":0},"firstSeen":[],"keptFresh":null}
            """#
        )

        guard case .ok(let summary) = response else { return XCTFail("expected ok, got \(response)") }
        XCTAssertNil(summary.previousTotal)
    }

    func testRequestLimitCapMatchesTheResolver() {
        XCTAssertEqual(QueryHistoryRequest.maxLimit, 1000)
    }

    func testTopHostsDecodes() throws {
        let response = try decode(
            QueryHistoryTopHosts.self,
            #"""
            {"status":"ok","totalHosts":1284,"hosts":[{"name":"www.google.com","count":1502,"cache":1100,"provider":402,
             "blocked":0,"notFound":0,"failed":0,"lastSeen":1762519000,"blockRule":"","blockCategory":""}]}
            """#
        )

        guard case .ok(let top) = response else { return XCTFail("expected ok, got \(response)") }
        XCTAssertEqual(top.totalHosts, 1284)
        XCTAssertEqual(
            top.hosts,
            [
                .init(
                    name: "www.google.com", count: 1502, cache: 1100, provider: 402, blocked: 0,
                    notFound: 0, failed: 0, lastSeen: 1_762_519_000, blockRule: "", blockCategory: ""
                )
            ]
        )
    }

    func testHostDetailDecodes() throws {
        let response = try decode(
            QueryHistoryHostDetail.self,
            #"""
            {"status":"ok","name":"www.google.com","firstSeen":1761000000,"lastSeen":1762519000,
             "series":[{"start":1762500000,"count":61}],"routes":{"cache":1100,"provider":402},
             "providers":[{"name":"Cloudflare","count":300}],"qtypes":[{"qtype":1,"count":800}],
             "blockRule":"","blockCategory":""}
            """#
        )

        guard case .ok(let detail) = response else { return XCTFail("expected ok, got \(response)") }
        XCTAssertEqual(detail.name, "www.google.com")
        XCTAssertEqual(detail.firstSeen, 1_761_000_000)
        XCTAssertEqual(detail.lastSeen, 1_762_519_000)
        XCTAssertEqual(detail.series, [.init(start: 1_762_500_000, count: 61)])
        XCTAssertEqual(detail.routes, ["cache": 1100, "provider": 402])
        XCTAssertEqual(detail.providers, [.init(name: "Cloudflare", count: 300)])
        XCTAssertEqual(detail.qtypes, [.init(qtype: 1, count: 800)])
        XCTAssertEqual(detail.blockRule, "")
        XCTAssertEqual(detail.blockCategory, "")
    }

    /// A name with no `names` row (purged or never seen) has no first or last
    /// sighting. The resolver sends `null` for both.
    func testHostDetailForAnUnknownNameHasNoSightings() throws {
        let response = try decode(
            QueryHistoryHostDetail.self,
            #"""
            {"status":"ok","name":"gone.example","firstSeen":null,"lastSeen":null,"series":[],"routes":{},
             "providers":[],"qtypes":[],"blockRule":"","blockCategory":""}
            """#
        )

        guard case .ok(let detail) = response else { return XCTFail("expected ok, got \(response)") }
        XCTAssertNil(detail.firstSeen)
        XCTAssertNil(detail.lastSeen)
        XCTAssertEqual(detail.routes, [:])
    }

    func testLogDecodes() throws {
        let response = try decode(
            QueryHistoryLog.self,
            #"""
            {"status":"ok","entries":[{"id":48211,"ts":1762519012,"name":"app-measurement.com","qtype":1,"rcode":0,
             "route":"blocked","provider":"","latencyMs":0.2,"blockRule":"app-measurement.com","blockCategory":"trackers"}]}
            """#
        )

        guard case .ok(let log) = response else { return XCTFail("expected ok, got \(response)") }
        XCTAssertEqual(
            log.entries,
            [
                .init(
                    id: 48_211, ts: 1_762_519_012, name: "app-measurement.com", qtype: 1, rcode: 0,
                    route: "blocked", provider: "", latencyMs: 0.2, blockRule: "app-measurement.com",
                    blockCategory: "trackers"
                )
            ]
        )
    }

    func testTopBlockedDecodes() throws {
        let response = try decode(
            QueryHistoryTopBlocked.self,
            #"""
            {"status":"ok","domains":[{"domain":"stats.g.doubleclick.net","matchedRule":"doubleclick.net",
             "category":"ads_tracking","blockCount":758}]}
            """#
        )

        guard case .ok(let top) = response else { return XCTFail("expected ok, got \(response)") }
        XCTAssertEqual(
            top.domains,
            [
                .init(
                    domain: "stats.g.doubleclick.net", matchedRule: "doubleclick.net",
                    category: "ads_tracking", blockCount: 758
                )
            ]
        )
    }

    /// Activity keeps rendering `BlockedDomain`. The category travels as the
    /// blocklist tag the resolver matched, which may carry a level suffix.
    func testTopBlockedMapsToActivityRowsAndSkipsUnknownCategories() {
        let top = QueryHistoryTopBlocked(domains: [
            .init(domain: "ads.example", matchedRule: "example", category: "ads_tracking", blockCount: 7),
            .init(domain: "bad.example", matchedRule: "bad.example", category: "malware_security.tif.medium", blockCount: 2),
            .init(domain: "odd.example", matchedRule: "odd.example", category: "not_a_category", blockCount: 1),
        ])

        let rows = top.blockedDomains

        XCTAssertEqual(rows.map(\.domain), ["ads.example", "bad.example"])
        XCTAssertEqual(rows.map(\.matchedRule), ["example", "bad.example"])
        XCTAssertEqual(rows.map(\.category), [.adsTracking, .malwareSecurity])
        XCTAssertEqual(rows.map(\.blockCount), [7, 2])
    }

    func testStatusDecodes() throws {
        let response = try decode(
            QueryHistoryStatus.self,
            #"{"status":"ok","enabled":true,"sizeBytes":7340032,"droppedEvents":0,"retentionDays":30}"#
        )

        XCTAssertEqual(
            response,
            .ok(.init(enabled: true, sizeBytes: 7_340_032, droppedEvents: 0, retentionDays: 30))
        )
    }

    func testDisabledCarriesNoPayloadForEveryKind() throws {
        let body = #"{"status":"disabled"}"#

        XCTAssertEqual(try decode(QueryHistorySummary.self, body), .disabled)
        XCTAssertEqual(try decode(QueryHistoryTopHosts.self, body), .disabled)
        XCTAssertEqual(try decode(QueryHistoryHostDetail.self, body), .disabled)
        XCTAssertEqual(try decode(QueryHistoryLog.self, body), .disabled)
        XCTAssertEqual(try decode(QueryHistoryTopBlocked.self, body), .disabled)
        XCTAssertEqual(try decode(QueryHistoryStatus.self, body), .disabled)
    }

    func testUnavailableCarriesTheReason() throws {
        let body = #"{"status":"unavailable","reason":"cannot open history database: disk I/O error"}"#

        XCTAssertEqual(
            try decode(QueryHistorySummary.self, body),
            .unavailable(reason: "cannot open history database: disk I/O error")
        )
        XCTAssertEqual(
            try decode(QueryHistoryStatus.self, body),
            .unavailable(reason: "cannot open history database: disk I/O error")
        )
    }

    /// `error` is a bug in the request, never a store fault the user can wait out.
    func testCallerErrorIsDistinctFromUnavailable() throws {
        let response = try decode(
            QueryHistoryLog.self,
            #"{"status":"error","reason":"limit must be between 1 and 1000"}"#
        )

        XCTAssertEqual(response, .error(reason: "limit must be between 1 and 1000"))
        XCTAssertNotEqual(response, .unavailable(reason: "limit must be between 1 and 1000"))
    }

    func testUnknownStatusIsADecodingFailure() {
        XCTAssertThrowsError(try decode(QueryHistoryStatus.self, #"{"status":"maybe"}"#))
    }

    func testOkWithoutItsPayloadIsADecodingFailure() {
        XCTAssertThrowsError(try decode(QueryHistoryTopHosts.self, #"{"status":"ok"}"#))
    }

    // MARK: - Helpers

    private func encoded(_ request: QueryHistoryRequest) throws -> [String: Any] {
        let object = try JSONSerialization.jsonObject(with: request.encoded())
        return try XCTUnwrap(object as? [String: Any])
    }

    private func decode<Payload: Decodable & Equatable>(
        _: Payload.Type,
        _ body: String
    ) throws -> QueryHistoryResponse<Payload> {
        try JSONDecoder().decode(QueryHistoryResponse<Payload>.self, from: Data(body.utf8))
    }
}
