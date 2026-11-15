// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

final class SharedConfigStateTests: XCTestCase {
    func testConfigStateDecodesOldPayloadWithDoHDefaults() throws {
        let data = """
            {
              "dnssecEnabled": true,
              "logQueriesEnabled": false,
              "logRepliesEnabled": false,
              "prefetchEnabled": true,
              "serveExpiredEnabled": true,
              "blockDohDotEnabled": true
            }
            """.data(using: .utf8)!

        let state = try JSONDecoder().decode(ConfigState.self, from: data)

        XCTAssertEqual(state.dohProviders, [.cloudflare, .google, .quad9])
        XCTAssertEqual(state.dohDispatchMode, .staggeredParallel)
        XCTAssertTrue(state.dnsAnswerRefinementEnabled)
        XCTAssertTrue(state.queryHistoryEnabled)
        XCTAssertEqual(state.queryHistoryRetentionDays, 30)
        XCTAssertEqual(state.popularPrefetchCount, 0)
        XCTAssertEqual(state.popularPrefetchDays, 7)
    }

    func testConfigStateDefaultsKeepHistoryOnAndPopularPrefetchOff() {
        let state = ConfigState.default

        XCTAssertTrue(state.queryHistoryEnabled)
        XCTAssertEqual(state.queryHistoryRetentionDays, 30)
        XCTAssertEqual(state.popularPrefetchCount, 0)
        XCTAssertEqual(state.popularPrefetchDays, 7)
    }

    func testConfigStateRoundTripsHistorySettings() throws {
        let original = ConfigState(
            queryHistoryEnabled: false,
            queryHistoryRetentionDays: 90,
            popularPrefetchCount: 500,
            popularPrefetchDays: 14
        )

        let data = try JSONEncoder().encode(original)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let decoded = try JSONDecoder().decode(ConfigState.self, from: data)

        XCTAssertEqual(decoded, original)
        XCTAssertEqual(object["queryHistoryEnabled"] as? Bool, false)
        XCTAssertEqual(object["queryHistoryRetentionDays"] as? Int, 90)
        XCTAssertEqual(object["popularPrefetchCount"] as? Int, 500)
        XCTAssertEqual(object["popularPrefetchDays"] as? Int, 14)
    }

    func testConfigStateBlocksDoHAndDoTOnlyWhenAsked() {
        XCTAssertFalse(ConfigState().blockDohDotEnabled)
        XCTAssertFalse(ConfigState.default.blockDohDotEnabled)
        XCTAssertTrue(ConfigState(blockDohDotEnabled: true).blockDohDotEnabled)
    }

    func testConfigStateDecodesMissingDoHBlockingAsOff() throws {
        let state = try JSONDecoder().decode(
            ConfigState.self,
            from: Data("{}".utf8)
        )

        XCTAssertFalse(state.blockDohDotEnabled)
    }

    func testConfigStateKeepsStoredDoHBlockingValue() throws {
        for stored in [false, true] {
            let state = try JSONDecoder().decode(
                ConfigState.self,
                from: Data(#"{"blockDohDotEnabled": \#(stored)}"#.utf8)
            )

            XCTAssertEqual(state.blockDohDotEnabled, stored)
        }
    }

    func testConfigStateCanonicalizesProviderList() throws {
        let data = """
            {
              "dohProviders": ["quad9", "invalid", "cloudflare", "quad9"],
              "dohDispatchMode": "parallel",
              "dnsAnswerRefinementEnabled": false
            }
            """.data(using: .utf8)!

        let state = try JSONDecoder().decode(ConfigState.self, from: data)

        XCTAssertEqual(state.dohProviders, [.cloudflare, .quad9])
        XCTAssertEqual(state.dohDispatchMode, .parallel)
        XCTAssertFalse(state.dnsAnswerRefinementEnabled)
    }

    func testConfigStateFallsBackForInvalidProviderListAndDispatchMode() throws {
        let data = """
            {
              "dohProviders": ["invalid"],
              "dohDispatchMode": "bad"
            }
            """.data(using: .utf8)!

        let state = try JSONDecoder().decode(ConfigState.self, from: data)

        XCTAssertEqual(state.dohProviders, [.cloudflare, .google, .quad9])
        XCTAssertEqual(state.dohDispatchMode, .staggeredParallel)
    }
}
