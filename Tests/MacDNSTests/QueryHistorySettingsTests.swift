// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

/// The four lookup-history keys in `state.json`. Missing keys take the shipped
/// defaults. Present values must have the right type and be one of the allowed
/// choices: they are rejected, never adjusted.
final class QueryHistorySettingsTests: XCTestCase {
    func testMissingKeysTakeTheDefaults() throws {
        let settings = try QueryHistorySettings(config: [:])

        XCTAssertEqual(settings, .default)
        XCTAssertEqual(
            settings,
            QueryHistorySettings(enabled: true, retentionDays: 30, popularCount: 0, popularDays: 7)
        )
    }

    func testEveryAllowedCombinationIsAccepted() throws {
        for retention in [7, 14, 30, 90] {
            for count in [0, 100, 250, 500, 1000, 2000] {
                for days in [1, 7, 14, 30] where days <= retention {
                    let settings = try QueryHistorySettings(config: [
                        "queryHistoryEnabled": false,
                        "queryHistoryRetentionDays": retention,
                        "popularPrefetchCount": count,
                        "popularPrefetchDays": days,
                    ])

                    XCTAssertEqual(
                        settings,
                        QueryHistorySettings(
                            enabled: false,
                            retentionDays: retention,
                            popularCount: count,
                            popularDays: days
                        )
                    )
                }
            }
        }
    }

    func testValuesOutsideTheirSetAreRejected() {
        let cases: [(String, Any, QueryHistorySettings.ValidationError)] = [
            ("queryHistoryRetentionDays", 31, .retentionDays(31)),
            ("queryHistoryRetentionDays", 0, .retentionDays(0)),
            ("popularPrefetchCount", 300, .popularCount(300)),
            ("popularPrefetchCount", -100, .popularCount(-100)),
            ("popularPrefetchDays", 3, .popularDays(3)),
        ]
        for (key, value, expected) in cases {
            XCTAssertThrowsError(try QueryHistorySettings(config: [key: value]), "\(key)=\(value)") {
                XCTAssertEqual($0 as? QueryHistorySettings.ValidationError, expected)
            }
        }
    }

    func testLookBackLongerThanRetentionIsRejected() {
        XCTAssertThrowsError(
            try QueryHistorySettings(config: [
                "queryHistoryRetentionDays": 7,
                "popularPrefetchDays": 14,
            ])
        ) {
            XCTAssertEqual(
                $0 as? QueryHistorySettings.ValidationError,
                .popularDaysExceedRetention(days: 14, retentionDays: 7)
            )
        }
    }

    /// `JSONSerialization` hands a JSON `true` over as an `NSNumber` that
    /// `as? Int` reads as 1, and `1.5` as a number `as? Bool` reads as true.
    func testWrongTypesAreRejected() {
        let cases: [(String, Any)] = [
            ("queryHistoryEnabled", 1),
            ("queryHistoryEnabled", "true"),
            ("queryHistoryRetentionDays", true),
            ("queryHistoryRetentionDays", "30"),
            ("queryHistoryRetentionDays", 30.5),
            ("popularPrefetchCount", NSNull()),
            ("popularPrefetchDays", [7]),
        ]
        for (key, value) in cases {
            XCTAssertThrowsError(try QueryHistorySettings(config: [key: value]), "\(key)=\(value)") {
                XCTAssertEqual($0 as? QueryHistorySettings.ValidationError, .wrongType(key: key))
            }
        }
    }

    func testValuesReadBackFromStateJSONAreAccepted() throws {
        let data = Data(
            #"{"queryHistoryEnabled":true,"queryHistoryRetentionDays":14,"popularPrefetchCount":250,"popularPrefetchDays":1}"#
                .utf8
        )
        let config = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(
            try QueryHistorySettings(config: config),
            QueryHistorySettings(enabled: true, retentionDays: 14, popularCount: 250, popularDays: 1)
        )
    }

    func testRejectionsExplainWhatIsWrong() {
        XCTAssertEqual(
            QueryHistorySettings.ValidationError.retentionDays(31).errorDescription,
            "queryHistoryRetentionDays 31 is not one of 7, 14, 30, 90"
        )
        XCTAssertEqual(
            QueryHistorySettings.ValidationError.popularDaysExceedRetention(days: 14, retentionDays: 7)
                .errorDescription,
            "popularPrefetchDays 14 is longer than queryHistoryRetentionDays 7"
        )
        XCTAssertEqual(
            QueryHistorySettings.ValidationError.wrongType(key: "popularPrefetchCount").errorDescription,
            "popularPrefetchCount has the wrong type"
        )
    }

    func testStateDictionaryUsesTheStateJSONKeys() {
        let settings = QueryHistorySettings(enabled: false, retentionDays: 90, popularCount: 1000, popularDays: 30)

        XCTAssertEqual(
            settings.stateDictionary as NSDictionary,
            [
                "queryHistoryEnabled": false,
                "queryHistoryRetentionDays": 90,
                "popularPrefetchCount": 1000,
                "popularPrefetchDays": 30,
            ] as NSDictionary
        )
    }
}
