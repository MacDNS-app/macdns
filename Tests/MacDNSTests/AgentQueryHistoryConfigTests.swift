// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import ObjectiveC
import Shared
import XCTest

@testable import MacDNSAgent

/// How the agent carries the four lookup-history keys from `state.json` to the
/// resolver: defaults, validation of a save, the launch configure and which
/// saves reconfigure history.
final class AgentQueryHistoryConfigTests: XCTestCase {
    private let custom: [String: Any] = [
        "queryHistoryEnabled": false,
        "queryHistoryRetentionDays": 90,
        "popularPrefetchCount": 500,
        "popularPrefetchDays": 14,
    ]

    // MARK: - Defaults

    func testShippedDefaultsKeepHistoryOnAndPopularPrefetchOff() {
        let defaults = FullConfigNormalizationPolicy.defaults()

        XCTAssertEqual(defaults["queryHistoryEnabled"] as? Bool, true)
        XCTAssertEqual(defaults["queryHistoryRetentionDays"] as? Int, 30)
        XCTAssertEqual(defaults["popularPrefetchCount"] as? Int, 0)
        XCTAssertEqual(defaults["popularPrefetchDays"] as? Int, 7)
    }

    func testStateWrittenBeforeHistoryExistedNormalizesToTheDefaults() throws {
        let normalized = try XCTUnwrap(
            FullConfigNormalizationPolicy.normalized([
                "schemaVersion": ConfigSchemaPolicy.currentVersion,
                "isEnabled": true,
                "prefetchEnabled": true,
            ])
        )

        XCTAssertEqual(try QueryHistorySettings(config: normalized), .default)
    }

    func testSaveWithoutHistoryKeysKeepsThePersistedValues() throws {
        let normalized = try XCTUnwrap(
            FullConfigNormalizationPolicy.normalized(["isEnabled": true], mergedWith: custom)
        )

        XCTAssertEqual(
            try QueryHistorySettings(config: normalized),
            QueryHistorySettings(enabled: false, retentionDays: 90, popularCount: 500, popularDays: 14)
        )
    }

    // MARK: - Save validation

    func testSaveAcceptsAllowedHistorySettings() throws {
        let normalized = try XCTUnwrap(FullConfigNormalizationPolicy.normalized(custom))

        XCTAssertNil(MacDNSAgent.normalizedConfigRejection(for: normalized))
    }

    func testSaveRejectsAValueOutsideItsSetWithTheReason() throws {
        let normalized = try XCTUnwrap(
            FullConfigNormalizationPolicy.normalized(["popularPrefetchCount": 300])
        )

        XCTAssertEqual(
            MacDNSAgent.normalizedConfigRejection(for: normalized),
            "popularPrefetchCount 300 is not one of 0, 100, 250, 500, 1000, 2000"
        )
    }

    /// A payload that sends only the look-back must still be checked against
    /// the persisted retention it is merged with.
    func testSaveRejectsALookBackLongerThanThePersistedRetention() throws {
        let normalized = try XCTUnwrap(
            FullConfigNormalizationPolicy.normalized(
                ["popularPrefetchDays": 30],
                mergedWith: ["queryHistoryRetentionDays": 7]
            )
        )

        XCTAssertEqual(
            MacDNSAgent.normalizedConfigRejection(for: normalized),
            "popularPrefetchDays 30 is longer than queryHistoryRetentionDays 7"
        )
    }

    func testSaveRejectsAWrongType() throws {
        let normalized = try XCTUnwrap(
            FullConfigNormalizationPolicy.normalized(["queryHistoryEnabled": "yes"])
        )

        XCTAssertEqual(
            MacDNSAgent.normalizedConfigRejection(for: normalized),
            "queryHistoryEnabled has the wrong type"
        )
    }

    // MARK: - Launch

    func testLaunchConfiguresHistoryFromStateJSON() {
        var configured: [QueryHistorySettings] = []

        let applied = MacDNSAgent.configureHistoryAtLaunch(config: custom) { settings in
            configured.append(settings)
            return true
        }

        XCTAssertTrue(applied)
        XCTAssertEqual(
            configured,
            [QueryHistorySettings(enabled: false, retentionDays: 90, popularCount: 500, popularDays: 14)]
        )
    }

    func testLaunchWithoutHistoryKeysConfiguresTheDefaults() {
        var configured: [QueryHistorySettings] = []

        MacDNSAgent.configureHistoryAtLaunch(config: [:]) { settings in
            configured.append(settings)
            return true
        }

        XCTAssertEqual(configured, [.default])
    }

    /// A hand-edited value outside the allowed set is never adjusted: history
    /// stays off (the resolver's own default) and the agent carries on.
    func testBadPersistedHistoryValueLeavesHistoryOff() {
        for bad: [String: Any] in [
            ["queryHistoryRetentionDays": 8],
            ["popularPrefetchCount": 300],
            ["queryHistoryEnabled": "yes"],
        ] {
            var calls = 0

            let applied = MacDNSAgent.configureHistoryAtLaunch(config: bad) { _ in
                calls += 1
                return true
            }

            XCTAssertFalse(applied, "\(bad)")
            XCTAssertEqual(calls, 0, "\(bad)")
        }
    }

    func testRejectedLaunchConfigureReportsHistoryOff() {
        XCTAssertFalse(MacDNSAgent.configureHistoryAtLaunch(config: custom) { _ in false })
    }

    /// Protection starts from the resolver options alone, so a bad history
    /// value can never fail `start()`.
    func testBadPersistedHistoryValueDoesNotChangeTheResolverOptions() {
        let clean = MacDNSAgent.resolverOptions(from: ["dnssecEnabled": false, "prefetchEnabled": false])
        let withBadHistory = MacDNSAgent.resolverOptions(
            from: ["dnssecEnabled": false, "prefetchEnabled": false, "queryHistoryRetentionDays": 8]
        )

        XCTAssertEqual(withBadHistory.dnssec, clean.dnssec)
        XCTAssertEqual(withBadHistory.prefetch, clean.prefetch)
        XCTAssertEqual(withBadHistory.serveExpired, clean.serveExpired)
        XCTAssertEqual(withBadHistory.dohProviders, clean.dohProviders)
    }

    // MARK: - Save

    func testSaveWithUnchangedHistoryKeysLeavesHistoryAlone() {
        XCTAssertNil(MacDNSAgent.historySettingsChange(old: custom, new: custom))
        XCTAssertNil(MacDNSAgent.historySettingsChange(old: [:], new: QueryHistorySettings.default.stateDictionary))
    }

    func testSaveThatChangesAHistoryKeyAppliesTheNewSettings() {
        var turnedOff = QueryHistorySettings.default.stateDictionary
        turnedOff["queryHistoryEnabled"] = false

        XCTAssertEqual(
            MacDNSAgent.historySettingsChange(old: [:], new: turnedOff),
            QueryHistorySettings(enabled: false, retentionDays: 30, popularCount: 0, popularDays: 7)
        )
    }

    /// History stayed off at launch because of the bad value, so the first
    /// valid save must configure it.
    func testSaveOverABadPersistedValueAppliesTheNewSettings() {
        XCTAssertEqual(
            MacDNSAgent.historySettingsChange(
                old: ["queryHistoryRetentionDays": 8],
                new: QueryHistorySettings.default.stateDictionary
            ),
            .default
        )
    }

    // MARK: - Clear

    /// Without the resolver library the store was never configured, so
    /// nothing was deleted and the App must not show success.
    func testClearWithoutAConfiguredStoreFails() {
        XCTAssertFalse(ResolverModule.shared.clearHistory())
    }

    // MARK: - XPC surface

    func testXPCInterfaceReadsAndClearsHistoryInsteadOfTheOldCounters() {
        let expected: [(String, Bool)] = [
            ("queryHistoryWithRequest:withReply:", true),
            ("clearQueryHistoryWithReply:", true),
            ("getBlocklistStatsWithReply:", false),
            ("clearBlocklistStatsWithReply:", false),
        ]
        for (selector, present) in expected {
            let description = protocol_getMethodDescription(
                MacDNSXPCProtocol.self,
                NSSelectorFromString(selector),
                true,
                true
            )
            XCTAssertEqual(description.name != nil, present, selector)
        }
    }

    /// A request is passed to the resolver as a C string, so an embedded NUL
    /// would silently cut it short. Such a request is a caller bug.
    func testRequestThatIsNotAPlainUTF8StringIsACallerError() throws {
        for request in [Data([0xFF, 0xFE]), Data(#"{"kind":"status"}\#0{"#.utf8)] {
            let response = try JSONDecoder().decode(
                QueryHistoryResponse<QueryHistoryStatus>.self,
                from: ResolverModule.shared.queryHistory(request)
            )

            guard case .error = response else {
                return XCTFail("expected a caller error, got \(response)")
            }
        }
    }
}
