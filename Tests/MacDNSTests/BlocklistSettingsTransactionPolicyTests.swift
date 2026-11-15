// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNS
@testable import MacDNSAgent

/// Blocklist settings live in `state.json`, so the agent refresh timestamp and
/// an App fallback category change are two writers of the same revisioned
/// document instead of two owners of a private file.
@MainActor
final class BlocklistSettingsTransactionPolicyTests: XCTestCase {
    func testBootstrapPersistsEnabledDefaultProfileWhenSettingsAreMissing() throws {
        for hasExistingState in [false, true] {
            let environment = try environment()
            if hasExistingState {
                var config = fullConfigSnapshot()
                config["isEnabled"] = false
                try JSONSerialization.data(withJSONObject: config).write(to: environment.stateFile)
            }

            environment.store.bootstrapSettings()

            let settings = try projectedSettings(environment)
            XCTAssertTrue(settings.enabled)
            XCTAssertEqual(settings.level(for: .adsTracking), .normal)
            XCTAssertEqual(settings.level(for: .malwareSecurity), .pro)
            XCTAssertEqual(settings.level(for: .adultContent), .light)
            XCTAssertEqual(settings.level(for: .gambling), .pro)
            XCTAssertEqual(settings.level(for: .socialMedia), .disabled)
            XCTAssertEqual(settings.level(for: .miscellaneous), .light)
            XCTAssertEqual(settings.categories.count, 5)
            XCTAssertTrue(settings.categories.allSatisfy { $0.enabled && $0.action == "null" })
            XCTAssertEqual(settings.dbBasePath, environment.blocklistsDir)
            XCTAssertEqual(environment.store.settings(), settings)
            guard case .valid(let document) = StateFileLock.load(stateFile: environment.stateFile) else {
                return XCTFail("state.json must contain the default blocklist profile")
            }
            XCTAssertEqual(
                BlocklistSettingsTransactionPolicy.persisted(in: document, dbBasePath: environment.blocklistsDir),
                .valid(settings)
            )
            if hasExistingState {
                XCTAssertEqual(document["isEnabled"] as? Bool, false)
            }
            let revisionAfterBootstrap = try XCTUnwrap(revision(of: environment.stateFile))

            environment.store.bootstrapSettings()

            XCTAssertEqual(try projectedSettings(environment), settings)
            XCTAssertEqual(revision(of: environment.stateFile), revisionAfterBootstrap)
        }
    }

    func testBootstrapPreservesSavedDisabledProfiles() throws {
        for categories in [
            [CategoryConfig(name: "Ads & Tracking Light", identifier: "ads_tracking", level: "light")],
            [],
        ] {
            let environment = try environment()
            let saved = BlocklistSettings(
                enabled: false,
                categories: categories,
                dbBasePath: environment.blocklistsDir
            )
            seedSettings(environment, saved)

            environment.store.bootstrapSettings()

            XCTAssertEqual(environment.store.settings(), saved)
            XCTAssertEqual(try projectedSettings(environment), saved)
        }
    }

    func testNewCategoriesUseNullBlockingAfterChangingLevel() {
        var settings = BlocklistSettings(dbBasePath: "/unused")
        XCTAssertTrue(settings.categories.allSatisfy { $0.action == "null" })

        settings.setLevel(.pro, for: .adsTracking)

        XCTAssertTrue(settings.categories.allSatisfy { $0.action == "null" })
    }

    func testBootstrapNormalizesNxdomainActionsIdempotentlyWithoutChangingOtherSettings() throws {
        let environment = try environment()
        var legacy = BlocklistSettingsFixtures.ads(environment.blocklistsDir)
        legacy.enabled = false
        legacy.categories[0].action = "nxdomain"
        legacy.categories[0].enabled = false
        for action in ["NXDOMAIN", "localhost", "192.0.2.1", "2001:db8::1", "null"] {
            legacy.categories.append(
                CategoryConfig(name: action, identifier: action, level: "multi", action: action)
            )
        }
        legacy.lastUpdated = Date(timeIntervalSince1970: 1_000)
        seedSettings(environment, legacy)
        let zone: [String: Any] = [
            "id": UUID().uuidString,
            "domain": "corp.example",
            "forwardIP": "10.0.0.53",
            "enabled": true,
        ]
        var snapshot = fullConfigSnapshot()
        snapshot["customZones"] = [zone]
        let seededRevision = try XCTUnwrap(revision(of: environment.stateFile))
        XCTAssertNotNil(
            RevisionAwareConfigFileStore.save(
                snapshot: snapshot,
                expectedRevision: seededRevision,
                stateFile: environment.stateFile
            )
        )
        let revisionBefore = try XCTUnwrap(revision(of: environment.stateFile))
        var expected = legacy
        expected.categories[0].action = "null"
        expected.categories[1].action = "null"

        environment.store.bootstrapSettings()

        XCTAssertEqual(environment.store.settings(), expected)
        XCTAssertEqual(try projectedSettings(environment), expected)
        XCTAssertEqual(revision(of: environment.stateFile), revisionBefore + 1)
        guard case .valid(let document) = StateFileLock.load(stateFile: environment.stateFile) else {
            return XCTFail("state.json must stay readable")
        }
        XCTAssertEqual(
            BlocklistSettingsTransactionPolicy.persisted(in: document, dbBasePath: environment.blocklistsDir),
            .valid(expected)
        )
        let zones = try XCTUnwrap(document["customZones"] as? [[String: Any]])
        XCTAssertEqual(zones.map { $0["domain"] as? String }, ["corp.example"])
        XCTAssertEqual(document["isEnabled"] as? Bool, true)

        environment.store.bootstrapSettings()

        XCTAssertEqual(environment.store.settings(), expected)
        XCTAssertEqual(try projectedSettings(environment), expected)
        XCTAssertEqual(revision(of: environment.stateFile), revisionBefore + 1)
    }

    func testBootstrapKeepsStateWhenNormalizedProjectionCannotBeWritten() throws {
        let environment = try environment()
        var legacy = BlocklistSettingsFixtures.ads(environment.blocklistsDir)
        legacy.categories[0].action = "nxdomain"
        seedSettings(environment, legacy)
        let revisionBefore = try XCTUnwrap(revision(of: environment.stateFile))
        try FileManager.default.removeItem(at: environment.projectionFile)
        try FileManager.default.createDirectory(
            at: environment.projectionFile.appendingPathComponent("blocker"),
            withIntermediateDirectories: true
        )

        environment.store.bootstrapSettings()

        XCTAssertEqual(revision(of: environment.stateFile), revisionBefore)
        XCTAssertEqual(environment.store.settings(), legacy)

        try FileManager.default.removeItem(at: environment.projectionFile)
        var expected = legacy
        expected.categories[0].action = "null"

        environment.store.bootstrapSettings()

        XCTAssertEqual(environment.store.settings(), expected)
        XCTAssertEqual(try projectedSettings(environment), expected)
        XCTAssertEqual(revision(of: environment.stateFile), revisionBefore + 1)
    }

    func testRefreshTimestampKeepsCategoriesWrittenByAnotherProcess() throws {
        let environment = try environment()
        seedSettings(environment, BlocklistSettingsFixtures.ads(environment.blocklistsDir))
        let revisionBeforeFallback = try XCTUnwrap(revision(of: environment.stateFile))

        // The App fallback commits a new category selection while the manager
        // still holds the snapshot it loaded at boot.
        let fallbackSettings = BlocklistSettingsFixtures.malware(environment.blocklistsDir)
        let fallbackRevision = try XCTUnwrap(
            RevisionAwareConfigFileStore.save(
                snapshot: BlocklistSettingsTransactionPolicy.config(
                    fullConfigSnapshot(),
                    settings: fallbackSettings
                ),
                expectedRevision: revisionBeforeFallback,
                stateFile: environment.stateFile
            )
        )

        environment.manager.markRefreshCompleted(at: Date(timeIntervalSince1970: 1_000))

        var expected = fallbackSettings
        expected.lastUpdated = Date(timeIntervalSince1970: 1_000)
        XCTAssertEqual(environment.manager.getSettings(), expected)
        XCTAssertEqual(try projectedSettings(environment), expected)
        XCTAssertEqual(revision(of: environment.stateFile), fallbackRevision + 1)
    }

    func testFallbackSaveKeepsTheZonesTheAgentPersisted() throws {
        let environment = try environment()
        seedSettings(environment, BlocklistSettingsFixtures.ads(environment.blocklistsDir))
        let zone: [String: Any] = [
            "id": UUID().uuidString,
            "domain": "corp.example",
            "forwardIP": "10.0.0.53",
            "enabled": true,
        ]
        var snapshot = fullConfigSnapshot()
        snapshot["customZones"] = [zone]
        let expectedRevision = try XCTUnwrap(revision(of: environment.stateFile))
        XCTAssertNotNil(
            RevisionAwareConfigFileStore.save(
                snapshot: snapshot,
                expectedRevision: expectedRevision,
                stateFile: environment.stateFile
            )
        )

        environment.manager.markRefreshCompleted(at: Date(timeIntervalSince1970: 2_000))

        guard case .valid(let config) = StateFileLock.load(stateFile: environment.stateFile) else {
            return XCTFail("state.json must stay readable")
        }
        let zones = try XCTUnwrap(config["customZones"] as? [[String: Any]])
        XCTAssertEqual(zones.count, 1)
        XCTAssertEqual(zones.first?["domain"] as? String, "corp.example")
        XCTAssertEqual(
            environment.manager.getSettings().lastUpdated,
            Date(timeIntervalSince1970: 2_000)
        )
    }

    /// `state.json` is the only source of blocklist settings. A projection
    /// left without settings in the document is replaced by the default
    /// profile, never adopted.
    func testBootstrapIgnoresAProjectionTheDocumentDoesNotHold() throws {
        let environment = try environment()
        try JSONCoding.encoder.encode(BlocklistSettingsFixtures.malware(environment.blocklistsDir))
            .write(to: environment.projectionFile, options: .atomic)

        environment.store.bootstrapSettings()

        let settings = environment.store.settings()
        XCTAssertEqual(settings, BlocklistSettings(dbBasePath: environment.blocklistsDir))
        XCTAssertEqual(try projectedSettings(environment), settings)
    }

    func testBlocklistSaveDoesNotPinDoHBlockingOfAStateWithoutTheKey() throws {
        let environment = try environment()
        try Data(#"{"isEnabled": true}"#.utf8).write(to: environment.stateFile)

        seedSettings(environment, BlocklistSettingsFixtures.ads(environment.blocklistsDir))

        guard case .valid(let config) = StateFileLock.load(stateFile: environment.stateFile) else {
            return XCTFail("state.json must stay readable")
        }
        XCTAssertNil(config["blockDohDotEnabled"])
    }

    func testBlocklistSaveWithoutStateFileDoesNotPinDoHBlocking() throws {
        let environment = try environment()

        seedSettings(environment, BlocklistSettingsFixtures.ads(environment.blocklistsDir))

        guard case .valid(let config) = StateFileLock.load(stateFile: environment.stateFile) else {
            return XCTFail("state.json must be created")
        }
        XCTAssertNil(config["blockDohDotEnabled"])
    }

    // MARK: - Helpers

    private struct Environment {
        let store: StateFileBlocklistSettingsStore
        let manager: BlocklistManager
        let stateFile: URL
        let projectionFile: URL
        let blocklistsDir: String
    }

    private func environment() throws -> Environment {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("macdns-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: tempDir)
        }

        let stateFile = tempDir.appendingPathComponent("state.json")
        let projectionFile = tempDir.appendingPathComponent("blocklist_settings.json")
        let blocklistsDir = tempDir.appendingPathComponent("blocklists").path
        let store = StateFileBlocklistSettingsStore(
            stateFile: stateFile,
            projectionFile: projectionFile,
            blocklistsDir: blocklistsDir
        )
        return Environment(
            store: store,
            manager: BlocklistManager(
                resolver: AcceptingResolver(),
                store: store,
                blocklistsDir: blocklistsDir
            ),
            stateFile: stateFile,
            projectionFile: projectionFile,
            blocklistsDir: blocklistsDir
        )
    }

    private func seedSettings(_ environment: Environment, _ settings: BlocklistSettings) {
        XCTAssertNotNil(environment.store.mutate { _ in settings })
    }

    private func projectedSettings(_ environment: Environment) throws -> BlocklistSettings {
        try JSONCoding.decoder.decode(
            BlocklistSettings.self,
            from: Data(contentsOf: environment.projectionFile)
        )
    }

    private func revision(of stateFile: URL) -> ConfigRevision? {
        guard case .valid(let config) = StateFileLock.load(stateFile: stateFile) else {
            return nil
        }
        return ConfigRevisionPolicy.revision(from: config)
    }

    private func fullConfigSnapshot() -> [String: Any] {
        FullConfigSnapshotBuilder.build(
            isEnabled: true,
            dnssecEnabled: true,
            logQueriesEnabled: false,
            logRepliesEnabled: false,
            prefetchEnabled: true,
            serveExpiredEnabled: true,
            dohProviders: Set(DoHProviderID.defaultProviders),
            dohDispatchMode: .defaultMode,
            dnsAnswerRefinementEnabled: true,
            blockDohDotEnabled: true,
            queryHistory: .default,
            customZones: [],
            dnsOverrides: [],
            allowedDomains: []
        )
    }
}

private enum BlocklistSettingsFixtures {
    static func ads(_ dbBasePath: String) -> BlocklistSettings {
        BlocklistSettings(
            enabled: true,
            categories: [
                CategoryConfig(name: "Ads & Tracking Normal", identifier: "ads_tracking", level: "multi")
            ],
            dbBasePath: dbBasePath
        )
    }

    static func malware(_ dbBasePath: String) -> BlocklistSettings {
        BlocklistSettings(
            enabled: true,
            categories: [
                CategoryConfig(name: "Malware & Security Pro", identifier: "malware_security", level: "tif.medium")
            ],
            dbBasePath: dbBasePath
        )
    }
}

private final class AcceptingResolver: BlocklistResolverBackend {
    func configureBlocklist(settingsPath: String) -> Bool { true }
    func forceBlocklistUpdateResult() -> ResolverModule.BlocklistUpdateResult { .unchanged }
    func reloadBlocklist() -> Bool { true }
}
