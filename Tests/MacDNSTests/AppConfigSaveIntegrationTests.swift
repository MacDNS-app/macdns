// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNS

@MainActor
final class AppConfigSaveIntegrationTests: XCTestCase {
    func testXPCClientExposesOnlyTypedFullConfigSaveAPI() {
        let typedSave: ([String: Any]) async -> Result<FullConfigSaveResponse, XPCError> =
            XPCClient.shared.saveFullConfigAsync(config:)

        _ = typedSave
    }

    func testSnapshotBuilderContainsEveryPersistedConfigKey() throws {
        let zone = ForwardZone(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            domain: "corp.example",
            forwardIP: "10.0.0.53"
        )
        let override = DNSOverride(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
            domain: "service.example",
            value: "10.0.0.10",
            qtype: "A"
        )
        let allowed = AllowedDomain(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000003")!,
            domain: "allowed.example"
        )

        let snapshot = FullConfigSnapshotBuilder.build(
            isEnabled: true,
            dnssecEnabled: false,
            logQueriesEnabled: true,
            logRepliesEnabled: true,
            prefetchEnabled: false,
            serveExpiredEnabled: false,
            dohProviders: [.cloudflare, .quad9],
            dohDispatchMode: .parallel,
            dnsAnswerRefinementEnabled: false,
            blockDohDotEnabled: false,
            queryHistory: QueryHistorySettings(enabled: false, retentionDays: 14, popularCount: 500, popularDays: 14),
            customZones: [zone],
            dnsOverrides: [override],
            allowedDomains: [allowed]
        )

        XCTAssertEqual(
            Set(snapshot.keys),
            Set([
                "isEnabled",
                "dnssecEnabled",
                "logQueriesEnabled",
                "logRepliesEnabled",
                "prefetchEnabled",
                "serveExpiredEnabled",
                "dohProviders",
                "dohDispatchMode",
                "dnsAnswerRefinementEnabled",
                "blockDohDotEnabled",
                "queryHistoryEnabled",
                "queryHistoryRetentionDays",
                "popularPrefetchCount",
                "popularPrefetchDays",
                "customZones",
                "dnsOverrides",
                "allowlist",
            ])
        )
        XCTAssertEqual(
            snapshot["dohProviders"] as? [String],
            ["cloudflare", "quad9"]
        )
        XCTAssertEqual(
            (snapshot["customZones"] as? [[String: Any]])?.count,
            1
        )
        XCTAssertEqual(
            try QueryHistorySettings(config: snapshot),
            QueryHistorySettings(enabled: false, retentionDays: 14, popularCount: 500, popularDays: 14)
        )
        XCTAssertNil(snapshot["timestamp"])
        XCTAssertNil(snapshot["configRevision"])
    }

    func testFallbackSaveUsesCompareAndSwapRevision() throws {
        let stateFile = try temporaryStateFile(
            config: ["configRevision": 2, "value": "old"]
        )

        let revision = RevisionAwareConfigFileStore.save(
            snapshot: ["value": "new"],
            expectedRevision: 2,
            stateFile: stateFile,
            timestamp: 123
        )

        XCTAssertEqual(revision, 3)
        let persisted = try loadConfig(from: stateFile)
        XCTAssertEqual(ConfigRevisionPolicy.revision(from: persisted), 3)
        XCTAssertEqual(persisted["value"] as? String, "new")
        XCTAssertEqual(persisted["timestamp"] as? Double, 123)
    }

    func testFallbackSaveRejectsRevisionConflict() throws {
        let stateFile = try temporaryStateFile(
            config: ["configRevision": 2, "value": "old"]
        )

        let revision = RevisionAwareConfigFileStore.save(
            snapshot: ["value": "new"],
            expectedRevision: 1,
            stateFile: stateFile,
            timestamp: 123
        )

        XCTAssertNil(revision)
        let persisted = try loadConfig(from: stateFile)
        XCTAssertEqual(ConfigRevisionPolicy.revision(from: persisted), 2)
        XCTAssertEqual(persisted["value"] as? String, "old")
    }

    func testFallbackSaveRejectsStructurallyInvalidDNSPolicyBeforeCAS() throws {
        let stateFile = try temporaryStateFile(
            config: ["configRevision": 2, "value": "old"]
        )

        let revision = RevisionAwareConfigFileStore.save(
            snapshot: [
                "value": "new",
                "customZones": [
                    [
                        "id": "not-a-uuid",
                        "domain": "corp.example",
                        "forwardIP": "10.0.0.53",
                        "enabled": true,
                    ]
                ],
            ],
            expectedRevision: 2,
            stateFile: stateFile,
            timestamp: 123
        )

        XCTAssertNil(revision)
        let persisted = try loadConfig(from: stateFile)
        XCTAssertEqual(ConfigRevisionPolicy.revision(from: persisted), 2)
        XCTAssertEqual(persisted["value"] as? String, "old")
    }

    func testFallbackSaveRefusesToDowngradeANewerSchema() throws {
        let stateFile = try temporaryStateFile(
            config: [
                "configRevision": 2,
                "value": "old",
                "schemaVersion": ConfigSchemaPolicy.currentVersion + 1,
            ]
        )

        let revision = RevisionAwareConfigFileStore.save(
            snapshot: ["value": "new"],
            expectedRevision: 2,
            stateFile: stateFile,
            timestamp: 123
        )

        XCTAssertNil(revision)
        let persisted = try loadConfig(from: stateFile)
        XCTAssertEqual(persisted["value"] as? String, "old")
        XCTAssertEqual(
            persisted["schemaVersion"] as? Int,
            ConfigSchemaPolicy.currentVersion + 1
        )
    }

    func testFallbackSaveKeepsUnknownPersistedFieldsAndStampsTheSchema() throws {
        let stateFile = try temporaryStateFile(
            config: [
                "configRevision": 2,
                "value": "old",
                "fieldFromANewerBuild": "keep-me",
            ]
        )

        let revision = RevisionAwareConfigFileStore.save(
            snapshot: ["value": "new"],
            expectedRevision: 2,
            stateFile: stateFile,
            timestamp: 123
        )

        XCTAssertEqual(revision, 3)
        let persisted = try loadConfig(from: stateFile)
        XCTAssertEqual(persisted["value"] as? String, "new")
        XCTAssertEqual(persisted["fieldFromANewerBuild"] as? String, "keep-me")
        XCTAssertEqual(
            persisted["schemaVersion"] as? Int,
            ConfigSchemaPolicy.currentVersion
        )
    }

    func testFallbackSaveRejectsSemanticallyInvalidDNSPolicyBeforeCAS() throws {
        for (name, snapshot) in Self.semanticallyInvalidSnapshots {
            let stateFile = try temporaryStateFile(
                config: ["configRevision": 2, "value": "old"]
            )

            let revision = RevisionAwareConfigFileStore.save(
                snapshot: snapshot,
                expectedRevision: 2,
                stateFile: stateFile,
                timestamp: 123
            )

            XCTAssertNil(revision, "\(name) must not commit")
            let persisted = try loadConfig(from: stateFile)
            XCTAssertEqual(ConfigRevisionPolicy.revision(from: persisted), 2)
            XCTAssertEqual(persisted["value"] as? String, "old")
        }
    }

    func testFallbackSaveAcceptsSemanticallyValidDNSPolicy() throws {
        let stateFile = try temporaryStateFile(
            config: ["configRevision": 2, "value": "old"]
        )

        let revision = RevisionAwareConfigFileStore.save(
            snapshot: [
                "customZones": [
                    Self.zone(id: 1, domain: "corp.example", forwardIP: "10.0.0.53")
                ],
                "dnsOverrides": [
                    Self.override(id: 2, domain: "host.example", qtype: "A", value: "10.0.0.10"),
                    Self.override(id: 3, domain: "alias.example", qtype: "CNAME", value: "target.example."),
                    Self.override(id: 4, domain: "mail.example", qtype: "MX", value: "10 mx.example."),
                ],
            ],
            expectedRevision: 2,
            stateFile: stateFile,
            timestamp: 123
        )

        XCTAssertEqual(revision, 3)
    }

    func testFallbackSaveKeepsDisabledEntriesOutOfSemanticValidation() throws {
        let stateFile = try temporaryStateFile(
            config: ["configRevision": 2, "value": "old"]
        )

        let revision = RevisionAwareConfigFileStore.save(
            snapshot: [
                "dnsOverrides": [
                    Self.override(
                        id: 2,
                        domain: "host.example",
                        qtype: "A",
                        value: "not-an-ip",
                        enabled: false
                    )
                ]
            ],
            expectedRevision: 2,
            stateFile: stateFile,
            timestamp: 123
        )

        XCTAssertEqual(
            revision,
            3,
            "the resolver only receives enabled entries, so a disabled entry must not block a save"
        )
    }

    func testFallbackSaveRejectsStructurallyInvalidPersistedDNSPolicy() throws {
        let stateFile = try temporaryStateFile(
            config: [
                "configRevision": 2,
                "value": "old",
                "dnsOverrides": [
                    [
                        "id": "00000000-0000-0000-0000-000000000001",
                        "domain": "host.example",
                        "value": "10.0.0.10",
                        "qtype": "A",
                        "enabled": 1,
                    ]
                ],
            ]
        )

        let revision = RevisionAwareConfigFileStore.save(
            snapshot: ["value": "new"],
            expectedRevision: 2,
            stateFile: stateFile,
            timestamp: 123
        )

        XCTAssertNil(revision)
        let persisted = try loadConfig(from: stateFile)
        XCTAssertEqual(ConfigRevisionPolicy.revision(from: persisted), 2)
        XCTAssertEqual(persisted["value"] as? String, "old")
    }

    func testFallbackSaveNormalizesMissingDNSPolicyCollections() throws {
        let stateFile = try temporaryStateFile(
            config: ["configRevision": 0, "value": "old"]
        )

        let revision = RevisionAwareConfigFileStore.save(
            snapshot: ["value": "new"],
            expectedRevision: 0,
            stateFile: stateFile,
            timestamp: 123
        )

        XCTAssertEqual(revision, 1)
        let persisted = try loadConfig(from: stateFile)
        XCTAssertEqual((persisted["customZones"] as? [Any])?.count, 0)
        XCTAssertEqual((persisted["dnsOverrides"] as? [Any])?.count, 0)
    }

    func testConcurrentFallbackCASAllowsOnlyOneWriter() throws {
        let stateFile = try temporaryStateFile(
            config: ["configRevision": 0, "value": "initial"]
        )
        let resultLock = NSLock()
        var revisions: [ConfigRevision?] = []

        DispatchQueue.concurrentPerform(iterations: 2) { index in
            let revision = RevisionAwareConfigFileStore.save(
                snapshot: ["value": "writer-\(index)"],
                expectedRevision: 0,
                stateFile: stateFile,
                timestamp: TimeInterval(index)
            )
            resultLock.lock()
            revisions.append(revision)
            resultLock.unlock()
        }

        XCTAssertEqual(revisions.compactMap { $0 }, [1])
        let persisted = try loadConfig(from: stateFile)
        XCTAssertEqual(ConfigRevisionPolicy.revision(from: persisted), 1)
    }

    func testFallbackSaveDoesNotOverwriteInvalidState() throws {
        let stateFile = try temporaryStateFile(
            config: ["configRevision": 0]
        )
        let invalidData = Data("{invalid".utf8)
        try invalidData.write(to: stateFile, options: .atomic)

        let revision = RevisionAwareConfigFileStore.save(
            snapshot: ["value": "new"],
            expectedRevision: 0,
            stateFile: stateFile,
            timestamp: 123
        )

        XCTAssertNil(revision)
        XCTAssertEqual(try Data(contentsOf: stateFile), invalidData)
        guard case .invalid = StateFileLock.load(stateFile: stateFile) else {
            return XCTFail("Corrupt state must be classified as invalid")
        }
    }

    func testFallbackSaveCreatesMissingParentDirectory() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let stateFile =
            root
            .appendingPathComponent("nested", isDirectory: true)
            .appendingPathComponent("state.json")
        addTeardownBlock {
            try? FileManager.default.removeItem(at: root)
        }

        let revision = RevisionAwareConfigFileStore.save(
            snapshot: ["value": "new"],
            expectedRevision: 0,
            stateFile: stateFile,
            timestamp: 123
        )

        XCTAssertEqual(revision, 1)
        let persisted = try loadConfig(from: stateFile)
        XCTAssertEqual(ConfigRevisionPolicy.revision(from: persisted), 1)
        XCTAssertEqual(persisted["value"] as? String, "new")
    }

    func testStateDirectoryIsClassifiedAsIOFailure() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }

        guard case .ioFailure = StateFileLock.load(stateFile: directory) else {
            return XCTFail("Directory-backed state must fail as an I/O error")
        }
    }

    /// Same rejection cases `policy.rs` pins for `build_snapshot`, expressed in
    /// `state.json` shape so the App fallback writer is held to the resolver's
    /// contract.
    private static let semanticallyInvalidSnapshots: [(String, [String: Any])] = [
        (
            "invalid A value",
            ["dnsOverrides": [override(id: 1, domain: "host.example", qtype: "A", value: "not-an-ip")]]
        ),
        (
            "unsupported qtype",
            ["dnsOverrides": [override(id: 1, domain: "host.example", qtype: "NOTAREALTYPE", value: "x")]]
        ),
        (
            "invalid MX rdata",
            ["dnsOverrides": [override(id: 1, domain: "host.example", qtype: "MX", value: "99999 mx.example.")]]
        ),
        (
            "canonical duplicate override",
            [
                "dnsOverrides": [
                    override(id: 1, domain: "a.example", qtype: "A", value: "10.0.0.1"),
                    override(id: 2, domain: "A.EXAMPLE.", qtype: "A", value: "10.0.0.2"),
                ]
            ]
        ),
        (
            "CNAME conflict at one owner",
            [
                "dnsOverrides": [
                    override(id: 1, domain: "alias.example", qtype: "CNAME", value: "target.example."),
                    override(id: 2, domain: "alias.example", qtype: "A", value: "10.0.0.1"),
                ]
            ]
        ),
        (
            "invalid forward IP",
            ["customZones": [zone(id: 1, domain: "corp.example", forwardIP: "nope")]]
        ),
        (
            "canonical duplicate forward zone",
            [
                "customZones": [
                    zone(id: 1, domain: "corp.local", forwardIP: "10.0.0.53"),
                    zone(id: 2, domain: "CORP.LOCAL", forwardIP: "10.0.0.54"),
                ]
            ]
        ),
    ]

    private static func override(
        id: Int,
        domain: String,
        qtype: String,
        value: String,
        enabled: Bool = true
    ) -> [String: Any] {
        [
            "id": String(format: "00000000-0000-0000-0000-%012d", id),
            "domain": domain,
            "value": value,
            "qtype": qtype,
            "enabled": enabled,
        ]
    }

    private static func zone(
        id: Int,
        domain: String,
        forwardIP: String,
        enabled: Bool = true
    ) -> [String: Any] {
        [
            "id": String(format: "00000000-0000-0000-0000-%012d", id),
            "domain": domain,
            "forwardIP": forwardIP,
            "enabled": enabled,
        ]
    }

    private func temporaryStateFile(
        config: [String: Any]
    ) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        let stateFile = directory.appendingPathComponent("state.json")
        let data = try JSONSerialization.data(withJSONObject: config)
        try data.write(to: stateFile, options: .atomic)
        return stateFile
    }

    private func loadConfig(from stateFile: URL) throws -> [String: Any] {
        try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(contentsOf: stateFile)
            ) as? [String: Any]
        )
    }
}
