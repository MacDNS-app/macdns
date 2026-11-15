// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Security
import Shared
import XCTest

@testable import MacDNSAgent

final class AgentConfigurationSafetyTests: XCTestCase {
    func testBlocklistSettingsRollbackWhenResolverRejectsConfiguration() throws {
        let environment = try blocklistEnvironment(
            resolver: RejectingBlocklistResolver(),
            initialSettings: BlocklistTestSettings.disabled
        )
        let newSettings = environment.settings(BlocklistTestSettings.ads)

        let result = waitForBlocklistUpdate(manager: environment.manager, settings: newSettings)

        XCTAssertFalse(result)
        XCTAssertEqual(environment.manager.getSettings(), environment.settings(BlocklistTestSettings.disabled))
        XCTAssertEqual(try environment.projectedSettings(), environment.settings(BlocklistTestSettings.disabled))
    }

    func testStaleBlocklistRollbackDoesNotOverwriteNewerSettings() throws {
        let environment = try blocklistEnvironment(
            resolver: AcceptingBlocklistResolver(),
            initialSettings: BlocklistTestSettings.malware
        )
        let failedSettings = environment.settings(BlocklistTestSettings.ads)
        let oldSettings = environment.settings(BlocklistTestSettings.disabled)
        let newerSettings = environment.settings(BlocklistTestSettings.malware)

        let rolledBack = environment.manager.rollback(from: failedSettings, to: oldSettings)

        XCTAssertFalse(rolledBack)
        XCTAssertEqual(environment.manager.getSettings(), newerSettings)
        XCTAssertEqual(try environment.projectedSettings(), newerSettings)
    }

    func testConfigureFailureRollbackDoesNotOverwriteNewerSettings() throws {
        let resolver = InterleavedRejectingBlocklistResolver()
        let environment = try blocklistEnvironment(
            resolver: resolver,
            initialSettings: BlocklistTestSettings.disabled
        )
        let newerSettings = environment.settings(BlocklistTestSettings.malware)
        resolver.onFirstRejectedConfigure = {
            _ = environment.manager.rollback(to: newerSettings)
        }

        let result = waitForBlocklistUpdate(
            manager: environment.manager,
            settings: environment.settings(BlocklistTestSettings.ads)
        )

        XCTAssertFalse(result)
        XCTAssertEqual(environment.manager.getSettings(), newerSettings)
        XCTAssertEqual(try environment.projectedSettings(), newerSettings)
    }

    func testReloadFailureRollsBackBlocklistSettings() throws {
        let environment = try blocklistEnvironment(
            resolver: ReloadFailingBlocklistResolver(),
            initialSettings: BlocklistTestSettings.ads
        )
        let oldSettings = environment.settings(BlocklistTestSettings.ads)
        var failedSettings = oldSettings
        failedSettings.enabled = false

        let result = waitForBlocklistUpdate(
            manager: environment.manager,
            settings: failedSettings,
            reloadAfterUpdate: true
        )

        XCTAssertFalse(result)
        XCTAssertEqual(environment.manager.getSettings(), oldSettings)
        XCTAssertEqual(try environment.projectedSettings(), oldSettings)
    }

    func testReloadFailureRollbackDoesNotOverwriteNewerSettings() throws {
        let resolver = ReloadFailingBlocklistResolver()
        let environment = try blocklistEnvironment(
            resolver: resolver,
            initialSettings: BlocklistTestSettings.ads
        )
        let newerSettings = environment.settings(BlocklistTestSettings.malware)
        resolver.onReload = {
            _ = environment.manager.rollback(to: newerSettings)
        }
        var failedSettings = environment.settings(BlocklistTestSettings.ads)
        failedSettings.enabled = false

        let result = waitForBlocklistUpdate(
            manager: environment.manager,
            settings: failedSettings,
            reloadAfterUpdate: true
        )

        XCTAssertFalse(result)
        XCTAssertEqual(environment.manager.getSettings(), newerSettings)
        XCTAssertEqual(try environment.projectedSettings(), newerSettings)
    }

    func testBlocklistSettingsDiskWriteFailureDoesNotConfigureResolver() throws {
        let tempDir = try temporaryDirectory()
        let resolver = CountingBlocklistResolver()
        let environment = try blocklistEnvironment(
            in: tempDir,
            resolver: resolver,
            initialSettings: nil,
            stateFile: tempDir.appendingPathComponent("missing-parent/state.json")
        )
        let newSettings = environment.settings(BlocklistTestSettings.ads)

        let result = waitForBlocklistUpdate(manager: environment.manager, settings: newSettings)

        XCTAssertFalse(result)
        XCTAssertNotEqual(environment.manager.getSettings(), newSettings)
        XCTAssertEqual(resolver.configureCallCount, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: environment.stateFile.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: environment.projectionFile.path))
    }

    /// The projection is derived state: when it cannot be emitted the whole
    /// transaction is refused and `state.json` keeps the last value the running
    /// resolver was configured from.
    func testUnwritableProjectionKeepsTheLastValidRuntimeState() throws {
        let resolver = CountingBlocklistResolver()
        let environment = try blocklistEnvironment(
            resolver: resolver,
            initialSettings: BlocklistTestSettings.ads
        )
        let persistedSettings = environment.settings(BlocklistTestSettings.ads)
        let persistedRevision = try XCTUnwrap(environment.persistedRevision())
        try FileManager.default.removeItem(at: environment.projectionFile)
        try FileManager.default.createDirectory(
            at: environment.projectionFile,
            withIntermediateDirectories: false
        )

        let result = waitForBlocklistUpdate(
            manager: environment.manager,
            settings: environment.settings(BlocklistTestSettings.malware)
        )

        XCTAssertFalse(result)
        XCTAssertEqual(environment.manager.getSettings(), persistedSettings)
        XCTAssertEqual(environment.persistedRevision(), persistedRevision)
        XCTAssertEqual(resolver.configureCallCount, 0)
    }

    func testBlocklistRollbackIgnoresLastUpdatedWhenConfigurationStillMatches() throws {
        var refreshedSettings = BlocklistTestSettings.ads
        refreshedSettings.lastUpdated = Date(timeIntervalSince1970: 1_234)
        let environment = try blocklistEnvironment(
            resolver: AcceptingBlocklistResolver(),
            initialSettings: refreshedSettings
        )
        let failedSettings = environment.settings(BlocklistTestSettings.ads)
        let oldSettings = environment.settings(BlocklistTestSettings.disabled)

        let rolledBack = environment.manager.rollback(from: failedSettings, to: oldSettings)

        XCTAssertTrue(rolledBack)
        XCTAssertEqual(environment.manager.getSettings(), oldSettings)
        XCTAssertEqual(try environment.projectedSettings(), oldSettings)
    }

    func testCompleteRollbackNeitherStopsNorBypasses() {
        let recovery = RollbackRecoveryRecorder(stopSucceeds: true, forcedStopSucceeds: true)

        let outcome = recovery.recover(fullyRestored: true)

        XCTAssertEqual(outcome, .restored)
        XCTAssertEqual(recovery.events, [])
    }

    func testIncompleteRollbackWithConfirmedStopDoesNotEscalate() {
        let recovery = RollbackRecoveryRecorder(stopSucceeds: true, forcedStopSucceeds: true)

        let outcome = recovery.recover(fullyRestored: false)

        XCTAssertEqual(outcome, .stopped)
        XCTAssertEqual(recovery.events, [.stop])
    }

    func testIncompleteRollbackBypassesBeforeForcingTeardownWhenStopIsUnconfirmed() {
        let recovery = RollbackRecoveryRecorder(stopSucceeds: false, forcedStopSucceeds: true)

        let outcome = recovery.recover(fullyRestored: false)

        XCTAssertEqual(outcome, .forcedStop)
        XCTAssertEqual(recovery.events, [.stop, .bypass, .forcedStop])
    }

    func testIncompleteRollbackKeepsInterceptionBypassedWhenTeardownNeverConfirms() {
        let recovery = RollbackRecoveryRecorder(stopSucceeds: false, forcedStopSucceeds: false)

        let outcome = recovery.recover(fullyRestored: false)

        XCTAssertEqual(outcome, .bypassed)
        XCTAssertEqual(recovery.events, [.stop, .bypass, .forcedStop])
    }

    /// Admission validates the incoming payload. The merge must not be able to
    /// hand `writeFile` policy that was never admitted. Structural
    /// normalization always materializes both collections, so the candidate,
    /// never the persisted document, decides them.
    func testMergedMutationCannotResurrectPolicyAdmissionDidNotValidate() throws {
        let persistedZone: [String: Any] = [
            "id": UUID().uuidString,
            "domain": "legacy.example",
            "forwardIP": "10.0.0.53",
            "enabled": true,
        ]
        let persisted: [String: Any] = [
            "configRevision": ConfigRevision(4),
            "customZones": [persistedZone],
            "dnsOverrides": [persistedZone],
        ]
        let candidate = try XCTUnwrap(
            DNSPolicyStructuralPolicy.validateAndNormalize(["isEnabled": true])
        ).normalizedConfig

        let merged = FullConfigMutationMergePolicy.merged(
            candidate: candidate,
            persisted: persisted,
            defaults: [:]
        )

        XCTAssertEqual((merged["customZones"] as? [[String: Any]])?.count, 0)
        XCTAssertEqual((merged["dnsOverrides"] as? [[String: Any]])?.count, 0)
        XCTAssertNil(MacDNSAgent.fullConfigAdmissionRejection(for: merged))
    }

    func testCodeSignValidationBuildsParseableClientRequirement() {
        let requirementString = CodeSignValidator.clientRequirementString(expectedTeamID: "TEAMID")

        XCTAssertEqual(
            requirementString,
            #"anchor apple generic and identifier "app.macdns" and certificate leaf[subject.OU] = "TEAMID""#
        )

        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(requirementString as CFString, SecCSFlags(), &requirement)
        XCTAssertEqual(status, errSecSuccess)
        XCTAssertNotNil(requirement)
    }

    func testStaleRevisionIsRejectedBeforeRuntimeApply() throws {
        let harness = AcceptedFullConfigTransactionHarness(failure: .allowlist)
        let persisted = harness.oldConfig
        var incoming = harness.pendingConfig
        incoming["configRevision"] = ConfigRevision(3)

        let classification = try AgentConfigRevisionPolicy.classify(
            incoming: incoming,
            persisted: persisted
        )

        XCTAssertEqual(classification, .conflict)

        let response = performFullConfigTransaction(
            using: harness,
            classification: classification,
            persistedRevision: 4,
            oldConfig: persisted,
            fullConfig: incoming
        )

        XCTAssertEqual(response.status, .conflict)
        XCTAssertEqual(response.authoritativeRevision, 4)
        assertNoFullConfigCollaboratorCalls(harness)
    }

    func testAcceptedSaveIncrementsRevisionExactlyOnce() throws {
        let classification = try AgentConfigRevisionPolicy.classify(
            incoming: ["configRevision": 4, "isEnabled": true],
            persisted: ["configRevision": 4, "isEnabled": false]
        )

        XCTAssertEqual(classification, .accept(nextRevision: 5))
    }

    func testIdenticalRetryReturnsAlreadyCommittedWithoutMutation() throws {
        let harness = AcceptedFullConfigTransactionHarness(failure: .allowlist)
        var incoming = harness.oldConfig
        incoming["configRevision"] = ConfigRevision(4)
        var persisted = harness.oldConfig
        persisted["configRevision"] = ConfigRevision(5)
        let classification = try AgentConfigRevisionPolicy.classify(
            incoming: incoming,
            persisted: persisted
        )

        XCTAssertEqual(classification, .idempotentSuccess)

        let response = performFullConfigTransaction(
            using: harness,
            classification: classification,
            persistedRevision: 5,
            oldConfig: persisted,
            fullConfig: incoming
        )

        XCTAssertEqual(response.status, .alreadyCommitted)
        XCTAssertEqual(response.authoritativeRevision, 5)
        assertNoFullConfigCollaboratorCalls(harness)
    }

    func testDifferentRetryAtConsumedRevisionIsRejected() throws {
        let classification = try AgentConfigRevisionPolicy.classify(
            incoming: ["configRevision": 4, "isEnabled": false],
            persisted: ["configRevision": 5, "isEnabled": true]
        )

        XCTAssertEqual(classification, .conflict)
    }

    func testAcceptedAllowlistFailureRollsBackConsumedRevision() throws {
        try assertAcceptedFailureRollsBack(.allowlist)
    }

    func testAcceptedZonesFailureRollsBackConsumedRevision() throws {
        try assertAcceptedFailureRollsBack(.zonesAndOverrides)
    }

    func testAcceptedBlocklistFailureRollsBackConsumedRevision() throws {
        try assertAcceptedFailureRollsBack(.blocklist)
    }

    func testAcceptedBackendBounceFailureRollsBackExactlyOnceAtConsumedRevision() throws {
        try assertAcceptedFailureRollsBack(.backendBounce)
    }

    func testSuccessfulBackendBounceSkipsPreBounceGenerationCommitCheck() {
        let harness = AcceptedFullConfigTransactionHarness(
            failure: .successfulBackendBounce
        )

        let response = performFullConfigTransaction(using: harness)

        XCTAssertEqual(response.status, .committed)
        XCTAssertEqual(response.authoritativeRevision, 5)
        XCTAssertEqual(harness.backendBounceCallCount, 1)
        XCTAssertEqual(harness.rollbackCallCount, 0)
        XCTAssertEqual(harness.commitCallCount, 0)
    }

    func testCommittedSaveAppliesHistorySettingsLastBeforeCommit() {
        let harness = AcceptedFullConfigTransactionHarness(failure: nil)

        let response = performFullConfigTransaction(using: harness)

        XCTAssertEqual(response.status, .committed)
        XCTAssertEqual(harness.steps, ["options", "allowlist", "zones", "blocklist", "history", "commit"])
        XCTAssertEqual(harness.historySettings, AcceptedFullConfigTransactionHarness.pendingHistory)
    }

    func testHistorySettingsApplyAfterASuccessfulBackendBounce() {
        let harness = AcceptedFullConfigTransactionHarness(failure: .successfulBackendBounce)

        let response = performFullConfigTransaction(using: harness)

        XCTAssertEqual(response.status, .committed)
        XCTAssertEqual(harness.steps, ["allowlist", "bounce", "history"])
        XCTAssertEqual(harness.historySettings, AcceptedFullConfigTransactionHarness.pendingHistory)
    }

    /// Turning history off while protection is off must delete the database
    /// at once, not at the next start.
    func testHistorySettingsApplyWhileTheResolverIsStopped() {
        let harness = AcceptedFullConfigTransactionHarness(failure: nil, resolverRunning: false)

        let response = performFullConfigTransaction(using: harness)

        XCTAssertEqual(response.status, .committed)
        XCTAssertEqual(harness.steps, ["allowlist", "history", "commit"])
        XCTAssertEqual(harness.historySettings, AcceptedFullConfigTransactionHarness.pendingHistory)
    }

    /// Turning history off deletes the database, which no rollback can bring
    /// back, so a step that can still fail must never run after it.
    func testFailingEarlierStepLeavesHistoryUntouched() {
        let failures: [AcceptedFullConfigTransactionHarness.Failure] = [
            .options, .allowlist, .zonesAndOverrides, .blocklist, .backendBounce,
        ]
        for failure in failures {
            let harness = AcceptedFullConfigTransactionHarness(failure: failure)

            let response = performFullConfigTransaction(using: harness)

            XCTAssertEqual(response.status, .rejected, "\(failure)")
            XCTAssertEqual(harness.rollbackCallCount, 1, "\(failure)")
            XCTAssertEqual(harness.historyCallCount, 0, "\(failure)")
            XCTAssertEqual(
                harness.historySettings,
                AcceptedFullConfigTransactionHarness.oldHistory,
                "\(failure)"
            )
        }
    }

    func testRejectedHistorySettingsRollBackTheEarlierSteps() throws {
        try assertAcceptedFailureRollsBack(.history)
    }

    func testAcceptedFileWriteFailureKeepsPersistedRevisionWithoutRollback() {
        let harness = AcceptedFullConfigTransactionHarness(failure: .fileWrite)

        let response = performFullConfigTransaction(using: harness)

        XCTAssertEqual(response.status, .rejected)
        XCTAssertEqual(response.authoritativeRevision, 4)
        XCTAssertEqual(response.rejectionReason, .persistenceFailure)
        XCTAssertEqual(harness.prepareCallCount, 1)
        XCTAssertEqual(harness.fileWriteCallCount, 1)
        XCTAssertEqual(harness.optionsCallCount, 0)
        XCTAssertEqual(harness.allowlistCallCount, 0)
        XCTAssertEqual(harness.zonesAndOverridesCallCount, 0)
        XCTAssertEqual(harness.blocklistCallCount, 0)
        XCTAssertEqual(harness.backendBounceCallCount, 0)
        XCTAssertEqual(harness.rollbackCallCount, 0)
        XCTAssertEqual(harness.commitCallCount, 0)
        XCTAssertNil(harness.rollbackConfig)
        XCTAssertEqual(harness.persistedDomain, "old.example")
    }

    func testAgentOwnedMutationRefusesRevisionOverflow() {
        XCTAssertNil(
            AgentConfigRevisionPolicy.configForAgentOwnedMutation(
                ["configRevision": ConfigRevision.max]
            )
        )
    }

    func testLifecycleGenerationPolicyRejectsConcurrentStop() {
        XCTAssertTrue(
            AgentLifecycleGenerationPolicy.matches(
                lifecycleGeneration: 7,
                stopGeneration: 3,
                expectedLifecycleGeneration: 7,
                expectedStopGeneration: 3
            )
        )
        XCTAssertFalse(
            AgentLifecycleGenerationPolicy.matches(
                lifecycleGeneration: 7,
                stopGeneration: 4,
                expectedLifecycleGeneration: 7,
                expectedStopGeneration: 3
            )
        )
    }

    func testLifecycleGenerationPolicyRejectsConcurrentStart() {
        XCTAssertFalse(
            AgentLifecycleGenerationPolicy.matches(
                lifecycleGeneration: 8,
                stopGeneration: 3,
                expectedLifecycleGeneration: 7,
                expectedStopGeneration: 3
            )
        )
    }

    func testMissingAllowlistIsClassifiedForMigration() {
        guard case .missing = AgentAllowlistConfigPolicy.classify([:]) else {
            return XCTFail("Missing allowlist must remain distinguishable")
        }
    }

    func testExplicitEmptyAllowlistIsValid() {
        guard
            case .valid(let dictionaries, let domains) =
                AgentAllowlistConfigPolicy.classify(["allowlist": []])
        else {
            return XCTFail("Explicit empty allowlist must be authoritative")
        }
        XCTAssertTrue(dictionaries.isEmpty)
        XCTAssertTrue(domains.isEmpty)
    }

    func testMalformedAllowlistIsRejected() {
        let validID = UUID().uuidString
        for value: Any in [
            NSNull(),
            "bad",
            [["enabled": true]],
            [["id": "bad", "domain": "example.com", "enabled": true]],
            [["id": validID, "domain": "", "enabled": true]],
            [["id": validID, "domain": "example.com", "enabled": "false"]],
        ] {
            guard
                case .invalid = AgentAllowlistConfigPolicy.classify([
                    "allowlist": value
                ])
            else {
                return XCTFail("Malformed allowlist must not clear LMDB")
            }
        }
    }

    private func waitForBlocklistUpdate(
        manager: BlocklistManager, settings: BlocklistSettings, reloadAfterUpdate: Bool = false
    ) -> Bool {
        let expectation = expectation(description: "blocklist update completes")
        var result = true
        manager.updateSettings(settings, reloadAfterUpdate: reloadAfterUpdate) { success in
            result = success
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)
        return result
    }

    private func assertAcceptedFailureRollsBack(
        _ failure: AcceptedFullConfigTransactionHarness.Failure
    ) throws {
        let harness = AcceptedFullConfigTransactionHarness(failure: failure)

        let response = performFullConfigTransaction(using: harness)

        XCTAssertEqual(response.status, .rejected)
        XCTAssertNotEqual(response.status, .committed)
        XCTAssertEqual(response.authoritativeRevision, 5)
        XCTAssertEqual(response.rejectionReason, .runtimeApplyFailure)
        let rollback = try XCTUnwrap(harness.rollbackConfig)
        XCTAssertEqual(ConfigRevisionPolicy.revision(from: rollback), 5)
        XCTAssertEqual(harness.persistedDomain, "old.example")
        XCTAssertEqual(harness.allowlistDomain, "allowed.old.example")
        XCTAssertEqual(harness.zoneDomain, "zone.old.example")
        XCTAssertEqual(harness.overrideValue, "10.0.0.1")
        XCTAssertEqual(harness.dnssecEnabled, true)
        XCTAssertEqual(harness.blocklistState, .old)
        XCTAssertEqual(harness.prepareCallCount, 1)
        XCTAssertEqual(harness.fileWriteCallCount, 1)
        XCTAssertEqual(harness.rollbackCallCount, 1)
        XCTAssertEqual(harness.commitCallCount, 0)
        if failure == .backendBounce {
            XCTAssertEqual(harness.backendBounceCallCount, 1)
        }
        if failure == .history {
            XCTAssertEqual(harness.steps.suffix(2), ["history", "rollback"])
            XCTAssertEqual(harness.historySettings, AcceptedFullConfigTransactionHarness.oldHistory)
        }
    }

    private func performFullConfigTransaction(
        using harness: AcceptedFullConfigTransactionHarness,
        classification: ConfigSaveRequestClassification = .accept(nextRevision: 5),
        persistedRevision: ConfigRevision = 4,
        oldConfig: [String: Any]? = nil,
        fullConfig: [String: Any]? = nil
    ) -> FullConfigSaveResponse {
        MacDNSAgent.performFullConfigTransaction(
            classification: classification,
            persistedRevision: persistedRevision,
            oldConfig: oldConfig ?? harness.oldConfig,
            fullConfig: fullConfig ?? harness.pendingConfig,
            prepareAccepted: harness.prepareAccepted,
            writeFile: harness.writeFile,
            syncAllowlist: harness.syncAllowlist,
            applyZonesAndOverrides: harness.applyZonesAndOverrides,
            reloadBlocklist: harness.reloadBlocklist
        )
    }

    private func assertNoFullConfigCollaboratorCalls(
        _ harness: AcceptedFullConfigTransactionHarness
    ) {
        XCTAssertEqual(harness.prepareCallCount, 0)
        XCTAssertEqual(harness.optionsCallCount, 0)
        XCTAssertEqual(harness.fileWriteCallCount, 0)
        XCTAssertEqual(harness.allowlistCallCount, 0)
        XCTAssertEqual(harness.zonesAndOverridesCallCount, 0)
        XCTAssertEqual(harness.blocklistCallCount, 0)
        XCTAssertEqual(harness.backendBounceCallCount, 0)
        XCTAssertEqual(harness.rollbackCallCount, 0)
        XCTAssertEqual(harness.commitCallCount, 0)
        XCTAssertEqual(harness.historyCallCount, 0)
    }

    func testConcurrentStopWaitsForTheInFlightStopBeforeAnswering() {
        var stopInFlight = true
        var resolverRunning = true
        var waitCount = 0

        let stopped = ConcurrentStopSequencer.awaitInFlightStop(
            enqueueWaiter: { stopInFlight ? waitCount : nil },
            wait: { _ in
                waitCount += 1
                stopInFlight = false
                resolverRunning = false
                return true
            },
            resolverStopped: { !resolverRunning }
        )

        XCTAssertTrue(stopped)
        XCTAssertEqual(waitCount, 1)
    }

    func testConcurrentStopKeepsWaitingUntilTheStopFlagClears() {
        var remainingTransitions = 3
        var waitCount = 0

        let stopped = ConcurrentStopSequencer.awaitInFlightStop(
            enqueueWaiter: { remainingTransitions > 0 ? waitCount : nil },
            wait: { _ in
                waitCount += 1
                remainingTransitions -= 1
                return true
            },
            resolverStopped: { true }
        )

        XCTAssertTrue(stopped)
        XCTAssertEqual(waitCount, 3)
    }

    func testConcurrentStopReportsObservedStateWhenTheWaitTimesOut() {
        var waitCount = 0

        let stopped = ConcurrentStopSequencer.awaitInFlightStop(
            enqueueWaiter: { waitCount },
            wait: { _ in
                waitCount += 1
                return false
            },
            resolverStopped: { false }
        )

        XCTAssertFalse(stopped)
        XCTAssertEqual(waitCount, 1)
    }

    func testMutationKeepsPersistedValuesForFieldsTheCallerOmitted() {
        let merged = FullConfigMutationMergePolicy.merged(
            candidate: ["isEnabled": true],
            persisted: ["isEnabled": false, "blockDohDotEnabled": false],
            defaults: ["isEnabled": false, "blockDohDotEnabled": true, "dnssecEnabled": true]
        )

        XCTAssertEqual(merged["isEnabled"] as? Bool, true)
        XCTAssertEqual(merged["blockDohDotEnabled"] as? Bool, false)
        XCTAssertEqual(merged["dnssecEnabled"] as? Bool, true)
    }

    func testShippedDefaultsLeaveDoHBlockingOff() {
        XCTAssertEqual(
            FullConfigNormalizationPolicy.defaults()["blockDohDotEnabled"] as? Bool,
            false
        )
    }

    func testSavePayloadWithoutDoHBlockingKeyKeepsThePersistedValue() throws {
        for persisted in [false, true] {
            let normalized = try XCTUnwrap(
                FullConfigNormalizationPolicy.normalized(
                    ["isEnabled": true],
                    mergedWith: ["blockDohDotEnabled": persisted]
                )
            )

            XCTAssertEqual(normalized["blockDohDotEnabled"] as? Bool, persisted)
        }
    }

    func testMissingStateDocumentNormalizesToOff() throws {
        let normalized = try XCTUnwrap(
            FullConfigNormalizationPolicy.normalized([:])
        )

        XCTAssertEqual(normalized["blockDohDotEnabled"] as? Bool, false)
    }

    func testStateWithoutDoHBlockingKeyNormalizesToOff() throws {
        for state in [
            ["schemaVersion": ConfigSchemaPolicy.currentVersion, "isEnabled": true],
            ["isEnabled": true],
        ] as [[String: Any]] {
            let normalized = try XCTUnwrap(FullConfigNormalizationPolicy.normalized(state))

            XCTAssertEqual(normalized["blockDohDotEnabled"] as? Bool, false)
        }
    }

    func testMutationPreservesUnknownTopLevelFieldsFromBothSides() {
        let merged = FullConfigMutationMergePolicy.merged(
            candidate: ["fromNewerClient": 1],
            persisted: ["fromNewerBuild": "keep-me"],
            defaults: ["isEnabled": false]
        )

        XCTAssertEqual(merged["fromNewerClient"] as? Int, 1)
        XCTAssertEqual(merged["fromNewerBuild"] as? String, "keep-me")
        XCTAssertEqual(merged["isEnabled"] as? Bool, false)
    }

    func testMutationLetsTheCallerOverrideEveryPersistedValue() {
        let merged = FullConfigMutationMergePolicy.merged(
            candidate: ["isEnabled": false, "customZones": [[String: Any]]()],
            persisted: ["isEnabled": true, "customZones": [["id": "x"]]],
            defaults: ["isEnabled": false, "customZones": [[String: Any]]()]
        )

        XCTAssertEqual(merged["isEnabled"] as? Bool, false)
        XCTAssertEqual((merged["customZones"] as? [Any])?.count, 0)
    }

    func testDefaultsApplyWhenThereIsNoPersistedState() {
        let merged = FullConfigMutationMergePolicy.merged(
            candidate: [:],
            persisted: [:],
            defaults: ["isEnabled": false, "blockDohDotEnabled": true]
        )

        XCTAssertEqual(merged["isEnabled"] as? Bool, false)
        XCTAssertEqual(merged["blockDohDotEnabled"] as? Bool, true)
    }

    func testAdmissionRejectsPayloadsJSONSerializationCannotEncode() {
        XCTAssertNotNil(
            MacDNSAgent.fullConfigAdmissionRejection(
                for: ["isEnabled": true, "timestamp": Date()]
            )
        )
    }

    func testAdmissionRejectsPolicyTheResolverWouldRefuse() {
        for candidate in [
            Self.candidate(overrides: [
                Self.override(domain: "host.example", qtype: "A", value: "not-an-ip")
            ]),
            Self.candidate(overrides: [
                Self.override(domain: "host.example", qtype: "NOTAREALTYPE", value: "x")
            ]),
            Self.candidate(overrides: [
                Self.override(domain: "mail.example", qtype: "MX", value: "99999 mx.example.")
            ]),
            Self.candidate(overrides: [
                Self.override(id: 1, domain: "a.example", qtype: "A", value: "10.0.0.1"),
                Self.override(id: 2, domain: "A.EXAMPLE.", qtype: "A", value: "10.0.0.2"),
            ]),
            Self.candidate(overrides: [
                Self.override(
                    id: 1,
                    domain: "alias.example",
                    qtype: "CNAME",
                    value: "target.example"
                ),
                Self.override(id: 2, domain: "alias.example", qtype: "A", value: "10.0.0.1"),
            ]),
            Self.candidate(zones: [Self.zone(domain: "corp.local", forwardIP: "nope")]),
            Self.candidate(zones: [
                Self.zone(id: 1, domain: "corp.local", forwardIP: "10.0.0.53"),
                Self.zone(id: 2, domain: "CORP.LOCAL", forwardIP: "10.0.0.54"),
            ]),
        ] {
            XCTAssertNotNil(
                MacDNSAgent.fullConfigAdmissionRejection(for: candidate),
                "admitted \(candidate)"
            )
        }
    }

    func testAdmissionAcceptsPolicyTheResolverWouldAccept() {
        XCTAssertNil(
            MacDNSAgent.fullConfigAdmissionRejection(
                for: Self.candidate(
                    zones: [Self.zone(domain: "corp.local", forwardIP: "10.0.0.53")],
                    overrides: [
                        Self.override(domain: "host.example", qtype: "A", value: "10.0.0.10")
                    ]
                )
            )
        )
    }

    func testAdmissionIgnoresDisabledEntries() {
        XCTAssertNil(
            MacDNSAgent.fullConfigAdmissionRejection(
                for: Self.candidate(
                    zones: [
                        Self.zone(domain: "corp.local", forwardIP: "nope", enabled: false)
                    ],
                    overrides: [
                        Self.override(
                            domain: "host.example",
                            qtype: "A",
                            value: "not-an-ip",
                            enabled: false
                        )
                    ]
                )
            )
        )
    }

    private static func candidate(
        zones: [[String: Any]] = [],
        overrides: [[String: Any]] = []
    ) -> [String: Any] {
        ["isEnabled": true, "customZones": zones, "dnsOverrides": overrides]
    }

    private static func zone(
        id: Int = 1,
        domain: String,
        forwardIP: String,
        enabled: Bool = true
    ) -> [String: Any] {
        [
            "id": identifier(id),
            "domain": domain,
            "forwardIP": forwardIP,
            "enabled": enabled,
        ]
    }

    private static func override(
        id: Int = 2,
        domain: String,
        qtype: String,
        value: String,
        enabled: Bool = true
    ) -> [String: Any] {
        [
            "id": identifier(id),
            "domain": domain,
            "value": value,
            "qtype": qtype,
            "enabled": enabled,
        ]
    }

    private static func identifier(_ id: Int) -> String {
        String(format: "00000000-0000-0000-0000-%012d", id)
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("macdns-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
        }
        return url
    }

    private func blocklistEnvironment(
        in directory: URL? = nil,
        resolver: BlocklistResolverBackend,
        initialSettings: BlocklistSettings?,
        stateFile: URL? = nil,
        projectionFile: URL? = nil
    ) throws -> BlocklistTestEnvironment {
        let tempDir = try directory ?? temporaryDirectory()
        let environment = BlocklistTestEnvironment(
            resolver: resolver,
            stateFile: stateFile ?? tempDir.appendingPathComponent("state.json"),
            projectionFile: projectionFile
                ?? tempDir.appendingPathComponent("blocklist_settings.json"),
            blocklistsDir: tempDir.appendingPathComponent("blocklists").path
        )
        if let initialSettings {
            XCTAssertNotNil(
                environment.store.mutate { _ in environment.settings(initialSettings) },
                "seeding the blocklist settings must succeed"
            )
        }
        return environment
    }
}

/// Records the order in which an incomplete rollback escalates, so a bypass
/// that lands after the forced teardown is a failure instead of a detail.
private final class RollbackRecoveryRecorder {
    enum Event: Equatable {
        case stop
        case bypass
        case forcedStop
    }

    private(set) var events: [Event] = []
    private let stopSucceeds: Bool
    private let forcedStopSucceeds: Bool

    init(stopSucceeds: Bool, forcedStopSucceeds: Bool) {
        self.stopSucceeds = stopSucceeds
        self.forcedStopSucceeds = forcedStopSucceeds
    }

    func recover(fullyRestored: Bool) -> IncompleteRollbackRecoveryPolicy.Outcome {
        IncompleteRollbackRecoveryPolicy.recover(
            fullyRestored: fullyRestored,
            stopServices: {
                events.append(.stop)
                return stopSucceeds
            },
            forceStopServices: {
                events.append(.forcedStop)
                return forcedStopSucceeds
            },
            failClosedBypass: { events.append(.bypass) }
        )
    }
}

/// Category selections the blocklist tests persist. `dbBasePath` is bound to the
/// test's temporary directory by `BlocklistTestEnvironment.settings(_:)`.
private enum BlocklistTestSettings {
    static let disabled = BlocklistSettings(enabled: false, categories: [], dbBasePath: "")
    static let ads = BlocklistSettings(
        enabled: true,
        categories: [
            CategoryConfig(name: "Ads & Tracking Normal", identifier: "ads_tracking", level: "multi")
        ],
        dbBasePath: ""
    )
    static let malware = BlocklistSettings(
        enabled: true,
        categories: [
            CategoryConfig(name: "Malware & Security Pro", identifier: "malware_security", level: "tif.medium")
        ],
        dbBasePath: ""
    )
}

private struct BlocklistTestEnvironment {
    let store: StateFileBlocklistSettingsStore
    let manager: BlocklistManager
    let stateFile: URL
    let projectionFile: URL
    let blocklistsDir: String

    init(
        resolver: BlocklistResolverBackend,
        stateFile: URL,
        projectionFile: URL,
        blocklistsDir: String
    ) {
        self.stateFile = stateFile
        self.projectionFile = projectionFile
        self.blocklistsDir = blocklistsDir
        store = StateFileBlocklistSettingsStore(
            stateFile: stateFile,
            projectionFile: projectionFile,
            blocklistsDir: blocklistsDir
        )
        manager = BlocklistManager(
            resolver: resolver,
            store: store,
            blocklistsDir: blocklistsDir
        )
    }

    func settings(_ template: BlocklistSettings) -> BlocklistSettings {
        var settings = template
        settings.dbBasePath = blocklistsDir
        return settings
    }

    func projectedSettings() throws -> BlocklistSettings {
        try JSONCoding.decoder.decode(
            BlocklistSettings.self,
            from: Data(contentsOf: projectionFile)
        )
    }

    func persistedRevision() -> ConfigRevision? {
        guard case .valid(let config) = StateFileLock.load(stateFile: stateFile) else {
            return nil
        }
        return ConfigRevisionPolicy.revision(from: config)
    }
}

private final class RejectingBlocklistResolver: BlocklistResolverBackend {
    func configureBlocklist(settingsPath: String) -> Bool {
        false
    }

    func forceBlocklistUpdateResult() -> ResolverModule.BlocklistUpdateResult {
        .unchanged
    }

    func reloadBlocklist() -> Bool {
        true
    }

}

private final class InterleavedRejectingBlocklistResolver: BlocklistResolverBackend {
    var onFirstRejectedConfigure: (() -> Void)?
    private var configureCallCount = 0

    func configureBlocklist(settingsPath: String) -> Bool {
        configureCallCount += 1
        guard configureCallCount == 1 else { return true }

        onFirstRejectedConfigure?()
        return false
    }

    func forceBlocklistUpdateResult() -> ResolverModule.BlocklistUpdateResult {
        .unchanged
    }

    func reloadBlocklist() -> Bool {
        true
    }

}

private final class AcceptingBlocklistResolver: BlocklistResolverBackend {
    func configureBlocklist(settingsPath: String) -> Bool {
        true
    }

    func forceBlocklistUpdateResult() -> ResolverModule.BlocklistUpdateResult {
        .unchanged
    }

    func reloadBlocklist() -> Bool {
        true
    }

}

private final class ReloadFailingBlocklistResolver: BlocklistResolverBackend {
    var onReload: (() -> Void)?

    func configureBlocklist(settingsPath: String) -> Bool {
        true
    }

    func forceBlocklistUpdateResult() -> ResolverModule.BlocklistUpdateResult {
        .unchanged
    }

    func reloadBlocklist() -> Bool {
        onReload?()
        return false
    }

}

private final class CountingBlocklistResolver: BlocklistResolverBackend {
    private(set) var configureCallCount = 0

    func configureBlocklist(settingsPath: String) -> Bool {
        configureCallCount += 1
        return true
    }

    func forceBlocklistUpdateResult() -> ResolverModule.BlocklistUpdateResult {
        .unchanged
    }

    func reloadBlocklist() -> Bool {
        true
    }

}

private final class AcceptedFullConfigTransactionHarness {
    enum Failure {
        case fileWrite
        case options
        case allowlist
        case zonesAndOverrides
        case blocklist
        case backendBounce
        case successfulBackendBounce
        case history
    }

    enum BlocklistState {
        case old
        case pending
    }

    static let oldHistory = QueryHistorySettings.default
    static let pendingHistory = QueryHistorySettings(
        enabled: false,
        retentionDays: 90,
        popularCount: 500,
        popularDays: 14
    )

    let failure: Failure?
    let resolverRunning: Bool
    let oldConfig: [String: Any]
    let pendingConfig: [String: Any]

    private(set) var persistedConfig: [String: Any]
    private(set) var persistedDomain = "old.example"
    private(set) var allowlistDomain = "allowed.old.example"
    private(set) var zoneDomain = "zone.old.example"
    private(set) var overrideValue = "10.0.0.1"
    private(set) var dnssecEnabled = true
    private(set) var historySettings = AcceptedFullConfigTransactionHarness.oldHistory
    private(set) var blocklistState = BlocklistState.old
    private(set) var rollbackConfig: [String: Any]?
    private(set) var prepareCallCount = 0
    private(set) var optionsCallCount = 0
    private(set) var fileWriteCallCount = 0
    private(set) var allowlistCallCount = 0
    private(set) var zonesAndOverridesCallCount = 0
    private(set) var blocklistCallCount = 0
    private(set) var backendBounceCallCount = 0
    private(set) var rollbackCallCount = 0
    private(set) var commitCallCount = 0
    private(set) var historyCallCount = 0
    /// Runtime steps in the order the transaction ran them.
    private(set) var steps: [String] = []

    init(failure: Failure?, resolverRunning: Bool = true) {
        self.failure = failure
        self.resolverRunning = resolverRunning
        oldConfig = Self.config(
            revision: 4,
            persistedDomain: "old.example",
            allowlistDomain: "allowed.old.example",
            zoneDomain: "zone.old.example",
            overrideValue: "10.0.0.1",
            dnssecEnabled: true,
            history: Self.oldHistory
        )
        pendingConfig = Self.config(
            revision: 4,
            persistedDomain: "new.example",
            allowlistDomain: "allowed.new.example",
            zoneDomain: "zone.new.example",
            overrideValue: "10.0.0.2",
            dnssecEnabled: false,
            history: Self.pendingHistory
        )
        persistedConfig = oldConfig
    }

    func prepareAccepted(
        _: [String: Any]
    ) -> MacDNSAgent.FullConfigTransactionPreparation {
        prepareCallCount += 1
        return .ready(
            MacDNSAgent.FullConfigTransactionContext(
                resolverRunning: resolverRunning,
                backendBounceRequired: failure == .backendBounce
                    || failure == .successfulBackendBounce,
                applyOptions: applyOptions,
                performBackendBounce: performBackendBounce,
                applyHistory: applyHistory,
                rollback: rollback,
                didCommit: didCommit
            )
        )
    }

    func applyOptions() -> MacDNSAgent.AcceptedFullConfigOptionsResult {
        optionsCallCount += 1
        steps.append("options")
        dnssecEnabled = false
        guard failure != .options else {
            return .response(
                FullConfigSaveResponse(status: .rejected, rejectionReason: .runtimeApplyFailure)
            )
        }
        return .applied
    }

    func writeFile(_ config: [String: Any]) throws {
        fileWriteCallCount += 1
        if failure == .fileWrite {
            throw HarnessError.writeFailed
        }
        persistedConfig = config
        persistedDomain = config["persistedDomain"] as? String ?? ""
    }

    func syncAllowlist(_ config: [String: Any]) -> Bool {
        allowlistCallCount += 1
        steps.append("allowlist")
        guard failure != .allowlist else { return false }
        allowlistDomain = Self.allowlistDomain(from: config)
        return true
    }

    func applyZonesAndOverrides(_ config: [String: Any]) -> Bool {
        zonesAndOverridesCallCount += 1
        steps.append("zones")
        guard failure != .zonesAndOverrides else { return false }
        zoneDomain = Self.zoneDomain(from: config)
        overrideValue = Self.overrideValue(from: config)
        return true
    }

    func reloadBlocklist() -> Bool {
        blocklistCallCount += 1
        steps.append("blocklist")
        guard failure != .blocklist else { return false }
        blocklistState = .pending
        return true
    }

    func performBackendBounce(_ rollback: () -> Bool) -> Bool {
        backendBounceCallCount += 1
        steps.append("bounce")
        guard failure != .backendBounce else {
            blocklistState = .pending
            _ = rollback()
            return false
        }
        return true
    }

    /// A rejected configure changes nothing in the resolver, so the old
    /// settings stay in place.
    func applyHistory() -> Bool {
        historyCallCount += 1
        steps.append("history")
        guard failure != .history else { return false }
        historySettings = Self.pendingHistory
        return true
    }

    func didCommit() {
        commitCallCount += 1
        steps.append("commit")
    }

    func rollback(_ config: [String: Any]) -> Bool {
        rollbackCallCount += 1
        steps.append("rollback")
        rollbackConfig = config
        persistedConfig = config
        persistedDomain = config["persistedDomain"] as? String ?? ""
        allowlistDomain = Self.allowlistDomain(from: config)
        zoneDomain = Self.zoneDomain(from: config)
        overrideValue = Self.overrideValue(from: config)
        dnssecEnabled = config["dnssecEnabled"] as? Bool ?? false
        blocklistState = .old
        return true
    }

    private static func config(
        revision: ConfigRevision,
        persistedDomain: String,
        allowlistDomain: String,
        zoneDomain: String,
        overrideValue: String,
        dnssecEnabled: Bool,
        history: QueryHistorySettings
    ) -> [String: Any] {
        history.stateDictionary.merging([
            "configRevision": revision,
            "persistedDomain": persistedDomain,
            "allowlist": [
                [
                    "id": "00000000-0000-0000-0000-000000000001",
                    "domain": allowlistDomain,
                    "enabled": true,
                ]
            ],
            "customZones": [
                [
                    "domain": zoneDomain,
                    "forwardIP": "10.0.0.53",
                    "enabled": true,
                ]
            ],
            "dnsOverrides": [
                [
                    "domain": "host.example",
                    "qtype": "A",
                    "value": overrideValue,
                    "enabled": true,
                ]
            ],
            "dnssecEnabled": dnssecEnabled,
        ]) { _, new in new }
    }

    private static func allowlistDomain(from config: [String: Any]) -> String {
        (config["allowlist"] as? [[String: Any]])?.first?["domain"] as? String ?? ""
    }

    private static func zoneDomain(from config: [String: Any]) -> String {
        (config["customZones"] as? [[String: Any]])?.first?["domain"] as? String ?? ""
    }

    private static func overrideValue(from config: [String: Any]) -> String {
        (config["dnsOverrides"] as? [[String: Any]])?.first?["value"] as? String ?? ""
    }

    private enum HarnessError: Error {
        case writeFailed
    }
}
