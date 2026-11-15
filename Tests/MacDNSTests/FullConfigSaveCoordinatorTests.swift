// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import ServiceManagement
import Shared
import XCTest

@testable import MacDNS
@testable import MacDNSAgent

@MainActor
final class FullConfigSaveCoordinatorTests: XCTestCase {
    func testKeepsOneRealSaveInFlightUntilCallback() async {
        let backend = ControlledConfigSaveBackend()
        let coordinator = makeCoordinator(backend: backend)

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { backend.requests.count == 1 }
        coordinator.enqueue(snapshot(value: "B"))
        coordinator.enqueue(snapshot(value: "C"))

        for _ in 0..<100 {
            await Task.yield()
        }
        XCTAssertEqual(backend.requests.count, 1)
        XCTAssertEqual(backend.maximumActiveCalls, 1)
        XCTAssertFalse(coordinator.isIdle)

        backend.resolveNext(.success(FullConfigSaveResponse(status: .committed)))
        await waitUntil { backend.requests.count == 2 }
        backend.resolveNext(.success(FullConfigSaveResponse(status: .committed)))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(backend.requests.count, 2)
        XCTAssertEqual(backend.requests[0]["value"] as? String, "A")
        XCTAssertEqual(backend.requests[1]["value"] as? String, "C")
        XCTAssertEqual(backend.maximumActiveCalls, 1)
        XCTAssertEqual(coordinator.revision, 2)
    }

    func testLifecycleBusyRetriesWithoutApplyingAuthoritativeState() async {
        let backend = ControlledConfigSaveBackend()
        var appliedAuthoritative = 0
        var authoritativeLoads = 0
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { config in
                await backend.save(config)
            },
            loadAuthoritative: {
                authoritativeLoads += 1
                return ["value": "server-side", "configRevision": 9]
            },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { _ in appliedAuthoritative += 1 }
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { backend.requests.count == 1 }

        // The agent was starting or stopping: the edit must survive.
        backend.resolveNext(
            .success(
                FullConfigSaveResponse(
                    status: .lifecycleBusy,
                    authoritativeRevision: 4
                )
            )
        )
        // The retry is deferred behind the capped backoff, so allow real time.
        await waitUntilTimed { backend.requests.count == 2 }

        XCTAssertEqual(authoritativeLoads, 0)
        XCTAssertEqual(appliedAuthoritative, 0)
        XCTAssertEqual(coordinator.revision, 4)
        XCTAssertEqual(backend.requests[1]["value"] as? String, "A")

        backend.resolveNext(
            .success(
                FullConfigSaveResponse(
                    status: .committed,
                    authoritativeRevision: 5
                )
            )
        )
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(coordinator.revision, 5)
        XCTAssertEqual(appliedAuthoritative, 0)
    }

    func testAmbiguousResponseRebasesOnceWithoutDecreasingRevision() async {
        var saveCalls = 0
        var applied: [[String: Any]] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 5,
            saveToAgent: { _ in
                saveCalls += 1
                return .failure(.decodingFailed("ambiguous reply"))
            },
            loadAuthoritative: {
                ["configRevision": 3, "value": "server-side"]
            },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 5, "value": "server-side"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(saveCalls, 2)
        XCTAssertEqual(coordinator.revision, 5)
        XCTAssertTrue(applied.isEmpty)
    }

    func testDecodingFailureRecognizesConfirmedCommitWithoutFallback() async {
        var saveCalls = 0
        var fallbackCalls = 0
        var fallbackAllowed = false
        var applied: [[String: Any]] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { _ in
                saveCalls += 1
                fallbackAllowed = true
                return .failure(.decodingFailed("ambiguous reply"))
            },
            loadAuthoritative: {
                ["configRevision": 1, "value": "A"]
            },
            shouldUseFallback: { fallbackAllowed },
            saveFallback: { _, _ in
                fallbackCalls += 1
                return 1
            },
            applyAuthoritative: { applied.append($0) }
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(saveCalls, 1)
        XCTAssertEqual(fallbackCalls, 0)
        XCTAssertEqual(coordinator.revision, 1)
        XCTAssertEqual(applied.first?["value"] as? String, "A")
    }

    func testDecodingFailureRebasesAndRetriesWithoutFallback() async {
        var requests: [[String: Any]] = []
        var fallbackCalls = 0
        var fallbackAllowed = false
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { request in
                requests.append(request)
                if requests.count == 1 {
                    fallbackAllowed = true
                    return .failure(.decodingFailed("ambiguous reply"))
                }
                return .success(
                    FullConfigSaveResponse(
                        status: .committed,
                        authoritativeRevision: 2
                    )
                )
            },
            loadAuthoritative: {
                ["configRevision": 1, "value": "server-side"]
            },
            shouldUseFallback: { fallbackAllowed },
            saveFallback: { _, _ in
                fallbackCalls += 1
                return nil
            },
            applyAuthoritative: { _ in }
        )
        coordinator.adopt(loaded: ["configRevision": 0, "value": "server-side"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(
            requests.map { ConfigRevisionPolicy.revision(from: $0) },
            [0, 1]
        )
        XCTAssertEqual(requests.map { $0["value"] as? String }, ["A", "A"])
        XCTAssertEqual(fallbackCalls, 0)
        XCTAssertEqual(coordinator.revision, 2)
    }

    func testDecodingFailureRetainsSnapshotWhenReloadIsUnavailable() async {
        var requests: [[String: Any]] = []
        var fallbackCalls = 0
        var fallbackAllowed = false
        var retryContinuation: CheckedContinuation<Void, Never>?
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { request in
                requests.append(request)
                if requests.count == 1 {
                    fallbackAllowed = true
                    return .failure(.decodingFailed("ambiguous reply"))
                }
                return .success(FullConfigSaveResponse(status: .committed))
            },
            loadAuthoritative: { nil },
            shouldUseFallback: { fallbackAllowed },
            saveFallback: { _, _ in
                fallbackCalls += 1
                return nil
            },
            applyAuthoritative: { _ in },
            retryDelay: { _ in
                await withCheckedContinuation { continuation in
                    retryContinuation = continuation
                }
            }
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { retryContinuation != nil }

        XCTAssertFalse(coordinator.isIdle)
        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(fallbackCalls, 0)

        retryContinuation?.resume()
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(
            requests.map { ConfigRevisionPolicy.revision(from: $0) },
            [0, 0]
        )
        XCTAssertEqual(requests.map { $0["value"] as? String }, ["A", "A"])
        XCTAssertEqual(fallbackCalls, 0)
        XCTAssertEqual(coordinator.revision, 1)
    }

    func testConfirmedAgentUnavailabilityUsesRevisionAwareFallback() async {
        var fallbackExpectedRevision: ConfigRevision?
        let coordinator = FullConfigSaveCoordinator(
            revision: 4,
            saveToAgent: { _ in .failure(.agentNotResponding) },
            loadAuthoritative: { nil },
            shouldUseFallback: { true },
            saveFallback: { _, expectedRevision in
                fallbackExpectedRevision = expectedRevision
                return expectedRevision + 1
            },
            applyAuthoritative: { _ in }
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(fallbackExpectedRevision, 4)
        XCTAssertEqual(coordinator.revision, 5)
    }

    func testAmbiguousAgentFailureDoesNotFallbackOverAuthoritativeRollback() async {
        var fallbackCalls = 0
        var applied: [[String: Any]] = []
        let authoritative: [String: Any] = [
            "configRevision": 1,
            "value": "rolled-back",
        ]
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { _ in .failure(.agentNotResponding) },
            loadAuthoritative: { authoritative },
            saveFallback: { _, expectedRevision in
                fallbackCalls += 1
                return expectedRevision + 1
            },
            applyAuthoritative: { applied.append($0) }
        )

        coordinator.enqueue(snapshot(value: "rejected"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(fallbackCalls, 0)
        XCTAssertEqual(applied.count, 1)
        XCTAssertEqual(applied.first?["value"] as? String, "rolled-back")
        XCTAssertEqual(coordinator.revision, 1)
    }

    func testConflictAppliesAuthoritativeConfigWithoutResending() async {
        var requests: [[String: Any]] = []
        var applied: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { request in
                requests.append(request)
                return .success(
                    FullConfigSaveResponse(
                        status: .conflict,
                        authoritativeRevision: 3
                    )
                )
            },
            loadAuthoritative: {
                ["configRevision": 3, "value": "other"]
            },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 0, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.map { $0["value"] as? String }, ["A"])
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["other"])
        XCTAssertEqual(outcomes, [.conflict])
        XCTAssertEqual(coordinator.revision, 3)
    }

    func testConflictWithUnavailableReloadRetriesAtTheStaleRevision() async {
        var requests: [[String: Any]] = []
        var loadCalls = 0
        var applied: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { request in
                requests.append(request)
                return .success(
                    FullConfigSaveResponse(
                        status: .conflict,
                        authoritativeRevision: 1
                    )
                )
            },
            loadAuthoritative: {
                loadCalls += 1
                return loadCalls == 1
                    ? nil
                    : ["configRevision": 1, "value": "server-side"]
            },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            retryDelay: { _ in },
            publishOutcome: { outcomes.append($0) }
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        // The retry must conflict again, not win at the Agent's revision.
        XCTAssertEqual(
            requests.map { ConfigRevisionPolicy.revision(from: $0) },
            [0, 0]
        )
        XCTAssertEqual(loadCalls, 2)
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["server-side"])
        XCTAssertEqual(outcomes, [.conflict])
        XCTAssertEqual(coordinator.revision, 1)
    }

    func testNewerSnapshotConflictsInTurnAfterInFlightConflict() async {
        let backend = ControlledConfigSaveBackend()
        var applied: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { config in
                await backend.save(config)
            },
            loadAuthoritative: {
                ["configRevision": 4, "value": "other"]
            },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            publishOutcome: { outcomes.append($0) }
        )
        let conflict = FullConfigSaveResponse(
            status: .conflict,
            authoritativeRevision: 4
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { backend.requests.count == 1 }
        coordinator.enqueue(snapshot(value: "B"))
        backend.resolveNext(.success(conflict))
        await waitUntil { backend.requests.count == 2 }

        // B was edited on top of the same stale configuration as A.
        XCTAssertEqual(backend.requests[1]["value"] as? String, "B")
        XCTAssertEqual(
            ConfigRevisionPolicy.revision(from: backend.requests[1]),
            0
        )
        XCTAssertTrue(applied.isEmpty)
        XCTAssertTrue(outcomes.isEmpty)

        backend.resolveNext(.success(conflict))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(backend.requests.count, 2)
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["other"])
        XCTAssertEqual(outcomes, [.conflict])
        XCTAssertEqual(coordinator.revision, 4)
    }

    func testConflictMessageSaysTheChangeWasNotSaved() throws {
        let message = try XCTUnwrap(FullConfigSaveOutcome.conflict.failureMessage)

        XCTAssertTrue(message.contains("changed elsewhere"))
        XCTAssertTrue(message.contains("not saved"))
    }

    func testDefinitiveSaveFailureRevertsAndReportsIt() async throws {
        var saveCalls = 0
        var applied: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 2,
            saveToAgent: { _ in
                saveCalls += 1
                return .failure(.agentError("refused"))
            },
            loadAuthoritative: {
                ["configRevision": 2, "value": "server-side"]
            },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            publishOutcome: { outcomes.append($0) }
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(saveCalls, 1)
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["server-side"])
        XCTAssertEqual(outcomes.count, 1)
        let message = try XCTUnwrap(outcomes.first?.failureMessage)
        XCTAssertTrue(message.contains("not saved"))
        XCTAssertTrue(message.contains("reverted"))
    }

    func testConflictFromAnAgentOwnedRevisionBumpResendsTheEdit() async {
        var requests: [[String: Any]] = []
        var applied: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { request in
                requests.append(request)
                let status: FullConfigSaveResponse.Status =
                    requests.count == 1 ? .conflict : .committed
                return .success(
                    FullConfigSaveResponse(
                        status: status,
                        authoritativeRevision: requests.count == 1 ? 2 : 3
                    )
                )
            },
            // The Agent recorded a blocklist refresh: the revision moved and
            // nothing the App edits changed.
            loadAuthoritative: {
                ["configRevision": 2, "value": "base", "schemaVersion": 4]
            },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(
            loaded: ["configRevision": 0, "value": "base", "schemaVersion": 4]
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.map { $0["value"] as? String }, ["A", "A"])
        XCTAssertEqual(
            requests.map { ConfigRevisionPolicy.revision(from: $0) },
            [0, 2]
        )
        XCTAssertTrue(applied.isEmpty)
        XCTAssertEqual(outcomes, [.committed])
        XCTAssertEqual(coordinator.revision, 3)
    }

    func testConflictAfterTheAppsOwnCommitResendsTheNextEdit() async {
        var requests: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        var authoritative: [String: Any] = [:]
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { request in
                requests.append(request)
                // The second request is sent on the revision the App's own
                // commit produced, after the Agent consumed one more.
                let conflicts = requests.count == 2
                return .success(
                    FullConfigSaveResponse(
                        status: conflicts ? .conflict : .committed,
                        authoritativeRevision: [1, 2, 3][requests.count - 1]
                    )
                )
            },
            loadAuthoritative: { authoritative },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { _ in },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 0, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }
        authoritative = ["configRevision": 2, "value": "A"]
        coordinator.enqueue(snapshot(value: "B"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.map { $0["value"] as? String }, ["A", "B", "B"])
        XCTAssertEqual(
            requests.map { ConfigRevisionPolicy.revision(from: $0) },
            [0, 1, 2]
        )
        XCTAssertEqual(outcomes, [.committed, .committed])
        XCTAssertEqual(coordinator.revision, 3)
    }

    func testSecondConflictAfterAResendDropsTheEdit() async {
        var requests: [[String: Any]] = []
        var applied: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { request in
                requests.append(request)
                return .success(
                    FullConfigSaveResponse(
                        status: .conflict,
                        authoritativeRevision: 2
                    )
                )
            },
            loadAuthoritative: { ["configRevision": 2, "value": "base"] },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 0, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["base"])
        XCTAssertEqual(outcomes, [.conflict])
    }

    func testUnavailableAgentRetainsSnapshotWhenFallbackAndReloadFail() async {
        var saveCalls = 0
        var fallbackCalls = 0
        var shouldSucceed = false
        var shouldUseFallback = true
        var retryContinuation: CheckedContinuation<Void, Never>?
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { _ in
                saveCalls += 1
                return shouldSucceed
                    ? .success(FullConfigSaveResponse(status: .committed))
                    : .failure(.agentNotResponding)
            },
            loadAuthoritative: { nil },
            shouldUseFallback: { shouldUseFallback },
            saveFallback: { _, _ in
                fallbackCalls += 1
                return nil
            },
            applyAuthoritative: { _ in },
            retryDelay: { _ in
                await withCheckedContinuation { continuation in
                    retryContinuation = continuation
                }
            }
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { retryContinuation != nil }

        XCTAssertFalse(coordinator.isIdle)
        XCTAssertEqual(saveCalls, 0)
        XCTAssertEqual(fallbackCalls, 1)

        shouldUseFallback = false
        shouldSucceed = true
        retryContinuation?.resume()
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(saveCalls, 1)
        XCTAssertEqual(coordinator.revision, 1)
    }

    func testFallbackConflictReloadsFileRevisionAndRetries() async {
        var fallbackExpectedRevisions: [ConfigRevision] = []
        var persisted: [String: Any] = [
            "configRevision": 1,
            "value": "other",
        ]
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { _ in .failure(.agentNotResponding) },
            loadAuthoritative: { persisted },
            shouldUseFallback: { true },
            saveFallback: { snapshot, expectedRevision in
                fallbackExpectedRevisions.append(expectedRevision)
                guard
                    ConfigRevisionPolicy.revision(from: persisted)
                        == expectedRevision
                else {
                    return nil
                }
                persisted = snapshot
                persisted["configRevision"] = expectedRevision + 1
                return expectedRevision + 1
            },
            applyAuthoritative: { _ in }
        )
        coordinator.adopt(loaded: ["configRevision": 0, "value": "other"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(fallbackExpectedRevisions, [0, 1])
        XCTAssertEqual(coordinator.revision, 2)
        XCTAssertEqual(persisted["value"] as? String, "A")
    }

    /// The fallback's own commit is the base of the next edit, so a write
    /// that fails after it is sent again instead of being taken for someone
    /// else's change.
    func testFailedFallbackWriteAfterTheAppsOwnFallbackCommitResendsTheNextEdit() async {
        var persisted: [String: Any] = ["configRevision": 0, "value": "base"]
        var failNextWrite = false
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { _ in .failure(.agentNotResponding) },
            loadAuthoritative: { persisted },
            shouldUseFallback: { true },
            saveFallback: { snapshot, expectedRevision in
                if failNextWrite {
                    failNextWrite = false
                    return nil
                }
                persisted = snapshot
                persisted["configRevision"] = expectedRevision + 1
                return expectedRevision + 1
            },
            applyAuthoritative: { _ in },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: persisted)

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }
        failNextWrite = true
        coordinator.enqueue(snapshot(value: "B"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(persisted["value"] as? String, "B")
        XCTAssertEqual(outcomes, [.committed, .committed])
        XCTAssertEqual(coordinator.revision, 2)
    }

    func testFallbackConflictOverAChangedConfigDropsTheEdit() async {
        var fallbackExpectedRevisions: [ConfigRevision] = []
        var applied: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        let persisted: [String: Any] = ["configRevision": 1, "value": "other"]
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { _ in .failure(.agentNotResponding) },
            loadAuthoritative: { persisted },
            shouldUseFallback: { true },
            saveFallback: { _, expectedRevision in
                fallbackExpectedRevisions.append(expectedRevision)
                return nil
            },
            applyAuthoritative: { applied.append($0) },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 0, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(fallbackExpectedRevisions, [0])
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["other"])
        XCTAssertEqual(outcomes, [.conflict])
        XCTAssertEqual(coordinator.revision, 1)
    }

    func testFallbackThatKeepsFailingReportsTheDroppedEdit() async {
        var fallbackCalls = 0
        var applied: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { _ in .failure(.agentNotResponding) },
            loadAuthoritative: { ["configRevision": 0, "value": "base"] },
            shouldUseFallback: { true },
            saveFallback: { _, _ in
                fallbackCalls += 1
                return nil
            },
            applyAuthoritative: { applied.append($0) },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 0, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(fallbackCalls, 2)
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["base"])
        XCTAssertEqual(outcomes, [.rejected(reason: .persistenceFailure)])
    }

    func testAmbiguousFailureOverAChangedConfigDropsTheEdit() async {
        var saveCalls = 0
        var applied: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { _ in
                saveCalls += 1
                return .failure(.decodingFailed("ambiguous reply"))
            },
            loadAuthoritative: { ["configRevision": 1, "value": "other"] },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 0, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(saveCalls, 1)
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["other"])
        XCTAssertEqual(outcomes, [.conflict])
        XCTAssertEqual(coordinator.revision, 1)
    }

    /// The write that failed ambiguously had landed. The edit made meanwhile
    /// starts from it, so it is sent on the revision that write produced.
    func testNewerSnapshotIsSentOnTheRevisionOfALandedAmbiguousWrite() async {
        let backend = ControlledConfigSaveBackend()
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { config in await backend.save(config) },
            loadAuthoritative: { ["configRevision": 1, "value": "A"] },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { _ in },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 0, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { backend.requests.count == 1 }
        coordinator.enqueue(snapshot(value: "B"))
        backend.resolveNext(.failure(.decodingFailed("ambiguous reply")))
        await waitUntil { backend.requests.count == 2 }
        backend.resolveNext(
            .success(
                FullConfigSaveResponse(status: .committed, authoritativeRevision: 2)
            )
        )
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(backend.requests.map { $0["value"] as? String }, ["A", "B"])
        XCTAssertEqual(
            backend.requests.map { ConfigRevisionPolicy.revision(from: $0) },
            [0, 1]
        )
        XCTAssertEqual(outcomes, [.committed])
        XCTAssertEqual(coordinator.revision, 2)
    }

    /// The write that failed ambiguously landed and the Agent then consumed a
    /// revision for state of its own. That is the App's own write, not a
    /// conflict.
    func testAmbiguousWriteThatLandedBeforeAnAgentOwnedRevisionIsNotAConflict() async {
        var saveCalls = 0
        var applied: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { _ in
                saveCalls += 1
                return .failure(.decodingFailed("ambiguous reply"))
            },
            loadAuthoritative: { ["configRevision": 2, "value": "A"] },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 0, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(saveCalls, 1)
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["A"])
        XCTAssertEqual(outcomes, [])
        XCTAssertEqual(coordinator.revision, 2)
    }

    /// The edit made while an ambiguous write was in flight is sent on the
    /// current revision, not on the one the landed write produced.
    func testNewerSnapshotIsSentOnTheCurrentRevisionAfterALandedAmbiguousWrite() async {
        let backend = ControlledConfigSaveBackend()
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { config in await backend.save(config) },
            loadAuthoritative: { ["configRevision": 2, "value": "A"] },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { _ in },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 0, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { backend.requests.count == 1 }
        coordinator.enqueue(snapshot(value: "B"))
        backend.resolveNext(.failure(.decodingFailed("ambiguous reply")))
        await waitUntil { backend.requests.count == 2 }
        backend.resolveNext(
            .success(
                FullConfigSaveResponse(status: .committed, authoritativeRevision: 3)
            )
        )
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(backend.requests.map { $0["value"] as? String }, ["A", "B"])
        XCTAssertEqual(
            backend.requests.map { ConfigRevisionPolicy.revision(from: $0) },
            [0, 2]
        )
        XCTAssertEqual(outcomes, [.committed])
        XCTAssertEqual(coordinator.revision, 3)
    }

    func testPermanentRejectionReloadsWithoutRetryLoop() async {
        var saveCalls = 0
        var loadCalls = 0
        var applied: [[String: Any]] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { _ in
                saveCalls += 1
                return .success(
                    FullConfigSaveResponse(
                        status: .rejected,
                        authoritativeRevision: 1,
                        rejectionReason: .invalidConfiguration
                    )
                )
            },
            loadAuthoritative: {
                loadCalls += 1
                return ["configRevision": 1, "value": "server-side"]
            },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) }
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(saveCalls, 1)
        XCTAssertEqual(loadCalls, 1)
        XCTAssertEqual(coordinator.revision, 1)
        XCTAssertEqual(applied.count, 1)
    }

    func testNewerSnapshotSurvivesRejectedInFlightSave() async {
        var requests: [[String: Any]] = []
        var applied: [[String: Any]] = []
        var firstSaveContinuation: CheckedContinuation<Result<FullConfigSaveResponse, XPCError>, Never>?
        let authoritativeA: [String: Any] = [
            "configRevision": 1,
            "value": "A",
        ]
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { request in
                requests.append(request)
                if requests.count == 1 {
                    return await withCheckedContinuation { continuation in
                        firstSaveContinuation = continuation
                    }
                }
                return .success(
                    FullConfigSaveResponse(
                        status: .committed,
                        authoritativeRevision: 2
                    )
                )
            },
            loadAuthoritative: { authoritativeA },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) }
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { firstSaveContinuation != nil }
        coordinator.enqueue(snapshot(value: "B"))
        firstSaveContinuation?.resume(
            returning: .success(
                FullConfigSaveResponse(
                    status: .rejected,
                    authoritativeRevision: 1,
                    rejectionReason: .runtimeApplyFailure
                )
            )
        )
        await waitUntil { coordinator.isIdle }

        XCTAssertTrue(applied.isEmpty)
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(requests[0]["value"] as? String, "A")
        XCTAssertEqual(requests[1]["value"] as? String, "B")
        XCTAssertEqual(
            requests.map { ConfigRevisionPolicy.revision(from: $0) },
            [0, 1]
        )
        XCTAssertEqual(coordinator.revision, 2)
    }

    func testCoordinatorRequestsMatchAgentCASAcrossConsecutiveMutations() async {
        var persisted: [String: Any] = [
            "configRevision": 0,
            "value": "initial",
        ]
        var expectedRevisions: [ConfigRevision] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { request in
                expectedRevisions.append(
                    ConfigRevisionPolicy.revision(from: request)
                )
                guard
                    let classification = try? AgentConfigRevisionPolicy.classify(
                        incoming: request,
                        persisted: persisted
                    )
                else {
                    return .success(FullConfigSaveResponse(status: .rejected))
                }
                switch classification {
                case .accept(let nextRevision):
                    persisted = request
                    persisted["configRevision"] = nextRevision
                    return .success(FullConfigSaveResponse(status: .committed))
                case .idempotentSuccess:
                    return .success(FullConfigSaveResponse(status: .committed))
                case .conflict:
                    return .success(FullConfigSaveResponse(status: .rejected))
                }
            },
            loadAuthoritative: { persisted },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { _ in }
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { coordinator.isIdle }
        coordinator.enqueue(snapshot(value: "B"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(expectedRevisions, [0, 1])
        XCTAssertEqual(ConfigRevisionPolicy.revision(from: persisted), 2)
        XCTAssertEqual(persisted["value"] as? String, "B")
    }

    func testHungSaveTransitionsToStalledWithoutStartingSecondTransaction() async {
        var requests: [[String: Any]] = []
        var loadCalls = 0
        var authoritative: [String: Any]?
        var outcomes: [FullConfigSaveOutcome] = []
        var applied: [[String: Any]] = []
        var retryContinuation: CheckedContinuation<Void, Never>?
        let coordinator = FullConfigSaveCoordinator(
            revision: 7,
            saveToAgent: { request in
                requests.append(request)
                return requests.count == 1
                    ? .failure(.timeout)
                    : .success(FullConfigSaveResponse(status: .committed))
            },
            loadAuthoritative: {
                loadCalls += 1
                return authoritative
            },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            retryDelay: { _ in
                await withCheckedContinuation { continuation in
                    retryContinuation = continuation
                }
            },
            publishOutcome: { outcomes.append($0) }
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { retryContinuation != nil }

        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(outcomes, [.stalled])
        XCTAssertFalse(coordinator.isIdle)

        // Still unreachable: the snapshot is retained and nothing is written.
        let stalledRetry = retryContinuation
        retryContinuation = nil
        stalledRetry?.resume()
        await waitUntil { retryContinuation != nil }

        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(loadCalls, 1)
        XCTAssertEqual(coordinator.revision, 7)

        // The reload proves the stalled write never consumed the revision.
        authoritative = ["configRevision": 7, "value": "server-side"]
        let recoveryRetry = retryContinuation
        retryContinuation = nil
        recoveryRetry?.resume()
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.map { $0["value"] as? String }, ["A", "A"])
        XCTAssertEqual(
            requests.map { ConfigRevisionPolicy.revision(from: $0) },
            [7, 7]
        )
        XCTAssertEqual(loadCalls, 2)
        XCTAssertEqual(outcomes, [.stalled, .recovered, .committed])
        XCTAssertEqual(coordinator.revision, 8)
        XCTAssertTrue(applied.isEmpty)
    }

    func testStalledSaveThatLandedIsAdoptedWithoutRewriting() async {
        var requests: [[String: Any]] = []
        var authoritative: [String: Any]?
        var outcomes: [FullConfigSaveOutcome] = []
        var applied: [[String: Any]] = []
        var retryContinuation: CheckedContinuation<Void, Never>?
        let coordinator = FullConfigSaveCoordinator(
            revision: 7,
            saveToAgent: { request in
                requests.append(request)
                return .failure(.timeout)
            },
            loadAuthoritative: { authoritative },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            retryDelay: { _ in
                await withCheckedContinuation { continuation in
                    retryContinuation = continuation
                }
            },
            publishOutcome: { outcomes.append($0) }
        )

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { retryContinuation != nil }

        XCTAssertEqual(requests.count, 1)

        // The Agent committed the stalled write before the reply was lost.
        authoritative = ["configRevision": 8, "value": "A"]
        retryContinuation?.resume()
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(outcomes, [.stalled, .recovered])
        XCTAssertEqual(coordinator.revision, 8)
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["A"])
    }

    /// The stalled write never landed and another writer changed the same
    /// value meanwhile. Sending the edit on the new revision would overwrite it.
    func testStalledSaveOverAnotherWritersChangeDropsTheEdit() async {
        var requests: [[String: Any]] = []
        var authoritative: [String: Any]?
        var outcomes: [FullConfigSaveOutcome] = []
        var applied: [[String: Any]] = []
        var retryContinuation: CheckedContinuation<Void, Never>?
        let coordinator = FullConfigSaveCoordinator(
            revision: 7,
            saveToAgent: { request in
                requests.append(request)
                return requests.count == 1
                    ? .failure(.timeout)
                    : .success(FullConfigSaveResponse(status: .committed))
            },
            loadAuthoritative: { authoritative },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            retryDelay: { _ in
                await withCheckedContinuation { continuation in
                    retryContinuation = continuation
                }
            },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 7, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { retryContinuation != nil }
        authoritative = ["configRevision": 8, "value": "other"]
        retryContinuation?.resume()
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(outcomes, [.stalled, .recovered, .conflict])
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["other"])
        XCTAssertEqual(coordinator.revision, 8)
    }

    /// The Agent consumed the revision for state of its own, so the edit still
    /// applies and is sent on the new revision.
    func testStalledSaveAfterAnAgentOwnedRevisionIsSentAgain() async {
        var requests: [[String: Any]] = []
        var authoritative: [String: Any]?
        var outcomes: [FullConfigSaveOutcome] = []
        var retryContinuation: CheckedContinuation<Void, Never>?
        let coordinator = FullConfigSaveCoordinator(
            revision: 7,
            saveToAgent: { request in
                requests.append(request)
                return requests.count == 1
                    ? .failure(.timeout)
                    : .success(FullConfigSaveResponse(status: .committed))
            },
            loadAuthoritative: { authoritative },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { _ in },
            retryDelay: { _ in
                await withCheckedContinuation { continuation in
                    retryContinuation = continuation
                }
            },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 7, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { retryContinuation != nil }
        authoritative = ["configRevision": 8, "value": "base", "agentOwned": "refreshed"]
        retryContinuation?.resume()
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.map { $0["value"] as? String }, ["A", "A"])
        XCTAssertEqual(requests.map { ConfigRevisionPolicy.revision(from: $0) }, [7, 8])
        XCTAssertEqual(outcomes, [.stalled, .recovered, .committed])
        XCTAssertEqual(coordinator.revision, 9)
    }

    /// The stalled write landed, and the edit made meanwhile starts from it.
    func testNewerEditAfterALandedStalledWriteIsSentOnItsRevision() async {
        var requests: [[String: Any]] = []
        var authoritative: [String: Any]?
        var outcomes: [FullConfigSaveOutcome] = []
        var retryContinuation: CheckedContinuation<Void, Never>?
        let coordinator = FullConfigSaveCoordinator(
            revision: 7,
            saveToAgent: { request in
                requests.append(request)
                return requests.count == 1
                    ? .failure(.timeout)
                    : .success(FullConfigSaveResponse(status: .committed))
            },
            loadAuthoritative: { authoritative },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { _ in },
            retryDelay: { _ in
                await withCheckedContinuation { continuation in
                    retryContinuation = continuation
                }
            },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 7, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { retryContinuation != nil }
        coordinator.enqueue(snapshot(value: "B"))
        authoritative = ["configRevision": 8, "value": "A"]
        retryContinuation?.resume()
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.map { $0["value"] as? String }, ["A", "B"])
        XCTAssertEqual(requests.map { ConfigRevisionPolicy.revision(from: $0) }, [7, 8])
        XCTAssertEqual(outcomes, [.stalled, .recovered, .committed])
        XCTAssertEqual(coordinator.revision, 9)
    }

    /// The stalled write landed and the Agent then consumed a revision for
    /// state of its own. The edit made meanwhile starts from the landed write,
    /// so it is sent on the current revision instead of being dropped.
    func testNewerEditAfterALandedStalledWriteAndAnAgentOwnedRevisionIsSent() async {
        var requests: [[String: Any]] = []
        var authoritative: [String: Any]?
        var outcomes: [FullConfigSaveOutcome] = []
        var retryContinuation: CheckedContinuation<Void, Never>?
        let coordinator = FullConfigSaveCoordinator(
            revision: 7,
            saveToAgent: { request in
                requests.append(request)
                return requests.count == 1
                    ? .failure(.timeout)
                    : .success(FullConfigSaveResponse(status: .committed))
            },
            loadAuthoritative: { authoritative },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { _ in },
            retryDelay: { _ in
                await withCheckedContinuation { continuation in
                    retryContinuation = continuation
                }
            },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 7, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { retryContinuation != nil }
        coordinator.enqueue(snapshot(value: "B"))
        authoritative = ["configRevision": 9, "value": "A"]
        retryContinuation?.resume()
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.map { $0["value"] as? String }, ["A", "B"])
        XCTAssertEqual(requests.map { ConfigRevisionPolicy.revision(from: $0) }, [7, 9])
        XCTAssertEqual(outcomes, [.stalled, .recovered, .committed])
        XCTAssertEqual(coordinator.revision, 10)
    }

    /// The stalled write landed and the Agent then consumed a revision for
    /// state of its own. Nothing is pending, so the landed write is adopted
    /// without a conflict.
    func testLandedStalledWriteFollowedByAnAgentOwnedRevisionIsNotAConflict() async {
        var requests: [[String: Any]] = []
        var authoritative: [String: Any]?
        var applied: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        var retryContinuation: CheckedContinuation<Void, Never>?
        let coordinator = FullConfigSaveCoordinator(
            revision: 7,
            saveToAgent: { request in
                requests.append(request)
                return .failure(.timeout)
            },
            loadAuthoritative: { authoritative },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            retryDelay: { _ in
                await withCheckedContinuation { continuation in
                    retryContinuation = continuation
                }
            },
            publishOutcome: { outcomes.append($0) }
        )
        coordinator.adopt(loaded: ["configRevision": 7, "value": "base"])

        coordinator.enqueue(snapshot(value: "A"))
        await waitUntil { retryContinuation != nil }
        authoritative = ["configRevision": 9, "value": "A"]
        retryContinuation?.resume()
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(requests.map { $0["value"] as? String }, ["A"])
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["A"])
        XCTAssertEqual(outcomes, [.stalled, .recovered])
        XCTAssertEqual(coordinator.revision, 9)
    }

    func testPermanentRejectionReloadsAndSurfacesReason() async {
        var loadCalls = 0
        var applied: [[String: Any]] = []
        var outcomes: [FullConfigSaveOutcome] = []
        let coordinator = FullConfigSaveCoordinator(
            revision: 3,
            saveToAgent: { _ in
                .success(
                    FullConfigSaveResponse(
                        status: .rejected,
                        authoritativeRevision: 3,
                        rejectionReason: .invalidConfiguration
                    )
                )
            },
            loadAuthoritative: {
                loadCalls += 1
                return ["configRevision": 3, "value": "server-side"]
            },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { applied.append($0) },
            publishOutcome: { outcomes.append($0) }
        )

        coordinator.enqueue(snapshot(value: "invalid-zone"))
        await waitUntil { coordinator.isIdle }

        XCTAssertEqual(loadCalls, 1)
        XCTAssertEqual(applied.map { $0["value"] as? String }, ["server-side"])
        XCTAssertEqual(outcomes, [.rejected(reason: .invalidConfiguration)])
        XCTAssertEqual(coordinator.revision, 3)

        let message = outcomes.first?.failureMessage
        XCTAssertNotNil(message)
        XCTAssertTrue(message?.contains("rejected it as invalid") == true)
    }

    func testEveryRejectionReasonProducesADistinctMessage() {
        let reasons: [FullConfigSaveResponse.RejectionReason?] = [
            .invalidConfiguration,
            .persistenceFailure,
            .runtimeApplyFailure,
            .revisionExhausted,
            nil,
        ]
        let messages = reasons.map {
            FullConfigSaveOutcome.rejected(reason: $0).failureMessage
        }

        XCTAssertEqual(Set(messages.compactMap { $0 }).count, reasons.count)
        XCTAssertNil(FullConfigSaveOutcome.committed.failureMessage)
        XCTAssertNil(FullConfigSaveOutcome.recovered.failureMessage)
        XCTAssertNotNil(FullConfigSaveOutcome.stalled.failureMessage)
        XCTAssertFalse(
            messages.contains(FullConfigSaveOutcome.conflict.failureMessage)
        )
    }

    private func makeCoordinator(
        backend: ControlledConfigSaveBackend
    ) -> FullConfigSaveCoordinator {
        FullConfigSaveCoordinator(
            revision: 0,
            saveToAgent: { config in
                await backend.save(config)
            },
            loadAuthoritative: { nil },
            saveFallback: { _, _ in nil },
            applyAuthoritative: { _ in }
        )
    }

    private func snapshot(value: String) -> [String: Any] {
        ["value": value]
    }

    /// Waits in real time, for conditions gated behind the retry backoff.
    private func waitUntilTimed(
        _ condition: @escaping @MainActor () -> Bool
    ) async {
        for _ in 0..<600 {
            if condition() {
                return
            }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("Condition was not met")
    }

    private func waitUntil(
        _ condition: @escaping @MainActor () -> Bool
    ) async {
        for _ in 0..<1_000 {
            if condition() {
                return
            }
            await Task.yield()
        }
        XCTFail("Condition was not met")
    }
}

final class AgentStateFileFallbackPolicyTests: XCTestCase {
    func testEnabledServiceDoesNotAllowFallbackWithoutPIDState() {
        XCTAssertFalse(
            AgentStateFileFallbackPolicy.canUseFallback(
                for: AgentServiceRegistrationStatus(
                    SMAppService.Status.enabled
                )
            )
        )
    }

    func testNonExecutableServiceStatusesAllowFallback() {
        XCTAssertTrue(
            AgentStateFileFallbackPolicy.canUseFallback(
                for: AgentServiceRegistrationStatus(
                    SMAppService.Status.notRegistered
                )
            )
        )
        XCTAssertTrue(
            AgentStateFileFallbackPolicy.canUseFallback(
                for: AgentServiceRegistrationStatus(
                    SMAppService.Status.notFound
                )
            )
        )
        XCTAssertTrue(
            AgentStateFileFallbackPolicy.canUseFallback(
                for: AgentServiceRegistrationStatus(
                    SMAppService.Status.requiresApproval
                )
            )
        )
    }

    func testUnknownServiceStatusFailsClosed() {
        XCTAssertFalse(
            AgentStateFileFallbackPolicy.canUseFallback(for: .unknown)
        )
    }
}

@MainActor
private final class ControlledConfigSaveBackend {
    private(set) var requests: [[String: Any]] = []
    private(set) var maximumActiveCalls = 0
    private var activeCalls = 0
    private var continuations: [CheckedContinuation<Result<FullConfigSaveResponse, XPCError>, Never>] = []

    func save(_ config: [String: Any]) async -> Result<FullConfigSaveResponse, XPCError> {
        requests.append(config)
        activeCalls += 1
        maximumActiveCalls = max(maximumActiveCalls, activeCalls)
        let result = await withCheckedContinuation { continuation in
            continuations.append(continuation)
        }
        activeCalls -= 1
        return result
    }

    func resolveNext(_ result: Result<FullConfigSaveResponse, XPCError>) {
        continuations.removeFirst().resume(returning: result)
    }
}
