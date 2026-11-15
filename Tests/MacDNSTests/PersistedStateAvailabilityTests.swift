// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

@MainActor
final class PersistedStateAvailabilityTests: XCTestCase {
    func testMissingCountEventTimesOutAndAllowsALaterEvent() async throws {
        let signal = ControlledCountSignal()
        let completed = expectation(description: "missing count wait ended")
        let waiting = Task { () -> ControlledCountWaitError? in
            defer { completed.fulfill() }
            do {
                try await signal.wait(until: 1, timeout: 0.02)
                return nil
            } catch let error as ControlledCountWaitError {
                return error
            } catch {
                XCTFail("Unexpected count wait error: \(error)")
                return nil
            }
        }
        defer { waiting.cancel() }
        let result = await XCTWaiter.fulfillment(of: [completed], timeout: 1)
        signal.increment()
        guard result == .completed else {
            return XCTFail("A missing count event must terminate its wait")
        }
        let error = await waiting.value
        XCTAssertEqual(error, .timedOut(expectedCount: 1))
        try await signal.wait(until: 1, timeout: 0.02)
    }

    func testAppViewModelExposesAuthoritativeStateAvailability() {
        let keyPath: KeyPath<AppViewModel, PersistedStateAvailability> =
            \.persistedStateAvailability

        XCTAssertNotNil(keyPath)
    }

    func testLifecycleActionsAreAllowedOnlyWhenStateIsLoaded() {
        XCTAssertFalse(PersistedStateAvailability.loading.allowsLifecycleActions)
        XCTAssertFalse(PersistedStateAvailability.unavailable.allowsLifecycleActions)
        XCTAssertFalse(
            PersistedStateAvailability.invalidConfiguration
                .allowsLifecycleActions
        )
        XCTAssertTrue(PersistedStateAvailability.loaded.allowsLifecycleActions)
    }

    func testAutomaticRecoveryRequestsOnlyRunForTransientAvailability() {
        XCTAssertTrue(PersistedStateAvailability.loading.allowsRecoveryRequests)
        XCTAssertTrue(PersistedStateAvailability.unavailable.allowsRecoveryRequests)
        XCTAssertFalse(PersistedStateAvailability.loaded.allowsRecoveryRequests)
        XCTAssertFalse(
            PersistedStateAvailability.invalidConfiguration
                .allowsRecoveryRequests
        )
    }

    func testConfigurationMutationIsAllowedOnlyWhenStateIsLoaded() {
        XCTAssertFalse(
            PersistedStateAvailability.loading.allowsConfigurationMutation
        )
        XCTAssertFalse(
            PersistedStateAvailability.unavailable.allowsConfigurationMutation
        )
        XCTAssertFalse(
            PersistedStateAvailability.invalidConfiguration
                .allowsConfigurationMutation
        )
        XCTAssertTrue(
            PersistedStateAvailability.loaded.allowsConfigurationMutation
        )
    }

    func testUnknownStateDoesNotBuildOrScheduleFullConfigSave() {
        for availability in [
            PersistedStateAvailability.loading,
            .unavailable,
            .invalidConfiguration,
        ] {
            var snapshotBuildCount = 0
            var scheduledSnapshots: [[String: Any]] = []

            let performed = FullConfigSaveBoundary.performIfAllowed(
                availability: availability,
                isApplyingPersistedState: false
            ) {
                snapshotBuildCount += 1
                scheduledSnapshots.append(["isEnabled": false])
            }

            XCTAssertFalse(performed)
            XCTAssertEqual(snapshotBuildCount, 0)
            XCTAssertTrue(scheduledSnapshots.isEmpty)
        }
    }

    func testLoadedStateBuildsAndSchedulesFullConfigSave() {
        var snapshotBuildCount = 0
        var scheduledSnapshots: [[String: Any]] = []

        let performed = FullConfigSaveBoundary.performIfAllowed(
            availability: .loaded,
            isApplyingPersistedState: false
        ) {
            snapshotBuildCount += 1
            scheduledSnapshots.append(["isEnabled": true])
        }

        XCTAssertTrue(performed)
        XCTAssertEqual(snapshotBuildCount, 1)
        XCTAssertEqual(scheduledSnapshots.count, 1)
        XCTAssertEqual(scheduledSnapshots[0]["isEnabled"] as? Bool, true)
    }

    func testUnknownStateRejectsAllowlistMutation() {
        var allowedDomains: [String] = []

        let accepted = ConfigurationMutationBoundary.performIfAllowed(
            availability: .unavailable
        ) {
            allowedDomains.append("blocked.example")
        }

        XCTAssertFalse(accepted)
        XCTAssertTrue(allowedDomains.isEmpty)
    }

    func testApplyingPersistedStateDoesNotScheduleFullConfigSave() {
        var saveCount = 0

        let performed = FullConfigSaveBoundary.performIfAllowed(
            availability: .loaded,
            isApplyingPersistedState: true
        ) {
            saveCount += 1
        }

        XCTAssertFalse(performed)
        XCTAssertEqual(saveCount, 0)
    }

    func testPresentationPolicyForEachAvailability() {
        XCTAssertEqual(
            PersistedStateAvailability.loading.statusMessageOverride,
            "Waiting for Agent"
        )
        XCTAssertEqual(
            PersistedStateAvailability.unavailable.statusMessageOverride,
            "Waiting for Agent"
        )
        XCTAssertEqual(
            PersistedStateAvailability.invalidConfiguration.statusMessageOverride,
            "Configuration Error"
        )
        XCTAssertNil(PersistedStateAvailability.loaded.statusMessageOverride)

        XCTAssertEqual(
            PersistedStateAvailability.loading.protectionHeadlineOverride,
            "Protection State Unknown"
        )
        XCTAssertEqual(
            PersistedStateAvailability.unavailable.protectionHeadlineOverride,
            "Protection State Unknown"
        )
        XCTAssertEqual(
            PersistedStateAvailability.invalidConfiguration
                .protectionHeadlineOverride,
            "Configuration Error"
        )
        XCTAssertNil(
            PersistedStateAvailability.loaded.protectionHeadlineOverride
        )

        XCTAssertFalse(
            PersistedStateAvailability.loading.showsProtectionToggle
        )
        XCTAssertFalse(
            PersistedStateAvailability.unavailable.showsProtectionToggle
        )
        XCTAssertFalse(
            PersistedStateAvailability.invalidConfiguration
                .showsProtectionToggle
        )
        XCTAssertTrue(PersistedStateAvailability.loaded.showsProtectionToggle)

        XCTAssertTrue(
            PersistedStateAvailability.loading.showsProgressIndicator
        )
        XCTAssertTrue(
            PersistedStateAvailability.unavailable.showsProgressIndicator
        )
        XCTAssertFalse(
            PersistedStateAvailability.invalidConfiguration
                .showsProgressIndicator
        )
        XCTAssertFalse(
            PersistedStateAvailability.loaded.showsProgressIndicator
        )
    }

    func testLoadErrorClassification() {
        XCTAssertEqual(
            PersistedStateLoadPolicy.decision(
                for: .timeout,
                canUseStateFileFallback: true
            ),
            .retry(.timeout)
        )
        XCTAssertEqual(
            PersistedStateLoadPolicy.decision(
                for: .agentNotResponding,
                canUseStateFileFallback: true
            ),
            .useStateFileFallback
        )
        XCTAssertEqual(
            PersistedStateLoadPolicy.decision(
                for: .agentNotResponding,
                canUseStateFileFallback: false
            ),
            .retry(.agentNotResponding)
        )
        XCTAssertEqual(
            PersistedStateLoadPolicy.decision(
                for: .connectionInterrupted,
                canUseStateFileFallback: true
            ),
            .useStateFileFallback
        )
        XCTAssertEqual(
            PersistedStateLoadPolicy.decision(
                for: .connectionInterrupted,
                canUseStateFileFallback: false
            ),
            .retry(.connectionInterrupted)
        )
        XCTAssertEqual(
            PersistedStateLoadPolicy.decision(
                for: .decodingFailed("state"),
                canUseStateFileFallback: false
            ),
            .invalidConfiguration
        )
        XCTAssertEqual(
            PersistedStateLoadPolicy.decision(
                for: .agentError("state"),
                canUseStateFileFallback: true
            ),
            .invalidConfiguration
        )
        // The Agent answered, so the state file fallback never applies.
        XCTAssertEqual(
            PersistedStateLoadPolicy.decision(
                for: .agentStateUnreadable,
                canUseStateFileFallback: true
            ),
            .retry(.stateReadFailure)
        )
        XCTAssertEqual(
            PersistedStateLoadPolicy.decision(
                for: .agentStateUnreadable,
                canUseStateFileFallback: false
            ),
            .retry(.stateReadFailure)
        )
    }

    func testRetryDelayUsesCappedExponentialBackoff() {
        XCTAssertEqual(
            PersistedStateLoadPolicy.retryDelayNanoseconds(attempt: 1),
            1_000_000_000
        )
        XCTAssertEqual(
            [1, 2, 3, 4, 5, 6].map(
                PersistedStateLoadPolicy.retryDelayNanoseconds
            ),
            [1, 2, 4, 8, 15, 15].map {
                UInt64($0) * 1_000_000_000
            }
        )
    }

    func testStartCreatesOnlyOneWorkerAndOneActiveAttempt() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        let coordinator = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: completions.record
        )

        for _ in 0..<100 {
            coordinator.start()
        }
        try await backend.waitForAttemptCount(1)

        XCTAssertEqual(backend.attempts, [1])
        XCTAssertEqual(backend.maximumActiveCalls, 1)

        backend.resolveNext(.loaded)
        try await completions.waitForCount(1)
    }

    func testWakeRequestsDuringAttemptCoalesceIntoOneNextAttempt() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        let coordinator = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: completions.record
        )

        coordinator.start()
        try await backend.waitForAttemptCount(1)
        for _ in 0..<100 {
            coordinator.requestEarlierRetry()
        }

        XCTAssertEqual(backend.attempts, [1])
        XCTAssertEqual(backend.activeCalls, 1)

        backend.resolveNext(.unavailable(.timeout))
        try await backend.waitForAttemptCount(2)

        XCTAssertEqual(backend.attempts, [1, 2])
        XCTAssertEqual(backend.maximumActiveCalls, 1)
        XCTAssertTrue(delay.requestedNanoseconds.isEmpty)

        backend.resolveNext(.loaded)
        try await completions.waitForCount(2)
        XCTAssertEqual(completions.records.map(\.1), [1, 2])
    }

    func testFreshLoadAndWakeShareOneSerializedNextAttempt() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        let coordinator = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: completions.record
        )

        coordinator.start()
        try await backend.waitForAttemptCount(1)

        let freshLoad = Task { await coordinator.loadFresh() }
        await Task.yield()
        for _ in 0..<100 {
            coordinator.requestEarlierRetry()
        }

        backend.resolveNext(.superseded)
        try await backend.waitForAttemptCount(2)

        XCTAssertEqual(backend.attempts, [1, 2])
        XCTAssertEqual(backend.maximumActiveCalls, 1)
        XCTAssertTrue(delay.requestedNanoseconds.isEmpty)

        backend.resolveNext(.loaded)
        let freshOutcome = await freshLoad.value
        XCTAssertEqual(freshOutcome, .loaded)
        try await completions.waitForCount(2)
        XCTAssertEqual(backend.attempts, [1, 2])
    }

    func testPostStartupUnavailableFreshLoadReconcilesOnceAfterRetryLoads() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        let lifecycleGeneration: UInt64 = 42
        var postRecoveryReconciliation =
            PersistedStatePostRecoveryReconciliation()
        var reconciliationCount = 0
        let coordinator = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: { outcome, attempt in
                completions.record(outcome: outcome, attempt: attempt)
                if postRecoveryReconciliation.consumeIfCurrent(
                    outcome: outcome,
                    currentLifecycleGeneration: lifecycleGeneration
                ) {
                    reconciliationCount += 1
                }
            }
        )

        let freshLoad = Task { await coordinator.loadFresh() }
        try await backend.waitForAttemptCount(1)
        backend.resolveNext(.unavailable(.timeout))

        let freshOutcome = await freshLoad.value
        XCTAssertEqual(freshOutcome, .unavailable(.timeout))
        postRecoveryReconciliation.markPending(
            lifecycleGeneration: lifecycleGeneration
        )
        postRecoveryReconciliation.markPending(
            lifecycleGeneration: lifecycleGeneration
        )

        try await delay.waitForRequestCount(1)
        coordinator.requestEarlierRetry()
        try await backend.waitForAttemptCount(2)
        backend.resolveNext(.loaded)
        try await completions.waitForCount(2)

        XCTAssertEqual(reconciliationCount, 1)

        coordinator.start()
        try await backend.waitForAttemptCount(3)
        backend.resolveNext(.loaded)
        try await completions.waitForCount(3)

        XCTAssertEqual(reconciliationCount, 1)
    }

    func testInvalidConfigurationClearsPendingPostRecoveryReconciliation() {
        var postRecoveryReconciliation =
            PersistedStatePostRecoveryReconciliation()
        postRecoveryReconciliation.markPending(lifecycleGeneration: 42)

        XCTAssertFalse(
            postRecoveryReconciliation.consumeIfCurrent(
                outcome: .invalidConfiguration,
                currentLifecycleGeneration: 42
            )
        )
        XCTAssertFalse(
            postRecoveryReconciliation.consumeIfCurrent(
                outcome: .loaded,
                currentLifecycleGeneration: 42
            )
        )
    }

    func testFreshLoadRequestedDuringFreshAttemptWaitsForNextAttempt() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        let coordinator = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: completions.record
        )

        let firstFreshLoad = Task { await coordinator.loadFresh() }
        try await backend.waitForAttemptCount(1)

        let secondFreshLoad = Task { await coordinator.loadFresh() }
        await Task.yield()
        backend.resolveNext(.superseded)

        let firstOutcome = await firstFreshLoad.value
        XCTAssertEqual(firstOutcome, .superseded)
        try await backend.waitForAttemptCount(2)

        backend.resolveNext(.loaded)
        let secondOutcome = await secondFreshLoad.value
        XCTAssertEqual(secondOutcome, .loaded)
        try await completions.waitForCount(2)
        XCTAssertEqual(backend.maximumActiveCalls, 1)
    }

    func testWakeDuringDelayCancelsOnlyDelayAndStartsOneNextAttempt() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        let coordinator = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: completions.record
        )

        coordinator.start()
        try await backend.waitForAttemptCount(1)
        backend.resolveNext(.unavailable(.connectionInterrupted))
        try await delay.waitForRequestCount(1)

        coordinator.requestEarlierRetry()
        try await backend.waitForAttemptCount(2)

        XCTAssertEqual(backend.attempts, [1, 2])
        XCTAssertEqual(backend.maximumActiveCalls, 1)
        XCTAssertEqual(delay.cancellationCount, 1)

        backend.resolveNext(.loaded)
        try await completions.waitForCount(2)
    }

    func testLoadedStopsRetryAndNextStartResetsAttemptToOne() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        let coordinator = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: completions.record
        )

        coordinator.start()
        try await backend.waitForAttemptCount(1)
        backend.resolveNext(.loaded)
        try await completions.waitForCount(1)

        coordinator.start()
        try await backend.waitForAttemptCount(2)
        XCTAssertEqual(backend.attempts, [1, 1])
        XCTAssertTrue(delay.requestedNanoseconds.isEmpty)

        backend.resolveNext(.loaded)
        try await completions.waitForCount(2)
    }

    func testCoordinatorDeallocatesDuringInFlightAttemptAndDoesNotRetry() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        var coordinator: PersistedStateRecoveryCoordinator? = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: completions.record
        )
        let coordinatorReference = WeakReference(coordinator)

        coordinator?.start()
        try await backend.waitForAttemptCount(1)
        coordinator = nil

        XCTAssertNil(coordinatorReference.value)

        backend.resolveNext(.unavailable(.timeout))
        try await completions.waitForCount(1)

        XCTAssertEqual(backend.attempts, [1])
        XCTAssertTrue(delay.requestedNanoseconds.isEmpty)
    }

    func testReentrantWakeFromCompletionStartsImmediateRetry() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        let coordinatorReference =
            WeakReference<PersistedStateRecoveryCoordinator>(nil)
        let coordinator = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: { outcome, attempt in
                completions.record(outcome: outcome, attempt: attempt)
                if attempt == 1 {
                    coordinatorReference.value?.requestEarlierRetry()
                }
            }
        )
        coordinatorReference.value = coordinator

        coordinator.start()
        try await backend.waitForAttemptCount(1)
        backend.resolveNext(.unavailable(.timeout))
        try await completions.waitForCount(1)

        XCTAssertEqual(backend.attempts, [1, 2])
        XCTAssertTrue(delay.requestedNanoseconds.isEmpty)

        backend.resolveNext(.loaded)
        try await completions.waitForCount(2)
    }

    func testInvalidConfigurationStopsRetry() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        let coordinator = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: completions.record
        )

        coordinator.start()
        try await backend.waitForAttemptCount(1)
        backend.resolveNext(.invalidConfiguration)
        try await completions.waitForCount(1)

        XCTAssertEqual(backend.attempts, [1])
        XCTAssertTrue(delay.requestedNanoseconds.isEmpty)
    }

    func testUnavailableAndSupersededContinueWithBackoff() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        let coordinator = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: completions.record
        )

        coordinator.start()
        try await backend.waitForAttemptCount(1)
        backend.resolveNext(.unavailable(.agentNotResponding))
        try await delay.waitForRequestCount(1)
        XCTAssertEqual(delay.requestedNanoseconds, [1_000_000_000])

        delay.resumePendingWait()
        try await backend.waitForAttemptCount(2)
        backend.resolveNext(.superseded)
        try await delay.waitForRequestCount(2)
        XCTAssertEqual(
            delay.requestedNanoseconds,
            [1_000_000_000, 2_000_000_000]
        )

        delay.resumePendingWait()
        try await backend.waitForAttemptCount(3)
        backend.resolveNext(.loaded)
        try await completions.waitForCount(3)

        XCTAssertEqual(backend.attempts, [1, 2, 3])
        XCTAssertEqual(completions.records.map(\.1), [1, 2, 3])
    }

    func testCancelDuringAttemptPreventsCompletionFromStartingRetry() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        let coordinator = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: completions.record
        )

        coordinator.start()
        try await backend.waitForAttemptCount(1)
        coordinator.cancel()
        backend.resolveNext(.unavailable(.timeout))
        try await completions.waitForCount(1)

        XCTAssertEqual(backend.attempts, [1])
        XCTAssertEqual(completions.records.map(\.1), [1])
        XCTAssertTrue(delay.requestedNanoseconds.isEmpty)
    }

    func testAgentSetupAllowsOnlyTheUserEnableAction() {
        let setup = PersistedStateAvailability.agentSetupRequired

        XCTAssertTrue(setup.allowsUserEnable)
        XCTAssertTrue(setup.showsProtectionToggle)
        XCTAssertFalse(setup.allowsLifecycleActions)
        XCTAssertFalse(setup.allowsConfigurationMutation)
        XCTAssertFalse(setup.allowsRecoveryRequests)
        XCTAssertFalse(setup.showsProgressIndicator)
        XCTAssertNil(setup.statusMessageOverride)
        XCTAssertNil(setup.protectionHeadlineOverride)
    }

    func testUserEnableIsAllowedOnlyWhenLoadedOrAwaitingAgentSetup() {
        XCTAssertTrue(PersistedStateAvailability.loaded.allowsUserEnable)
        XCTAssertFalse(PersistedStateAvailability.loading.allowsUserEnable)
        XCTAssertFalse(PersistedStateAvailability.unavailable.allowsUserEnable)
        XCTAssertFalse(
            PersistedStateAvailability.invalidConfiguration.allowsUserEnable
        )
    }

    func testMissingStateFileWithoutRunnableAgentRequiresAgentSetup() {
        XCTAssertTrue(
            AgentSetupRequirementPolicy.requiresAgentSetup(
                stateFile: .missing,
                supportDirectoryExists: true
            )
        )
    }

    func testUnreadableStateFileWithoutSupportDirectoryRequiresAgentSetup() {
        XCTAssertTrue(
            AgentSetupRequirementPolicy.requiresAgentSetup(
                stateFile: .ioFailure,
                supportDirectoryExists: false
            )
        )
    }

    func testUnreadableStateFileInExistingSupportDirectoryIsNotAFreshInstall() {
        XCTAssertFalse(
            AgentSetupRequirementPolicy.requiresAgentSetup(
                stateFile: .ioFailure,
                supportDirectoryExists: true
            )
        )
    }

    func testExistingStateFileIsNeverTreatedAsAFreshInstall() {
        XCTAssertFalse(
            AgentSetupRequirementPolicy.requiresAgentSetup(
                stateFile: .valid([:]),
                supportDirectoryExists: true
            )
        )
        XCTAssertFalse(
            AgentSetupRequirementPolicy.requiresAgentSetup(
                stateFile: .invalidConfiguration,
                supportDirectoryExists: true
            )
        )
    }

    func testAgentSetupStopsRetryAndFreshLoadStartsANewAttempt() async throws {
        let backend = ControlledPersistedStateLoadBackend()
        let delay = ControlledPersistedStateRetryDelay()
        let completions = ControlledAttemptCompletionRecorder()
        let coordinator = makeCoordinator(
            backend: backend,
            delay: delay,
            completion: completions.record
        )

        coordinator.start()
        try await backend.waitForAttemptCount(1)
        backend.resolveNext(.agentSetupRequired)
        try await completions.waitForCount(1)

        XCTAssertEqual(backend.attempts, [1])
        XCTAssertTrue(delay.requestedNanoseconds.isEmpty)

        let freshLoad = Task { await coordinator.loadFresh() }
        try await backend.waitForAttemptCount(2)
        backend.resolveNext(.loaded)

        let outcome = await freshLoad.value
        XCTAssertEqual(outcome, .loaded)
        XCTAssertEqual(backend.attempts, [1, 1])
    }

    private func makeCoordinator(
        backend: ControlledPersistedStateLoadBackend,
        delay: ControlledPersistedStateRetryDelay,
        completion: @escaping PersistedStateRecoveryCoordinator.AttemptCompletion
    ) -> PersistedStateRecoveryCoordinator {
        let coordinator = PersistedStateRecoveryCoordinator(
            loadAttempt: { attempt in
                await backend.load(attempt: attempt)
            },
            attemptCompletion: completion,
            retryDelay: { nanoseconds in
                await delay.wait(nanoseconds: nanoseconds)
            }
        )
        let coordinatorReference = WeakReference(coordinator)
        addTeardownBlock {
            await MainActor.run {
                coordinatorReference.value?.cancel()
                backend.close()
                delay.close()
            }
        }
        return coordinator
    }
}

@MainActor
private final class ControlledPersistedStateLoadBackend {
    private(set) var attempts: [Int] = []
    private(set) var activeCalls = 0
    private(set) var maximumActiveCalls = 0

    private let attemptCountSignal = ControlledCountSignal()
    private var continuations: [CheckedContinuation<PersistedStateLoadOutcome, Never>] = []
    private var isClosed = false

    func load(attempt: Int) async -> PersistedStateLoadOutcome {
        guard !isClosed else { return .invalidConfiguration }
        attempts.append(attempt)
        activeCalls += 1
        maximumActiveCalls = max(maximumActiveCalls, activeCalls)
        attemptCountSignal.increment()
        let outcome = await withCheckedContinuation { continuation in
            continuations.append(continuation)
        }
        activeCalls -= 1
        return outcome
    }

    func waitForAttemptCount(_ count: Int) async throws {
        try await attemptCountSignal.wait(until: count)
    }

    func resolveNext(_ outcome: PersistedStateLoadOutcome) {
        guard !continuations.isEmpty else {
            XCTFail("No persisted-state load attempt is pending")
            return
        }
        continuations.removeFirst().resume(returning: outcome)
    }

    func close() {
        isClosed = true
        let pending = continuations
        continuations.removeAll()
        pending.forEach { $0.resume(returning: .invalidConfiguration) }
    }
}

@MainActor
private final class ControlledAttemptCompletionRecorder {
    private(set) var records: [(PersistedStateLoadOutcome, Int)] = []

    private let countSignal = ControlledCountSignal()

    func record(outcome: PersistedStateLoadOutcome, attempt: Int) {
        records.append((outcome, attempt))
        countSignal.increment()
    }

    func waitForCount(_ count: Int) async throws {
        try await countSignal.wait(until: count)
    }
}

@MainActor
private final class ControlledPersistedStateRetryDelay {
    private(set) var requestedNanoseconds: [UInt64] = []
    private(set) var cancellationCount = 0

    private let requestCountSignal = ControlledCountSignal()
    private var cancelledIDs: Set<UUID> = []
    private var pendingID: UUID?
    private var pendingContinuation: CheckedContinuation<Void, Never>?
    private var isClosed = false

    func wait(nanoseconds: UInt64) async {
        guard !isClosed else { return }
        let id = UUID()
        requestedNanoseconds.append(nanoseconds)
        requestCountSignal.increment()
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled || cancelledIDs.contains(id) {
                    continuation.resume()
                    return
                }
                guard pendingContinuation == nil else {
                    XCTFail("More than one retry delay is pending")
                    continuation.resume()
                    return
                }
                pendingID = id
                pendingContinuation = continuation
            }
        } onCancel: {
            Task { @MainActor [weak self] in
                self?.cancel(id: id)
            }
        }
    }

    func waitForRequestCount(_ count: Int) async throws {
        try await requestCountSignal.wait(until: count)
    }

    func resumePendingWait() {
        guard let continuation = pendingContinuation else {
            XCTFail("No retry delay is pending")
            return
        }
        pendingID = nil
        pendingContinuation = nil
        continuation.resume()
    }

    private func cancel(id: UUID) {
        guard cancelledIDs.insert(id).inserted else { return }
        cancellationCount += 1
        guard pendingID == id else { return }
        resumePendingWait()
    }

    func close() {
        isClosed = true
        pendingID = nil
        let pending = pendingContinuation
        pendingContinuation = nil
        pending?.resume()
    }
}

private enum ControlledCountWaitError: Error, Equatable {
    case timedOut(expectedCount: Int)
}

@MainActor
private final class ControlledCountSignal {
    private struct Waiter {
        let count: Int
        let expectation: XCTestExpectation
    }

    private var count = 0
    private var waiters: [UUID: Waiter] = [:]

    func increment() {
        count += 1
        let ready = waiters.filter { $0.value.count <= count }
        for (id, waiter) in ready {
            waiters.removeValue(forKey: id)
            waiter.expectation.fulfill()
        }
    }

    func wait(until expectedCount: Int, timeout: TimeInterval = 2) async throws {
        try Task.checkCancellation()
        guard count < expectedCount else { return }
        let id = UUID()
        let expectation = XCTestExpectation(description: "count reaches \(expectedCount)")
        waiters[id] = Waiter(count: expectedCount, expectation: expectation)
        defer { waiters.removeValue(forKey: id) }
        let result = await XCTWaiter.fulfillment(of: [expectation], timeout: timeout)
        try Task.checkCancellation()
        guard result == .completed else {
            throw ControlledCountWaitError.timedOut(expectedCount: expectedCount)
        }
    }
}

private final class WeakReference<Value: AnyObject> {
    weak var value: Value?

    init(_ value: Value?) {
        self.value = value
    }
}
