// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

enum PersistedStateAvailability: Equatable {
    case loading
    case loaded
    case unavailable
    case invalidConfiguration
    /// Fresh install: no Agent can run and no `state.json` exists yet. Only an
    /// explicit Enable may proceed. It installs the Agent, which bootstraps
    /// `state.json`, and then loads the authoritative state.
    case agentSetupRequired

    var allowsLifecycleActions: Bool {
        self == .loaded
    }

    var allowsUserEnable: Bool {
        self == .loaded || self == .agentSetupRequired
    }

    var allowsConfigurationMutation: Bool {
        self == .loaded
    }

    var allowsRecoveryRequests: Bool {
        self == .loading || self == .unavailable
    }

    var statusMessageOverride: String? {
        switch self {
        case .loading, .unavailable:
            return "Waiting for Agent"
        case .invalidConfiguration:
            return "Configuration Error"
        case .loaded, .agentSetupRequired:
            return nil
        }
    }

    var protectionHeadlineOverride: String? {
        switch self {
        case .loading, .unavailable:
            return "Protection State Unknown"
        case .invalidConfiguration:
            return "Configuration Error"
        case .loaded, .agentSetupRequired:
            return nil
        }
    }

    var showsProtectionToggle: Bool {
        allowsUserEnable
    }

    var showsProgressIndicator: Bool {
        self == .loading || self == .unavailable
    }
}

enum ConfigurationMutationBoundary {
    @discardableResult
    static func performIfAllowed(
        availability: PersistedStateAvailability,
        mutation: () -> Void
    ) -> Bool {
        guard availability.allowsConfigurationMutation else { return false }

        mutation()
        return true
    }
}

enum FullConfigSaveBoundary {
    @discardableResult
    static func performIfAllowed(
        availability: PersistedStateAvailability,
        isApplyingPersistedState: Bool,
        save: () -> Void
    ) -> Bool {
        guard !isApplyingPersistedState else { return false }

        return ConfigurationMutationBoundary.performIfAllowed(
            availability: availability,
            mutation: save
        )
    }
}

enum PersistedStateUnavailableReason: Equatable {
    case timeout
    case agentNotResponding
    case connectionInterrupted
    case stateReadFailure
}

enum PersistedStateLoadOutcome: Equatable {
    case loaded
    case unavailable(PersistedStateUnavailableReason)
    case invalidConfiguration
    case agentSetupRequired
    case superseded
}

enum PersistedStateFileLoadOutcome {
    case valid([String: Any])
    case missing
    case invalidConfiguration
    case ioFailure
}

/// Recognizes a fresh install once the Agent is known not to be runnable.
///
/// On a pristine Mac the MacDNS support directory does not exist, so the state
/// file lock cannot be opened and the read reports an I/O failure rather than a
/// missing file. Only that positively established absence counts. Any other
/// I/O failure stays unavailable and is never replaced by defaults.
enum AgentSetupRequirementPolicy {
    static func requiresAgentSetup(
        stateFile: PersistedStateFileLoadOutcome,
        supportDirectoryExists: Bool
    ) -> Bool {
        switch stateFile {
        case .missing:
            return true
        case .ioFailure:
            return !supportDirectoryExists
        case .valid, .invalidConfiguration:
            return false
        }
    }
}

struct PersistedStatePostRecoveryReconciliation {
    private var pendingLifecycleGeneration: UInt64?

    mutating func markPending(lifecycleGeneration: UInt64) {
        pendingLifecycleGeneration = lifecycleGeneration
    }

    mutating func consumeIfCurrent(
        outcome: PersistedStateLoadOutcome,
        currentLifecycleGeneration: UInt64
    ) -> Bool {
        switch outcome {
        case .loaded:
            guard let pendingLifecycleGeneration else { return false }
            self.pendingLifecycleGeneration = nil
            return pendingLifecycleGeneration == currentLifecycleGeneration
        case .invalidConfiguration:
            pendingLifecycleGeneration = nil
            return false
        case .unavailable, .agentSetupRequired, .superseded:
            return false
        }
    }
}

enum PersistedStateLoadDecision: Equatable {
    case retry(PersistedStateUnavailableReason)
    case useStateFileFallback
    case invalidConfiguration
}

enum PersistedStateLoadPolicy {
    static func decision(
        for error: XPCError,
        canUseStateFileFallback: Bool
    ) -> PersistedStateLoadDecision {
        switch error {
        case .timeout:
            return .retry(.timeout)
        case .agentNotResponding:
            return canUseStateFileFallback
                ? .useStateFileFallback
                : .retry(.agentNotResponding)
        case .connectionInterrupted:
            return canUseStateFileFallback
                ? .useStateFileFallback
                : .retry(.connectionInterrupted)
        case .agentStateUnreadable:
            return .retry(.stateReadFailure)
        case .decodingFailed, .agentError:
            return .invalidConfiguration
        }
    }

    static func retryDelayNanoseconds(attempt: Int) -> UInt64 {
        let seconds = [1, 2, 4, 8, 15][min(max(attempt - 1, 0), 4)]
        return UInt64(seconds) * 1_000_000_000
    }
}

@MainActor
final class PersistedStateRecoveryCoordinator {
    typealias LoadAttempt =
        (_ attempt: Int) async -> PersistedStateLoadOutcome
    typealias AttemptCompletion =
        (_ outcome: PersistedStateLoadOutcome, _ attempt: Int) -> Void
    typealias RetryDelay = (_ nanoseconds: UInt64) async -> Void
    private typealias FreshLoadWaiter =
        CheckedContinuation<PersistedStateLoadOutcome, Never>

    private final class WorkerState {
        var isRunning = false
        var isAttemptInFlight = false
        var retryImmediatelyAfterAttempt = false
        var freshLoadRequested = false
        var delayTask: Task<Void, Never>?
        var freshLoadWaiters: [FreshLoadWaiter] = []

        func cancel() {
            retryImmediatelyAfterAttempt = false
            freshLoadRequested = false
            delayTask?.cancel()
            resolvePendingFreshLoads(with: .superseded)
        }

        func finish() {
            isRunning = false
            isAttemptInFlight = false
            retryImmediatelyAfterAttempt = false
            freshLoadRequested = false
            delayTask?.cancel()
            delayTask = nil
            resolvePendingFreshLoads(with: .superseded)
        }

        func takeFreshLoadWaiters() -> [FreshLoadWaiter]? {
            guard freshLoadRequested else { return nil }
            freshLoadRequested = false
            let waiters = freshLoadWaiters
            freshLoadWaiters.removeAll()
            return waiters
        }

        func resolveFreshLoadWaiters(
            _ waiters: [FreshLoadWaiter],
            with outcome: PersistedStateLoadOutcome
        ) {
            waiters.forEach { $0.resume(returning: outcome) }
        }

        private func resolvePendingFreshLoads(
            with outcome: PersistedStateLoadOutcome
        ) {
            let waiters = freshLoadWaiters
            freshLoadWaiters.removeAll()
            resolveFreshLoadWaiters(waiters, with: outcome)
        }
    }

    private let loadAttempt: LoadAttempt
    private let attemptCompletion: AttemptCompletion
    private let retryDelay: RetryDelay
    private let state = WorkerState()

    private var worker: Task<Void, Never>?

    init(
        loadAttempt: @escaping LoadAttempt,
        attemptCompletion: @escaping AttemptCompletion,
        retryDelay: @escaping RetryDelay = { nanoseconds in
            try? await Task.sleep(nanoseconds: nanoseconds)
        }
    ) {
        self.loadAttempt = loadAttempt
        self.attemptCompletion = attemptCompletion
        self.retryDelay = retryDelay
    }

    deinit {
        state.cancel()
        worker?.cancel()
    }

    func start() {
        guard !state.isRunning else { return }
        state.isRunning = true
        let state = state
        let loadAttempt = loadAttempt
        let attemptCompletion = attemptCompletion
        let retryDelay = retryDelay
        worker = Task { @MainActor in
            defer { state.finish() }
            await Self.runWorker(
                state: state,
                loadAttempt: loadAttempt,
                attemptCompletion: attemptCompletion,
                retryDelay: retryDelay
            )
        }
    }

    func loadFresh() async -> PersistedStateLoadOutcome {
        await withCheckedContinuation { continuation in
            state.freshLoadWaiters.append(continuation)
            state.freshLoadRequested = true
            requestEarlierRetry()
        }
    }

    func requestEarlierRetry() {
        guard state.isRunning else {
            start()
            return
        }
        if state.isAttemptInFlight || state.delayTask == nil {
            state.retryImmediatelyAfterAttempt = true
        } else {
            state.delayTask?.cancel()
        }
    }

    func cancel() {
        state.cancel()
        worker?.cancel()
    }

    private static func runWorker(
        state: WorkerState,
        loadAttempt: LoadAttempt,
        attemptCompletion: AttemptCompletion,
        retryDelay: @escaping RetryDelay
    ) async {
        var attempt = 1
        while !Task.isCancelled {
            let freshLoadWaiters = state.takeFreshLoadWaiters()

            state.isAttemptInFlight = true
            let outcome = await loadAttempt(attempt)
            state.isAttemptInFlight = false
            attemptCompletion(outcome, attempt)
            if let freshLoadWaiters {
                state.resolveFreshLoadWaiters(
                    freshLoadWaiters,
                    with: outcome
                )
            }

            guard !Task.isCancelled else { return }
            if state.freshLoadRequested {
                state.retryImmediatelyAfterAttempt = false
                attempt += 1
                continue
            }

            switch outcome {
            case .loaded, .invalidConfiguration, .agentSetupRequired:
                state.retryImmediatelyAfterAttempt = false
                return
            case .unavailable, .superseded:
                break
            }

            if state.retryImmediatelyAfterAttempt {
                state.retryImmediatelyAfterAttempt = false
            } else {
                let nanoseconds =
                    PersistedStateLoadPolicy.retryDelayNanoseconds(
                        attempt: attempt
                    )
                let task = Task { @MainActor in
                    await retryDelay(nanoseconds)
                }
                state.delayTask = task
                await task.value
                state.delayTask = nil
                guard !Task.isCancelled else { return }
            }
            attempt += 1
        }
    }
}
