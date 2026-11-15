// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

/// Save results the UI must be able to report instead of failing silently.
enum FullConfigSaveOutcome: Equatable {
    /// The write is durably persisted.
    case committed
    /// The Agent never answered a write. The snapshot is retained and no new
    /// transaction starts until an authoritative reload accounts for it.
    case stalled
    /// The Agent refused the write permanently.
    case rejected(reason: FullConfigSaveResponse.RejectionReason?)
    /// An authoritative reload accounted for a previously stalled write.
    case recovered
    /// The configuration changed after the App last loaded it. The write was
    /// dropped and the authoritative configuration replaced the edit.
    case conflict

    /// Persistent message for the App, or `nil` when nothing is wrong.
    var failureMessage: String? {
        switch self {
        case .committed, .recovered:
            return nil
        case .stalled:
            return
                "Configuration not confirmed: the Agent has not answered the last save. Retrying."
        case .rejected(let reason):
            return
                "Configuration not saved: \(Self.description(of: reason)). The last change was reverted."
        case .conflict:
            return
                "The configuration changed elsewhere, so the last change was not saved."
        }
    }

    private static func description(
        of reason: FullConfigSaveResponse.RejectionReason?
    ) -> String {
        switch reason {
        case .invalidConfiguration:
            return "the Agent rejected it as invalid"
        case .persistenceFailure:
            return "the Agent could not write the configuration file"
        case .runtimeApplyFailure:
            return "the Agent could not apply it to the resolver"
        case .revisionExhausted:
            return "the configuration revision limit was reached"
        case nil:
            return "the Agent refused it"
        }
    }
}

@MainActor
final class FullConfigSaveCoordinator {
    typealias SaveToAgent =
        ([String: Any]) async -> Result<FullConfigSaveResponse, XPCError>
    typealias LoadAuthoritative = () async -> [String: Any]?
    typealias ShouldUseFallback = () -> Bool
    typealias SaveFallback = ([String: Any], ConfigRevision) -> ConfigRevision?
    typealias ApplyAuthoritative = ([String: Any]) -> Void
    typealias RetryDelay = (UInt64) async -> Void
    typealias PublishOutcome = (FullConfigSaveOutcome) -> Void

    private enum SaveDisposition {
        case completed
        case retryLater(PendingSave)
        /// The write is unaccounted for: keep the snapshot, start nothing new.
        case stalled(PendingSave, expectedRevision: ConfigRevision)
    }

    private struct PendingSave {
        let snapshot: [String: Any]
        var agentAttempted: Bool
    }

    /// A write the Agent never answered, kept until a reload accounts for it.
    private struct StalledWrite {
        let snapshot: [String: Any]
        let expectedRevision: ConfigRevision
    }

    private let saveToAgent: SaveToAgent
    private let loadAuthoritative: LoadAuthoritative
    private let shouldUseFallback: ShouldUseFallback
    private let saveFallback: SaveFallback
    private let applyAuthoritative: ApplyAuthoritative
    private let retryDelay: RetryDelay
    private let publishOutcome: PublishOutcome

    private(set) var revision: ConfigRevision
    private var pendingSave: PendingSave?
    private var worker: Task<Void, Never>?
    private var stalledWrite: StalledWrite?
    /// The configuration the App's edits start from: the last one it loaded,
    /// applied or committed.
    private var editBase: [String: Any]?

    var isIdle: Bool {
        worker == nil && pendingSave == nil
    }

    init(
        revision: ConfigRevision,
        saveToAgent: @escaping SaveToAgent,
        loadAuthoritative: @escaping LoadAuthoritative,
        shouldUseFallback: @escaping ShouldUseFallback = { false },
        saveFallback: @escaping SaveFallback,
        applyAuthoritative: @escaping ApplyAuthoritative,
        retryDelay: @escaping RetryDelay = { nanoseconds in
            try? await Task.sleep(nanoseconds: nanoseconds)
        },
        publishOutcome: @escaping PublishOutcome = { _ in }
    ) {
        self.revision = max(0, revision)
        self.saveToAgent = saveToAgent
        self.loadAuthoritative = loadAuthoritative
        self.shouldUseFallback = shouldUseFallback
        self.saveFallback = saveFallback
        self.applyAuthoritative = applyAuthoritative
        self.retryDelay = retryDelay
        self.publishOutcome = publishOutcome
    }

    func adoptRevision(from config: [String: Any]) {
        adoptRevision(ConfigRevisionPolicy.revision(from: config))
    }

    /// Adopts a configuration the App loaded and now shows.
    func adopt(loaded config: [String: Any]) {
        editBase = config
        adoptRevision(from: config)
    }

    func enqueue(_ snapshot: [String: Any]) {
        pendingSave = PendingSave(snapshot: snapshot, agentAttempted: false)
        guard worker == nil else { return }
        worker = Task { @MainActor [weak self] in
            guard let self else { return }
            defer { self.worker = nil }
            await self.runLoop()
        }
    }

    private func runLoop() async {
        var deferredRetryCount = 0
        while let currentSave = pendingSave {
            pendingSave = nil
            switch await save(currentSave) {
            case .completed:
                deferredRetryCount = 0
            case .retryLater(let retry):
                if pendingSave != nil {
                    deferredRetryCount = 0
                    continue
                }
                pendingSave = retry
                let delay = retryDelayNanoseconds(
                    deferredRetryCount: deferredRetryCount
                )
                deferredRetryCount += 1
                await retryDelay(delay)
            case .stalled(let retry, let expectedRevision):
                stalledWrite = StalledWrite(
                    snapshot: retry.snapshot,
                    expectedRevision: expectedRevision
                )
                publishOutcome(.stalled)
                if pendingSave == nil {
                    pendingSave = retry
                }
                let delay = retryDelayNanoseconds(
                    deferredRetryCount: deferredRetryCount
                )
                deferredRetryCount += 1
                await retryDelay(delay)
            }
        }
    }

    private func save(_ initialSave: PendingSave) async -> SaveDisposition {
        var pending = initialSave
        var didRebase = false

        if let stalledWrite {
            switch await confirmStalledWrite(
                stalledWrite,
                pending: pending,
                didRebase: &didRebase
            ) {
            case .accountedFor, .dropped:
                return .completed
            case .unaccountable:
                return .retryLater(pending)
            case .supersedable:
                break
            }
        }

        while revision < .max {
            let snapshot = pending.snapshot
            let expectedRevision = revision

            if !pending.agentAttempted && shouldUseFallback() {
                if let persistedRevision = saveFallback(
                    snapshot,
                    expectedRevision
                ), persistedRevision == expectedRevision + 1 {
                    adoptRevision(persistedRevision)
                    editBase = snapshot
                    publishOutcome(.committed)
                    return .completed
                }

                guard let authoritative = await loadAuthoritative() else {
                    return .retryLater(pending)
                }
                guard pendingSave == nil else {
                    return .completed
                }
                guard
                    rebase(
                        snapshot, onto: authoritative, didRebase: &didRebase,
                        exhausted: .rejected(reason: .persistenceFailure))
                else {
                    return .completed
                }
                continue
            }

            pending.agentAttempted = true
            let request = request(
                snapshot: snapshot,
                expectedRevision: expectedRevision
            )
            let result = await saveToAgent(request)

            switch result {
            case .success(let response):
                // A conflict keeps the stale revision until the authoritative
                // configuration replaces the edit, so no retry can win on it.
                if response.status != .conflict,
                    let authoritativeRevision = response.authoritativeRevision
                {
                    adoptRevision(authoritativeRevision)
                }

                switch response.status {
                case .committed, .alreadyCommitted:
                    if response.authoritativeRevision == nil {
                        adoptRevision(expectedRevision + 1)
                    }
                    editBase = snapshot
                    publishOutcome(.committed)
                    return .completed

                case .lifecycleBusy:
                    return .retryLater(pending)

                case .conflict:
                    guard let authoritative = await loadAuthoritative() else {
                        return .retryLater(pending)
                    }
                    // A newer snapshot was edited on the same stale
                    // configuration and conflicts in turn.
                    guard pendingSave == nil else {
                        return .completed
                    }
                    guard
                        rebase(
                            snapshot, onto: authoritative, didRebase: &didRebase,
                            exhausted: .conflict)
                    else {
                        return .completed
                    }

                case .rejected:
                    publishOutcome(
                        .rejected(reason: response.rejectionReason)
                    )
                    if let authoritative = await loadAndAdoptAuthoritative() {
                        applyIfCurrent(authoritative)
                    }
                    return .completed
                }

            case .failure(let error):
                if case .timeout = error {
                    return .stalled(
                        pending,
                        expectedRevision: expectedRevision
                    )
                }

                guard isAmbiguousWriteResult(error) else {
                    publishOutcome(.rejected(reason: nil))
                    if let authoritative = await loadAndAdoptAuthoritative() {
                        applyIfCurrent(authoritative)
                    }
                    return .completed
                }

                guard let authoritative = await loadAuthoritative() else {
                    return .retryLater(pending)
                }

                if landed(snapshot, on: expectedRevision, in: authoritative) {
                    adoptRevision(ConfigRevisionPolicy.revision(from: authoritative))
                    editBase = snapshot
                    applyIfCurrent(authoritative)
                    return .completed
                }
                guard pendingSave == nil else {
                    return .completed
                }
                guard
                    rebase(
                        snapshot, onto: authoritative, didRebase: &didRebase,
                        exhausted: .rejected(reason: nil))
                else {
                    return .completed
                }
            }
        }

        guard let authoritative = await loadAndAdoptAuthoritative() else {
            return .retryLater(pending)
        }
        applyIfCurrent(authoritative)
        return .completed
    }

    private enum StalledWriteConfirmation {
        /// The stalled write landed. The pending snapshot needs nothing more.
        case accountedFor
        /// The Agent is still unreachable: confirm again, start no transaction.
        case unaccountable
        /// The pending snapshot may be written on the reloaded revision.
        case supersedable
        /// Another writer changed what the pending snapshot writes. The
        /// authoritative configuration replaced the edit.
        case dropped
    }

    /// A stalled write may still be running inside the Agent, so the only safe
    /// next step is an authoritative reload: it proves the connection recovered
    /// and reveals whether the write consumed the revision it was given. A
    /// revision consumed by anything else is handled like a conflict.
    private func confirmStalledWrite(
        _ stalled: StalledWrite,
        pending: PendingSave,
        didRebase: inout Bool
    ) async -> StalledWriteConfirmation {
        guard let authoritative = await loadAndAdoptAuthoritative() else {
            return .unaccountable
        }
        stalledWrite = nil
        publishOutcome(.recovered)

        if landed(stalled.snapshot, on: stalled.expectedRevision, in: authoritative) {
            editBase = stalled.snapshot
            guard holds(pending.snapshot, in: authoritative) else {
                return .supersedable
            }
            applyIfCurrent(authoritative)
            return .accountedFor
        }
        guard ConfigRevisionPolicy.revision(from: authoritative) == stalled.expectedRevision else {
            return rebase(
                pending.snapshot, onto: authoritative, didRebase: &didRebase,
                exhausted: .conflict) ? .supersedable : .dropped
        }
        return .supersedable
    }

    private func adoptRevision(_ authoritativeRevision: ConfigRevision) {
        revision = max(revision, authoritativeRevision)
    }

    private func loadAndAdoptAuthoritative() async -> [String: Any]? {
        guard let authoritative = await loadAuthoritative() else {
            return nil
        }
        adoptRevision(ConfigRevisionPolicy.revision(from: authoritative))
        return authoritative
    }

    private func applyIfCurrent(_ authoritative: [String: Any]) {
        guard pendingSave == nil else { return }
        let authoritativeRevision = ConfigRevisionPolicy.revision(
            from: authoritative
        )
        guard authoritativeRevision >= revision else { return }
        adoptRevision(authoritativeRevision)
        editBase = authoritative
        applyAuthoritative(authoritative)
    }

    private func isAmbiguousWriteResult(_ error: XPCError) -> Bool {
        switch error {
        case .agentNotResponding, .connectionInterrupted, .decodingFailed:
            return true
        default:
            return false
        }
    }

    private func request(
        snapshot: [String: Any],
        expectedRevision: ConfigRevision
    ) -> [String: Any] {
        var request = snapshot
        request["configRevision"] = expectedRevision
        return request
    }

    /// Whether a write sent on `expectedRevision` is in `authoritative`. The
    /// revision may have moved past the one the write produced, because the
    /// Agent consumes revisions for state of its own, such as a blocklist
    /// refresh, and that state is never part of what the App writes.
    private func landed(
        _ snapshot: [String: Any],
        on expectedRevision: ConfigRevision,
        in authoritative: [String: Any]
    ) -> Bool {
        ConfigRevisionPolicy.revision(from: authoritative) > expectedRevision
            && holds(snapshot, in: authoritative)
    }

    /// Whether `authoritative` holds every value `snapshot` writes.
    private func holds(
        _ snapshot: [String: Any],
        in authoritative: [String: Any]
    ) -> Bool {
        guard
            let written = try? ConfigRevisionPolicy.canonicalPayload(snapshot),
            let persisted = try? ConfigRevisionPolicy.canonicalPayload(
                authoritative.filter { snapshot.keys.contains($0.key) }
            )
        else {
            return false
        }
        return written == persisted
    }

    /// Decides what happens to a snapshot that could not be written on the
    /// revision the App held. Returns true when it is to be sent again: the
    /// Agent consumes revisions for state of its own, such as a blocklist
    /// refresh, and the edit still applies then. Otherwise the authoritative
    /// configuration replaces the edit and the App says why: a conflict, or
    /// `exhausted` when the second attempt failed as well.
    private func rebase(
        _ snapshot: [String: Any],
        onto authoritative: [String: Any],
        didRebase: inout Bool,
        exhausted: FullConfigSaveOutcome
    ) -> Bool {
        let editStillApplies = overwritesOnlyItsBase(snapshot, in: authoritative)
        if editStillApplies, !didRebase {
            adoptRevision(ConfigRevisionPolicy.revision(from: authoritative))
            didRebase = true
            return true
        }
        applyIfCurrent(authoritative)
        publishOutcome(editStillApplies ? exhausted : .conflict)
        return false
    }

    /// Whether every value `snapshot` would write still holds, in
    /// `authoritative`, the value the edit started from. Sending the snapshot
    /// again then overwrites nobody's change.
    private func overwritesOnlyItsBase(
        _ snapshot: [String: Any],
        in authoritative: [String: Any]
    ) -> Bool {
        guard
            let editBase,
            let base = try? ConfigRevisionPolicy.canonicalPayload(
                editBase.filter { snapshot.keys.contains($0.key) }
            ),
            let current = try? ConfigRevisionPolicy.canonicalPayload(
                authoritative.filter { snapshot.keys.contains($0.key) }
            )
        else {
            return false
        }
        return base == current
    }

    private func retryDelayNanoseconds(
        deferredRetryCount: Int
    ) -> UInt64 {
        let cappedRetryCount = min(deferredRetryCount, 4)
        return 100_000_000 << UInt64(cappedRetryCount)
    }
}

@MainActor
enum FullConfigSnapshotBuilder {
    static func build(
        isEnabled: Bool,
        dnssecEnabled: Bool,
        logQueriesEnabled: Bool,
        logRepliesEnabled: Bool,
        prefetchEnabled: Bool,
        serveExpiredEnabled: Bool,
        dohProviders: Set<DoHProviderID>,
        dohDispatchMode: DoHDispatchMode,
        dnsAnswerRefinementEnabled: Bool,
        blockDohDotEnabled: Bool,
        queryHistory: QueryHistorySettings,
        customZones: [ForwardZone],
        dnsOverrides: [DNSOverride],
        allowedDomains: [AllowedDomain]
    ) -> [String: Any] {
        var snapshot: [String: Any] = [
            "isEnabled": isEnabled,
            "dnssecEnabled": dnssecEnabled,
            "logQueriesEnabled": logQueriesEnabled,
            "logRepliesEnabled": logRepliesEnabled,
            "prefetchEnabled": prefetchEnabled,
            "serveExpiredEnabled": serveExpiredEnabled,
            "dohProviders": DoHProviderID.allCases
                .filter { dohProviders.contains($0) }
                .map(\.rawValue),
            "dohDispatchMode": dohDispatchMode.rawValue,
            "dnsAnswerRefinementEnabled": dnsAnswerRefinementEnabled,
            "blockDohDotEnabled": blockDohDotEnabled,
            "customZones": customZones.map { $0.toDictionary() },
            "dnsOverrides": dnsOverrides.map { $0.toDictionary() },
            "allowlist": allowedDomains.map { $0.toDictionary() },
        ]
        snapshot.merge(queryHistory.stateDictionary) { _, history in history }
        return snapshot
    }
}
