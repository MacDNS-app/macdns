// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

/// Reason the license subsystem latched into fail-closed mode.
enum LicenseFailClosedReason: String, Codable, Equatable, Sendable {
    case stateLoadFailed
    case statePersistenceFailed
    case networkGraceExpired
}

/// Durable fail-closed latch.
///
/// Once engaged, only an authoritative license transition that was persisted
/// successfully may clear it. Network grace, timers, and in-memory parses never
/// clear the latch.
final class LicenseFailClosedLatch: @unchecked Sendable {
    private let lock = NSLock()
    private let store: LicenseStateFileStore
    private var state: LicenseFailClosedState?

    init(store: LicenseStateFileStore) {
        self.store = store
    }

    var reason: LicenseFailClosedReason? {
        lock.lock()
        defer { lock.unlock() }
        return state?.reason
    }

    var isEngaged: Bool {
        reason != nil
    }

    func restore(_ persistedState: LicenseFailClosedState) {
        lock.lock()
        defer { lock.unlock() }
        guard state == nil else { return }
        state = persistedState
    }

    @discardableResult
    func engage(
        _ reason: LicenseFailClosedReason,
        engagedAt: Date = Date()
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if state == nil {
            state = LicenseFailClosedState(
                reason: reason,
                engagedAt: engagedAt
            )
        }
        guard let state else { return false }
        return store.saveFailClosedState(state)
    }

    /// Clears the latch for a rights-*granting* authoritative transition.
    ///
    /// `AuthoritativeEvidence` can only be produced by `LicenseResponseVerifier`,
    /// so an unverified, forged or replayed API response can never reach here.
    @discardableResult
    func clearForAuthoritativeTransition(evidence: AuthoritativeEvidence) -> Bool {
        _ = evidence
        return clearLatch()
    }

    /// Clears the latch for an explicit rights-*reducing* transition, i.e. user
    /// deactivation. It only removes rights, so it needs no server evidence.
    @discardableResult
    func clearForRightsReducingTransition() -> Bool {
        clearLatch()
    }

    private func clearLatch() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard store.clearFailClosedState() else { return false }
        state = nil
        return true
    }
}

/// Pure scheduling rule for the periodic license validation timer.
enum LicenseValidationSchedule {
    /// A grace admission expires at `deadline`, so validation must re-run then
    /// and not up to a whole interval later. Always at least one second so a
    /// past deadline cannot produce a zero or negative timer.
    static func nextInterval(
        now: Date,
        deadline: Date?,
        maxInterval: TimeInterval
    ) -> TimeInterval {
        guard let deadline else { return maxInterval }
        return max(1, min(maxInterval, deadline.timeIntervalSince(now)))
    }
}

/// Classifies license API responses so transient server conditions are retried
/// instead of being persisted as terminal rejections.
enum LicenseHTTPClassification {
    static func isTransient(_ statusCode: Int) -> Bool {
        if statusCode == 408 || statusCode == 429 {
            return true
        }
        return (500...599).contains(statusCode)
    }
}

/// What a stored `validate-key` answer proves once its signature verified:
/// when Keygen last confirmed this machine's license and when that license
/// ends.
struct LicenseOfflineProof: Equatable, Sendable {
    let validatedAt: Date
    let expiresAt: Date?
}

/// Pure admission rules for license state.
///
/// The effective deadline is always the earliest of the offline validation
/// grace deadline and the license expiration, so grace can never extend a
/// license past its own expiry.
enum LicenseFailClosedPolicy {
    static let gracePeriod: TimeInterval = 72 * 60 * 60

    /// Statuses that may run while the license is otherwise admissible.
    static func isRunnableStatus(_ status: LicenseStatus) -> Bool {
        switch status {
        case .trial, .valid:
            return true
        case .trialExpired, .expired, .invalid, .unknown:
            return false
        }
    }

    /// Latest instant a state may still admit service without fresh validation.
    ///
    /// Returns nil when the state can never admit service offline: no signed
    /// validation proves it, its status is not runnable, or the machine still
    /// needs reactivation. A machine awaiting reactivation has no confirmed
    /// seat, so offline grace must never cover it.
    ///
    /// The validation time and the expiry come from `proof`, never from
    /// `state`. `license.json` is user-writable, so what it says about them
    /// would let an edited file run offline forever.
    static func effectiveDeadline(
        for state: LicenseState,
        proof: LicenseOfflineProof?
    ) -> Date? {
        guard isRunnableStatus(state.status) else { return nil }
        guard state.machineReactivationPending != true else { return nil }
        guard let proof else { return nil }

        let graceDeadline = proof.validatedAt.addingTimeInterval(gracePeriod)

        guard let expiresAt = proof.expiresAt else { return graceDeadline }
        return min(graceDeadline, expiresAt)
    }

    static func isWithinGracePeriod(
        _ state: LicenseState,
        proof: LicenseOfflineProof?,
        now: Date = Date()
    ) -> Bool {
        guard let deadline = effectiveDeadline(for: state, proof: proof) else { return false }
        return now < deadline
    }

    static func graceHoursRemaining(
        _ state: LicenseState,
        proof: LicenseOfflineProof?,
        now: Date = Date()
    ) -> Int {
        guard let deadline = effectiveDeadline(for: state, proof: proof) else { return 0 }
        return max(0, Int(deadline.timeIntervalSince(now) / 3600))
    }

    /// Whether the persisted state alone admits service.
    static func allowsService(_ state: LicenseState, now: Date = Date()) -> Bool {
        guard state.machineReactivationPending != true else { return false }
        switch state.status {
        case .trial, .valid:
            guard let expiresAt = state.expiresAt else { return true }
            return now < expiresAt

        case .trialExpired, .expired, .invalid, .unknown:
            return false
        }
    }
}
