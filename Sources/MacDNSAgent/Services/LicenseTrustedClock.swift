// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Why the local time cannot be trusted for a licensing decision.
enum LicenseClockDistrust: String, Equatable, Sendable {
    /// The wall clock is behind the highest server time already seen.
    case rollbackDetected
    /// A high-water mark exists on disk but could not be read, so no wall clock
    /// can be compared against it.
    case markUnreadable
}

/// Trusted time source for licensing decisions.
///
/// Authoritative verdicts use the signed server time carried by
/// `AuthoritativeEvidence`. Everything that measures *elapsed* time, such as
/// offline grace and admission deadlines, reads this clock instead of `Date()`.
///
/// - Within a boot, time is measured monotonically from the last verified server
///   time using the system uptime, so moving the wall clock has no effect.
/// - Across boots only a high-water mark of verified server time is persisted. A
///   wall clock behind that mark is a rollback and blocks instead of granting
///   time. It never extends grace and never persists a terminal expiry.
final class LicenseTrustedClock: @unchecked Sendable {
    enum Reading: Equatable {
        case trusted(Date)
        case untrusted(LicenseClockDistrust)

        var date: Date? {
            switch self {
            case .trusted(let date): return date
            case .untrusted: return nil
            }
        }
    }

    private struct Anchor {
        let serverTime: Date
        let uptime: TimeInterval
    }

    private let lock = NSLock()
    private let store: LicenseStateFileStore
    private let wallClock: @Sendable () -> Date
    private let uptime: @Sendable () -> TimeInterval
    private let tolerance: TimeInterval

    private var anchor: Anchor?
    private var highWaterMark: Date?
    private var distrust: LicenseClockDistrust?

    init(
        store: LicenseStateFileStore,
        wallClock: @escaping @Sendable () -> Date = { Date() },
        uptime: @escaping @Sendable () -> TimeInterval = {
            ProcessInfo.processInfo.systemUptime
        },
        tolerance: TimeInterval = 5 * 60
    ) {
        self.store = store
        self.wallClock = wallClock
        self.uptime = uptime
        self.tolerance = tolerance
    }

    /// Loads the persisted high-water mark. Safe to call more than once.
    ///
    /// A mark that exists but cannot be read is a tamper or I/O signal, not a
    /// fresh install. The clock stays untrusted until fresh signed server time
    /// anchors it again.
    ///
    /// A mark that is absent while a license is persisted is either an install
    /// that predates the sidecar or a deleted sidecar, and the two look the same
    /// on disk. Blocking would deny service to every existing offline install on
    /// upgrade, so the mark is rebuilt from the verified server time that license
    /// already carries. Rollback detection survives, and erasing the evidence
    /// takes editing the license state itself.
    func restore() {
        switch store.loadTrustedTimeMark() {
        case .missing:
            return
        case .loaded(let mark):
            lock.lock()
            defer { lock.unlock() }
            if let current = highWaterMark, current >= mark.serverTime { return }
            highWaterMark = mark.serverTime
        case .missingWithPersistedLicense(let lastValidatedAt):
            AgentLogger.shared.warning(
                "Trusted license time high-water mark is missing for a persisted license"
            )
            guard let lastValidatedAt else { return }
            lock.lock()
            defer { lock.unlock() }
            if let current = highWaterMark, current >= lastValidatedAt { return }
            highWaterMark = lastValidatedAt
        case .invalid(let reason), .ioFailure(let reason):
            AgentLogger.shared.error(
                "Trusted license time high-water mark is unreadable: \(reason)"
            )
            lock.lock()
            defer { lock.unlock() }
            distrust = .markUnreadable
        case .lockFailure(let reason):
            // Nothing is known about the mark. The whole license directory is
            // unusable, which `LicenseStateFileStore.load()` already latches
            // fail-closed, so this must not additionally distrust the clock.
            AgentLogger.shared.error(
                "Failed to read trusted license time: \(reason)"
            )
        }
    }

    /// Records signed server time from a verified response and persists the
    /// high-water mark. Only `AuthoritativeEvidence` can supply that time.
    ///
    /// Returns false when the mark could not be persisted. The high-water mark is
    /// part of the authoritative transition, so the caller must treat that as a
    /// failed transition and keep the fail-closed latch engaged.
    func record(_ evidence: AuthoritativeEvidence) -> Bool {
        let shouldPersist: Bool = {
            lock.lock()
            defer { lock.unlock() }
            advanceAnchorLocked(to: evidence.serverTime)
            guard let current = highWaterMark, current >= evidence.serverTime else {
                return true
            }
            return false
        }()
        guard shouldPersist else { return true }
        guard
            store.saveTrustedTimeMark(
                LicenseTrustedTimeMark(serverTime: evidence.serverTime)
            )
        else {
            return false
        }
        lock.lock()
        defer { lock.unlock() }
        if let current = highWaterMark, current >= evidence.serverTime { return true }
        highWaterMark = evidence.serverTime
        return true
    }

    /// Anchors this boot on server time from a verified, nonce-bound response.
    ///
    /// The nonce proves the response answers a request made now, so its server
    /// time is current even when the wall clock is not. Nothing is persisted.
    /// The high-water mark only moves through `record`, as part of an
    /// authoritative transition.
    func observe(_ evidence: AuthoritativeEvidence) {
        lock.lock()
        defer { lock.unlock() }
        advanceAnchorLocked(to: evidence.serverTime)
    }

    /// Raises the high-water mark, in memory only, to the signed time of a
    /// stored answer. That instant has passed, so a wall clock behind it was
    /// rolled back. It is not the current time, so it never anchors this boot.
    func acknowledge(stored evidence: AuthoritativeEvidence) {
        lock.lock()
        defer { lock.unlock() }
        if let current = highWaterMark, current >= evidence.serverTime { return }
        highWaterMark = evidence.serverTime
    }

    /// Re-anchors only on server time that is ahead of what this clock already
    /// reports.
    ///
    /// Signature verification proves a response was issued by the account, not
    /// that it is the *latest* one. A captured response replayed inside the
    /// freshness window would otherwise reset the anchor to its older instant
    /// and make `now()` restart from there, freezing grace and expiry for as
    /// long as the replay continues.
    private func advanceAnchorLocked(to serverTime: Date) {
        if let anchor, serverTime <= projectedNowLocked(anchor) { return }
        anchor = Anchor(serverTime: serverTime, uptime: uptime())
    }

    private func projectedNowLocked(_ anchor: Anchor) -> Date {
        anchor.serverTime.addingTimeInterval(max(0, uptime() - anchor.uptime))
    }

    func now() -> Reading {
        lock.lock()
        defer { lock.unlock() }

        if let anchor { return .trusted(projectedNowLocked(anchor)) }

        if let distrust { return .untrusted(distrust) }

        let wall = wallClock()
        guard let mark = highWaterMark else { return .trusted(wall) }
        guard wall.addingTimeInterval(tolerance) >= mark else {
            return .untrusted(.rollbackDetected)
        }
        return .trusted(wall)
    }

    var persistedHighWaterMark: Date? {
        lock.lock()
        defer { lock.unlock() }
        return highWaterMark
    }
}
