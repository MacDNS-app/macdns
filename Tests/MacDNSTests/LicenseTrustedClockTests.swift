// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNSAgent

final class LicenseTrustedClockTests: XCTestCase {
    private final class MutableClock: @unchecked Sendable {
        private let lock = NSLock()
        private var wall: Date
        private var monotonic: TimeInterval

        init(wall: Date, monotonic: TimeInterval) {
            self.wall = wall
            self.monotonic = monotonic
        }

        func read() -> Date {
            lock.lock()
            defer { lock.unlock() }
            return wall
        }

        func uptime() -> TimeInterval {
            lock.lock()
            defer { lock.unlock() }
            return monotonic
        }

        func advance(wall wallDelta: TimeInterval, monotonic monotonicDelta: TimeInterval) {
            lock.lock()
            wall = wall.addingTimeInterval(wallDelta)
            monotonic += monotonicDelta
            lock.unlock()
        }

        func setWall(_ date: Date) {
            lock.lock()
            wall = date
            lock.unlock()
        }
    }

    private struct Context {
        let directory: URL
        let store: LicenseStateFileStore
        let clock: MutableClock
        let trusted: LicenseTrustedClock
    }

    private func makeContext(
        wall: Date = Date(timeIntervalSince1970: 1_700_000_000),
        monotonic: TimeInterval = 1_000
    ) throws -> Context {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let store = LicenseStateFileStore(
            path: directory.appendingPathComponent("license.json")
        )
        let clock = MutableClock(wall: wall, monotonic: monotonic)
        return Context(
            directory: directory,
            store: store,
            clock: clock,
            trusted: LicenseTrustedClock(
                store: store,
                wallClock: { clock.read() },
                uptime: { clock.uptime() }
            )
        )
    }

    private func persistLicense(
        lastValidatedAt: Date?,
        in context: Context
    ) throws {
        let state = LicenseState(
            licenseKey: "paid-key",
            licenseId: "license-1",
            status: .valid,
            lastValidatedAt: lastValidatedAt
        )
        try JSONCoding.encoder.encode(state).write(to: context.store.path)
    }

    private func loadedMark(_ store: LicenseStateFileStore) -> LicenseTrustedTimeMark? {
        guard case .loaded(let mark) = store.loadTrustedTimeMark() else { return nil }
        return mark
    }

    func testWithoutAnyEvidenceTheWallClockIsUsed() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }

        XCTAssertEqual(context.trusted.now(), .trusted(context.clock.read()))
    }

    /// Within a boot, elapsed time is measured monotonically from the last
    /// verified server time, so moving the wall clock has no effect at all.
    func testElapsedTimeIsMeasuredMonotonicallyFromVerifiedServerTime() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let serverTime = Date(timeIntervalSince1970: 1_700_000_500)
        XCTAssertTrue(
            context.trusted.record(
                try LicenseTestResponseSigner.makeEvidence(serverTime: serverTime)
            )
        )

        context.clock.advance(wall: -(10 * 24 * 60 * 60), monotonic: 120)

        XCTAssertEqual(
            context.trusted.now(),
            .trusted(serverTime.addingTimeInterval(120))
        )
    }

    func testForwardWallClockJumpCannotManufactureElapsedTime() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let serverTime = Date(timeIntervalSince1970: 1_700_000_500)
        XCTAssertTrue(
            context.trusted.record(
                try LicenseTestResponseSigner.makeEvidence(serverTime: serverTime)
            )
        )

        context.clock.advance(wall: 90 * 24 * 60 * 60, monotonic: 5)

        XCTAssertEqual(
            context.trusted.now(),
            .trusted(serverTime.addingTimeInterval(5))
        )
    }

    /// Server time from a nonce-bound response anchors this boot, so the
    /// nonce-less requests that follow are judged against it instead of a wrong
    /// wall clock. Persisting the mark stays the job of `record`.
    func testObservedServerTimeAnchorsTheBootWithoutPersistingAMark() throws {
        let context = try makeContext(wall: Date(timeIntervalSince1970: 1_700_000_600))
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let serverTime = Date(timeIntervalSince1970: 1_700_000_000)

        context.trusted.observe(
            try LicenseTestResponseSigner.makeEvidence(serverTime: serverTime)
        )
        context.clock.advance(wall: 0, monotonic: 30)

        XCTAssertEqual(context.trusted.now(), .trusted(serverTime.addingTimeInterval(30)))
        XCTAssertNil(loadedMark(context.store))
    }

    func testVerifiedServerTimeIsPersistedAsHighWaterMark() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let serverTime = Date(timeIntervalSince1970: 1_700_000_500)

        XCTAssertTrue(
            context.trusted.record(
                try LicenseTestResponseSigner.makeEvidence(serverTime: serverTime)
            )
        )

        XCTAssertEqual(
            try XCTUnwrap(loadedMark(context.store)).serverTime.timeIntervalSince1970,
            serverTime.timeIntervalSince1970,
            accuracy: 1
        )
    }

    func testOlderServerTimeDoesNotLowerTheHighWaterMark() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let newest = Date(timeIntervalSince1970: 1_700_001_000)
        XCTAssertTrue(
            context.trusted.record(
                try LicenseTestResponseSigner.makeEvidence(serverTime: newest)
            )
        )

        XCTAssertTrue(
            context.trusted.record(
                try LicenseTestResponseSigner.makeEvidence(
                    serverTime: Date(timeIntervalSince1970: 1_600_000_000)
                )
            )
        )

        XCTAssertEqual(
            try XCTUnwrap(loadedMark(context.store)).serverTime.timeIntervalSince1970,
            newest.timeIntervalSince1970,
            accuracy: 1
        )
    }

    /// Across boots the persisted mark is the only defence. A wall clock behind it
    /// blocks instead of granting a fresh window.
    func testRollbackAcrossBootsIsUntrusted() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let serverTime = Date(timeIntervalSince1970: 1_700_000_500)
        XCTAssertTrue(
            context.store.saveTrustedTimeMark(
                LicenseTrustedTimeMark(serverTime: serverTime)
            )
        )
        context.clock.setWall(serverTime.addingTimeInterval(-(30 * 24 * 60 * 60)))

        context.trusted.restore()

        XCTAssertEqual(context.trusted.now(), .untrusted(.rollbackDetected))
        XCTAssertNil(context.trusted.now().date)
    }

    /// A mark that exists but cannot be read is a tamper or I/O signal. Collapsing
    /// it into "never recorded" would accept any wall clock, including a
    /// rolled-back one.
    func testUnreadableHighWaterMarkIsUntrusted() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        try FileManager.default.createDirectory(
            at: context.store.trustedTimePath,
            withIntermediateDirectories: true
        )

        context.trusted.restore()

        XCTAssertEqual(context.trusted.now(), .untrusted(.markUnreadable))
        XCTAssertNil(context.trusted.now().date)
    }

    /// The caller has to see the write failure: the high-water mark is part of the
    /// authoritative transition that clears the fail-closed latch.
    func testFailureToPersistTheHighWaterMarkIsReported() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        try FileManager.default.createDirectory(
            at: context.store.trustedTimePath,
            withIntermediateDirectories: true
        )

        XCTAssertFalse(
            context.trusted.record(
                try LicenseTestResponseSigner.makeEvidence(
                    serverTime: Date(timeIntervalSince1970: 1_700_000_500)
                )
            )
        )
    }

    func testSmallClockSkewWithinToleranceStaysTrusted() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let serverTime = Date(timeIntervalSince1970: 1_700_000_500)
        XCTAssertTrue(
            context.store.saveTrustedTimeMark(
                LicenseTrustedTimeMark(serverTime: serverTime)
            )
        )
        let skewed = serverTime.addingTimeInterval(-60)
        context.clock.setWall(skewed)

        context.trusted.restore()

        XCTAssertEqual(context.trusted.now(), .trusted(skewed))
    }

    func testRestoreDoesNotLowerAnAlreadyHigherMark() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let newest = Date(timeIntervalSince1970: 1_700_002_000)
        XCTAssertTrue(
            context.trusted.record(
                try LicenseTestResponseSigner.makeEvidence(serverTime: newest)
            )
        )
        XCTAssertTrue(
            context.store.saveTrustedTimeMark(
                LicenseTrustedTimeMark(
                    serverTime: Date(timeIntervalSince1970: 1_600_000_000)
                )
            )
        )

        context.trusted.restore()

        XCTAssertEqual(
            try XCTUnwrap(context.trusted.persistedHighWaterMark).timeIntervalSince1970,
            newest.timeIntervalSince1970,
            accuracy: 1
        )
    }

    /// A signature proves who issued a response, not that it is the latest one.
    /// A captured response replayed inside the freshness window must not reset
    /// the anchor to its older instant: `now()` would restart from there and
    /// freeze grace and expiry for as long as the replay continues.
    func testReplayedServerTimeDoesNotRewindTheClock() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let captured = Date(timeIntervalSince1970: 1_700_000_500)
        XCTAssertTrue(
            context.trusted.record(
                try LicenseTestResponseSigner.makeEvidence(serverTime: captured)
            )
        )
        context.clock.advance(wall: 600, monotonic: 600)
        let projected = try XCTUnwrap(context.trusted.now().date)

        XCTAssertTrue(
            context.trusted.record(
                try LicenseTestResponseSigner.makeEvidence(serverTime: captured)
            )
        )

        XCTAssertEqual(
            try XCTUnwrap(context.trusted.now().date).timeIntervalSince1970,
            projected.timeIntervalSince1970,
            accuracy: 1
        )
    }

    /// Server time that is newer than the last recorded one but still behind
    /// what this clock already reports is the same replay in a subtler form.
    func testServerTimeBehindTheProjectionDoesNotRewindTheClock() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let first = Date(timeIntervalSince1970: 1_700_000_500)
        XCTAssertTrue(
            context.trusted.record(
                try LicenseTestResponseSigner.makeEvidence(serverTime: first)
            )
        )
        context.clock.advance(wall: 600, monotonic: 600)
        let projected = try XCTUnwrap(context.trusted.now().date)

        XCTAssertTrue(
            context.trusted.record(
                try LicenseTestResponseSigner.makeEvidence(
                    serverTime: first.addingTimeInterval(100)
                )
            )
        )

        XCTAssertEqual(
            try XCTUnwrap(context.trusted.now().date).timeIntervalSince1970,
            projected.timeIntervalSince1970,
            accuracy: 1
        )
    }

    /// The in-memory mark may not advance ahead of the durable one: a retry with
    /// the same evidence would otherwise find its own optimistic value on file
    /// and report success for a mark that was never written.
    func testRetryAfterAFailedPersistStillReportsFailure() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        try FileManager.default.createDirectory(
            at: context.store.trustedTimePath,
            withIntermediateDirectories: true
        )
        let evidence = try LicenseTestResponseSigner.makeEvidence(
            serverTime: Date(timeIntervalSince1970: 1_700_000_500)
        )

        XCTAssertFalse(context.trusted.record(evidence))
        XCTAssertFalse(context.trusted.record(evidence))
        XCTAssertNil(context.trusted.persistedHighWaterMark)
    }

    /// An install that predates the sidecar, or one whose sidecar was deleted to
    /// erase rollback evidence, looks the same on disk. Neither may be blocked,
    /// so the mark is rebuilt from the verified server time the license carries
    /// and a clock behind it is still a rollback.
    func testMissingMarkAdoptsTheVerifiedTimeOfThePersistedLicense() throws {
        let lastValidatedAt = Date(timeIntervalSince1970: 1_700_000_000)
        let context = try makeContext(wall: lastValidatedAt)
        defer { try? FileManager.default.removeItem(at: context.directory) }
        try persistLicense(lastValidatedAt: lastValidatedAt, in: context)

        context.trusted.restore()

        XCTAssertNotNil(context.trusted.now().date)
        context.clock.setWall(lastValidatedAt.addingTimeInterval(-3600))
        XCTAssertEqual(context.trusted.now(), .untrusted(.rollbackDetected))
    }

    /// A license that was persisted before any response was verified carries no
    /// server time at all, so there is no rollback evidence to lose.
    func testMissingMarkForANeverValidatedLicenseStaysTrusted() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        try persistLicense(lastValidatedAt: nil, in: context)

        context.trusted.restore()

        XCTAssertNotNil(context.trusted.now().date)
    }

    /// A genuinely fresh installation has neither file and must still be able to
    /// reach the server for the first time.
    func testMissingMarkOnAFreshInstallStaysTrusted() throws {
        let context = try makeContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }

        context.trusted.restore()

        XCTAssertNotNil(context.trusted.now().date)
    }
}
