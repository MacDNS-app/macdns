// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent
@testable import Shared

final class LicenseFailClosedPolicyTests: XCTestCase {

    // MARK: - Effective Deadline

    private let paid = LicenseState(licenseKey: "key", status: .valid)
    private let trial = LicenseState(licenseId: "trial-1", status: .trial)

    func testTrialWithoutExpiryUsesGraceDeadline() {
        let validated = Date()
        let proof = LicenseOfflineProof(validatedAt: validated, expiresAt: nil)

        XCTAssertEqual(
            LicenseFailClosedPolicy.effectiveDeadline(for: trial, proof: proof),
            validated.addingTimeInterval(LicenseFailClosedPolicy.gracePeriod)
        )
    }

    func testTrialDeadlineIsEarliestOfGraceAndExpiry() {
        let validated = Date()
        let expiry = validated.addingTimeInterval(3600)
        let proof = LicenseOfflineProof(validatedAt: validated, expiresAt: expiry)

        XCTAssertEqual(
            LicenseFailClosedPolicy.effectiveDeadline(for: trial, proof: proof),
            expiry
        )
    }

    func testExpiringPaidLicenseDeadlineIsEarliestOfGraceAndExpiry() {
        let validated = Date()
        let graceEnd = validated.addingTimeInterval(LicenseFailClosedPolicy.gracePeriod)
        let proof = LicenseOfflineProof(
            validatedAt: validated,
            expiresAt: validated.addingTimeInterval(LicenseFailClosedPolicy.gracePeriod * 2)
        )

        XCTAssertEqual(
            LicenseFailClosedPolicy.effectiveDeadline(for: paid, proof: proof),
            graceEnd
        )
    }

    func testPerpetualPaidLicenseUsesGraceDeadline() {
        let validated = Date()
        let proof = LicenseOfflineProof(validatedAt: validated, expiresAt: nil)

        XCTAssertEqual(
            LicenseFailClosedPolicy.effectiveDeadline(for: paid, proof: proof),
            validated.addingTimeInterval(LicenseFailClosedPolicy.gracePeriod)
        )
    }

    /// `license.json` is user-writable, so the validation time and the expiry
    /// it claims never produce a deadline.
    func testStateWithoutAProofHasNoDeadlineWhateverItClaims() {
        let claimed = LicenseState(
            licenseKey: "key",
            status: .valid,
            expiresAt: nil,
            lastValidatedAt: Date()
        )

        XCTAssertNil(LicenseFailClosedPolicy.effectiveDeadline(for: claimed, proof: nil))
        XCTAssertFalse(LicenseFailClosedPolicy.isWithinGracePeriod(claimed, proof: nil))
    }

    func testDeadlineIgnoresTheValidationTimeAndExpiryTheStateClaims() {
        let validated = Date().addingTimeInterval(-3600)
        let expiry = validated.addingTimeInterval(7200)
        let claimed = LicenseState(
            licenseKey: "key",
            status: .valid,
            expiresAt: nil,
            lastValidatedAt: Date()
        )

        XCTAssertEqual(
            LicenseFailClosedPolicy.effectiveDeadline(
                for: claimed,
                proof: LicenseOfflineProof(validatedAt: validated, expiresAt: expiry)
            ),
            expiry
        )
    }

    /// A machine awaiting reactivation has no confirmed seat, so offline grace
    /// must not cover it, or a machine the server already rejected keeps
    /// running for the whole window by staying offline.
    func testPendingReactivationHasNoOfflineDeadline() {
        var state = paid
        state.machineReactivationPending = true
        let proof = LicenseOfflineProof(validatedAt: Date(), expiresAt: nil)

        XCTAssertNil(LicenseFailClosedPolicy.effectiveDeadline(for: state, proof: proof))
        XCTAssertFalse(LicenseFailClosedPolicy.isWithinGracePeriod(state, proof: proof))
        XCTAssertEqual(LicenseFailClosedPolicy.graceHoursRemaining(state, proof: proof), 0)
    }

    // MARK: - Validation Schedule

    func testValidationScheduleUsesFullIntervalWithoutDeadline() {
        XCTAssertEqual(
            LicenseValidationSchedule.nextInterval(
                now: Date(),
                deadline: nil,
                maxInterval: 8 * 60 * 60
            ),
            8 * 60 * 60
        )
    }

    /// A grace admission expires at its deadline, so the timer must fire then and
    /// not up to a whole validation interval later.
    func testValidationScheduleNeverOutlivesTheDeadline() {
        let now = Date()

        XCTAssertEqual(
            LicenseValidationSchedule.nextInterval(
                now: now,
                deadline: now.addingTimeInterval(90),
                maxInterval: 8 * 60 * 60
            ),
            90,
            accuracy: 0.001
        )
    }

    func testValidationScheduleClampsPastDeadlineToOneSecond() {
        let now = Date()

        XCTAssertEqual(
            LicenseValidationSchedule.nextInterval(
                now: now,
                deadline: now.addingTimeInterval(-3600),
                maxInterval: 8 * 60 * 60
            ),
            1
        )
    }

    // MARK: - Grace Admission

    func testGraceAllowedBeforeDeadline() {
        let proof = LicenseOfflineProof(validatedAt: Date(), expiresAt: nil)

        XCTAssertTrue(LicenseFailClosedPolicy.isWithinGracePeriod(paid, proof: proof))
    }

    func testGraceRejectedAfterLicenseExpiry() {
        let proof = LicenseOfflineProof(
            validatedAt: Date().addingTimeInterval(-60),
            expiresAt: Date().addingTimeInterval(-1)
        )

        XCTAssertFalse(LicenseFailClosedPolicy.isWithinGracePeriod(paid, proof: proof))
    }

    func testGraceAllowedForTrialWithoutExpiry() {
        let proof = LicenseOfflineProof(validatedAt: Date(), expiresAt: nil)

        XCTAssertTrue(LicenseFailClosedPolicy.isWithinGracePeriod(trial, proof: proof))
    }

    func testGraceRejectedForNonRunnableStatus() {
        let state = LicenseState(licenseKey: "key", status: .expired)
        let proof = LicenseOfflineProof(validatedAt: Date(), expiresAt: nil)

        XCTAssertFalse(LicenseFailClosedPolicy.isWithinGracePeriod(state, proof: proof))
    }

    // MARK: - Service Admission

    func testTrialWithoutExpiryIsAllowed() {
        let state = LicenseState(
            licenseId: "trial-1",
            status: .trial,
            expiresAt: nil
        )
        let allowed = LicenseFailClosedPolicy.allowsService(state)
        let info = LicenseInfo(from: state, isServiceAllowed: allowed)

        XCTAssertTrue(allowed)
        XCTAssertTrue(state.isActive)
        XCTAssertFalse(state.isTrialExpired)
        XCTAssertEqual(info.status, .trial)
        XCTAssertNil(info.expiresAt)
        XCTAssertTrue(info.isServiceAllowed)
        XCTAssertEqual(info.statusDescription, "Trial active")
    }

    func testTrialWithFutureExpiryIsAllowed() {
        let state = LicenseState(
            licenseId: "trial-1",
            status: .trial,
            expiresAt: Date().addingTimeInterval(3600)
        )

        XCTAssertTrue(LicenseFailClosedPolicy.allowsService(state))
        XCTAssertTrue(state.isActive)
    }

    func testPerpetualPaidLicenseIsAllowed() {
        let state = LicenseState(licenseKey: "key", status: .valid, expiresAt: nil)

        XCTAssertTrue(LicenseFailClosedPolicy.allowsService(state))
        XCTAssertTrue(state.isActive)
    }

    func testExpiredPaidLicenseIsNotAllowed() {
        let state = LicenseState(
            licenseKey: "key",
            status: .valid,
            expiresAt: Date().addingTimeInterval(-1)
        )

        XCTAssertFalse(LicenseFailClosedPolicy.allowsService(state))
        XCTAssertFalse(state.isActive)
    }

    // MARK: - Latch

    func testLatchEngagementPersistsAndRestoresAfterRestart() throws {
        let context = try makeLatchContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let firstLatch = LicenseFailClosedLatch(store: context.store)

        XCTAssertTrue(firstLatch.engage(.stateLoadFailed))
        XCTAssertEqual(firstLatch.reason, .stateLoadFailed)

        guard case .loaded(let persisted) = context.store.loadFailClosedState() else {
            return XCTFail("Expected persisted fail-closed state")
        }
        let restartedLatch = LicenseFailClosedLatch(store: context.store)
        restartedLatch.restore(persisted)

        XCTAssertEqual(restartedLatch.reason, .stateLoadFailed)
    }

    func testLatchClearsOnlyAfterDurableClear() throws {
        let context = try makeLatchContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let latch = LicenseFailClosedLatch(store: context.store)
        XCTAssertTrue(latch.engage(.stateLoadFailed))

        XCTAssertTrue(
            latch.clearForAuthoritativeTransition(
                evidence: try LicenseTestResponseSigner.makeEvidence()
            )
        )

        XCTAssertNil(latch.reason)
        guard case .missing = context.store.loadFailClosedState() else {
            return XCTFail("Expected fail-closed marker to be removed")
        }
    }

    /// Explicit user deactivation only removes rights, so it must not need server
    /// evidence. Otherwise an unreachable API would strand the user's own seat.
    func testLatchClearsForRightsReducingTransition() throws {
        let context = try makeLatchContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let latch = LicenseFailClosedLatch(store: context.store)
        XCTAssertTrue(latch.engage(.networkGraceExpired))

        XCTAssertTrue(latch.clearForRightsReducingTransition())

        XCTAssertNil(latch.reason)
    }

    func testLatchKeepsFirstReasonWhenEngagedAgain() throws {
        let context = try makeLatchContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let latch = LicenseFailClosedLatch(store: context.store)
        XCTAssertTrue(latch.engage(.stateLoadFailed))
        XCTAssertTrue(latch.engage(.networkGraceExpired))

        XCTAssertEqual(latch.reason, .stateLoadFailed)
    }

    func testLatchRemainsEngagedWhenPersistenceFails() {
        let missingDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let store = LicenseStateFileStore(
            path: missingDirectory.appendingPathComponent("license.json")
        )
        let latch = LicenseFailClosedLatch(store: store)

        XCTAssertFalse(latch.engage(.statePersistenceFailed))
        XCTAssertEqual(latch.reason, .statePersistenceFailed)
    }

    func testFailedClearKeepsLatchEngaged() throws {
        let context = try makeLatchContext()
        defer { try? FileManager.default.removeItem(at: context.directory) }
        let latch = LicenseFailClosedLatch(store: context.store)
        latch.restore(
            LicenseFailClosedState(
                reason: .statePersistenceFailed,
                engagedAt: Date()
            )
        )
        try FileManager.default.createDirectory(
            at: context.store.failClosedPath,
            withIntermediateDirectories: true
        )

        XCTAssertFalse(
            latch.clearForAuthoritativeTransition(
                evidence: try LicenseTestResponseSigner.makeEvidence()
            )
        )
        XCTAssertEqual(latch.reason, .statePersistenceFailed)
    }

    private func makeLatchContext() throws -> (
        directory: URL,
        store: LicenseStateFileStore
    ) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        return (
            directory,
            LicenseStateFileStore(
                path: directory.appendingPathComponent("license.json")
            )
        )
    }
}
