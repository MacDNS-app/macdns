// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS
@testable import Shared

final class FirstRunTrialStepTests: XCTestCase {
    private final class Calls: @unchecked Sendable {
        private let lock = NSLock()
        private var counts: [String: Int] = [:]
        private var sequence: [String] = []

        func record(_ name: String) {
            lock.lock()
            defer { lock.unlock() }
            counts[name, default: 0] += 1
            sequence.append(name)
        }

        var order: [String] {
            lock.lock()
            defer { lock.unlock() }
            return sequence
        }

        func count(_ name: String) -> Int {
            lock.lock()
            defer { lock.unlock() }
            return counts[name, default: 0]
        }
    }

    private func info(_ status: LicenseStatus, allowed: Bool, expiresAt: Date? = nil) -> LicenseInfo {
        LicenseInfo(
            from: LicenseState(status: status, expiresAt: expiresAt), isServiceAllowed: allowed, blockReason: nil)
    }

    private func makeStep(
        calls: Calls,
        supportedLocation: Bool = true,
        agentInstalled: Bool = true,
        installError: Error? = nil,
        license: LicenseInfo?,
        trial: LicenseInfo? = nil
    ) -> FirstRunTrialStep {
        FirstRunTrialStep(
            isSupportedLocation: supportedLocation,
            agentInstalled: agentInstalled,
            installAgent: {
                calls.record("install")
                if let installError { throw installError }
            },
            licenseInfo: {
                calls.record("license")
                return license
            },
            requestTrial: {
                calls.record("trial")
                return trial
            }
        )
    }

    func testOutsideApplicationsDoesNothing() async {
        let calls = Calls()
        let step = makeStep(calls: calls, supportedLocation: false, agentInstalled: false, license: nil)

        let outcome = await step.run()

        XCTAssertEqual(outcome, .unsupportedLocation)
        XCTAssertFalse(outcome.continuesToEnable)
        XCTAssertEqual(calls.count("install"), 0)
        XCTAssertEqual(calls.count("license"), 0)
        XCTAssertEqual(calls.count("trial"), 0)
    }

    func testInstallsTheMissingAgentThenRequestsTheTrial() async {
        let calls = Calls()
        let step = makeStep(
            calls: calls, agentInstalled: false,
            license: info(.unknown, allowed: false), trial: info(.trial, allowed: true))

        let outcome = await step.run()

        XCTAssertEqual(outcome, .licensed(blocksEnable: false))
        XCTAssertEqual(calls.order, ["install", "license", "trial"])
    }

    func testInstalledAgentSkipsTheInstall() async {
        let calls = Calls()
        let step = makeStep(calls: calls, agentInstalled: true, license: info(.trial, allowed: true))

        _ = await step.run()

        XCTAssertEqual(calls.count("install"), 0)
    }

    func testExistingLicenseIsNotRevalidated() async {
        let calls = Calls()
        let step = makeStep(calls: calls, license: info(.trial, allowed: true))

        let outcome = await step.run()

        XCTAssertEqual(outcome, .licensed(blocksEnable: false))
        XCTAssertEqual(calls.count("trial"), 0)
    }

    func testEndedTrialBlocksEnable() async {
        let calls = Calls()
        let step = makeStep(calls: calls, license: info(.trialExpired, allowed: false))

        let outcome = await step.run()

        XCTAssertEqual(outcome, .licensed(blocksEnable: true))
        XCTAssertFalse(outcome.continuesToEnable)
        XCTAssertEqual(calls.count("trial"), 0)
    }

    /// Periodic validation stops while protection is off, so a trial that ran
    /// out meanwhile is still stored as `.trial`. Its expiry is enough to show
    /// Trial ended without calling Keygen.
    func testTrialPastItsExpiryBlocksEnableWithoutCallingHome() async {
        let calls = Calls()
        let elapsed = info(.trial, allowed: false, expiresAt: Date().addingTimeInterval(-60))
        let step = makeStep(calls: calls, license: elapsed)

        let outcome = await step.run()

        XCTAssertEqual(outcome, .licensed(blocksEnable: true))
        XCTAssertFalse(outcome.continuesToEnable)
        XCTAssertEqual(calls.count("trial"), 0)
    }

    func testTrialBlockedForAnotherReasonBeforeItsExpiryStillContinues() async {
        let calls = Calls()
        let clockBehind = info(.trial, allowed: false, expiresAt: Date().addingTimeInterval(86_400))
        let step = makeStep(calls: calls, license: clockBehind)

        let outcome = await step.run()

        XCTAssertEqual(outcome, .licensed(blocksEnable: false))
        XCTAssertTrue(outcome.continuesToEnable)
    }

    func testAgentApprovalRequiredStillContinuesToEnable() async {
        let calls = Calls()
        let step = makeStep(
            calls: calls, agentInstalled: false, installError: AgentError.requiresApproval,
            license: info(.unknown, allowed: false), trial: info(.trial, allowed: true))

        let outcome = await step.run()

        XCTAssertEqual(outcome, .agentUnavailable)
        XCTAssertTrue(outcome.continuesToEnable)
        XCTAssertEqual(calls.count("license"), 0)
        XCTAssertEqual(calls.count("trial"), 0)
    }

    func testOfflineTrialRequestStillContinuesToEnable() async {
        let calls = Calls()
        let step = makeStep(calls: calls, license: info(.unknown, allowed: false), trial: nil)

        let outcome = await step.run()

        XCTAssertEqual(outcome, .licenseUnknown)
        XCTAssertTrue(outcome.continuesToEnable)
        XCTAssertEqual(calls.count("trial"), 1)
    }
}
