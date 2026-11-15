// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS
@testable import Shared

/// A brand-new install must always reach the Enable action: the Agent that
/// bootstraps `state.json` and registers the trial is installed by Enable or by
/// the first-run trial step.
/// Every policy on that path is exercised here against a support directory that
/// does not exist yet, which is what a pristine Mac looks like.
@MainActor
final class FreshInstallOnboardingTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("fresh-install-tests-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
        try super.tearDownWithError()
    }

    func testFreshInstallReachesTheEnableActionWithoutALicenseVerdict() {
        let supportDirectory = directory.appendingPathComponent("MacDNS")
        let stateFile = supportDirectory.appendingPathComponent("state.json")
        let licenseFile = supportDirectory.appendingPathComponent("license.json")

        for error in [XPCError.agentNotResponding, .connectionInterrupted] {
            XCTAssertEqual(
                PersistedStateLoadPolicy.decision(
                    for: error,
                    canUseStateFileFallback:
                        AgentStateFileFallbackPolicy.canUseFallback(for: .notRegistered)
                ),
                .useStateFileFallback
            )
        }

        XCTAssertTrue(
            AgentSetupRequirementPolicy.requiresAgentSetup(
                stateFile: fileOutcome(StateFileLock.load(stateFile: stateFile)),
                supportDirectoryExists: FileManager.default.fileExists(
                    atPath: supportDirectory.path
                )
            )
        )

        let availability = PersistedStateAvailability.agentSetupRequired
        XCTAssertTrue(availability.showsProtectionToggle)
        XCTAssertTrue(availability.allowsUserEnable)

        let license = LicenseInfoFileFallback(path: licenseFile).load()
        XCTAssertFalse(LicenseEnableGatePolicy.blocksEnable(license.info, agentInstalled: false))
    }

    /// After "Quit and Remove Services" the configuration still exists but no Agent
    /// runs, so an ended trial read from `license.json` must not stop Enable from
    /// reinstalling the Agent that activation needs.
    func testEndedTrialWithoutARunningAgentStillReachesEnable() throws {
        let supportDirectory = directory.appendingPathComponent("MacDNS")
        try FileManager.default.createDirectory(
            at: supportDirectory,
            withIntermediateDirectories: true
        )
        let licenseFile = supportDirectory.appendingPathComponent("license.json")
        try JSONCoding.encoder.encode(
            LicenseState(licenseId: "trial-1", status: .trialExpired)
        ).write(to: licenseFile)

        let license = LicenseInfoFileFallback(path: licenseFile).load()

        XCTAssertEqual(license.info?.status, .trialExpired)
        XCTAssertEqual(license.info?.isServiceAllowed, false)
        XCTAssertFalse(LicenseEnableGatePolicy.blocksEnable(license.info, agentInstalled: false))
    }

    private func fileOutcome(_ result: StateFileLoadResult) -> PersistedStateFileLoadOutcome {
        switch result {
        case .missing:
            return .missing
        case .valid(let config):
            return .valid(config)
        case .invalid:
            return .invalidConfiguration
        case .ioFailure:
            return .ioFailure
        }
    }
}
