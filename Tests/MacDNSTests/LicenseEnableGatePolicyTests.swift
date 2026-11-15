// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS
@testable import Shared

final class LicenseEnableGatePolicyTests: XCTestCase {
    func testMissingLicenseInfoLetsTheAgentDecide() {
        XCTAssertFalse(LicenseEnableGatePolicy.blocksEnable(nil, agentInstalled: true))
    }

    func testUnknownLicenseLetsTheAgentRegisterATrial() {
        let info = licenseInfo(status: .unknown, isServiceAllowed: false)

        XCTAssertFalse(LicenseEnableGatePolicy.blocksEnable(info, agentInstalled: true))
    }

    func testRunnableStatusDeniedByTheAgentStillLetsTheAgentRevalidate() {
        for status in [LicenseStatus.trial, .valid] {
            let info = licenseInfo(status: status, isServiceAllowed: false)

            XCTAssertFalse(LicenseEnableGatePolicy.blocksEnable(info, agentInstalled: true), "\(status)")
        }
    }

    func testDefinitiveLicenseVerdictBlocksEnable() {
        for status in [LicenseStatus.trialExpired, .expired, .invalid] {
            let info = licenseInfo(status: status, isServiceAllowed: false)

            XCTAssertTrue(LicenseEnableGatePolicy.blocksEnable(info, agentInstalled: true), "\(status)")
        }
    }

    /// Activate needs a running Agent and only Enable installs it. Refusing
    /// Enable on a verdict read from `license.json` while no Agent runs, as after
    /// "Quit and Remove Services", would leave no way to enter a purchased key.
    func testDefinitiveVerdictWithoutARunningAgentLetsEnableInstallIt() {
        for status in [LicenseStatus.trialExpired, .expired, .invalid] {
            let info = licenseInfo(status: status, isServiceAllowed: false)

            XCTAssertFalse(
                LicenseEnableGatePolicy.blocksEnable(info, agentInstalled: false),
                "\(status)"
            )
        }
    }

    func testAllowedLicenseNeverBlocksEnable() {
        let info = licenseInfo(status: .trial, isServiceAllowed: true)

        XCTAssertFalse(LicenseEnableGatePolicy.blocksEnable(info, agentInstalled: true))
    }

    private func licenseInfo(
        status: LicenseStatus,
        isServiceAllowed: Bool
    ) -> LicenseInfo {
        LicenseInfo(
            from: LicenseState(status: status),
            isServiceAllowed: isServiceAllowed
        )
    }
}
