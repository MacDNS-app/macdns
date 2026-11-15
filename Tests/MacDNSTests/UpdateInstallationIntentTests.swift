// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class UpdateInstallationIntentTests: XCTestCase {
    func testManualReadyUpdateRequiresAgentShutdownWhenUserQuitsWithoutRelaunchButton() {
        var intent = UpdateInstallationIntent()
        intent.receive(.extractionStarted)
        XCTAssertTrue(intent.requiresPreparation)
        intent.receive(.readyToInstall)
        intent.receive(.dismissed)
        intent.receive(.discoveryFinished)

        XCTAssertTrue(intent.requiresPreparation, "Dismissal leaves Sparkle's installer waiting for App termination")
    }

    func testSkippingStagedUpdatePreservesAgentOnTheNextOrdinaryQuit() {
        var intent = UpdateInstallationIntent()
        intent.receive(.readyToInstall)
        intent.receive(.skipped)
        intent.receive(.discoveryFinished)

        XCTAssertFalse(intent.requiresPreparation)
    }

    func testFailedExtractionDoesNotTurnOrdinaryQuitIntoServiceShutdown() {
        var intent = UpdateInstallationIntent()
        intent.receive(.extractionStarted)
        intent.receive(.installationFailed)

        XCTAssertFalse(intent.requiresPreparation)
    }

    func testDiscoveryWithoutDownloadedUpdateKeepsAgentRunningOnQuit() {
        var intent = UpdateInstallationIntent()
        intent.receive(.discoveryFinished)
        XCTAssertFalse(intent.requiresPreparation)
    }

    func testAuthorizationDeferredBeforeInstallerLaunchPreservesAgentOnQuit() {
        var intent = UpdateInstallationIntent()
        intent.receive(.extractionStarted)
        intent.receive(.downloadedUpdateResumed)
        intent.receive(.dismissed)

        XCTAssertFalse(intent.requiresPreparation, "A downloaded archive alone cannot install on quit")
    }
}
