// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class FreshInstallSetupPolicyTests: XCTestCase {
    private func outcome(
        protectionActive: Bool = false,
        restartRequired: Bool = false,
        approvalRequired: Bool = false,
        enableCompleted: Bool = false
    ) -> FreshInstallSetupOutcome {
        FreshInstallSetupPolicy(
            protectionActive: protectionActive,
            restartRequired: restartRequired,
            approvalRequired: approvalRequired,
            enableCompleted: enableCompleted
        ).outcome
    }

    func testEachSingleInputSelectsItsOutcome() {
        XCTAssertEqual(outcome(protectionActive: true), .done)
        XCTAssertEqual(outcome(restartRequired: true), .restartRequired)
        XCTAssertEqual(outcome(approvalRequired: true), .waitingForApproval)
        XCTAssertEqual(outcome(enableCompleted: true), .done)
    }

    func testAnAttemptThatEndsWithNoSignalFailed() {
        XCTAssertEqual(outcome(), .failed)
    }

    func testActiveProtectionNeverAlerts() {
        XCTAssertEqual(
            outcome(
                protectionActive: true,
                restartRequired: true,
                approvalRequired: true,
                enableCompleted: true
            ),
            .done
        )
    }

    func testRestartRequiredWinsOverPendingApproval() {
        XCTAssertEqual(
            outcome(restartRequired: true, approvalRequired: true),
            .restartRequired
        )
    }

    func testPendingApprovalWaitsInsteadOfFailing() {
        XCTAssertEqual(
            outcome(approvalRequired: true, enableCompleted: true),
            .waitingForApproval
        )
    }

    func testFinishedEnableWithoutInterceptionIsDone() {
        XCTAssertEqual(outcome(enableCompleted: true), .done)
    }

    /// A failed resolver start clears the desire to run DNS itself. The attempt
    /// must still report, or the failure alert never shows.
    func testSetupAttemptNoLaterLifecycleReplacedReports() {
        XCTAssertTrue(reports(setupGeneration: 7, attemptGeneration: 7, currentGeneration: 7))
    }

    func testAttemptReplacedByALaterLifecycleDoesNotReport() {
        XCTAssertFalse(reports(setupGeneration: 7, attemptGeneration: 7, currentGeneration: 8))
        XCTAssertFalse(reports(setupGeneration: 7, attemptGeneration: 7, currentGeneration: 7, isStopping: true))
        XCTAssertFalse(reports(setupGeneration: 7, attemptGeneration: 7, currentGeneration: 7, updateSuspended: true))
    }

    func testAttemptOutsideTheSetupDoesNotReport() {
        XCTAssertFalse(reports(setupGeneration: nil, attemptGeneration: 7, currentGeneration: 7))
        XCTAssertFalse(reports(setupGeneration: 6, attemptGeneration: 7, currentGeneration: 7))
    }

    func testTurnOnStartsTheSetup() {
        XCTAssertTrue(continues(startedAsFreshInstall: true, setupGeneration: nil, currentGeneration: 3))
    }

    /// The Enable that resumes after an approval continues the setup that
    /// waited for it.
    func testResumeAfterApprovalContinuesTheSetup() {
        XCTAssertTrue(continues(startedAsFreshInstall: false, setupGeneration: 3, currentGeneration: 3))
    }

    func testOrdinaryEnableWithoutASetupStartsNone() {
        XCTAssertFalse(continues(startedAsFreshInstall: false, setupGeneration: nil, currentGeneration: 3))
    }

    /// Fresh install waits for an approval, the user runs Uninstall, and a
    /// later ordinary Enable fails to start the resolver. It must not show the
    /// first-run alert.
    func testApprovalWaitCancelledByALaterLifecycleEndsTheSetup() {
        let waitingSetup: UInt64 = 3
        let afterRemoveAll: UInt64 = 4
        XCTAssertFalse(
            continues(startedAsFreshInstall: false, setupGeneration: waitingSetup, currentGeneration: afterRemoveAll))
        XCTAssertFalse(reports(setupGeneration: nil, attemptGeneration: 5, currentGeneration: 5))
    }

    /// A disable, update or Uninstall during the attempt skips its report.
    /// The setup still ends, or the window shows it running forever.
    func testASupersededAttemptEndsItsSetup() {
        XCTAssertNil(FreshInstallSetupPolicy.setupGenerationAfterSupersededAttempt(7, setupGeneration: 7))
    }

    /// A newer Enable may already own the setup when the old attempt ends.
    func testASupersededAttemptLeavesANewerSetupAlone() {
        XCTAssertEqual(FreshInstallSetupPolicy.setupGenerationAfterSupersededAttempt(7, setupGeneration: 9), 9)
        XCTAssertNil(FreshInstallSetupPolicy.setupGenerationAfterSupersededAttempt(7, setupGeneration: nil))
    }

    /// A fresh install has no state for the lifecycle checks to act on.
    func testAgentApprovalResumesAFreshInstallEnable() {
        XCTAssertTrue(resumesAfterAgentApproval(agentSetupRequired: true, setupGeneration: nil, currentGeneration: 3))
    }

    /// A resumed setup with `state.json` loads it from the file fallback, and
    /// the lifecycle checks stop at `isEnabled: false`. The setup that waited
    /// for the approval must still resume.
    func testAgentApprovalResumesASetupThatWaitedWithLoadedState() {
        XCTAssertTrue(resumesAfterAgentApproval(agentSetupRequired: false, setupGeneration: 3, currentGeneration: 3))
    }

    func testAgentApprovalWithoutASetupOrFreshInstallDoesNotResume() {
        XCTAssertFalse(resumesAfterAgentApproval(agentSetupRequired: false, setupGeneration: nil, currentGeneration: 3))
    }

    /// A disable or Uninstall after the approval wait ended the setup.
    func testAgentApprovalAfterALaterLifecycleDoesNotResume() {
        XCTAssertFalse(resumesAfterAgentApproval(agentSetupRequired: false, setupGeneration: 3, currentGeneration: 4))
        XCTAssertFalse(
            resumesAfterAgentApproval(
                agentSetupRequired: true, setupGeneration: 3, currentGeneration: 3, runtimeDNSDesired: false))
        XCTAssertFalse(
            resumesAfterAgentApproval(
                agentSetupRequired: false, setupGeneration: 3, currentGeneration: 3, runtimeDNSDesired: false))
    }

    func testAgentApprovalNeverStartsASecondEnableOrRacesAStop() {
        XCTAssertFalse(
            resumesAfterAgentApproval(
                agentSetupRequired: false, setupGeneration: 3, currentGeneration: 3, isEnablingDNS: true))
        XCTAssertFalse(
            resumesAfterAgentApproval(
                agentSetupRequired: true, setupGeneration: nil, currentGeneration: 3, isEnablingDNS: true))
        XCTAssertFalse(
            resumesAfterAgentApproval(
                agentSetupRequired: false, setupGeneration: 3, currentGeneration: 3, isStoppingDNS: true))
    }

    /// The late approval leaves the registration to the resumed Enable only
    /// while the window is open and that Enable would continue the setup.
    func testLateRegistrationDefersOnlyWhileTheOpenWindowsSetupOwnsTheLifecycle() {
        XCTAssertTrue(defers(windowOpen: true, setupGeneration: 3, currentGeneration: 3))
        XCTAssertFalse(defers(windowOpen: false, setupGeneration: 3, currentGeneration: 3))
        XCTAssertFalse(defers(windowOpen: true, setupGeneration: nil, currentGeneration: 3))
    }

    /// A Disable during the approval wait moves the lifecycle on and keeps
    /// the stale setup generation. The late approval must register as today.
    func testLateRegistrationIsNotDeferredAfterALaterLifecycle() {
        XCTAssertFalse(defers(windowOpen: true, setupGeneration: 3, currentGeneration: 4))
        XCTAssertFalse(continues(startedAsFreshInstall: false, setupGeneration: 3, currentGeneration: 4))
    }

    private func defers(windowOpen: Bool, setupGeneration: UInt64?, currentGeneration: UInt64) -> Bool {
        FreshInstallSetupPolicy.defersLateProviderRegistration(
            windowOpen: windowOpen,
            setupGeneration: setupGeneration,
            currentGeneration: currentGeneration
        )
    }

    private func resumesAfterAgentApproval(
        agentSetupRequired: Bool,
        setupGeneration: UInt64?,
        currentGeneration: UInt64,
        runtimeDNSDesired: Bool = true,
        isEnablingDNS: Bool = false,
        isStoppingDNS: Bool = false
    ) -> Bool {
        FreshInstallSetupPolicy.resumesEnableAfterAgentApproval(
            agentSetupRequired: agentSetupRequired,
            setupGeneration: setupGeneration,
            currentGeneration: currentGeneration,
            runtimeDNSDesired: runtimeDNSDesired,
            isEnablingDNS: isEnablingDNS,
            isStoppingDNS: isStoppingDNS
        )
    }

    private func reports(
        setupGeneration: UInt64?,
        attemptGeneration: UInt64,
        currentGeneration: UInt64,
        isStopping: Bool = false,
        updateSuspended: Bool = false
    ) -> Bool {
        FreshInstallSetupPolicy.reportsAttempt(
            setupGeneration: setupGeneration,
            attemptGeneration: attemptGeneration,
            currentGeneration: currentGeneration,
            isStopping: isStopping,
            updateSuspended: updateSuspended
        )
    }

    private func continues(startedAsFreshInstall: Bool, setupGeneration: UInt64?, currentGeneration: UInt64) -> Bool {
        FreshInstallSetupPolicy.continuesSetup(
            startedAsFreshInstall: startedAsFreshInstall,
            setupGeneration: setupGeneration,
            currentGeneration: currentGeneration
        )
    }
}
