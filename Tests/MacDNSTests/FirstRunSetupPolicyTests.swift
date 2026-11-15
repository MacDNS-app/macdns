// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class FirstRunSetupPolicyTests: XCTestCase {
    private func inputs(
        supportedLocation: Bool = true,
        trialStepRunning: Bool = false,
        trialEnded: Bool = false,
        trialStepFinished: Bool = false,
        licenseKnown: Bool = false,
        agentApprovalPending: Bool = false,
        extensionActivated: Bool = false,
        extensionConfigured: Bool = false,
        notificationsDecided: Bool = false,
        notificationsSkipped: Bool = false,
        setupRunning: Bool = false,
        awaitingContinue: FirstRunSetupStep? = nil,
        outcome: FreshInstallSetupOutcome? = nil,
        macOSMajorVersion: Int = 15
    ) -> FirstRunSetupInputs {
        FirstRunSetupInputs(
            supportedLocation: supportedLocation,
            trialStepRunning: trialStepRunning,
            trialEnded: trialEnded,
            trialStepFinished: trialStepFinished,
            licenseKnown: licenseKnown,
            agentApprovalPending: agentApprovalPending,
            extensionActivated: extensionActivated,
            extensionConfigured: extensionConfigured,
            notificationsDecided: notificationsDecided,
            notificationsSkipped: notificationsSkipped,
            setupRunning: setupRunning,
            awaitingContinue: awaitingContinue,
            outcome: outcome,
            macOSMajorVersion: macOSMajorVersion
        )
    }

    private func policy(_ value: FirstRunSetupInputs) -> FirstRunSetupPolicy {
        FirstRunSetupPolicy(inputs: value)
    }

    func testFreshInstallStartsWithPrepareCurrent() {
        let sut = policy(inputs())
        XCTAssertEqual(sut.screen, .steps(.notStarted))
        XCTAssertEqual(sut.currentStep, .prepare)
        XCTAssertEqual(sut.status(of: .prepare), .current)
        XCTAssertEqual(sut.status(of: .networkExtension), .pending)
        XCTAssertEqual(sut.status(of: .dnsFilter), .pending)
        XCTAssertEqual(sut.status(of: .notifications), .pending)
    }

    func testExtensionConfiguredResumesAtNotifications() {
        let sut = policy(inputs(trialStepFinished: true, extensionConfigured: true))
        XCTAssertEqual(sut.screen, .steps(.resumed))
        XCTAssertEqual(sut.status(of: .prepare), .done)
        XCTAssertEqual(sut.status(of: .networkExtension), .done)
        XCTAssertEqual(sut.status(of: .dnsFilter), .done)
        XCTAssertEqual(sut.status(of: .notifications), .current)
        XCTAssertEqual(sut.currentStep, .notifications)
    }

    func testExtensionStepDoneOnceActivated() {
        let sut = policy(inputs(trialStepFinished: true, extensionActivated: true, extensionConfigured: false, setupRunning: true))
        XCTAssertEqual(sut.status(of: .networkExtension), .done)
        XCTAssertEqual(sut.status(of: .dnsFilter), .current)
        XCTAssertEqual(sut.currentStep, .dnsFilter)
    }

    func testDNSFilterDoneWhenConfigured() {
        let sut = policy(inputs(trialStepFinished: true, extensionConfigured: true))
        XCTAssertEqual(sut.status(of: .networkExtension), .done)
        XCTAssertEqual(sut.status(of: .dnsFilter), .done)
    }

    func testAwaitsContinueOnlyForCurrentStep() {
        let base = inputs(trialStepFinished: true, extensionActivated: true, setupRunning: true, awaitingContinue: .dnsFilter)
        XCTAssertTrue(policy(base).awaitsContinue)

        var otherStep = base
        otherStep.awaitingContinue = .notifications
        XCTAssertFalse(policy(otherStep).awaitsContinue)

        var notRunning = base
        notRunning.setupRunning = false
        XCTAssertFalse(policy(notRunning).awaitsContinue)

        var nothingAwaited = base
        nothingAwaited.awaitingContinue = nil
        XCTAssertFalse(policy(nothingAwaited).awaitsContinue)
    }

    func testBringsWindowToFrontWhenWaitStarts() {
        let waiting = policy(
            inputs(trialStepFinished: true, extensionActivated: true, setupRunning: true, awaitingContinue: .dnsFilter))
        let working = policy(inputs(trialStepFinished: true, extensionActivated: true, setupRunning: true))
        XCTAssertTrue(FirstRunSetupPolicy.bringsWindowToFront(from: working, to: waiting))
        XCTAssertFalse(FirstRunSetupPolicy.bringsWindowToFront(from: waiting, to: waiting))
        XCTAssertFalse(FirstRunSetupPolicy.bringsWindowToFront(from: waiting, to: working))
    }

    func testBringsWindowToFrontOnOutcome() {
        let running = policy(inputs(setupRunning: true))
        for outcome in [FreshInstallSetupOutcome.done, .failed, .restartRequired] {
            let finished = policy(inputs(setupRunning: true, outcome: outcome))
            XCTAssertTrue(FirstRunSetupPolicy.bringsWindowToFront(from: running, to: finished))
            XCTAssertFalse(FirstRunSetupPolicy.bringsWindowToFront(from: finished, to: finished))
        }
        let failed = policy(inputs(outcome: .failed))
        let restart = policy(inputs(outcome: .restartRequired))
        XCTAssertFalse(FirstRunSetupPolicy.bringsWindowToFront(from: failed, to: restart))
    }

    func testBringsWindowToFrontIgnoresUnchangedState() {
        let running = policy(inputs(setupRunning: true))
        XCTAssertFalse(FirstRunSetupPolicy.bringsWindowToFront(from: running, to: running))
        XCTAssertFalse(FirstRunSetupPolicy.bringsWindowToFront(from: policy(inputs()), to: running))
    }

    func testPrepareDoneWhenLicenseKnown() {
        let sut = policy(inputs(licenseKnown: true))
        XCTAssertEqual(sut.status(of: .prepare), .done)
        XCTAssertEqual(sut.screen, .steps(.resumed))
        XCTAssertEqual(sut.currentStep, .networkExtension)
    }

    func testAgentApprovalKeepsPrepareCurrent() {
        for licenseKnown in [false, true] {
            let sut = policy(inputs(trialStepFinished: true, licenseKnown: licenseKnown, agentApprovalPending: true))
            XCTAssertEqual(sut.status(of: .prepare), .current)
            XCTAssertEqual(sut.currentStep, .prepare)
            XCTAssertTrue(sut.showsAgentApprovalInstruction)
        }
    }

    func testApprovalInstructionHiddenWhenPrepareIsNotCurrent() {
        XCTAssertFalse(policy(inputs()).showsAgentApprovalInstruction)
        XCTAssertFalse(policy(inputs(trialStepFinished: true)).showsAgentApprovalInstruction)
    }

    func testNotificationsDoneWhenDecidedOrSkipped() {
        XCTAssertEqual(policy(inputs(notificationsDecided: true)).status(of: .notifications), .done)
        XCTAssertEqual(policy(inputs(notificationsSkipped: true)).status(of: .notifications), .done)
    }

    /// A user who missed the macOS banner can still pass the step while the
    /// notification request runs.
    func testSkipWhileTheSetupRunsOnNotifications() {
        let base = inputs(trialStepFinished: true, extensionConfigured: true)
        var running = base
        running.setupRunning = true
        XCTAssertTrue(policy(running).offersSkip)
        running.awaitingContinue = .notifications
        XCTAssertTrue(policy(running).offersSkip)
        XCTAssertFalse(policy(base).offersSkip)

        var skipped = running
        skipped.awaitingContinue = nil
        skipped.notificationsSkipped = true
        XCTAssertFalse(policy(skipped).offersSkip)

        var prepareRunning = inputs(trialStepRunning: true)
        XCTAssertFalse(policy(prepareRunning).offersSkip)
        prepareRunning.setupRunning = true
        XCTAssertFalse(policy(prepareRunning).offersSkip)

        var failed = running
        failed.outcome = .failed
        XCTAssertFalse(policy(failed).offersSkip)
    }

    func testCompletedEnableWithoutActiveProtectionIsDone() {
        let sut = policy(inputs(outcome: .done))
        XCTAssertEqual(sut.screen, .steps(.done))
        for step in sut.visibleSteps {
            XCTAssertEqual(sut.status(of: step), .done)
        }
        XCTAssertNil(sut.currentStep)
        XCTAssertFalse(sut.showsTurningOnProtection)
    }

    /// Every step the app can request and read is done, and Enable still
    /// starts the resolver and the DNS Proxy.
    func testTurningOnProtectionOnceEveryStepIsDoneWhileRunning() {
        let sut = policy(
            inputs(trialStepFinished: true, extensionConfigured: true, notificationsDecided: true, setupRunning: true))
        XCTAssertEqual(sut.screen, .steps(.running))
        XCTAssertNil(sut.currentStep)
        XCTAssertTrue(sut.showsTurningOnProtection)
        XCTAssertFalse(sut.awaitsContinue)
    }

    func testNotTurningOnProtectionWhileAStepIsCurrent() {
        XCTAssertFalse(policy(inputs(trialStepFinished: true, setupRunning: true)).showsTurningOnProtection)
        XCTAssertFalse(policy(inputs(trialStepRunning: true)).showsTurningOnProtection)
    }

    func testRunningWhileTrialStepOrSetupRuns() {
        XCTAssertEqual(policy(inputs(trialStepRunning: true)).screen, .steps(.running))
        XCTAssertEqual(policy(inputs(setupRunning: true)).screen, .steps(.running))
    }

    func testWaitingForApprovalStaysRunning() {
        let sut = policy(inputs(trialStepFinished: true, outcome: .waitingForApproval))
        XCTAssertEqual(sut.screen, .steps(.running))
        XCTAssertEqual(sut.currentStep, .networkExtension)
    }

    func testFailureMarksTheFirstUnfinishedStepFailed() {
        let sut = policy(inputs(trialStepFinished: true, outcome: .failed))
        XCTAssertEqual(sut.screen, .steps(.failed))
        XCTAssertEqual(sut.status(of: .prepare), .done)
        XCTAssertEqual(sut.status(of: .networkExtension), .failed)
        XCTAssertEqual(sut.status(of: .dnsFilter), .pending)
        XCTAssertEqual(sut.status(of: .notifications), .pending)
        XCTAssertNil(sut.currentStep)
    }

    func testRestartMarksTheFirstUnfinishedStepFailed() {
        let sut = policy(inputs(trialStepFinished: true, extensionConfigured: true, outcome: .restartRequired))
        XCTAssertEqual(sut.screen, .steps(.restartRequired))
        XCTAssertEqual(sut.status(of: .networkExtension), .done)
        XCTAssertEqual(sut.status(of: .notifications), .failed)
        XCTAssertNil(sut.currentStep)
    }

    func testOutcomeWinsOverRunningFlags() {
        let sut = policy(inputs(trialStepRunning: true, setupRunning: true, outcome: .failed))
        XCTAssertEqual(sut.screen, .steps(.failed))
    }

    /// macOS shows the local network request when the agent first reaches
    /// the local network, and the app can neither trigger nor read it. It is
    /// a note, not a step.
    func testLocalNetworkIsANoteNotAStep() {
        for version in [14, 15, 27] {
            XCTAssertEqual(
                policy(inputs(macOSMajorVersion: version)).visibleSteps,
                [.prepare, .networkExtension, .dnsFilter, .notifications])
        }
        XCTAssertEqual(FirstRunSetupStep.allCases, [.prepare, .networkExtension, .dnsFilter, .notifications])
    }

    func testLocalNetworkNoteFromMacOS15() {
        XCTAssertFalse(policy(inputs(macOSMajorVersion: 14)).showsLocalNetworkNote)
        XCTAssertTrue(policy(inputs(macOSMajorVersion: 15)).showsLocalNetworkNote)
        XCTAssertTrue(policy(inputs(macOSMajorVersion: 27)).showsLocalNetworkNote)
    }

    func testTrialEndedWinsOverStepsButNotOverARunningTrialStep() {
        XCTAssertEqual(policy(inputs(trialEnded: true)).screen, .trialEnded)
        XCTAssertEqual(policy(inputs(trialStepRunning: true, trialEnded: true)).screen, .steps(.running))
    }

    func testOutsideApplicationsShowsMove() {
        XCTAssertEqual(policy(inputs(supportedLocation: false)).screen, .moveToApplications)
        XCTAssertEqual(policy(inputs(supportedLocation: false, trialEnded: true)).screen, .moveToApplications)
    }

    func testWindowRule() {
        XCTAssertFalse(
            FirstRunSetupPolicy.presentsWindow(proxyConfigured: true, notificationsDecided: true, protectionEnabled: false))
        XCTAssertFalse(
            FirstRunSetupPolicy.presentsWindow(proxyConfigured: true, notificationsDecided: false, protectionEnabled: true))
        XCTAssertTrue(
            FirstRunSetupPolicy.presentsWindow(proxyConfigured: true, notificationsDecided: false, protectionEnabled: false))
        XCTAssertTrue(
            FirstRunSetupPolicy.presentsWindow(proxyConfigured: false, notificationsDecided: true, protectionEnabled: true))
    }
}
