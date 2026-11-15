// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class FirstRunStepPolicyTests: XCTestCase {
    func testSupportedInstallLocation() {
        let supported = [
            "/Applications/MacDNS.app",
            "/Applications/Utilities/MacDNS.app",
        ]
        let unsupported = [
            "/Volumes/MacDNS/MacDNS.app",
            "/Users/someone/Downloads/MacDNS.app",
            "/private/var/folders/xy/abc/T/AppTranslocation/1234/d/MacDNS.app",
            "/Users/someone/Applications/MacDNS.app",
            "/Applications",
            "/ApplicationsCopy/MacDNS.app",
        ]

        for path in supported {
            XCTAssertTrue(
                FirstRunStepPolicy.isSupportedInstallLocation(URL(fileURLWithPath: path)),
                path
            )
        }
        for path in unsupported {
            XCTAssertFalse(
                FirstRunStepPolicy.isSupportedInstallLocation(URL(fileURLWithPath: path)),
                path
            )
        }
    }

    func testExitRunsTheTrialStepOnlyBeforeSetupStartsAndBeforeHandOff() {
        XCTAssertTrue(FirstRunStepPolicy.runsTrialStepOnExit(windowScreen: .steps(.notStarted), handedOff: false))
        XCTAssertTrue(FirstRunStepPolicy.runsTrialStepOnExit(windowScreen: .steps(.resumed), handedOff: false))

        let skipped: [(FirstRunScreen?, Bool)] = [
            (.steps(.notStarted), true),
            (.steps(.resumed), true),
            (nil, false),
            (.steps(.running), false),
            (.steps(.failed), false),
            (.steps(.restartRequired), false),
            (.steps(.done), false),
            (.trialEnded, false),
            (.moveToApplications, false),
        ]
        for (screen, handedOff) in skipped {
            XCTAssertFalse(
                FirstRunStepPolicy.runsTrialStepOnExit(windowScreen: screen, handedOff: handedOff),
                "\(String(describing: screen)) handedOff=\(handedOff)"
            )
        }
    }

    func testExitBeforeSetupStartsRunsTheTrialStep() {
        XCTAssertEqual(exitAction(windowScreen: .steps(.notStarted)), .runTrialStep)
        XCTAssertEqual(exitAction(windowScreen: .steps(.resumed)), .runTrialStep)
    }

    func testExitWhileSetupRunsOrAfterHandOffProceeds() {
        XCTAssertEqual(exitAction(windowScreen: .steps(.notStarted), handedOff: true), .proceed)
        XCTAssertEqual(exitAction(windowScreen: nil), .proceed)
        XCTAssertEqual(exitAction(windowScreen: .steps(.running)), .proceed)
        XCTAssertEqual(exitAction(windowScreen: .trialEnded), .proceed)
        XCTAssertEqual(exitAction(windowScreen: .moveToApplications), .proceed)
    }

    func testQuitAfterCloseWaitsForTheRunningTrialStep() {
        // Closing hid the window, so the step on screen is gone.
        XCTAssertEqual(
            exitAction(windowScreen: nil, trialStepStarted: true, trialStepRunning: true),
            .awaitRunningTrialStep
        )
    }

    func testTrialStepNeverRunsTwice() {
        XCTAssertEqual(exitAction(windowScreen: .steps(.notStarted), trialStepStarted: true), .proceed)
    }

    func testRemovingServicesNeverRunsOrAwaitsTheTrialStep() {
        XCTAssertEqual(exitAction(windowScreen: .steps(.notStarted), removingServices: true), .proceed)
        XCTAssertEqual(
            exitAction(windowScreen: nil, trialStepStarted: true, trialStepRunning: true, removingServices: true),
            .proceed
        )
    }

    /// Uninstall leaves the window open before setup starts. Closing it or quitting
    /// later must not register the Agent again.
    func testExitAfterServicesWereRemovedNeverRunsOrAwaitsTheTrialStep() {
        XCTAssertEqual(exitAction(windowScreen: .steps(.notStarted), servicesRemoved: true), .proceed)
        XCTAssertEqual(
            exitAction(windowScreen: nil, trialStepStarted: true, trialStepRunning: true, servicesRemoved: true),
            .proceed
        )
    }

    /// Sparkle unregisters the Agent before it terminates the app. The trial
    /// step would register it again while the bundle is being replaced.
    func testInstallingAnUpdateNeverRunsOrAwaitsTheTrialStep() {
        XCTAssertEqual(exitAction(windowScreen: .steps(.notStarted), installingUpdate: true), .proceed)
        XCTAssertEqual(
            exitAction(windowScreen: nil, trialStepStarted: true, trialStepRunning: true, installingUpdate: true),
            .proceed
        )
    }

    func testTurnOnHandsOffOnlyWhileTheWindowIsOpen() {
        XCTAssertTrue(handsOff(.licensed(blocksEnable: false)))
        XCTAssertTrue(handsOff(.licenseUnknown))
    }

    /// Closing the window never turns protection on, also while Turn On is
    /// still preparing.
    func testClosingWhilePreparingCancelsTheHandOff() {
        XCTAssertFalse(handsOff(.licensed(blocksEnable: false), windowOpen: false))
        XCTAssertFalse(handsOff(.agentUnavailable, windowOpen: false))
    }

    func testEndedLicenseNeverHandsOff() {
        XCTAssertFalse(handsOff(.licensed(blocksEnable: true)))
        XCTAssertFalse(handsOff(.unsupportedLocation))
    }

    /// Uninstall, Quit and Remove Services, a disable, an update or a menu
    /// Enable while Turn On prepares replaces its lifecycle. Handing off then
    /// would reinstall what the user just removed.
    func testLifecycleReplacedWhilePreparingCancelsTheHandOff() {
        XCTAssertFalse(handsOff(.licensed(blocksEnable: false), startGeneration: 4, currentGeneration: 5))
        XCTAssertFalse(handsOff(.licenseUnknown, startGeneration: 4, currentGeneration: 5))
    }

    private func handsOff(
        _ outcome: FirstRunTrialOutcome,
        windowOpen: Bool = true,
        startGeneration: UInt64 = 4,
        currentGeneration: UInt64 = 4
    ) -> Bool {
        FirstRunStepPolicy.handsOffToEnable(
            outcome,
            windowOpen: windowOpen,
            startGeneration: startGeneration,
            currentGeneration: currentGeneration
        )
    }

    private func exitAction(
        windowScreen: FirstRunScreen?,
        handedOff: Bool = false,
        trialStepStarted: Bool = false,
        trialStepRunning: Bool = false,
        removingServices: Bool = false,
        servicesRemoved: Bool = false,
        installingUpdate: Bool = false
    ) -> FirstRunExitAction {
        FirstRunStepPolicy.exitAction(
            windowScreen: windowScreen,
            handedOff: handedOff,
            trialStepStarted: trialStepStarted,
            trialStepRunning: trialStepRunning,
            removingServices: removingServices,
            servicesRemoved: servicesRemoved,
            installingUpdate: installingUpdate
        )
    }
}
