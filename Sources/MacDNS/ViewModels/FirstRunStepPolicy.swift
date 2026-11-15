// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Exit and hand-off rules for the first-run window.
enum FirstRunStepPolicy {
    /// macOS activates system extensions only from an app inside /Applications.
    /// A copy run from the disk image or a translocated path would register the
    /// Agent at a path that disappears.
    static func isSupportedInstallLocation(_ bundleURL: URL) -> Bool {
        bundleURL.standardizedFileURL.path.hasPrefix("/Applications/")
    }

    /// Close and quit run the trial step only before setup starts, and never
    /// after Turn On, Continue or an activation handed over to `enableDNS()`.
    static func runsTrialStepOnExit(windowScreen: FirstRunScreen?, handedOff: Bool) -> Bool {
        guard !handedOff else { return false }
        return windowScreen == .steps(.notStarted) || windowScreen == .steps(.resumed)
    }

    /// Turn On and a successful activation hand over to `enableDNS()` only
    /// while the window is still open and no other DNS lifecycle started
    /// since they did. Closing the window never turns protection on, also
    /// while the trial step runs, and Enable never undoes an Uninstall, quit,
    /// disable or update that ran meanwhile.
    static func handsOffToEnable(
        _ outcome: FirstRunTrialOutcome,
        windowOpen: Bool,
        startGeneration: UInt64,
        currentGeneration: UInt64
    ) -> Bool {
        windowOpen && startGeneration == currentGeneration && outcome.continuesToEnable
    }

    /// What closing the window or quitting does about the trial step. The step
    /// runs at most once per process, and quit waits for one still running so
    /// a close followed by a quick quit still sends the trial request.
    /// Removing services, services already removed by Uninstall and
    /// installing an update never run or wait for it: each unregisters the
    /// Agent, and the step would register it again.
    static func exitAction(
        windowScreen: FirstRunScreen?,
        handedOff: Bool,
        trialStepStarted: Bool,
        trialStepRunning: Bool,
        removingServices: Bool,
        servicesRemoved: Bool,
        installingUpdate: Bool
    ) -> FirstRunExitAction {
        if removingServices || servicesRemoved || installingUpdate { return .proceed }
        if trialStepRunning { return .awaitRunningTrialStep }
        if trialStepStarted { return .proceed }
        return runsTrialStepOnExit(windowScreen: windowScreen, handedOff: handedOff) ? .runTrialStep : .proceed
    }
}

enum FirstRunExitAction: Equatable {
    case proceed, runTrialStep, awaitRunningTrialStep
}
