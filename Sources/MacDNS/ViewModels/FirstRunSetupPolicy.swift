// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

enum FirstRunSetupStep: Equatable, CaseIterable {
    case prepare, networkExtension, dnsFilter, notifications
}

enum FirstRunStepStatus: Equatable {
    case pending, current, done, failed
}

enum FirstRunStepsPhase: Equatable {
    case notStarted, resumed, running, failed, restartRequired, done
}

enum FirstRunScreen: Equatable {
    case steps(FirstRunStepsPhase)
    case moveToApplications, trialEnded
}

struct FirstRunSetupInputs: Equatable {
    var supportedLocation: Bool
    var trialStepRunning: Bool
    var trialEnded: Bool
    var trialStepFinished: Bool
    var licenseKnown: Bool
    var agentApprovalPending: Bool
    var extensionActivated: Bool
    var extensionConfigured: Bool
    var notificationsDecided: Bool
    var notificationsSkipped: Bool
    var setupRunning: Bool
    var awaitingContinue: FirstRunSetupStep?
    var outcome: FreshInstallSetupOutcome?
    var macOSMajorVersion: Int
}

/// Derives the guided first-run steps from observed state. Nothing here is
/// stored: a relaunch rebuilds the same view from macOS and the agent.
struct FirstRunSetupPolicy: Equatable {
    let inputs: FirstRunSetupInputs

    /// macOS asks for local network access from macOS 15 on.
    private static let localNetworkMinimumMajorVersion = 15

    var screen: FirstRunScreen {
        if !inputs.supportedLocation { return .moveToApplications }
        if inputs.trialEnded && !inputs.trialStepRunning { return .trialEnded }
        return .steps(phase)
    }

    /// Only requests the app can trigger and read back. macOS raises the
    /// local network request when the agent first reaches the local network,
    /// and its answer cannot be read, so it is a note instead.
    var visibleSteps: [FirstRunSetupStep] { FirstRunSetupStep.allCases }

    var showsLocalNetworkNote: Bool {
        inputs.macOSMajorVersion >= Self.localNetworkMinimumMajorVersion
    }

    /// Every step is done and Enable still starts the resolver and the proxy.
    var showsTurningOnProtection: Bool {
        phase == .running && currentStep == nil
    }

    func status(of step: FirstRunSetupStep) -> FirstRunStepStatus {
        guard visibleSteps.contains(step) else { return .pending }
        if phase == .done { return .done }
        if isDone(step) { return .done }
        guard step == firstUnfinishedStep else { return .pending }
        switch phase {
        case .failed, .restartRequired: return .failed
        default: return .current
        }
    }

    var currentStep: FirstRunSetupStep? {
        visibleSteps.first { status(of: $0) == .current }
    }

    /// The agent approval keeps Prepare current: macOS asks the user to allow
    /// the background item, and the trial cannot start before that.
    var showsAgentApprovalInstruction: Bool {
        inputs.agentApprovalPending && currentStep == .prepare
    }

    var awaitsContinue: Bool {
        phase == .running && currentStep != nil && inputs.awaitingContinue == currentStep
    }

    /// Also while macOS shows the request, for a user who missed its banner.
    var offersSkip: Bool {
        phase == .running && currentStep == .notifications
    }

    /// Brings the window forward when a step starts waiting for Continue and
    /// when the run reaches an outcome the user must see.
    static func bringsWindowToFront(from old: FirstRunSetupPolicy, to new: FirstRunSetupPolicy) -> Bool {
        if new.awaitsContinue && !old.awaitsContinue { return true }
        let outcomes: [FirstRunScreen] = [.steps(.done), .steps(.failed), .steps(.restartRequired)]
        return outcomes.contains(new.screen) && !outcomes.contains(old.screen)
    }

    /// The window is derived from macOS state: it stays until the DNS Proxy is
    /// configured and the notification choice is made or protection is on.
    static func presentsWindow(proxyConfigured: Bool, notificationsDecided: Bool, protectionEnabled: Bool) -> Bool {
        !proxyConfigured || (!notificationsDecided && !protectionEnabled)
    }

    private var phase: FirstRunStepsPhase {
        switch inputs.outcome {
        case .done: return .done
        case .restartRequired: return .restartRequired
        case .failed: return .failed
        case .waitingForApproval, nil: break
        }
        if inputs.trialStepRunning || inputs.setupRunning || inputs.outcome == .waitingForApproval {
            return .running
        }
        return visibleSteps.contains(where: isDone) ? .resumed : .notStarted
    }

    private var firstUnfinishedStep: FirstRunSetupStep? {
        visibleSteps.first { !isDone($0) }
    }

    private func isDone(_ step: FirstRunSetupStep) -> Bool {
        switch step {
        case .prepare: return (inputs.trialStepFinished || inputs.licenseKnown) && !inputs.agentApprovalPending
        case .networkExtension: return inputs.extensionActivated || inputs.extensionConfigured
        case .dnsFilter: return inputs.extensionConfigured
        case .notifications: return inputs.notificationsDecided || inputs.notificationsSkipped
        }
    }
}
