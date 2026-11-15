// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import OSLog
import SwiftUI

/// Hosts the first-run window: at most once per process, and only while
/// setup is not finished.
@MainActor
final class FirstRunWindowController: NSObject, ObservableObject, NSWindowDelegate {
    static let shared = FirstRunWindowController()

    private static let copyFailedMessage =
        "MacDNS couldn't move itself. Drag MacDNS to the Applications folder and open it from there."
    private static let licenseURL = URL(string: "https://macdns.app/buy")!

    private let logger = Logger(subsystem: "app.macdns", category: "FirstRunWindow")
    private var presentationRequested = false
    private var window: NSWindow?
    private var viewModel: AppViewModel?
    private var isShowing = false
    private var isMoving = false
    private var exitTrialStepStarted = false
    private var exitTrialStepTask: Task<Void, Never>?
    @Published fileprivate private(set) var moveFailed = false

    /// True once Turn On, Continue or an activation handed over to `enableDNS()`.
    private(set) var handedOff = false

    /// The screen on display, nil when no window is visible.
    var currentScreen: FirstRunScreen? {
        guard isShowing, let viewModel else { return nil }
        return Self.setup(for: viewModel).screen
    }

    fileprivate static func setup(for viewModel: AppViewModel) -> FirstRunSetupPolicy {
        FirstRunSetupPolicy(
            inputs: FirstRunSetupInputs(
                supportedLocation: FirstRunStepPolicy.isSupportedInstallLocation(Bundle.main.bundleURL),
                trialStepRunning: viewModel.firstRunPreparing,
                trialEnded: viewModel.firstRunTrialEnded,
                trialStepFinished: viewModel.firstRunTrialStepFinished,
                licenseKnown: viewModel.licenseInfo.map { $0.status != .unknown } ?? false,
                agentApprovalPending: viewModel.agentNeedsPermissionApproval,
                extensionActivated: ExtensionManager.shared.systemExtensionActivated,
                extensionConfigured: ExtensionManager.shared.isActive,
                notificationsDecided: viewModel.notificationsDecided,
                notificationsSkipped: viewModel.firstRunNotificationsSkipped,
                setupRunning: viewModel.freshInstallSetupRunning || viewModel.isEnablingDNS,
                awaitingContinue: viewModel.firstRunAwaitingContinue,
                outcome: viewModel.freshInstallSetupOutcome,
                macOSMajorVersion: ProcessInfo.processInfo.operatingSystemVersion.majorVersion
            )
        )
    }

    func presentIfNeeded(viewModel: AppViewModel) async {
        guard !presentationRequested else { return }
        presentationRequested = true

        do {
            try await ExtensionManager.shared.refreshProxyStatus()
        } catch {
            logger.warning(
                "First-run window skipped, DNS Proxy status unavailable: \(error.localizedDescription, privacy: .public)"
            )
            return
        }
        await viewModel.refreshNotificationAuthorization()
        let proxyConfigured = ExtensionManager.shared.isActive
        var protectionEnabled = false
        if proxyConfigured {
            for await _ in viewModel.$persistedStateAvailability.first(where: { $0 != .loading }).values {}
            protectionEnabled = viewModel.isEnabled
        }
        guard
            FirstRunSetupPolicy.presentsWindow(
                proxyConfigured: proxyConfigured,
                notificationsDecided: viewModel.notificationsDecided,
                protectionEnabled: protectionEnabled
            )
        else {
            // A finished setup may restore protection without an Enable, so it
            // is asked at launch. Setup asks during its own steps.
            viewModel.requestNotificationPermission()
            return
        }

        self.viewModel = viewModel
        let hosting = NSHostingController(rootView: FirstRunWindowContent(controller: self, viewModel: viewModel))
        hosting.sizingOptions = .preferredContentSize

        let window = FirstRunWindow(contentViewController: hosting)
        window.styleMask = [.titled, .closable]
        window.title = "MacDNS"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.backgroundColor = NSColor(FirstRunView.brandBlue)
        window.isReleasedWhenClosed = false
        window.delegate = self
        self.window = window
        isShowing = true
        viewModel.firstRunWindowOpen = true

        logger.info(
            "Presenting first-run window: \(String(describing: Self.setup(for: viewModel).screen), privacy: .public)"
        )
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    /// Comes forward without staying above other windows, so System Settings
    /// can cover it while the user approves a request.
    fileprivate func bringWindowToFront() {
        guard isShowing, let window else { return }
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    /// The trial step quit must wait for, started here when quitting before
    /// setup starts. Nil when quit proceeds at once.
    func exitTrialStepForQuit() -> Task<Void, Never>? {
        switch exitAction() {
        case .runTrialStep: return startExitTrialStep()
        case .awaitRunningTrialStep: return exitTrialStepTask
        case .proceed: return nil
        }
    }

    /// Closing never cancels a running setup. It only ends the waits for
    /// Continue and for the notification answer, and the outcome alert
    /// reports how the setup ended.
    func windowWillClose(_ notification: Notification) {
        if exitAction() == .runTrialStep {
            startExitTrialStep()
        }
        isShowing = false
        viewModel?.firstRunWindowOpen = false
        viewModel?.endFirstRunWaits()
    }

    private func exitAction() -> FirstRunExitAction {
        FirstRunStepPolicy.exitAction(
            windowScreen: currentScreen,
            handedOff: handedOff,
            trialStepStarted: exitTrialStepStarted,
            trialStepRunning: exitTrialStepTask != nil,
            removingServices: viewModel?.servicesRemovalRequested ?? false,
            servicesRemoved: viewModel?.servicesRemoved ?? false,
            installingUpdate: (viewModel?.softwareUpdateSuspended ?? false) || UpdaterManager.shared.installationPending
        )
    }

    @discardableResult
    private func startExitTrialStep() -> Task<Void, Never>? {
        guard let viewModel else { return nil }
        exitTrialStepStarted = true
        let task = Task { @MainActor [weak self] in
            await viewModel.dismissFirstRun()
            self?.exitTrialStepTask = nil
        }
        exitTrialStepTask = task
        return task
    }

    fileprivate func makeActions(viewModel: AppViewModel) -> FirstRunActions {
        let windowOpen: @MainActor () -> Bool = { [weak self] in self?.isShowing ?? false }
        // Turn On and the resumed Continue also answer the step they explain.
        let approveCurrentStep: @MainActor () -> Void = {
            viewModel.firstRunApprovedStep = Self.setup(for: viewModel).currentStep
        }
        return FirstRunActions(
            turnOn: { [weak self] in
                approveCurrentStep()
                Task { @MainActor in
                    guard await viewModel.turnOnFromFirstRun(windowOpen: windowOpen) else { return }
                    self?.handedOff = true
                }
            },
            close: { [weak self] in self?.window?.close() },
            tryAgain: { viewModel.retryFreshInstallSetup() },
            continueStep: { viewModel.continueFirstRunStep() },
            skipNotifications: { viewModel.skipFirstRunNotifications() },
            moveToApplications: { [weak self] in self?.moveToApplications() },
            quit: { NSApp.terminate(nil) },
            activate: { [weak self] key in
                Task { @MainActor in
                    guard await viewModel.activateLicenseAndTurnOn(key: key, windowOpen: windowOpen) else { return }
                    self?.handedOff = true
                }
            },
            getLicense: { NSWorkspace.shared.open(Self.licenseURL) }
        )
    }

    private func moveToApplications() {
        guard !isMoving else { return }
        isMoving = true
        moveFailed = false
        Task { @MainActor in
            defer { isMoving = false }
            do {
                let mover = ApplicationMover(
                    applicationsDirectory: URL(fileURLWithPath: "/Applications", isDirectory: true),
                    recycle: { _ = try await NSWorkspace.shared.recycle([$0]) }
                )
                let copy = try await mover.install(Bundle.main.bundleURL)
                let configuration = NSWorkspace.OpenConfiguration()
                // Same bundle identifier as this process: without a new
                // instance, Launch Services would only reactivate this copy.
                configuration.createsNewApplicationInstance = true
                _ = try await NSWorkspace.shared.openApplication(at: copy, configuration: configuration)
                logger.info("Moved MacDNS to \(copy.path, privacy: .public), terminating this copy")
                NSApp.terminate(nil)
            } catch {
                logger.error("Move to Applications failed: \(String(describing: error), privacy: .public)")
                moveFailed = true
            }
        }
    }

    fileprivate func message(for screen: FirstRunScreen, viewModel: AppViewModel) -> String? {
        switch screen {
        case .moveToApplications:
            return moveFailed ? Self.copyFailedMessage : nil
        case .trialEnded:
            guard let feedback = viewModel.licenseActivationFeedback, !feedback.isSuccess else { return nil }
            return feedback.message
        case .steps(.failed):
            return viewModel.freshInstallSetupFailureMessage
        case .steps:
            return nil
        }
    }
}

/// Escape closes the window like the close button.
private final class FirstRunWindow: NSWindow {
    override func cancelOperation(_ sender: Any?) {
        performClose(sender)
    }
}

/// Binds the view model and controller state to the plain-value `FirstRunView`.
private struct FirstRunWindowContent: View {
    @ObservedObject var controller: FirstRunWindowController
    @ObservedObject var viewModel: AppViewModel
    /// The extension steps read `systemExtensionActivated` and `isActive`.
    @ObservedObject private var extensionManager = ExtensionManager.shared

    var body: some View {
        let setup = FirstRunWindowController.setup(for: viewModel)
        FirstRunView(
            setup: setup,
            message: controller.message(for: setup.screen, viewModel: viewModel),
            actions: controller.makeActions(viewModel: viewModel),
            canActivate: !viewModel.isLoadingLicense && !viewModel.firstRunPreparing
        )
        .onChange(of: setup) { old, new in
            if FirstRunSetupPolicy.bringsWindowToFront(from: old, to: new) {
                controller.bringWindowToFront()
            }
        }
    }
}
