// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import Combine
import Foundation
import Shared
import Sparkle
import os.log

// MARK: - Updater Manager

@MainActor
final class UpdaterManager: NSObject, ObservableObject, SPUUpdaterDelegate, @MainActor SPUStandardUserDriverDelegate {

    // MARK: - Singleton

    static let shared = UpdaterManager()

    // MARK: - Properties

    private let logger = Logger(subsystem: "app.macdns.app", category: "updater")

    private lazy var updaterController = SPUStandardUpdaterController(
        startingUpdater: false,
        updaterDelegate: self,
        userDriverDelegate: self
    )

    private let promptHistory = UpdatePromptHistory.persistedUpdatePromptHistory()
    private var automaticCheckCompletion: CheckedContinuation<Bool, Never>?
    private var fallbackTask: Task<Void, Never>?
    private var foregroundCheckTask: Task<Void, Never>?
    private var startedAt: Date?
    private var lastDiscoveryCompletedAt: Date?
    private static let deferralErrorDomain = "app.macdns.updater.deferred"

    var onUpdateCycleFinished: (() -> Void)?
    var installationLifecycle: SoftwareUpdateLifecycle?
    private var immediateInstallationPending = false
    private var installationIntent = UpdateInstallationIntent()
    var installationPending: Bool { immediateInstallationPending || installationIntent.requiresPreparation }

    @Published private(set) var canCheckForUpdates = false

    var lastUpdateCheckDate: Date? { updaterController.updater.lastUpdateCheckDate }

    // MARK: - Initialization

    private override init() {
        super.init()
    }

    isolated deinit {
        fallbackTask?.cancel()
        foregroundCheckTask?.cancel()
    }

    // MARK: - Public Methods

    /// Call once at app launch.
    func startUpdater() {
        guard fallbackTask == nil else { return }
        startedAt = Date()
        updaterController.updater.publisher(for: \.canCheckForUpdates)
            .assign(to: &$canCheckForUpdates)
        updaterController.startUpdater()
        fallbackTask = Task { [weak self] in
            await UpdateFallbackScheduler.run(
                checkForUpdates: { await self?.showUpdateIfAvailable(nil) ?? true }
            )
        }
    }

    func checkForUpdates() {
        guard updaterController.updater.canCheckForUpdates else {
            logger.warning("Sparkle updater cannot check for updates")
            return
        }
        updaterController.checkForUpdates(nil)
    }

    func checkForUpdatesIfStale() {
        guard let startedAt, Date().timeIntervalSince(startedAt) >= 30,
            !installationPending, foregroundCheckTask == nil,
            UpdateDiscoveryFreshnessPolicy.shouldCheck(lastCompletedAt: lastDiscoveryCompletedAt)
        else { return }
        foregroundCheckTask = Task { [weak self] in
            guard let self else { return }
            defer { foregroundCheckTask = nil }
            _ = await showUpdateIfAvailable(nil)
        }
    }

    /// A nil cache lets Sparkle discover the update. False requests another delivery attempt.
    func showUpdateIfAvailable(_ info: UpdateInfo?) async -> Bool {
        if let info {
            guard info.isUpdateAvailable,
                promptHistory.allowsPrompt(version: info.latestVersion)
            else { return true }
        }

        let updater = updaterController.updater
        guard updater.canCheckForUpdates, !updater.sessionInProgress,
            automaticCheckCompletion == nil
        else { return false }

        return await withCheckedContinuation { continuation in
            automaticCheckCompletion = continuation
            // Background checks honor skipped versions and suppress no-update dialogs.
            updater.checkForUpdatesInBackground()
        }
    }

    func updater(
        _ updater: SPUUpdater,
        shouldProceedWithUpdate update: SUAppcastItem,
        updateCheck: SPUUpdateCheck
    ) throws {
        guard updateCheck != .updates,
            !promptHistory.allowsPrompt(version: update.displayVersionString)
        else { return }
        throw NSError(
            domain: Self.deferralErrorDomain,
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: "The update reminder was deferred"]
        )
    }

    func updater(
        _ updater: SPUUpdater,
        didFinishUpdateCycleFor updateCheck: SPUUpdateCheck,
        error: Error?
    ) {
        let failure = error as NSError?
        let completed =
            failure == nil
            || failure?.domain == Self.deferralErrorDomain
            || (failure?.domain == SUSparkleErrorDomain
                && failure?.code == Int(SUError.noUpdateError.rawValue))
        if !completed {
            logger.warning(
                "Update cycle failed: \(error?.localizedDescription ?? "unknown error", privacy: .public)"
            )
        }
        if completed { lastDiscoveryCompletedAt = Date() }
        completeAutomaticCheck(delivered: completed)
        if failure?.domain == SUSparkleErrorDomain,
            failure?.code == Int(SUError.installationAuthorizeLaterError.rawValue)
        {
            installationIntent.receive(.downloadedUpdateResumed)
        }
        installationIntent.receive(.discoveryFinished)
        guard immediateInstallationPending,
            let installationLifecycle, installationLifecycle.state != .idle
        else {
            immediateInstallationPending = false
            onUpdateCycleFinished?()
            return
        }
        let installationAttempt = installationLifecycle.attemptID
        Task { [weak self] in
            guard let self else { return }
            await installationLifecycle.finishUpdateCycle(for: installationAttempt)
            if installationLifecycle.state == .idle { immediateInstallationPending = false }
            onUpdateCycleFinished?()
        }
    }

    func updater(
        _ updater: SPUUpdater,
        shouldPostponeRelaunchForUpdate item: SUAppcastItem,
        untilInvokingBlock installHandler: @escaping () -> Void
    ) -> Bool {
        immediateInstallationPending = true
        Task { @MainActor in
            guard let installationLifecycle else {
                showPreparationFailure()
                installHandler()
                return
            }
            let ready = await installationLifecycle.prepare()
            guard installationLifecycle.state == .prepared || installationLifecycle.state == .failed else { return }
            // Re-entering Sparkle checks mayRelaunch again, aborting a failed preparation.
            installHandler()
            if !ready {
                await installationLifecycle.finishCycle()
                showPreparationFailure()
            }
        }
        return true
    }

    func updaterShouldRelaunchApplication(_ updater: SPUUpdater) -> Bool {
        installationLifecycle?.mayRelaunch ?? false
    }

    func updater(_ updater: SPUUpdater, willInstallUpdate item: SUAppcastItem) {
        immediateInstallationPending = true
    }

    func updater(_ updater: SPUUpdater, willExtractUpdate item: SUAppcastItem) {
        installationIntent.receive(.extractionStarted)
    }

    func updater(_ updater: SPUUpdater, didExtractUpdate item: SUAppcastItem) {
        installationIntent.receive(.readyToInstall)
    }

    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) {
        let failure = error as NSError
        if failure.domain == SUSparkleErrorDomain,
            failure.code >= Int(SUError.unarchivingError.rawValue),
            failure.code < Int(SUError.incorrectAPIUsageError.rawValue),
            failure.code != Int(SUError.installationAuthorizeLaterError.rawValue)
        {
            installationIntent.receive(.installationFailed)
        }
    }

    func updater(
        _ updater: SPUUpdater,
        willInstallUpdateOnQuit item: SUAppcastItem,
        immediateInstallationBlock immediateInstallHandler: @escaping () -> Void
    ) -> Bool {
        installationIntent.receive(.readyToInstall)
        return false
    }

    /// Covers install-on-quit and resumed installations that skip Sparkle's postponement hook.
    func prepareForUpdateTermination() async -> Bool {
        guard let installationLifecycle else { return false }
        let ready = await installationLifecycle.prepare(for: .applicationTermination)
        if !ready {
            await installationLifecycle.finishCycle()
            showPreparationFailure()
        }
        return ready && installationLifecycle.state == .prepared
    }

    private func showPreparationFailure() {
        logger.error("Software update cancelled because the Agent could not be safely stopped")
        let alert = NSAlert()
        alert.messageText = "Could not prepare the update"
        alert.informativeText =
            "MacDNS could not finish stopping its services. Please wait for any pending changes and try the update again."
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    func updater(
        _ updater: SPUUpdater,
        userDidMake choice: SPUUserUpdateChoice,
        forUpdate update: SUAppcastItem,
        state: SPUUserUpdateState
    ) {
        if choice == .skip, state.stage == .installing {
            installationIntent.receive(.skipped)
        }
        if choice == .dismiss {
            installationIntent.receive(.dismissed)
            promptHistory.recordPrompt(version: update.displayVersionString)
        }
    }

    var supportsGentleScheduledUpdateReminders: Bool { true }

    func standardUserDriverShouldHandleShowingScheduledUpdate(
        _ update: SUAppcastItem,
        andInImmediateFocus immediateFocus: Bool
    ) -> Bool {
        false
    }

    func standardUserDriverWillHandleShowingUpdate(
        _ handleShowingUpdate: Bool,
        forUpdate update: SUAppcastItem,
        state: SPUUserUpdateState
    ) {
        if state.stage == .installing {
            installationIntent.receive(.readyToInstall)
        } else if state.stage == .downloaded {
            installationIntent.receive(.downloadedUpdateResumed)
        }
        if !handleShowingUpdate {
            // Focus the validated update already held by Sparkle, without opening Settings.
            checkForUpdates()
        }
        promptHistory.recordPrompt(version: update.displayVersionString)
        lastDiscoveryCompletedAt = Date()
        completeAutomaticCheck(delivered: true)
    }

    private func completeAutomaticCheck(delivered: Bool) {
        let completion = automaticCheckCompletion
        automaticCheckCompletion = nil
        completion?.resume(returning: delivered)
    }
}
