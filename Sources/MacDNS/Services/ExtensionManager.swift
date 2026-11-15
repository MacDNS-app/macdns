// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import NetworkExtension
import Shared
import SwiftUI
import SystemExtensions
import os.log

enum ExtensionError: Error, LocalizedError {
    case managerNotLoaded
    case activationRequiresReboot
    case activationFailed(String)
    case proxyEnableFailed(Error)
    case proxyDisableFailed(Error)

    var errorDescription: String? {
        switch self {
        case .managerNotLoaded:
            return "DNS Proxy Manager could not be loaded"
        case .activationRequiresReboot:
            return "System Extension activation requires restart"
        case .activationFailed(let reason):
            return "Failed to activate System Extension: \(reason)"
        case .proxyEnableFailed(let error):
            return "Failed to enable DNS Proxy: \(error.localizedDescription)"
        case .proxyDisableFailed(let error):
            return "Failed to disable DNS Proxy: \(error.localizedDescription)"
        }
    }
}

/// Tracks the replacement-drain state together with a monotonic token that
/// identifies the drain owning it.
///
/// A drain spans several `await`s, and the cancellation it asks for clears
/// `extensionRequestInProgress`, so a newer activation can take over the
/// extension lifecycle while the drain is still waiting on the old provider.
/// Every drain step re-validates its token, so a superseded drain cannot reach
/// `.drained`, restore the proxy, or resubmit a request.
struct ReplacementDrainGenerationPolicy: Equatable {
    private(set) var state: ReplacementDrainState = .idle
    private(set) var activeToken: UInt64?
    private var lastIssuedToken: UInt64 = 0

    var isActive: Bool { state != .idle }

    mutating func begin() -> UInt64 {
        lastIssuedToken &+= 1
        activeToken = lastIssuedToken
        state = .draining
        return lastIssuedToken
    }

    func owns(_ token: UInt64) -> Bool {
        activeToken == token
    }

    /// Promotes the drain to `.drained`. Mutates nothing and returns false when
    /// the token no longer owns the drain.
    mutating func markDrained(_ token: UInt64) -> Bool {
        guard owns(token) else { return false }
        state = .drained
        return true
    }

    /// Closes the drain owned by `token`. Returns false for a stale token.
    mutating func close(_ token: UInt64) -> Bool {
        guard owns(token) else { return false }
        closeActive()
        return true
    }

    /// Closes whichever drain is active. Used by terminal request callbacks,
    /// which are already generation-validated, and when a newer activation
    /// supersedes an in-flight drain.
    mutating func closeActive() {
        state = .idle
        activeToken = nil
    }
}

/// Outcome of a replacement drain's restore step, published so a failure is
/// visible instead of being swallowed by a log line.
enum ReplacementDrainOutcome: Equatable {
    case nothingToRestore
    case restored
    case restoreFailed(String)
    /// The drain was abandoned because a newer activation took over the
    /// extension lifecycle. Re-enable intent is preserved and replayed by that
    /// request's terminal callback.
    case superseded
}

/// Turns a published drain outcome into the App's reconciliation request.
///
/// A drain disables the Content Filter along with the proxy, so every outcome,
/// terminal or abandoned, must reconcile. Darwin notifications are lossy
/// wake-up hints, never a delivery guarantee, and nothing else restores the
/// filter.
struct ReplacementDrainReconciliationPolicy {
    let outcome: ReplacementDrainOutcome

    var shouldScheduleReconciliation: Bool {
        switch outcome {
        case .nothingToRestore, .restored, .restoreFailed, .superseded:
            return true
        }
    }

    var reason: String {
        switch outcome {
        case .nothingToRestore: return "replacement-drain-finished"
        case .restored: return "replacement-drain-restored"
        case .restoreFailed: return "replacement-drain-restore-failed"
        case .superseded: return "replacement-drain-superseded"
        }
    }
}

/// Re-enable intent recorded by a replacement drain.
///
/// The intent outlives a failed restore: clearing it before the enable is
/// confirmed drops the user's ON state with nothing guaranteed to replay it.
struct ReplacementDrainRecoveryPolicy: Equatable {
    var reenableProxyAfterReplacement = false
    var enableRequestedDuringDrain = false

    enum RestoreResult: Equatable {
        case succeeded
        case failed(String)
    }

    var shouldReenableProxy: Bool {
        reenableProxyAfterReplacement || enableRequestedDuringDrain
    }

    mutating func recordRestoreResult(_ result: RestoreResult) -> ReplacementDrainOutcome {
        switch result {
        case .succeeded:
            reenableProxyAfterReplacement = false
            enableRequestedDuringDrain = false
            return .restored
        case .failed(let message):
            // Intent stays pending so a later reconciliation retries.
            return .restoreFailed(message)
        }
    }
}

/// Whether a request that reached the user approval stage restores the proxy a
/// replacement drain disabled. The prompt can stay unanswered indefinitely, so
/// protection comes back now instead of at the terminal callback. A drain still
/// waiting on the old provider owns the proxy and restores it itself.
struct ReplacementDrainApprovalPolicy {
    let drainState: ReplacementDrainState
    let recovery: ReplacementDrainRecoveryPolicy

    var shouldRestoreProxy: Bool {
        switch drainState {
        case .draining: return false
        case .drained: return true
        case .idle: return recovery.shouldReenableProxy
        }
    }
}

@MainActor
class ExtensionManager: NSObject, ObservableObject {
    static let shared = ExtensionManager()

    /// Reported when the activation watchdog expires. Distinct from the Content
    /// Filter message so the two watchdogs are never confused.
    static let activationTimeoutMessage = "System Extension activation timed out with no response"

    private let logger = Logger(subsystem: "app.macdns", category: "ExtensionManager")
    private let extensionIdentifier = DNSProxyConfigurationPolicy.providerBundleIdentifier

    private let filterManager = FilterManager.shared

    @Published var isInstalled: Bool = false
    @Published var isActive: Bool = false
    @Published var proxyEnabled: Bool = false
    @Published var needsUserApproval: Bool = false
    @Published var activationRequiresRestart: Bool = false
    @Published var lastError: String?
    /// Last terminal outcome of a replacement drain's restore step.
    @Published var lastReplacementDrainOutcome: ReplacementDrainOutcome?
    /// True when the last drain did not confirm the complete provider handoff:
    /// either proxy disable failed or a provider required to release the
    /// proxy-control endpoint did not exit. Cleared by the next confirmed drain.
    @Published private(set) var replacementDrainUnconfirmed = false
    /// True once an activation request completed in this process. Reset by
    /// Uninstall, which deactivates the extension outside this manager.
    @Published private(set) var systemExtensionActivated = false
    /// Set while the first-run window owns the attempt, so a late approval
    /// leaves the DNS Proxy registration to the window's gated `activate`.
    var defersLateProviderRegistration = false

    private let activationCoordinator = ActivationRequestCoordinator(
        timeoutNanoseconds: 60_000_000_000,
        timeoutError: { ExtensionError.activationFailed("System Extension approval timed out") }
    )
    private var configurationObserver: NSObjectProtocol?

    private var extensionRequestInProgress = false

    /// Drain-before-replace state for the sysext upgrade endpoint race, with the
    /// token that guards drain work resuming after an await.
    private var drainGeneration = ReplacementDrainGenerationPolicy()
    /// Re-enable intent the drain must replay once the replacement finishes.
    private var drainRecovery = ReplacementDrainRecoveryPolicy()

    /// True while a system extension activation/replace is mid-flight. Used to
    /// suppress the stale-version restart notice during a normal update window.
    var isActivationInProgress: Bool { extensionRequestInProgress }

    /// True while a replacement drain owns the proxy configuration. Enable
    /// requests are deferred and replayed by the drain when it finishes.
    var isReplacementDrainActive: Bool { drainGeneration.isActive }

    /// CFBundleVersion of the DNS Proxy extension shipped inside this app bundle,
    /// the version the system should be running. Compared against the version the
    /// live provider reports to detect a stale extension awaiting restart.
    var bundledExtensionVersion: String? {
        let url = Bundle.main.bundleURL.appendingPathComponent(
            "Contents/Library/SystemExtensions/\(extensionIdentifier).systemextension/Contents/Info.plist"
        )
        guard let plist = NSDictionary(contentsOf: url) else { return nil }
        return plist["CFBundleVersion"] as? String
    }

    private override init() {
        super.init()
        Task {
            await updateStatus()
            await checkForExtensionUpdate()
        }
    }

    deinit {
        if let observer = configurationObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    // MARK: - Extension Approval Check

    /// Submits an activation request to check approval. A request that needs
    /// approval opens System Settings from `requestNeedsUserApproval`.
    func ensureApproved() async {
        guard !extensionRequestInProgress else {
            logger.debug("Extension request already in progress, skipping ensureApproved")
            return
        }
        guard !drainGeneration.isActive else {
            logger.info("Extension check deferred: replacement drain in progress")
            return
        }

        logger.info("Checking if System Extension is approved...")
        supersedeReplacementDrainIfNeeded()
        extensionRequestInProgress = true

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self

        submitActivationRequest(request)
    }

    // MARK: - Extension Update Check

    /// Runs at launch and after enabling the proxy, so the installed extension
    /// matches the bundled one.
    private func checkForExtensionUpdate() async {
        // An installed configuration is the trigger, not an enabled one. Submit
        // the upgrade before a later enable can launch the stale provider. The
        // replacement policy handles any running-provider handoff.
        guard isInstalled else {
            logger.info("Extension update check skipped - no DNS Proxy configuration installed")
            return
        }

        guard !extensionRequestInProgress else {
            logger.debug("Extension request already in progress, skipping update check")
            return
        }
        guard !drainGeneration.isActive else {
            logger.info("Extension check deferred: replacement drain in progress")
            return
        }

        logger.info("Checking for extension update...")
        supersedeReplacementDrainIfNeeded()
        extensionRequestInProgress = true

        // The system calls actionForReplacingExtension when the bundled
        // extension differs from the installed one.
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self

        submitActivationRequest(request)
    }

    // MARK: - Status

    func updateStatus() async {
        do {
            _ = try await refreshProxyStatus()
        } catch {
            logger.error("Failed to load DNS Proxy status: \(error.localizedDescription, privacy: .public)")
        }
    }

    @discardableResult
    func refreshProxyStatus() async throws -> Bool {
        let manager = NEDNSProxyManager.shared()
        try await manager.loadFromPreferences()
        let enabled = applyAuthoritativeStatus(from: manager)
        setupConfigurationObserver()
        return enabled
    }

    @discardableResult
    private func applyAuthoritativeStatus(from manager: NEDNSProxyManager) -> Bool {
        let isConfigured = DNSProxyConfigurationPolicy.isConfigured(
            providerBundleIdentifier: manager.providerProtocol?.providerBundleIdentifier
        )
        let enabled = manager.isEnabled

        if isActive != isConfigured || proxyEnabled != enabled {
            let statusSummary = "configured=\(isConfigured), enabled=\(enabled)"
            logger.debug("DNS Proxy status: \(statusSummary, privacy: .public)")
        }

        isInstalled = isConfigured
        isActive = isConfigured
        proxyEnabled = enabled
        return enabled
    }

    private func setupConfigurationObserver() {
        if let observer = configurationObserver {
            NotificationCenter.default.removeObserver(observer)
        }

        configurationObserver = NotificationCenter.default.addObserver(
            forName: .NEDNSProxyConfigurationDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                await self?.updateStatus()
            }
        }
    }

    // MARK: - System Extension Activation

    /// Activates the System Extension and configures the DNS Proxy. Prompts for
    /// approval in System Settings when needed.
    func activate(beforeRegistering: (@MainActor () async throws -> Void)? = nil) async throws {
        if extensionRequestInProgress {
            logger.info("Extension request already in progress, waiting for completion...")
            try await waitForActivationCompletion()
            try await beforeRegistering?()
            try await registerProxyProvider()
            return
        }

        logger.info("Activating System Extension...")
        supersedeReplacementDrainIfNeeded()
        extensionRequestInProgress = true

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self

        try await waitForActivationCompletion {
            self.submitActivationRequest(request)
        }

        try await beforeRegistering?()
        try await registerProxyProvider()
    }

    func markSystemExtensionDeactivated() {
        systemExtensionActivated = false
    }

    private func waitForActivationCompletion(submitRequest: (@MainActor () -> Void)? = nil) async throws {
        try await activationCoordinator.waitForCompletion(submitRequest: submitRequest) {
            self.extensionRequestInProgress = false
        }
    }

    private func submitActivationRequest(_ request: OSSystemExtensionRequest) {
        activationRequiresRestart = false
        activationCoordinator.submitRequest(request) { [weak self] in
            Task { @MainActor in
                await self?.handleActivationRequestTimeout()
            }
        }
    }

    /// No terminal callback or approval request ever arrived for a submitted
    /// activation, so the system dropped it. Close the request, fail
    /// the waiters, and restore whatever a drain disabled. A request waiting for
    /// approval restores it in `requestNeedsUserApproval` instead, so either way
    /// the proxy is never left off while the persisted toggle still says ON.
    private func handleActivationRequestTimeout() async {
        let message = Self.activationTimeoutMessage
        logger.error("\(message, privacy: .public)")
        extensionRequestInProgress = false
        activationRequiresRestart = false
        lastError = message
        _ = finishActivationContinuations(.failure(ExtensionError.activationFailed(message)))
        await restoreProxyAfterReplacementIfNeeded()
    }

    /// A newly submitted activation takes over the extension lifecycle, so any
    /// drain still waiting on the old provider is abandoned and cannot mutate
    /// shared state or resubmit. Recorded re-enable intent is preserved
    /// and replayed by the new request's terminal callback.
    private func supersedeReplacementDrainIfNeeded() {
        guard drainGeneration.isActive else { return }
        logger.warning("A new activation request superseded the in-flight replacement drain")
        drainGeneration.closeActive()
    }

    private func shouldHandleActivationCallback(for request: OSSystemExtensionRequest) -> Bool {
        guard activationCoordinator.shouldHandleCallback(for: request) else {
            logger.debug("Ignoring stale DNS Proxy activation callback")
            return false
        }

        return true
    }

    private func shouldApplyActivationStatusUpdate(for request: OSSystemExtensionRequest) -> Bool {
        guard activationCoordinator.shouldApplyStatusUpdate(for: request) else {
            logger.debug("Ignoring stale DNS Proxy activation status update")
            return false
        }

        return true
    }

    private func finishActivationContinuations(_ result: Result<Void, Error>) -> Bool {
        activationCoordinator.finish(result)
    }

    /// Registers the extension with NEDNSProxyManager (one-time setup).
    /// Leaves the proxy off unless `preserveExistingEnabledState` keeps an
    /// already enabled one. `enableProxy()` turns it on once the resolver runs.
    private func registerProxyProvider(preserveExistingEnabledState: Bool = false) async throws {
        let manager = NEDNSProxyManager.shared()

        try await manager.loadFromPreferences()
        let existingProviderMatches = manager.providerProtocol?.providerBundleIdentifier == extensionIdentifier
        let existingProxyEnabled = existingProviderMatches && manager.isEnabled

        let proxyProtocol = NEDNSProxyProviderProtocol()
        proxyProtocol.providerBundleIdentifier = extensionIdentifier
        proxyProtocol.serverAddress = "127.0.0.1"  // Not used but required by API
        let registrationPolicy = DNSProxyRegistrationPolicy(
            preserveExistingEnabledState: preserveExistingEnabledState,
            existingProxyEnabled: existingProxyEnabled
        )

        manager.providerProtocol = proxyProtocol
        manager.localizedDescription = "MacDNS DNS Proxy"
        manager.isEnabled = registrationPolicy.shouldEnableProxyDuringRegistration

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()

        // Extension is now configured. The app enables the proxy only after the resolver is running.
        _ = applyAuthoritativeStatus(from: manager)
        setupConfigurationObserver()

        logger.info("System Extension ready")
    }

    // MARK: - Proxy Control

    /// The Content Filter is controlled separately through `enableContentFilter()`.
    func enableProxy() async throws {
        guard !drainGeneration.isActive else {
            drainRecovery.enableRequestedDuringDrain = true
            logger.info(
                "Enable skipped: replacement drain in progress or drained; proxy will be restored by the drain once it finishes"
            )
            return
        }

        logger.info("Enabling DNS Proxy...")

        let manager = NEDNSProxyManager.shared()

        do {
            try await manager.loadFromPreferences()

            guard
                DNSProxyConfigurationPolicy.isConfigured(
                    providerBundleIdentifier: manager.providerProtocol?.providerBundleIdentifier
                )
            else {
                throw ExtensionError.managerNotLoaded
            }

            if !manager.isEnabled {
                manager.isEnabled = true
                try await manager.saveToPreferences()
            }

            try await manager.loadFromPreferences()
            let enabled = applyAuthoritativeStatus(from: manager)
            setupConfigurationObserver()

            guard enabled else {
                throw NSError(
                    domain: "MacDNS",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "DNS Proxy remained disabled after enable request"]
                )
            }

            logger.info("DNS Proxy enabled")

            // An app launched with the proxy disabled skipped the launch check.
            await checkForExtensionUpdate()
        } catch {
            logger.error("Failed to enable DNS Proxy: \(error.localizedDescription, privacy: .public)")
            throw ExtensionError.proxyEnableFailed(error)
        }
    }

    // MARK: - Content Filter Control

    func enableContentFilter() async throws {
        try Task.checkCancellation()

        if !filterManager.extensionActivated {
            try await filterManager.activate()
            try Task.checkCancellation()
        }

        try await filterManager.enableFilter()
        try Task.checkCancellation()

        guard filterManager.filterEnabled else {
            throw FilterError.activationFailed("Content Filter configuration did not become enabled")
        }
    }

    func disableContentFilter() async throws {
        try await filterManager.disableFilter()
    }

    /// Keeps the configuration, so `isActive` stays true.
    func disableProxy() async throws {
        logger.info("Disabling DNS Proxy...")

        let manager = NEDNSProxyManager.shared()

        do {
            try await manager.loadFromPreferences()

            if manager.isEnabled {
                manager.isEnabled = false
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
            }

            let enabled = applyAuthoritativeStatus(from: manager)
            setupConfigurationObserver()
            guard !enabled else {
                throw NSError(
                    domain: "MacDNS",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "DNS Proxy remained enabled after disable request"]
                )
            }

            logger.info("DNS Proxy disabled")

            do {
                try await filterManager.disableFilter()
            } catch {
                logger.warning("Failed to disable Content Filter: \(error.localizedDescription, privacy: .public)")
            }
        } catch {
            logger.error("Failed to disable DNS Proxy: \(error.localizedDescription, privacy: .public)")
            throw ExtensionError.proxyDisableFailed(error)
        }
    }

    // MARK: - Replacement Drain

    /// Disables the proxy config, waits for the provider that owns the
    /// proxy-control Mach endpoint to exit, then resubmits the replacement
    /// activation.
    private func runReplacementDrain(token: UInt64) async {
        var proxyDisableConfirmed = true
        do {
            if proxyEnabled {
                // Record the intent immediately: if this drain is superseded
                // or disableProxy partially commits before throwing, the enable
                // must still be replayed.
                drainRecovery.reenableProxyAfterReplacement = true
                try await disableProxy()
            }
        } catch {
            proxyDisableConfirmed = false
            logger.error(
                "Replacement drain: disable failed: \(error.localizedDescription, privacy: .public)"
            )
        }

        guard drainGeneration.owns(token) else {
            abandonSupersededDrain("while disabling the proxy")
            return
        }

        let providerExited =
            await DNSProxyProviderProcessInspector.waitForProviderExit(timeout: 30)

        // Publish only while the token still owns the drain. A drain superseded
        // during the provider-exit check would otherwise overwrite the signal
        // the newer drain is about to set, and the App drives restartRequired
        // and bounce suppression straight off that value.
        guard drainGeneration.markDrained(token) else {
            abandonSupersededDrain("while completing the provider handoff")
            return
        }

        publishDrainConfirmation(
            ReplacementDrainConfirmationPolicy(
                proxyDisableConfirmed: proxyDisableConfirmed,
                providerExited: providerExited
            )
        )

        guard !extensionRequestInProgress else {
            logger.warning("Replacement drain: another extension request is in flight")
            // No resubmission will happen on this drain cycle, so the drain
            // must self-close: restore whatever it disabled and reset to
            // .idle, and fail any activate() waiters since nothing else
            // will resolve them.
            await restoreProxyAfterReplacement(token: token)
            _ = finishActivationContinuations(
                .failure(
                    ExtensionError.activationFailed(
                        "Replacement drain abandoned: another request was already in flight")))
            return
        }
        extensionRequestInProgress = true
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        submitActivationRequest(request)
    }

    private nonisolated static func isRequestCanceled(_ error: Error) -> Bool {
        let nsError = error as NSError
        return nsError.domain == OSSystemExtensionErrorDomain
            && nsError.code == OSSystemExtensionError.requestCanceled.rawValue
    }

    /// Restores the proxy enabled-state the drain removed. Called after the
    /// replacement finishes (or fails) so protection never stays silently off.
    /// Terminal request callbacks are already generation-validated, so they close
    /// whichever drain is active.
    @discardableResult
    private func restoreProxyAfterReplacementIfNeeded() async -> ReplacementDrainOutcome {
        drainGeneration.closeActive()
        return await restoreProxyForDrain()
    }

    /// Restore driven by the drain task itself, which must prove it still owns
    /// the drain before touching the proxy configuration.
    private func restoreProxyAfterReplacement(token: UInt64) async {
        guard drainGeneration.close(token) else {
            abandonSupersededDrain("before restore; leaving it to the new request")
            return
        }
        _ = await restoreProxyForDrain()
    }

    /// A drain that lost ownership restores nothing, so it must still hand the
    /// App a reconciliation trigger: it disabled the Content Filter and only a
    /// deterministic signal brings it back.
    private func abandonSupersededDrain(_ context: String) {
        logger.warning("Replacement drain superseded \(context, privacy: .public)")
        publishDrainOutcome(.superseded)
    }

    /// Replays the recorded re-enable intent. The intent is only cleared once the
    /// enable is confirmed, so a failure stays pending for the next
    /// reconciliation instead of silently leaving the proxy off.
    private func restoreProxyForDrain() async -> ReplacementDrainOutcome {
        guard drainRecovery.shouldReenableProxy else {
            return publishDrainOutcome(.nothingToRestore)
        }

        do {
            try await enableProxy()
            return publishDrainOutcome(drainRecovery.recordRestoreResult(.succeeded))
        } catch {
            let message = error.localizedDescription
            logger.error(
                "Failed to re-enable DNS Proxy after replacement: \(message, privacy: .public)"
            )
            return publishDrainOutcome(drainRecovery.recordRestoreResult(.failed(message)))
        }
    }

    /// Publishes whether the drain preceding the replacement was confirmed. The
    /// replacement is submitted either way, so this is the earliest moment the
    /// App can surface an incomplete handoff.
    private func publishDrainConfirmation(_ confirmation: ReplacementDrainConfirmationPolicy) {
        replacementDrainUnconfirmed = !confirmation.isConfirmed
        guard let reason = confirmation.unconfirmedReason else { return }
        logger.warning(
            "Replacement drain not confirmed (\(reason, privacy: .public)); replacing anyway, restart required to complete provider handoff"
        )
    }

    @discardableResult
    private func publishDrainOutcome(_ outcome: ReplacementDrainOutcome) -> ReplacementDrainOutcome {
        lastReplacementDrainOutcome = outcome
        if case .restoreFailed(let message) = outcome {
            lastError = message
        }
        return outcome
    }

    // MARK: - Helper Methods

    func openExtensionsSettings() {
        // macOS 14+: Login Items & Extensions > Network Extensions
        if let url = URL(
            string:
                "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point"
        ) {
            NSWorkspace.shared.open(url)
        }
    }

    func reload() async {
        await updateStatus()
    }
}

// MARK: - OSSystemExtensionRequestDelegate

extension ExtensionManager: OSSystemExtensionRequestDelegate {
    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        // Delegate callbacks arrive on the main queue (activation requests are
        // created with queue: .main), so main-actor state is safely accessible.
        let plan = MainActor.assumeIsolated { () -> (ExtensionReplacementDrainPolicy.Decision, UInt64?) in
            // A stale request must never start a drain or touch drain state.
            guard self.shouldApplyActivationStatusUpdate(for: request) else {
                return (.replaceNow, nil)
            }
            let decision = ExtensionReplacementDrainPolicy(
                providerRunning: DNSProxyProviderProcessInspector.isProviderRunning(),
                drainState: self.drainGeneration.state
            ).decision
            switch decision {
            case .replaceNow:
                return (decision, nil)
            case .cancelAndDrain:
                return (decision, self.drainGeneration.begin())
            }
        }
        switch plan.0 {
        case .replaceNow:
            Task { @MainActor in
                self.logger.info(
                    "Replacing extension: \(existing.bundleShortVersion, privacy: .public) (\(existing.bundleVersion, privacy: .public)) → \(ext.bundleShortVersion, privacy: .public) (\(ext.bundleVersion, privacy: .public))"
                )
            }
            return .replace
        case .cancelAndDrain:
            guard let token = plan.1 else { return .replace }
            Task { @MainActor in
                self.logger.info(
                    "Old DNS Proxy provider still running; draining before replacing \(existing.bundleVersion, privacy: .public) → \(ext.bundleVersion, privacy: .public)"
                )
                await self.runReplacementDrain(token: token)
            }
            return .cancel
        }
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            guard self.shouldApplyActivationStatusUpdate(for: request) else { return }
            self.activationCoordinator.markAwaitingApproval(request)
            self.needsUserApproval = true
            self.logger.info("DNS Proxy System Extension requires user approval in System Settings")
            self.openExtensionsSettings()
            let drainApproval = ReplacementDrainApprovalPolicy(
                drainState: self.drainGeneration.state,
                recovery: self.drainRecovery
            )
            if drainApproval.shouldRestoreProxy {
                await self.restoreProxyAfterReplacementIfNeeded()
            }
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in
            guard self.shouldHandleActivationCallback(for: request) else { return }

            self.extensionRequestInProgress = false

            switch result {
            case .completed:
                self.logger.info("System Extension request completed")
                self.isInstalled = true
                self.systemExtensionActivated = true
                self.activationRequiresRestart = false
                let hadWaitingContinuations = self.finishActivationContinuations(.success(()))
                let policy = ExtensionActivationCompletionPolicy(
                    hadWaitingContinuations: hadWaitingContinuations,
                    providerConfigured: self.isActive,
                    registrationDeferred: self.defersLateProviderRegistration
                )
                if policy.shouldRegisterProviderAfterCompletion {
                    do {
                        try await self.registerProxyProvider(preserveExistingEnabledState: true)
                    } catch {
                        self.lastError = error.localizedDescription
                        self.logger.error(
                            "Failed to register DNS Proxy after late approval: \(error.localizedDescription, privacy: .public)"
                        )
                    }
                }
                await self.restoreProxyAfterReplacementIfNeeded()
                self.needsUserApproval = false
                return
            case .willCompleteAfterReboot:
                self.logger.info("System Extension will complete after reboot")
                self.activationRequiresRestart = true
                await self.restoreProxyAfterReplacementIfNeeded()
                _ = self.finishActivationContinuations(.failure(ExtensionError.activationRequiresReboot))
                self.needsUserApproval = false
                return
            @unknown default:
                self.logger.warning("Unknown System Extension result: \(String(describing: result), privacy: .public)")
                await self.restoreProxyAfterReplacementIfNeeded()
            }

            _ = self.finishActivationContinuations(.success(()))
            self.needsUserApproval = false
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            guard self.shouldHandleActivationCallback(for: request) else { return }

            self.needsUserApproval = false
            self.extensionRequestInProgress = false
            self.activationRequiresRestart = false

            if Self.isRequestCanceled(error), self.drainGeneration.state == .draining {
                // Expected: the .cancel answer drains the old provider, and the
                // drain task resubmits the activation when the drain finishes.
                // Pending activate() continuations stay unresolved here. The
                // resubmitted request's terminal callback, or the drain's own
                // abandonment or failure handling, resolves them, so callers
                // never see a failure for a cancel MacDNS caused.
                self.logger.info("Extension request canceled for replacement drain")
                return
            }

            let errorMessage = error.localizedDescription
            self.lastError = errorMessage
            self.logger.error("System Extension request failed: \(errorMessage, privacy: .public)")

            _ = self.finishActivationContinuations(.failure(ExtensionError.activationFailed(errorMessage)))

            if self.drainGeneration.state != .draining {
                // The request that owns the replacement failed. Restore
                // protection with the still-installed old extension rather than
                // staying off, and publish the outcome so the App reconciles.
                // `.idle` is included because a superseded drain leaves its
                // re-enable intent pending on this request.
                await self.restoreProxyAfterReplacementIfNeeded()
            }
        }
    }
}
