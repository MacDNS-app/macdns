// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import AppKit
import Foundation
import NetworkExtension
import SystemExtensions
import os.log

enum FilterError: Error, LocalizedError {
    case activationFailed(String)
    case activationRequiresReboot
    case configurationFailed(String)

    var errorDescription: String? {
        switch self {
        case .activationFailed(let reason):
            return "Failed to activate Content Filter: \(reason)"
        case .activationRequiresReboot:
            return "Content Filter activation requires restart"
        case .configurationFailed(let reason):
            return "Content Filter configuration failed: \(reason)"
        }
    }
}

@MainActor
final class ContentFilterPreferenceMutationCoordinator {
    private var operationInProgress = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    var pendingOperationCount: Int { waiters.count }

    func perform(
        respectCancellation: Bool = false,
        _ operation: @MainActor () async throws -> Void
    ) async throws {
        if respectCancellation {
            try Task.checkCancellation()
        }
        await acquire()
        defer { release() }

        if respectCancellation {
            try Task.checkCancellation()
        }
        try await operation()
    }

    private func acquire() async {
        guard operationInProgress else {
            operationInProgress = true
            return
        }

        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    private func release() {
        guard !waiters.isEmpty else {
            operationInProgress = false
            return
        }

        waiters.removeFirst().resume()
    }
}

/// Manages the Content Filter system extension for DoH/DoT blocking
@MainActor
final class FilterManager: NSObject, ObservableObject {
    static let shared = FilterManager()

    @Published private(set) var isInstalled = false
    @Published private(set) var filterEnabled = false
    @Published private(set) var needsUserApproval = false
    @Published private(set) var extensionActivated = false
    @Published private(set) var activationRequiresRestart = false

    /// Reported when the activation watchdog expires. Names the Content Filter
    /// so it is never mistaken for the DNS Proxy watchdog in logs or in a
    /// caller's failure handling.
    static let activationTimeoutMessage = "Content Filter activation timed out with no response"

    private let logger = Logger(subsystem: "app.macdns", category: "filter-manager")
    private let extensionIdentifier = "app.macdns.contentfilter"
    private let preferenceMutationCoordinator = ContentFilterPreferenceMutationCoordinator()

    private var activationInProgress = false
    private let activationCoordinator = ActivationRequestCoordinator(
        timeoutNanoseconds: 60_000_000_000,
        timeoutError: { FilterError.activationFailed("Content Filter approval timed out") }
    )

    override init() {
        super.init()
        Task { await updateStatus() }

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(filterConfigurationDidChange),
            name: .NEFilterConfigurationDidChange,
            object: nil
        )
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    @objc private func filterConfigurationDidChange(_ notification: Notification) {
        Task { @MainActor in
            await updateStatus()
        }
    }

    func activate() async throws {
        guard !extensionActivated else {
            logger.debug("Content Filter activation skipped (already activated)")
            return
        }

        if activationInProgress {
            logger.debug("Content Filter activation already in progress, waiting for completion")
            try await waitForActivationCompletion()
            return
        }

        activationInProgress = true
        logger.info("Activating Content Filter extension")
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self

        try await waitForActivationCompletion {
            self.submitActivationRequest(request)
        }
    }

    func enableFilter() async throws {
        try await preferenceMutationCoordinator.perform(respectCancellation: true) {
            let manager = NEFilterManager.shared()
            try await manager.loadFromPreferences()

            let config = NEFilterProviderConfiguration()
            config.filterSockets = true
            config.filterDataProviderBundleIdentifier = extensionIdentifier
            config.organization = "MacDNS"

            manager.providerConfiguration = config
            manager.isEnabled = true
            manager.localizedDescription = "MacDNS DoH/DoT Filter"

            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            applyStatus(from: manager)
            logger.info("Content Filter enabled")
        }
    }

    func disableFilter() async throws {
        try await preferenceMutationCoordinator.perform {
            let manager = NEFilterManager.shared()
            try await manager.loadFromPreferences()

            if manager.isEnabled {
                manager.isEnabled = false
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
            }

            applyStatus(from: manager)

            guard !manager.isEnabled else {
                throw FilterError.configurationFailed(
                    "Content Filter remained enabled after disable request"
                )
            }
            logger.info("Content Filter disabled")
        }
    }

    func removeFilter() async throws {
        try await preferenceMutationCoordinator.perform {
            let manager = NEFilterManager.shared()

            try await manager.loadFromPreferences()

            guard let config = manager.providerConfiguration,
                config.filterDataProviderBundleIdentifier?.contains("macdns") == true
            else {
                logger.info("No MacDNS Content Filter config found to remove")
                return
            }

            if manager.isEnabled {
                manager.isEnabled = false
                do {
                    try await manager.saveToPreferences()
                } catch {
                    logger.warning(
                        "Failed to disable Content Filter: \(error.localizedDescription, privacy: .public)"
                    )
                    // Continue with removal even if disable fails
                }
            }

            do {
                try await manager.removeFromPreferences()
                logger.info("Removed Content Filter config")
            } catch {
                logger.warning(
                    "removeFromPreferences failed: \(error.localizedDescription, privacy: .public), forcing reset..."
                )
                manager.providerConfiguration = nil
                try await manager.saveToPreferences()
                logger.info("Forced Content Filter config reset (providerConfiguration = nil)")
            }

            await updateStatusWithoutSerialization()
        }
    }

    func updateStatus() async {
        do {
            try await preferenceMutationCoordinator.perform {
                await updateStatusWithoutSerialization()
            }
        } catch is CancellationError {
            return
        } catch {
            logger.error(
                "Failed to serialize filter status refresh: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    @discardableResult
    func refreshStatus() async throws -> Bool {
        var enabled = false
        try await preferenceMutationCoordinator.perform {
            enabled = try await refreshStatusWithoutSerialization()
        }
        return enabled
    }

    private func updateStatusWithoutSerialization() async {
        do {
            _ = try await refreshStatusWithoutSerialization()
        } catch {
            logger.error("Failed to load filter status: \(error.localizedDescription, privacy: .public)")
            isInstalled = false
            filterEnabled = false
        }
    }

    private func refreshStatusWithoutSerialization() async throws -> Bool {
        let manager = NEFilterManager.shared()
        try await manager.loadFromPreferences()
        applyStatus(from: manager)
        return filterEnabled
    }

    private func applyStatus(from manager: NEFilterManager) {
        isInstalled = manager.providerConfiguration != nil
        filterEnabled = manager.isEnabled
    }

    private func finishActivation(_ result: Result<Void, Error>) {
        activationInProgress = false
        activationCoordinator.finish(result)
    }

    private func waitForActivationCompletion(submitRequest: (@MainActor () -> Void)? = nil) async throws {
        try await activationCoordinator.waitForCompletion(submitRequest: submitRequest) {
            self.activationInProgress = false
        }
    }

    private func submitActivationRequest(_ request: OSSystemExtensionRequest) {
        activationRequiresRestart = false
        activationCoordinator.submitRequest(request) { [weak self] in
            self?.handleActivationRequestTimeout()
        }
    }

    /// No terminal callback or approval request ever arrived for a submitted
    /// Content Filter activation, so the system dropped the request.
    /// Close the request so its generation stops accepting late callbacks and no
    /// waiter is left believing the filter is still coming up.
    private func handleActivationRequestTimeout() {
        logger.error("\(Self.activationTimeoutMessage, privacy: .public)")
        activationRequiresRestart = false
        finishActivation(.failure(FilterError.activationFailed(Self.activationTimeoutMessage)))
    }

    private func shouldHandleActivationCallback(for request: OSSystemExtensionRequest) -> Bool {
        guard activationCoordinator.shouldHandleCallback(for: request) else {
            logger.debug("Ignoring stale Content Filter activation callback")
            return false
        }

        return true
    }

    private func shouldApplyActivationStatusUpdate(for request: OSSystemExtensionRequest) -> Bool {
        guard activationCoordinator.shouldApplyStatusUpdate(for: request) else {
            logger.debug("Ignoring stale Content Filter activation status update")
            return false
        }

        return true
    }
}

// MARK: - OSSystemExtensionRequestDelegate

extension FilterManager: OSSystemExtensionRequestDelegate {
    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        // Always replace with newer version
        return .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            guard shouldApplyActivationStatusUpdate(for: request) else { return }
            activationCoordinator.markAwaitingApproval(request)
            needsUserApproval = true
            logger.info("Content Filter extension needs user approval")
            openExtensionsSettings()
        }
    }

    private func openExtensionsSettings() {
        if let url = URL(
            string:
                "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point"
        ) {
            NSWorkspace.shared.open(url)
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in
            guard shouldHandleActivationCallback(for: request) else { return }

            needsUserApproval = false
            if result == .completed {
                extensionActivated = true
                activationRequiresRestart = false
                logger.info("Content Filter extension activation request completed")
                await updateStatus()
                finishActivation(.success(()))
            } else if result == .willCompleteAfterReboot {
                extensionActivated = false
                activationRequiresRestart = true
                logger.info("Content Filter extension activation will complete after reboot")
                await updateStatus()
                finishActivation(.failure(FilterError.activationRequiresReboot))
            } else {
                activationRequiresRestart = false
                logger.warning("Content Filter activation result: \(String(describing: result), privacy: .public)")
                await updateStatus()
                finishActivation(.failure(FilterError.activationFailed(String(describing: result))))
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            guard shouldHandleActivationCallback(for: request) else { return }

            needsUserApproval = false
            activationRequiresRestart = false
            logger.error("Content Filter extension activation failed: \(error.localizedDescription, privacy: .public)")
            await updateStatus()
            finishActivation(.failure(FilterError.activationFailed(error.localizedDescription)))
        }
    }
}
