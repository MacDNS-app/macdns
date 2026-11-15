// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import ServiceManagement
import SwiftUI
import os.log

enum AgentServiceRegistrationStatus: Equatable {
    case notRegistered
    case enabled
    case requiresApproval
    case notFound
    case unknown

    init(_ status: SMAppService.Status) {
        switch status {
        case .notRegistered:
            self = .notRegistered
        case .enabled:
            self = .enabled
        case .requiresApproval:
            self = .requiresApproval
        case .notFound:
            self = .notFound
        @unknown default:
            self = .unknown
        }
    }
}

/// Parses the tabular output of the no-argument `launchctl list`.
///
/// `launchctl list <label>` prints a legacy plist dictionary that always starts
/// with `{` whether or not the job owns a PID, so only the tabular form can
/// prove a job is running. Fails closed: a line must be exactly
/// `<pid>\t<status>\t<label>` with an exact label match and a positive numeric
/// PID before the job is reported running.
enum AgentLaunchctlListPolicy {
    static func isJobRunning(output: String, label: String) -> Bool {
        guard !label.isEmpty else { return false }

        for line in output.split(separator: "\n", omittingEmptySubsequences: true) {
            let columns = line.split(separator: "\t", omittingEmptySubsequences: false)
            guard columns.count == 3, String(columns[2]) == label else { continue }
            guard let pid = Int(columns[0]), pid > 0 else { return false }
            return true
        }

        return false
    }
}

/// Decides what `install()` must do for the current registration status.
///
/// Unregistering terminates a running LaunchAgent and re-registration can
/// require user approval again, so a confirmed-running enabled job must never
/// be touched. Only a confirmed-stopped enabled job is re-registered.
struct AgentInstallDecisionPolicy: Equatable {
    let status: AgentServiceRegistrationStatus
    let isJobRunning: Bool

    enum Decision: Equatable {
        case alreadyRunning
        case reregister
        case register
        case requiresApproval
        case unknownStatus
    }

    var decision: Decision {
        switch status {
        case .enabled:
            return isJobRunning ? .alreadyRunning : .reregister
        case .requiresApproval:
            return .requiresApproval
        case .notRegistered, .notFound:
            return .register
        case .unknown:
            return .unknownStatus
        }
    }
}

/// Decides whether `uninstall()` must unregister the agent.
///
/// An agent waiting for Login Items approval is still registered, and an
/// unknown status may hide a registration, so both are unregistered.
enum AgentUninstallDecisionPolicy {
    static func shouldUnregister(
        for status: AgentServiceRegistrationStatus
    ) -> Bool {
        switch status {
        case .enabled, .requiresApproval, .unknown:
            return true
        case .notRegistered, .notFound:
            return false
        }
    }
}

/// Runs one agent install at a time. A caller that arrives while an install
/// runs waits for it and sees the same error, because a second
/// `AgentInstaller.install()` could unregister the job the first one just
/// registered.
@MainActor
final class AgentInstallSerializer {
    private(set) var running: Task<Void, Error>?

    func run(_ install: @escaping @MainActor () async throws -> Void) async throws {
        if let running {
            return try await running.value
        }
        // Cleared by the task itself, so a caller that waited for it never
        // finds the finished install still registered as running.
        let task = Task { @MainActor in
            defer { running = nil }
            try await install()
        }
        running = task
        try await task.value
    }
}

enum AgentStateFileFallbackPolicy {
    static func canUseFallback(
        for status: AgentServiceRegistrationStatus
    ) -> Bool {
        switch status {
        case .notRegistered, .notFound, .requiresApproval:
            return true
        case .enabled, .unknown:
            return false
        }
    }
}

@MainActor
class AgentInstaller: ObservableObject {
    static let shared = AgentInstaller()

    @Published var status: SMAppService.Status = .notRegistered
    @Published var lastError: String?

    private static let agentLabel = "app.macdns.agent"
    private static let agentPlistName = "app.macdns.agent.plist"

    private let logger = Logger(subsystem: "app.macdns", category: "AgentInstaller")
    private let service: SMAppService

    private init() {
        service = SMAppService.agent(plistName: Self.agentPlistName)
        updateStatus()
    }

    // MARK: - Status Management

    private func updateStatus() {
        let oldStatus = status
        status = service.status
        if oldStatus != status {
            logger.info("Agent status: \(self.statusDescription, privacy: .public)")
        }
    }

    private var statusDescription: String {
        switch status {
        case .notRegistered:
            return "Not Registered"
        case .enabled:
            return "Enabled"
        case .requiresApproval:
            return "Requires Approval"
        case .notFound:
            return "Not Found"
        @unknown default:
            return "Unknown"
        }
    }

    // MARK: - Installation

    /// `SMAppService.register()` is synchronous and validates the bundle's code
    /// signature through the Security framework on the calling thread, so it
    /// must not run on the main thread. `SMAppService` is not `Sendable`, so the
    /// detached task builds its own instance instead of capturing `service`.
    private func registerOffMainThread() async throws {
        let plistName = Self.agentPlistName
        try await Task.detached {
            try SMAppService.agent(plistName: plistName).register()
        }.value
    }

    /// May require user approval in System Settings > General > Login Items.
    func install() async throws {
        logger.info("Attempting to install MacDNSAgent...")

        updateStatus()

        let decision = AgentInstallDecisionPolicy(
            status: AgentServiceRegistrationStatus(status),
            isJobRunning: status == .enabled ? isAgentJobRunning() : false
        ).decision

        switch decision {
        case .alreadyRunning:
            logger.info("Agent is already registered and running; nothing to install")
            return

        case .reregister:
            logger.info("Agent is registered but not running; re-registering...")

            // Unregister and re-register so launchd starts the stopped job.
            do {
                try await service.unregister()
                logger.info("Unregistered stale agent registration")
            } catch {
                logger.warning("Failed to unregister: \(error.localizedDescription, privacy: .public)")
            }

            logger.info("Re-registering agent...")
            do {
                try await registerOffMainThread()
                updateStatus()
                if status == .requiresApproval {
                    logger.warning("Agent re-registration succeeded but requires user approval")
                    lastError = "Please approve MacDNS in System Settings > General > Login Items"
                    throw AgentError.requiresApproval
                }
                logger.info("Agent re-registered, new status: \(self.statusDescription, privacy: .public)")
            } catch let error as AgentError {
                throw error
            } catch {
                logger.error("Failed to re-register agent: \(error.localizedDescription, privacy: .public)")
                throw AgentError.registrationFailed(error)
            }
            return

        case .requiresApproval:
            logger.warning("Agent requires user approval in System Settings")
            lastError = "Please approve MacDNS in System Settings > General > Login Items"
            throw AgentError.requiresApproval

        case .register:
            logger.info("Registering MacDNSAgent... (status: \(self.status.rawValue, privacy: .public))")
            do {
                try await registerOffMainThread()
                updateStatus()

                if status == .requiresApproval {
                    logger.warning("Registration succeeded but requires user approval")
                    lastError = "Please approve MacDNS in System Settings > General > Login Items"
                    throw AgentError.requiresApproval
                }

                logger.info(
                    "MacDNSAgent registered successfully (new status: \(self.status.rawValue, privacy: .public))"
                )

            } catch let error as AgentError {
                throw error
            } catch let error as NSError {
                let registrationError =
                    "Failed to register agent: \(error.localizedDescription) "
                    + "(domain: \(error.domain), code: \(error.code))"
                logger.error("\(registrationError, privacy: .public)")
                lastError = error.localizedDescription
                throw AgentError.registrationFailed(error)
            }

        case .unknownStatus:
            logger.error("Unknown agent status: \(String(describing: self.status), privacy: .public)")
            throw AgentError.unknownStatus
        }
    }

    // MARK: - Uninstallation

    /// Unregisters the MacDNSAgent. The async call completes after the old
    /// process has terminated and it is safe to register the service again.
    func uninstall() async throws {
        logger.info("Attempting to uninstall MacDNSAgent...")
        updateStatus()

        guard
            AgentUninstallDecisionPolicy.shouldUnregister(
                for: AgentServiceRegistrationStatus(status)
            )
        else {
            logger.info("Agent is not installed, nothing to uninstall")
            return
        }

        do {
            try await service.unregister()
            updateStatus()
            logger.info("MacDNSAgent unregistered successfully")

        } catch {
            logger.error("Failed to unregister agent: \(error.localizedDescription, privacy: .public)")
            lastError = error.localizedDescription
            throw AgentError.unregistrationFailed(error)
        }
    }

    // MARK: - Permissions & Status

    /// Checks whether launchd still has an enabled agent registration.
    func isRegistered() -> Bool {
        updateStatus()
        return status == .enabled
    }

    /// True when the agent is registered, enabled and its job is running.
    func isInstalled() -> Bool {
        updateStatus()

        // Even if SMAppService says .enabled, verify the agent is actually running
        guard status == .enabled else { return false }
        return isAgentJobRunning()
    }

    /// True only when the no-argument `launchctl list` table reports a live PID
    /// for the agent label.
    private func isAgentJobRunning() -> Bool {
        guard let output = launchctlListOutput() else { return false }
        return AgentLaunchctlListPolicy.isJobRunning(output: output, label: Self.agentLabel)
    }

    private func launchctlListOutput() -> String? {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["list"]

        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()

        do {
            try task.run()
            // The full table is far larger than the pipe buffer, so drain it
            // before waiting for exit.
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()

            guard task.terminationStatus == 0 else { return nil }
            return String(data: data, encoding: .utf8)
        } catch {
            logger.warning("Failed to check launchctl: \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    func canUseStateFileFallback() -> Bool {
        updateStatus()
        return AgentStateFileFallbackPolicy.canUseFallback(
            for: AgentServiceRegistrationStatus(status)
        )
    }

    func requiresApproval() -> Bool {
        updateStatus()
        return status == .requiresApproval
    }

    /// Opens Login Items > Background Items, where the user approves the agent.
    func openSystemSettings() {
        // macOS 14+: Login Items & Extensions > Background Items (for LaunchAgents)
        // Source: https://gist.github.com/rmcdongit/f66ff91e0dad78d4d6346a75ded4b751
        let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension?BackgroundItems")!
        NSWorkspace.shared.open(url)
    }

    func refreshStatus() {
        updateStatus()
    }

    /// Opens System Settings when the agent still needs user approval.
    func ensureApproved() {
        updateStatus()

        if status == .requiresApproval {
            logger.info("Agent requires approval - opening System Settings")
            openSystemSettings()
        }
    }
}

// MARK: - Errors

enum AgentError: LocalizedError {
    case requiresApproval
    case registrationFailed(Error)
    case unregistrationFailed(Error)
    case unknownStatus
    case softwareUpdateInProgress
    case servicesStopping

    var errorDescription: String? {
        switch self {
        case .requiresApproval:
            return "MacDNS Agent requires user approval in System Settings"
        case .registrationFailed(let error):
            return "Failed to register agent: \(error.localizedDescription)"
        case .unregistrationFailed(let error):
            return "Failed to unregister agent: \(error.localizedDescription)"
        case .unknownStatus:
            return "Unknown agent status"
        case .softwareUpdateInProgress:
            return "A MacDNS update is being installed"
        case .servicesStopping:
            return "MacDNS is stopping its services"
        }
    }

    var recoverySuggestion: String? {
        switch self {
        case .requiresApproval:
            return "Go to System Settings > General > Login Items and enable MacDNS"
        case .registrationFailed, .unregistrationFailed:
            return "Try restarting the application or check system logs for more details"
        case .unknownStatus:
            return "Contact support"
        case .softwareUpdateInProgress:
            return "Open MacDNS again once the update finishes"
        case .servicesStopping:
            return "Turn MacDNS on again once it finishes stopping"
        }
    }
}
