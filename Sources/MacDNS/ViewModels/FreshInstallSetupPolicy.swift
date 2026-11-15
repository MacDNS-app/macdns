// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

enum FreshInstallSetupOutcome: Equatable {
    /// macOS waits for an approval. The Enable that resumes after it reports again.
    case waitingForApproval
    case done
    case restartRequired
    case failed
}

/// Decides what a fresh install tells the user when an Enable attempt ends.
///
/// Active protection wins over every notice: a restart notice raised later by
/// the Content Filter or a stale provider must not alert a working install. A
/// finished enable without interception (captive portal bypass, provider not
/// reporting yet) is done as well, and the menu bar shows its status.
struct FreshInstallSetupPolicy: Equatable {
    let protectionActive: Bool
    let restartRequired: Bool
    let approvalRequired: Bool
    let enableCompleted: Bool

    /// Whether an Enable starting now belongs to the fresh install setup. The
    /// setup is tied to one DNS lifecycle generation. Turn On and its retry
    /// start it. The Enable that resumes after an approval continues it only
    /// when no other lifecycle ran since the attempt that waited, so a
    /// disable, Uninstall, update or license stop ends it.
    static func continuesSetup(
        startedAsFreshInstall: Bool,
        setupGeneration: UInt64?,
        currentGeneration: UInt64
    ) -> Bool {
        startedAsFreshInstall || setupGeneration == currentGeneration
    }

    /// Whether a late extension approval leaves the DNS Proxy registration to
    /// the Enable it resumes. Only while the window is open and that Enable
    /// would continue the setup, so a Disable or other lifecycle since the
    /// attempt that waited lets the approval register as without the window.
    static func defersLateProviderRegistration(
        windowOpen: Bool,
        setupGeneration: UInt64?,
        currentGeneration: UInt64
    ) -> Bool {
        windowOpen
            && continuesSetup(
                startedAsFreshInstall: false,
                setupGeneration: setupGeneration,
                currentGeneration: currentGeneration
            )
    }

    /// Whether an ended Enable attempt reports. It reports when it belongs to
    /// the setup and no later lifecycle replaced it. A failed start clears the
    /// desire to run DNS on its own, so the attempt is matched by its
    /// generation, never by that desire.
    static func reportsAttempt(
        setupGeneration: UInt64?,
        attemptGeneration: UInt64,
        currentGeneration: UInt64,
        isStopping: Bool,
        updateSuspended: Bool
    ) -> Bool {
        setupGeneration == attemptGeneration && attemptGeneration == currentGeneration && !isStopping
            && !updateSuspended
    }

    /// The setup generation after an attempt whose report was skipped because
    /// a later lifecycle replaced it. The setup ends with that attempt, unless
    /// a newer Enable already owns it.
    static func setupGenerationAfterSupersededAttempt(
        _ attemptGeneration: UInt64,
        setupGeneration: UInt64?
    ) -> UInt64? {
        setupGeneration == attemptGeneration ? nil : setupGeneration
    }

    /// Whether a Login Items approval resumes the Enable that hit it. A fresh
    /// install has no state for the lifecycle checks to act on, and a setup
    /// that waited may have loaded `state.json` with `isEnabled: false`, which
    /// those checks leave alone. A disable or Uninstall since the attempt
    /// clears the desire to run DNS or moves the lifecycle on.
    static func resumesEnableAfterAgentApproval(
        agentSetupRequired: Bool,
        setupGeneration: UInt64?,
        currentGeneration: UInt64,
        runtimeDNSDesired: Bool,
        isEnablingDNS: Bool,
        isStoppingDNS: Bool
    ) -> Bool {
        (agentSetupRequired || setupGeneration == currentGeneration) && runtimeDNSDesired && !isEnablingDNS
            && !isStoppingDNS
    }

    var outcome: FreshInstallSetupOutcome {
        if protectionActive { return .done }
        if restartRequired { return .restartRequired }
        if approvalRequired { return .waitingForApproval }
        if enableCompleted { return .done }
        return .failed
    }
}
