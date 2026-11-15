// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

enum AgentLifecycleGenerationPolicy {
    static func shouldReconcileRunningResolver(
        resolverRunning: Bool,
        acceptingCallbacks: Bool
    ) -> Bool {
        resolverRunning && !acceptingCallbacks
    }

    static func matches(
        lifecycleGeneration: UInt64,
        stopGeneration: UInt64,
        expectedLifecycleGeneration: UInt64,
        expectedStopGeneration: UInt64
    ) -> Bool {
        lifecycleGeneration == expectedLifecycleGeneration
            && stopGeneration == expectedStopGeneration
    }

    /// Whether a restore may start services after awaiting license validation.
    ///
    /// The await releases every lifecycle lock, so a stop or user disable can
    /// complete meanwhile. Restoring then would resurrect services the user
    /// already turned off.
    static func canRestoreAfterLicenseCheck(
        isEnabledAfterLicenseCheck: Bool,
        currentLifecycleGeneration: UInt64,
        currentStopGeneration: UInt64,
        capturedLifecycleGeneration: UInt64,
        capturedStopGeneration: UInt64,
        transitionInProgress: Bool
    ) -> Bool {
        guard isEnabledAfterLicenseCheck, !transitionInProgress else {
            return false
        }
        return matches(
            lifecycleGeneration: currentLifecycleGeneration,
            stopGeneration: currentStopGeneration,
            expectedLifecycleGeneration: capturedLifecycleGeneration,
            expectedStopGeneration: capturedStopGeneration
        )
    }
}

enum LicenseStatusChangeAction: Equatable {
    case restoreServices
    case stopServices
    case none
}

enum LicenseStatusChangePolicy {
    static func action(
        allowed: Bool,
        isRestoringServices: Bool,
        resolverRunning: Bool
    ) -> LicenseStatusChangeAction {
        guard allowed else { return .stopServices }
        guard !isRestoringServices, !resolverRunning else { return .none }
        return .restoreServices
    }
}
