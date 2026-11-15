// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

struct ForwardingTransitionSnapshot: Equatable {
    let stopGeneration: UInt64
    let transitionGeneration: UInt64
    let resolverRunning: Bool
    let forwardingEnabled: Bool

    var intent: ForwardingTransitionIntent {
        ForwardingTransitionIntent(
            stopGeneration: stopGeneration,
            transitionGeneration: transitionGeneration
        )
    }
}

struct ForwardingTransitionIntent: Equatable {
    let stopGeneration: UInt64
    let transitionGeneration: UInt64
}

enum ForwardingReadinessCommitResult: Equatable {
    case committed(wasBypassing: Bool)
    case stale
    case readinessRejected
}

enum ForwardingFailSafeCommitResult: Equatable {
    case published
    case noLongerNeeded
    case bypassRejected
}

enum DirectDoHRecoveryCompletionResult: Equatable {
    case committed(wasBypassing: Bool)
    case stale
    case disableRejected
    case readinessRejected
}

enum CompatibilityTransitionAction: Equatable {
    case keepScopedForwarding
    case keepApprovedBypass
    case restoreScopedForwardingFromBypass
    case establishScopedForwarding
}

enum CompatibilityTransitionPolicy {
    static func action(
        forwardingEnabled: Bool,
        fullBypassActive: Bool,
        portalCleared: Bool
    ) -> CompatibilityTransitionAction {
        if fullBypassActive {
            guard portalCleared else { return .keepApprovedBypass }
            return forwardingEnabled
                ? .restoreScopedForwardingFromBypass
                : .establishScopedForwarding
        }
        return forwardingEnabled
            ? .keepScopedForwarding
            : .establishScopedForwarding
    }
}

enum ForwardingTransitionPolicy {
    static func nextIntent(
        currentStopGeneration: UInt64,
        currentTransitionGeneration: UInt64,
        currentLifecycleGeneration: UInt64,
        callbackLifecycleGeneration: UInt64,
        acceptingCallbacks: Bool,
        isStopping: Bool,
        resolverRunning: Bool,
        captiveBypassEnabled: Bool
    ) -> ForwardingTransitionIntent? {
        guard
            acceptingCallbacks,
            !isStopping,
            currentLifecycleGeneration == callbackLifecycleGeneration,
            resolverRunning || captiveBypassEnabled
        else {
            return nil
        }
        return ForwardingTransitionIntent(
            stopGeneration: currentStopGeneration,
            transitionGeneration: currentTransitionGeneration &+ 1
        )
    }

    static func isCurrentIntent(
        _ intent: ForwardingTransitionIntent,
        currentStopGeneration: UInt64,
        currentTransitionGeneration: UInt64,
        isStopping: Bool,
        resolverRunning: Bool,
        captiveBypassEnabled: Bool
    ) -> Bool {
        !isStopping
            && currentStopGeneration == intent.stopGeneration
            && currentTransitionGeneration == intent.transitionGeneration
            && (resolverRunning || captiveBypassEnabled)
    }

    static func mayPublish(
        captured: ForwardingTransitionSnapshot,
        current: ForwardingTransitionSnapshot
    ) -> Bool {
        captured == current && current.resolverRunning
    }

    static func generationAfterFailSafeStateChange(
        expectedGeneration: UInt64,
        currentGeneration: UInt64
    ) -> UInt64 {
        guard currentGeneration == expectedGeneration else {
            return currentGeneration
        }
        return currentGeneration &+ 1
    }
}

enum ForwardingTransitionOrchestrator {
    static func restartIfCurrent(
        intent: ForwardingTransitionIntent,
        isCurrent: () -> Bool,
        restart: (UInt64) -> Bool
    ) -> Bool {
        guard isCurrent() else { return false }
        return restart(intent.stopGeneration)
    }

    static func commitReadiness(
        captured: ForwardingTransitionSnapshot,
        current: () -> ForwardingTransitionSnapshot,
        setReady: () -> Bool,
        publish: () -> Bool
    ) -> ForwardingReadinessCommitResult {
        guard
            ForwardingTransitionPolicy.mayPublish(
                captured: captured,
                current: current()
            )
        else {
            return .stale
        }
        guard setReady() else {
            return .readinessRejected
        }
        return .committed(wasBypassing: publish())
    }

    /// `republishNetworkProfile` runs on commit because the network profile
    /// derived behind a portal, such as a day-long negative NAT64 answer, does
    /// not describe the network once the portal clears.
    static func finishCaptiveResolution(
        commitReadiness: () -> ForwardingReadinessCommitResult,
        enterFailSafe: () -> Void,
        wakeReady: () -> Void,
        republishNetworkProfile: () -> Void
    ) -> ForwardingReadinessCommitResult {
        let result = commitReadiness()
        switch result {
        case .committed:
            republishNetworkProfile()
            wakeReady()
        case .stale, .readinessRejected:
            enterFailSafe()
        }
        return result
    }

    /// Runs a fail-safe bypass commit as decide → publish → decide again.
    ///
    /// Publishing the bypass cannot hold the state lock, so between the two
    /// decisions the approval can lapse and a newer transition can restore
    /// interception. The verdict that commits must be the one taken *after*
    /// the publish. Committing on the opening verdict lets a stale callback
    /// re-establish a bypass nobody authorizes any more.
    ///
    /// `commit` reports whether the caller has to take the published bypass
    /// back. That is true only when it published one and no other transition
    /// owns an active bypass to inherit it.
    static func commitFailSafeBypass(
        decide: () -> ForwardingFailSafeAuthorizationPolicy.Action,
        restoreInterception: () -> Void,
        publishBypass: () -> Bool,
        commit: (_ bypassPublished: Bool) -> (ForwardingFailSafeCommitResult, Bool)
    ) -> ForwardingFailSafeCommitResult {
        switch decide() {
        case .discard:
            return .noLongerNeeded
        case .keepProtectionClosed:
            restoreInterception()
            return .noLongerNeeded
        case .claimFullBypass:
            break
        }

        let (result, mustRestoreInterception) = commit(publishBypass())
        if mustRestoreInterception {
            restoreInterception()
        }
        return result
    }

    @discardableResult
    static func enterFailSafe(
        commitBypass: () -> ForwardingFailSafeCommitResult,
        resolverIsRunning: () -> Bool,
        stopResolver: () -> Void,
        wakeProxy: () -> Void
    ) -> ForwardingFailSafeCommitResult {
        let commit = commitBypass()
        guard commit != .noLongerNeeded else { return commit }

        if commit == .bypassRejected && resolverIsRunning() {
            stopResolver()
        }
        wakeProxy()
        return commit
    }

    /// Republishes the network profile on commit for the same reason as
    /// `finishCaptiveResolution`.
    static func completeDirectDoHRecovery(
        isCurrent: () -> Bool,
        disableForwarding: () -> Bool,
        publishReadiness: () -> Bool,
        commitDisabledState: () -> Bool?,
        enterFailSafe: (_ forwardingEnabled: Bool) -> Void,
        republishNetworkProfile: () -> Void
    ) -> DirectDoHRecoveryCompletionResult {
        guard isCurrent() else {
            enterFailSafe(true)
            return .stale
        }
        guard disableForwarding() else {
            enterFailSafe(true)
            return .disableRejected
        }
        guard isCurrent() else {
            enterFailSafe(false)
            return .stale
        }
        guard publishReadiness() else {
            enterFailSafe(false)
            return .readinessRejected
        }
        guard let wasBypassing = commitDisabledState() else {
            enterFailSafe(false)
            return .stale
        }
        republishNetworkProfile()
        return .committed(wasBypassing: wasBypassing)
    }

    static func disableAndPublish(
        disableForwarding: () -> Bool,
        publishDisabledState: () -> Bool
    ) -> Bool {
        disableForwarding() && publishDisabledState()
    }
}
