// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared

/// Decides whether a freshly enabled DNS Proxy may stay enabled.
///
/// Enabling the proxy awaits NetworkExtension preferences, and the Agent can
/// stop and restart during that await without changing the app's own lifecycle
/// generation. The Agent's generation must therefore be revalidated after the
/// await, or the proxy could keep intercepting for a resolver session that no
/// longer exists.
enum ProxyEnableRuntimeValidationPolicy {
    static func shouldRollbackRejectedEnable(
        attemptLifecycleGeneration: UInt64,
        currentLifecycleGeneration: UInt64
    ) -> Bool {
        attemptLifecycleGeneration == currentLifecycleGeneration
    }

    static func canStartProxyEnable(
        preEnableRuntimeState: AgentRuntimeState?,
        appLifecycleIsCurrent: Bool,
        runtimeDNSDesired: Bool,
        isStopping: Bool
    ) -> Bool {
        guard let state = preEnableRuntimeState else { return false }
        return shouldKeepProxyEnabled(
            postEnableRuntimeState: state,
            expectedAgentLifecycleGeneration: state.lifecycleGeneration,
            appLifecycleIsCurrent: appLifecycleIsCurrent,
            runtimeDNSDesired: runtimeDNSDesired,
            isStopping: isStopping
        )
    }

    static func shouldKeepProxyEnabled(
        postEnableRuntimeState: AgentRuntimeState?,
        expectedAgentLifecycleGeneration: UInt64,
        appLifecycleIsCurrent: Bool,
        runtimeDNSDesired: Bool,
        isStopping: Bool
    ) -> Bool {
        guard appLifecycleIsCurrent, runtimeDNSDesired, !isStopping else {
            return false
        }
        // A missing runtime state is not proof of health: fail closed.
        guard let state = postEnableRuntimeState else { return false }

        return state.lifecycleGeneration == expectedAgentLifecycleGeneration
            && state.servicesRunning
            && !state.transitionInProgress
            && !state.captivePortalDetected
    }
}
