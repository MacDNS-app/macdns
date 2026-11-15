// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

final class ServiceWakeupGate: @unchecked Sendable {
    private let lock = NSLock()
    private var enqueued = false
    private var generation: UInt64 = 0

    var currentGeneration: UInt64 {
        lock.withLock { generation }
    }

    func begin() -> Bool {
        lock.withLock {
            generation &+= 1
            guard !enqueued else { return false }
            enqueued = true
            return true
        }
    }

    func advanceGeneration() -> UInt64 {
        lock.withLock {
            generation &+= 1
            return generation
        }
    }

    @discardableResult
    func complete() -> UInt64 {
        lock.withLock {
            enqueued = false
            return generation
        }
    }
}

struct AgentRuntimeState: Equatable {
    let servicesRunning: Bool
    let captivePortalDetected: Bool
    let forwarding: Bool
    let lifecycleGeneration: UInt64
    let transitionInProgress: Bool
    let proxyInterceptionState: String?
    let proxyInterceptionReason: String?
    let proxyProviderVersion: String?
    let proxyControlUnreachable: Bool?

    init(
        servicesRunning: Bool,
        captivePortalDetected: Bool,
        forwarding: Bool,
        lifecycleGeneration: UInt64 = 0,
        transitionInProgress: Bool = false,
        proxyInterceptionState: String? = nil,
        proxyInterceptionReason: String? = nil,
        proxyProviderVersion: String? = nil,
        proxyControlUnreachable: Bool? = nil
    ) {
        self.servicesRunning = servicesRunning
        self.captivePortalDetected = captivePortalDetected
        self.forwarding = forwarding
        self.lifecycleGeneration = lifecycleGeneration
        self.transitionInProgress = transitionInProgress
        self.proxyInterceptionState = proxyInterceptionState
        self.proxyInterceptionReason = proxyInterceptionReason
        self.proxyProviderVersion = proxyProviderVersion
        self.proxyControlUnreachable = proxyControlUnreachable
    }

    init(snapshot: AgentRuntimeStateSnapshot) {
        self.init(
            servicesRunning: snapshot.servicesRunning,
            captivePortalDetected: snapshot.captivePortalDetected,
            forwarding: snapshot.forwarding,
            lifecycleGeneration: snapshot.lifecycleGeneration,
            transitionInProgress: snapshot.transitionInProgress,
            proxyInterceptionState: snapshot.proxyInterceptionState,
            proxyInterceptionReason: snapshot.proxyInterceptionReason,
            proxyProviderVersion: snapshot.proxyProviderVersion,
            proxyControlUnreachable: snapshot.proxyControlUnreachable
        )
    }

    var providerIntercepting: Bool {
        proxyInterceptionState == "intercepting"
    }
}

/// Decides whether the running DNS Proxy provider is an outdated build still
/// alive after an update, so the new extension only takes over on restart.
/// Fires only when both versions are known, the proxy is enabled, and no
/// activation is in flight, so a normal in-progress replace never flickers.
struct ExtensionVersionStalePolicy {
    let runningVersion: String?
    let bundledVersion: String?
    let proxyEnabled: Bool
    let activationInProgress: Bool

    var isStale: Bool {
        guard proxyEnabled, !activationInProgress,
            let running = runningVersion, let bundled = bundledVersion
        else { return false }
        return running != bundled
    }
}

enum ServiceWakeExtensionAction: Equatable {
    case none
    case enable
    case disable
}

struct ServiceWakeGenerationPolicy {
    let capturedWakeGeneration: UInt64
    let currentWakeGeneration: UInt64
    let capturedLifecycleGeneration: UInt64
    let currentLifecycleGeneration: UInt64

    var isCurrent: Bool {
        capturedWakeGeneration == currentWakeGeneration
            && capturedLifecycleGeneration == currentLifecycleGeneration
    }

    func agentRespondingUpdate(forXPCSucceeded succeeded: Bool) -> Bool? {
        guard isCurrent else { return nil }
        return succeeded
    }
}

enum LicenseStatusLifecycleAction: Equatable {
    case none
    case reconcile
    case disable
}

struct LicenseStatusWakeResponsePolicy {
    let authoritativeInfo: LicenseInfo
    let isEnabled: Bool
    let isStoppingDNS: Bool
    let capturedWakeGeneration: UInt64
    let currentWakeGeneration: UInt64
    let capturedLifecycleGeneration: UInt64
    let currentLifecycleGeneration: UInt64
    let persistedStateAvailability: PersistedStateAvailability

    init(
        authoritativeInfo: LicenseInfo,
        isEnabled: Bool,
        isStoppingDNS: Bool,
        capturedWakeGeneration: UInt64,
        currentWakeGeneration: UInt64,
        capturedLifecycleGeneration: UInt64,
        currentLifecycleGeneration: UInt64,
        persistedStateAvailability: PersistedStateAvailability
    ) {
        self.authoritativeInfo = authoritativeInfo
        self.isEnabled = isEnabled
        self.isStoppingDNS = isStoppingDNS
        self.capturedWakeGeneration = capturedWakeGeneration
        self.currentWakeGeneration = currentWakeGeneration
        self.capturedLifecycleGeneration = capturedLifecycleGeneration
        self.currentLifecycleGeneration = currentLifecycleGeneration
        self.persistedStateAvailability = persistedStateAvailability
    }

    private var generationPolicy: ServiceWakeGenerationPolicy {
        ServiceWakeGenerationPolicy(
            capturedWakeGeneration: capturedWakeGeneration,
            currentWakeGeneration: currentWakeGeneration,
            capturedLifecycleGeneration: capturedLifecycleGeneration,
            currentLifecycleGeneration: currentLifecycleGeneration
        )
    }

    var shouldApply: Bool {
        generationPolicy.isCurrent && !isStoppingDNS
    }

    var lifecycleAction: LicenseStatusLifecycleAction {
        guard shouldApply else { return .none }
        guard authoritativeInfo.isServiceAllowed else { return .disable }
        guard persistedStateAvailability.allowsLifecycleActions else { return .none }
        return isEnabled ? .reconcile : .none
    }

    func agentRespondingUpdate(forXPCSucceeded succeeded: Bool) -> Bool? {
        guard shouldApply else { return nil }
        return succeeded
    }
}

struct ServiceWakeReconciliationPolicy {
    let runtimeState: AgentRuntimeState
    let runtimeDNSDesired: Bool
    let isStoppingDNS: Bool
    let capturedWakeGeneration: UInt64
    let currentWakeGeneration: UInt64
    let capturedLifecycleGeneration: UInt64
    let currentLifecycleGeneration: UInt64
    let authoritativeProxyEnabled: Bool
    let authoritativeFilterEnabled: Bool
    let shouldKeepContentFilterEnabled: Bool
    let persistedStateAvailability: PersistedStateAvailability

    init(
        runtimeState: AgentRuntimeState,
        runtimeDNSDesired: Bool,
        isStoppingDNS: Bool,
        capturedWakeGeneration: UInt64,
        currentWakeGeneration: UInt64,
        capturedLifecycleGeneration: UInt64,
        currentLifecycleGeneration: UInt64,
        authoritativeProxyEnabled: Bool,
        authoritativeFilterEnabled: Bool,
        shouldKeepContentFilterEnabled: Bool,
        persistedStateAvailability: PersistedStateAvailability
    ) {
        self.runtimeState = runtimeState
        self.runtimeDNSDesired = runtimeDNSDesired
        self.isStoppingDNS = isStoppingDNS
        self.capturedWakeGeneration = capturedWakeGeneration
        self.currentWakeGeneration = currentWakeGeneration
        self.capturedLifecycleGeneration = capturedLifecycleGeneration
        self.currentLifecycleGeneration = currentLifecycleGeneration
        self.authoritativeProxyEnabled = authoritativeProxyEnabled
        self.authoritativeFilterEnabled = authoritativeFilterEnabled
        self.shouldKeepContentFilterEnabled = shouldKeepContentFilterEnabled
        self.persistedStateAvailability = persistedStateAvailability
    }

    private var generationPolicy: ServiceWakeGenerationPolicy {
        ServiceWakeGenerationPolicy(
            capturedWakeGeneration: capturedWakeGeneration,
            currentWakeGeneration: currentWakeGeneration,
            capturedLifecycleGeneration: capturedLifecycleGeneration,
            currentLifecycleGeneration: currentLifecycleGeneration
        )
    }

    var generationsAreCurrent: Bool {
        generationPolicy.isCurrent
    }

    var shouldApply: Bool {
        persistedStateAvailability.allowsLifecycleActions
            && generationsAreCurrent
            && !runtimeState.transitionInProgress
    }

    var shouldStopUnexpectedResolver: Bool {
        shouldApply
            && runtimeState.servicesRunning
            && !runtimeDNSDesired
            && !isStoppingDNS
    }

    func agentRespondingUpdate(forXPCSucceeded succeeded: Bool) -> Bool? {
        generationPolicy.agentRespondingUpdate(forXPCSucceeded: succeeded)
    }

    var shouldEnableProxy: Bool {
        shouldApply
            && runtimeDNSDesired
            && !isStoppingDNS
            && runtimeState.servicesRunning
            && !runtimeState.captivePortalDetected
    }

    var proxyAction: ServiceWakeExtensionAction {
        guard shouldApply else { return .none }
        if shouldEnableProxy {
            return authoritativeProxyEnabled ? .none : .enable
        }
        return authoritativeProxyEnabled ? .disable : .none
    }

    var contentFilterAction: ServiceWakeExtensionAction {
        guard shouldApply else { return .none }
        if shouldEnableProxy && shouldKeepContentFilterEnabled {
            return authoritativeFilterEnabled ? .none : .enable
        }
        return authoritativeFilterEnabled ? .disable : .none
    }

    var resolverModeText: String {
        RuntimeStatePresentationPolicy.presentation(for: runtimeState)
            .resolverMode
    }
}
