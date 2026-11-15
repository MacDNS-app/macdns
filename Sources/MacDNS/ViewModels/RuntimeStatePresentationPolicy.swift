// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared

/// Provider-facing presentation fields derived from one Agent runtime snapshot.
struct RuntimeStatePresentation: Equatable {
    let providerState: ProviderInterceptionDisplayState
    let forwarding: Bool
    let resolverMode: String
}

/// Maps an Agent runtime snapshot, or the absence of one, onto the
/// provider-facing presentation fields.
///
/// Interception state reaches the App only inside the Agent's snapshot, so a
/// snapshot that cannot be read maps the provider to `unknown`. That failure
/// invalidates only the provider view: it never implies the resolver stopped,
/// which the caller keeps modelling separately through `servicesRunning`.
enum RuntimeStatePresentationPolicy {
    static func presentation(
        for runtimeState: AgentRuntimeState
    ) -> RuntimeStatePresentation {
        let providerState: ProviderInterceptionDisplayState
        switch runtimeState.proxyInterceptionState {
        case "intercepting":
            providerState = .intercepting
        case "bypass":
            providerState = .bypass(reason: runtimeState.proxyInterceptionReason)
        default:
            providerState = .unknown
        }

        return RuntimeStatePresentation(
            providerState: providerState,
            forwarding: runtimeState.forwarding,
            resolverMode: resolverMode(
                providerState: providerState,
                forwarding: runtimeState.forwarding
            )
        )
    }

    /// The runtime snapshot could not be read.
    static var unavailable: RuntimeStatePresentation {
        RuntimeStatePresentation(
            providerState: .unknown,
            forwarding: false,
            resolverMode: ProtectionStatusPolicy.unknownStatusMessage
        )
    }

    /// The Agent stayed in a lifecycle transition for the whole retry budget.
    static var transitioning: RuntimeStatePresentation {
        RuntimeStatePresentation(
            providerState: .unknown,
            forwarding: false,
            resolverMode: "Starting or stopping"
        )
    }

    static func resolverMode(
        providerState: ProviderInterceptionDisplayState,
        forwarding: Bool
    ) -> String {
        switch providerState {
        case .intercepting:
            return forwarding
                ? ProtectionStatusPolicy.forwardingModeMessage : ProtectionStatusPolicy.encryptedModeMessage
        case .bypass(let reason):
            return ProtectionStatusPolicy.pausedMessage(reason: reason)
        case .unknown:
            return ProtectionStatusPolicy.unknownStatusMessage
        }
    }
}
