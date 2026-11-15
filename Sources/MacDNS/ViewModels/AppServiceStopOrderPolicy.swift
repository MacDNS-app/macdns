// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// App-side cleanup steps, in the only order they may run.
enum AppServiceStopStep: Equatable, Hashable {
    case stopAgentServices
    case disableDNSProxy
}

struct AppServiceStopOutcome: Equatable {
    let agentStopped: Bool
    let proxyDisabled: Bool
}

/// Single order for every App-side service cleanup path.
///
/// The Agent stops first: its own `stopAllServices` requests provider bypass
/// before resolver teardown, so the provider never intercepts without a
/// resolver behind it. The App then reconciles `NEDNSProxyManager` to disabled.
///
/// The proxy step runs even when the Agent stop failed. Skipping it leaves the
/// manager enabled after a stale start, with the App believing the service is
/// off.
enum AppServiceStopOrderPolicy {
    static let orderedSteps: [AppServiceStopStep] = [
        .stopAgentServices,
        .disableDNSProxy,
    ]

    static func execute(
        _ perform: (AppServiceStopStep) async -> Bool
    ) async -> AppServiceStopOutcome {
        var results: [AppServiceStopStep: Bool] = [:]
        for step in orderedSteps {
            results[step] = await perform(step)
        }
        return AppServiceStopOutcome(
            agentStopped: results[.stopAgentServices] ?? false,
            proxyDisabled: results[.disableDNSProxy] ?? false
        )
    }
}
