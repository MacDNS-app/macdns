// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

enum ProxyReadinessAction: Equatable {
    case setBypassRequested(Bool)
    case notifyProxyEnable
    case notifyProxyDisable
    case wakeBypassProbe
}

enum ProxyReadinessLifecyclePolicy {
    static func startActions(
        keepProxyBypass: Bool
    ) -> [ProxyReadinessAction] {
        [
            .notifyProxyEnable,
            .setBypassRequested(keepProxyBypass),
            .wakeBypassProbe,
        ]
    }

    static let stopActions: [ProxyReadinessAction] = [
        .setBypassRequested(true),
        .wakeBypassProbe,
        .notifyProxyDisable,
    ]

    static let captivePortalBypassActions: [ProxyReadinessAction] = [
        .setBypassRequested(true),
        .wakeBypassProbe,
    ]
}
