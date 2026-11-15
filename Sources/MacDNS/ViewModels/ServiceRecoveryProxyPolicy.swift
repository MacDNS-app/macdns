// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

struct ServiceRecoveryProxyPolicy: Equatable {
    let isEnabled: Bool
    let isUpdatingAgent: Bool
    let isStoppingServices: Bool
    let dnsProxyEnabled: Bool
    let persistedStateAvailability: PersistedStateAvailability

    init(
        isEnabled: Bool,
        isUpdatingAgent: Bool,
        isStoppingServices: Bool,
        dnsProxyEnabled: Bool,
        persistedStateAvailability: PersistedStateAvailability
    ) {
        self.isEnabled = isEnabled
        self.isUpdatingAgent = isUpdatingAgent
        self.isStoppingServices = isStoppingServices
        self.dnsProxyEnabled = dnsProxyEnabled
        self.persistedStateAvailability = persistedStateAvailability
    }

    var shouldAttemptAutoStart: Bool {
        persistedStateAvailability.allowsLifecycleActions
            && isEnabled
            && !isUpdatingAgent
            && !isStoppingServices
    }

    var shouldDisableProxyBeforeAutoStart: Bool {
        persistedStateAvailability.allowsLifecycleActions
            && dnsProxyEnabled
            && !shouldAttemptAutoStart
    }

    var shouldDisableProxyAfterAutoStartFailure: Bool {
        persistedStateAvailability.allowsLifecycleActions
            && dnsProxyEnabled
            && shouldAttemptAutoStart
    }
}
