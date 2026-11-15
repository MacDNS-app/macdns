// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

struct RuntimeStateRefreshRetryPolicy {
    private static let delays: [UInt64] = [
        1_000_000_000, 2_000_000_000, 4_000_000_000,
        8_000_000_000, 16_000_000_000, 16_000_000_000,
    ]
    private var retriesScheduled = 0

    mutating func reset() {
        retriesScheduled = 0
    }

    mutating func nextDelay(
        for runtimeState: AgentRuntimeState?,
        runtimeDNSDesired: Bool,
        isStoppingDNS: Bool,
        softwareUpdateSuspended: Bool,
        generationsAreCurrent: Bool
    ) -> UInt64? {
        guard runtimeDNSDesired,
            !isStoppingDNS,
            !softwareUpdateSuspended,
            generationsAreCurrent,
            Self.needsRefresh(runtimeState),
            retriesScheduled < Self.delays.count
        else { return nil }

        let delay = Self.delays[retriesScheduled]
        retriesScheduled += 1
        return delay
    }

    private static func needsRefresh(_ runtimeState: AgentRuntimeState?) -> Bool {
        guard let runtimeState else { return true }
        if runtimeState.transitionInProgress { return true }
        guard runtimeState.servicesRunning, !runtimeState.captivePortalDetected else {
            return false
        }
        switch runtimeState.proxyInterceptionState {
        case "intercepting":
            return false
        case "bypass":
            return runtimeState.proxyInterceptionReason != "stopping"
        default:
            return true
        }
    }
}
