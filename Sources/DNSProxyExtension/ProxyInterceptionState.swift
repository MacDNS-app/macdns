// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// `CaseIterable` so `ProxyControlReportInteropTests` can assert this copy still
/// carries the same cases as `Shared.ProxyInterceptionReason`. A reason the App
/// cannot decode makes it report `unknown` instead of the real bypass cause.
enum ProxyInterceptionReason: String, CaseIterable {
    case starting
    case agentUnavailable
    case sessionUnavailable
    case resolverNotReady
    case probeFailed
    case dnsDestinationsUnavailable
    case stopping
}

enum ProxyInterceptionState: Equatable {
    case bypass(ProxyInterceptionReason)
    case intercepting(sessionID: String)

    /// JSON matching Shared.ProxyControlStateReport:
    /// {"state":...,"reason":...,"providerVersion":...}. The intercepting session
    /// id stays in provider logs, not on the wire.
    func encodedReport(providerVersion: String?) -> Data? {
        let state: String
        let reason: String?
        switch self {
        case .bypass(let r):
            state = "bypass"
            reason = r.rawValue
        case .intercepting:
            state = "intercepting"
            reason = nil
        }
        var dict: [String: Any] = ["state": state]
        if let reason { dict["reason"] = reason }
        if let providerVersion { dict["providerVersion"] = providerVersion }
        return try? JSONSerialization.data(withJSONObject: dict)
    }
}
