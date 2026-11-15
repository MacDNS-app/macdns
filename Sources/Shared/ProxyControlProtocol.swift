// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

// NE requires this name to be PREFIXED by an App Group from the extension's
// com.apple.security.application-groups entitlement (NetworkExtensionErrorDomain
// Code=6 rejects the sysext otherwise). Not the Team ID, which is the ES convention.
public let proxyControlMachServiceName = "group.app.macdns.proxy-control"
public let proxyControlAgentRequirement =
    "identifier \"app.macdns.agent\" and anchor apple generic and "
    + "certificate leaf[subject.OU] = \"MY427949GW\""
public let proxyControlProviderRequirement =
    "identifier \"app.macdns.dnsproxy\" and anchor apple generic and "
    + "certificate leaf[subject.OU] = \"MY427949GW\""

/// Max encoded payload size accepted on the control plane (defensive cap).
public let proxyControlMaxPayloadBytes = 4096

/// Wire version of the challenge/response plane. The provider and the Rust
/// resolver carry their own copy of this constant because the DNS Proxy cannot
/// import `Shared`. The cross-language golden vector guards them against drift.
public let proxyControlVersion: UInt16 = 1

public struct ProxyControlBootstrap: Codable, Equatable, Sendable {
    public let version: UInt16
    public let sessionID: Data
    /// Mutable so the agent can scrub the decoded key the moment it is handed
    /// to the resolver. The material must not outlive the installation.
    public var hmacKey: Data
    public init(version: UInt16, sessionID: Data, hmacKey: Data) {
        self.version = version
        self.sessionID = sessionID
        self.hmacKey = hmacKey
    }
}

public struct ProxyControlStateReport: Codable, Equatable, Sendable {
    public let state: String
    public let reason: String?
    /// CFBundleVersion of the extension process that produced this report. Lets
    /// the App detect a stale provider still running after an update (restart
    /// required). nil when decoded from an older provider that never sent it.
    public let providerVersion: String?
    public init(state: String, reason: String?, providerVersion: String? = nil) {
        self.state = state
        self.reason = reason
        self.providerVersion = providerVersion
    }
}

public enum ProxyInterceptionReason: String, Codable, Equatable, Sendable, CaseIterable {
    case starting
    case agentUnavailable
    case sessionUnavailable
    case resolverNotReady
    case probeFailed
    case dnsDestinationsUnavailable
    case stopping
}

public enum ProxyInterceptionState: Equatable, Sendable {
    case bypass(ProxyInterceptionReason)
    case intercepting(sessionID: String)

    /// The session id in the intercepting case is informational (logs only) and
    /// is not carried on the wire. The App only distinguishes state.
    public func toReport() -> ProxyControlStateReport {
        switch self {
        case .bypass(let reason):
            return ProxyControlStateReport(state: "bypass", reason: reason.rawValue)
        case .intercepting:
            return ProxyControlStateReport(state: "intercepting", reason: nil)
        }
    }

    public init?(report: ProxyControlStateReport) {
        switch report.state {
        case "intercepting":
            self = .intercepting(sessionID: "")
        case "bypass":
            guard let raw = report.reason, let reason = ProxyInterceptionReason(rawValue: raw)
            else { return nil }
            self = .bypass(reason)
        default:
            return nil
        }
    }
}

@objc public protocol MacDNSProxyControlProtocol {
    /// Returns a JSON-encoded `ProxyControlBootstrap`, or nil on failure.
    func beginControlSession(withReply reply: @escaping (Data?) -> Void)
    /// Returns a JSON-encoded `ProxyControlStateReport`, or nil on failure.
    func currentProviderState(withReply reply: @escaping (Data?) -> Void)
}
