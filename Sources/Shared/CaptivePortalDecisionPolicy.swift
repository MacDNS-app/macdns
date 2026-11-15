// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// How much of the DNS security model a suspected captive portal may switch
/// off.
public enum CaptivePortalCompatibilityMode: String, Codable, Equatable, Sendable {
    /// No portal suspicion. Full protection.
    case none
    /// A portal is suspected. Queries are routed through the current network's
    /// DHCP resolvers while the DNS Proxy, the blocklist and the Content Filter
    /// stay active.
    case scopedForwarding
    /// The user explicitly approved a full interception bypass for this
    /// network.
    case approvedFullBypass

    /// Derives the mode from the agent's authoritative runtime flags, the only
    /// channel that carries interception state to the App.
    public static func from(
        fullBypassActive: Bool,
        forwarding: Bool
    ) -> CaptivePortalCompatibilityMode {
        if fullBypassActive {
            return .approvedFullBypass
        }
        return forwarding ? .scopedForwarding : .none
    }
}

/// A user-granted authorization to bypass interception, bound to one network
/// identity and one short fixed window.
///
/// `grant` is the only constructor a user action uses: the deadline is derived
/// from the grant instant, never from a probe result, so no amount of forged
/// HTTP can extend it.
public struct CaptivePortalFullBypassApproval: Equatable, Sendable {
    /// Fixed lifetime of a granted approval. Long enough to finish a portal
    /// sign-in, short enough that a network the user already left cannot keep
    /// the bypass alive.
    public static let window: TimeInterval = 900

    public let networkIdentity: String
    public let expiresAt: Date

    public init(networkIdentity: String, expiresAt: Date) {
        self.networkIdentity = networkIdentity
        self.expiresAt = expiresAt
    }

    public static func grant(
        networkIdentity: String,
        at now: Date
    ) -> CaptivePortalFullBypassApproval {
        CaptivePortalFullBypassApproval(
            networkIdentity: networkIdentity,
            expiresAt: now.addingTimeInterval(window)
        )
    }

    public func authorizes(networkIdentity: String?, at now: Date) -> Bool {
        guard let networkIdentity, networkIdentity == self.networkIdentity else {
            return false
        }
        return now < expiresAt
    }
}

/// What has to happen to a full bypass that is already active.
///
/// Entering the bypass is not the only moment the authorization matters: the
/// detector only reports status *changes*, so a portal that keeps answering
/// `.captive` produces no further callbacks and nothing would ever notice that
/// the window lapsed or that the host moved to another network.
public enum CaptiveFullBypassContinuation: Equatable, Sendable {
    /// The approval still covers the attached network and the window.
    case keepBypass
    /// The bypass is active on an approval that no longer holds. Drop the
    /// approval and restore DNS protection.
    case revokeBypass
    /// No bypass is active, but a lapsed approval is still on file and could
    /// authorize a later transition.
    case dropApproval
    case none
}

/// Decides what a captive-portal probe result is allowed to change.
///
/// The probe is cleartext HTTP against a well-known host, so an on-path
/// attacker controls it completely, including the consecutive confirmations
/// the detector requires. A probe may therefore only select the constrained
/// compatibility mode, which keeps the DNS Proxy, the blocklist and the Content
/// Filter active. Full bypass needs an approval the user granted for this exact
/// network inside a window the probe cannot extend.
public struct CaptivePortalDecisionPolicy: Equatable {
    public let portalSuspected: Bool
    public let networkIdentity: String?
    public let approval: CaptivePortalFullBypassApproval?
    public let now: Date

    public init(
        portalSuspected: Bool,
        networkIdentity: String?,
        approval: CaptivePortalFullBypassApproval?,
        now: Date
    ) {
        self.portalSuspected = portalSuspected
        self.networkIdentity = networkIdentity
        self.approval = approval
        self.now = now
    }

    public var mode: CaptivePortalCompatibilityMode {
        guard portalSuspected else { return .none }
        guard
            approval?.authorizes(networkIdentity: networkIdentity, at: now)
                == true
        else {
            return .scopedForwarding
        }
        return .approvedFullBypass
    }

    /// Re-evaluates an authorization against the live bypass state.
    ///
    /// Called on the approval's deadline and whenever the attached network
    /// moves, so a bypass cannot outlive the grant that authorized it.
    public static func continuation(
        fullBypassActive: Bool,
        networkIdentity: String?,
        approval: CaptivePortalFullBypassApproval?,
        now: Date
    ) -> CaptiveFullBypassContinuation {
        let authorized =
            approval?.authorizes(networkIdentity: networkIdentity, at: now)
            == true
        if fullBypassActive {
            return authorized ? .keepBypass : .revokeBypass
        }
        guard approval != nil, !authorized else { return .none }
        return .dropApproval
    }
}
