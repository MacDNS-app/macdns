// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

#if canImport(SharedExtensionKit)
    // SPM builds this as a module for the tests. The shipped providers compile
    // the same files directly (see Package.swift).
    import SharedExtensionKit
#endif

/// MacDNS components whose DNS traffic must bypass interception.
///
/// The identity table itself lives in `SharedExtensionKit` so the Content
/// Filter cannot drift from it. Which roles this provider accepts stays here:
/// only the agent and this extension originate DNS that must not be
/// intercepted, and the Content Filter is deliberately not on that list.
typealias DNSProxyProcessRole = MacDNSProcessRole

enum DNSProxyBypassableRoles {
    static let all: [MacDNSProcessRole] = [.agent, .dnsProxy]

    static func role(forCanonicalPath path: String) -> MacDNSProcessRole? {
        MacDNSProcessRole.role(forCanonicalPath: path, among: all)
    }
}

/// Evidence gathered for one flow's source process.
///
/// `claimedSigningIdentifier` comes from flow metadata and is attacker
/// controlled. It selects a candidate role but never grants trust on its own.
struct DNSProxyPassthroughEvidence {
    let claimedSigningIdentifier: String
    let hasAuditToken: Bool
    let resolvedRole: DNSProxyProcessRole?
    let staticSigningIdentifier: String?
    let staticTeamIdentifier: String?
    let staticCodeValid: Bool
    /// Whether the OS-supplied source identity matches a code-directory hash of
    /// the binary that was inspected, binding the running process to the file.
    let sourceCDHashMatches: Bool
}

enum DNSProxyIdentityPolicy {
    /// Grants passthrough only when every independent check agrees.
    ///
    /// A failure here does not drop the flow: the process simply loses its
    /// privileged bypass and is handled as ordinary DNS traffic.
    static func isPassthrough(
        evidence: DNSProxyPassthroughEvidence,
        expectedTeamIdentifier: String
    ) -> Bool {
        guard let role = evidence.resolvedRole else { return false }
        guard evidence.hasAuditToken else { return false }
        guard evidence.claimedSigningIdentifier == role.signingIdentifier else {
            return false
        }
        guard evidence.staticSigningIdentifier == role.signingIdentifier else {
            return false
        }
        guard let team = evidence.staticTeamIdentifier,
            team == expectedTeamIdentifier
        else {
            return false
        }
        guard evidence.staticCodeValid else { return false }
        return evidence.sourceCDHashMatches
    }
}
