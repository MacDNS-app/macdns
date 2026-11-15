// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation
import Security

#if canImport(SharedExtensionKit)
    // SPM builds this as a module for the tests. The shipped providers compile
    // the same files directly (see Package.swift).
    import SharedExtensionKit
#endif

struct DNSProxyProcessCacheKey: Hashable {
    let pid: Int32
    let pidVersion: Int32
    let sourceIdentifier: Data
    let resolvedRole: DNSProxyProcessRole?
    let claimedSigningIdentifier: String
}

typealias DNSProxyValidationCache = MacDNSValidationCache<DNSProxyProcessCacheKey>

/// Verifies that a flow's source process really is a MacDNS component.
///
/// Runs once per flow during admission, never on the DNS packet hot path.
/// Results are cached by audit-token identity, resolved role, claimed identity,
/// and the OS-supplied source identifier so PID reuse cannot inherit a previous
/// decision.
final class DNSProxyProcessValidator {

    private struct ResolvedProcess {
        let canonicalPath: String?
        let role: DNSProxyProcessRole?
    }

    private let cache: DNSProxyValidationCache
    private let expectedTeamIdentifier: String?

    init(
        expectedTeamIdentifier: String? = nil,
        cacheCapacity: Int = 256
    ) {
        self.expectedTeamIdentifier =
            expectedTeamIdentifier ?? Self.ownTeamIdentifier()
        self.cache = Self.makeCache(maxEntries: cacheCapacity)
    }

    /// A negative verdict can come from one transient Security-framework
    /// failure, so it expires and the next flow validates again.
    static func makeCache(
        maxEntries: Int,
        now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) -> DNSProxyValidationCache {
        DNSProxyValidationCache(maxEntries: maxEntries, negativeTTL: 1, now: now)
    }

    /// Returns true only when the source process is a verified MacDNS binary.
    ///
    /// Returns false when identity cannot be proven. The caller then treats the
    /// flow as ordinary DNS traffic rather than dropping it.
    func isPassthrough(
        claimedSigningIdentifier: String,
        auditToken: Data?,
        sourceUniqueIdentifier: Data?
    ) -> Bool {
        guard let expectedTeamIdentifier else { return false }
        guard let auditToken, auditToken.count == MemoryLayout<audit_token_t>.size
        else {
            return false
        }
        guard let sourceUniqueIdentifier else { return false }

        var token = audit_token_t()
        _ = withUnsafeMutableBytes(of: &token) { raw in
            auditToken.copyBytes(to: raw)
        }

        let resolvedProcess = resolveProcess(token: &token)

        // Field layout per <bsm/libbsm.h>: val[5] is the PID and val[7] is the
        // PID generation. Reading them directly avoids linking libbsm.
        let key = DNSProxyProcessCacheKey(
            pid: Int32(bitPattern: token.val.5),
            pidVersion: Int32(bitPattern: token.val.7),
            sourceIdentifier: sourceUniqueIdentifier,
            resolvedRole: resolvedProcess.role,
            claimedSigningIdentifier: claimedSigningIdentifier
        )
        if let cached = cache.value(for: key) {
            return cached
        }

        let evidence = gatherEvidence(
            claimedSigningIdentifier: claimedSigningIdentifier,
            resolvedProcess: resolvedProcess,
            sourceUniqueIdentifier: sourceUniqueIdentifier,
            expectedTeamIdentifier: expectedTeamIdentifier
        )
        let trusted = DNSProxyIdentityPolicy.isPassthrough(
            evidence: evidence,
            expectedTeamIdentifier: expectedTeamIdentifier
        )
        cache.insert(trusted, for: key)

        return trusted
    }

    static func requirementString(
        for role: DNSProxyProcessRole,
        expectedTeamIdentifier: String
    ) -> String {
        #"anchor apple generic and identifier "\#(role.signingIdentifier)" and certificate leaf[subject.OU] = "\#(expectedTeamIdentifier)""#
    }

    private func resolveProcess(token: inout audit_token_t) -> ResolvedProcess {
        // Resolve the path from the audit token, not the bare PID, so a reused
        // PID cannot point validation at a different process.
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) * 4)
        let length = proc_pidpath_audittoken(
            &token,
            &buffer,
            UInt32(buffer.count)
        )

        guard length > 0, let rawPath = String(validatingUTF8: buffer) else {
            return ResolvedProcess(canonicalPath: nil, role: nil)
        }

        let canonicalPath = URL(fileURLWithPath: rawPath)
            .standardizedFileURL
            .resolvingSymlinksInPath()
            .path
        return ResolvedProcess(
            canonicalPath: canonicalPath,
            role: DNSProxyBypassableRoles.role(forCanonicalPath: canonicalPath)
        )
    }

    private func gatherEvidence(
        claimedSigningIdentifier: String,
        resolvedProcess: ResolvedProcess,
        sourceUniqueIdentifier: Data,
        expectedTeamIdentifier: String
    ) -> DNSProxyPassthroughEvidence {
        guard let canonicalPath = resolvedProcess.canonicalPath,
            let role = resolvedProcess.role
        else {
            return DNSProxyPassthroughEvidence(
                claimedSigningIdentifier: claimedSigningIdentifier,
                hasAuditToken: true,
                resolvedRole: resolvedProcess.role,
                staticSigningIdentifier: nil,
                staticTeamIdentifier: nil,
                staticCodeValid: false,
                sourceCDHashMatches: false
            )
        }

        let signature = signingInformation(
            forPath: canonicalPath,
            role: role,
            expectedTeamIdentifier: expectedTeamIdentifier
        )
        return DNSProxyPassthroughEvidence(
            claimedSigningIdentifier: claimedSigningIdentifier,
            hasAuditToken: true,
            resolvedRole: role,
            staticSigningIdentifier: signature.signingIdentifier,
            staticTeamIdentifier: signature.teamIdentifier,
            staticCodeValid: signature.valid,
            sourceCDHashMatches: signature.cdHashes.contains(sourceUniqueIdentifier)
        )
    }

    private func signingInformation(
        forPath path: String,
        role: DNSProxyProcessRole,
        expectedTeamIdentifier: String
    ) -> (
        signingIdentifier: String?, teamIdentifier: String?, valid: Bool,
        cdHashes: [Data]
    ) {
        var staticCode: SecStaticCode?
        guard
            SecStaticCodeCreateWithPath(
                URL(fileURLWithPath: path) as CFURL,
                SecCSFlags(),
                &staticCode
            ) == errSecSuccess,
            let staticCode
        else {
            return (nil, nil, false, [])
        }

        var infoRef: CFDictionary?
        guard
            SecCodeCopySigningInformation(
                staticCode,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &infoRef
            ) == errSecSuccess,
            let info = infoRef as? [String: Any]
        else {
            return (nil, nil, false, [])
        }

        let signingIdentifier = info[kSecCodeInfoIdentifier as String] as? String
        let teamIdentifier = info[kSecCodeInfoTeamIdentifier as String] as? String
        let cdHashes = (info[kSecCodeInfoCdHashes as String] as? [Data]) ?? []
        let requirementString = Self.requirementString(
            for: role,
            expectedTeamIdentifier: expectedTeamIdentifier
        )
        var requirement: SecRequirement?
        guard
            SecRequirementCreateWithString(
                requirementString as CFString,
                SecCSFlags(),
                &requirement
            ) == errSecSuccess,
            let requirement
        else {
            return (signingIdentifier, teamIdentifier, false, cdHashes)
        }

        let valid =
            SecStaticCodeCheckValidity(
                staticCode,
                SecCSFlags(),
                requirement
            ) == errSecSuccess

        return (signingIdentifier, teamIdentifier, valid, cdHashes)
    }

    private static func ownTeamIdentifier() -> String? {
        var staticCode: SecStaticCode?
        guard
            SecStaticCodeCreateWithPath(
                Bundle.main.bundleURL as CFURL,
                SecCSFlags(),
                &staticCode
            ) == errSecSuccess,
            let staticCode
        else {
            return nil
        }

        var infoRef: CFDictionary?
        guard
            SecCodeCopySigningInformation(
                staticCode,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &infoRef
            ) == errSecSuccess,
            let info = infoRef as? [String: Any]
        else {
            return nil
        }
        return info[kSecCodeInfoTeamIdentifier as String] as? String
    }
}
