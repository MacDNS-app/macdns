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

struct ContentFilterProcessSnapshot {
    let canonicalPath: String
    let signingIdentifier: String?
    let teamIdentifier: String?
    let signatureValid: Bool
}

struct ContentFilterProcessCacheKey: Hashable {
    let pid: Int32
    let pidVersion: Int32
    let canonicalPath: String
    let role: MacDNSProcessRole
}

typealias ContentFilterValidationCache = MacDNSValidationCache<ContentFilterProcessCacheKey>
typealias ContentFilterAuditTokenIdentity = MacDNSAuditTokenIdentity

struct ContentFilterProcessEvaluation {
    let canonicalPath: String?
    let trusted: Bool
}

/// Decides whether a filtered flow belongs to one of MacDNS's own binaries.
///
/// Runs once per blockable flow, never per packet. The source path is resolved
/// only from the audit token, and verdicts are cached by PID plus PID
/// generation together with the canonical path and role resolved from that
/// token, so a reused PID cannot inherit a previous verdict. Paths that do not
/// match a MacDNS role are rejected by pure path matching and never reach the
/// Security framework, so unrelated processes cannot flood the cache.
final class ContentFilterProcessValidator {
    typealias PathResolver = (Data) -> String?
    typealias SignatureProbe = (String, MacDNSProcessRole, String) ->
        ContentFilterProcessSnapshot

    private let cache: ContentFilterValidationCache
    private let resolvePath: PathResolver
    private let probeSignature: SignatureProbe
    private let teamIdentifierLock = NSLock()
    private var expectedTeamIdentifierValue: String?

    init(
        expectedTeamIdentifier: String? = nil,
        cacheCapacity: Int = 64,
        now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
        resolvePath: @escaping PathResolver =
            ContentFilterProcessValidator.resolveCanonicalPath(auditToken:),
        probeSignature: @escaping SignatureProbe =
            ContentFilterProcessValidator.signatureSnapshot(
                canonicalPath:role:expectedTeamIdentifier:)
    ) {
        self.cache = ContentFilterValidationCache(maxEntries: cacheCapacity, negativeTTL: 1, now: now)
        self.resolvePath = resolvePath
        self.probeSignature = probeSignature
        self.expectedTeamIdentifierValue = expectedTeamIdentifier
    }

    /// Returns the canonical source path, when resolvable, and whether the
    /// process is a verified MacDNS binary. A false verdict is not proof of
    /// hostility, only that MacDNS ownership could not be proven.
    func evaluate(auditToken: Data?) -> ContentFilterProcessEvaluation {
        guard let auditToken,
            let identity = ContentFilterAuditTokenIdentity(auditToken: auditToken),
            let canonicalPath = resolvePath(auditToken)
        else {
            return ContentFilterProcessEvaluation(canonicalPath: nil, trusted: false)
        }

        guard let role = Self.role(forCanonicalPath: canonicalPath) else {
            return ContentFilterProcessEvaluation(
                canonicalPath: canonicalPath,
                trusted: false
            )
        }

        let key = ContentFilterProcessCacheKey(
            pid: identity.pid,
            pidVersion: identity.pidVersion,
            canonicalPath: canonicalPath,
            role: role
        )
        if let cached = cache.value(for: key) {
            return ContentFilterProcessEvaluation(
                canonicalPath: canonicalPath,
                trusted: cached
            )
        }

        // Not cached when the team identifier is unavailable: the next flow
        // must be able to retry instead of inheriting a transient failure.
        guard let expectedTeamIdentifier = expectedTeamIdentifier() else {
            return ContentFilterProcessEvaluation(
                canonicalPath: canonicalPath,
                trusted: false
            )
        }

        let trusted = Self.isTrusted(
            snapshot: probeSignature(canonicalPath, role, expectedTeamIdentifier),
            expectedTeamIdentifier: expectedTeamIdentifier
        )
        cache.insert(trusted, for: key)

        return ContentFilterProcessEvaluation(
            canonicalPath: canonicalPath,
            trusted: trusted
        )
    }

    static func canonicalPath(_ path: String) -> String {
        URL(fileURLWithPath: path)
            .resolvingSymlinksInPath()
            .standardizedFileURL.path
    }

    /// The Content Filter must let every MacDNS binary through before it drops
    /// DoH/DoT, including the DNS Proxy's sibling extension.
    static func role(forCanonicalPath path: String) -> MacDNSProcessRole? {
        MacDNSProcessRole.role(
            forCanonicalPath: path,
            among: [.agent, .dnsProxy, .contentFilter]
        )
    }

    static func isTrusted(
        snapshot: ContentFilterProcessSnapshot,
        expectedTeamIdentifier: String
    ) -> Bool {
        guard let role = role(forCanonicalPath: snapshot.canonicalPath) else {
            return false
        }
        return snapshot.signatureValid
            && snapshot.signingIdentifier == role.signingIdentifier
            && snapshot.teamIdentifier == expectedTeamIdentifier
    }

    /// Resolves the source path from the audit token rather than the bare PID,
    /// so a recycled PID cannot point validation at a different process.
    static func resolveCanonicalPath(auditToken: Data) -> String? {
        guard auditToken.count == MemoryLayout<audit_token_t>.size else {
            return nil
        }
        var token = audit_token_t()
        _ = withUnsafeMutableBytes(of: &token) { raw in
            auditToken.copyBytes(to: raw)
        }

        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let length = proc_pidpath_audittoken(
            &token,
            &buffer,
            UInt32(buffer.count)
        )
        guard length > 0, let rawPath = String(validatingUTF8: buffer) else {
            return nil
        }
        return canonicalPath(rawPath)
    }

    private func expectedTeamIdentifier() -> String? {
        teamIdentifierLock.lock()
        defer { teamIdentifierLock.unlock() }

        if let expectedTeamIdentifierValue {
            return expectedTeamIdentifierValue
        }
        let resolved = Self.signingInformation(for: Bundle.main.bundleURL)
            .teamIdentifier
        expectedTeamIdentifierValue = resolved
        return resolved
    }

    static func signatureSnapshot(
        canonicalPath: String,
        role: MacDNSProcessRole,
        expectedTeamIdentifier: String
    ) -> ContentFilterProcessSnapshot {
        var staticCode: SecStaticCode?
        guard
            SecStaticCodeCreateWithPath(
                URL(fileURLWithPath: canonicalPath) as CFURL,
                SecCSFlags(),
                &staticCode
            ) == errSecSuccess, let staticCode
        else {
            return ContentFilterProcessSnapshot(
                canonicalPath: canonicalPath,
                signingIdentifier: nil,
                teamIdentifier: nil,
                signatureValid: false
            )
        }

        let info = signingInformation(for: staticCode)
        let requirementString =
            #"anchor apple generic and identifier "\#(role.signingIdentifier)" and certificate leaf[subject.OU] = "\#(expectedTeamIdentifier)""#
        var requirement: SecRequirement?
        guard
            SecRequirementCreateWithString(
                requirementString as CFString,
                SecCSFlags(),
                &requirement
            ) == errSecSuccess, let requirement
        else {
            return ContentFilterProcessSnapshot(
                canonicalPath: canonicalPath,
                signingIdentifier: info.signingIdentifier,
                teamIdentifier: info.teamIdentifier,
                signatureValid: false
            )
        }

        let valid =
            SecStaticCodeCheckValidity(
                staticCode,
                SecCSFlags(),
                requirement
            ) == errSecSuccess
        return ContentFilterProcessSnapshot(
            canonicalPath: canonicalPath,
            signingIdentifier: info.signingIdentifier,
            teamIdentifier: info.teamIdentifier,
            signatureValid: valid
        )
    }

    private static func signingInformation(
        for url: URL
    ) -> (signingIdentifier: String?, teamIdentifier: String?) {
        var staticCode: SecStaticCode?
        guard
            SecStaticCodeCreateWithPath(
                url as CFURL,
                SecCSFlags(),
                &staticCode
            ) == errSecSuccess, let staticCode
        else {
            return (nil, nil)
        }
        return signingInformation(for: staticCode)
    }

    private static func signingInformation(
        for staticCode: SecStaticCode
    ) -> (signingIdentifier: String?, teamIdentifier: String?) {
        var information: CFDictionary?
        guard
            SecCodeCopySigningInformation(
                staticCode,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &information
            ) == errSecSuccess,
            let values = information as? [String: Any]
        else {
            return (nil, nil)
        }
        return (
            values[kSecCodeInfoIdentifier as String] as? String,
            values[kSecCodeInfoTeamIdentifier as String] as? String
        )
    }
}
