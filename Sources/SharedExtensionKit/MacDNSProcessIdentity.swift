// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation

/// Process-identity primitives shared by the two NetworkExtension providers.
///
/// Both providers must recognise MacDNS's own binaries: the Content Filter has
/// to let them through before it drops DoH/DoT, and the DNS Proxy has to avoid
/// intercepting its own upstream traffic. With separate copies of the signing
/// identifiers and bundle paths, a rename or bundle-layout change applied to one
/// side only would silently make that provider stop recognising a MacDNS binary
/// (the Content Filter killing the agent's own DoH, or the DNS Proxy looping on
/// itself), and no build would fail.
///
/// These files are compiled into BOTH extension binaries. The providers are
/// built by a bare `swiftc Sources/<Ext>/*.swift` (see `Sources/MacDNS/Makefile`)
/// and cannot import a module, so the directory is added to each compile line
/// instead. Keep everything here free of NetworkExtension and provider-specific
/// types so both sides can compile it.

/// A MacDNS component whose traffic each provider must be able to identify.
public enum MacDNSProcessRole: Hashable, CaseIterable {
    case agent
    case dnsProxy
    case contentFilter

    public var signingIdentifier: String {
        switch self {
        case .agent: return "app.macdns.agent"
        case .dnsProxy: return "app.macdns.dnsproxy"
        case .contentFilter: return "app.macdns.contentfilter"
        }
    }

    /// Terminal path components that identify this role. The bundle prefix and
    /// any system-extension UUID directory are not fixed, so only the trailing
    /// components are matched, never `contains` or a bare basename.
    public var terminalPathComponents: [String] {
        switch self {
        case .agent:
            return ["MacDNS.app", "Contents", "MacOS", "MacDNSAgent"]
        case .dnsProxy:
            return [
                "app.macdns.dnsproxy.systemextension",
                "Contents",
                "MacOS",
                "app.macdns.dnsproxy",
            ]
        case .contentFilter:
            return [
                "app.macdns.contentfilter.systemextension",
                "Contents",
                "MacOS",
                "app.macdns.contentfilter",
            ]
        }
    }

    /// Resolves `path` against `candidates` only. The set of roles a provider
    /// accepts is its own policy and deliberately stays at the call site: the
    /// DNS Proxy recognises the agent and itself, while the Content Filter also
    /// has to recognise the DNS Proxy's sibling extension.
    public static func role(
        forCanonicalPath path: String,
        among candidates: [MacDNSProcessRole]
    ) -> MacDNSProcessRole? {
        let components = (path as NSString).pathComponents
        return candidates.first { role in
            let expected = role.terminalPathComponents
            guard components.count >= expected.count else { return false }
            return Array(components.suffix(expected.count)) == expected
        }
    }
}

/// Identity of a process as reported by its audit token.
public struct MacDNSAuditTokenIdentity: Hashable {
    public let pid: Int32
    public let pidVersion: Int32

    public init?(auditToken: Data) {
        guard auditToken.count == MemoryLayout<audit_token_t>.size else {
            return nil
        }
        var token = audit_token_t()
        _ = withUnsafeMutableBytes(of: &token) { raw in
            auditToken.copyBytes(to: raw)
        }
        // Field layout per <bsm/libbsm.h>: val[5] is the PID and val[7] is the
        // PID generation. Reading them directly avoids linking libbsm.
        self.pid = Int32(bitPattern: token.val.5)
        self.pidVersion = Int32(bitPattern: token.val.7)
    }
}

/// Bounded verdict cache keyed by whatever identity the provider considers
/// sufficient. Insertion-ordered eviction, not LRU: a verdict is cheap to
/// recompute and the cache exists to keep the Security framework off the
/// admission path, not to be optimal.
public final class MacDNSValidationCache<Key: Hashable> {
    private let lock = NSLock()
    private struct Entry {
        let verdict: Bool
        let expiresAt: TimeInterval?
    }

    private let maxEntries: Int
    private let negativeTTL: TimeInterval?
    private let now: () -> TimeInterval
    private var values: [Key: Entry] = [:]
    private var insertionOrder: [Key] = []

    public init(
        maxEntries: Int,
        negativeTTL: TimeInterval? = nil,
        now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) {
        self.maxEntries = max(0, maxEntries)
        self.negativeTTL = negativeTTL
        self.now = now
    }

    public func value(for key: Key) -> Bool? {
        lock.lock()
        defer { lock.unlock() }
        guard let entry = values[key] else { return nil }
        if let expiresAt = entry.expiresAt, now() >= expiresAt {
            values.removeValue(forKey: key)
            insertionOrder.removeAll { $0 == key }
            return nil
        }
        return entry.verdict
    }

    public func insert(_ value: Bool, for key: Key) {
        lock.lock()
        defer { lock.unlock() }

        guard maxEntries > 0 else { return }
        let expiresAt = value ? nil : negativeTTL.map { now() + max(0, $0) }
        let entry = Entry(verdict: value, expiresAt: expiresAt)
        if values.updateValue(entry, forKey: key) != nil {
            return
        }

        if insertionOrder.count == maxEntries {
            let oldestKey = insertionOrder.removeFirst()
            values.removeValue(forKey: oldestKey)
        }
        insertionOrder.append(key)
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return values.count
    }
}
