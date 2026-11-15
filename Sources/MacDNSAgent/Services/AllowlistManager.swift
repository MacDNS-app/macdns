// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

protocol AllowlistResolverBackend {
    func listAllowedDomains() -> Result<
        [String], ResolverModule.AllowlistListError
    >
    func replaceAllowedDomains(_ domains: [String]) -> Bool
    func addAllowedDomain(_ domain: String) -> Bool
    func removeAllowedDomain(_ domain: String) -> Bool
}

extension ResolverModule: AllowlistResolverBackend {}

/// Wraps the in-process allowlist FFI (`dns_allowlist_*`) exposed by the
/// resolver dylib. LMDB ownership lives inside the resolver so the Swift
/// side never forks a helper.
///
/// `ResolverModule.shared.setAllowlistPath(...)` runs once at agent startup and
/// the Rust side opens the LMDB env lazily on the first read or write. Every
/// method here is therefore safe while the resolver is stopped, which
/// Preferences relies on to list, add and remove long before `start()`.
class AllowlistManager {
    static let shared = AllowlistManager()

    private let resolver: AllowlistResolverBackend

    // The 5 s TTL keeps the UI from re-entering the FFI on every keystroke,
    // and read-heavy call sites (capability callbacks, sync-to-LMDB) burst
    // through the same window.
    private var cachedDomains: [AllowedDomain]?
    private var lastCacheUpdate: Date?
    private let cacheTTL: TimeInterval = 5.0
    private let cacheLock = NSLock()

    init(resolver: AllowlistResolverBackend = ResolverModule.shared) {
        self.resolver = resolver
    }

    // MARK: - Cache Management

    private func isCacheValid() -> Bool {
        guard let lastUpdate = lastCacheUpdate else { return false }
        return Date().timeIntervalSince(lastUpdate) < cacheTTL
    }

    private func invalidateCache() {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        cachedDomains = nil
        lastCacheUpdate = nil
    }

    // MARK: - Allowlist Operations

    /// Returns the allowlist LMDB contents for migration into `state.json`.
    /// `state.json` is authoritative. Its enabled domains replace LMDB contents
    /// through `syncToLMDBStrict`.
    func getAllowedDomains() throws -> [AllowedDomain] {
        cacheLock.lock()
        if isCacheValid(), let cached = cachedDomains {
            cacheLock.unlock()
            AgentLogger.shared.debug("Returning cached allowlist (\(cached.count) domains)")
            return cached
        }
        cacheLock.unlock()

        let domainStrings: [String]
        switch resolver.listAllowedDomains() {
        case .success(let listedDomains):
            domainStrings = listedDomains
        case .failure:
            throw AllowlistError.executionFailed(
                "dns_allowlist_list failed"
            )
        }
        let domains = domainStrings.map { AllowedDomain(domain: $0) }

        cacheLock.lock()
        cachedDomains = domains
        lastCacheUpdate = Date()
        cacheLock.unlock()

        AgentLogger.shared.debug("Loaded \(domains.count) domains from allowlist")
        return domains
    }

    func addDomain(_ domain: String) throws {
        guard !domain.isEmpty, domain.contains(".") else {
            throw AllowlistError.invalidDomain(domain)
        }
        guard resolver.addAllowedDomain(domain) else {
            AgentLogger.shared.error("addAllowedDomain FFI returned failure for '\(domain)'")
            throw AllowlistError.commandFailed("dns_allowlist_add failed for \(domain)")
        }
        invalidateCache()
    }

    func removeDomain(_ domain: String) throws {
        guard resolver.removeAllowedDomain(domain) else {
            AgentLogger.shared.error("removeAllowedDomain FFI returned failure for '\(domain)'")
            throw AllowlistError.commandFailed("dns_allowlist_remove failed for \(domain)")
        }
        invalidateCache()
    }

    /// The enabled domains in `state.json` become the complete LMDB contents.
    @discardableResult
    func syncToLMDB(domains: [AllowedDomain]) -> (added: [String], removed: [String]) {
        let result = syncToLMDBStrict(domains: domains)
        return (added: result.added, removed: result.removed)
    }

    /// Publishes the authoritative allowlist as a single atomic replacement.
    ///
    /// The reported `added`/`removed` values are a diff for logging only. The
    /// replacement itself either commits in full or leaves LMDB untouched.
    @discardableResult
    func syncToLMDBStrict(domains: [AllowedDomain]) -> (success: Bool, added: [String], removed: [String]) {
        let currentLMDBDomains: Set<String>
        switch resolver.listAllowedDomains() {
        case .success(let listedDomains):
            currentLMDBDomains = Set(listedDomains)
        case .failure:
            AgentLogger.shared.error(
                "Cannot sync allowlist: dns_allowlist_list failed"
            )
            return (success: false, added: [], removed: [])
        }
        let enabledDomains = Set(domains.filter { $0.enabled }.map { $0.domain })

        guard resolver.replaceAllowedDomains(Array(enabledDomains).sorted()) else {
            AgentLogger.shared.error(
                "Cannot sync allowlist: atomic replacement failed, previous allowlist retained"
            )
            return (success: false, added: [], removed: [])
        }
        invalidateCache()

        let added = enabledDomains.subtracting(currentLMDBDomains).sorted()
        let removed = currentLMDBDomains.subtracting(enabledDomains).sorted()

        if !added.isEmpty || !removed.isEmpty {
            AgentLogger.shared.info(
                "Synced allowlist to LMDB: added \(added.count), removed \(removed.count)"
            )
        }

        return (success: true, added: added, removed: removed)
    }
}

// MARK: - Error Types

enum AllowlistError: Error, LocalizedError {
    case invalidDomain(String)
    case commandFailed(String)
    case executionFailed(String)

    var errorDescription: String? {
        switch self {
        case .invalidDomain(let domain):
            return "Invalid domain: \(domain)"
        case .commandFailed(let message):
            return "Command failed: \(message)"
        case .executionFailed(let message):
            return "Execution failed: \(message)"
        }
    }
}
