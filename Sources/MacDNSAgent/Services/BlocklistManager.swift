// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

protocol BlocklistResolverBackend: AnyObject {
    func configureBlocklist(settingsPath: String) -> Bool
    func forceBlocklistUpdateResult() -> ResolverModule.BlocklistUpdateResult
    func reloadBlocklist() -> Bool

    /// Whether the resolver runtime is up. Loading the category selection and
    /// reloading LMDB work while it is down. Downloading lists does not,
    /// because the refresh runs on the resolver's Tokio runtime.
    func isRunning() -> Bool
}

extension BlocklistResolverBackend {
    func isRunning() -> Bool { true }
}

extension ResolverModule: BlocklistResolverBackend {}

/// Persistence seam for blocklist settings. Every mutation is a read-modify-write
/// inside one `state.json` transaction, so a caller can never persist a value it
/// derived from a snapshot another writer has already superseded.
protocol BlocklistSettingsStore: AnyObject {
    /// Path of the derived projection handed to the Rust scheduler.
    var projectionPath: String { get }

    func settings() -> BlocklistSettings

    /// Applies `transform` to the settings currently persisted. Returns the
    /// settings that were replaced, or `nil` when the transform declined the
    /// change or the transaction could not be persisted.
    func mutate(
        _ transform: (BlocklistSettings) -> BlocklistSettings?
    ) -> BlocklistSettings?
}

/// The only writer of `blocklist_settings.json`.
///
/// Blocklist settings are persisted in `state.json` under the same flock and
/// revision guard as the rest of the configuration. The projection the Rust
/// scheduler reads is re-derived from the committed document inside the same
/// critical section.
final class StateFileBlocklistSettingsStore: BlocklistSettingsStore {
    static let shared = StateFileBlocklistSettingsStore()

    private let stateFile: URL
    private let projectionFile: URL
    private let blocklistsDir: String

    init(
        stateFile: URL = PathResolver.stateFile,
        projectionFile: URL = PathResolver.blocklistSettings,
        blocklistsDir: String = PathResolver.blocklistsDir.path
    ) {
        self.stateFile = stateFile
        self.projectionFile = projectionFile
        self.blocklistsDir = blocklistsDir
    }

    var projectionPath: String { projectionFile.path }

    private var defaultSettings: BlocklistSettings {
        BlocklistSettings(dbBasePath: blocklistsDir)
    }

    func settings() -> BlocklistSettings {
        let load =
            (try? StateFileLock.withExclusiveLock(stateFile: stateFile) {
                StateFileLock.loadUnlocked(stateFile: stateFile)
            }) ?? .ioFailure("state lock failed")
        guard case .valid(let document) = load else {
            return defaultSettings
        }
        return settingsLocked(in: document)
    }

    func mutate(
        _ transform: (BlocklistSettings) -> BlocklistSettings?
    ) -> BlocklistSettings? {
        do {
            return try StateFileLock.withExclusiveLock(stateFile: stateFile) {
                guard let document = mutableDocumentLocked() else { return nil }
                let current = settingsLocked(in: document)
                guard let updated = transform(current) else { return nil }
                guard let nextDocument = documentForMutation(document, settings: updated)
                else {
                    return nil
                }
                do {
                    try prepareStateDirectory()
                    try StateDocumentWriter.write(
                        stampedDocument(nextDocument),
                        to: stateFile,
                        refreshProjection: refreshProjection(from:)
                    )
                } catch {
                    AgentLogger.shared.error(
                        "Failed to save blocklist settings: \(error)"
                    )
                    return nil
                }
                return current
            }
        } catch {
            AgentLogger.shared.error(
                "Blocklist settings transaction refused: state lock failed: \(error)"
            )
            return nil
        }
    }

    /// Boot reconciliation. Persists the default profile when state.json
    /// carries no blocklist state, migrates legacy blocking actions, and
    /// re-emits the scheduler projection.
    func bootstrapSettings() {
        do {
            try StateFileLock.withExclusiveLock(stateFile: stateFile) {
                guard let document = mutableDocumentLocked() else { return }
                let persistedSettings: BlocklistSettings?
                var settings: BlocklistSettings
                switch BlocklistSettingsTransactionPolicy.persisted(
                    in: document,
                    dbBasePath: blocklistsDir
                ) {
                case .valid(let valid):
                    persistedSettings = valid
                    settings = valid
                case .missing:
                    persistedSettings = nil
                    settings = defaultSettings
                case .malformed:
                    persistedSettings = nil
                    settings = projectedSettings() ?? defaultSettings
                }
                // Positive address answers avoid search-suffix retries that disclose blocked names.
                for index in settings.categories.indices
                where settings.categories[index].action.lowercased() == "nxdomain" {
                    settings.categories[index].action = "null"
                }
                if let persistedSettings, persistedSettings == settings {
                    try writeProjection(settings)
                    return
                }
                guard let nextDocument = documentForMutation(document, settings: settings) else {
                    return
                }
                try prepareStateDirectory()
                try StateDocumentWriter.write(
                    stampedDocument(nextDocument),
                    to: stateFile,
                    refreshProjection: refreshProjection(from:)
                )
                AgentLogger.shared.info("Reconciled blocklist settings into state.json")
            }
        } catch {
            AgentLogger.shared.error(
                "Failed to bootstrap blocklist settings: \(error)"
            )
        }
    }

    /// Re-derives the projection from a `state.json` document the agent is
    /// committing. Called inside the state-file transaction.
    func refreshProjection(from document: [String: Any]) throws {
        switch BlocklistSettingsTransactionPolicy.persisted(
            in: document,
            dbBasePath: blocklistsDir
        ) {
        case .missing:
            return
        case .malformed:
            throw NSError(
                domain: "MacDNSAgent.BlocklistSettings",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "malformed blocklist settings in state.json"
                ]
            )
        case .valid(let settings):
            try writeProjection(settings)
        }
    }

    /// Settings held by a `state.json` document. A malformed fragment falls
    /// back to the last projection instead of silently reporting defaults.
    private func settingsLocked(in document: [String: Any]) -> BlocklistSettings {
        switch BlocklistSettingsTransactionPolicy.persisted(
            in: document,
            dbBasePath: blocklistsDir
        ) {
        case .valid(let settings):
            return settings
        case .missing:
            return defaultSettings
        case .malformed:
            AgentLogger.shared.error(
                "Persisted blocklist settings are malformed; falling back to the last projection"
            )
            return projectedSettings() ?? defaultSettings
        }
    }

    private func documentForMutation(
        _ document: [String: Any],
        settings: BlocklistSettings
    ) -> [String: Any]? {
        guard
            let nextDocument = AgentConfigRevisionPolicy.configForAgentOwnedMutation(
                BlocklistSettingsTransactionPolicy.config(
                    document,
                    settings: settings
                )
            )
        else {
            AgentLogger.shared.error(
                "Blocklist settings not saved: configuration revision exhausted"
            )
            return nil
        }
        return nextDocument
    }

    private func mutableDocumentLocked() -> [String: Any]? {
        let document: [String: Any]
        switch StateFileLock.loadUnlocked(stateFile: stateFile) {
        case .missing:
            document = [:]
        case .valid(let persisted):
            document = persisted
        case .invalid(let reason), .ioFailure(let reason):
            AgentLogger.shared.error(
                "Blocklist settings not saved: unusable state.json: \(reason)"
            )
            return nil
        }
        guard let writable = ConfigSchemaPolicy.writable(document) else {
            AgentLogger.shared.error(
                "Blocklist settings not saved: state.json was written by a newer MacDNS"
            )
            return nil
        }
        guard
            let validated = DNSPolicyStructuralPolicy.validateAndNormalize(
                writable
            )
        else {
            AgentLogger.shared.error(
                "Blocklist settings not saved: state.json holds malformed overrides/zones"
            )
            return nil
        }
        return validated.normalizedConfig
    }

    private func prepareStateDirectory() throws {
        try FileManager.default.createDirectory(
            at: stateFile.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
    }

    private func stampedDocument(_ document: [String: Any]) -> [String: Any] {
        var persisted = ConfigSchemaPolicy.stamped(document)
        persisted["timestamp"] = Date().timeIntervalSinceReferenceDate
        return persisted
    }

    private func writeProjection(_ settings: BlocklistSettings) throws {
        let data = try JSONCoding.encoder.encode(settings)
        try data.write(to: projectionFile, options: .atomic)
    }

    /// The settings last projected to `blocklist_settings.json`. Read only while
    /// the fragment in state.json is malformed.
    private func projectedSettings() -> BlocklistSettings? {
        guard let data = try? Data(contentsOf: projectionFile) else {
            return nil
        }
        guard
            var settings = try? JSONCoding.decoder.decode(
                BlocklistSettings.self,
                from: data
            )
        else {
            AgentLogger.shared.error(
                "Ignoring unreadable blocklist_settings.json while recovering blocklist state"
            )
            return nil
        }
        settings.dbBasePath = blocklistsDir
        return settings
    }
}

/// Singleton with agent-lifetime scope. Marked `@unchecked Sendable` because it
/// is shared by XPC handlers and refresh callbacks. Settings are never cached.
/// Every read and every mutation goes through the state-file transaction.
final class BlocklistManager: @unchecked Sendable {
    static let shared = BlocklistManager()

    private let resolver: BlocklistResolverBackend
    private let store: BlocklistSettingsStore
    private let blocklistsDir: String
    private let networkReadyGate: NetworkReadyWorkGate

    init(
        resolver: BlocklistResolverBackend = ResolverModule.shared,
        store: BlocklistSettingsStore = StateFileBlocklistSettingsStore.shared,
        blocklistsDir: String = PathResolver.blocklistsDir.path,
        networkReadyGate: NetworkReadyWorkGate = .shared
    ) {
        self.resolver = resolver
        self.store = store
        self.blocklistsDir = blocklistsDir
        self.networkReadyGate = networkReadyGate
        createBlocklistsDirectory()
    }

    // MARK: - Directory Management

    private func createBlocklistsDirectory() {
        do {
            try FileManager.default.createDirectory(
                atPath: blocklistsDir,
                withIntermediateDirectories: true,
                attributes: nil
            )
        } catch {
            AgentLogger.shared.error("Failed to create blocklists directory: \(error)")
        }
    }

    // MARK: - Settings Management

    func getSettings() -> BlocklistSettings {
        store.settings()
    }

    func getSettingsData() -> Data? {
        do {
            return try JSONCoding.encoder.encode(store.settings())
        } catch {
            AgentLogger.shared.error("Failed to encode blocklist settings: \(error)")
            return nil
        }
    }

    func updateSettings(from data: Data, reloadAfterUpdate: Bool = false, completion: @escaping (Bool) -> Void) {
        let newSettings: BlocklistSettings
        do {
            newSettings = try JSONCoding.decoder.decode(BlocklistSettings.self, from: data)
        } catch {
            AgentLogger.shared.error("Failed to decode blocklist settings from XPC: \(error)")
            completion(false)
            return
        }
        updateSettings(newSettings, reloadAfterUpdate: reloadAfterUpdate, completion: completion)
    }

    func updateSettings(
        _ newSettings: BlocklistSettings, reloadAfterUpdate: Bool = false, completion: @escaping (Bool) -> Void
    ) {
        guard let oldSettings = store.mutate({ _ in newSettings }) else {
            completion(false)
            return
        }

        // Push the new category selection to the in-process scheduler so the
        // next refresh cycle picks it up. Fail fast, because the XPC reply must
        // surface scheduler misconfiguration instead of the UI claiming success
        // while filtering runs against stale state.
        if !resolver.configureBlocklist(settingsPath: store.projectionPath) {
            AgentLogger.shared.error(
                "resolver: configureBlocklist failed during updateSettings — scheduler still running with previous category selection"
            )
            _ = rollback(from: newSettings, to: oldSettings)
            completion(false)
            return
        }

        if newSettings.enabled {
            // A stopped resolver has no runtime to download on, so forcing a
            // refresh here would fail and roll the user's selection back.
            // state.json stays authoritative: `startServices()` configures the
            // scheduler and refreshes it once the network-ready gate opens.
            guard resolver.isRunning() else {
                AgentLogger.shared.info(
                    "Blocklist settings saved while the resolver is stopped — lists download on the next service start"
                )
                completeSettingsUpdate(
                    newSettings: newSettings,
                    oldSettings: oldSettings,
                    reloadAfterUpdate: reloadAfterUpdate,
                    completion: completion
                )
                return
            }

            if !oldSettings.enabled {
                // First enable: refresh before completeSettingsUpdate reloads
                // so blocking takes effect. Gated so a first enable during the
                // boot window does not race Content Filter activation. The
                // save stands when every selected list is loaded, even from a
                // copy that could not be refreshed, but `lastUpdated` only
                // moves when Rust reports changed files.
                Task {
                    await self.networkReadyGate.run {
                        DispatchQueue.global(qos: .background).async {
                            let result = self.resolver.forceBlocklistUpdateResult()
                            if result.changedFiles {
                                self.markRefreshCompleted()
                            } else if !result.selectionLoaded {
                                AgentLogger.shared.error("First-enable blocklist refresh failed")
                            }
                            let ok = result.selectionLoaded
                            if !ok {
                                _ = self.rollback(from: newSettings, to: oldSettings)
                                completion(false)
                                return
                            }
                            self.completeSettingsUpdate(
                                newSettings: newSettings,
                                oldSettings: oldSettings,
                                reloadAfterUpdate: reloadAfterUpdate,
                                completion: completion
                            )
                        }
                    }
                }
            } else {
                var changedCategories: [BlocklistCategory] = []

                for category in BlocklistCategory.allCases {
                    let oldLevel = oldSettings.level(for: category)
                    let newLevel = newSettings.level(for: category)

                    if oldLevel != newLevel {
                        changedCategories.append(category)
                    }
                }

                if !changedCategories.isEmpty {
                    // completeSettingsUpdate does the single reload afterwards.
                    AgentLogger.shared.info("Updating \(changedCategories.count) changed categories, fetching new DBs")
                    refreshDatabases { result in
                        if !result.selectionLoaded {
                            AgentLogger.shared.error("Category change refresh failed")
                            _ = self.rollback(from: newSettings, to: oldSettings)
                            completion(false)
                            return
                        }
                        self.completeSettingsUpdate(
                            newSettings: newSettings,
                            oldSettings: oldSettings,
                            reloadAfterUpdate: reloadAfterUpdate,
                            completion: completion
                        )
                    }
                } else {
                    completeSettingsUpdate(
                        newSettings: newSettings,
                        oldSettings: oldSettings,
                        reloadAfterUpdate: reloadAfterUpdate,
                        completion: completion
                    )
                }
            }
        } else {
            completeSettingsUpdate(
                newSettings: newSettings,
                oldSettings: oldSettings,
                reloadAfterUpdate: reloadAfterUpdate,
                completion: completion
            )
        }
    }

    private func completeSettingsUpdate(
        newSettings: BlocklistSettings,
        oldSettings: BlocklistSettings,
        reloadAfterUpdate: Bool,
        completion: @escaping (Bool) -> Void
    ) {
        guard reloadAfterUpdate else {
            completion(true)
            return
        }

        guard resolver.reloadBlocklist() else {
            AgentLogger.shared.error("resolver: reloadBlocklist failed after blocklist settings update")
            _ = rollback(from: newSettings, to: oldSettings)
            completion(false)
            return
        }

        completion(true)
    }

    @discardableResult
    func rollback(to previousSettings: BlocklistSettings) -> Bool {
        guard store.mutate({ _ in previousSettings }) != nil else { return false }
        return reconfigureAfterRollback()
    }

    @discardableResult
    func rollback(from expectedCurrentSettings: BlocklistSettings, to previousSettings: BlocklistSettings) -> Bool {
        let replaced = store.mutate { current in
            guard current.hasSameConfiguration(as: expectedCurrentSettings) else {
                AgentLogger.shared.warning("Skipping stale blocklist rollback because settings changed after failure")
                return nil
            }
            return previousSettings
        }

        guard replaced != nil else { return false }
        return reconfigureAfterRollback()
    }

    private func reconfigureAfterRollback() -> Bool {
        let restored = resolver.configureBlocklist(settingsPath: store.projectionPath)
        if !restored {
            AgentLogger.shared.error("resolver: configureBlocklist failed during blocklist rollback")
        }
        return restored
    }

    /// Records a completed refresh as a field-level mutation of the persisted
    /// settings, so a category change committed meanwhile survives the write.
    func markRefreshCompleted(at date: Date = Date()) {
        let updated = store.mutate { current in
            var refreshed = current
            refreshed.lastUpdated = date
            return refreshed
        }
        if updated == nil {
            AgentLogger.shared.error("Failed to record the blocklist refresh timestamp")
        }
    }

    // MARK: - Category Update Logic

    /// Downloads changed blocklist databases. The Rust refresh hot-reloads the
    /// live blocklist itself whenever a database changed, and blocklist
    /// decisions run before the answer cache, so no reload or cache flush is
    /// needed here. The caller decides what the result means for it.
    private func refreshDatabases(
        completion: @escaping (ResolverModule.BlocklistUpdateResult) -> Void
    ) {
        guard getSettings().enabled else {
            completion(.failed)
            return
        }

        // Gated so a refresh during the boot window waits, up to 30 s, for the
        // network stack to settle instead of stalling reqwest or racing
        // Content Filter activation.
        Task {
            await self.networkReadyGate.run {
                DispatchQueue.global(qos: .background).async {
                    let result = self.resolver.forceBlocklistUpdateResult()
                    if result.changedFiles {
                        self.markRefreshCompleted()
                    }
                    completion(result)
                }
            }
        }
    }

    // MARK: - Manual Update

    func forceUpdate(completion: @escaping (Bool) -> Void) {
        refreshDatabases { result in
            if !result.refreshed {
                AgentLogger.shared.error("Blocklist refresh failed")
            }
            completion(result.refreshed)
        }
    }
}

extension BlocklistSettings {
    fileprivate func hasSameConfiguration(as other: BlocklistSettings) -> Bool {
        var lhs = self
        var rhs = other
        lhs.lastUpdated = nil
        rhs.lastUpdated = nil
        return lhs == rhs
    }
}
