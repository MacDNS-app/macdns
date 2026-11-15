// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNSAgent

private final class RefreshRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    var callCount: Int {
        lock.withLock { count }
    }

    func record() {
        lock.withLock { count += 1 }
    }
}

/// Stands in for a resolver whose Tokio runtime is down: the category selection
/// still loads, but any forced refresh would fail with `runtime not started`.
private final class StoppedResolver: BlocklistResolverBackend {
    let refreshes = RefreshRecorder()
    let reloads = RefreshRecorder()
    private(set) var configureCallCount = 0

    func configureBlocklist(settingsPath: String) -> Bool {
        configureCallCount += 1
        return true
    }

    func forceBlocklistUpdateResult() -> ResolverModule.BlocklistUpdateResult {
        refreshes.record()
        return .failed
    }

    func reloadBlocklist() -> Bool {
        reloads.record()
        return true
    }


    func isRunning() -> Bool { false }
}

/// A resolver with the runtime up whose forced refresh ends in `refreshResult`.
private final class RunningResolver: BlocklistResolverBackend {
    let refreshes = RefreshRecorder()
    private let refreshResult: ResolverModule.BlocklistUpdateResult

    init(refreshResult: ResolverModule.BlocklistUpdateResult) {
        self.refreshResult = refreshResult
    }

    func configureBlocklist(settingsPath: String) -> Bool { true }

    func forceBlocklistUpdateResult() -> ResolverModule.BlocklistUpdateResult {
        refreshes.record()
        return refreshResult
    }

    func reloadBlocklist() -> Bool { true }


    func isRunning() -> Bool { true }
}

/// `state.json` stays authoritative while DNS protection is off: the user can
/// prepare a blocklist selection with the resolver stopped, and the lists are
/// downloaded by `startServices()` after the network-ready gate opens.
final class BlocklistStoppedResolverPolicyTests: XCTestCase {
    func testFirstEnableWithStoppedResolverPersistsWithoutRefresh() throws {
        let resolver = StoppedResolver()
        let store = try makeStore(seededWith: disabledSettings())
        let manager = makeManager(resolver: resolver, store: store)
        let newSettings = enabledSettings(level: "multi")

        let completed = expectation(description: "first enable completed")
        manager.updateSettings(newSettings, reloadAfterUpdate: true) { success in
            XCTAssertTrue(success, "enabling the blocklist with DNS off must report success")
            completed.fulfill()
        }
        wait(for: [completed], timeout: 2.0)

        XCTAssertEqual(
            resolver.refreshes.callCount,
            0,
            "a stopped resolver has no runtime to download on"
        )
        XCTAssertEqual(resolver.configureCallCount, 1)
        XCTAssertEqual(resolver.reloads.callCount, 1, "LMDB hot reload still applies the selection")
        XCTAssertEqual(store.settings(), newSettings, "the new selection must not roll back")
        XCTAssertEqual(try projectedSettings(store), newSettings)
    }

    func testCategoryChangeWithStoppedResolverPersistsWithoutRefresh() throws {
        let resolver = StoppedResolver()
        let store = try makeStore(seededWith: enabledSettings(level: "multi"))
        let manager = makeManager(resolver: resolver, store: store)
        let newSettings = enabledSettings(level: "pro")

        let completed = expectation(description: "category change completed")
        manager.updateSettings(newSettings, reloadAfterUpdate: true) { success in
            XCTAssertTrue(success, "changing categories with DNS off must report success")
            completed.fulfill()
        }
        wait(for: [completed], timeout: 2.0)

        XCTAssertEqual(resolver.refreshes.callCount, 0)
        XCTAssertEqual(store.settings(), newSettings, "the new selection must not roll back")
        XCTAssertEqual(try projectedSettings(store), newSettings)
    }

    // MARK: - Running resolver

    func testFirstEnableRollsBackWhenASelectedListIsNotLoaded() throws {
        let resolver = RunningResolver(refreshResult: .failed)
        let previousSettings = disabledSettings()
        let store = try makeStore(seededWith: previousSettings)
        let manager = makeManager(resolver: resolver, store: store)

        XCTAssertFalse(
            save(enabledSettings(level: "multi"), with: manager),
            "a selection that is not filtering must not be reported as saved"
        )

        XCTAssertEqual(resolver.refreshes.callCount, 1)
        XCTAssertEqual(store.settings(), previousSettings, "a selection that is not loaded must roll back")
    }

    func testCategoryChangeRollsBackWhenASelectedListIsNotLoaded() throws {
        let resolver = RunningResolver(refreshResult: .failed)
        let previousSettings = enabledSettings(level: "multi")
        let store = try makeStore(seededWith: previousSettings)
        let manager = makeManager(resolver: resolver, store: store)

        XCTAssertFalse(save(enabledSettings(level: "pro"), with: manager))

        XCTAssertEqual(resolver.refreshes.callCount, 1)
        XCTAssertEqual(store.settings(), previousSettings, "a selection that is not loaded must roll back")
    }

    /// The selected lists filter with the copy already on disk. The periodic
    /// scheduler retries the download, so the save must stand.
    func testFirstEnableKeepsSelectionWhenSelectedListsAreLoadedButStale() throws {
        let resolver = RunningResolver(refreshResult: .loadedStale)
        let store = try makeStore(seededWith: disabledSettings())
        let manager = makeManager(resolver: resolver, store: store)
        let newSettings = enabledSettings(level: "multi")

        XCTAssertTrue(save(newSettings, with: manager), "loaded lists must not fail the save")

        XCTAssertEqual(resolver.refreshes.callCount, 1)
        XCTAssertEqual(store.settings(), newSettings, "the new selection must not roll back")
        XCTAssertEqual(try projectedSettings(store), newSettings)
    }

    func testCategoryChangeKeepsSelectionWhenSelectedListsAreLoadedButStale() throws {
        let resolver = RunningResolver(refreshResult: .loadedStale)
        let store = try makeStore(seededWith: enabledSettings(level: "multi"))
        let manager = makeManager(resolver: resolver, store: store)
        let newSettings = enabledSettings(level: "pro")

        XCTAssertTrue(save(newSettings, with: manager), "loaded lists must not fail the save")

        XCTAssertEqual(resolver.refreshes.callCount, 1)
        XCTAssertEqual(store.settings(), newSettings, "the new selection must not roll back")
        XCTAssertEqual(try projectedSettings(store), newSettings)
    }

    /// "Update Now" is the user asking for fresh lists. An older copy still
    /// filtering is not what was asked for.
    func testUpdateNowFailsWhenSelectedListsAreLoadedButStale() throws {
        let resolver = RunningResolver(refreshResult: .loadedStale)
        let settings = enabledSettings(level: "multi")
        let store = try makeStore(seededWith: settings)
        let manager = makeManager(resolver: resolver, store: store)

        let completed = expectation(description: "update now completed")
        manager.forceUpdate { success in
            XCTAssertFalse(success, "a selected list that was not refreshed must fail Update Now")
            completed.fulfill()
        }
        wait(for: [completed], timeout: 2.0)

        XCTAssertEqual(resolver.refreshes.callCount, 1)
        XCTAssertEqual(store.settings(), settings, "the selection and its refresh date must stay as they were")
    }

    func testUpdateNowSucceedsWhenSelectedListsWereRefreshed() throws {
        let resolver = RunningResolver(refreshResult: .unchanged)
        let store = try makeStore(seededWith: enabledSettings(level: "multi"))
        let manager = makeManager(resolver: resolver, store: store)

        let completed = expectation(description: "update now completed")
        manager.forceUpdate { success in
            XCTAssertTrue(success)
            completed.fulfill()
        }
        wait(for: [completed], timeout: 2.0)
    }

    func testForcedRefreshStatusCodesMapToResults() {
        XCTAssertEqual(ResolverModule.blocklistUpdateResult(1), .changed)
        XCTAssertEqual(ResolverModule.blocklistUpdateResult(0), .unchanged)
        XCTAssertEqual(ResolverModule.blocklistUpdateResult(2), .loadedStale)
        XCTAssertEqual(ResolverModule.blocklistUpdateResult(-1), .failed)
        XCTAssertEqual(ResolverModule.blocklistUpdateResult(3), .failed, "an unknown code must not read as success")
    }

    // MARK: - Helpers

    private lazy var temporaryRoot: URL = {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("macdns-tests-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
        }
        return url
    }()

    private var blocklistsDirectory: URL {
        temporaryRoot.appendingPathComponent("blocklists", isDirectory: true)
    }

    private func disabledSettings() -> BlocklistSettings {
        BlocklistSettings(
            enabled: false,
            categories: [],
            dbBasePath: blocklistsDirectory.path
        )
    }

    private func enabledSettings(level: String) -> BlocklistSettings {
        BlocklistSettings(
            enabled: true,
            categories: [
                CategoryConfig(name: "Ads & Tracking", identifier: "ads_tracking", level: level)
            ],
            dbBasePath: blocklistsDirectory.path
        )
    }

    private func makeStore(
        seededWith settings: BlocklistSettings
    ) throws -> StateFileBlocklistSettingsStore {
        let store = StateFileBlocklistSettingsStore(
            stateFile: temporaryRoot.appendingPathComponent("state.json"),
            projectionFile: temporaryRoot.appendingPathComponent("blocklist_settings.json"),
            blocklistsDir: blocklistsDirectory.path
        )
        XCTAssertNotNil(
            store.mutate { _ in settings },
            "seeding the blocklist settings must succeed"
        )
        return store
    }

    private func save(_ settings: BlocklistSettings, with manager: BlocklistManager) -> Bool {
        let completed = expectation(description: "settings save completed")
        let outcome = RefreshRecorder()
        manager.updateSettings(settings, reloadAfterUpdate: true) { success in
            if success { outcome.record() }
            completed.fulfill()
        }
        wait(for: [completed], timeout: 2.0)
        return outcome.callCount == 1
    }

    private func makeManager(
        resolver: BlocklistResolverBackend,
        store: StateFileBlocklistSettingsStore
    ) -> BlocklistManager {
        BlocklistManager(
            resolver: resolver,
            store: store,
            blocklistsDir: blocklistsDirectory.path,
            networkReadyGate: NetworkReadyWorkGate {}
        )
    }

    private func projectedSettings(
        _ store: StateFileBlocklistSettingsStore
    ) throws -> BlocklistSettings {
        try JSONCoding.decoder.decode(
            BlocklistSettings.self,
            from: Data(contentsOf: URL(fileURLWithPath: store.projectionPath))
        )
    }
}
