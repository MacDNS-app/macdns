// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNS
@testable import MacDNSAgent

final class BlocklistLateReplyTests: XCTestCase {
    func testTimeoutThenAgentRollbackRefreshesTheDisplayedSettings() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let started = expectation(description: "agent refresh started")
        let settled = expectation(description: "late reply reconciled")
        let resolver = DelayedFailingBlocklistResolver(started: started)
        defer {
            resolver.release.signal()
            try? FileManager.default.removeItem(at: directory)
        }
        let store = StateFileBlocklistSettingsStore(
            stateFile: directory.appendingPathComponent("state.json"),
            projectionFile: directory.appendingPathComponent("blocklist_settings.json"),
            blocklistsDir: directory.path
        )
        let previous = BlocklistSettings(enabled: false, categories: [], dbBasePath: directory.path)
        XCTAssertNotNil(store.mutate { _ in previous })
        let manager = BlocklistManager(
            resolver: resolver, store: store, blocklistsDir: directory.path,
            networkReadyGate: NetworkReadyWorkGate {}
        )
        var changed = previous
        changed.enabled = true
        let display = BlocklistDisplayRecorder()
        var deadline: (() -> Void)?
        BoundedCallback.run(
            seconds: 30, timeoutValue: false,
            schedule: { _, action in deadline = action },
            completion: { _ in display.recordDeadline(settings: manager.getSettings()) },
            onLateReply: { success in
                XCTAssertFalse(success)
                display.recordLateReply(settings: manager.getSettings())
                settled.fulfill()
            },
            operation: { finish in
                manager.updateSettings(changed, reloadAfterUpdate: true, completion: finish)
            }
        )
        wait(for: [started], timeout: 2)
        XCTAssertTrue(manager.getSettings().enabled, "the agent persists selection before downloading")
        deadline?()
        XCTAssertTrue(display.snapshot.enabled)
        resolver.release.signal()
        wait(for: [settled], timeout: 2)
        XCTAssertEqual(manager.getSettings(), previous)
        XCTAssertFalse(display.snapshot.enabled)
        XCTAssertEqual(display.snapshot.completions, 1)
        XCTAssertEqual(display.snapshot.lateReplies, 1)
    }
}

private final class DelayedFailingBlocklistResolver: BlocklistResolverBackend {
    let release = DispatchSemaphore(value: 0)
    private let started: XCTestExpectation

    init(started: XCTestExpectation) {
        self.started = started
    }

    func configureBlocklist(settingsPath: String) -> Bool { true }

    func forceBlocklistUpdateResult() -> ResolverModule.BlocklistUpdateResult {
        started.fulfill()
        _ = release.wait(timeout: .now() + 5)
        return .failed
    }

    func reloadBlocklist() -> Bool { true }
    func isRunning() -> Bool { true }
}

private final class BlocklistDisplayRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var enabled = false
    private var completions = 0
    private var lateReplies = 0

    var snapshot: (enabled: Bool, completions: Int, lateReplies: Int) {
        lock.withLock { (enabled, completions, lateReplies) }
    }

    func recordDeadline(settings: BlocklistSettings) {
        lock.withLock {
            completions += 1
            enabled = settings.enabled
        }
    }

    func recordLateReply(settings: BlocklistSettings) {
        lock.withLock {
            lateReplies += 1
            enabled = settings.enabled
        }
    }
}
