// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNSAgent

/// Manually released stand-in for `NetworkReadySignal`, so tests can prove that
/// agent-originated network work stays parked while the gate is closed.
private actor ReleasableGate {
    private var released = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if released { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        released = true
        for waiter in waiters { waiter.resume() }
        waiters.removeAll()
    }
}

private final class CallRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    var callCount: Int {
        lock.withLock { count }
    }

    func record() {
        lock.withLock { count += 1 }
    }
}

private final class GatedRefreshResolver: BlocklistResolverBackend {
    let refreshes = CallRecorder()

    func configureBlocklist(settingsPath: String) -> Bool {
        true
    }

    func forceBlocklistUpdateResult() -> ResolverModule.BlocklistUpdateResult {
        refreshes.record()
        return .unchanged
    }

    func reloadBlocklist() -> Bool {
        true
    }

}

/// Every agent-originated external network start must sit behind
/// `NetworkReadyWorkGate`, or it can hit ENETDOWN or a 60s stall. These tests
/// fail as soon as a gate wait is dropped from any of the routed paths.
final class NetworkReadySignalPolicyTests: XCTestCase {
    func testGateParksWorkUntilReleased() {
        let gate = ReleasableGate()
        let workGate = NetworkReadyWorkGate { await gate.wait() }
        let recorder = CallRecorder()
        let finished = expectation(description: "gated work ran")

        Task {
            await workGate.run {
                recorder.record()
                finished.fulfill()
            }
        }

        drainQueues()
        XCTAssertEqual(
            recorder.callCount,
            0,
            "gated work must not start before network-ready releases"
        )

        Task { await gate.release() }
        wait(for: [finished], timeout: 2.0)
        XCTAssertEqual(recorder.callCount, 1)
    }

    func testGateRunsWorkWhenAlreadyReleased() {
        let gate = ReleasableGate()
        let workGate = NetworkReadyWorkGate { await gate.wait() }
        let finished = expectation(description: "gated work ran")

        Task {
            await gate.release()
            await workGate.run { finished.fulfill() }
        }

        wait(for: [finished], timeout: 2.0)
    }

    func testBlocklistForceUpdateWaitsForNetworkReady() throws {
        let gate = ReleasableGate()
        let resolver = GatedRefreshResolver()
        let manager = try makeManager(
            resolver: resolver,
            initialSettings: enabledSettings(level: "multi"),
            gate: gate
        )

        let completed = expectation(description: "force update completed")
        manager.forceUpdate { success in
            XCTAssertTrue(success)
            completed.fulfill()
        }

        drainQueues()
        XCTAssertEqual(
            resolver.refreshes.callCount,
            0,
            "blocklist refresh must not start before network-ready releases"
        )

        Task { await gate.release() }
        wait(for: [completed], timeout: 2.0)
        XCTAssertEqual(resolver.refreshes.callCount, 1)
    }

    func testBlocklistFirstEnableRefreshWaitsForNetworkReady() throws {
        let gate = ReleasableGate()
        let resolver = GatedRefreshResolver()
        let manager = try makeManager(
            resolver: resolver,
            initialSettings: BlocklistSettings(
                enabled: false,
                categories: [],
                dbBasePath: blocklistsDirectory.path
            ),
            gate: gate
        )

        let completed = expectation(description: "first enable completed")
        manager.updateSettings(enabledSettings(level: "multi")) { success in
            XCTAssertTrue(success)
            completed.fulfill()
        }

        drainQueues()
        XCTAssertEqual(
            resolver.refreshes.callCount,
            0,
            "first-enable refresh must not start before network-ready releases"
        )

        Task { await gate.release() }
        wait(for: [completed], timeout: 2.0)
        XCTAssertEqual(resolver.refreshes.callCount, 1)
    }

    func testBlocklistCategoryChangeRefreshWaitsForNetworkReady() throws {
        let gate = ReleasableGate()
        let resolver = GatedRefreshResolver()
        let manager = try makeManager(
            resolver: resolver,
            initialSettings: enabledSettings(level: "multi"),
            gate: gate
        )

        let completed = expectation(description: "category change completed")
        manager.updateSettings(enabledSettings(level: "pro")) { success in
            XCTAssertTrue(success)
            completed.fulfill()
        }

        drainQueues()
        XCTAssertEqual(
            resolver.refreshes.callCount,
            0,
            "category change refresh must not start before network-ready releases"
        )

        Task { await gate.release() }
        wait(for: [completed], timeout: 2.0)
        XCTAssertEqual(resolver.refreshes.callCount, 1)
    }

    func testValueReturningGateParksWorkUntilReleased() async {
        let gate = ReleasableGate()
        let workGate = NetworkReadyWorkGate { await gate.wait() }
        let recorder = CallRecorder()

        let gated = Task { () -> Int in
            await workGate.run {
                recorder.record()
                return 7
            }
        }

        try? await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(
            recorder.callCount,
            0,
            "value-returning gated work must not start before network-ready releases"
        )

        await gate.release()
        let result = await gated.value
        XCTAssertEqual(result, 7, "the gate must hand the caller its result back")
        XCTAssertEqual(recorder.callCount, 1)
    }

    func testScheduledUpdateChecksWaitForNetworkReady() async {
        let gate = ReleasableGate()
        let recorder = CallRecorder()
        let checked = expectation(description: "scheduled check ran")
        let task = Task {
            await UpdateChecker.runScheduledChecks(
                networkReadyGate: NetworkReadyWorkGate { await gate.wait() },
                check: {
                    recorder.record()
                    checked.fulfill()
                }
            )
        }

        try? await Task.sleep(for: .milliseconds(20))
        XCTAssertEqual(recorder.callCount, 0)
        await gate.release()
        await fulfillment(of: [checked], timeout: 2)
        task.cancel()
        await task.value
        XCTAssertEqual(recorder.callCount, 1)
    }

    // MARK: - Helpers

    private var blocklistsDirectory: URL {
        temporaryRoot.appendingPathComponent("blocklists", isDirectory: true)
    }

    private lazy var temporaryRoot: URL = {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("macdns-tests-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: url)
        }
        return url
    }()

    private func enabledSettings(level: String) -> BlocklistSettings {
        BlocklistSettings(
            enabled: true,
            categories: [
                CategoryConfig(name: "Ads & Tracking", identifier: "ads_tracking", level: level)
            ],
            dbBasePath: blocklistsDirectory.path
        )
    }

    private func makeManager(
        resolver: BlocklistResolverBackend,
        initialSettings: BlocklistSettings,
        gate: ReleasableGate
    ) throws -> BlocklistManager {
        let store = StateFileBlocklistSettingsStore(
            stateFile: temporaryRoot.appendingPathComponent("state.json"),
            projectionFile: temporaryRoot.appendingPathComponent("blocklist_settings.json"),
            blocklistsDir: blocklistsDirectory.path
        )
        XCTAssertNotNil(
            store.mutate { _ in initialSettings },
            "seeding the blocklist settings must succeed"
        )
        return BlocklistManager(
            resolver: resolver,
            store: store,
            blocklistsDir: blocklistsDirectory.path,
            networkReadyGate: NetworkReadyWorkGate { await gate.wait() }
        )
    }

    private func drainQueues(for seconds: TimeInterval = 0.2) {
        let drained = expectation(description: "queues drained")
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) { drained.fulfill() }
        wait(for: [drained], timeout: seconds + 2.0)
    }
}
