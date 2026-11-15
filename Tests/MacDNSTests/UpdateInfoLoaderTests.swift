// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNS

@MainActor
final class UpdateInfoLoaderTests: XCTestCase {
    private let info = UpdateInfo(currentVersion: "1.0.0", latestVersion: "2.0.0")

    func testTransientCacheFailureRecoversWithoutAnotherDarwinNotification() async {
        var reads = 0
        var loaded: [UpdateInfo] = []
        var presented: [String] = []
        let loader = UpdateInfoLoader(
            retryDelays: [0, 0],
            load: {
                reads += 1
                return reads < 3 ? nil : self.info
            },
            didLoad: { loaded.append($0) },
            present: {
                presented.append($0.latestVersion)
                return true
            }
        )

        loader.refresh(presentIfAvailable: true)
        await waitUntil { loader.isIdle }

        XCTAssertEqual(reads, 3)
        XCTAssertEqual(loaded.map(\.latestVersion), ["2.0.0"])
        XCTAssertEqual(presented, ["2.0.0"])
    }

    func testBackgroundHintsDuringStaleAboutReadAreCoalescedAndReconciled() async {
        let cache = ControlledUpdateCache()
        var presented = 0
        let loader = UpdateInfoLoader(
            retryDelays: [],
            load: { await cache.read() },
            didLoad: { _ in },
            present: { _ in
                presented += 1
                return true
            }
        )

        loader.refresh(presentIfAvailable: false)
        await waitUntil { cache.reads == 1 }
        for _ in 0..<20 { loader.refresh(presentIfAvailable: true) }
        cache.resolve(UpdateInfo(currentVersion: "1.0.0", latestVersion: "1.0.0"))
        await waitUntil { cache.reads == 2 }
        cache.resolve(info)
        await waitUntil { loader.isIdle }

        XCTAssertEqual(cache.reads, 2)
        XCTAssertEqual(presented, 1)
    }

    func testBusySparkleAndTransientDownloadFailureAreRetried() async {
        var attempts = 0
        let loader = UpdateInfoLoader(
            retryDelays: [0, 0],
            load: { self.info },
            didLoad: { _ in },
            present: { _ in
                attempts += 1
                return attempts == 3
            }
        )

        loader.refresh(presentIfAvailable: true)
        await waitUntil { loader.isIdle }

        XCTAssertEqual(attempts, 3)
    }

    func testExhaustedBusyRetriesResumeWhenSparkleFinishesExistingSession() async {
        var ready = false
        var presented = 0
        let loader = UpdateInfoLoader(
            retryDelays: [],
            load: { self.info },
            didLoad: { _ in },
            present: { _ in
                if ready { presented += 1 }
                return ready
            }
        )

        loader.refresh(presentIfAvailable: true)
        await waitUntil { loader.isIdle }
        XCTAssertEqual(presented, 0)
        ready = true
        loader.retryPendingPresentation()
        await waitUntil { loader.isIdle }
        loader.retryPendingPresentation()

        XCTAssertTrue(loader.isIdle)
        XCTAssertEqual(presented, 1)
    }

    func testFailedReadsAreBoundedAndNeverPresentUnverifiedInfo() async {
        var reads = 0
        var presented = 0
        let loader = UpdateInfoLoader(
            retryDelays: [0, 0],
            load: {
                reads += 1
                return nil
            },
            didLoad: { _ in XCTFail("no authoritative response") },
            present: { _ in
                presented += 1
                return true
            }
        )

        loader.refresh(presentIfAvailable: true)
        await waitUntil { loader.isIdle }

        XCTAssertEqual(reads, 3)
        XCTAssertEqual(presented, 0)
    }

    func testAboutReadDoesNotPresentAndCancellationIgnoresLateReply() async {
        let cache = ControlledUpdateCache()
        let loader = UpdateInfoLoader(
            retryDelays: [],
            load: { await cache.read() },
            didLoad: { _ in XCTFail("cancelled reply must be ignored") },
            present: { _ in
                XCTFail("About must not prompt")
                return true
            }
        )

        loader.refresh(presentIfAvailable: false)
        await waitUntil { cache.reads == 1 }
        loader.cancel()
        cache.resolve(info)
        await waitUntil { loader.isIdle }
        loader.retryPendingPresentation()

        XCTAssertTrue(loader.isIdle)
        XCTAssertEqual(cache.reads, 1)
    }

    func testSettingsReadLoadsAnAvailableUpdateWithoutPresentingIt() async {
        var loaded: UpdateInfo?
        let loader = UpdateInfoLoader(
            retryDelays: [],
            load: { self.info },
            didLoad: { loaded = $0 },
            present: { _ in
                XCTFail("Opening Settings must not present an update")
                return true
            }
        )

        loader.refresh(presentIfAvailable: false)
        await waitUntil { loader.isIdle }

        XCTAssertEqual(loaded?.latestVersion, info.latestVersion)
    }

    private func waitUntil(_ predicate: () -> Bool, file: StaticString = #filePath, line: UInt = #line) async {
        for _ in 0..<1000 {
            if predicate() { return }
            await Task.yield()
        }
        XCTFail("operation did not finish", file: file, line: line)
    }
}

@MainActor
private final class ControlledUpdateCache {
    private var continuation: CheckedContinuation<UpdateInfo?, Never>?
    private(set) var reads = 0

    func read() async -> UpdateInfo? {
        reads += 1
        return await withCheckedContinuation { continuation = $0 }
    }

    func resolve(_ info: UpdateInfo?) {
        continuation?.resume(returning: info)
        continuation = nil
    }
}
