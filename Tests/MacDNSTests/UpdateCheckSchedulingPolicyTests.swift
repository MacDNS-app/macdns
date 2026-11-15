// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNSAgent

private final class AttemptRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    var attempts: Int {
        lock.withLock { count }
    }

    func record() -> Int {
        lock.withLock {
            count += 1
            return count
        }
    }
}

final class UpdateCheckSchedulingPolicyTests: XCTestCase {
    private let info = UpdateInfo(currentVersion: "1.0.0", latestVersion: "1.1.0")

    func testTransientFailureRetriesWithinBounds() async {
        let recorder = AttemptRecorder()

        let result = await UpdateChecker.withBoundedRetry(retryDelays: [0.01, 0.01, 0.01]) {
            recorder.record() < 3 ? nil : self.info
        }

        XCTAssertEqual(result?.latestVersion, "1.1.0")
        XCTAssertEqual(recorder.attempts, 3)
    }

    func testRetriesStopWhenBackoffScheduleIsExhausted() async {
        let recorder = AttemptRecorder()

        let result = await UpdateChecker.withBoundedRetry(retryDelays: [0.01, 0.01]) {
            _ = recorder.record()
            return nil
        }

        XCTAssertNil(result)
        XCTAssertEqual(
            recorder.attempts,
            3,
            "one immediate attempt plus one per configured backoff delay"
        )
    }

    func testSuccessStopsRetries() async {
        let recorder = AttemptRecorder()

        let result = await UpdateChecker.withBoundedRetry(retryDelays: [60, 60]) {
            _ = recorder.record()
            return self.info
        }

        XCTAssertNotNil(result)
        XCTAssertEqual(recorder.attempts, 1)
    }

    func testCancellationStopsPendingRetry() {
        let recorder = AttemptRecorder()
        let firstAttempt = expectation(description: "first attempt ran")
        let finished = expectation(description: "retry driver returned")

        let task = Task {
            let result = await UpdateChecker.withBoundedRetry(retryDelays: [60, 60]) {
                if recorder.record() == 1 {
                    firstAttempt.fulfill()
                }
                return nil
            }
            XCTAssertNil(result)
            finished.fulfill()
        }

        wait(for: [firstAttempt], timeout: 2.0)
        task.cancel()
        wait(for: [finished], timeout: 2.0)

        XCTAssertEqual(
            recorder.attempts,
            1,
            "a cancelled agent shutdown must not run another attempt"
        )
    }

    func testInitialRetryScheduleIsBounded() {
        XCTAssertFalse(UpdateChecker.initialRetryDelays.isEmpty)
        XCTAssertEqual(
            UpdateChecker.initialRetryDelays,
            UpdateChecker.initialRetryDelays.sorted(),
            "backoff must not shrink between attempts"
        )
    }

    func testScheduledChecksRepeatWithoutLicenseOrResolverActivity() async {
        let recorder = AttemptRecorder()
        let repeated = expectation(description: "update check repeated")
        let task = Task {
            await UpdateChecker.runScheduledChecks(
                interval: 0.01,
                networkReadyGate: NetworkReadyWorkGate {},
                check: {
                    if recorder.record() == 2 { repeated.fulfill() }
                }
            )
        }

        await fulfillment(of: [repeated], timeout: 2)
        task.cancel()
        await task.value
        XCTAssertGreaterThanOrEqual(recorder.attempts, 2)
    }

    func testScheduledCheckCancellationDoesNotStartWorkAfterNetworkGateOpens() async {
        let gate = UpdateNetworkGate()
        let recorder = AttemptRecorder()
        let task = Task {
            await UpdateChecker.runScheduledChecks(
                networkReadyGate: NetworkReadyWorkGate { await gate.wait() },
                check: { _ = recorder.record() }
            )
        }

        await gate.waitUntilBlocked()
        XCTAssertEqual(recorder.attempts, 0)
        task.cancel()
        await gate.release()
        await task.value
        XCTAssertEqual(recorder.attempts, 0)
    }

    func testScheduledChecksWaitForPreviousCheckToFinish() async {
        let gate = UpdateNetworkGate()
        let recorder = AttemptRecorder()
        let task = Task {
            await UpdateChecker.runScheduledChecks(
                interval: 0,
                networkReadyGate: NetworkReadyWorkGate {},
                check: {
                    _ = recorder.record()
                    await gate.wait()
                }
            )
        }

        await gate.waitUntilBlocked()
        XCTAssertEqual(recorder.attempts, 1)
        task.cancel()
        await gate.release()
        await task.value
        XCTAssertEqual(recorder.attempts, 1)
    }

    func testAgentFeedMatchesCanonicalBuildFeed() throws {
        let helperMakefile = try XCTUnwrap(
            repositoryFile(named: "helper.mk"),
            "helper.mk not found above the test source path"
        )
        let contents = try String(contentsOf: helperMakefile, encoding: .utf8)
        let buildFeed = try XCTUnwrap(
            contents
                .split(separator: "\n")
                .first(where: { $0.hasPrefix("SPARKLE_FEED_URL") })?
                .split(separator: "=", maxSplits: 1).last?
                .trimmingCharacters(in: .whitespaces),
            "SPARKLE_FEED_URL missing from helper.mk"
        )

        XCTAssertEqual(
            UpdateChecker.appcastFeedURL,
            buildFeed,
            "the agent must poll the same appcast feed Sparkle is built against"
        )
    }

    private func repositoryFile(named name: String, from filePath: String = #filePath) -> URL? {
        var directory = URL(fileURLWithPath: filePath).deletingLastPathComponent()
        while directory.path != "/" {
            let candidate = directory.appendingPathComponent(name)
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
            directory = directory.deletingLastPathComponent()
        }
        return nil
    }
}

private actor UpdateNetworkGate {
    private var waiter: CheckedContinuation<Void, Never>?
    private var observers: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        await withCheckedContinuation { continuation in
            waiter = continuation
            observers.forEach { $0.resume() }
            observers.removeAll()
        }
    }

    func waitUntilBlocked() async {
        if waiter != nil { return }
        await withCheckedContinuation { observers.append($0) }
    }

    func release() {
        waiter?.resume()
        waiter = nil
    }
}
