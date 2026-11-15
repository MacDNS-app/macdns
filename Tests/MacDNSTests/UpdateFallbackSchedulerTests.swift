// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNS

@MainActor
final class UpdateFallbackSchedulerTests: XCTestCase {
    func testFallbackChecksEveryHourAfterStartupDelayWithoutOpeningSettings() async {
        let clock = FallbackTestClock(allowedSleeps: 2)
        var checks = 0
        await UpdateFallbackScheduler.run(
            checkForUpdates: {
                XCTAssertEqual(clock.delays.first, 30, "The first network check must wait for startup")
                checks += 1
                return true
            },
            sleep: clock.sleep
        )

        XCTAssertEqual(checks, 2)
        XCTAssertEqual(clock.delays, [30, 3600, 3600])
    }

    func testBusyOrFailedSparkleChecksRetryUntilDelivered() async {
        let clock = FallbackTestClock(allowedSleeps: 3)
        var checks = 0
        await UpdateFallbackScheduler.run(
            retryDelays: [1, 5, 30],
            checkForUpdates: {
                checks += 1
                return checks == 3
            },
            sleep: clock.sleep
        )

        XCTAssertEqual(checks, 3)
        XCTAssertEqual(clock.delays, [30, 1, 5, 3600])
    }

    func testFailedRetriesAreBoundedAndResumeNextCycle() async {
        let clock = FallbackTestClock(allowedSleeps: 6)
        var checks = 0
        await UpdateFallbackScheduler.run(
            retryDelays: [1, 5],
            checkForUpdates: {
                checks += 1
                return false
            },
            sleep: clock.sleep
        )

        XCTAssertEqual(checks, 6)
        XCTAssertEqual(clock.delays, [30, 1, 5, 3600, 1, 5, 3600])
    }

    func testCancellationDuringRetryWaitStopsFurtherDiscovery() async {
        let clock = FallbackTestClock(allowedSleeps: 1)
        var checks = 0
        await UpdateFallbackScheduler.run(
            checkForUpdates: {
                checks += 1
                return false
            },
            sleep: clock.sleep
        )

        XCTAssertEqual(checks, 1)
        XCTAssertEqual(clock.delays, [30, 1])
    }

    func testCancellationDuringStartupPreventsNetworkWork() async {
        let task = Task {
            await UpdateFallbackScheduler.run(
                checkForUpdates: {
                    XCTFail("Cancelled startup must not start Sparkle")
                    return true
                }
            )
        }
        task.cancel()
        await task.value
    }

    func testCancellationDuringDiscoveryStopsBeforeFurtherWaits() async {
        let clock = FallbackTestClock(allowedSleeps: 2)
        var checks = 0
        let task = Task {
            await UpdateFallbackScheduler.run(
                checkForUpdates: {
                    checks += 1
                    withUnsafeCurrentTask { $0?.cancel() }
                    return false
                },
                sleep: clock.sleep
            )
        }
        await task.value

        XCTAssertEqual(checks, 1)
        XCTAssertEqual(clock.delays, [30])
    }
}

@MainActor
private final class FallbackTestClock {
    private let allowedSleeps: Int
    private(set) var delays: [TimeInterval] = []

    init(allowedSleeps: Int) {
        self.allowedSleeps = allowedSleeps
    }

    func sleep(_ delay: TimeInterval) async throws {
        delays.append(delay)
        if delays.count > allowedSleeps { throw CancellationError() }
    }
}
