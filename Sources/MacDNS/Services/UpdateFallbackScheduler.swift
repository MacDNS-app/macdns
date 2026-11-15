// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Discovers updates independently of the Agent's cached update information.
@MainActor
enum UpdateFallbackScheduler {
    static func run(
        initialDelay: TimeInterval = 30,
        interval: TimeInterval = UpdateDiscoveryFreshnessPolicy.interval,
        retryDelays: [TimeInterval] = [1, 5, 30, 60],
        checkForUpdates: () async -> Bool,
        sleep: (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) }
    ) async {
        do {
            try await sleep(max(initialDelay, 0))
            while !Task.isCancelled {
                for delay in [0] + retryDelays {
                    if delay > 0 { try await sleep(delay) }
                    try Task.checkCancellation()
                    let completed = await checkForUpdates()
                    try Task.checkCancellation()
                    if completed { break }
                }
                try Task.checkCancellation()
                try await sleep(max(interval, 0))
            }
        } catch {
            // Cancelling the App's task ends startup, retry, or periodic waits.
        }
    }
}
