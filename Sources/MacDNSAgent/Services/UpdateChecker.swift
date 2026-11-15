// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

// MARK: - Update Checker

/// Checks appcast.xml and signals the App when an update is available.
actor UpdateChecker {

    // MARK: - Singleton

    static let shared = UpdateChecker()

    // MARK: - Configuration

    /// Must stay identical to `SPARKLE_FEED_URL` in `helper.mk`. The agent's
    /// update notification and the App's Sparkle updater must never read
    /// different feeds.
    static let appcastFeedURL = "https://raw.githubusercontent.com/MacDNS-app/macdns/main/appcast.xml"

    /// Each scheduled check gets bounded retries before the next 2h cycle.
    static let initialRetryDelays: [TimeInterval] = [15, 60, 300]

    static let checkInterval: TimeInterval = 2 * 3600

    private enum Config {
        static let requestTimeout: TimeInterval = 30
    }

    // MARK: - Properties

    private var cachedUpdateInfo: UpdateInfo?

    nonisolated(unsafe) var onUpdateAvailable: (() -> Void)?

    // MARK: - Initialization

    private init() {}

    // MARK: - Public Methods

    /// - Parameter notifyApp: Whether to wake the App through a Darwin notification.
    /// - Returns: nil when the check failed.
    func checkForUpdates(notifyApp: Bool = true) async -> UpdateInfo? {
        guard let url = URL(string: UpdateChecker.appcastFeedURL) else {
            AgentLogger.shared.error("Invalid appcast URL")
            return nil
        }

        do {
            var request = URLRequest(url: url)
            request.timeoutInterval = Config.requestTimeout
            request.cachePolicy = .reloadIgnoringLocalCacheData

            let (data, response) = try await URLSession.shared.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse,
                httpResponse.statusCode == 200
            else {
                AgentLogger.shared.error("Failed to fetch appcast: invalid response")
                return nil
            }

            guard let latestVersion = parseAppcastVersion(from: data) else {
                AgentLogger.shared.error("Failed to parse appcast version")
                return nil
            }

            let currentVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"

            let info = UpdateInfo(
                currentVersion: currentVersion,
                latestVersion: latestVersion
            )

            cachedUpdateInfo = info

            if info.isUpdateAvailable {
                AgentLogger.shared.info("Update available: \(currentVersion) -> \(latestVersion)")

                if notifyApp {
                    await MainActor.run {
                        onUpdateAvailable?()
                    }
                }
            } else {
                AgentLogger.shared.debug("No update available (current: \(currentVersion), latest: \(latestVersion))")
            }

            return info
        } catch {
            AgentLogger.shared.error("Failed to check for updates: \(error)")
            return nil
        }
    }

    /// Runs for the Agent lifetime, independent of license and resolver state.
    static func runScheduledChecks(
        interval: TimeInterval = checkInterval,
        networkReadyGate: NetworkReadyWorkGate = .shared,
        check: (@Sendable () async -> Void)? = nil
    ) async {
        await networkReadyGate.run {
            while !Task.isCancelled {
                if let check {
                    await check()
                } else {
                    _ = await UpdateChecker.shared.checkForUpdatesWithBoundedRetry()
                }
                do {
                    try await Task.sleep(for: .seconds(max(interval, 0)))
                } catch {
                    return
                }
            }
        }
    }

    func checkForUpdatesWithBoundedRetry() async -> UpdateInfo? {
        await UpdateChecker.withBoundedRetry(retryDelays: UpdateChecker.initialRetryDelays) {
            await self.checkForUpdates()
        }
    }

    /// Retry sequencer, kept separate from the network call so the bounds and the
    /// cancellation behaviour are testable without network access. Returns the
    /// first successful result, or `nil` once the schedule is exhausted or the
    /// surrounding task is cancelled.
    static func withBoundedRetry(
        retryDelays: [TimeInterval],
        check: () async -> UpdateInfo?
    ) async -> UpdateInfo? {
        var attempt = 0
        while true {
            guard !Task.isCancelled else { return nil }
            if let info = await check() {
                return info
            }
            attempt += 1
            guard attempt <= retryDelays.count else {
                AgentLogger.shared.warning("Update check gave up after \(attempt) attempts")
                return nil
            }
            let delay = max(retryDelays[attempt - 1], 0)
            do {
                try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            } catch {
                return nil
            }
        }
    }

    func getCachedUpdateInfo() -> UpdateInfo? {
        cachedUpdateInfo
    }

    // MARK: - Private Methods

    /// Prefers `shortVersionString` (the display version) over `version` (the
    /// build number).
    private func parseAppcastVersion(from data: Data) -> String? {
        guard let xmlString = String(data: data, encoding: .utf8) else { return nil }

        let shortVersionPattern = #"<sparkle:shortVersionString>([^<]+)</sparkle:shortVersionString>"#
        if let regex = try? NSRegularExpression(pattern: shortVersionPattern),
            let match = regex.firstMatch(in: xmlString, range: NSRange(xmlString.startIndex..., in: xmlString)),
            let versionRange = Range(match.range(at: 1), in: xmlString)
        {
            return String(xmlString[versionRange])
        }

        let versionPattern = #"<sparkle:version>([^<]+)</sparkle:version>"#
        if let regex = try? NSRegularExpression(pattern: versionPattern),
            let match = regex.firstMatch(in: xmlString, range: NSRange(xmlString.startIndex..., in: xmlString)),
            let versionRange = Range(match.range(at: 1), in: xmlString)
        {
            return String(xmlString[versionRange])
        }

        return nil
    }

}
