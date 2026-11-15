// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNS

@MainActor
final class UpdatePromptHistoryTests: XCTestCase {
    func testPromptCooldownSurvivesRelaunchWithoutChangingSparklePreferences() throws {
        let domain = "app.macdns.update-prompt-test.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: domain))
        defer { defaults.removePersistentDomain(forName: domain) }
        defaults.set(true, forKey: "SUEnableAutomaticChecks")
        let firstLaunch = UpdatePromptHistory.persistedUpdatePromptHistory(defaults: defaults)
        let shownAt = Date(timeIntervalSince1970: 1000)

        XCTAssertTrue(firstLaunch.allowsPrompt(version: "2.0.0", at: shownAt))
        firstLaunch.recordPrompt(version: "2.0.0", at: shownAt)
        let nextLaunch = UpdatePromptHistory.persistedUpdatePromptHistory(
            defaults: try XCTUnwrap(UserDefaults(suiteName: domain))
        )

        XCTAssertFalse(nextLaunch.allowsPrompt(version: "2.0.0", at: shownAt.addingTimeInterval(60)))
        XCTAssertTrue(nextLaunch.allowsPrompt(version: "2.0.0", at: shownAt.addingTimeInterval(24 * 3600)))
        XCTAssertTrue(nextLaunch.allowsPrompt(version: "2.1.0", at: shownAt.addingTimeInterval(60)))
        nextLaunch.recordPrompt(version: "2.1.0", at: shownAt.addingTimeInterval(60))
        XCTAssertFalse(nextLaunch.allowsPrompt(version: "2.0.0", at: shownAt.addingTimeInterval(120)))
        XCTAssertTrue(defaults.bool(forKey: "SUEnableAutomaticChecks"))
    }

    func testClockRollbackDoesNotSuppressPromptsIndefinitely() throws {
        let domain = "app.macdns.update-prompt-test.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: domain))
        defer { defaults.removePersistentDomain(forName: domain) }
        let history = UpdatePromptHistory.persistedUpdatePromptHistory(defaults: defaults)
        let shownAt = Date(timeIntervalSince1970: 1000)
        history.recordPrompt(version: "2.0.0", at: shownAt)

        XCTAssertTrue(history.allowsPrompt(version: "2.0.0", at: shownAt.addingTimeInterval(-3600)))
    }
}
