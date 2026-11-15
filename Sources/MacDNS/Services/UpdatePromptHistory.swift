// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Presentation history only. Configuration remains owned by the Agent.
@MainActor
struct UpdatePromptHistory {
    private let read: () -> [String: Date]
    private let write: (String, Date) -> Void
    private static let cooldown: TimeInterval = 24 * 3600

    func allowsPrompt(version: String, at date: Date = Date()) -> Bool {
        guard let previous = read()[version] else { return true }
        let elapsed = date.timeIntervalSince(previous)
        return elapsed < 0 || elapsed >= Self.cooldown
    }

    func recordPrompt(version: String, at date: Date = Date()) {
        write(version, date)
    }

    static func persistedUpdatePromptHistory(defaults: UserDefaults = .standard) -> Self {
        let key = "softwareUpdatePromptDates"
        return Self(
            read: {
                defaults.dictionary(forKey: key) as? [String: Date] ?? [:]
            },
            write: { version, date in
                var dates = (defaults.dictionary(forKey: key) as? [String: Date] ?? [:]).filter {
                    let elapsed = date.timeIntervalSince($0.value)
                    return elapsed >= 0 && elapsed < Self.cooldown
                }
                dates[version] = date
                defaults.set(dates, forKey: key)
            }
        )
    }
}
