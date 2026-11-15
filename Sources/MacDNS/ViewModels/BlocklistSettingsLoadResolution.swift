// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared

/// Resolves a blocklist settings load using the agent response first and the
/// authoritative `state.json` file fallback second. The agent projects these
/// settings into `blocklist_settings.json` for the resolver. When both load
/// sources fail, settings stay unavailable and mutation must remain blocked
/// so in-memory defaults cannot overwrite the user's saved categories.
enum BlocklistSettingsLoadResolution: Equatable {
    case apply(BlocklistSettings)
    case keepUnavailable

    static func resolve(
        agentSettings: BlocklistSettings?,
        fileSettings: () -> BlocklistSettings?
    ) -> BlocklistSettingsLoadResolution {
        if let agentSettings {
            return .apply(agentSettings)
        }
        if let fileSettings = fileSettings() {
            return .apply(fileSettings)
        }
        return .keepUnavailable
    }
}
