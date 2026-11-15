// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

enum PersistedStateResponsePolicy {
    static func canApply(
        requestGeneration: UInt64,
        currentGeneration: UInt64,
        coordinatorIsIdle: Bool
    ) -> Bool {
        requestGeneration == currentGeneration && coordinatorIsIdle
    }
}
