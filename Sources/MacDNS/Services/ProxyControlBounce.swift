// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

@MainActor
enum ProxyControlBounce {
    static func run(
        isCurrent: () -> Bool,
        disable: () async throws -> Void,
        waitForExit: () async -> Void,
        enable: () async throws -> Void,
        rollbackStaleEnable: () async -> Void = {}
    ) async throws {
        guard !Task.isCancelled, isCurrent() else { return }
        try await disable()
        guard !Task.isCancelled, isCurrent() else { return }
        await waitForExit()
        guard !Task.isCancelled, isCurrent() else { return }
        do {
            try await enable()
        } catch {
            if !isCurrent() { await rollbackStaleEnable() }
            throw error
        }
        if !isCurrent() { await rollbackStaleEnable() }
    }
}
