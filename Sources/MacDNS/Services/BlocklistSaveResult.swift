// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

enum BlocklistSaveResult: Equatable {
    case saved
    case rejectedByAgent
    case agentUnavailable
    case timedOut
    case encodingFailed

    func shouldFallbackToFile(agentAllowsFallback: Bool) -> Bool {
        self == .agentUnavailable && agentAllowsFallback
    }
}
