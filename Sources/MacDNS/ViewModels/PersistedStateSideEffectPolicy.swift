// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// Runtime work triggered by the Block DoH & DoT toggle.
enum BlockDohDotSideEffect: Equatable {
    case none
    case enableContentFilter
    case disableContentFilter
}

/// Decides which side effects a persisted-state apply is allowed to trigger.
///
/// The decision must be taken synchronously inside the property observer:
/// `isApplyingPersistedState` is cleared by a `defer` as soon as the apply
/// returns, so a guard evaluated later, inside a `Task` body, always sees
/// `false` and lets a reloaded value tear down runtime state and clear notices.
enum PersistedStateSideEffectPolicy {
    static func blockDohDotSideEffect(
        oldValue: Bool,
        newValue: Bool,
        isApplyingPersistedState: Bool
    ) -> BlockDohDotSideEffect {
        guard oldValue != newValue, !isApplyingPersistedState else {
            return .none
        }
        return newValue ? .enableContentFilter : .disableContentFilter
    }
}
