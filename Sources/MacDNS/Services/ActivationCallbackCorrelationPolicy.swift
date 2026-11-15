// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

struct ActivationCallbackCorrelationPolicy: Equatable {
    let callbackGeneration: UInt64?
    let activeGeneration: UInt64?

    var shouldApplyCallback: Bool {
        guard let callbackGeneration, let activeGeneration else { return false }
        return callbackGeneration == activeGeneration
    }
}
