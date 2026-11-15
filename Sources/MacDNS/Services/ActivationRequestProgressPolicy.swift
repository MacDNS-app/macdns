// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

struct ActivationRequestProgressPolicy: Equatable {
    let pendingContinuations: Int

    var shouldClearInProgressAfterWaiterRemoval: Bool {
        pendingContinuations == 0
    }
}
