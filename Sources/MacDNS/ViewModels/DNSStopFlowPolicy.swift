// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

struct DNSStopFlowPolicy: Equatable {
    let contentFilterEnabled: Bool

    var shouldDisableContentFilter: Bool {
        contentFilterEnabled
    }
}
