// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

struct PermissionApprovalStatePolicy: Equatable {
    let agentNeedsApproval: Bool
    let proxyNeedsApproval: Bool
    let filterNeedsApproval: Bool

    var needsPermissionApproval: Bool {
        agentNeedsApproval || proxyNeedsApproval || filterNeedsApproval
    }
}
