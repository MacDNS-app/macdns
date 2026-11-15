// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared

enum ProxyEnableResult: Equatable {
    case enabled
    case inactive
    case captivePortalBypass

    var resolverModeText: String {
        switch self {
        case .enabled:
            return ProtectionStatusPolicy.encryptedModeMessage
        case .inactive:
            return ProtectionStatusPolicy.dnsProxyInactiveMessage
        case .captivePortalBypass:
            return ProtectionStatusPolicy.captiveBypassMessage
        }
    }

    var captivePortalDetectedAfterResolveAttempt: Bool {
        self == .captivePortalBypass
    }
}
