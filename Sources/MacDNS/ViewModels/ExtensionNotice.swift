// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

enum ExtensionNotice: Equatable {
    case none
    case proxyApprovalRequired
    case filterApprovalRequired
    case restartRequired

    mutating func applyApprovalStatus(proxyNeedsApproval: Bool, filterNeedsApproval: Bool) {
        guard self != .restartRequired else { return }

        if proxyNeedsApproval {
            self = .proxyApprovalRequired
        } else if filterNeedsApproval {
            self = .filterApprovalRequired
        } else if self == .proxyApprovalRequired || self == .filterApprovalRequired {
            self = .none
        }
    }

    mutating func clearRestartRequiredIfResolved(
        proxyRequiresRestart: Bool, filterRequiresRestart: Bool, versionStale: Bool,
        recoveryExhausted: Bool
    ) {
        guard self == .restartRequired, !proxyRequiresRestart, !filterRequiresRestart,
            !versionStale, !recoveryExhausted
        else { return }
        self = .none
    }

    func statusMessageOverride(isProtectionActive: Bool) -> String? {
        switch self {
        case .none:
            return nil
        case .proxyApprovalRequired:
            return "Approval Required"
        case .filterApprovalRequired:
            return isProtectionActive ? nil : "Approval Required"
        case .restartRequired:
            return "Restart Required"
        }
    }

    func statusMessageOverride(isProtectionActive: Bool, fallbackNeedsApproval: Bool) -> String? {
        guard self == .none else {
            return statusMessageOverride(isProtectionActive: isProtectionActive)
        }

        return fallbackNeedsApproval ? "Approval Required" : nil
    }

    func permissionBannerMessage(isProtectionActive: Bool) -> String? {
        switch self {
        case .none:
            return nil
        case .proxyApprovalRequired:
            return "Approval required in System Settings"
        case .filterApprovalRequired:
            return isProtectionActive
                ? "Approve Content Filter to block DoH/DoT"
                : "Approval required in System Settings"
        case .restartRequired:
            return "Restart required to finish extension activation"
        }
    }

    func permissionBannerMessage(isProtectionActive: Bool, fallbackNeedsApproval: Bool) -> String? {
        if let message = permissionBannerMessage(isProtectionActive: isProtectionActive) {
            return message
        }

        return fallbackNeedsApproval ? "Approval required in System Settings" : nil
    }
}
