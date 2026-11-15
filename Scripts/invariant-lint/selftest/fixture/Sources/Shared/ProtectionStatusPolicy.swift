import Foundation

public enum ProtectionStatus {
    case active
    case degraded
    case off
}

public enum ProviderInterceptionState {
    case intercepting
    case bypass
    case unknown
}

// The single owner of every user-visible protection string.
public struct ProtectionStatusPolicy {
    public let providerState: ProviderInterceptionState

    public var status: ProtectionStatus {
        switch providerState {
        case .intercepting:
            return .active
        case .bypass:
            return .degraded
        case .unknown:
            return .degraded
        }
    }

    public var headline: String {
        switch status {
        case .active:
            return "Active"
        default:
            return "Not Protected"
        }
    }

    public var statusMessage: String {
        switch status {
        case .active:
            return "Protection Active"
        default:
            return "Protection Off"
        }
    }
}
