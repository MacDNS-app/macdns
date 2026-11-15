import Foundation

public struct ProtectionDisplayState {
    public let providerState: ProviderInterceptionState

    // The single derivation point: everything user-visible comes from here.
    public var statusPolicy: ProtectionStatusPolicy {
        ProtectionStatusPolicy(providerState: providerState)
    }
}
