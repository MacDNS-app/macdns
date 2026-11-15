import Foundation

// The one place that decides interception, and it only ever reports what the
// agent observed — never what the user asked for.
struct RuntimeStatePresentationPolicy {
    static func displayState(from snapshot: RuntimeStateSnapshot) -> ProtectionDisplayState {
        var providerState: ProviderInterceptionState = .unknown
        switch snapshot.proxyInterceptionState {
        case "intercepting":
            providerState = .intercepting
        case "bypass":
            providerState = .bypass
        default:
            providerState = .unknown
        }
        return ProtectionDisplayState(providerState: providerState)
    }
}
