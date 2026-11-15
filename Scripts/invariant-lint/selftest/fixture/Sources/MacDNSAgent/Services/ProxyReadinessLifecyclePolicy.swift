import Foundation

// The ordered readiness steps the agent publishes around a resolver
// start/stop. The invariant's notification order lives here: start is
// proxyEnable then bypassDisable, stop is bypassEnable then proxyDisable.
//
// `.wakeBypassProbe` posts bypassEnable when the list also requests bypass and
// bypassDisable otherwise, so the position of `.setBypassRequested(true)`
// decides which of the two a list ends in.
enum ProxyReadinessAction: Equatable {
    case setBypassRequested(Bool)
    case notifyProxyEnable
    case notifyProxyDisable
    case wakeBypassProbe
}

enum ProxyReadinessLifecyclePolicy {
    static func startActions(
        keepProxyBypass: Bool
    ) -> [ProxyReadinessAction] {
        [
            .notifyProxyEnable,
            .setBypassRequested(keepProxyBypass),
            .wakeBypassProbe,
        ]
    }

    static let stopActions: [ProxyReadinessAction] = [
        .setBypassRequested(true),
        .wakeBypassProbe,
        .notifyProxyDisable,
    ]

    static let captivePortalBypassActions: [ProxyReadinessAction] = [
        .setBypassRequested(true),
        .wakeBypassProbe,
    ]
}
