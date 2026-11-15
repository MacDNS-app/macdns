import Foundation
import SystemConfiguration

// The SCDynamicStore callback runs on configd's thread: it may only hand work
// off. Calling back into SCDynamicStore* from the callback can deadlock configd.
final class NetworkMonitor {
    let queue = DispatchQueue(label: "app.macdns.agent.network")
    let dnsKey = "State:/Network/Global/DNS" as CFString
    var store: SCDynamicStore?

    func start() {
        var context = SCDynamicStoreContext(
            version: 0, info: nil, retain: nil, release: nil, copyDescription: nil)
        context.info = Unmanaged.passUnretained(self).toOpaque()
        store = SCDynamicStoreCreate(
            nil,
            "app.macdns.agent" as CFString,
            { _, changedKeys, info in
                guard let info else { return }
                let monitor = Unmanaged<NetworkMonitor>.fromOpaque(info).takeUnretainedValue()
                // NEGATIVE CONTROL for J10: the configd read is inside a
                // single-line hand-off, so it runs on the monitor's queue and
                // not on configd's thread. Only the closure body is exempt.
                monitor.queue.async { _ = SCDynamicStoreCopyValue(monitor.store, monitor.dnsKey) }
            },
            &context)
    }

    func enqueueConfigurationChange(changedKeys: CFArray?) {
        queue.async { [weak self] in
            self?.reload()
        }
    }

    func reload() {
        _ = SCDynamicStoreCopyValue(store, dnsKey)
    }
}
