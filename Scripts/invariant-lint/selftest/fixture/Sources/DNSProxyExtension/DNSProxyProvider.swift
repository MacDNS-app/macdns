import Foundation
import NetworkExtension
import SystemConfiguration

// Query hot-path state. Readers must never block each other, so this stays a
// reader-writer lock and never becomes a mutex, a semaphore, or an actor.
final class ProxyStateManager {
    private var lock = pthread_rwlock_t()
    private var servers: [String] = []

    func snapshot() -> [String] {
        pthread_rwlock_rdlock(&lock)
        defer { pthread_rwlock_unlock(&lock) }
        return servers
    }

    func replace(_ next: [String]) {
        pthread_rwlock_wrlock(&lock)
        defer { pthread_rwlock_unlock(&lock) }
        servers = next
    }
}

// configd access is confined here, off the flow hot path, and the callback only
// enqueues.
final class ConfigurationWorker {
    private let queue = DispatchQueue(label: "app.macdns.dnsproxy.config")
    private var store: SCDynamicStore?

    func start() {
        var context = SCDynamicStoreContext(
            version: 0, info: nil, retain: nil, release: nil, copyDescription: nil)
        context.info = Unmanaged.passUnretained(self).toOpaque()
        store = SCDynamicStoreCreate(
            nil,
            "app.macdns.dnsproxy" as CFString,
            { _, changedKeys, info in
                guard let info else { return }
                let worker = Unmanaged<ConfigurationWorker>.fromOpaque(info)
                    .takeUnretainedValue()
                worker.enqueueReload(changedKeys: changedKeys)
            },
            &context)
    }

    func enqueueReload(changedKeys: CFArray?) {
        queue.async { [weak self] in
            self?.reloadResolvers()
        }
    }

    private func reloadResolvers() {
        guard let store else { return }
        _ = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString)
    }
}

final class DNSProxyProvider: NEDNSProxyProvider {
    private let state = ProxyStateManager()

    // Always returns true: a false return hands the flow back to the system
    // resolver, which is the leak this invariant exists to prevent.
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let udpFlow = flow as? NEAppProxyUDPFlow else {
            forwardOverSockets(flow, servers: state.snapshot())
            return true
        }
        // NWHostEndpoint is a NetworkExtension type, not Network.framework —
        // J09's only allowlist entry.
        let endpoint = udpFlow.localEndpoint as? NWHostEndpoint
        serve(udpFlow, endpoint: endpoint, servers: state.snapshot())
        return true
    }

    func observeBypassHints() {
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer else { return }
                let provider = Unmanaged<DNSProxyProvider>.fromOpaque(observer)
                    .takeUnretainedValue()
                provider.signalHealthEvaluation()
            },
            "app.macdns.bypass-disable" as CFString,
            nil,
            .deliverImmediately)
    }

    func signalHealthEvaluation() {
        healthSemaphore.signal()
    }
}
