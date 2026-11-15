// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import SystemConfiguration

protocol NetworkMonitorDelegate: AnyObject {
    func networkStatusChanged(
        isConnected: Bool,
        callbackLifecycleGeneration: UInt64
    )
    func networkConfigurationChanged(
        isConnected: Bool,
        callbackLifecycleGeneration: UInt64
    )
}

/// Reads network configuration values.
///
/// Abstracted so the monitor never touches `SCDynamicStore` from inside a
/// configd callback and so the deferred read path is testable.
protocol NetworkConfigurationReading: AnyObject {
    func copyValue(forKey key: String) -> [String: Any]?
}

private final class DynamicStoreConfigurationReader: NetworkConfigurationReading {
    private let store: SCDynamicStore

    init(store: SCDynamicStore) {
        self.store = store
    }

    func copyValue(forKey key: String) -> [String: Any]? {
        SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any]
    }
}

/// Reachability derived from both global address families.
///
/// Connected means either family exposes a primary interface, so an IPv6-only
/// configuration is not reported as disconnected. The concrete interface and
/// service identity is retained so callers can tell a primary-interface
/// replacement apart from an unchanged connection.
struct NetworkReachabilitySnapshot: Equatable {
    static let ipv4GlobalKey = "State:/Network/Global/IPv4"
    static let ipv6GlobalKey = "State:/Network/Global/IPv6"

    static let disconnected = NetworkReachabilitySnapshot(ipv4: nil, ipv6: nil)

    let ipv4Interface: String?
    let ipv4Service: String?
    let ipv6Interface: String?
    let ipv6Service: String?

    var isConnected: Bool {
        ipv4Interface != nil || ipv6Interface != nil
    }

    init(ipv4: [String: Any]?, ipv6: [String: Any]?) {
        ipv4Interface = ipv4?["PrimaryInterface"] as? String
        ipv4Service = ipv4?["PrimaryService"] as? String
        ipv6Interface = ipv6?["PrimaryInterface"] as? String
        ipv6Service = ipv6?["PrimaryService"] as? String
    }

    static func read(using reader: NetworkConfigurationReading) -> NetworkReachabilitySnapshot {
        NetworkReachabilitySnapshot(
            ipv4: reader.copyValue(forKey: ipv4GlobalKey),
            ipv6: reader.copyValue(forKey: ipv6GlobalKey)
        )
    }
}

/// Identity of the currently attached network.
///
/// Binds user-granted captive-portal approvals so an approval cannot survive a
/// move to a different network. Read separately from
/// `NetworkReachabilitySnapshot` because it costs two extra `SCDynamicStore`
/// copies. Reachability is re-read on every configuration change, the identity
/// only when an approval is granted or re-checked.
struct NetworkIdentitySnapshot: Equatable {
    static let globalDNSKey = "State:/Network/Global/DNS"

    static func ipv4ServiceKey(_ serviceID: String) -> String {
        "State:/Network/Service/\(serviceID)/IPv4"
    }

    let reachability: NetworkReachabilitySnapshot
    let router: String?
    let resolvers: [String]

    /// Stable identity of the attached network, `nil` while disconnected.
    ///
    /// The primary service and interface alone do not discriminate: two
    /// different Wi-Fi networks joined through the same configured service on
    /// `en0` produce a byte-identical tuple. The router address and the
    /// resolver set the network handed out are the attributes that actually
    /// differ between them.
    ///
    /// An attacker who controls the network can replicate every one of these
    /// values, so this authenticates nothing. It is a same-window
    /// cross-network guard. An approval granted on one network stops covering
    /// the next one.
    var identity: String? {
        guard reachability.isConnected else { return nil }
        return [
            reachability.ipv4Service ?? "",
            reachability.ipv4Interface ?? "",
            reachability.ipv6Service ?? "",
            reachability.ipv6Interface ?? "",
            router ?? "",
            // Sorted because the resolver order the network hands out is not
            // stable, and a reordered but otherwise identical set is the same
            // network. Revoking a live approval over it would break a sign-in
            // in flight.
            resolvers.sorted().joined(separator: ","),
        ].joined(separator: "|")
    }

    init(
        reachability: NetworkReachabilitySnapshot,
        primaryIPv4Service: [String: Any]?,
        globalDNS: [String: Any]?
    ) {
        self.reachability = reachability
        router = primaryIPv4Service?["Router"] as? String
        resolvers = DNSResolverAddressParser.serverAddresses(
            globalDNS: globalDNS,
            dhcpOption6: nil
        )
    }

    static func read(using reader: NetworkConfigurationReading) -> NetworkIdentitySnapshot {
        let reachability = NetworkReachabilitySnapshot.read(using: reader)
        return NetworkIdentitySnapshot(
            reachability: reachability,
            primaryIPv4Service: reachability.ipv4Service.flatMap {
                reader.copyValue(forKey: ipv4ServiceKey($0))
            },
            globalDNS: reader.copyValue(forKey: globalDNSKey)
        )
    }
}

/// Forward routes derived from the search domains the attached network handed
/// out.
///
/// Runtime-derived and never persisted, so `state.json` stays the single source
/// of truth for user configuration. This type only discovers and normalizes.
/// The resolver owns the private-use suffix guard that decides which discovered
/// domain may claim a route, so this unauthenticated DHCP input has a single
/// enforcement point.
struct EphemeralSearchDomainRoutes: Equatable {
    struct Route: Equatable {
        let domain: String
        let forwardIP: String
    }

    static let globalDNSKey = "State:/Network/Global/DNS"

    static let empty = EphemeralSearchDomainRoutes(searchDomains: [], resolvers: [])

    let routes: [Route]

    init(searchDomains: [String], resolvers: [String]) {
        guard let forwardIP = resolvers.first else {
            routes = []
            return
        }

        var seen = Set<String>()
        routes = searchDomains.compactMap { candidate -> Route? in
            let domain =
                candidate
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
                .trimmingCharacters(in: CharacterSet(charactersIn: "."))
            guard !domain.isEmpty, seen.insert(domain).inserted else { return nil }
            return Route(domain: domain, forwardIP: forwardIP)
        }
    }

    static func read(
        using reader: NetworkConfigurationReading
    ) -> EphemeralSearchDomainRoutes {
        guard let globalDNS = reader.copyValue(forKey: globalDNSKey) else {
            return .empty
        }

        var searchDomains = globalDNS["SearchDomains"] as? [String] ?? []
        if let domainName = globalDNS["DomainName"] as? String {
            searchDomains.append(domainName)
        }

        return EphemeralSearchDomainRoutes(
            searchDomains: searchDomains,
            resolvers: DNSResolverAddressParser.serverAddresses(
                globalDNS: globalDNS,
                dhcpOption6: nil
            )
        )
    }
}

/// Facts about the attached network that the resolver turns into its network
/// profile (address families and NAT64 status, see `network_profile.rs`).
///
/// `resolvers` are the primary service's own DNS servers. `Global/DNS` is not
/// used because a VPN or Tailscale replaces it, and NAT64 discovery must ask
/// the network the traffic actually leaves through.
struct NetworkProfileSnapshot: Equatable {
    static let globalIPv4Key = NetworkReachabilitySnapshot.ipv4GlobalKey
    static let globalIPv6Key = NetworkReachabilitySnapshot.ipv6GlobalKey

    static func serviceDNSKey(_ serviceID: String) -> String {
        "State:/Network/Service/\(serviceID)/DNS"
    }

    /// Mirrors `MAX_RESOLVERS` in `network_profile.rs`, which refuses a longer
    /// list outright.
    static let maxResolvers = 8

    static let disconnected = NetworkProfileSnapshot(
        globalIPv4: nil,
        globalIPv6: nil,
        serviceDNS: nil,
        interfaceIndex: { _ in 0 }
    )

    let hasIPv4: Bool
    let hasIPv6: Bool
    let interface: String
    let interfaceIndex: UInt32
    let resolvers: [String]

    init(
        globalIPv4: [String: Any]?,
        globalIPv6: [String: Any]?,
        serviceDNS: [String: Any]?,
        interfaceIndex: (String) -> UInt32
    ) {
        hasIPv4 = globalIPv4?["Router"] != nil
        hasIPv6 = globalIPv6?["Router"] != nil
        interface =
            globalIPv4?["PrimaryInterface"] as? String
            ?? globalIPv6?["PrimaryInterface"] as? String
            ?? ""
        self.interfaceIndex = interface.isEmpty ? 0 : interfaceIndex(interface)

        var resolvers: [String] = []
        for raw in serviceDNS?["ServerAddresses"] as? [String] ?? [] {
            // configd may scope a link-local server as `fe80::1%en0`. The
            // resolver applies the scope itself from `interfaceIndex`.
            let address = String(raw.split(separator: "%", maxSplits: 1).first ?? "")
            guard DNSResolverAddressParser.isUsableForwardTarget(address),
                !resolvers.contains(address)
            else { continue }
            resolvers.append(address)
            if resolvers.count == Self.maxResolvers { break }
        }
        self.resolvers = resolvers
    }

    /// The JSON object `dns_apply_network_snapshot` expects.
    var payload: [String: Any] {
        [
            "ipv4": hasIPv4,
            "ipv6": hasIPv6,
            "interface": interface,
            "interfaceIndex": interfaceIndex,
            "resolvers": resolvers,
        ]
    }

    static func read(using reader: NetworkConfigurationReading) -> NetworkProfileSnapshot {
        let globalIPv4 = reader.copyValue(forKey: globalIPv4Key)
        let globalIPv6 = reader.copyValue(forKey: globalIPv6Key)
        let service =
            globalIPv4?["PrimaryService"] as? String
            ?? globalIPv6?["PrimaryService"] as? String
        return NetworkProfileSnapshot(
            globalIPv4: globalIPv4,
            globalIPv6: globalIPv6,
            serviceDNS: service.flatMap { reader.copyValue(forKey: serviceDNSKey($0)) },
            interfaceIndex: { if_nametoindex($0) }
        )
    }
}

/// Weak box handed to the SCDynamicStore callback, so a callback that fires
/// after the monitor is deallocated does nothing instead of crashing.
/// `@unchecked Sendable` because reading a weak reference is thread-safe.
private final class NetworkObserverContext: @unchecked Sendable {
    weak var monitor: NetworkMonitor?

    init(monitor: NetworkMonitor) {
        self.monitor = monitor
    }
}

private final class NetworkCallbackGeneration: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64?

    func load() -> UInt64? {
        lock.withLock { value }
    }

    func store(_ value: UInt64?) {
        lock.withLock { self.value = value }
    }
}

class NetworkMonitor {
    static let shared = NetworkMonitor()

    weak var delegate: NetworkMonitorDelegate?
    private let queue = DispatchQueue(label: "app.macdns.network-monitor")

    private var store: SCDynamicStore?
    private var reader: NetworkConfigurationReading?
    private var observerContext: NetworkObserverContext?
    private var reachability = NetworkReachabilitySnapshot.disconnected
    private var isStarted = false
    private var callbackLifecycleGeneration: UInt64?
    private let callbackGeneration = NetworkCallbackGeneration()

    private var debounceWorkItem: DispatchWorkItem?
    private let debounceDelay: TimeInterval

    init() {
        debounceDelay = 2.0
    }

    /// Binds the monitor to an injected configuration reader instead of a live
    /// `SCDynamicStore`, so the deferred callback path can be exercised.
    init(
        reader: NetworkConfigurationReading,
        callbackLifecycleGeneration: UInt64,
        debounceDelay: TimeInterval = 0.01
    ) {
        self.reader = reader
        self.callbackLifecycleGeneration = callbackLifecycleGeneration
        callbackGeneration.store(callbackLifecycleGeneration)
        self.debounceDelay = debounceDelay
        self.isStarted = true
    }

    func start(callbackLifecycleGeneration: UInt64) -> Bool {
        dispatchPrecondition(condition: .notOnQueue(queue))
        return queue.sync {
            guard !isStarted else {
                debounceWorkItem?.cancel()
                debounceWorkItem = nil
                self.callbackLifecycleGeneration = callbackLifecycleGeneration
                callbackGeneration.store(callbackLifecycleGeneration)
                return true
            }
            self.callbackLifecycleGeneration = callbackLifecycleGeneration
            callbackGeneration.store(callbackLifecycleGeneration)

            let contextWrapper = NetworkObserverContext(monitor: self)
            self.observerContext = contextWrapper

            // passUnretained is safe because `observerContext` keeps the
            // wrapper alive.
            var context = SCDynamicStoreContext(
                version: 0,
                info: Unmanaged.passUnretained(contextWrapper).toOpaque(),
                retain: nil,
                release: nil,
                copyDescription: nil
            )

            guard
                let store = SCDynamicStoreCreate(
                    nil,
                    "app.macdns.network-monitor" as CFString,
                    { _, changedKeys, info in
                        guard let info = info,
                            let keys = changedKeys as? [String]
                        else { return }
                        let contextWrapper = Unmanaged<NetworkObserverContext>.fromOpaque(info).takeUnretainedValue()
                        // CRITICAL: the callback only copies its arguments and
                        // enqueues. Calling SCDynamicStore functions here can
                        // deadlock or reenter configd.
                        contextWrapper.monitor?.enqueueConfigurationChange(changedKeys: keys)
                    },
                    &context
                )
            else {
                AgentLogger.shared.error("Failed to create SCDynamicStore")
                self.observerContext = nil
                self.callbackLifecycleGeneration = nil
                callbackGeneration.store(nil)
                return false
            }

            self.store = store

            // Global keys catch primary-route changes. Service patterns catch
            // DNS and service swaps during a Wi-Fi roam or a
            // captive-portal release where the global IPv4 object may not move.
            let specificKeys =
                [
                    "State:/Network/Global/IPv4",
                    "State:/Network/Global/IPv6",
                    "State:/Network/Global/DNS",
                ] as CFArray
            let patterns =
                [
                    "State:/Network/Service/.*/IPv4",
                    "State:/Network/Service/.*/IPv6",
                    "State:/Network/Service/.*/DNS",
                ] as CFArray

            if !SCDynamicStoreSetNotificationKeys(store, specificKeys, patterns) {
                AgentLogger.shared.error("Failed to set notification keys")
                self.store = nil
                self.observerContext = nil
                self.callbackLifecycleGeneration = nil
                callbackGeneration.store(nil)
                return false
            }

            if !SCDynamicStoreSetDispatchQueue(store, queue) {
                AgentLogger.shared.error("Failed to set dispatch queue")
                self.store = nil
                self.observerContext = nil
                self.callbackLifecycleGeneration = nil
                callbackGeneration.store(nil)
                return false
            }

            let liveReader = DynamicStoreConfigurationReader(store: store)
            self.reader = liveReader
            reachability = NetworkReachabilitySnapshot.read(using: liveReader)
            isStarted = true
            AgentLogger.shared.info("NetworkMonitor started")
            return true
        }
    }

    func stop() {
        dispatchPrecondition(condition: .notOnQueue(queue))
        queue.sync {
            guard isStarted else { return }

            debounceWorkItem?.cancel()
            debounceWorkItem = nil

            // Order matters. Detach the dispatch queue first so no new
            // callbacks arrive, then clear the weak reference so in-flight
            // callbacks become no-ops.
            if let store = store {
                SCDynamicStoreSetDispatchQueue(store, nil)
            }
            observerContext?.monitor = nil

            store = nil
            reader = nil
            observerContext = nil
            isStarted = false
            reachability = .disconnected
            callbackLifecycleGeneration = nil
            callbackGeneration.store(nil)
            AgentLogger.shared.info("NetworkMonitor stopped")
        }
    }

    // MARK: - Configuration Change Handler

    /// Entry point for the SCDynamicStore callback.
    ///
    /// Defers every configuration read, log line, status check and debounce
    /// decision to a later turn on `queue`, so the callback returns to configd
    /// without reentering it.
    func enqueueConfigurationChange(changedKeys: [String]) {
        guard let capturedGeneration = callbackGeneration.load() else { return }
        queue.async { [weak self] in
            self?.handleConfigurationChange(
                changedKeys: changedKeys,
                capturedGeneration: capturedGeneration
            )
        }
    }

    /// Runs on `queue`, in a later turn than the SCDynamicStore callback.
    private func handleConfigurationChange(
        changedKeys: [String],
        capturedGeneration: UInt64
    ) {
        guard isStarted else { return }
        guard callbackLifecycleGeneration == capturedGeneration else { return }

        AgentLogger.shared.debug("Network configuration changed: \(changedKeys)")

        let hasRelevantNetworkChange = changedKeys.contains {
            $0.contains("IPv4") || $0.contains("IPv6") || $0.contains("DNS")
        }
        guard hasRelevantNetworkChange else { return }

        checkNetworkStatus()

        debounceWorkItem?.cancel()
        guard let callbackLifecycleGeneration else { return }
        let isConnected = reachability.isConnected
        let workItem = DispatchWorkItem { [weak self] in
            guard let self = self, self.isStarted else { return }
            guard
                self.callbackLifecycleGeneration
                    == callbackLifecycleGeneration
            else {
                return
            }
            DispatchQueue.main.async { [weak self] in
                self?.deliverConfigurationChange(
                    isConnected: isConnected,
                    callbackLifecycleGeneration: callbackLifecycleGeneration
                )
            }
        }
        debounceWorkItem = workItem
        queue.asyncAfter(deadline: .now() + debounceDelay, execute: workItem)
    }

    // MARK: - Status Checks

    private func checkNetworkStatus() {
        guard let reader = reader else { return }
        guard let callbackLifecycleGeneration else { return }

        let previous = reachability
        reachability = NetworkReachabilitySnapshot.read(using: reader)

        guard reachability.isConnected != previous.isConnected else { return }

        let isConnected = reachability.isConnected
        AgentLogger.shared.debug(isConnected ? "Network connected" : "Network disconnected")
        DispatchQueue.main.async { [weak self] in
            self?.deliverStatusChange(
                isConnected: isConnected,
                callbackLifecycleGeneration: callbackLifecycleGeneration
            )
        }
    }

    private func deliverStatusChange(
        isConnected: Bool,
        callbackLifecycleGeneration: UInt64
    ) {
        let isCurrent = queue.sync {
            isStarted
                && self.callbackLifecycleGeneration
                    == callbackLifecycleGeneration
        }
        guard isCurrent else { return }
        delegate?.networkStatusChanged(
            isConnected: isConnected,
            callbackLifecycleGeneration: callbackLifecycleGeneration
        )
    }

    private func deliverConfigurationChange(
        isConnected: Bool,
        callbackLifecycleGeneration: UInt64
    ) {
        let isCurrent = queue.sync {
            isStarted
                && self.callbackLifecycleGeneration
                    == callbackLifecycleGeneration
        }
        guard isCurrent else { return }
        delegate?.networkConfigurationChanged(
            isConnected: isConnected,
            callbackLifecycleGeneration: callbackLifecycleGeneration
        )
    }

    var isConnected: Bool {
        dispatchPrecondition(condition: .notOnQueue(queue))
        return queue.sync { isStarted && reachability.isConnected }
    }

    // MARK: - Network Identity

    /// Reads the identity of the currently attached network directly from
    /// `SCDynamicStore`.
    ///
    /// Used by the captive-portal decision path, which must bind a user
    /// approval to the network attached at grant time and re-check it on every
    /// later decision.
    static func currentNetworkIdentity() -> String? {
        guard
            let store = SCDynamicStoreCreate(
                nil,
                "app.macdns.network-identity" as CFString,
                nil,
                nil
            )
        else {
            AgentLogger.shared.warning("Failed to create SCDynamicStore for network identity")
            return nil
        }

        return NetworkIdentitySnapshot.read(
            using: DynamicStoreConfigurationReader(store: store)
        ).identity
    }

    /// Reads the routes implied by the attached network's search domains.
    ///
    /// Returns an empty set whenever the configuration cannot be read, so a
    /// failed read clears the published routes instead of keeping stale ones
    /// from a previous network.
    static func currentSearchDomainRoutes() -> EphemeralSearchDomainRoutes {
        guard
            let store = SCDynamicStoreCreate(
                nil,
                "app.macdns.search-domains" as CFString,
                nil,
                nil
            )
        else {
            AgentLogger.shared.warning("Failed to create SCDynamicStore for search domains")
            return .empty
        }

        return EphemeralSearchDomainRoutes.read(
            using: DynamicStoreConfigurationReader(store: store)
        )
    }

    /// Reads the attached network's profile facts. A failed read reports a
    /// disconnected network, which makes the resolver drop any NAT64 prefix
    /// instead of keeping one from a previous network.
    static func currentProfileSnapshot() -> NetworkProfileSnapshot {
        guard
            let store = SCDynamicStoreCreate(
                nil,
                "app.macdns.network-profile" as CFString,
                nil,
                nil
            )
        else {
            AgentLogger.shared.warning("Failed to create SCDynamicStore for network profile")
            return .disconnected
        }

        return NetworkProfileSnapshot.read(
            using: DynamicStoreConfigurationReader(store: store)
        )
    }

    // MARK: - DHCP DNS Lookup

    /// DNS servers from `Global/DNS` and the primary service's DHCP option 6.
    static func getDHCPDNSServers() -> [String] {
        guard let store = SCDynamicStoreCreate(nil, "app.macdns.dhcp-query" as CFString, nil, nil) else {
            AgentLogger.shared.warning("Failed to create SCDynamicStore for DHCP query")
            return []
        }

        let globalDNSKey = "State:/Network/Global/DNS" as CFString
        let globalDNSDict = SCDynamicStoreCopyValue(store, globalDNSKey) as? [String: Any]

        let globalKey = "State:/Network/Global/IPv4" as CFString
        var dhcpOption6: Data?
        if let globalDict = SCDynamicStoreCopyValue(store, globalKey) as? [String: Any],
            let primaryService = globalDict["PrimaryService"] as? String
        {
            let dhcpKey = "State:/Network/Service/\(primaryService)/DHCP" as CFString
            let dhcpDict = SCDynamicStoreCopyValue(store, dhcpKey) as? [String: Any]
            dhcpOption6 = dhcpDict?["Option_6"] as? Data
        } else {
            AgentLogger.shared.debug("No primary IPv4 service found for DHCP DNS lookup")
        }

        let servers = DNSResolverAddressParser.serverAddresses(
            globalDNS: globalDNSDict,
            dhcpOption6: dhcpOption6
        )

        AgentLogger.shared.debug("DNS servers (via SCDynamicStore): \(servers)")
        return servers
    }

}
