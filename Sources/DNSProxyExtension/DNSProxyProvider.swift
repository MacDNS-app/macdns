// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation
import Network
import NetworkExtension
import SystemConfiguration
import os.log

private struct ScopedIPv6Address {
    let address: String
    let scopeID: UInt32

    static func parse(_ host: String) -> ScopedIPv6Address? {
        let address: String
        let zoneID: String?

        if let escapedZoneRange = host.range(of: "%25") {
            address = String(host[..<escapedZoneRange.lowerBound])
            zoneID = String(host[escapedZoneRange.upperBound...])
        } else if let zoneSeparator = host.firstIndex(of: "%") {
            address = String(host[..<zoneSeparator])
            zoneID = String(host[host.index(after: zoneSeparator)...])
        } else {
            address = host
            zoneID = nil
        }

        guard !address.isEmpty else { return nil }

        var parsedAddress = in6_addr()
        guard address.withCString({ inet_pton(AF_INET6, $0, &parsedAddress) }) == 1 else { return nil }

        guard let zoneID else {
            return ScopedIPv6Address(address: address, scopeID: 0)
        }

        guard !zoneID.isEmpty else { return nil }

        if let numericScopeID = UInt32(zoneID) {
            return ScopedIPv6Address(address: address, scopeID: numericScopeID)
        }

        let interfaceScopeID = zoneID.withCString { if_nametoindex($0) }
        guard interfaceScopeID != 0 else { return nil }

        return ScopedIPv6Address(address: address, scopeID: interfaceScopeID)
    }
}

// Must match DarwinNotifications.proxyInterceptionChanged in Shared. Posted to
// the App on a real bypass<->intercepting flip so it re-pulls the state.
private let interceptionChangedNotification =
    "app.macdns.dnsproxy.interceptionChanged" as CFString

/// Wakes the App on a real interception-state flip so it re-pulls the
/// authenticated provider state. Wake-up only, carries no payload.
private func postInterceptionChanged() {
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFNotificationName(interceptionChangedNotification),
        nil, nil, true)
}

// MARK: - Proxy State Manager

struct ProxyRoutingSnapshot {
    let allDNSIPs: Set<String>
    let bypassMode: Bool
    let revision: UInt64
}

/// Routing state behind a `pthread_rwlock`: concurrent readers on the query
/// hot path, exclusive writers. Write sections stay short and do no configd or
/// network work, because readers wait for them.
final class ProxyStateManager: @unchecked Sendable {
    private var rwlock = pthread_rwlock_t()
    private var _allDNSIPs: Set<String> = []
    private var _bypassMode: Bool = true
    private var _routingRevision: UInt64 = 0

    init() {
        pthread_rwlock_init(&rwlock, nil)
    }

    deinit {
        pthread_rwlock_destroy(&rwlock)
    }

    // MARK: - Read (concurrent readers, waits for active writers)

    func read() -> (allDNSIPs: Set<String>, bypassMode: Bool) {
        pthread_rwlock_rdlock(&rwlock)
        defer { pthread_rwlock_unlock(&rwlock) }
        return (_allDNSIPs, _bypassMode)
    }

    func routingSnapshot() -> ProxyRoutingSnapshot {
        pthread_rwlock_rdlock(&rwlock)
        defer { pthread_rwlock_unlock(&rwlock) }
        return ProxyRoutingSnapshot(
            allDNSIPs: _allDNSIPs,
            bypassMode: _bypassMode,
            revision: _routingRevision)
    }

    func isCurrentRoutingRevision(_ revision: UInt64) -> Bool {
        pthread_rwlock_rdlock(&rwlock)
        defer { pthread_rwlock_unlock(&rwlock) }
        return _routingRevision == revision
    }

    var bypassMode: Bool {
        pthread_rwlock_rdlock(&rwlock)
        defer { pthread_rwlock_unlock(&rwlock) }
        return _bypassMode
    }

    var allDNSIPs: Set<String> {
        pthread_rwlock_rdlock(&rwlock)
        defer { pthread_rwlock_unlock(&rwlock) }
        return _allDNSIPs
    }

    // MARK: - Write (exclusive, waits for readers to finish)

    /// Publishes the observed destination set. An empty set makes every
    /// interception match impossible, so bypass is forced in the same critical
    /// section. A reader can never observe an empty set while interception is
    /// still claimed and forward queries to their original destination.
    /// Returns true when this publication is what stopped interception.
    func publishDNSIPs(_ ips: Set<String>) -> Bool {
        pthread_rwlock_wrlock(&rwlock)
        defer { pthread_rwlock_unlock(&rwlock) }
        let destinationsChanged = _allDNSIPs != ips
        let interceptionStopped = ips.isEmpty && !_bypassMode
        _allDNSIPs = ips
        if interceptionStopped {
            _bypassMode = true
        }
        if destinationsChanged || interceptionStopped {
            _routingRevision &+= 1
        }
        return interceptionStopped
    }

    @discardableResult
    func setBypassMode(_ bypass: Bool) -> Bool {
        pthread_rwlock_wrlock(&rwlock)
        defer { pthread_rwlock_unlock(&rwlock) }
        guard _bypassMode != bypass else { return false }
        _bypassMode = bypass
        _routingRevision &+= 1
        return true
    }

    func prepareForStart() {
        setBypassMode(true)
    }
}

// MARK: - Configuration Observer Context

/// Weak `ConfigurationWorker` reference handed to the SCDynamicStore callback.
private final class ConfigObserverContext: @unchecked Sendable {
    weak var worker: ConfigurationWorker?

    init(worker: ConfigurationWorker) {
        self.worker = worker
    }
}

// MARK: - Configuration Worker

/// Runs every configd-dependent operation on its own queue, so the query hot
/// path never blocks on SCDynamicStore. SCDynamicStore callbacks must never call
/// SCDynamicStore functions synchronously, or configd can deadlock or reenter.
private final class ConfigurationWorker {
    private let stateManager: ProxyStateManager
    private let logger: Logger
    private let configQueue = DispatchQueue(label: "app.macdns.dnsproxy.config", qos: .utility)

    private var dynamicStore: SCDynamicStore?
    private var observerContext: ConfigObserverContext?
    private var probeTimer: DispatchSourceTimer?

    private let resolverHost = "127.0.0.1"
    private let resolverPort: UInt16 = 5335
    private let probeInterval: TimeInterval = 5.0
    private let probeTimeout: TimeInterval = 3.0
    private let immediateProbeMinimumIntervalNanoseconds: UInt64 = 100_000_000

    // Set by the provider so the worker can read the current session/state.
    weak var controlListener: ProxyControlListener?

    private var isRunning = false
    private var immediateProbePending = false
    private var probeRetry = DNSProxyProbeRetryPolicy()
    private var lastProbeUptimeNanoseconds: UInt64 = 0
    private var probeDiagnostics = ProxyProbeDiagnostics()

    init(stateManager: ProxyStateManager, logger: Logger) {
        self.stateManager = stateManager
        self.logger = logger
    }

    func start() {
        configQueue.async { [weak self] in
            guard let self else { return }
            isRunning = true
            loadDNSIPs()
            setupDNSObserver()
            startHealthProbe()
        }
    }

    func stop() {
        configQueue.sync { [weak self] in
            guard let self else { return }
            isRunning = false
            immediateProbePending = false
            stopHealthProbe()
            teardownDNSObserver()
        }
    }

    func enqueueDarwinWakeup(_ work: @escaping () -> Void) {
        configQueue.async(execute: work)
    }

    func handleDarwinWakeup(reason: String) {
        guard isRunning, !immediateProbePending else { return }
        immediateProbePending = true
        runPendingImmediateProbeWhenAllowed()
    }

    // MARK: - Interception transitions

    /// Runs on configQueue after a bypass/intercepting flip or destination-set
    /// replacement. The provider retires connections routed under the old state.
    var onRoutingChanged: (() -> Void)?

    private func noteInterceptionChanged() {
        postInterceptionChanged()
        onRoutingChanged?()
    }

    // MARK: - DNS IPs Loading (runs on configQueue - can block)

    private func loadDNSIPs() {
        // A store that cannot be opened leaves the destinations unknown, so the
        // provider bypasses instead of intercepting for servers it cannot verify.
        publishDNSIPs(readConfiguredDNSIPs() ?? [])
    }

    private func readConfiguredDNSIPs() -> Set<String>? {
        guard let store = SCDynamicStoreCreate(nil, "dns-proxy" as CFString, nil, nil) else {
            logger.error("Failed to create SCDynamicStore for DNS query")
            return nil
        }

        var newIPs = Set<String>()

        if let globalDNS = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any],
            let servers = globalDNS["ServerAddresses"] as? [String]
        {
            newIPs.formUnion(servers)
        }

        // Per-service State keys hold dynamic servers (DHCP, VPN). Setup keys
        // below hold manually configured ones.
        let statePattern = "State:/Network/Service/.*/DNS" as CFString
        if let keys = SCDynamicStoreCopyKeyList(store, statePattern) as? [String] {
            for key in keys {
                if let serviceDNS = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                    let servers = serviceDNS["ServerAddresses"] as? [String]
                {
                    newIPs.formUnion(servers)
                }
            }
        }

        let setupPattern = "Setup:/Network/Service/.*/DNS" as CFString
        if let keys = SCDynamicStoreCopyKeyList(store, setupPattern) as? [String] {
            for key in keys {
                if let serviceDNS = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                    let servers = serviceDNS["ServerAddresses"] as? [String]
                {
                    newIPs.formUnion(servers)
                }
            }
        }

        return newIPs
    }

    private func publishDNSIPs(_ newIPs: Set<String>) {
        guard stateManager.allDNSIPs != newIPs else { return }
        let interceptionStopped = stateManager.publishDNSIPs(newIPs)
        if newIPs.isEmpty {
            controlListener?.setState(.bypass(.dnsDestinationsUnavailable))
            logger.notice("DNS destinations empty; interception suspended")
            if interceptionStopped {
                noteInterceptionChanged()
            } else {
                onRoutingChanged?()
            }
        } else {
            logger.notice("DNS destinations updated (\(newIPs.count, privacy: .public) servers)")
            onRoutingChanged?()
        }
    }

    // MARK: - DNS Observer (runs on configQueue - can block)

    private func setupDNSObserver() {
        let contextWrapper = ConfigObserverContext(worker: self)
        self.observerContext = contextWrapper

        var context = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(contextWrapper).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )

        // Must not call SCDynamicStore functions. It only enqueues an async
        // reload, so configd cannot deadlock or reenter.
        let callback: SCDynamicStoreCallBack = { _, _, info in
            guard let info = info else { return }
            let ctx = Unmanaged<ConfigObserverContext>.fromOpaque(info).takeUnretainedValue()
            ctx.worker?.configQueue.async {
                ctx.worker?.loadDNSIPs()
            }
        }

        guard let store = SCDynamicStoreCreate(nil, "dns-proxy-observer" as CFString, callback, &context) else {
            logger.error("Failed to create SCDynamicStore for DNS observation")
            self.observerContext = nil
            return
        }

        let specificKeys = ["State:/Network/Global/DNS"] as CFArray

        let patterns =
            [
                "State:/Network/Service/.*/DNS",
                "Setup:/Network/Service/.*/DNS",
            ] as CFArray

        if !SCDynamicStoreSetNotificationKeys(store, specificKeys, patterns) {
            logger.error("Failed to set SCDynamicStore notification keys")
            self.observerContext = nil
            return
        }

        // configQueue, not main, so configd work stays off the main queue.
        if !SCDynamicStoreSetDispatchQueue(store, configQueue) {
            logger.error("Failed to set SCDynamicStore dispatch queue")
            self.observerContext = nil
            return
        }

        self.dynamicStore = store
    }

    private func teardownDNSObserver() {
        if let store = dynamicStore {
            SCDynamicStoreSetDispatchQueue(store, nil)
        }
        observerContext?.worker = nil
        dynamicStore = nil
        observerContext = nil
    }

    // MARK: - Health Probe (BSD sockets - no configd dependency)

    private func startHealthProbe() {
        let timer = DispatchSource.makeTimerSource(queue: configQueue)
        timer.schedule(deadline: .now(), repeating: probeInterval)
        timer.setEventHandler { [weak self] in
            self?.performHealthEvaluation()
        }
        timer.resume()
        probeTimer = timer
    }

    private func stopHealthProbe() {
        probeTimer?.cancel()
        probeTimer = nil
    }

    private func runPendingImmediateProbeWhenAllowed() {
        guard isRunning, immediateProbePending else { return }

        let now = DispatchTime.now().uptimeNanoseconds
        if lastProbeUptimeNanoseconds != 0 {
            let elapsed = now &- lastProbeUptimeNanoseconds
            if elapsed < immediateProbeMinimumIntervalNanoseconds {
                let remaining = immediateProbeMinimumIntervalNanoseconds - elapsed
                configQueue.asyncAfter(
                    deadline: .now() + .nanoseconds(Int(remaining))
                ) { [weak self] in
                    self?.runPendingImmediateProbeWhenAllowed()
                }
                return
            }
        }

        immediateProbePending = false
        performHealthEvaluation()
    }

    private func performHealthEvaluation() {
        guard isRunning else { return }
        lastProbeUptimeNanoseconds = DispatchTime.now().uptimeNanoseconds
        // Every evaluation re-reads the destinations, so a missed configd
        // notification cannot leave interception aimed at stale servers.
        loadDNSIPs()

        guard let session = controlListener?.currentSession else {
            applyDecision(.bypass(.sessionUnavailable))
            return
        }
        let dnsPresent = !stateManager.allDNSIPs.isEmpty
        // Both transports run concurrently, so the serial configQueue blocks for
        // max(udp, tcp) instead of their sum and DNS-IP reloads do not queue
        // behind a slow challenge.
        var udp: ProxyProbeResult?
        var tcp: ProxyProbeResult?
        let group = DispatchGroup()
        let probeQueue = DispatchQueue(label: "app.macdns.dnsproxy.probe", attributes: .concurrent)
        group.enter()
        probeQueue.async {
            udp = self.runChallenge(session: session, transport: .udp)
            group.leave()
        }
        group.enter()
        probeQueue.async {
            tcp = self.runChallenge(session: session, transport: .tcp)
            group.leave()
        }
        group.wait()
        // A session lost while the probes were in flight must not be overwritten
        // by a stale success, so the probed session has to still be the live one.
        guard controlListener?.isCurrentSession(session.sessionIDHex) == true else {
            applyDecision(.bypass(.sessionUnavailable))
            return
        }
        guard let udp, let tcp else {
            applyDecision(.bypass(.probeFailed))
            return
        }
        let probes = ProxyProbeReport(udp: udp, tcp: tcp)
        let decision = DNSProxyHealthEvaluator.decide(
            DNSProxyHealthInputs(
                sessionInstalled: true, udp: udp.outcome, tcp: tcp.outcome,
                dnsDestinationsPresent: dnsPresent),
            sessionID: session.sessionIDHex)
        var intercepting = false
        if case .intercepting = controlListener?.currentState { intercepting = true }
        if probeRetry.shouldRepeat(decision, probes: probes, intercepting: intercepting) {
            logger.notice(
                "Probe round unanswered; repeating before bypass (\(probes.summary, privacy: .public))")
            // A separate queue job, so a stop or a DNS reload is not held
            // behind two rounds.
            immediateProbePending = true
            configQueue.async { [weak self] in
                self?.runPendingImmediateProbeWhenAllowed()
            }
            return
        }
        applyDecision(decision, probes: probes)
    }

    private func applyDecision(_ decision: DNSProxyHealthDecision, probes: ProxyProbeReport? = nil) {
        switch decision {
        case .intercept(let id):
            var interceptionStarted = false
            // The decision only holds for the session it was computed for, so it
            // is committed inside the listener's critical section. A session lost
            // while the challenges were in flight refuses the commit instead of
            // leaving interception claimed without a session.
            let committed =
                controlListener?.commitIntercepting(sessionID: id) {
                    interceptionStarted = stateManager.setBypassMode(false)
                } ?? false
            guard committed else {
                applyBypass(.sessionUnavailable)
                return
            }
            _ = probeDiagnostics.record(probes)
            if interceptionStarted {
                let details = probes?.summary ?? "probes=notRun"
                logger.notice("Control challenge validated; bypass disabled (\(details, privacy: .public))")
                noteInterceptionChanged()
            }
        case .bypass(let reason):
            applyBypass(reason, probes: probes)
        }
    }

    private func applyBypass(_ reason: ProxyInterceptionReason, probes: ProxyProbeReport? = nil) {
        let previousState = controlListener?.currentState
        let wasIntercepting = stateManager.setBypassMode(true)
        controlListener?.setState(.bypass(reason))
        let diagnosticChanged = probeDiagnostics.record(probes)
        let details = probes?.summary ?? "probes=notRun"
        if wasIntercepting {
            logger.warning("Bypass entered (reason=\(reason.rawValue, privacy: .public) \(details, privacy: .public))")
            noteInterceptionChanged()
        } else if previousState != .bypass(reason) || diagnosticChanged {
            logger.notice("Bypass continues (reason=\(reason.rawValue, privacy: .public) \(details, privacy: .public))")
        }
    }

    /// Sends one authenticated challenge over the given transport and verifies
    /// the HMAC response. The outcome separates an unreachable or unauthenticated
    /// transport from a resolver that authentically reported itself not ready.
    private func runChallenge(
        session: ProxyControlSession, transport: ProxyControlChallengeClientTransport
    ) -> ProxyProbeResult {
        let started = DispatchTime.now().uptimeNanoseconds
        func result(_ outcome: ProxyControlChallengeOutcome) -> ProxyProbeResult {
            ProxyProbeResult(
                outcome: outcome,
                elapsedMilliseconds: (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000)
        }
        guard let nonce = ProxyControlChallengeClient.randomNonce() else {
            return result(.failed(.init(stage: .nonce, reason: .unavailable)))
        }
        let name = ProxyControlChallengeClient.queryName(nonce: nonce, transport: transport)
        let question = ProxyControlChallengeClient.questionWire(name: name)
        let txID = UInt16.random(in: 0...UInt16.max)
        // No EDNS OPT (ARCOUNT=0). The verifier's single-TXT parser requires
        // ARCOUNT=0 and the answer to be the last bytes on the wire. An OPT in
        // the query makes the resolver echo one into the response, which breaks
        // parsing and leaves the provider in permanent bypass.
        var query = Data()
        query.append(contentsOf: [UInt8(txID >> 8), UInt8(txID & 0xFF)])
        query.append(contentsOf: [0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        query.append(question)

        let response: Result<Data, ProxyProbeFailure>
        switch transport {
        case .udp:
            response = BSDUDPProbe.exchange(
                query: query, address: resolverSockaddr(), timeout: probeTimeout)
        case .tcp: response = sendTCP(query)
        }
        switch response {
        case .failure(let failure): return result(.failed(failure))
        case .success(let response):
            return result(
                ProxyControlChallengeClient.verify(
                    response: response, transactionID: txID, session: session,
                    transport: transport, nonce: nonce, question: question))
        }
    }

    private func resolverSockaddr() -> sockaddr_in {
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = resolverPort.bigEndian
        address.sin_len = __uint8_t(MemoryLayout<sockaddr_in>.size)
        _ = inet_pton(AF_INET, resolverHost, &address.sin_addr)
        return address
    }

    /// Opens a fresh DNS-over-TCP connection for each evaluation. A persistent
    /// connection is not accepted as proof of the current TCP listener. The whole
    /// exchange shares one absolute deadline so this serial queue, and the NE stop
    /// completion queued behind it, stay bounded.
    private func sendTCP(_ query: Data) -> Result<Data, ProxyProbeFailure> {
        do {
            let transport = try BSDBoundedTCPProbeTransport(address: resolverSockaddr())
            return BoundedTCPProbe.exchange(
                transport: transport, query: query,
                deadline: ProbeDeadline(timeout: probeTimeout), maxResponseBytes: 4096)
        } catch let failure as ProxyProbeFailure {
            return .failure(failure)
        } catch {
            return .failure(.init(stage: .socket, reason: .unavailable))
        }
    }
}

/// Redirects DNS flows aimed at the system's configured DNS servers to the
/// in-process Rust resolver at 127.0.0.1:5335. Flows from verified MacDNS
/// binaries pass through to their original destination, so the resolver's own
/// upstream traffic does not loop back into the proxy.
@objc(DNSProxyProvider)
class DNSProxyProvider: NEDNSProxyProvider {

    // MARK: - Constants

    private let resolverHost = "127.0.0.1"
    private let resolverPort: UInt16 = 5335
    private let connectionTimeout: TimeInterval = 5.0

    // A DNS-over-TCP connection that moves no byte for this long is abandoned.
    // RFC 7766 puts the recommended idle window in the seconds-to-two-minutes
    // range. The upper end is used so legitimate long-lived resolver
    // connections are never cut while silent ones stop accumulating.
    private let tcpIdleTimeout: TimeInterval = 120.0
    private static let tcpIdleSweepInterval: TimeInterval = 10.0

    // MARK: - Bypass Notification Constants
    // The extension cannot import Shared. These must match DarwinNotifications in
    // Shared/DarwinNotifications.swift.

    private let bypassEnableNotification = "app.macdns.dnsproxy.bypass.enable" as CFString
    private let bypassDisableNotification = "app.macdns.dnsproxy.bypass.disable" as CFString

    // MARK: - Properties

    private let logger = Logger(subsystem: "app.macdns.dnsproxy", category: "proxy")

    // Hot-path reads use RWLock and can wait for short write sections.
    private let stateManager = ProxyStateManager()

    // Flow-admission identity checks. Never runs on the DNS packet hot path.
    private let processValidator = DNSProxyProcessValidator()

    private let lifecycleCoordinator = DNSProxyLifecycleCoordinator()

    private lazy var wakeupCoalescer = NotificationWakeupCoalescer(
        enqueue: { [weak self] work in
            self?.configWorker?.enqueueDarwinWakeup(work)
        },
        handler: { [weak self] in
            self?.configWorker?.handleDarwinWakeup(reason: "darwin-wakeup")
        }
    )

    private var configWorker: ConfigurationWorker?

    private var controlListener: ProxyControlListener?

    private let dnsQueue = DispatchQueue(label: "app.macdns.dnsproxy.queue", qos: .userInteractive)

    private let tcpQueue = DispatchQueue(label: "app.macdns.dnsproxy.tcp", qos: .userInitiated)

    private var resolverSocketPool: ResolverSocketPool?

    // Admission budgets. Both families spend file descriptors, so they are
    // sized together from the process allowance instead of each taking a share
    // that could sum past the real limit. The limit is raised first because
    // the budgets are fixed once sized.
    private static let fileDescriptorLimit = ProxyResourceBudget.raiseFileDescriptorLimit()
    private static let budgetAllocation = ProxyResourceBudget.allocate(
        fileDescriptorLimit: DNSProxyProvider.fileDescriptorLimit)
    private let tcpProxyBudget = ProxyResourceBudget(capacity: DNSProxyProvider.budgetAllocation.tcpProxies)
    private let udpExchangeBudget = ProxyResourceBudget(capacity: DNSProxyProvider.budgetAllocation.udpExchanges)

    // Accessed only on dnsQueue. Bounds and expires every in-flight passthrough
    // exchange from one timer.
    private var udpExchangeRegistry: DNSUDPExchangeRegistry?

    // Accessed only on tcpQueue. Keeps half-closed TCP flows alive until both directions finish.
    private var activeTCPProxies: [UUID: TCPSocketProxy] = [:]
    private var tcpIdleSweeper: DispatchSourceTimer?
    private var tcpProxyStopping = false

    // MARK: - Lifecycle

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        ProviderStartWatchdog.shared.noteProxyStarted()
        stateManager.prepareForStart()
        lifecycleCoordinator.beginStart()
        // Synchronous so a stop arriving right after start cannot observe a
        // stale stopping flag.
        tcpQueue.sync { [self] in
            tcpProxyStopping = false
            startTCPIdleSweeper()
        }

        // Pre-connected resolver sockets share dnsQueue to avoid context
        // switching. Without them every intercepted query falls back to a
        // per-query exchange, which is slower but still answers.
        resolverSocketPool = ResolverSocketPool(host: resolverHost, port: resolverPort, poolSize: 8, queue: dnsQueue)
        if resolverSocketPool == nil {
            logger.error("Resolver socket pool unavailable; intercepted UDP queries use per-query sockets")
        }

        let registry = DNSUDPExchangeRegistry(
            queue: dnsQueue, budget: udpExchangeBudget, timeout: connectionTimeout)
        udpExchangeRegistry = registry
        registry.start()

        configWorker = ConfigurationWorker(stateManager: stateManager, logger: logger)
        configWorker?.onRoutingChanged = { [weak self] in
            self?.closeActiveTCPProxies()
        }

        controlListener = ProxyControlListener(logger: logger)
        controlListener?.onSessionIssued = { [weak self] _ in
            self?.configWorker?.enqueueDarwinWakeup {
                self?.configWorker?.handleDarwinWakeup(reason: "session-issued")
            }
        }
        controlListener?.onSessionLost = { [weak self] in
            self?.forceBypassAfterSessionLoss()
        }
        configWorker?.controlListener = controlListener
        configWorker?.start()
        controlListener?.start()

        wakeupCoalescer.reset()
        observeBypassNotifications()

        lifecycleCoordinator.finishStart()
        logger.notice("DNS Proxy started in BYPASS mode.")
        logger.notice(
            "Proxy resource budgets: nofile=\(Self.fileDescriptorLimit, privacy: .public) udp=\(Self.budgetAllocation.udpExchanges, privacy: .public) tcp=\(Self.budgetAllocation.tcpProxies, privacy: .public)"
        )
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // Invalidate the running generation before touching any resource so
        // in-flight socket callbacks become inert instead of racing teardown.
        guard lifecycleCoordinator.beginStop() else {
            completionHandler()
            return
        }

        // Stop wake-up observers first so no new work is scheduled during
        // teardown.
        stopBypassNotifications()

        // Shut down on the queue that owns the pool and exchange callbacks.
        let pool = resolverSocketPool
        resolverSocketPool = nil
        let registry = udpExchangeRegistry
        udpExchangeRegistry = nil
        dnsQueue.sync {
            pool?.shutdown()
            registry?.shutdown()
        }

        configWorker?.stop()
        configWorker = nil

        controlListener?.stop()
        controlListener = nil

        let reasonStr: String
        switch reason {
        case .none: reasonStr = "none"
        case .userInitiated: reasonStr = "user initiated"
        case .providerFailed: reasonStr = "provider failed"
        case .noNetworkAvailable: reasonStr = "no network"
        case .unrecoverableNetworkChange: reasonStr = "network change"
        case .providerDisabled: reasonStr = "provider disabled"
        case .authenticationCanceled: reasonStr = "auth canceled"
        case .configurationFailed: reasonStr = "config failed"
        case .idleTimeout: reasonStr = "idle timeout"
        case .configurationDisabled: reasonStr = "config disabled"
        case .configurationRemoved: reasonStr = "config removed"
        case .superceded: reasonStr = "superceded"
        case .userLogout: reasonStr = "user logout"
        case .userSwitch: reasonStr = "user switch"
        case .connectionFailed: reasonStr = "connection failed"
        case .sleep: reasonStr = "sleep"
        case .appUpdate: reasonStr = "app update"
        case .internalError: reasonStr = "internal error"
        @unknown default: reasonStr = "unknown"
        }
        tcpQueue.async { [self] in
            tcpProxyStopping = true
            tcpIdleSweeper?.cancel()
            tcpIdleSweeper = nil
            let proxies = Array(activeTCPProxies.values)
            for proxy in proxies {
                proxy.stop()
            }
            activeTCPProxies.removeAll()

            let terminationToken = lifecycleCoordinator.finishStop()
            logger.notice("DNS Proxy stopped (reason: \(reasonStr, privacy: .public))")
            completionHandler()

            // Exit once the stop ack has flushed. nesessionmanager keeps this
            // process alive after a stop, but launchd only removes the job, and
            // rebuilds its MachServices (the proxy-control endpoint) on the next
            // enable, when the process exits. Without this, a
            // disable/enable bounce reuses a job record whose endpoint
            // launchd stripped during an upgrade race, and the control plane
            // stays unreachable until reboot.
            //
            // Guarded by the stop generation. The normal App path disables an
            // already-enabled proxy before resolver start and re-enables right
            // after, so a start inside this delay must not be killed.
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(500)) {
                [lifecycleCoordinator, logger] in
                guard lifecycleCoordinator.mayTerminate(terminationToken) else {
                    logger.notice("Self-termination suppressed; a newer start claimed the provider")
                    return
                }
                exit(0)
            }
        }
    }

    /// Forces bypass the moment the control session is lost, instead of leaving
    /// forwarding in interception mode until the next health evaluation.
    private func forceBypassAfterSessionLoss() {
        let wasIntercepting = stateManager.setBypassMode(true)
        // The listener already logged why the session ended.
        if wasIntercepting {
            postInterceptionChanged()
            closeActiveTCPProxies()
        }
        configWorker?.enqueueDarwinWakeup { [weak self] in
            self?.configWorker?.handleDarwinWakeup(reason: "session-lost")
        }
    }

    // MARK: - Flow Handling

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let generation = lifecycleCoordinator.generationForNewFlow() else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return true
        }

        // The signing identifier is attacker-controlled metadata, so it only
        // selects a candidate. Trust requires audit-token path resolution,
        // static code identity, and the OS-supplied source identity matching a
        // code-directory hash of the inspected binary.
        let isPassthrough = processValidator.isPassthrough(
            claimedSigningIdentifier: flow.metaData.sourceAppSigningIdentifier,
            auditToken: flow.metaData.sourceAppAuditToken,
            sourceUniqueIdentifier: flow.metaData.sourceAppUniqueIdentifier
        )

        if let udpFlow = flow as? NEAppProxyUDPFlow {
            handleUDPFlow(
                udpFlow,
                isPassthrough: isPassthrough,
                generation: generation
            )
        } else if let tcpFlow = flow as? NEAppProxyTCPFlow {
            handleTCPFlow(
                tcpFlow,
                isPassthrough: isPassthrough,
                generation: generation
            )
        } else {
            logger.warning("Unknown flow type received, ignoring")
        }

        return true
    }

    // MARK: - UDP Flow Handling

    /// Peer resets and aborts are ordinary churn (connect-only probes closed
    /// before open completes). Anything else deserves an error line.
    private func logFlowOpenFailure(_ transport: String, error: Error) {
        guard !ProxyFlowOpenPolicy.isRoutineOpenFailure(error) else { return }
        logger.error("\(transport, privacy: .public) open failed: \(error.localizedDescription, privacy: .public)")
    }

    private func handleUDPFlow(
        _ flow: NEAppProxyUDPFlow,
        isPassthrough: Bool,
        generation: UInt64
    ) {
        let admitted = lifecycleCoordinator.performIfCurrent(generation) {
            flow.open(withLocalEndpoint: nil) { [weak self] error in
                guard let self = self else { return }
                guard self.lifecycleCoordinator.isCurrent(generation) else {
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                    return
                }
                if let error = error {
                    self.logFlowOpenFailure("UDP", error: error)
                    ProxyFlowOpenPolicy.closeAfterOpenFailure(flow, error: error)
                    return
                }
                self.readUDPDatagrams(
                    flow,
                    isPassthrough: isPassthrough,
                    generation: generation
                )
            }
        }
        guard admitted else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }
    }

    private func readUDPDatagrams(
        _ flow: NEAppProxyUDPFlow,
        isPassthrough: Bool,
        generation: UInt64
    ) {
        let admitted = lifecycleCoordinator.performIfCurrent(generation) {
            flow.readDatagrams { [weak self] datagrams, endpoints, readError in
                guard let self = self else { return }
                guard self.lifecycleCoordinator.isCurrent(generation) else {
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                    return
                }

                if readError != nil {
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                    return
                }
                guard let datagrams = datagrams, let endpoints = endpoints, !datagrams.isEmpty else { return }

                let count = min(datagrams.count, endpoints.count)

                for i in 0..<count {
                    guard let endpoint = endpoints[i] as? NWHostEndpoint else { continue }
                    let datagram = datagrams[i]

                    self.processUDPDatagramDirect(
                        flow: flow,
                        datagram: datagram,
                        endpoint: endpoint,
                        isPassthrough: isPassthrough,
                        generation: generation
                    )
                }

                self.readUDPDatagrams(
                    flow,
                    isPassthrough: isPassthrough,
                    generation: generation
                )
            }
        }
        guard admitted else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }
    }

    private func processUDPDatagramDirect(
        flow: NEAppProxyUDPFlow,
        datagram: Data,
        endpoint: NWHostEndpoint,
        isPassthrough: Bool,
        generation: UInt64
    ) {
        lifecycleCoordinator.performIfCurrent(generation) {
            let destination = endpoint.hostname

            let (currentAllDNSIPs, currentBypassMode) = stateManager.read()

            let toResolver =
                !isPassthrough && !currentBypassMode
                && matchesDNSIP(destination, in: currentAllDNSIPs)

            if toResolver, let pool = resolverSocketPool {
                pool.query(datagram, timeout: connectionTimeout) { [weak self, weak flow] response in
                    guard let self, let response, let flow else { return }
                    self.lifecycleCoordinator.performIfCurrent(generation) {
                        flow.writeDatagrams([response], sentBy: [endpoint]) { _ in }
                    }
                }
                return
            }

            let targetHost = toResolver ? resolverHost : destination
            let targetPort = toResolver ? resolverPort : (UInt16(endpoint.port) ?? 53)

            guard !targetHost.isEmpty, let registry = udpExchangeRegistry else { return }

            guard registry.acquireSlot() else {
                logUDPExchangeSaturation()
                return
            }
            guard
                let exchange = DNSUDPExchange(
                    host: targetHost, queue: dnsQueue, onDescriptorClosed: { registry.releaseSlot() })
            else {
                registry.releaseSlot()
                return
            }
            let token = registry.track(exchange)

            exchange.sendQuery(datagram, port: targetPort) { [weak self] response in
                registry.finish(token)
                guard let self else { return }
                guard let response else {
                    self.logger.debug("UDP exchange with \(targetHost, privacy: .public) ended without a response")
                    return
                }
                self.lifecycleCoordinator.performIfCurrent(generation) {
                    flow.writeDatagrams([response], sentBy: [endpoint]) { _ in }
                }
            }
        }
    }

    private func logUDPExchangeSaturation() {
        guard
            udpExchangeBudget.shouldLogSaturation(
                uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds)
        else { return }
        let capacity = udpExchangeBudget.capacity
        let dropped = udpExchangeBudget.rejected
        let message =
            "UDP passthrough budget saturated; datagrams dropped (capacity=\(capacity), dropped=\(dropped))"
        logger.warning("\(message, privacy: .public)")
    }

    /// One passthrough UDP DNS exchange over a BSD socket.
    ///
    /// The socket is connected to the selected destination, so the kernel drops
    /// datagrams from any other source, and every accepted datagram is still
    /// correlated against the outstanding transaction ID and Question before it
    /// is forwarded (RFC 5452 section 9.1). Expiry is driven by the registry's
    /// shared sweeper, not by per-datagram work items.
    final class DNSUDPExchange: @unchecked Sendable {
        private let fd: Int32
        private let lifecycle: ProxyDescriptorLifecycle
        private let queue: DispatchQueue
        private let isIPv6: Bool
        private let host: String
        private let ipv6ScopeID: UInt32
        private var readSource: DispatchSourceRead?
        private var completion: ((Data?) -> Void)?
        private var question: DNSQuestion?
        private var isCompleted = false
        private let lock = NSLock()

        // Preallocated so the hot path does not allocate.
        private var buffer = [UInt8](repeating: 0, count: 4096)

        /// Datagrams read per wake-up. An uncorrelated datagram is discarded and
        /// the exchange keeps waiting, so the drain loop needs a bound. The read
        /// source fires again while the socket still holds data.
        private static let maxDatagramsPerWakeup = 16

        init?(host: String, queue: DispatchQueue, onDescriptorClosed: @escaping () -> Void) {
            self.queue = queue

            var addr4 = in_addr()
            let useIPv6: Bool
            if let scopedIPv6Address = ScopedIPv6Address.parse(host) {
                self.host = scopedIPv6Address.address
                self.ipv6ScopeID = scopedIPv6Address.scopeID
                self.isIPv6 = true
                useIPv6 = true
            } else if inet_pton(AF_INET, host, &addr4) == 1 {
                self.host = host
                self.ipv6ScopeID = 0
                self.isIPv6 = false
                useIPv6 = false
            } else {
                return nil
            }

            let family: Int32 = useIPv6 ? AF_INET6 : AF_INET
            let socketFd = socket(family, SOCK_DGRAM, IPPROTO_UDP)
            if socketFd < 0 { return nil }
            self.fd = socketFd
            self.lifecycle = ProxyDescriptorLifecycle(fd: socketFd, onClosed: onDescriptorClosed)

            let flags = fcntl(fd, F_GETFL, 0)
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        }

        func sendQuery(_ data: Data, port: UInt16, completion: @escaping (Data?) -> Void) {
            lock.lock()
            guard !isCompleted else {
                lock.unlock()
                completion(nil)
                return
            }
            self.completion = completion
            let started = startExchangeLocked(data, port: port)
            lock.unlock()
            if !started { complete(with: nil) }
        }

        /// Runs under `lock`, so an expiry racing the send observes either an
        /// exchange that has not sent yet, which then refuses to send, or one
        /// whose read source already exists and can be cancelled.
        private func startExchangeLocked(_ data: Data, port: UInt16) -> Bool {
            guard !isCompleted else { return false }
            guard let outstanding = DNSResponseCorrelator.question(inQuery: data) else { return false }
            question = outstanding

            guard connectDestination(port: port) else { return false }

            let sent = data.withUnsafeBytes { buf in
                Darwin.send(fd, buf.baseAddress, data.count, 0)
            }
            guard sent == data.count else { return false }

            // The source captures self strongly, keeping the exchange alive
            // until complete() cancels it on a response or on expiry.
            let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
            lifecycle.addSource()
            source.setEventHandler { [self] in
                drainResponses()
            }
            source.setCancelHandler { [lifecycle] in
                lifecycle.sourceCancelled()
            }
            readSource = source
            source.resume()
            return true
        }

        /// Completes the exchange without an answer. Called by the registry's
        /// sweeper once the shared deadline passes.
        func expire() {
            complete(with: nil)
        }

        private func connectDestination(port: UInt16) -> Bool {
            if isIPv6 {
                var addr = sockaddr_in6()
                addr.sin6_family = sa_family_t(AF_INET6)
                addr.sin6_port = port.bigEndian
                addr.sin6_len = __uint8_t(MemoryLayout<sockaddr_in6>.size)
                addr.sin6_scope_id = ipv6ScopeID
                guard inet_pton(AF_INET6, host, &addr.sin6_addr) == 1 else { return false }
                return connectAddress(&addr)
            }

            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_len = __uint8_t(MemoryLayout<sockaddr_in>.size)
            guard inet_pton(AF_INET, host, &addr.sin_addr) == 1 else { return false }
            return connectAddress(&addr)
        }

        private func connectAddress<T>(_ address: inout T) -> Bool {
            let result = withUnsafePointer(to: &address) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    Darwin.connect(fd, saPtr, socklen_t(MemoryLayout<T>.size))
                }
            }
            return result == 0
        }

        private func drainResponses() {
            guard let question else {
                complete(with: nil)
                return
            }

            for _ in 0..<Self.maxDatagramsPerWakeup {
                var wasTruncated = false
                let received = receiveDatagram(truncated: &wasTruncated)

                if received < 0 {
                    let err = errno
                    if err == EAGAIN || err == EWOULDBLOCK || err == EINTR { return }
                    complete(with: nil)
                    return
                }

                let datagram = Data(buffer.prefix(received))
                // RFC 5452 section 9.1: a datagram that does not answer the
                // outstanding transaction is discarded, and the exchange keeps
                // waiting for the real response until its deadline.
                guard DNSResponseCorrelator.matches(response: datagram, question: question) else {
                    continue
                }

                if wasTruncated {
                    complete(
                        with: DNSResponseCorrelator.truncatedResponse(
                            from: datagram, question: question))
                } else {
                    complete(with: datagram)
                }
                return
            }
        }

        /// Reads one datagram and reports whether the kernel had to discard part
        /// of it, so an oversized response is never forwarded as a prefix.
        private func receiveDatagram(truncated: inout Bool) -> Int {
            var iov = iovec()
            var message = msghdr()
            var received = -1

            buffer.withUnsafeMutableBytes { raw in
                iov.iov_base = raw.baseAddress
                iov.iov_len = raw.count
                withUnsafeMutablePointer(to: &iov) { iovPtr in
                    message.msg_iov = iovPtr
                    message.msg_iovlen = 1
                    received = recvmsg(fd, &message, 0)
                }
            }

            truncated = received >= 0 && (message.msg_flags & MSG_TRUNC) != 0
            return received
        }

        private func complete(with data: Data?) {
            lock.lock()
            if isCompleted {
                lock.unlock()
                return
            }
            isCompleted = true
            let handler = completion
            completion = nil
            let source = readSource
            readSource = nil
            lock.unlock()

            // The lifecycle closes the descriptor only once the source has
            // cancelled. Closing it while the source still monitors it is
            // undefined behavior.
            source?.cancel()
            lifecycle.requestClose()
            handler?(data)
        }

        deinit {
            lock.lock()
            let alreadyDone = isCompleted
            lock.unlock()
            if !alreadyDone { lifecycle.requestClose() }
        }
    }

    /// Owns every in-flight passthrough exchange: one bounded budget admits them
    /// and one timer expires them, instead of two dispatch work items per
    /// datagram. At saturation the datagram is dropped deliberately rather than
    /// allocating another socket the process cannot afford.
    final class DNSUDPExchangeRegistry: @unchecked Sendable {
        private struct Tracked {
            let exchange: DNSUDPExchange
            let deadlineNanoseconds: UInt64
        }

        private static let sweepInterval: TimeInterval = 0.25

        private let queue: DispatchQueue
        private let budget: ProxyResourceBudget
        private let timeoutNanoseconds: UInt64
        private let lock = NSLock()
        private var tracked: [ObjectIdentifier: Tracked] = [:]
        private var sweeper: DispatchSourceTimer?
        private var isShutdown = false

        init(queue: DispatchQueue, budget: ProxyResourceBudget, timeout: TimeInterval) {
            self.queue = queue
            self.budget = budget
            self.timeoutNanoseconds = UInt64(max(timeout, 0) * 1_000_000_000)
        }

        func start() {
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(
                deadline: .now() + Self.sweepInterval,
                repeating: Self.sweepInterval,
                leeway: .milliseconds(50)
            )
            timer.setEventHandler { [weak self] in
                self?.expireOverdueExchanges()
            }
            timer.resume()

            lock.lock()
            sweeper = timer
            lock.unlock()
        }

        func acquireSlot() -> Bool {
            lock.lock()
            let running = !isShutdown
            lock.unlock()
            guard running else { return false }
            return budget.acquire()
        }

        func releaseSlot() {
            budget.release()
        }

        @discardableResult
        func track(_ exchange: DNSUDPExchange) -> ObjectIdentifier {
            let token = ObjectIdentifier(exchange)
            let deadline = DispatchTime.now().uptimeNanoseconds &+ timeoutNanoseconds
            lock.lock()
            tracked[token] = Tracked(exchange: exchange, deadlineNanoseconds: deadline)
            lock.unlock()
            return token
        }

        /// Stops tracking a finished exchange. The budget slot is not returned
        /// here. The exchange's descriptor lifecycle releases it exactly once,
        /// when the socket is actually closed.
        func finish(_ token: ObjectIdentifier) {
            lock.lock()
            tracked.removeValue(forKey: token)
            lock.unlock()
        }

        func shutdown() {
            lock.lock()
            guard !isShutdown else {
                lock.unlock()
                return
            }
            isShutdown = true
            let pending = tracked.values.map(\.exchange)
            tracked.removeAll()
            let timer = sweeper
            sweeper = nil
            lock.unlock()

            timer?.cancel()
            for exchange in pending {
                exchange.expire()
            }
        }

        func expireOverdueExchanges() {
            let now = DispatchTime.now().uptimeNanoseconds
            lock.lock()
            let overdue = tracked.filter { $0.value.deadlineNanoseconds <= now }
            for token in overdue.keys {
                tracked.removeValue(forKey: token)
            }
            lock.unlock()

            for entry in overdue.values {
                entry.exchange.expire()
            }
        }
    }

    private struct TCPConnectAttempt {
        let fd: Int32
        let result: Int32
        let error: Int32
    }

    private struct SocketSetupFailure: Error {
        let code: Int32
    }

    private enum TCPConnectSetup {
        case started(TCPConnectAttempt)
        case unsupportedTarget
        case socketUnavailable(Int32)
    }

    private final class TCPConnectState: @unchecked Sendable {
        let fd: Int32
        let lifecycle: ProxyDescriptorLifecycle
        let routingRevision: UInt64

        private var didComplete = false
        private let lock = NSLock()
        private var flow: NEAppProxyTCPFlow?
        private var source: DispatchSourceWrite?
        var timeoutWorkItem: DispatchWorkItem?

        init(
            fd: Int32,
            lifecycle: ProxyDescriptorLifecycle,
            flow: NEAppProxyTCPFlow,
            source: DispatchSourceWrite,
            routingRevision: UInt64
        ) {
            self.fd = fd
            self.lifecycle = lifecycle
            self.flow = flow
            self.source = source
            self.routingRevision = routingRevision
        }

        func markConnected() -> NEAppProxyTCPFlow? {
            lock.lock()
            guard !didComplete else {
                lock.unlock()
                return nil
            }
            didComplete = true
            let connectedFlow = flow
            let connectSource = source
            let timeout = timeoutWorkItem
            flow = nil
            source = nil
            timeoutWorkItem = nil
            lock.unlock()

            timeout?.cancel()
            connectSource?.cancel()
            return connectedFlow
        }

        func cleanup() {
            lock.lock()
            guard !didComplete else {
                lock.unlock()
                return
            }
            didComplete = true
            let staleFlow = flow
            let connectSource = source
            let timeout = timeoutWorkItem
            flow = nil
            source = nil
            timeoutWorkItem = nil
            lock.unlock()

            timeout?.cancel()
            connectSource?.cancel()
            lifecycle.requestClose()
            staleFlow?.closeReadWithError(nil)
            staleFlow?.closeWriteWithError(nil)
        }
    }

    // MARK: - TCP Flow Handling

    private struct TCPRoute {
        let toResolver: Bool
        let revision: UInt64
    }

    private func selectTCPRoute(destination: String, isPassthrough: Bool) -> TCPRoute {
        let snapshot = stateManager.routingSnapshot()
        let toResolver =
            !isPassthrough && !snapshot.bypassMode
            && matchesDNSIP(destination, in: snapshot.allDNSIPs)
        return TCPRoute(toResolver: toResolver, revision: snapshot.revision)
    }

    private func handleTCPFlow(
        _ flow: NEAppProxyTCPFlow,
        isPassthrough: Bool,
        generation: UInt64
    ) {
        guard let originalEndpoint = flow.remoteEndpoint as? NWHostEndpoint else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }

        let destination = originalEndpoint.hostname

        let admitted = lifecycleCoordinator.performIfCurrent(generation) {
            flow.open(withLocalEndpoint: nil) { [weak self] error in
                guard let self = self else { return }
                guard self.lifecycleCoordinator.isCurrent(generation) else {
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                    return
                }
                if let error = error {
                    self.logFlowOpenFailure("TCP", error: error)
                    ProxyFlowOpenPolicy.closeAfterOpenFailure(flow, error: error)
                    return
                }
                let route = self.selectTCPRoute(
                    destination: destination,
                    isPassthrough: isPassthrough)
                self.connectAndProxyTCP(
                    flow,
                    route: route,
                    originalEndpoint: originalEndpoint,
                    generation: generation
                )
            }
        }
        guard admitted else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }
    }

    private func connectAndProxyTCP(
        _ flow: NEAppProxyTCPFlow,
        route: TCPRoute,
        originalEndpoint: NWHostEndpoint,
        generation: UInt64
    ) {
        let admitted = lifecycleCoordinator.performIfCurrent(generation) {
            connectAndProxyTCPAdmitted(
                flow,
                route: route,
                originalEndpoint: originalEndpoint,
                generation: generation
            )
        }
        guard admitted else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }
    }

    private func connectAndProxyTCPAdmitted(
        _ flow: NEAppProxyTCPFlow,
        route: TCPRoute,
        originalEndpoint: NWHostEndpoint,
        generation: UInt64
    ) {
        guard stateManager.isCurrentRoutingRevision(route.revision) else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }

        let targetHost: String
        let targetPort: UInt16

        if route.toResolver {
            targetHost = resolverHost
            targetPort = resolverPort
        } else {
            targetHost = originalEndpoint.hostname
            targetPort = UInt16(originalEndpoint.port) ?? 53
        }

        guard !targetHost.isEmpty else {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }

        // Admission precedes the connect: the descriptor, the connect dispatch
        // source, and the connect timeout work item are all held for the whole
        // connect window, so a slot taken only after the connection succeeds
        // bounds the established proxies and leaves the in-progress ones
        // unlimited.
        guard let slot = tcpProxyBudget.acquireSlot() else {
            logTCPProxySaturation()
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }

        let attempt: TCPConnectAttempt
        switch createTCPConnectAttempt(host: targetHost, port: targetPort) {
        case .started(let startedAttempt):
            attempt = startedAttempt
        case .unsupportedTarget:
            logger.debug("TCP target is not a numeric IP address: \(targetHost, privacy: .public)")
            slot.release()
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        case .socketUnavailable(let code):
            logger.error("TCP upstream socket unavailable: errno=\(code, privacy: .public)")
            slot.release()
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }

        // The slot follows the descriptor: it is returned exactly once, when
        // the socket is actually closed, whichever path closes it.
        let lifecycle = ProxyDescriptorLifecycle(fd: attempt.fd) { slot.release() }
        if attempt.result == 0 {
            proxyTCPBidirectional(
                flow: flow,
                fd: attempt.fd,
                lifecycle: lifecycle,
                routingRevision: route.revision,
                generation: generation
            )
            return
        }

        guard attempt.error == EINPROGRESS else {
            logger.debug("TCP upstream connect failed: errno=\(attempt.error, privacy: .public)")
            lifecycle.requestClose()
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }

        waitForTCPConnect(
            flow: flow,
            fd: attempt.fd,
            lifecycle: lifecycle,
            routingRevision: route.revision,
            generation: generation
        )
    }

    private func createTCPConnectAttempt(host: String, port: UInt16) -> TCPConnectSetup {
        var addr4 = sockaddr_in()
        if inet_pton(AF_INET, host, &addr4.sin_addr) == 1 {
            addr4.sin_family = sa_family_t(AF_INET)
            addr4.sin_port = port.bigEndian
            addr4.sin_len = __uint8_t(MemoryLayout<sockaddr_in>.size)
            return connectTCPAddress(family: AF_INET, address: &addr4)
        }

        if let scopedIPv6Address = ScopedIPv6Address.parse(host) {
            var addr6 = sockaddr_in6()
            addr6.sin6_family = sa_family_t(AF_INET6)
            addr6.sin6_port = port.bigEndian
            addr6.sin6_len = __uint8_t(MemoryLayout<sockaddr_in6>.size)
            addr6.sin6_scope_id = scopedIPv6Address.scopeID
            _ = inet_pton(AF_INET6, scopedIPv6Address.address, &addr6.sin6_addr)
            return connectTCPAddress(family: AF_INET6, address: &addr6)
        }

        return .unsupportedTarget
    }

    private func connectTCPAddress<T>(family: Int32, address: inout T) -> TCPConnectSetup {
        let fd: Int32
        switch createConfiguredTCPSocket(family: family) {
        case .success(let descriptor): fd = descriptor
        case .failure(let failure): return .socketUnavailable(failure.code)
        }

        let result = withUnsafePointer(to: &address) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.connect(fd, saPtr, socklen_t(MemoryLayout<T>.size))
            }
        }
        let connectError = result == 0 ? 0 : errno
        return .started(TCPConnectAttempt(fd: fd, result: result, error: connectError))
    }

    private func createConfiguredTCPSocket(family: Int32) -> Result<Int32, SocketSetupFailure> {
        let fd = socket(family, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return .failure(SocketSetupFailure(code: errno)) }

        var one: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        let flags = fcntl(fd, F_GETFL, 0)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
            let failure = SocketSetupFailure(code: errno)
            Darwin.close(fd)
            return .failure(failure)
        }

        return .success(fd)
    }

    private func waitForTCPConnect(
        flow: NEAppProxyTCPFlow,
        fd: Int32,
        lifecycle: ProxyDescriptorLifecycle,
        routingRevision: UInt64,
        generation: UInt64
    ) {
        let source = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: tcpQueue)
        lifecycle.addSource()

        let state = TCPConnectState(
            fd: fd,
            lifecycle: lifecycle,
            flow: flow,
            source: source,
            routingRevision: routingRevision)
        source.setEventHandler { [weak self, state] in
            guard let self = self else {
                state.cleanup()
                return
            }
            self.finishTCPConnect(state, generation: generation)
        }
        source.setCancelHandler {
            lifecycle.sourceCancelled()
        }

        let timeout = DispatchWorkItem { [state] in
            state.cleanup()
        }
        state.timeoutWorkItem = timeout
        tcpQueue.asyncAfter(deadline: .now() + connectionTimeout, execute: timeout)

        source.resume()
    }

    private func finishTCPConnect(
        _ state: TCPConnectState,
        generation: UInt64
    ) {
        let admitted = lifecycleCoordinator.performIfCurrent(generation) {
            finishTCPConnectAdmitted(state, generation: generation)
        }
        guard admitted else {
            state.cleanup()
            return
        }
    }

    private func finishTCPConnectAdmitted(
        _ state: TCPConnectState,
        generation: UInt64
    ) {
        var socketError: Int32 = 0
        var socketErrorLength = socklen_t(MemoryLayout<Int32>.size)
        let result = getsockopt(state.fd, SOL_SOCKET, SO_ERROR, &socketError, &socketErrorLength)
        guard result == 0, socketError == 0 else {
            let connectError = result == 0 ? socketError : errno
            logger.debug("TCP upstream connect failed: errno=\(connectError, privacy: .public)")
            state.cleanup()
            return
        }

        guard let flow = state.markConnected() else { return }
        proxyTCPBidirectional(
            flow: flow,
            fd: state.fd,
            lifecycle: state.lifecycle,
            routingRevision: state.routingRevision,
            generation: generation
        )
    }

    private func proxyTCPBidirectional(
        flow: NEAppProxyTCPFlow,
        fd: Int32,
        lifecycle: ProxyDescriptorLifecycle,
        routingRevision: UInt64,
        generation: UInt64
    ) {
        tcpQueue.async { [weak self] in
            guard
                let self,
                !self.tcpProxyStopping,
                self.stateManager.isCurrentRoutingRevision(routingRevision)
            else {
                lifecycle.requestClose()
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return
            }

            let admitted = self.lifecycleCoordinator.performIfCurrent(generation) {
                let id = UUID()
                let proxy = TCPSocketProxy(
                    fd: fd,
                    lifecycle: lifecycle,
                    flow: flow,
                    queue: self.tcpQueue,
                    idleTimeout: self.tcpIdleTimeout
                ) { [weak self] in
                    self?.activeTCPProxies.removeValue(forKey: id)
                }
                self.activeTCPProxies[id] = proxy
                proxy.start()
            }
            guard admitted else {
                lifecycle.requestClose()
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return
            }
        }
    }

    private func logTCPProxySaturation() {
        guard
            tcpProxyBudget.shouldLogSaturation(
                uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds)
        else { return }
        let capacity = tcpProxyBudget.capacity
        let refused = tcpProxyBudget.rejected
        let message =
            "DNS-over-TCP proxy budget saturated; flows refused (capacity=\(capacity), refused=\(refused))"
        logger.warning("\(message, privacy: .public)")
    }

    /// Closes DNS-over-TCP proxies that moved no byte within the idle window.
    /// Runs on `tcpQueue`, which owns `activeTCPProxies`, and exits through the
    /// proxy's normal close path so sources, descriptor, and budget slot are all
    /// released the same way as a peer-initiated close.
    private func startTCPIdleSweeper() {
        tcpIdleSweeper?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: tcpQueue)
        timer.schedule(
            deadline: .now() + Self.tcpIdleSweepInterval,
            repeating: Self.tcpIdleSweepInterval,
            leeway: .seconds(1)
        )
        timer.setEventHandler { [weak self] in
            self?.closeIdleTCPProxies()
        }
        timer.resume()
        tcpIdleSweeper = timer
    }

    private func closeIdleTCPProxies() {
        let now = DispatchTime.now().uptimeNanoseconds
        let idle = activeTCPProxies.values.filter { $0.isIdle(at: now) }
        guard !idle.isEmpty else { return }
        for proxy in idle {
            proxy.stop()
        }
    }

    /// A DNS-over-TCP proxy keeps the route chosen when its flow opened, so a
    /// routing change retires the open ones. Clients reconnect and the new
    /// flows are routed under the current state.
    private func closeActiveTCPProxies() {
        tcpQueue.async { [weak self] in
            guard let self, !self.tcpProxyStopping, !self.activeTCPProxies.isEmpty else { return }
            let proxies = Array(self.activeTCPProxies.values)
            for proxy in proxies {
                proxy.stop()
            }
        }
    }

    private final class TCPSocketProxy: @unchecked Sendable {
        private static let maxFlowWriteBufferBytes = 1_048_576
        private static let resumeFlowWriteBufferBytes = 524_288

        private struct PendingSocketWrite {
            let data: Data
            var offset: Int
        }

        private let fd: Int32
        private let lifecycle: ProxyDescriptorLifecycle
        private let flow: NEAppProxyTCPFlow
        private let queue: DispatchQueue
        private let onClose: () -> Void
        private var readSource: DispatchSourceRead?
        private var writeSource: DispatchSourceWrite?
        private var socketWrites: [PendingSocketWrite] = []
        private var flowWrites: [Data] = []
        private var flowWriteBufferedBytes = 0
        private var isWritingToFlow = false
        private var isSocketReadPaused = false
        private var readFlowAfterSocketDrain = false
        private var flowReadClosed = false
        private var socketReadClosed = false
        private var flowWriteClosed = false
        private var isClosed = false
        private var readBuffer = [UInt8](repeating: 0, count: 65_535)
        private var idleDeadline: ProxyIdleDeadline

        init(
            fd: Int32,
            lifecycle: ProxyDescriptorLifecycle,
            flow: NEAppProxyTCPFlow,
            queue: DispatchQueue,
            idleTimeout: TimeInterval,
            onClose: @escaping () -> Void
        ) {
            self.fd = fd
            self.lifecycle = lifecycle
            self.flow = flow
            self.queue = queue
            self.onClose = onClose
            self.idleDeadline = ProxyIdleDeadline(
                timeout: idleTimeout, startedAt: DispatchTime.now().uptimeNanoseconds)
        }

        /// Whether this proxy has moved no byte within its idle window. Only
        /// `noteProgress` renews the deadline, so a silent connection expires
        /// however long its sources stay armed.
        func isIdle(at uptimeNanoseconds: UInt64) -> Bool {
            !isClosed && idleDeadline.isExpired(at: uptimeNanoseconds)
        }

        private func noteProgress() {
            idleDeadline.noteProgress(at: DispatchTime.now().uptimeNanoseconds)
        }

        func start() {
            let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
            lifecycle.addSource()
            source.setEventHandler { [self] in
                handleSocketReadable()
            }
            source.setCancelHandler { [lifecycle] in
                lifecycle.sourceCancelled()
            }
            readSource = source
            source.resume()

            readFlow()
        }

        func stop() {
            close()
        }

        private func readFlow() {
            guard !isClosed, !flowReadClosed else { return }
            flow.readData { [weak self] data, error in
                guard let self = self else { return }
                self.queue.async {
                    self.handleFlowRead(data: data, error: error)
                }
            }
        }

        private func handleFlowRead(data: Data?, error: Error?) {
            guard !isClosed else { return }
            guard error == nil, let data = data, !data.isEmpty else {
                flowReadClosed = true
                _ = shutdown(fd, SHUT_WR)
                closeIfFinished()
                return
            }

            noteProgress()
            socketWrites.append(PendingSocketWrite(data: data, offset: 0))
            readFlowAfterSocketDrain = true
            drainSocketWrites()
        }

        private func drainSocketWrites() {
            guard !isClosed else { return }

            while !socketWrites.isEmpty {
                var current = socketWrites[0]
                let sent = current.data.withUnsafeBytes { bytes -> Int in
                    guard let baseAddress = bytes.baseAddress else { return 0 }
                    return send(
                        fd,
                        baseAddress.advanced(by: current.offset),
                        current.data.count - current.offset,
                        0
                    )
                }

                if sent > 0 {
                    noteProgress()
                    current.offset += sent
                    if current.offset >= current.data.count {
                        socketWrites.removeFirst()
                    } else {
                        socketWrites[0] = current
                    }
                    continue
                }

                if sent == 0 || errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR {
                    ensureSocketWriteSource()
                    return
                }

                close()
                return
            }

            cancelSocketWriteSource()
            if readFlowAfterSocketDrain {
                readFlowAfterSocketDrain = false
                readFlow()
            }
            closeIfFinished()
        }

        private func ensureSocketWriteSource() {
            guard writeSource == nil else { return }
            let source = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: queue)
            lifecycle.addSource()
            source.setEventHandler { [self] in
                drainSocketWrites()
            }
            source.setCancelHandler { [lifecycle] in
                lifecycle.sourceCancelled()
            }
            writeSource = source
            source.resume()
        }

        private func cancelSocketWriteSource() {
            writeSource?.cancel()
            writeSource = nil
        }

        private func handleSocketReadable() {
            guard !isClosed else { return }

            while !isClosed {
                if flowWriteBufferedBytes >= Self.maxFlowWriteBufferBytes {
                    pauseSocketReadSource()
                    return
                }

                let received = recv(fd, &readBuffer, readBuffer.count, 0)
                if received > 0 {
                    noteProgress()
                    let data = Data(readBuffer.prefix(received))
                    flowWrites.append(data)
                    flowWriteBufferedBytes += data.count
                    drainFlowWrites()
                    if flowWriteBufferedBytes >= Self.maxFlowWriteBufferBytes {
                        pauseSocketReadSource()
                        return
                    }
                    continue
                }

                if received == 0 {
                    socketReadClosed = true
                    cancelSocketReadSource()
                    finishFlowOutputIfNeeded()
                    closeIfFinished()
                    return
                }

                if errno == EAGAIN || errno == EWOULDBLOCK {
                    return
                }
                if errno == EINTR {
                    continue
                }

                close()
                return
            }
        }

        private func pauseSocketReadSource() {
            guard !isSocketReadPaused, readSource != nil else { return }
            readSource?.suspend()
            isSocketReadPaused = true
        }

        private func resumeSocketReadSourceIfNeeded() {
            guard isSocketReadPaused, flowWriteBufferedBytes <= Self.resumeFlowWriteBufferBytes else { return }
            readSource?.resume()
            isSocketReadPaused = false
        }

        private func drainFlowWrites() {
            guard !isClosed, !isWritingToFlow, !flowWrites.isEmpty else {
                finishFlowOutputIfNeeded()
                return
            }

            isWritingToFlow = true
            let data = flowWrites[0]
            flow.write(data) { [weak self] error in
                guard let self = self else { return }
                self.queue.async {
                    self.finishFlowWrite(error: error)
                }
            }
        }

        private func finishFlowWrite(error: Error?) {
            guard !isClosed else { return }
            guard error == nil else {
                close()
                return
            }

            if !flowWrites.isEmpty {
                noteProgress()
                let finished = flowWrites.removeFirst()
                flowWriteBufferedBytes = max(0, flowWriteBufferedBytes - finished.count)
            }
            isWritingToFlow = false
            resumeSocketReadSourceIfNeeded()
            drainFlowWrites()
            closeIfFinished()
        }

        private func finishFlowOutputIfNeeded() {
            guard socketReadClosed, !flowWriteClosed, !isWritingToFlow, flowWrites.isEmpty else { return }
            flowWriteClosed = true
            flow.closeWriteWithError(nil)
        }

        private func cancelSocketReadSource() {
            if isSocketReadPaused {
                readSource?.resume()
                isSocketReadPaused = false
            }
            readSource?.cancel()
            readSource = nil
        }

        private func closeIfFinished() {
            finishFlowOutputIfNeeded()
            if flowReadClosed, socketReadClosed, flowWriteClosed {
                close()
            }
        }

        private func close() {
            guard !isClosed else { return }
            isClosed = true
            cancelSocketReadSource()
            cancelSocketWriteSource()
            lifecycle.requestClose()
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            onClose()
        }
    }

    // MARK: - Helpers

    private func matchesDNSIP(_ ip: String, in dnsIPs: Set<String>) -> Bool {
        if dnsIPs.contains(ip) {
            return true
        }

        // Retries without IPv6 brackets and zone ID.
        var normalized = ip.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if let zoneIndex = normalized.firstIndex(of: "%") {
            normalized = String(normalized[..<zoneIndex])
        }

        if dnsIPs.contains(normalized) {
            return true
        }
        if dnsIPs.contains("[\(normalized)]") {
            return true
        }

        return false
    }

    // MARK: - Bypass Notifications (Darwin Notifications from Agent)

    private func observeBypassNotifications() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()

        CFNotificationCenterAddObserver(
            center,
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer else { return }
                let provider = Unmanaged<DNSProxyProvider>.fromOpaque(observer).takeUnretainedValue()
                // Coalesce before enqueueing: a notification flood must not be
                // able to build a queue backlog.
                provider.wakeupCoalescer.signal()
            },
            bypassEnableNotification,
            nil,
            .deliverImmediately
        )

        CFNotificationCenterAddObserver(
            center,
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer else { return }
                let provider = Unmanaged<DNSProxyProvider>.fromOpaque(observer).takeUnretainedValue()
                // Coalesce before enqueueing: a notification flood must not be
                // able to build a queue backlog.
                provider.wakeupCoalescer.signal()
            },
            bypassDisableNotification,
            nil,
            .deliverImmediately
        )
    }

    private func stopBypassNotifications() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterRemoveObserver(center, Unmanaged.passUnretained(self).toOpaque(), nil, nil)
        // Cancel after removing the observer so no wake-up scheduled during
        // teardown can still reach the worker.
        wakeupCoalescer.cancel()
    }
}
