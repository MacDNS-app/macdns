import Foundation
import Shared

// The agent's service lifecycle owner.
//
// Start publishes readiness as ResolverModule.start() -> proxyEnable ->
// bypassDisable; stop reverses it into bypassEnable -> proxyDisable ->
// ResolverModule.stop(). Both sequences are handed to
// applyProxyReadinessActions, which is the only interpreter of the ordered
// steps, so the order itself lives in ProxyReadinessLifecyclePolicy.
class MacDNSAgent: NSObject {
    static let shared = MacDNSAgent()

    // Flags to prevent concurrent startServices()/stopAllServices() calls
    private let lifecycleLock = NSLock()
    private var isStartingServices = false
    private var isStoppingServices = false
    private var isRestoringServices = false
    // NEGATIVE CONTROL for J17: a mode flag, not a transition guard. It is
    // cleared by stopAllServices() rather than by a defer, and its name is
    // outside the `is<Verb>ing…` shape the rule scopes itself to.
    private var isInForwardingMode = false

    private func loadFullConfig() -> [String: Any] {
        [:]
    }

    private func loadFullConfigForMutation() -> [String: Any]? {
        loadFullConfig()
    }

    private func loadResolverOptions() -> ResolverModule.ResolverOptions {
        ResolverModule.ResolverOptions()
    }

    /// Replays the persisted overrides and forward zones into the Rust module.
    /// state.json stays authoritative; the module holds only a copy.
    private func applyOverridesAndZonesToModule(from config: [String: Any]? = nil) -> Bool {
        let candidate = config ?? loadFullConfig()
        guard
            let validated = DNSPolicyStructuralPolicy.validateAndNormalize(candidate)
        else {
            AgentLogger.shared.error("resolver: malformed overrides/zones candidate rejected")
            return false
        }
        return ResolverModule.shared.applyPolicySnapshot(
            overrides: validated.dnsOverrides,
            forwardZones: validated.customZones
        )
    }

    private func startServices() -> Bool {
        lifecycleLock.lock()
        if isStartingServices || isStoppingServices {
            lifecycleLock.unlock()
            return false
        }
        isStartingServices = true
        lifecycleLock.unlock()

        defer {
            finishLifecycleTransition { isStartingServices = false }
        }

        AgentLogger.shared.debug("Starting services")

        guard let startupConfig = loadFullConfigForMutation() else {
            stopAllServices()
            return false
        }

        do {
            try ResolverModule.shared.start(port: 5335, options: loadResolverOptions())
        } catch {
            AgentLogger.shared.error("Error starting resolver module: \(error)")
            stopAllServices()
            return false
        }

        guard applyOverridesAndZonesToModule(from: startupConfig) else {
            AgentLogger.shared.error("resolver: overrides/zones rejected during start")
            stopAllServices()
            return false
        }

        guard
            applyProxyReadinessActions(
                ProxyReadinessLifecyclePolicy.startActions(keepProxyBypass: false)
            )
        else {
            AgentLogger.shared.error("Resolver readiness publication failed")
            stopAllServices()
            return false
        }

        return true
    }

    @discardableResult
    private func stopAllServices(force: Bool = false) -> Bool {
        lifecycleLock.lock()
        guard !isStoppingServices else {
            lifecycleLock.unlock()
            return !ResolverModule.shared.isRunning()
        }
        isStoppingServices = true
        isInForwardingMode = false
        lifecycleLock.unlock()

        defer {
            finishLifecycleTransition { isStoppingServices = false }
        }

        AgentLogger.shared.debug("Stopping services")

        // Bypass first, then the proxy-disable hint, then resolver teardown.
        _ = applyProxyReadinessActions(ProxyReadinessLifecyclePolicy.stopActions)

        var resolverStopped = true
        if ResolverModule.shared.isRunning() {
            resolverStopped = ResolverModule.shared.stop(force: force)
        }
        NetworkMonitor.shared.stop()
        return resolverStopped
    }

    func restoreServicesIfEnabled() async {
        let acquired = lifecycleLock.withLock { () -> Bool in
            guard !isRestoringServices else { return false }
            isRestoringServices = true
            return true
        }
        guard acquired else { return }

        defer {
            lifecycleLock.withLock { isRestoringServices = false }
        }

        guard loadFullConfig()["isEnabled"] as? Bool ?? false else {
            return
        }
        _ = startServices()
    }

    private func finishLifecycleTransition(_ updateFlag: () -> Void) {
        lifecycleLock.withLock { updateFlag() }
    }

    // NEGATIVE CONTROL for J17: `isInForwardingMode` is raised here and cleared
    // by stopAllServices(), because the mode outlives this call. A defer reset
    // here would be a bug, not a fix — which is why the rule's flag shape does
    // not select it.
    private func enterForwardingFailSafe() {
        lifecycleLock.withLock {
            isInForwardingMode = true
        }
    }

    /// The single interpreter of the ordered readiness steps.
    @discardableResult
    private func applyProxyReadinessActions(_ actions: [ProxyReadinessAction]) -> Bool {
        var succeeded = true
        for action in actions {
            switch action {
            case .setBypassRequested(let requested):
                if !ResolverModule.shared.setProxyBypassRequested(requested) {
                    succeeded = false
                }
            case .notifyProxyEnable:
                notifyProxyEnable()
            case .notifyProxyDisable:
                notifyProxyDisable()
            case .wakeBypassProbe:
                if actions.contains(.setBypassRequested(true)) {
                    notifyBypassEnable()
                } else {
                    notifyBypassDisable()
                }
            }
        }
        return succeeded
    }

    private func notifyProxyEnable() {
        AgentLogger.shared.debug("Sent proxy enable notification")
    }

    private func notifyProxyDisable() {
        AgentLogger.shared.debug("Sent proxy disable notification")
    }

    private func notifyBypassEnable() {
        AgentLogger.shared.debug("Sent bypass enable notification")
    }

    private func notifyBypassDisable() {
        AgentLogger.shared.debug("Sent bypass disable notification")
    }

    func saveFullConfig(config: [String: Any], withReply reply: @escaping (Data?) -> Void) {
        reply(try? saveFullConfigTransactionLocked(config: config).encoded())
    }

    private func saveFullConfigTransactionLocked(
        config: [String: Any]
    ) -> FullConfigSaveResponse {
        Self.performFullConfigTransaction(
            fullConfig: config,
            writeFile: { try self.writeFullConfigAtomically($0) },
            applyZonesAndOverrides: applyOverridesAndZonesToModule(from:),
            reloadBlocklist: {
                ResolverModule.shared.reloadBlocklist()
            }
        )
    }

    static func performFullConfigTransaction(
        fullConfig: [String: Any],
        writeFile: ([String: Any]) throws -> Void,
        applyZonesAndOverrides: ([String: Any]) -> Bool,
        reloadBlocklist: () -> Bool
    ) -> FullConfigSaveResponse {
        do {
            try writeFile(fullConfig)
        } catch {
            return FullConfigSaveResponse(status: .rejected)
        }
        guard applyZonesAndOverrides(fullConfig) else {
            return FullConfigSaveResponse(status: .rejected)
        }
        guard reloadBlocklist() else {
            return FullConfigSaveResponse(status: .rejected)
        }
        return FullConfigSaveResponse(status: .committed)
    }

    private func writeFullConfigAtomically(_ config: [String: Any]) throws {
        _ = config
    }
}
