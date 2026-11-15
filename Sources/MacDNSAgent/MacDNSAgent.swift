// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

class MacDNSAgent: NSObject, MacDNSXPCProtocol, NetworkMonitorDelegate,
    CaptivePortalDetectorDelegate, SystemWakeMonitorDelegate
{
    static let shared = MacDNSAgent()

    private let stateFilePath = PathResolver.stateFile.path

    /// Computed once at startup.
    private let binaryHash: String? = BinaryHasher.currentExecutableHash()

    private var scheduledUpdateTask: Task<Void, Never>?

    // Guards the flags that keep startServices() and stopAllServices() from
    // overlapping.
    private let lifecycleLock = NSLock()
    private var isStartingServices = false
    private var isStoppingServices = false
    private var isRestoringServices = false
    private var captivePortalBypassEnabled = false
    private var isInForwardingMode = false
    /// User-granted authorization to bypass interception, bound to one network
    /// identity and one short window. A captive-portal probe result can never
    /// create or extend it.
    private var captiveFullBypassApproval: CaptivePortalFullBypassApproval?
    private var lifecycleTransitionWaiters: [DispatchSemaphore] = []
    private let configSaveQueue = DispatchQueue(label: "app.macdns.agent.config-save", qos: .userInitiated)
    /// Lookup-history reads and the clear (which waits up to 5 s for the
    /// resolver's writer) run here so they never hold the XPC thread.
    private let historyQueue = DispatchQueue(label: "app.macdns.agent.history", qos: .userInitiated)
    /// One-shot deadline for the granted approval. Nothing else observes the
    /// window. `CaptivePortalDetector` only reports confirmed outcome changes, so a
    /// portal that keeps confirming `.captive` never triggers another
    /// authorization check.
    private var captiveApprovalExpiryTimer: DispatchSourceTimer?
    /// Serializes captive portal and forwarding mode transitions, so delegate
    /// callbacks, network change handlers and recovery tests run in order
    /// without overlap. reloadConfig blocks up to 30 s.
    private let captivePortalQueue = DispatchQueue(label: "app.macdns.agent.captive", qos: .userInitiated)
    /// Incremented on every stopAllServices() entry. startServices() captures
    /// it at entry and aborts if it changes, which catches a stop that started
    /// AND finished between checkpoints.
    private var stopGeneration: UInt64 = 0
    private var lifecycleGeneration: UInt64 = 0
    private var forwardingTransitionGeneration: UInt64 = 0
    private var acceptsNetworkCallbacks = false
    private var isPreparingCaptiveResolver = false
    private var captiveResolverPreparationGeneration: UInt64?
    private var captiveResolverPreparationFailures = 0
    /// Non-blocking bridge for the license XPC handlers. XPC serializes calls to
    /// an exported object, so a blocking license handler stalls every other
    /// request on the same connection.
    private let licenseDispatch = LicenseXPCDispatch.live

    override init() {
        super.init()

        bootstrapRequiredFiles()

        // Register the allowlist LMDB path before any XPC or Preferences
        // consumer calls into AllowlistManager. The Rust side lazy-opens the
        // env on first use, so the allowlist works while the resolver is
        // stopped as long as the path was captured up front.
        if !ResolverModule.shared.setAllowlistPath(PathResolver.allowlistDB) {
            AgentLogger.shared.error(
                "resolver: setAllowlistPath failed for \(PathResolver.allowlistDB.path) — allowlist FFI disabled, UI will show empty list"
            )
        }
        Self.configureHistoryAtLaunch(
            config: loadFullConfig(),
            configure: ResolverModule.shared.configureHistory
        )

        NetworkMonitor.shared.delegate = self
        CaptivePortalDetector.shared.delegate = self
        SystemWakeMonitor.shared.delegate = self

        LicenseManager.shared.onStatusChange = { [weak self] _, allowed in
            guard let self else { return }
            defer { self.notifyLicenseStatusChanged() }

            let action = LicenseStatusChangePolicy.action(
                allowed: allowed,
                isRestoringServices: self.lifecycleLock.withLock {
                    self.isRestoringServices
                },
                resolverRunning: ResolverModule.shared.isRunning()
            )
            switch action {
            case .restoreServices:
                Task {
                    await self.restoreServicesIfEnabled()
                }
            case .stopServices:
                self.stopAllServices()
            case .none:
                break
            }
        }

        UpdateChecker.shared.onUpdateAvailable = { [weak self] in
            self?.notifyUpdateAvailable()
        }

        scheduledUpdateTask = Task {
            AgentLogger.shared.info("Scheduled update checks deferred until network-ready")
            await UpdateChecker.runScheduledChecks()
        }

        // When services do not start at boot (isEnabled=false, license
        // failure, resolver start failure) the captive-portal probe never
        // runs, so this timeout is the only release path. 30 s also covers
        // Content Filter activation when services do start, so firing the
        // fallback there is harmless.
        Task { await NetworkReadySignal.shared.armTimeoutFallback(seconds: 30) }

        MaintenanceManager.shared.start()
    }

    private func bootstrapRequiredFiles() {
        let fileManager = FileManager.default

        do {
            try PathResolver.ensureDirectoriesExist()
        } catch {
            AgentLogger.shared.error("Failed to create required directories: \(error)")
        }

        do {
            try StateFileLock.withExclusiveLock(
                stateFile: PathResolver.stateFile
            ) {
                let stateDirectory = PathResolver.stateFile
                    .deletingLastPathComponent()
                let load = StateFileLock.loadUnlocked(
                    stateFile: PathResolver.stateFile
                )
                let decision = PersistedStateRecoveryPolicy.decision(
                    for: load,
                    existingNames: Set(
                        (try? fileManager.contentsOfDirectory(
                            atPath: stateDirectory.path
                        )) ?? []
                    ),
                    stateFileName: PathResolver.stateFile.lastPathComponent
                )
                switch decision {
                case .useExisting:
                    break
                case .createDefaults:
                    try writeFullConfigAtomically(FullConfigNormalizationPolicy.defaults())
                    AgentLogger.shared.info("Created default state.json")
                case .quarantineThenCreateDefaults(let quarantineName, let reason):
                    try fileManager.moveItem(
                        at: PathResolver.stateFile,
                        to: stateDirectory.appendingPathComponent(quarantineName)
                    )
                    try writeFullConfigAtomically(FullConfigNormalizationPolicy.defaults())
                    AgentLogger.shared.error(
                        "Quarantined unusable state.json as \(quarantineName) (\(reason)) and recreated defaults"
                    )
                case .refuseIncompatible(let version):
                    AgentLogger.shared.error(
                        "Keeping state.json untouched: schema v\(version) was written by a newer MacDNS (this build supports v\(ConfigSchemaPolicy.currentVersion))"
                    )
                case .refuseUnreadable(let reason):
                    AgentLogger.shared.error(
                        "Refusing to replace unreadable state.json: \(reason)"
                    )
                }
            }
        } catch {
            AgentLogger.shared.error("Failed to bootstrap state.json: \(error)")
        }

        // Adopt any pre-transaction blocklist_settings.json into state.json and
        // re-emit the projection the Rust scheduler reads.
        StateFileBlocklistSettingsStore.shared.bootstrapSettings()
    }

    // MARK: - MacDNSXPCProtocol

    func startResolver(withReply reply: @escaping (Bool) -> Void) {
        licenseDispatch.ensureValidLicense { [weak self] allowed in
            guard let self else {
                reply(false)
                return
            }
            guard allowed else {
                AgentLogger.shared.debug("Cannot start: license not valid")
                reply(false)
                return
            }
            reply(self.startServices(skipLicenseCheck: true))
        }
    }

    /// A missing value counts as `true`, the default loadResolverOptions uses
    /// for `dnssecEnabled`.
    private func resolverKnobDiffers(
        old: [String: Any], new: [String: Any], key: String
    ) -> Bool {
        (old[key] as? Bool ?? true) != (new[key] as? Bool ?? true)
    }

    private func resolverArrayKnobDiffers(
        old: [String: Any], new: [String: Any], key: String
    ) -> Bool {
        (old[key] as? [String] ?? []) != (new[key] as? [String] ?? [])
    }

    /// Missing or unknown state.json keys fall back to defaults matching
    /// hickory-dns behavior.
    private func loadResolverOptions(from config: [String: Any]? = nil) -> ResolverModule.ResolverOptions {
        Self.resolverOptions(from: config ?? loadFullConfig())
    }

    static func resolverOptions(from cfg: [String: Any]) -> ResolverModule.ResolverOptions {
        let providers = DoHProviderID.canonicalized(
            cfg["dohProviders"] as? [String] ?? DoHProviderID.defaultProviders.map(\.rawValue)
        )
        let mode = (cfg["dohDispatchMode"] as? String).flatMap(DoHDispatchMode.init(rawValue:)) ?? .defaultMode
        return ResolverModule.ResolverOptions(
            dnssec: cfg["dnssecEnabled"] as? Bool ?? true,
            logQueries: cfg["logQueriesEnabled"] as? Bool ?? false,
            logReplies: cfg["logRepliesEnabled"] as? Bool ?? false,
            prefetch: cfg["prefetchEnabled"] as? Bool ?? true,
            serveExpired: cfg["serveExpiredEnabled"] as? Bool ?? true,
            dohProviders: providers,
            dohDispatchMode: mode,
            dnsAnswerRefinementEnabled: cfg["dnsAnswerRefinementEnabled"] as? Bool ?? true
        )
    }

    /// Lookup history works while the resolver is stopped, so the agent
    /// configures it once at launch, like the allowlist path. A persisted value
    /// outside the allowed set is never adjusted: history stays off (the
    /// resolver's default) and neither the agent nor protection is blocked.
    @discardableResult
    static func configureHistoryAtLaunch(
        config: [String: Any],
        configure: (QueryHistorySettings) -> Bool
    ) -> Bool {
        let settings: QueryHistorySettings
        do {
            settings = try QueryHistorySettings(config: config)
        } catch {
            AgentLogger.shared.error("Lookup history stays off: \(error.localizedDescription)")
            return false
        }
        guard configure(settings) else {
            AgentLogger.shared.error("Lookup history stays off: the resolver rejected its settings")
            return false
        }
        return true
    }

    /// The history settings a save must apply, or nil when the four keys are
    /// unchanged. `new` is already validated. An invalid persisted value
    /// counts as a change, because history stayed off at launch.
    static func historySettingsChange(
        old: [String: Any],
        new: [String: Any]
    ) -> QueryHistorySettings? {
        guard let pending = try? QueryHistorySettings(config: new) else { return nil }
        return (try? QueryHistorySettings(config: old)) == pending ? nil : pending
    }

    /// Replay current state.json overrides and forward zones into the Rust
    /// module. Called on start and whenever the module is running and state
    /// changes.
    private func applyOverridesAndZonesToModule(from config: [String: Any]? = nil) -> Bool {
        let candidate = config ?? loadFullConfig()
        guard
            let validated = DNSPolicyStructuralPolicy.validateAndNormalize(
                candidate
            )
        else {
            AgentLogger.shared.error(
                "resolver: malformed overrides/zones candidate rejected"
            )
            return false
        }

        let zones = validated.customZones
            .filter { $0.enabled }
            .map { ["domain": $0.domain, "forwardIP": $0.forwardIP] }

        let overrides = validated.dnsOverrides
            .filter { $0.enabled }
            .map { ["domain": $0.domain, "qtype": $0.qtype, "value": $0.value] }

        // Published as one unit: a rejected record leaves the previous policy
        // fully active instead of a half-applied mix.
        let result = ResolverModule.shared.applyPolicySnapshot(
            overrides: overrides,
            forwardZones: zones
        )
        if let rejection = result.rejection {
            AgentLogger.shared.error(
                "resolver: policy snapshot rejected — previous overrides and zones retained: \(rejection)"
            )
            return false
        }
        return true
    }

    /// Starts the resolver, network monitor and captive portal detector, then
    /// publishes resolver readiness and sends reconciliation wake-up hints.
    /// - Parameter skipLicenseCheck: Set by the async caller that already
    ///   validated the license.
    private func startServices(
        skipLicenseCheck: Bool = false,
        expectedLifecycleGeneration: UInt64? = nil,
        expectedStopGeneration: UInt64? = nil,
        keepProxyBypass: Bool = false
    ) -> Bool {
        var generationAtEntry: UInt64 = 0
        var reconcileRunningResolver = false

        while true {
            lifecycleLock.lock()
            let lifecycleChanged =
                expectedLifecycleGeneration.map {
                    lifecycleGeneration != $0
                } ?? false
            let stopChanged =
                expectedStopGeneration.map {
                    stopGeneration != $0
                } ?? false
            if lifecycleChanged || stopChanged {
                lifecycleLock.unlock()
                AgentLogger.shared.info(
                    "Service start cancelled by a concurrent lifecycle request"
                )
                return false
            }

            if isStartingServices || isStoppingServices {
                let waiter = DispatchSemaphore(value: 0)
                lifecycleTransitionWaiters.append(waiter)
                lifecycleLock.unlock()
                AgentLogger.shared.debug("Waiting for in-progress service transition")
                waiter.wait()
                continue
            }

            let resolverRunning = ResolverModule.shared.isRunning()
            if resolverRunning {
                guard
                    AgentLifecycleGenerationPolicy.shouldReconcileRunningResolver(
                        resolverRunning: true,
                        acceptingCallbacks: acceptsNetworkCallbacks
                    )
                else {
                    // Published under the lock, so a stop that follows always clears it.
                    LicenseManager.shared.setServicesRunning(true)
                    lifecycleLock.unlock()
                    return true
                }
                reconcileRunningResolver = true
            }

            isStartingServices = true
            lifecycleGeneration &+= 1
            acceptsNetworkCallbacks = false
            generationAtEntry = stopGeneration
            lifecycleLock.unlock()
            break
        }

        defer {
            finishLifecycleTransition { isStartingServices = false }
        }

        // Reads the cached admission. It never blocks on the license actor or
        // creates a trial.
        if !skipLicenseCheck {
            guard LicenseManager.shared.cachedServiceAllowed() else {
                AgentLogger.shared.debug("Cannot start: license not valid")
                stopAllServices(
                    preserveApprovedCaptiveBypass: keepProxyBypass
                )
                return false
            }
        }

        guard let startupConfig = loadFullConfigForMutation() else {
            AgentLogger.shared.error(
                "Cannot start: state.json is invalid or unreadable"
            )
            stopAllServices(
                preserveApprovedCaptiveBypass: keepProxyBypass
            )
            return false
        }

        if let rejection = Self.fullConfigAdmissionRejection(for: startupConfig) {
            AgentLogger.shared.error(
                "Cannot start: persisted DNS policy is invalid — \(rejection)"
            )
            stopAllServices(
                preserveApprovedCaptiveBypass: keepProxyBypass
            )
            return false
        }

        if reconcileRunningResolver {
            guard ResolverModule.shared.disableForwarding() else {
                AgentLogger.shared.error(
                    "Cannot reconcile running resolver after failed stop"
                )
                stopAllServices(
                    preserveApprovedCaptiveBypass: keepProxyBypass
                )
                return false
            }
        } else {
            do {
                try ResolverModule.shared.start(
                    port: 5335,
                    options: loadResolverOptions(from: startupConfig)
                )
            } catch {
                AgentLogger.shared.error("Error starting resolver module: \(error)")
                stopAllServices(
                    preserveApprovedCaptiveBypass: keepProxyBypass
                )
                return false
            }
        }
        if !ResolverModule.shared.configureBlocklist(settingsPath: PathResolver.blocklistSettings.path) {
            AgentLogger.shared.error(
                "resolver: configureBlocklist failed — LMDB reload skipped, agent will serve queries without category-level filtering"
            )
            stopAllServices(
                preserveApprovedCaptiveBypass: keepProxyBypass
            )
            return false
        }

        // The boot blocklist refresh downloads over reqwest. Starting before
        // the NetworkExtension stack settles kills connections mid-flight and
        // stalls them on a 60 s timeout, so the scheduler waits behind the same
        // gate as the update check.
        Task {
            await NetworkReadyWorkGate.shared.run {
                if !ResolverModule.shared.startBlocklistScheduler() {
                    AgentLogger.shared.error(
                        "resolver: startBlocklistScheduler failed — periodic blocklist refresh is NOT running")
                }
            }
        }

        guard applyOverridesAndZonesToModule(from: startupConfig) else {
            AgentLogger.shared.error("resolver: overrides/zones rejected during start")
            stopAllServices(
                preserveApprovedCaptiveBypass: keepProxyBypass
            )
            return false
        }

        republishEphemeralRoutes()
        republishNetworkProfile()

        lifecycleLock.lock()
        guard stopGeneration == generationAtEntry else {
            lifecycleLock.unlock()
            AgentLogger.shared.info("Stop occurred during start — aborting")
            stopAllServices(
                preserveApprovedCaptiveBypass: keepProxyBypass
            )
            return false
        }
        let callbackLifecycleGeneration = lifecycleGeneration
        guard
            NetworkMonitor.shared.start(
                callbackLifecycleGeneration: callbackLifecycleGeneration
            )
        else {
            lifecycleLock.unlock()
            AgentLogger.shared.error("Cannot start network monitor")
            stopAllServices(
                preserveApprovedCaptiveBypass: keepProxyBypass
            )
            return false
        }
        SystemWakeMonitor.shared.start(
            callbackLifecycleGeneration: callbackLifecycleGeneration
        )
        lifecycleLock.unlock()

        guard
            applyProxyReadinessActions(
                ProxyReadinessLifecyclePolicy.startActions(
                    keepProxyBypass: keepProxyBypass
                )
            )
        else {
            AgentLogger.shared.error(
                "Resolver readiness publication failed — stopping services"
            )
            stopAllServices(
                preserveApprovedCaptiveBypass: keepProxyBypass
            )
            return false
        }

        // `dns_init` cleared any prior control key. Install a fresh session now,
        // even under keepProxyBypass so the key is present when bypass lifts,
        // whether the XPC link is new or still alive from a previous start.
        ProxyControlClient.shared.ensureSessionInstalled()

        guard
            lifecycleLock.withLock({ () -> Bool in
                guard stopGeneration == generationAtEntry else { return false }
                guard lifecycleGeneration == callbackLifecycleGeneration else { return false }
                guard !isStoppingServices else { return false }
                acceptsNetworkCallbacks = true
                // Published under the lock, so a stop that follows always clears it.
                LicenseManager.shared.setServicesRunning(true)
                return true
            })
        else {
            AgentLogger.shared.info("Stop occurred during start — cleaning up")
            stopAllServices(
                preserveApprovedCaptiveBypass: keepProxyBypass
            )
            return false
        }

        if NetworkMonitor.shared.isConnected {
            enqueueCaptivePortalRecheck(
                trigger: .serviceStart,
                callbackLifecycleGeneration: callbackLifecycleGeneration
            )
        }

        return true
    }

    /// Stops all MacDNS services (resolver, network monitor, captive portal).
    /// Publishes bypass readiness and sends reconciliation wake-up hints.
    ///
    /// Returns `true` only when the resolver is confirmed stopped. A concurrent
    /// stop caller waits for the in-flight stop to finish and then reports the
    /// resolver's actual state, instead of grading a teardown still in progress.
    @discardableResult
    private func stopAllServices(
        force: Bool = false,
        preserveApprovedCaptiveBypass: Bool = false
    ) -> Bool {
        // XPC and SIGTERM can both call this at the same time.
        lifecycleLock.lock()
        LicenseManager.shared.setServicesRunning(false)
        stopGeneration &+= 1
        acceptsNetworkCallbacks = false
        guard !isStoppingServices else {
            lifecycleLock.unlock()
            let resolverStopped = awaitInFlightStop()
            guard !preserveApprovedCaptiveBypass else {
                return resolverStopped
            }
            return stopAllServices(force: force)
        }
        let preserveCaptiveState =
            preserveApprovedCaptiveBypass
            && captivePortalBypassEnabled
            && captiveFullBypassApproval != nil
        isStoppingServices = true
        if !preserveCaptiveState {
            captivePortalBypassEnabled = false
            captiveFullBypassApproval = nil
        }
        isInForwardingMode = false
        lifecycleGeneration &+= 1
        forwardingTransitionGeneration &+= 1
        lifecycleLock.unlock()

        if !preserveCaptiveState {
            stopCaptiveApprovalExpiryTimer()
        }
        SystemWakeMonitor.shared.stop()
        CaptivePortalDetector.shared.invalidateForNetworkTransition()

        defer {
            finishLifecycleTransition { isStoppingServices = false }
        }

        // Request bypass and wake the Extension before resolver teardown.
        _ = applyProxyReadinessActions(
            ProxyReadinessLifecyclePolicy.stopActions
        )

        ProxyControlClient.shared.disconnect()

        var resolverStopped = true
        if ResolverModule.shared.isRunning() {
            resolverStopped = ResolverModule.shared.stop(force: force)
        }
        if !resolverStopped, ResolverModule.shared.isRunning() {
            // The resolver still serves queries, so periodic validation must keep running.
            lifecycleLock.withLock { _ = LicenseManager.shared.setServicesRunning(true) }
        }
        NetworkMonitor.shared.stop()
        if preserveCaptiveState {
            lifecycleLock.lock()
            let callbackLifecycleGeneration = lifecycleGeneration
            let monitoringRestored = NetworkMonitor.shared.start(
                callbackLifecycleGeneration: callbackLifecycleGeneration
            )
            if monitoringRestored {
                SystemWakeMonitor.shared.start(
                    callbackLifecycleGeneration: callbackLifecycleGeneration
                )
                acceptsNetworkCallbacks = true
            }
            lifecycleLock.unlock()
            if !monitoringRestored {
                AgentLogger.shared.error(
                    "Approved captive bypass remains active without network monitoring"
                )
            }
        }
        return resolverStopped
    }

    /// Blocks until the stop already in flight completes, then reports whether
    /// the resolver is stopped. Bounded so a wedged teardown degrades to the
    /// observed state instead of hanging the caller's XPC reply.
    private func awaitInFlightStop() -> Bool {
        ConcurrentStopSequencer.awaitInFlightStop(
            enqueueWaiter: { () -> DispatchSemaphore? in
                lifecycleLock.withLock {
                    guard isStoppingServices else { return nil }
                    let waiter = DispatchSemaphore(value: 0)
                    lifecycleTransitionWaiters.append(waiter)
                    return waiter
                }
            },
            wait: { waiter in
                guard
                    waiter.wait(
                        timeout: .now() + Self.inFlightStopWaitSeconds
                    ) == .success
                else {
                    AgentLogger.shared.warning(
                        "Timed out waiting for an in-flight stop; reporting the observed resolver state"
                    )
                    return false
                }
                return true
            },
            resolverStopped: { !ResolverModule.shared.isRunning() }
        )
    }

    private static let inFlightStopWaitSeconds: Double = 15
    private static let maxCaptiveResolverPreparationFailures = 5

    private func finishLifecycleTransition(_ updateFlag: () -> Void) {
        lifecycleLock.lock()
        updateFlag()
        let waiters = lifecycleTransitionWaiters
        lifecycleTransitionWaiters.removeAll()
        lifecycleLock.unlock()

        waiters.forEach { $0.signal() }
    }

    /// Graceful shutdown for the SIGTERM and SIGINT handlers. Also stops
    /// MaintenanceManager.
    func shutdownServices() {
        scheduledUpdateTask?.cancel()
        stopAllServices()
        MaintenanceManager.shared.stop()
    }

    @discardableResult
    private func applyProxyReadinessActions(
        _ actions: [ProxyReadinessAction]
    ) -> Bool {
        var succeeded = true
        for action in actions {
            switch action {
            case .setBypassRequested(let requested):
                if !ResolverModule.shared.setProxyBypassRequested(requested) {
                    succeeded = false
                    AgentLogger.shared.error(
                        "Resolver rejected proxy bypass readiness=\(requested)"
                    )
                }
            case .notifyProxyEnable:
                notifyProxyEnable()
            case .notifyProxyDisable:
                notifyProxyDisable()
            case .wakeBypassProbe:
                if ResolverModule.shared.isRunning() {
                    if actions.contains(.setBypassRequested(true)) {
                        notifyBypassEnable()
                    } else {
                        notifyBypassDisable()
                    }
                } else {
                    notifyBypassEnable()
                }
            }
        }
        return succeeded
    }

    /// Wakes the App to reconcile authenticated runtime state while the resolver is running.
    private func notifyProxyEnable() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(DarwinNotifications.proxyEnable),
            nil,
            nil,
            true
        )
        AgentLogger.shared.debug("Sent proxy enable notification")
    }

    /// Wakes the App to reconcile authenticated runtime state while the resolver is stopping or stopped.
    func notifyProxyDisable() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(DarwinNotifications.proxyDisable),
            nil,
            nil,
            true
        )
        AgentLogger.shared.debug("Sent proxy disable notification")
    }

    private func notifyLicenseStatusChanged() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(DarwinNotifications.licenseStatusChanged),
            nil,
            nil,
            true
        )
        AgentLogger.shared.debug("Sent license status changed notification")
    }

    /// Wakes the Extension to re-evaluate authenticated resolver bypass readiness.
    private func notifyBypassEnable() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(DarwinNotifications.bypassEnable),
            nil,
            nil,
            true
        )
        AgentLogger.shared.debug("Sent bypass enable notification")
    }

    /// Wakes the Extension to re-evaluate authenticated resolver bypass readiness.
    private func notifyBypassDisable() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(DarwinNotifications.bypassDisable),
            nil,
            nil,
            true
        )
        AgentLogger.shared.debug("Sent bypass disable notification")
    }

    private func notifyUpdateAvailable() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(DarwinNotifications.updateAvailable),
            nil,
            nil,
            true
        )
        AgentLogger.shared.debug("Sent update available notification")
    }

    /// Replies `true` only when the resolver is confirmed stopped. The reply
    /// reports resolver teardown. The DNS Proxy extension has no
    /// acknowledgement channel and is never implied by this result.
    func stopResolver(withReply reply: @escaping (Bool) -> Void) {
        reply(stopAllServices(force: false))
    }

    func stopResolverForce(force: Bool, withReply reply: @escaping (Bool) -> Void) {
        reply(stopAllServices(force: force))
    }

    func isServicesRunning(withReply reply: @escaping (Bool) -> Void) {
        reply(ResolverModule.shared.isRunning())
    }

    func getRuntimeState(withReply reply: @escaping (Data?) -> Void) {
        let base = lifecycleLock.withLock { () -> (Bool, Bool, Bool, UInt64, Bool) in
            let transitionInProgress = isStartingServices || isStoppingServices
            let running = ResolverModule.shared.isRunning()
            return (
                running, captivePortalBypassEnabled, isInForwardingMode,
                lifecycleGeneration, transitionInProgress
            )
        }
        // Short timeout so getRuntimeState never hangs. A missing or malformed
        // report is nil, which the App shows as "unknown".
        let report = ProxyControlClient.shared.currentProviderStateReport(timeout: 0.5)
        let snapshot = AgentRuntimeStateSnapshot(
            servicesRunning: base.0,
            captivePortalDetected: base.1,
            forwarding: base.2,
            lifecycleGeneration: base.3,
            transitionInProgress: base.4,
            proxyInterceptionState: report?.state,
            proxyInterceptionReason: report?.reason,
            proxyProviderVersion: report?.providerVersion,
            proxyControlUnreachable: ProxyControlClient.shared.persistentOutageActive,
            resolverStats: ResolverModule.shared.statsSnapshot()
        )
        reply(try? JSONCoding.encoder.encode(snapshot))
    }

    // MARK: - Binary Hash Management

    func getAgentBinaryHash(withReply reply: @escaping (String?) -> Void) {
        reply(binaryHash)
    }

    // MARK: - Full Configuration Management

    func getFullConfig(withReply reply: @escaping ([String: Any]?) -> Void) {
        configSaveQueue.async { [weak self] in
            // Blocklist settings travel over their own XPC calls and are owned
            // by the agent. Like `schemaVersion` they stay out of the payload
            // the App compares and echoes back.
            reply(
                self?.loadFullConfigForMutation().map(
                    BlocklistSettingsTransactionPolicy.configWithoutSettings
                )
            )
        }
    }

    func readFullConfig(withReply reply: @escaping (Data?) -> Void) {
        configSaveQueue.async { [weak self] in
            guard let self else {
                reply(nil)
                return
            }
            let response = Self.fullConfigReadResponse(
                for: self.loadRawFullConfig()
            )
            if response.status != .loaded {
                AgentLogger.shared.error(
                    "Configuration not served to the App: \(response.status.rawValue)"
                )
            }
            reply(try? response.encoded())
        }
    }

    /// Classifies a `state.json` read the way `loadFullConfigForMutation` does
    /// and serves the same payload as `getFullConfig`.
    static func fullConfigReadResponse(
        for load: StateFileLoadResult
    ) -> FullConfigReadResponse {
        let config: [String: Any]
        switch load {
        case .missing:
            config = FullConfigNormalizationPolicy.defaults()
        case .valid(let state):
            if case .incompatible = ConfigSchemaPolicy.compatibility(of: state) {
                return FullConfigReadResponse(status: .incompatibleSchema)
            }
            guard
                let normalized = FullConfigNormalizationPolicy.normalized(state)
            else {
                return FullConfigReadResponse(status: .invalid)
            }
            config = normalized
        case .invalid:
            return FullConfigReadResponse(status: .invalid)
        case .ioFailure:
            return FullConfigReadResponse(status: .ioFailure)
        }
        return FullConfigReadResponse.loaded(
            BlocklistSettingsTransactionPolicy.configWithoutSettings(config)
        ) ?? FullConfigReadResponse(status: .invalid)
    }

    func saveFullConfig(config: [String: Any], withReply reply: @escaping (Data?) -> Void) {
        configSaveQueue.async { [weak self] in
            guard let self = self else {
                reply(
                    try? FullConfigSaveResponse(
                        status: .rejected,
                        rejectionReason: .persistenceFailure
                    ).encoded()
                )
                return
            }
            reply(try? self.saveFullConfigTransaction(config: config).encoded())
        }
    }

    private func saveFullConfigTransaction(
        config: [String: Any]
    ) -> FullConfigSaveResponse {
        do {
            return try StateFileLock.withExclusiveLock(
                stateFile: PathResolver.stateFile
            ) {
                saveFullConfigTransactionLocked(config: config)
            }
        } catch {
            AgentLogger.shared.error(
                "Configuration save rejected: state lock failed: \(error)"
            )
            return FullConfigSaveResponse(
                status: .rejected,
                rejectionReason: .persistenceFailure
            )
        }
    }

    /// Write-path admission checks a mutation must clear before it is
    /// classified against the persisted revision.
    ///
    /// A payload `JSONSerialization` cannot encode raises an Objective-C
    /// `NSInvalidArgumentException` inside `writeFullConfigAtomically` that no
    /// Swift `catch` can intercept, killing the agent with SIGABRT. A policy the
    /// resolver would refuse commits permanently while the resolver is stopped,
    /// because the runtime apply that would have rejected it is skipped.
    static func fullConfigAdmissionRejection(for config: [String: Any]) -> String? {
        guard FullConfigPayloadPolicy.isValidPayload(config) else {
            return "payload is not JSON-serializable"
        }
        guard
            let validated = DNSPolicyStructuralPolicy.validateAndNormalize(config)
        else {
            return "malformed customZones or dnsOverrides"
        }
        return DNSPolicySemanticPolicy.rejection(
            zones: validated.customZones,
            overrides: validated.dnsOverrides
        )?.reason
    }

    /// Checks that need the merged document: a payload that sends only some of
    /// the history keys is judged together with the persisted ones.
    static func normalizedConfigRejection(for fullConfig: [String: Any]) -> String? {
        do {
            _ = try QueryHistorySettings(config: fullConfig)
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    private func saveFullConfigTransactionLocked(
        config: [String: Any]
    ) -> FullConfigSaveResponse {
        if let reason = Self.fullConfigAdmissionRejection(for: config) {
            AgentLogger.shared.warning("Configuration save rejected: \(reason)")
            return rejected(.invalidConfiguration)
        }
        guard let oldConfig = loadFullConfigForMutation() else {
            AgentLogger.shared.error(
                "Configuration save rejected: state.json is invalid or unreadable"
            )
            return rejected(.persistenceFailure)
        }
        guard
            let fullConfig = FullConfigNormalizationPolicy.normalized(
                // The agent owns the persisted blocklist fragment. A client
                // payload can never carry it into the transaction.
                BlocklistSettingsTransactionPolicy.configWithoutSettings(config),
                mergedWith: oldConfig
            )
        else {
            AgentLogger.shared.warning(
                "Configuration save rejected: malformed overrides/zones"
            )
            return rejected(.invalidConfiguration)
        }
        guard hasValidAllowlist(fullConfig) else {
            AgentLogger.shared.warning("Configuration save rejected: malformed allowlist")
            return rejected(.invalidConfiguration)
        }
        if let reason = Self.normalizedConfigRejection(for: fullConfig) {
            AgentLogger.shared.warning("Configuration save rejected: \(reason)")
            return rejected(.invalidConfiguration)
        }
        let classification: ConfigSaveRequestClassification
        do {
            classification = try AgentConfigRevisionPolicy.classify(
                incoming: fullConfig,
                persisted: oldConfig
            )
        } catch {
            AgentLogger.shared.error("Configuration save rejected: invalid canonical payload")
            return rejected(.invalidConfiguration, config: oldConfig)
        }

        let persistedRevision = ConfigRevisionPolicy.revision(from: oldConfig)
        return Self.performFullConfigTransaction(
            classification: classification,
            persistedRevision: persistedRevision,
            oldConfig: oldConfig,
            fullConfig: fullConfig,
            prepareAccepted: { acceptedConfig in
                self.prepareFullConfigTransaction(
                    oldConfig: oldConfig,
                    fullConfig: acceptedConfig
                )
            },
            writeFile: { acceptedConfig in
                do {
                    try self.writeFullConfigAtomically(acceptedConfig)
                } catch {
                    AgentLogger.shared.error(
                        "Error saving/applying full configuration: \(error)"
                    )
                    throw error
                }
            },
            syncAllowlist: syncAllowlistStrict(from:),
            applyZonesAndOverrides: applyOverridesAndZonesToModule(from:),
            reloadBlocklist: {
                let reloaded = ResolverModule.shared.reloadBlocklist()
                if !reloaded {
                    AgentLogger.shared.error(
                        "resolver: reloadBlocklist failed after full configuration save"
                    )
                }
                return reloaded
            }
        )
    }

    enum AcceptedFullConfigOptionsResult {
        case applied
        case response(FullConfigSaveResponse)
    }

    struct FullConfigTransactionContext {
        let resolverRunning: Bool
        let backendBounceRequired: Bool
        let applyOptions: () -> AcceptedFullConfigOptionsResult
        let performBackendBounce: (_ rollback: () -> Bool) -> Bool
        /// Runs last, after every step that can fail, because the rollback
        /// does not reapply the previous history settings.
        let applyHistory: () -> Bool
        let rollback: ([String: Any]) -> Bool
        let didCommit: () -> Void
    }

    enum FullConfigTransactionPreparation {
        case ready(FullConfigTransactionContext)
        case response(FullConfigSaveResponse)
    }

    static func performFullConfigTransaction(
        classification: ConfigSaveRequestClassification,
        persistedRevision: ConfigRevision,
        oldConfig: [String: Any],
        fullConfig: [String: Any],
        prepareAccepted: ([String: Any]) -> FullConfigTransactionPreparation,
        writeFile: ([String: Any]) throws -> Void,
        syncAllowlist: ([String: Any]) -> Bool,
        applyZonesAndOverrides: ([String: Any]) -> Bool,
        reloadBlocklist: () -> Bool
    ) -> FullConfigSaveResponse {
        let transactionRevision: ConfigRevision
        var acceptedConfig = fullConfig
        switch classification {
        case .idempotentSuccess:
            return FullConfigSaveResponse(
                status: .alreadyCommitted,
                authoritativeRevision: persistedRevision
            )
        case .conflict:
            AgentLogger.shared.warning(
                "Configuration save rejected: expected revision \(ConfigRevisionPolicy.revision(from: fullConfig)), current \(persistedRevision)"
            )
            return FullConfigSaveResponse(
                status: .conflict,
                authoritativeRevision: persistedRevision
            )
        case .accept(let nextRevision):
            transactionRevision = nextRevision
            acceptedConfig["configRevision"] = nextRevision
        }

        let context: FullConfigTransactionContext
        switch prepareAccepted(acceptedConfig) {
        case .ready(let preparedContext):
            context = preparedContext
        case .response(let response):
            return response
        }

        do {
            try writeFile(acceptedConfig)
        } catch {
            let authoritativeRevision: ConfigRevision?
            if let restorationFailure = error as? StateDocumentWriter.RestorationFailure {
                authoritativeRevision = restorationFailure.persistedRevision
            } else {
                authoritativeRevision = persistedRevision
            }
            return FullConfigSaveResponse(
                status: .rejected,
                authoritativeRevision: authoritativeRevision,
                rejectionReason: .persistenceFailure
            )
        }

        let rollbackConfig = AgentConfigRevisionPolicy.rollbackConfig(
            restoring: oldConfig,
            consumedRevision: transactionRevision
        )
        var rollbackResult: Bool?

        func rollbackOnce() -> Bool {
            if let rollbackResult {
                return rollbackResult
            }
            let result = context.rollback(rollbackConfig)
            rollbackResult = result
            return result
        }

        func rejected(
            _ reason: FullConfigSaveResponse.RejectionReason
        ) -> FullConfigSaveResponse {
            _ = rollbackOnce()
            return FullConfigSaveResponse(
                status: .rejected,
                authoritativeRevision: transactionRevision,
                rejectionReason: reason
            )
        }

        if context.resolverRunning && !context.backendBounceRequired {
            switch context.applyOptions() {
            case .applied:
                break
            case .response(let response):
                _ = rollbackOnce()
                return FullConfigSaveResponse(
                    status: response.status,
                    authoritativeRevision: transactionRevision,
                    rejectionReason: response.rejectionReason
                )
            }
        }

        guard syncAllowlist(acceptedConfig) else {
            return rejected(.runtimeApplyFailure)
        }

        if context.backendBounceRequired {
            guard context.performBackendBounce(rollbackOnce) else {
                return rejected(.runtimeApplyFailure)
            }
        } else if context.resolverRunning {
            guard applyZonesAndOverrides(acceptedConfig) else {
                return rejected(.runtimeApplyFailure)
            }
            guard reloadBlocklist() else {
                return rejected(.runtimeApplyFailure)
            }
        }

        guard context.applyHistory() else {
            return rejected(.runtimeApplyFailure)
        }

        if !context.backendBounceRequired {
            context.didCommit()
        }
        return FullConfigSaveResponse(
            status: .committed,
            authoritativeRevision: transactionRevision
        )
    }

    private func prepareFullConfigTransaction(
        oldConfig: [String: Any],
        fullConfig: [String: Any]
    ) -> FullConfigTransactionPreparation {
        let lifecycleSnapshot = lifecycleLock.withLock {
            (
                generation: lifecycleGeneration,
                stopGeneration: stopGeneration,
                transitionInProgress: isStartingServices || isStoppingServices,
                resolverRunning: ResolverModule.shared.isRunning()
            )
        }
        guard !lifecycleSnapshot.transitionInProgress else {
            AgentLogger.shared.warning("Configuration save rejected: lifecycle transition in progress")
            return .response(busy(config: oldConfig))
        }

        let oldOptions = loadResolverOptions(from: oldConfig)
        let pendingOptions = loadResolverOptions(from: fullConfig)
        let historyChange = Self.historySettingsChange(old: oldConfig, new: fullConfig)
        let providerKnobChanged =
            resolverKnobDiffers(old: oldConfig, new: fullConfig, key: "dnssecEnabled")
            || resolverArrayKnobDiffers(old: oldConfig, new: fullConfig, key: "dohProviders")

        guard ResolverModule.shared.canApplyResolverOptions(pendingOptions) else {
            AgentLogger.shared.error("Configuration save rejected: resolver dylib cannot apply requested options")
            return .response(rejected(.invalidConfiguration, config: oldConfig))
        }

        guard
            lifecycleLock.withLock({
                AgentLifecycleGenerationPolicy.matches(
                    lifecycleGeneration: lifecycleGeneration,
                    stopGeneration: stopGeneration,
                    expectedLifecycleGeneration: lifecycleSnapshot.generation,
                    expectedStopGeneration: lifecycleSnapshot.stopGeneration
                )
            })
        else {
            AgentLogger.shared.warning("Configuration save rejected: lifecycle changed before apply")
            return .response(busy(config: oldConfig))
        }

        return .ready(
            FullConfigTransactionContext(
                resolverRunning: lifecycleSnapshot.resolverRunning,
                backendBounceRequired: lifecycleSnapshot.resolverRunning && providerKnobChanged,
                applyOptions: {
                    guard ResolverModule.shared.updateResolverOptions(pendingOptions) else {
                        AgentLogger.shared.error(
                            "Configuration save rejected: live resolver option apply failed"
                        )
                        return .response(self.rejected(.runtimeApplyFailure, config: oldConfig))
                    }
                    guard
                        self.lifecycleLock.withLock({
                            self.lifecycleGeneration == lifecycleSnapshot.generation
                                && self.stopGeneration == lifecycleSnapshot.stopGeneration
                        })
                    else {
                        AgentLogger.shared.warning(
                            "Configuration save rejected: lifecycle changed after live apply"
                        )
                        if ResolverModule.shared.isRunning() {
                            _ = ResolverModule.shared.updateResolverOptions(oldOptions)
                        }
                        return .response(self.busy(config: oldConfig))
                    }
                    return .applied
                },
                performBackendBounce: { rollback in
                    self.saveFullConfigWithBounce(
                        expectedLifecycleGeneration: lifecycleSnapshot.generation,
                        expectedStopGeneration: lifecycleSnapshot.stopGeneration,
                        rollback: rollback
                    )
                },
                applyHistory: {
                    guard let historyChange else { return true }
                    guard ResolverModule.shared.configureHistory(historyChange) else {
                        AgentLogger.shared.error(
                            "Configuration save rejected: lookup history settings apply failed"
                        )
                        return false
                    }
                    return true
                },
                rollback: { rollbackConfig in
                    self.rollbackFullConfig(
                        rollbackConfig: rollbackConfig,
                        oldOptions: oldOptions
                    )
                },
                didCommit: {
                    if !self.lifecycleLock.withLock({
                        self.lifecycleGeneration == lifecycleSnapshot.generation
                            && self.stopGeneration == lifecycleSnapshot.stopGeneration
                    }) {
                        AgentLogger.shared.warning(
                            "Configuration save accepted on disk; lifecycle changed before reply"
                        )
                    }
                }
            )
        )
    }

    /// Retryable contention. The payload was rolled back, so the returned
    /// revision is the one the client must rebase onto.
    private func busy(config: [String: Any]) -> FullConfigSaveResponse {
        FullConfigSaveResponse(
            status: .lifecycleBusy,
            authoritativeRevision: ConfigRevisionPolicy.revision(from: config)
        )
    }

    private func rejected(
        _ reason: FullConfigSaveResponse.RejectionReason,
        config: [String: Any]? = nil
    ) -> FullConfigSaveResponse {
        FullConfigSaveResponse(
            status: .rejected,
            authoritativeRevision: config.map {
                ConfigRevisionPolicy.revision(from: $0)
            },
            rejectionReason: reason
        )
    }

    private func saveFullConfigWithBounce(
        expectedLifecycleGeneration: UInt64,
        expectedStopGeneration: UInt64,
        rollback: () -> Bool
    ) -> Bool {
        guard
            lifecycleLock.withLock({
                AgentLifecycleGenerationPolicy.matches(
                    lifecycleGeneration: lifecycleGeneration,
                    stopGeneration: stopGeneration,
                    expectedLifecycleGeneration: expectedLifecycleGeneration,
                    expectedStopGeneration: expectedStopGeneration
                )
            })
        else {
            AgentLogger.shared.error("Backend bounce aborted: lifecycle changed before stop — rolling back")
            _ = rollback()
            return false
        }

        AgentLogger.shared.info("Backend bounce required (DNSSEC/provider policy changed)")
        stopAllServices()
        guard !ResolverModule.shared.isRunning() else {
            AgentLogger.shared.error("Backend bounce failed: resolver did not stop")
            _ = rollback()
            return false
        }
        let generationsAfterStop = lifecycleLock.withLock {
            (
                lifecycle: lifecycleGeneration,
                stop: stopGeneration
            )
        }
        guard
            generationsAfterStop.lifecycle == expectedLifecycleGeneration &+ 1,
            generationsAfterStop.stop == expectedStopGeneration &+ 1
        else {
            AgentLogger.shared.error(
                "Backend bounce cancelled by a concurrent stop request"
            )
            _ = rollback()
            return false
        }

        guard
            startServices(
                skipLicenseCheck: true,
                expectedLifecycleGeneration: generationsAfterStop.lifecycle,
                expectedStopGeneration: generationsAfterStop.stop
            )
        else {
            AgentLogger.shared.error("Backend bounce restart failed; attempting restored config restart")
            attemptRollbackRestart(
                rollback: rollback,
                expectedLifecycleGeneration: generationsAfterStop.lifecycle &+ 2,
                expectedStopGeneration: generationsAfterStop.stop &+ 1
            )
            return false
        }
        let generationsAfterStart = lifecycleLock.withLock {
            (
                lifecycle: lifecycleGeneration,
                stop: stopGeneration
            )
        }
        guard generationsAfterStart.stop == generationsAfterStop.stop else {
            AgentLogger.shared.error(
                "Backend bounce restart cancelled by a concurrent stop request"
            )
            _ = rollback()
            stopAllServices()
            return false
        }
        guard generationsAfterStart.lifecycle == generationsAfterStop.lifecycle &+ 1 else {
            AgentLogger.shared.error(
                "Backend bounce restart cancelled by a concurrent lifecycle request"
            )
            _ = rollback()
            stopAllServices()
            return false
        }

        guard ResolverModule.shared.reloadBlocklist() else {
            AgentLogger.shared.error("Backend bounce failed: blocklist reload rejected after restart")
            attemptRollbackRestart(
                rollback: rollback,
                expectedLifecycleGeneration: generationsAfterStart.lifecycle,
                expectedStopGeneration: generationsAfterStart.stop
            )
            return false
        }

        return true
    }

    @discardableResult
    private func rollbackFullConfig(
        rollbackConfig: [String: Any],
        oldOptions: ResolverModule.ResolverOptions
    ) -> Bool {
        var fullyRestored = true
        do {
            try writeFullConfigAtomically(rollbackConfig)
        } catch {
            AgentLogger.shared.error("Rollback failed writing state.json: \(error)")
            fullyRestored = false
        }
        if ResolverModule.shared.isRunning() {
            if !ResolverModule.shared.updateResolverOptions(oldOptions) {
                AgentLogger.shared.error("Rollback failed restoring resolver options")
                fullyRestored = false
            }
            if !applyOverridesAndZonesToModule(from: rollbackConfig) {
                AgentLogger.shared.error("Rollback failed restoring overrides/zones")
                fullyRestored = false
            }
            if !ResolverModule.shared.reloadBlocklist() {
                AgentLogger.shared.error("Rollback failed reloading blocklist")
                fullyRestored = false
            }
        }
        if !syncAllowlistStrict(from: rollbackConfig) {
            AgentLogger.shared.error("Rollback failed restoring allowlist LMDB")
            fullyRestored = false
        }
        if !fullyRestored {
            AgentLogger.shared.error(
                "Rollback incomplete; stopping DNS to avoid divergent policy"
            )
        }
        switch IncompleteRollbackRecoveryPolicy.recover(
            fullyRestored: fullyRestored,
            stopServices: { self.stopAllServices() },
            forceStopServices: { self.stopAllServices(force: true) },
            failClosedBypass: { self.requestFailClosedBypass() }
        ) {
        case .restored, .stopped:
            break
        case .forcedStop:
            AgentLogger.shared.error(
                "Rollback teardown was not confirmed; interception bypassed and DNS force-stopped"
            )
        case .bypassed:
            AgentLogger.shared.error(
                "Rollback teardown could not be confirmed even forced; interception stays bypassed"
            )
        }
        return fullyRestored
    }

    /// Stops interception without waiting for teardown: the provider leaves
    /// every flow to the system resolver instead of answering from policy the
    /// agent can no longer describe.
    private func requestFailClosedBypass() {
        if !applyProxyReadinessActions(
            ProxyReadinessLifecyclePolicy.captivePortalBypassActions
        ) {
            AgentLogger.shared.error("Resolver rejected the fail-closed bypass request")
        }
    }

    private func attemptRollbackRestart(
        rollback: () -> Bool,
        expectedLifecycleGeneration: UInt64,
        expectedStopGeneration: UInt64
    ) {
        guard
            lifecycleLock.withLock({
                AgentLifecycleGenerationPolicy.matches(
                    lifecycleGeneration: lifecycleGeneration,
                    stopGeneration: stopGeneration,
                    expectedLifecycleGeneration: expectedLifecycleGeneration,
                    expectedStopGeneration: expectedStopGeneration
                )
            })
        else {
            AgentLogger.shared.error(
                "DNS remains stopped: rollback restart cancelled by a concurrent lifecycle request"
            )
            _ = rollback()
            stopAllServices()
            return
        }

        stopAllServices()
        let stoppedLifecycleGeneration = expectedLifecycleGeneration &+ 1
        let rollbackStopGeneration = expectedStopGeneration &+ 1
        guard
            lifecycleLock.withLock({
                AgentLifecycleGenerationPolicy.matches(
                    lifecycleGeneration: lifecycleGeneration,
                    stopGeneration: stopGeneration,
                    expectedLifecycleGeneration: stoppedLifecycleGeneration,
                    expectedStopGeneration: rollbackStopGeneration
                )
            })
        else {
            AgentLogger.shared.error(
                "DNS remains stopped: rollback restart cancelled while stopping"
            )
            _ = rollback()
            return
        }

        let persistedRestored = rollback()
        guard persistedRestored else {
            AgentLogger.shared.error(
                "DNS remains stopped: rollback failed restoring state.json or allowlist LMDB; refusing to restart with divergent persisted state"
            )
            return
        }
        guard
            lifecycleLock.withLock({
                AgentLifecycleGenerationPolicy.matches(
                    lifecycleGeneration: lifecycleGeneration,
                    stopGeneration: stopGeneration,
                    expectedLifecycleGeneration: stoppedLifecycleGeneration,
                    expectedStopGeneration: rollbackStopGeneration
                )
            })
        else {
            AgentLogger.shared.error(
                "DNS remains stopped: rollback restart cancelled before start"
            )
            return
        }
        guard
            startServices(
                skipLicenseCheck: true,
                expectedLifecycleGeneration: stoppedLifecycleGeneration,
                expectedStopGeneration: rollbackStopGeneration
            )
        else {
            AgentLogger.shared.error("DNS remains stopped: rollback restart failed after bounce error")
            return
        }
        guard
            lifecycleLock.withLock({
                AgentLifecycleGenerationPolicy.matches(
                    lifecycleGeneration: lifecycleGeneration,
                    stopGeneration: stopGeneration,
                    expectedLifecycleGeneration: stoppedLifecycleGeneration &+ 1,
                    expectedStopGeneration: rollbackStopGeneration
                )
            })
        else {
            AgentLogger.shared.error(
                "DNS remains stopped: concurrent lifecycle request interrupted rollback restart"
            )
            stopAllServices()
            return
        }
    }

    private func hasValidAllowlist(_ config: [String: Any]) -> Bool {
        if case .valid = AgentAllowlistConfigPolicy.classify(config) {
            return true
        }
        return false
    }

    private func parsedAllowlist(
        from config: [String: Any]
    ) -> [AllowedDomain]? {
        guard
            case .valid(_, let domains) =
                AgentAllowlistConfigPolicy.classify(config)
        else {
            return nil
        }
        return domains
    }

    private func syncAllowlistStrict(from config: [String: Any]) -> Bool {
        guard let allowedDomains = parsedAllowlist(from: config) else {
            return false
        }
        return AllowlistManager.shared.syncToLMDBStrict(domains: allowedDomains).success
    }

    private func writeFullConfigAtomically(_ config: [String: Any]) throws {
        guard
            let validated = DNSPolicyStructuralPolicy.validateAndNormalize(
                config
            )
        else {
            throw NSError(
                domain: "MacDNSAgent.Configuration",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "malformed customZones or dnsOverrides"
                ]
            )
        }
        try StateFileLock.withExclusiveLock(
            stateFile: PathResolver.stateFile
        ) {
            var persisted = ConfigSchemaPolicy.stamped(validated.normalizedConfig)
            persisted["timestamp"] = Date().timeIntervalSinceReferenceDate
            let stateDir = (stateFilePath as NSString).deletingLastPathComponent
            try FileManager.default.createDirectory(
                atPath: stateDir,
                withIntermediateDirectories: true,
                attributes: nil
            )
            try StateDocumentWriter.write(
                persisted,
                to: PathResolver.stateFile,
                refreshProjection: StateFileBlocklistSettingsStore.shared
                    .refreshProjection(from:)
            )
        }
    }

    // MARK: - State Management

    private func loadFullConfig() -> [String: Any] {
        switch loadRawFullConfig() {
        case .missing:
            AgentLogger.shared.warning(
                "state.json missing at \(stateFilePath), using defaults"
            )
            return FullConfigNormalizationPolicy.defaults()
        case .valid(let state):
            if case .incompatible(let version) = ConfigSchemaPolicy.compatibility(of: state) {
                AgentLogger.shared.error(
                    "state.json at \(stateFilePath) uses schema v\(version), newer than the supported v\(ConfigSchemaPolicy.currentVersion): using defaults without touching the file"
                )
                return FullConfigNormalizationPolicy.defaults()
            }
            guard let normalized = FullConfigNormalizationPolicy.normalized(state) else {
                AgentLogger.shared.error(
                    "Invalid state.json at \(stateFilePath): malformed overrides/zones"
                )
                return FullConfigNormalizationPolicy.defaults()
            }
            return normalized
        case .invalid(let reason):
            AgentLogger.shared.error(
                "Invalid state.json at \(stateFilePath): \(reason)"
            )
            return FullConfigNormalizationPolicy.defaults()
        case .ioFailure(let reason):
            AgentLogger.shared.error(
                "Failed to load state.json at \(stateFilePath): \(reason)"
            )
            return FullConfigNormalizationPolicy.defaults()
        }
    }

    private func loadFullConfigForMutation() -> [String: Any]? {
        switch loadRawFullConfig() {
        case .missing:
            return FullConfigNormalizationPolicy.defaults()
        case .valid(let state):
            if case .incompatible(let version) = ConfigSchemaPolicy.compatibility(of: state) {
                AgentLogger.shared.error(
                    "Refusing to modify state.json: schema v\(version) was written by a newer MacDNS (this build supports v\(ConfigSchemaPolicy.currentVersion))"
                )
                return nil
            }
            return FullConfigNormalizationPolicy.normalized(state)
        case .invalid, .ioFailure:
            return nil
        }
    }

    private func loadRawFullConfig() -> StateFileLoadResult {
        StateFileLock.load(stateFile: PathResolver.stateFile)
    }

    /// Copies the allowlist persisted in state.json into LMDB at launch, so the
    /// resolver's list matches the source of truth.
    func syncAllowlistToLMDB() {
        configSaveQueue.sync {
            syncAllowlistToLMDBTransaction()
        }
    }

    private func syncAllowlistToLMDBTransaction() {
        do {
            try StateFileLock.withExclusiveLock(
                stateFile: PathResolver.stateFile
            ) {
                syncAllowlistToLMDBLocked()
            }
        } catch {
            AgentLogger.shared.error(
                "Allowlist sync refused: state lock failed: \(error)"
            )
        }
    }

    private func syncAllowlistToLMDBLocked() {
        let rawConfig: [String: Any]
        switch loadRawFullConfig() {
        case .missing:
            rawConfig = [:]
        case .valid(let persisted):
            rawConfig = persisted
        case .invalid(let reason):
            AgentLogger.shared.error(
                "Allowlist sync refused: invalid state.json: \(reason)"
            )
            return
        case .ioFailure(let reason):
            AgentLogger.shared.error(
                "Allowlist sync refused: unreadable state.json: \(reason)"
            )
            return
        }
        guard let fullConfig = FullConfigNormalizationPolicy.normalized(rawConfig) else {
            AgentLogger.shared.error(
                "Allowlist sync refused: malformed overrides/zones"
            )
            return
        }
        guard hasValidAllowlist(fullConfig) else {
            AgentLogger.shared.error(
                "Allowlist sync refused: persisted allowlist is malformed"
            )
            return
        }
        if !syncAllowlistStrict(from: fullConfig) {
            AgentLogger.shared.error("Failed to sync persisted allowlist to LMDB")
        }
    }

    /// Restores services if MacDNS was enabled before the agent restarted. Async
    /// so the license check never blocks the main thread.
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

        let (capturedLifecycle, capturedStop) = lifecycleLock.withLock {
            (lifecycleGeneration, stopGeneration)
        }

        guard loadFullConfig()["isEnabled"] as? Bool ?? false else {
            return
        }

        AgentLogger.shared.info("Restoring MacDNS services (isEnabled=true)...")

        // The license check releases every lifecycle lock, so a concurrent stop
        // or user disable must invalidate this restore.
        guard await LicenseManager.shared.ensureValidLicense() else {
            AgentLogger.shared.debug("Cannot restore: license not valid")
            stopAllServices()
            return
        }

        let stillEnabled = loadFullConfig()["isEnabled"] as? Bool ?? false
        let (currentLifecycle, currentStop, transitionInProgress) = lifecycleLock.withLock {
            (lifecycleGeneration, stopGeneration, isStartingServices || isStoppingServices)
        }

        guard
            AgentLifecycleGenerationPolicy.canRestoreAfterLicenseCheck(
                isEnabledAfterLicenseCheck: stillEnabled,
                currentLifecycleGeneration: currentLifecycle,
                currentStopGeneration: currentStop,
                capturedLifecycleGeneration: capturedLifecycle,
                capturedStopGeneration: capturedStop,
                transitionInProgress: transitionInProgress
            )
        else {
            AgentLogger.shared.info(
                "Service restore cancelled by a concurrent lifecycle request"
            )
            return
        }

        _ = startServices(
            skipLicenseCheck: true,
            expectedLifecycleGeneration: currentLifecycle,
            expectedStopGeneration: currentStop
        )
    }

    // MARK: - NetworkMonitorDelegate

    func networkStatusChanged(
        isConnected: Bool,
        callbackLifecycleGeneration: UInt64
    ) {
        AgentLogger.shared.notice("Network status changed: connected=\(isConnected)")

        // Capture the intent before enqueuing. If stopAllServices() runs before
        // the block executes, the generation changes and the block aborts.
        guard
            let intent = lifecycleLock.withLock({ () -> ForwardingTransitionIntent? in
                guard
                    let intent = captureForwardingIntentLocked(
                        callbackLifecycleGeneration: callbackLifecycleGeneration
                    )
                else {
                    return nil
                }
                captiveResolverPreparationGeneration = nil
                captiveResolverPreparationFailures = 0
                return intent
            })
        else {
            return
        }

        // reloadConfig blocks up to 30 s, so it must stay off main, and it must
        // finish before a new probe starts or forwarding config goes stale.
        captivePortalQueue.async { [weak self] in
            guard let self = self else { return }
            CaptivePortalDetector.shared.invalidateForNetworkTransition()
            guard let transition = self.forwardingSnapshot(ifCurrent: intent) else { return }

            var sequenceIntent = intent
            if transition.forwardingEnabled {
                guard
                    let disabledTransition = self.disableForwardingMode(
                        expectedIntent: intent
                    )
                else {
                    AgentLogger.shared.warning(
                        "Forwarding disable failed during network change"
                    )
                    self.enterForwardingFailSafe(
                        expectedIntent: intent,
                        forwardingEnabled: true
                    )
                    return
                }
                sequenceIntent = disabledTransition.intent
                AgentLogger.shared.notice("Forwarding mode disabled due to network change")
            }

            guard self.forwardingIntentIsCurrent(sequenceIntent) else { return }
        }

        enqueueCaptiveApprovalReconciliation()
    }

    func networkConfigurationChanged(
        isConnected: Bool,
        callbackLifecycleGeneration: UInt64
    ) {
        guard
            let intent = lifecycleLock.withLock({ () -> ForwardingTransitionIntent? in
                guard
                    let intent = captureForwardingIntentLocked(
                        callbackLifecycleGeneration: callbackLifecycleGeneration
                    )
                else {
                    return nil
                }
                captiveResolverPreparationGeneration = nil
                captiveResolverPreparationFailures = 0
                return intent
            })
        else {
            return
        }
        captivePortalQueue.async { [weak self] in
            guard let self else { return }
            NetworkConfigurationChangeOrchestrator.apply(
                isCurrent: { self.forwardingIntentIsCurrent(intent) },
                invalidateDetector: {
                    CaptivePortalDetector.shared.invalidateForNetworkTransition()
                },
                publishEphemeralRoutes: {
                    self.republishEphemeralRoutes()
                },
                rebuildNetworkInfrastructure: {
                    AgentLogger.shared.info("Network configuration changed, flushing infra cache")
                    ResolverModule.shared.notifyNetworkChange()
                },
                publishNetworkProfile: {
                    self.republishNetworkProfile()
                },
                forwardingActive: {
                    self.lifecycleLock.withLock { self.isInForwardingMode }
                },
                refreshForwardingTargets: {
                    self.refreshForwardingTargets(expectedIntent: intent)
                },
                isConnected: isConnected,
                recheckConnectivity: {
                    CaptivePortalDetector.shared.forceRecheck(
                        trigger: .networkConfiguration,
                        callbackLifecycleGeneration: callbackLifecycleGeneration
                    )
                }
            )
        }

        enqueueCaptiveApprovalReconciliation()
    }

    /// Replaces the routes implied by the attached network's search domains.
    ///
    /// The table is runtime-derived: it never reaches `state.json` and is
    /// replaced as a whole on every network change, so the routes a network
    /// handed out disappear as soon as the host leaves it.
    private func republishEphemeralRoutes() {
        let routes = NetworkMonitor.currentSearchDomainRoutes().routes
        guard ResolverModule.shared.applyEphemeralRoutes(routes) else { return }
        if !routes.isEmpty {
            // These are candidates, not installed routes. The resolver keeps
            // only private-use suffixes and logs each domain it rejects, so
            // claiming publication here would contradict it one line later.
            // `applyEphemeralRoutes` reports that the table was replaced, not
            // how much of it survived. Do not reword this into an outcome.
            AgentLogger.shared.info(
                "Submitted discovered search-domain route candidates to resolver: "
                    + "\(routes.map(\.domain))"
            )
        }
    }

    /// Hands the resolver the attached network's facts so it re-derives the
    /// network profile. Called on start, on every configuration change, and on
    /// wake, because a sleep can span a move to another network before configd
    /// reports the change.
    private func republishNetworkProfile() {
        let snapshot = NetworkMonitor.currentProfileSnapshot()
        if !ResolverModule.shared.applyNetworkSnapshot(snapshot) {
            AgentLogger.shared.warning("resolver: network snapshot rejected; NAT64 synthesis stays off")
        }
    }

    // MARK: - CaptivePortalDetectorDelegate

    func captiveConnectivityOutcomeConfirmed(
        from oldOutcome: CaptiveConnectivityOutcome?,
        to newOutcome: CaptiveConnectivityOutcome,
        callbackLifecycleGeneration: UInt64
    ) {
        guard
            let intent = lifecycleLock.withLock({
                captureForwardingIntentLocked(
                    callbackLifecycleGeneration: callbackLifecycleGeneration
                )
            })
        else {
            return
        }

        // The handlers call reloadConfig and startServices, which block up to
        // 30 s. The serial queue keeps transitions in order without overlap.
        captivePortalQueue.async { [weak self] in
            guard let self = self else { return }
            guard self.forwardingIntentIsCurrent(intent) else { return }

            switch newOutcome {
            case .captive:
                self.handleCaptivePortalSuspected(expectedIntent: intent)

            case .healthy:
                let state = self.lifecycleLock.withLock {
                    (self.captivePortalBypassEnabled, self.isInForwardingMode)
                }
                if state.0 {
                    self.handleCaptivePortalResolved(intent: intent)
                } else if state.1 {
                    self.completeVerifiedDirectDoHRecovery(
                        expectedIntent: intent
                    )
                }
                Task {
                    await NetworkReadySignal.shared.markReady(
                        reason: "direct-doh-healthy"
                    )
                }

            case .compatibilityRequired(let portalCleared):
                self.handleNetworkCompatibilityRequired(
                    expectedIntent: intent,
                    portalCleared: portalCleared
                )
            }
        }
    }

    // MARK: - Captive Portal Logic

    private func enqueueCaptivePortalRecheck(
        trigger: CaptivePortalRecheckTrigger,
        callbackLifecycleGeneration: UInt64
    ) {
        captivePortalQueue.async { [weak self] in
            guard let self else { return }
            let isCurrent = self.lifecycleLock.withLock {
                self.acceptsNetworkCallbacks
                    && !self.isStoppingServices
                    && self.lifecycleGeneration
                        == callbackLifecycleGeneration
            }
            guard isCurrent, NetworkMonitor.shared.isConnected else { return }
            CaptivePortalDetector.shared.forceRecheck(
                trigger: trigger,
                callbackLifecycleGeneration: callbackLifecycleGeneration
            )
        }
    }

    func systemDidWake(callbackLifecycleGeneration: UInt64) {
        captivePortalQueue.async { [weak self] in
            guard let self else { return }
            let isCurrent = self.lifecycleLock.withLock {
                self.acceptsNetworkCallbacks
                    && !self.isStoppingServices
                    && self.lifecycleGeneration == callbackLifecycleGeneration
            }
            guard isCurrent else { return }
            self.republishNetworkProfile()
        }
        enqueueCaptivePortalRecheck(
            trigger: .wake,
            callbackLifecycleGeneration: callbackLifecycleGeneration
        )
    }

    func captivePortalResolverPreparationRequested(
        probeGeneration: UInt64,
        callbackLifecycleGeneration: UInt64
    ) {
        captivePortalQueue.async { [weak self] in
            self?.prepareResolverForCaptiveProbe(
                probeGeneration: probeGeneration,
                callbackLifecycleGeneration: callbackLifecycleGeneration
            )
        }
    }

    private func prepareResolverForCaptiveProbe(
        probeGeneration: UInt64,
        callbackLifecycleGeneration: UInt64
    ) {
        guard NetworkMonitor.shared.isConnected else { return }
        guard captiveFullBypassIsAuthorized() else {
            reconcileCaptiveFullBypassAuthorization()
            return
        }

        guard
            let expectedStopGeneration = lifecycleLock.withLock({ () -> UInt64? in
                guard acceptsNetworkCallbacks else { return nil }
                guard !isStoppingServices else { return nil }
                guard lifecycleGeneration == callbackLifecycleGeneration else { return nil }
                guard captivePortalBypassEnabled else { return nil }
                guard !isPreparingCaptiveResolver else { return nil }
                guard captiveResolverPreparationGeneration != probeGeneration else { return nil }
                isPreparingCaptiveResolver = true
                captiveResolverPreparationGeneration = probeGeneration
                return stopGeneration
            })
        else {
            return
        }
        defer {
            lifecycleLock.withLock {
                isPreparingCaptiveResolver = false
            }
        }

        if ResolverModule.shared.isRunning() {
            let generation = lifecycleLock.withLock { lifecycleGeneration }
            enqueueCaptivePortalRecheck(
                trigger: .serviceStart,
                callbackLifecycleGeneration: generation
            )
            return
        }

        let restarted = startServices(
            expectedStopGeneration: expectedStopGeneration,
            keepProxyBypass: true
        )
        guard restarted else {
            guard
                let retryLifecycleGeneration = captiveBypassMonitoringGeneration()
            else {
                return
            }
            guard captiveFullBypassIsAuthorized() else {
                reconcileCaptiveFullBypassAuthorization()
                return
            }
            let failureCount = lifecycleLock.withLock { () -> Int in
                captiveResolverPreparationFailures += 1
                return captiveResolverPreparationFailures
            }
            CaptivePortalDetector.shared.scheduleRetryAfterResolverPreparationFailure(
                callbackLifecycleGeneration: retryLifecycleGeneration,
                failureCount: failureCount,
                maxFailures: Self.maxCaptiveResolverPreparationFailures
            )
            return
        }

        lifecycleLock.withLock {
            captiveResolverPreparationFailures = 0
        }
        guard captiveFullBypassIsAuthorized() else {
            reconcileCaptiveFullBypassAuthorization()
            return
        }
        // startServices enqueued the fresh service-start probe after installing
        // the new resolver and HMAC session.
    }

    private func captiveBypassMonitoringGeneration() -> UInt64? {
        lifecycleLock.withLock {
            guard !isStartingServices, !isStoppingServices else { return nil }
            guard acceptsNetworkCallbacks else { return nil }
            guard captivePortalBypassEnabled else { return nil }
            guard captiveFullBypassApproval != nil else { return nil }
            return lifecycleGeneration
        }
    }

    private func captureForwardingIntentLocked(
        callbackLifecycleGeneration: UInt64
    ) -> ForwardingTransitionIntent? {
        guard
            let intent = ForwardingTransitionPolicy.nextIntent(
                currentStopGeneration: stopGeneration,
                currentTransitionGeneration: forwardingTransitionGeneration,
                currentLifecycleGeneration: lifecycleGeneration,
                callbackLifecycleGeneration: callbackLifecycleGeneration,
                acceptingCallbacks: acceptsNetworkCallbacks,
                isStopping: isStoppingServices,
                resolverRunning: ResolverModule.shared.isRunning(),
                captiveBypassEnabled: captivePortalBypassEnabled
            )
        else {
            return nil
        }
        forwardingTransitionGeneration = intent.transitionGeneration
        return intent
    }

    private func beginForwardingTransition(
        ifCurrent intent: ForwardingTransitionIntent
    ) -> ForwardingTransitionSnapshot? {
        let resolverRunning = ResolverModule.shared.isRunning()
        return lifecycleLock.withLock {
            guard
                forwardingIntentIsCurrentLocked(
                    intent,
                    resolverRunning: resolverRunning
                )
            else {
                return nil
            }
            forwardingTransitionGeneration &+= 1
            return forwardingTransitionSnapshotLocked(
                resolverRunning: resolverRunning
            )
        }
    }

    private func forwardingTransitionSnapshotLocked(
        resolverRunning: Bool
    ) -> ForwardingTransitionSnapshot {
        ForwardingTransitionSnapshot(
            stopGeneration: stopGeneration,
            transitionGeneration: forwardingTransitionGeneration,
            resolverRunning: resolverRunning,
            forwardingEnabled: isInForwardingMode
        )
    }

    private func forwardingTransitionSnapshotLocked() -> ForwardingTransitionSnapshot {
        forwardingTransitionSnapshotLocked(
            resolverRunning: ResolverModule.shared.isRunning()
        )
    }

    private func forwardingIntentIsCurrent(
        _ intent: ForwardingTransitionIntent
    ) -> Bool {
        lifecycleLock.withLock {
            forwardingIntentIsCurrentLocked(intent)
        }
    }

    private func forwardingIntentIsCurrentLocked(
        _ intent: ForwardingTransitionIntent
    ) -> Bool {
        forwardingIntentIsCurrentLocked(
            intent,
            resolverRunning: ResolverModule.shared.isRunning()
        )
    }

    private func forwardingIntentIsCurrentLocked(
        _ intent: ForwardingTransitionIntent,
        resolverRunning: Bool
    ) -> Bool {
        ForwardingTransitionPolicy.isCurrentIntent(
            intent,
            currentStopGeneration: stopGeneration,
            currentTransitionGeneration: forwardingTransitionGeneration,
            isStopping: isStoppingServices,
            resolverRunning: resolverRunning,
            captiveBypassEnabled: captivePortalBypassEnabled
        )
    }

    private func forwardingSnapshot(
        ifCurrent intent: ForwardingTransitionIntent
    ) -> ForwardingTransitionSnapshot? {
        lifecycleLock.withLock {
            guard forwardingIntentIsCurrentLocked(intent) else { return nil }
            return forwardingTransitionSnapshotLocked()
        }
    }

    private func forwardingTransitionIsCurrent(
        _ captured: ForwardingTransitionSnapshot
    ) -> Bool {
        let resolverRunning = ResolverModule.shared.isRunning()
        return lifecycleLock.withLock {
            ForwardingTransitionPolicy.mayPublish(
                captured: captured,
                current: forwardingTransitionSnapshotLocked(
                    resolverRunning: resolverRunning
                )
            )
        }
    }

    private func publishForwardingModeIfCurrent(
        _ enabled: Bool,
        captured: ForwardingTransitionSnapshot
    ) -> Bool {
        lifecycleLock.withLock {
            guard
                ForwardingTransitionPolicy.mayPublish(
                    captured: captured,
                    current: forwardingTransitionSnapshotLocked()
                )
            else {
                return false
            }
            isInForwardingMode = enabled
            return true
        }
    }

    private func commitForwardingReadinessIfCurrent(
        captured: ForwardingTransitionSnapshot
    ) -> ForwardingReadinessCommitResult {
        lifecycleLock.withLock {
            ForwardingTransitionOrchestrator.commitReadiness(
                captured: captured,
                current: { forwardingTransitionSnapshotLocked() },
                setReady: {
                    ResolverModule.shared.setProxyBypassRequested(false)
                },
                publish: {
                    let wasBypassing = captivePortalBypassEnabled
                    captivePortalBypassEnabled = false
                    isInForwardingMode = true
                    return wasBypassing
                }
            )
        }
    }

    private func commitCaptivePortalResolvedIfCurrent(
        captured: ForwardingTransitionSnapshot
    ) -> ForwardingReadinessCommitResult {
        lifecycleLock.withLock {
            ForwardingTransitionOrchestrator.commitReadiness(
                captured: captured,
                current: { forwardingTransitionSnapshotLocked() },
                setReady: {
                    ResolverModule.shared.setProxyBypassRequested(false)
                },
                publish: {
                    let wasBypassing = captivePortalBypassEnabled
                    captivePortalBypassEnabled = false
                    return wasBypassing
                }
            )
        }
    }

    private func commitDirectDoHRecoveryStateIfCurrent(
        captured: ForwardingTransitionSnapshot
    ) -> Bool? {
        let resolverRunning = ResolverModule.shared.isRunning()
        return lifecycleLock.withLock {
            guard
                ForwardingTransitionPolicy.mayPublish(
                    captured: captured,
                    current: forwardingTransitionSnapshotLocked(
                        resolverRunning: resolverRunning
                    )
                )
            else {
                return nil
            }
            let wasBypassing = captivePortalBypassEnabled
            captivePortalBypassEnabled = false
            isInForwardingMode = false
            return wasBypassing
        }
    }

    @discardableResult
    private func failSafeAuthorization(
        expectedIntent: ForwardingTransitionIntent,
        fullBypassAuthorized: Bool
    ) -> ForwardingFailSafeAuthorizationPolicy.Action {
        lifecycleLock.withLock {
            failSafeAuthorizationLocked(
                expectedIntent: expectedIntent,
                fullBypassAuthorized: fullBypassAuthorized
            )
        }
    }

    private func failSafeAuthorizationLocked(
        expectedIntent: ForwardingTransitionIntent,
        fullBypassAuthorized: Bool
    ) -> ForwardingFailSafeAuthorizationPolicy.Action {
        ForwardingFailSafeAuthorizationPolicy.action(
            isStopping: isStoppingServices,
            stopGenerationMatches: stopGeneration == expectedIntent.stopGeneration,
            transitionGenerationMatches: forwardingTransitionGeneration
                == expectedIntent.transitionGeneration,
            bypassAlreadyActive: captivePortalBypassEnabled,
            fullBypassAuthorized: fullBypassAuthorized
        )
    }

    /// The commit result is informational: `enterFailSafe` already acts on it,
    /// stopping the resolver when the bypass could not be published, so callers
    /// that only need the fail-safe applied may ignore it.
    @discardableResult
    private func enterForwardingFailSafe(
        expectedIntent: ForwardingTransitionIntent,
        forwardingEnabled: Bool
    ) -> ForwardingFailSafeCommitResult {
        let fullBypassAuthorized = captiveFullBypassIsAuthorized()

        return ForwardingTransitionOrchestrator.enterFailSafe(
            commitBypass: {
                ForwardingTransitionOrchestrator.commitFailSafeBypass(
                    decide: {
                        failSafeAuthorization(
                            expectedIntent: expectedIntent,
                            fullBypassAuthorized: fullBypassAuthorized
                        )
                    },
                    restoreInterception: {
                        restoreInterceptionInsteadOfBypass()
                    },
                    publishBypass: {
                        ResolverModule.shared.setProxyBypassRequested(true)
                    },
                    commit: { bypassPublished in
                        // Re-decided after the publish: the approval may have
                        // lapsed and a newer transition may have restored
                        // interception while it was in flight.
                        let stillAuthorized = captiveFullBypassIsAuthorized()
                        return lifecycleLock.withLock {
                            () -> (ForwardingFailSafeCommitResult, Bool) in
                            guard
                                failSafeAuthorizationLocked(
                                    expectedIntent: expectedIntent,
                                    fullBypassAuthorized: stillAuthorized
                                ) == .claimFullBypass
                            else {
                                // The published bypass belongs to no
                                // transition. Take it back, unless another one
                                // is already running its own.
                                return (
                                    .noLongerNeeded,
                                    bypassPublished && !captivePortalBypassEnabled
                                )
                            }
                            if isInForwardingMode != forwardingEnabled
                                || !captivePortalBypassEnabled
                            {
                                forwardingTransitionGeneration =
                                    ForwardingTransitionPolicy.generationAfterFailSafeStateChange(
                                        expectedGeneration: expectedIntent.transitionGeneration,
                                        currentGeneration: forwardingTransitionGeneration
                                    )
                                isInForwardingMode = forwardingEnabled
                                captivePortalBypassEnabled = true
                            }
                            return (bypassPublished ? .published : .bypassRejected, false)
                        }
                    }
                )
            },
            resolverIsRunning: {
                ResolverModule.shared.isRunning()
            },
            stopResolver: {
                _ = ResolverModule.shared.stop()
            },
            wakeProxy: {
                notifyBypassEnable()
            }
        )
    }

    /// Full bypass releases the DNS Proxy, the blocklist and the Content
    /// Filter. Portal suspicion comes from unauthenticated cleartext HTTP, so
    /// only an approval the user granted for the currently attached network,
    /// inside a window no probe result can extend, may authorize it.
    private func captiveFullBypassIsAuthorized() -> Bool {
        CaptivePortalDecisionPolicy(
            portalSuspected: true,
            networkIdentity: NetworkMonitor.currentNetworkIdentity(),
            approval: lifecycleLock.withLock { captiveFullBypassApproval },
            now: Date()
        ).mode == .approvedFullBypass
    }

    /// Publishes resolver readiness so the DNS Proxy keeps intercepting, in
    /// place of the bypass an unapproved fail-safe would otherwise claim.
    ///
    /// Requesting readiness is the only action available here. Stopping the
    /// resolver hands the provider a bypass by itself, which is exactly the
    /// outcome no probe result may produce.
    private func restoreInterceptionInsteadOfBypass() {
        guard ResolverModule.shared.setProxyBypassRequested(false) else {
            AgentLogger.shared.error(
                "Failed to publish resolver readiness while restoring DNS protection; keeping the reported bypass state"
            )
            return
        }
        let wasBypassing = lifecycleLock.withLock { () -> Bool in
            let wasBypassing = captivePortalBypassEnabled
            captivePortalBypassEnabled = false
            return wasBypassing
        }
        guard wasBypassing else { return }
        notifyBypassDisable()
        notifyCaptivePortalResolved()
        AgentLogger.shared.warning(
            "Captive-portal full bypass ended without an approval; DNS protection restored"
        )
    }

    /// Re-evaluates the granted approval against the live bypass and the
    /// attached network.
    ///
    /// Runs on the approval's deadline and after every network change, because
    /// the detector cannot be relied on to notice either: it only calls the
    /// delegate when the confirmed outcome changes, and an attacker who keeps
    /// answering `.captive` produces no change at all.
    private func reconcileCaptiveFullBypassAuthorization() {
        let networkIdentity = NetworkMonitor.currentNetworkIdentity()
        let (fullBypassActive, approval) = lifecycleLock.withLock {
            (captivePortalBypassEnabled, captiveFullBypassApproval)
        }

        switch CaptivePortalDecisionPolicy.continuation(
            fullBypassActive: fullBypassActive,
            networkIdentity: networkIdentity,
            approval: approval,
            now: Date()
        ) {
        case .none:
            return
        case .keepBypass:
            rearmCaptiveApprovalExpiryTimer(for: approval)
        case .dropApproval:
            guard clearCaptiveFullBypassApproval(approval) else { return }
            AgentLogger.shared.notice(
                "Captive-portal bypass approval dropped: window lapsed or the attached network changed"
            )
        case .revokeBypass:
            // A grant that landed after this pass read the state owns the
            // decision now. Restoring here would revoke it before its own
            // transition runs.
            guard clearCaptiveFullBypassApproval(approval) else { return }
            if approval != nil {
                AgentLogger.shared.warning(
                    "Captive-portal bypass approval is no longer valid; returning to the constrained compatibility mode"
                )
            }
            restoreProtectionAfterApprovalLapsed()
        }
    }

    @discardableResult
    private func clearCaptiveFullBypassApproval(
        _ granted: CaptivePortalFullBypassApproval?
    ) -> Bool {
        let cleared = lifecycleLock.withLock { () -> Bool in
            guard captiveFullBypassApproval == granted else { return false }
            captiveFullBypassApproval = nil
            return true
        }
        guard cleared else { return false }
        stopCaptiveApprovalExpiryTimer()
        return true
    }

    /// Re-arms the one-shot deadline of a bypass this pass decided to keep.
    ///
    /// The timer deadline is monotonic while the window is wall-clock, so a
    /// backward clock jump makes reconciliation keep the bypass after the timer
    /// has already been consumed. Without a fresh deadline nothing else would
    /// ever expire it.
    private func rearmCaptiveApprovalExpiryTimer(
        for approval: CaptivePortalFullBypassApproval?
    ) {
        guard let approval else { return }
        startCaptiveApprovalExpiryTimer(
            firingIn: max(
                approval.expiresAt.timeIntervalSince(Date()),
                Self.captiveApprovalRecheckFloor
            )
        )
    }

    /// Leaves the full bypass and re-enters scoped forwarding, so the DNS
    /// Proxy, the blocklist and the Content Filter are active again while a
    /// portal may still stand in front of the host.
    private func restoreProtectionAfterApprovalLapsed() {
        guard
            let resolutionIntent = lifecycleLock.withLock({
                captureForwardingIntentLocked(
                    callbackLifecycleGeneration: lifecycleGeneration
                )
            })
        else {
            return
        }
        handleCaptivePortalResolved(intent: resolutionIntent)

        guard !lifecycleLock.withLock({ captivePortalBypassEnabled }) else {
            // Restoration failed, through a resolver restart or a stale transition.
            // The approval and its deadline are already gone, so nothing else
            // would try again and the host would stay bypassed indefinitely.
            AgentLogger.shared.error(
                "Failed to restore DNS protection after the bypass approval lapsed; retrying"
            )
            startCaptiveApprovalExpiryTimer(
                firingIn: Self.captiveProtectionRestoreRetryInterval
            )
            return
        }

        guard
            CaptiveApprovalActivationPolicy.needsConstrainedForwarding(
                CaptivePortalDetector.shared.getCurrentStatus()
            )
        else {
            return
        }
        guard
            let constrainedIntent = lifecycleLock.withLock({
                captureForwardingIntentLocked(
                    callbackLifecycleGeneration: lifecycleGeneration
                )
            })
        else {
            return
        }
        handleNetworkCompatibilityRequired(expectedIntent: constrainedIntent)
    }

    /// Enqueues the authorization re-check behind the transition the caller
    /// just scheduled, so it observes the settled state instead of racing it.
    private func enqueueCaptiveApprovalReconciliation() {
        captivePortalQueue.async { [weak self] in
            self?.reconcileCaptiveFullBypassAuthorization()
        }
    }

    /// Lower bound for a re-armed deadline, so a window that rounds to zero
    /// cannot turn reconciliation into a busy loop against itself.
    private static let captiveApprovalRecheckFloor: TimeInterval = 1

    /// Delay before retrying a restoration that did not take.
    private static let captiveProtectionRestoreRetryInterval: TimeInterval = 30

    private func startCaptiveApprovalExpiryTimer(
        firingIn seconds: TimeInterval
    ) {
        let timer = DispatchSource.makeTimerSource(queue: captivePortalQueue)
        timer.schedule(deadline: .now() + max(seconds, 0))
        timer.setEventHandler { [weak self] in
            self?.reconcileCaptiveFullBypassAuthorization()
        }

        lifecycleLock.lock()
        let previous = captiveApprovalExpiryTimer
        captiveApprovalExpiryTimer = timer
        lifecycleLock.unlock()

        previous?.cancel()
        timer.resume()
    }

    private func stopCaptiveApprovalExpiryTimer() {
        lifecycleLock.lock()
        let timer = captiveApprovalExpiryTimer
        captiveApprovalExpiryTimer = nil
        lifecycleLock.unlock()
        timer?.cancel()
    }

    /// Handles a suspected captive portal.
    ///
    /// Without an approval the agent enters the constrained compatibility mode
    /// instead: queries are forwarded to the network's own resolvers while the
    /// DNS Proxy, the blocklist and the Content Filter stay active.
    private func handleCaptivePortalSuspected(
        expectedIntent: ForwardingTransitionIntent
    ) {
        guard captiveFullBypassIsAuthorized() else {
            handleNetworkCompatibilityRequired(expectedIntent: expectedIntent)
            return
        }
        handleCaptivePortalDetected(
            expectedIntent: expectedIntent,
            forwardingEnabled: lifecycleLock.withLock { isInForwardingMode }
        )
    }

    private func handleCaptivePortalDetected(
        expectedIntent: ForwardingTransitionIntent,
        forwardingEnabled: Bool
    ) {
        guard captiveFullBypassIsAuthorized() else {
            AgentLogger.shared.warning(
                "Captive-portal full bypass is not approved for this network; keeping DNS protection active"
            )
            return
        }

        let result = enterForwardingFailSafe(
            expectedIntent: expectedIntent,
            forwardingEnabled: forwardingEnabled
        )
        guard result != .noLongerNeeded else { return }
        if result == .bypassRejected {
            AgentLogger.shared.error(
                "Failed to publish captive-portal bypass readiness; stopping resolver"
            )
        } else {
            AgentLogger.shared.notice("Captive portal bypass enabled")
        }
        notifyCaptivePortalDetected()
    }

    private func handleCaptivePortalResolved(
        intent: ForwardingTransitionIntent
    ) {
        let state = lifecycleLock.withLock { () -> (Bool, Bool)? in
            guard forwardingIntentIsCurrentLocked(intent) else { return nil }
            return (captivePortalBypassEnabled, isInForwardingMode)
        }
        guard let (wasBypassing, wasForwarding) = state else { return }
        guard wasBypassing else { return }

        var sequenceIntent = intent

        if wasForwarding {
            let resolverWasRunning = ResolverModule.shared.isRunning()
            guard
                let disabledTransition = disableForwardingMode(
                    expectedIntent: sequenceIntent
                )
            else {
                if resolverWasRunning {
                    AgentLogger.shared.error(
                        "Failed to disable forwarding after captive portal; keeping bypass enabled"
                    )
                }
                enterForwardingFailSafe(
                    expectedIntent: intent,
                    forwardingEnabled: true
                )
                return
            }
            sequenceIntent = ForwardingTransitionIntent(
                stopGeneration: intent.stopGeneration,
                transitionGeneration: disabledTransition.transitionGeneration
            )
        }

        if !ResolverModule.shared.isRunning() {
            AgentLogger.shared.warning("Local DNS backend not running - restarting via full startServices")
            let restarted = ForwardingTransitionOrchestrator.restartIfCurrent(
                intent: sequenceIntent,
                isCurrent: {
                    forwardingIntentIsCurrent(sequenceIntent)
                },
                restart: { originalStopGeneration in
                    startServices(
                        expectedStopGeneration: originalStopGeneration,
                        keepProxyBypass: true
                    )
                }
            )
            if !restarted {
                AgentLogger.shared.error("Failed to restart services - keeping bypass enabled")
                return
            }
        }

        guard let transition = forwardingSnapshot(ifCurrent: sequenceIntent) else {
            AgentLogger.shared.info("Discarded stale captive-portal resolution")
            enterForwardingFailSafe(
                expectedIntent: intent,
                forwardingEnabled: false
            )
            return
        }
        let result = ForwardingTransitionOrchestrator.finishCaptiveResolution(
            commitReadiness: {
                commitCaptivePortalResolvedIfCurrent(captured: transition)
            },
            enterFailSafe: {
                enterForwardingFailSafe(
                    expectedIntent: intent,
                    forwardingEnabled: false
                )
            },
            wakeReady: {
                notifyBypassDisable()
                notifyCaptivePortalResolved()
            },
            republishNetworkProfile: {
                republishNetworkProfile()
            }
        )
        switch result {
        case .committed:
            AgentLogger.shared.notice(
                "Captive portal bypass disabled - DNS back to local backend"
            )
        case .stale:
            AgentLogger.shared.info("Discarded stale captive-portal resolution")
        case .readinessRejected:
            AgentLogger.shared.error(
                "Failed to publish resolver readiness; keeping captive bypass enabled"
            )
        }
    }

    // MARK: - Network Compatibility Handling

    private func handleNetworkCompatibilityRequired(
        expectedIntent: ForwardingTransitionIntent,
        portalCleared: Bool = false
    ) {
        guard
            let transition = beginForwardingTransition(
                ifCurrent: expectedIntent
            )
        else {
            return
        }

        let compatibilityAction = CompatibilityTransitionPolicy.action(
            forwardingEnabled: transition.forwardingEnabled,
            fullBypassActive: lifecycleLock.withLock {
                captivePortalBypassEnabled
            },
            portalCleared: portalCleared
        )
        switch compatibilityAction {
        case .keepScopedForwarding:
            AgentLogger.shared.info(
                "Direct DoH remains unavailable; keeping scoped network compatibility forwarding"
            )
            return
        case .keepApprovedBypass:
            AgentLogger.shared.info(
                "Portal state remains uncertain; preserving the approved bypass until its deadline"
            )
            reconcileCaptiveFullBypassAuthorization()
            return
        case .restoreScopedForwardingFromBypass:
            switch commitForwardingReadinessIfCurrent(captured: transition) {
            case .committed(let wasBypassing):
                if wasBypassing {
                    notifyBypassDisable()
                    notifyCaptivePortalResolved()
                }
                AgentLogger.shared.notice(
                    "Portal cleared; restored scoped network compatibility forwarding"
                )
            case .stale:
                AgentLogger.shared.debug(
                    "Discarded stale scoped forwarding restoration"
                )
            case .readinessRejected:
                enterForwardingFailSafe(
                    expectedIntent: transition.intent,
                    forwardingEnabled: true
                )
            }
            return
        case .establishScopedForwarding:
            break
        }

        guard transition.resolverRunning else {
            AgentLogger.shared.error(
                "Forwarding enable rejected; keeping bypass enabled"
            )
            handleCaptivePortalDetected(
                expectedIntent: transition.intent,
                forwardingEnabled: false
            )
            return
        }

        let dhcpDNS = NetworkMonitor.getDHCPDNSServers()
        guard !dhcpDNS.isEmpty else {
            // Without DHCP DNS only bypass is left. The extension stops
            // intercepting and the system resolver answers natively.
            AgentLogger.shared.warning("No DHCP DNS servers, falling back to bypass")
            handleCaptivePortalDetected(
                expectedIntent: transition.intent,
                forwardingEnabled: false
            )
            return
        }

        guard forwardingTransitionIsCurrent(transition) else {
            AgentLogger.shared.info("Discarded stale forwarding enable before FFI")
            return
        }
        guard ResolverModule.shared.enableForwarding(servers: dhcpDNS) else {
            AgentLogger.shared.error(
                "Forwarding enable rejected; keeping bypass enabled"
            )
            handleCaptivePortalDetected(
                expectedIntent: transition.intent,
                forwardingEnabled: false
            )
            return
        }

        let wasBypassing: Bool
        switch commitForwardingReadinessIfCurrent(captured: transition) {
        case .committed(let committedWasBypassing):
            wasBypassing = committedWasBypassing
        case .stale:
            enterForwardingFailSafe(
                expectedIntent: transition.intent,
                forwardingEnabled: true
            )
            AgentLogger.shared.info("Discarded stale forwarding enable")
            return
        case .readinessRejected:
            AgentLogger.shared.error(
                "Failed to publish forwarding readiness; falling back to bypass"
            )
            enterForwardingFailSafe(
                expectedIntent: transition.intent,
                forwardingEnabled: true
            )
            return
        }

        if wasBypassing {
            notifyBypassDisable()
            notifyCaptivePortalResolved()
        }

        AgentLogger.shared.notice(
            "Network compatibility mode enabled with DHCP DNS: \(dhcpDNS)"
        )
    }

    @discardableResult
    private func disableForwardingMode(
        expectedIntent: ForwardingTransitionIntent
    ) -> ForwardingTransitionSnapshot? {
        guard
            let transition = beginForwardingTransition(
                ifCurrent: expectedIntent
            )
        else {
            return nil
        }
        guard transition.resolverRunning else {
            let stateCleared = lifecycleLock.withLock { () -> Bool in
                if stopGeneration == transition.stopGeneration,
                    forwardingTransitionGeneration
                        == transition.transitionGeneration
                {
                    isInForwardingMode = false
                    return true
                }
                return false
            }
            return stateCleared ? transition : nil
        }

        let disabled = ForwardingTransitionOrchestrator.disableAndPublish(
            disableForwarding: {
                ResolverModule.shared.disableForwarding()
            },
            publishDisabledState: {
                publishForwardingModeIfCurrent(
                    false,
                    captured: transition
                )
            }
        )
        if !disabled {
            AgentLogger.shared.info("Discarded stale forwarding disable result")
        }
        return disabled ? transition : nil
    }

    private func refreshForwardingTargets(
        expectedIntent: ForwardingTransitionIntent
    ) {
        guard let transition = forwardingSnapshot(ifCurrent: expectedIntent) else { return }
        guard transition.forwardingEnabled, transition.resolverRunning else { return }

        let dhcpDNS = NetworkMonitor.getDHCPDNSServers()
        guard !dhcpDNS.isEmpty else {
            AgentLogger.shared.warning(
                "DHCP DNS refresh returned no targets; keeping the previous forwarding snapshot"
            )
            return
        }

        guard forwardingTransitionIsCurrent(transition) else { return }
        guard ResolverModule.shared.enableForwarding(servers: dhcpDNS) else {
            AgentLogger.shared.warning(
                "DHCP DNS refresh was rejected; keeping the previous forwarding snapshot"
            )
            return
        }
        AgentLogger.shared.debug(
            "Refreshed network compatibility forwarding targets: \(dhcpDNS)"
        )
    }

    private func completeVerifiedDirectDoHRecovery(
        expectedIntent: ForwardingTransitionIntent
    ) {
        guard
            let transition = beginForwardingTransition(
                ifCurrent: expectedIntent
            )
        else {
            return
        }
        guard transition.forwardingEnabled, transition.resolverRunning else { return }

        let completion = ForwardingTransitionOrchestrator.completeDirectDoHRecovery(
            isCurrent: {
                forwardingTransitionIsCurrent(transition)
            },
            disableForwarding: {
                ResolverModule.shared.disableForwarding()
            },
            publishReadiness: {
                ResolverModule.shared.setProxyBypassRequested(false)
            },
            commitDisabledState: {
                commitDirectDoHRecoveryStateIfCurrent(
                    captured: transition
                )
            },
            enterFailSafe: { forwardingEnabled in
                enterForwardingFailSafe(
                    expectedIntent: transition.intent,
                    forwardingEnabled: forwardingEnabled
                )
            },
            republishNetworkProfile: {
                republishNetworkProfile()
            }
        )
        switch completion {
        case .committed(let wasBypassing):
            if wasBypassing {
                notifyBypassDisable()
                notifyCaptivePortalResolved()
            }
            AgentLogger.shared.notice(
                "Direct DoH health restored; network compatibility forwarding disabled"
            )
        case .stale:
            AgentLogger.shared.debug(
                "Discarded stale direct DoH recovery commit"
            )
        case .disableRejected:
            AgentLogger.shared.error(
                "Direct DoH recovery could not confirm forwarding disable"
            )
        case .readinessRejected:
            AgentLogger.shared.error(
                "Direct DoH recovery could not publish resolver readiness"
            )
        }
    }

    private func notifyCaptivePortalDetected() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(DarwinNotifications.captivePortalDetected),
            nil,
            nil,
            true
        )
    }

    private func notifyCaptivePortalResolved() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(DarwinNotifications.captivePortalResolved),
            nil,
            nil,
            true
        )
    }

    // MARK: - XPC Methods for Captive Portal

    func getCaptivePortalStatus(withReply reply: @escaping (String) -> Void) {
        let status = CaptivePortalDetector.shared.getCurrentStatus()

        let statusString: String
        switch status {
        case .normal: statusString = "normal"
        case .captive: statusString = "captive"
        case .dnsIntercepted: statusString = "dnsIntercepted"
        case .unknown: statusString = "unknown"
        }

        let (isBypassing, forwarding) = lifecycleLock.withLock {
            (captivePortalBypassEnabled, isInForwardingMode)
        }
        // Bypass outranks forwarding: the fail-safe can hold both flags, and
        // the App must never read an active full bypass as protected
        // forwarding.
        let modeString: String
        switch CaptivePortalCompatibilityMode.from(
            fullBypassActive: isBypassing,
            forwarding: forwarding
        ) {
        case .approvedFullBypass: modeString = "bypass"
        case .scopedForwarding: modeString = "forwarding"
        case .none: modeString = "normal"
        }

        reply("\(statusString)|\(modeString)")
    }

    func getResolverMode(withReply reply: @escaping (String) -> Void) {
        let isResolverRunning = ResolverModule.shared.isRunning()
        let (isCaptivePortalBypass, forwarding) = lifecycleLock.withLock {
            (captivePortalBypassEnabled, isInForwardingMode)
        }

        let mode: String
        if isCaptivePortalBypass {
            mode = "Bypass (Captive Portal)"
        } else if forwarding {
            mode = "Forwarding (Network Compatibility)"
        } else if isResolverRunning {
            mode = "Normal (via local DNS)"
        } else {
            mode = "Bypass (local DNS stopped)"
        }
        reply(mode)
    }

    func recheckCaptivePortal(withReply reply: @escaping (Bool) -> Void) {
        guard
            let callbackLifecycleGeneration = lifecycleLock.withLock({
                acceptsNetworkCallbacks ? lifecycleGeneration : nil
            })
        else {
            reply(false)
            return
        }
        guard NetworkMonitor.shared.isConnected else {
            reply(false)
            return
        }
        enqueueCaptivePortalRecheck(
            trigger: .manual,
            callbackLifecycleGeneration: callbackLifecycleGeneration
        )
        reply(true)
    }

    /// Records the user's approval for a full bypass on the currently attached
    /// network. The approval only permits the transition. The detector still has
    /// to suspect a portal for it to be used, and it dies with the window, the
    /// network identity or `stopAllServices()`.
    func approveCaptivePortalBypass(withReply reply: @escaping (Bool) -> Void) {
        guard let identity = NetworkMonitor.currentNetworkIdentity() else {
            AgentLogger.shared.warning(
                "Refusing captive-portal bypass approval: current network cannot be identified"
            )
            reply(false)
            return
        }
        lifecycleLock.withLock {
            captiveFullBypassApproval = .grant(
                networkIdentity: identity,
                at: Date()
            )
        }
        startCaptiveApprovalExpiryTimer(
            firingIn: CaptivePortalFullBypassApproval.window
        )
        AgentLogger.shared.notice(
            "Captive-portal full bypass approved by the user for \(CaptivePortalFullBypassApproval.window)s on this network"
        )
        applyGrantedCaptiveFullBypassApproval()
        reply(true)
    }

    /// Applies a freshly granted approval to the portal the detector already
    /// suspects.
    ///
    /// A probe re-confirmation cannot carry the approval: the detector only
    /// calls the delegate when the confirmed outcome changes, so a portal that keeps
    /// answering `.captive` produces no callback and the grant would sit unused
    /// until the portal cleared. The grant itself is authenticated user intent,
    /// so it is applied directly.
    private func applyGrantedCaptiveFullBypassApproval() {
        let fullBypassActive = lifecycleLock.withLock { captivePortalBypassEnabled }
        guard
            CaptiveApprovalActivationPolicy.appliesImmediately(
                detectorStatus: CaptivePortalDetector.shared.getCurrentStatus(),
                fullBypassActive: fullBypassActive
            )
        else {
            return
        }
        guard
            let intent = lifecycleLock.withLock({
                captureForwardingIntentLocked(
                    callbackLifecycleGeneration: lifecycleGeneration
                )
            })
        else {
            return
        }

        captivePortalQueue.async { [weak self] in
            guard let self else { return }
            guard self.forwardingIntentIsCurrent(intent) else { return }
            self.handleCaptivePortalSuspected(expectedIntent: intent)
        }
    }

    // MARK: - Blocklist Management

    func getBlocklistSettings(withReply reply: @escaping (Data?) -> Void) {
        reply(BlocklistManager.shared.getSettingsData())
    }

    func saveBlocklistSettings(settingsData: Data, withReply reply: @escaping (Bool) -> Void) {
        BlocklistManager.shared.updateSettings(from: settingsData, reloadAfterUpdate: true) { success in
            reply(success)
        }
    }

    func forceBlocklistUpdate(withReply reply: @escaping (Bool) -> Void) {
        BlocklistManager.shared.forceUpdate { success in
            if !success {
                AgentLogger.shared.error(
                    "blocklist forceUpdate reported failure — UI 'Update Now' will surface error")
            }
            reply(success)
        }
    }

    // MARK: - Cache Management

    /// The user-facing flush resets everything the resolver holds: answers,
    /// the cache dump, provider connections and forward/stub resolvers.
    func flushCache(withReply reply: @escaping (Bool) -> Void) {
        ResolverModule.shared.notifyNetworkChange()
        reply(true)
    }

    // MARK: - Lookup History

    func queryHistory(request: Data, withReply reply: @escaping (Data?) -> Void) {
        historyQueue.async {
            reply(ResolverModule.shared.queryHistory(request))
        }
    }

    func clearQueryHistory(withReply reply: @escaping (Bool) -> Void) {
        historyQueue.async {
            let cleared = ResolverModule.shared.clearHistory()
            if !cleared {
                AgentLogger.shared.error("Lookup history clear was not confirmed by the resolver")
            }
            reply(cleared)
        }
    }

    // MARK: - License Management

    func getLicenseInfo(withReply reply: @escaping (Data?) -> Void) {
        licenseDispatch.licenseInfo { info in
            let data = try? JSONCoding.encoder.encode(info)
            reply(data)
        }
    }

    func activateLicense(licenseKey: String, withReply reply: @escaping (Data?) -> Void) {
        Task {
            let result = await LicenseManager.shared.activateLicense(key: licenseKey)
            let data = try? JSONCoding.encoder.encode(result)
            reply(data)
        }
    }

    func deactivateLicense(withReply reply: @escaping (Bool) -> Void) {
        Task {
            let success = await LicenseManager.shared.deactivateLicense()
            reply(success)
        }
    }

    func validateLicense(withReply reply: @escaping (Data?) -> Void) {
        Task {
            let info = await LicenseManager.shared.validateLicense()
            let data = try? JSONCoding.encoder.encode(info)
            reply(data)
        }
    }

    // MARK: - Update Management

    func getUpdateInfo(withReply reply: @escaping (Data?) -> Void) {
        Task {
            let info = await UpdateChecker.shared.getCachedUpdateInfo()
            let data = try? JSONEncoder().encode(info)
            reply(data)
        }
    }

    func checkForUpdatesNow(withReply reply: @escaping (Data?) -> Void) {
        Task {
            // Agent-originated network start, so it waits for network-ready like
            // every other one. No system notification, because the user is
            // already in the App.
            let info = await NetworkReadyWorkGate.shared.run {
                await UpdateChecker.shared.checkForUpdates(notifyApp: false)
            }
            let data = try? JSONEncoder().encode(info)
            reply(data)
        }
    }
}

/// Sequencing for a debounced network configuration change.
///
/// A roam or VPN attach changes the DHCP DNS servers while forwarding is live,
/// so the forwarding targets are refreshed immediately instead of waiting for
/// the periodic recovery timer. That timer is up to 600 s away and every
/// configuration change re-arms it, so churn could postpone recovery
/// indefinitely. The transition intent is re-checked before each side effect so
/// a concurrent stop or fail-safe still wins.
enum NetworkConfigurationChangeOrchestrator {
    static func apply(
        isCurrent: () -> Bool,
        invalidateDetector: () -> Void,
        publishEphemeralRoutes: () -> Void,
        rebuildNetworkInfrastructure: () -> Void,
        publishNetworkProfile: () -> Void,
        forwardingActive: () -> Bool,
        refreshForwardingTargets: () -> Void,
        isConnected: Bool,
        recheckConnectivity: () -> Void
    ) {
        guard isCurrent() else { return }
        invalidateDetector()
        guard isCurrent() else { return }
        publishEphemeralRoutes()
        guard isCurrent() else { return }
        rebuildNetworkInfrastructure()
        guard isCurrent() else { return }
        publishNetworkProfile()
        guard isCurrent() else { return }
        if forwardingActive() {
            refreshForwardingTargets()
        }
        guard isCurrent(), isConnected else { return }
        recheckConnectivity()
    }
}

/// What a forwarding fail-safe is allowed to do.
///
/// The fail-safe exists because a failed transition can leave the resolver in a
/// state nobody can describe. Its historical answer, request a proxy bypass
/// and stop the resolver, is also a complete shutdown of the DNS security
/// model, so it cannot be reached from an unauthenticated captive indication.
/// Without a live approval the fail-safe restores interception instead.
///
/// Staleness is graded separately for the two cases: a fail-safe that would
/// *create* a bypass must still own the current transition, otherwise it
/// overrides a newer one. A fail-safe that only re-affirms the bypass it is
/// already holding may run behind a newer transition, because refusing it there
/// would strand an active bypass with no owner.
enum ForwardingFailSafeAuthorizationPolicy {
    enum Action: Equatable {
        /// Another transition owns the state, so do nothing.
        case discard
        /// A user approval covers this network and window.
        case claimFullBypass
        /// No approval: keep the DNS Proxy, the blocklist and the Content
        /// Filter engaged instead of claiming a bypass.
        case keepProtectionClosed
    }

    static func action(
        isStopping: Bool,
        stopGenerationMatches: Bool,
        transitionGenerationMatches: Bool,
        bypassAlreadyActive: Bool,
        fullBypassAuthorized: Bool
    ) -> Action {
        guard !isStopping, stopGenerationMatches else { return .discard }
        if bypassAlreadyActive {
            return fullBypassAuthorized ? .claimFullBypass : .keepProtectionClosed
        }
        guard transitionGenerationMatches else { return .discard }
        return fullBypassAuthorized ? .claimFullBypass : .keepProtectionClosed
    }
}

/// Whether an approval the user just granted has to be applied right away.
///
/// `CaptivePortalDetector` only calls its delegate when the confirmed status
/// changes, so a portal that keeps answering `.captive` produces no callback at
/// all. An approval granted while the constrained compatibility mode is already
/// active would therefore never be applied, and the button would do nothing.
/// A probe re-confirmation may not carry it either. Only the grant itself, which
/// is authenticated user intent, does.
enum CaptiveApprovalActivationPolicy {
    /// Whether the constrained compatibility mode is the right place for this
    /// status. It is the same set an approval may be granted against, so
    /// leaving the bypass returns to it instead of to unconstrained resolution.
    static func needsConstrainedForwarding(
        _ status: CaptivePortalStatus
    ) -> Bool {
        switch status {
        case .captive, .dnsIntercepted:
            return true
        case .normal, .unknown:
            return false
        }
    }

    static func appliesImmediately(
        detectorStatus: CaptivePortalStatus,
        fullBypassActive: Bool
    ) -> Bool {
        guard !fullBypassActive else { return false }
        return needsConstrainedForwarding(detectorStatus)
    }
}

/// The persisted `state.json` document as the agent writes it: migrated to the
/// current schema, structurally validated, merged over defaults and stamped
/// with its revision. Used for bootstrap migration, loads and every mutation.
enum FullConfigNormalizationPolicy {
    static func defaults() -> [String: Any] {
        [
            "configRevision": ConfigRevision(0),
            "isEnabled": false,
            "dnssecEnabled": true,
            "logQueriesEnabled": false,
            "logRepliesEnabled": false,
            "prefetchEnabled": true,
            "serveExpiredEnabled": true,
            "dohProviders": DoHProviderID.defaultProviders.map(\.rawValue),
            "dohDispatchMode": DoHDispatchMode.defaultMode.rawValue,
            "dnsAnswerRefinementEnabled": true,
            QueryHistorySettings.enabledKey: QueryHistorySettings.default.enabled,
            QueryHistorySettings.retentionDaysKey: QueryHistorySettings.default.retentionDays,
            QueryHistorySettings.popularCountKey: QueryHistorySettings.default.popularCount,
            QueryHistorySettings.popularDaysKey: QueryHistorySettings.default.popularDays,
            "blockDohDotEnabled": false,
            "customZones": [[String: Any]](),
            "dnsOverrides": [[String: Any]](),
            "allowlist": [[String: Any]](),
        ]
    }

    /// Normalizes a candidate document. `mergedWith` carries the persisted
    /// state for mutations, so a field the caller omitted keeps its stored value
    /// instead of silently reverting to a default. Defaults only fill fields
    /// neither side has.
    static func normalized(
        _ raw: [String: Any],
        mergedWith persisted: [String: Any] = [:]
    ) -> [String: Any]? {
        guard
            let writable = ConfigSchemaPolicy.writable(raw),
            let validated = DNSPolicyStructuralPolicy.validateAndNormalize(
                writable
            )
        else {
            return nil
        }

        let candidate = validated.normalizedConfig
        var normalized = FullConfigMutationMergePolicy.merged(
            candidate: candidate,
            persisted: persisted,
            defaults: defaults()
        )
        normalized["configRevision"] = ConfigRevisionPolicy.revision(from: candidate)
        normalized["dohProviders"] = DoHProviderID.canonicalized(
            normalized["dohProviders"] as? [String] ?? DoHProviderID.defaultProviders.map(\.rawValue)
        ).map(\.rawValue)

        let rawMode = normalized["dohDispatchMode"] as? String
        if rawMode.flatMap(DoHDispatchMode.init(rawValue:)) == nil {
            normalized["dohDispatchMode"] = DoHDispatchMode.defaultMode.rawValue
        }

        // The schema version describes the persisted document, not the user's
        // configuration: like `timestamp` it is stamped on write and kept out of
        // the payload the App and the Agent compare.
        normalized.removeValue(forKey: ConfigSchemaPolicy.versionKey)
        return normalized
    }
}

/// Field precedence for a configuration mutation: what the caller sent, then
/// what is already persisted, then the shipped defaults.
///
/// Starting from defaults would turn every field a caller omitted into a silent
/// reset, and would drop top-level fields written by a newer build, so a
/// downgrade-then-upgrade round trip would lose them permanently.
enum FullConfigMutationMergePolicy {
    static func merged(
        candidate: [String: Any],
        persisted: [String: Any],
        defaults: [String: Any]
    ) -> [String: Any] {
        var merged = persisted
        for (key, value) in candidate {
            merged[key] = value
        }
        for (key, value) in defaults where merged[key] == nil {
            merged[key] = value
        }
        return merged
    }
}

/// Recovery for a configuration rollback that could not be fully restored.
///
/// A partial restore leaves the persisted document and the live resolver policy
/// divergent, so DNS must stop. Requesting the stop is not enough: an
/// unconfirmed teardown keeps queries flowing through policy nobody can
/// describe. The escalation is a fail-closed bypass first, so the provider
/// stops intercepting immediately, and only then a forced teardown.
enum IncompleteRollbackRecoveryPolicy {
    enum Outcome: Equatable {
        case restored
        case stopped
        case forcedStop
        /// Teardown was never confirmed. Interception stays bypassed.
        case bypassed
    }

    static func recover(
        fullyRestored: Bool,
        stopServices: () -> Bool,
        forceStopServices: () -> Bool,
        failClosedBypass: () -> Void
    ) -> Outcome {
        guard !fullyRestored else { return .restored }
        if stopServices() { return .stopped }
        failClosedBypass()
        return forceStopServices() ? .forcedStop : .bypassed
    }
}

/// The agent's single `state.json` writer.
///
/// The derived `blocklist_settings.json` projection is refreshed inside the
/// same critical section. A failed projection restores the previous document.
/// If restoration also fails, the error reports both failures and the revision
/// still observable on disk.
enum StateDocumentWriter {
    struct RestorationFailure: LocalizedError, CustomStringConvertible {
        let projectionError: Error
        let restorationError: Error
        let persistedRevision: ConfigRevision?

        var errorDescription: String? { description }

        var description: String {
            let revision = persistedRevision.map(String.init) ?? "unknown"
            return "Configuration projection failed: \(projectionError.localizedDescription). "
                + "State restoration failed: \(restorationError.localizedDescription). "
                + "Persisted configuration revision: \(revision)."
        }
    }

    static func write(
        _ document: [String: Any],
        to stateFile: URL,
        writeData: (Data, URL) throws -> Void = { data, url in
            try data.write(to: url, options: .atomic)
        },
        readData: (URL) throws -> Data? = { url in
            do {
                return try Data(contentsOf: url)
            } catch CocoaError.fileReadNoSuchFile {
                return nil
            }
        },
        removeFile: (URL) throws -> Void = { try FileManager.default.removeItem(at: $0) },
        refreshProjection: ([String: Any]) throws -> Void
    ) throws {
        let previousData = try readData(stateFile)
        let data = try JSONSerialization.data(
            withJSONObject: document,
            options: [.prettyPrinted, .sortedKeys]
        )
        try writeData(data, stateFile)
        do {
            try refreshProjection(document)
        } catch let projectionError {
            do {
                if let previousData {
                    try writeData(previousData, stateFile)
                } else {
                    try removeFile(stateFile)
                }
            } catch {
                let persistedRevision: ConfigRevision?
                if let data = try? readData(stateFile),
                    let document = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                {
                    if let value = document["configRevision"] {
                        if let number = value as? NSNumber,
                            CFGetTypeID(number) != CFBooleanGetTypeID(),
                            let revision = ConfigRevision(number.stringValue), revision >= 0
                        {
                            persistedRevision = revision
                        } else {
                            persistedRevision = nil
                        }
                    } else {
                        persistedRevision = 0
                    }
                } else {
                    persistedRevision = nil
                }
                throw RestorationFailure(
                    projectionError: projectionError,
                    restorationError: error,
                    persistedRevision: persistedRevision
                )
            }
            throw projectionError
        }
    }
}

/// Sequencing for a stop request that arrives while another stop is still
/// running.
///
/// Answering `!isRunning()` right away answers "is the resolver stopped *yet*",
/// which is almost always `false` mid-teardown, and the App turns that into a
/// spurious "Stopping DNS failed - retrying". The late caller waits for the
/// in-flight stop and then reports the confirmed state. A wait that times out
/// falls back to the observed state instead of blocking forever.
enum ConcurrentStopSequencer {
    static func awaitInFlightStop<Waiter>(
        enqueueWaiter: () -> Waiter?,
        wait: (Waiter) -> Bool,
        resolverStopped: () -> Bool
    ) -> Bool {
        while let waiter = enqueueWaiter() {
            guard wait(waiter) else { break }
        }
        return resolverStopped()
    }
}
