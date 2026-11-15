// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

// MARK: - Configuration

struct CaptivePortalConfig {
    let confirmationsRequired = 2

    let determinationInterval: TimeInterval = 3.0
    let maxDeterminationAttempts = 10

    let healthCheckWarmInterval: TimeInterval = 60.0
    let healthCheckColdInterval: TimeInterval = 120.0
    let healthCheckWarmDuration: TimeInterval = 900.0

    let captivePollingInterval: TimeInterval = 10.0
    let maxCaptivePollingAttempts = 30

    let errorRetryInterval: TimeInterval = 5.0
    let maxConsecutiveErrors = 5

    let httpProbeTimeout: TimeInterval = 5.0
}

// MARK: - Types

enum CaptivePortalStatus: String, Equatable, CustomStringConvertible {
    case unknown
    case normal
    case captive
    case dnsIntercepted

    var description: String { rawValue }
}

private enum DetectorPhase: CustomStringConvertible {
    case idle
    case determining
    case healthCheck
    case captivePolling

    var description: String {
        switch self {
        case .idle: return "idle"
        case .determining: return "determining"
        case .healthCheck: return "healthCheck"
        case .captivePolling: return "captivePolling"
        }
    }
}

private enum HTTPProbeResult {
    case normal
    case captive
    case inconclusive(reason: String)
    case error(reason: String)

    var evidence: CaptiveHTTPProbeEvidence {
        switch self {
        case .normal:
            return .normal
        case .captive:
            return .captive
        case .inconclusive:
            return .inconclusive
        case .error:
            return .error
        }
    }
}

enum CaptivePortalRecheckTrigger: String, Equatable {
    case serviceStart = "service-start"
    case manual
    case wake
    case networkConfiguration = "network-configuration"
}

/// Attempt budget for the intensive captive-polling phase.
///
/// Re-confirming `.captive` while already polling must reschedule without
/// resetting the budget, otherwise a stable portal never reaches the timeout
/// and polls forever. Once the budget is exhausted the detector stays in
/// health check until a real status change or an explicit recheck.
struct CaptivePollingPhase: Equatable {
    enum Decision: Equatable {
        case enterIntensivePolling
        case continueIntensivePolling
        case remainInHealthCheck
    }

    let maxAttempts: Int
    private(set) var attempts = 0
    private(set) var isExhausted = false

    init(maxAttempts: Int) {
        self.maxAttempts = maxAttempts
    }

    /// Decides how a confirmed `.captive` status is handled.
    mutating func confirmCaptive(statusChanged: Bool, isPolling: Bool) -> Decision {
        if isPolling && !statusChanged {
            return .continueIntensivePolling
        }
        if isExhausted && !statusChanged {
            return .remainInHealthCheck
        }
        attempts = 0
        isExhausted = false
        return .enterIntensivePolling
    }

    /// Records one intensive-polling tick. Returns `false` once the budget is
    /// exhausted and the caller must fall back to health check.
    mutating func recordAttempt() -> Bool {
        attempts += 1
        guard attempts <= maxAttempts else {
            isExhausted = true
            return false
        }
        return true
    }

    mutating func reset() {
        attempts = 0
        isExhausted = false
    }
}

protocol CaptivePortalDetectorDelegate: AnyObject {
    func captiveConnectivityOutcomeConfirmed(
        from oldOutcome: CaptiveConnectivityOutcome?,
        to newOutcome: CaptiveConnectivityOutcome,
        callbackLifecycleGeneration: UInt64
    )

    func captivePortalResolverPreparationRequested(
        probeGeneration: UInt64,
        callbackLifecycleGeneration: UInt64
    )
}

// MARK: - RedirectBlocker

/// URLSession delegate that captures HTTP redirects without following them.
/// Captive portals use 302/307 redirects to their login page.
private class RedirectBlocker: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

// MARK: - CaptivePortalDetector

/// Detects captive portal networks using HTTP evidence and direct DoH provider health.
///
/// Phases:
/// 1. IDLE: not active.
/// 2. DETERMINING: initial probing until 2 consecutive results agree.
/// 3. HEALTH_CHECK: normal confirmed. Probes every 60 s for 15 min, then every
///    120 s, to detect session expiry.
/// 4. CAPTIVE_POLLING: captive confirmed. Probes every 10 s until resolved or
///    the attempt budget runs out.
///
/// Evidence:
/// - HTTP probe to captive.apple.com detects captive portals (redirect/DNS hijack/HTTP-only)
/// - Direct provider dispatch proves whether configured DoH providers work on the current network
class CaptivePortalDetector {
    static let shared = CaptivePortalDetector()

    weak var delegate: CaptivePortalDetectorDelegate?

    private let config = CaptivePortalConfig()

    private var currentStatus: CaptivePortalStatus = .unknown
    private var phase: DetectorPhase = .idle
    private var callbackLifecycleGeneration: UInt64 = 0
    private var probeGeneration: UInt64 = 0
    private var activeTrigger: CaptivePortalRecheckTrigger = .serviceStart
    private lazy var confirmationTracker = CaptiveConnectivityConfirmationTracker(
        confirmationsRequired: config.confirmationsRequired
    )
    private var consecutiveErrorCount = 0
    private var determinationAttempts = 0
    private var preparationRequestedGeneration: UInt64?
    private lazy var captivePolling = CaptivePollingPhase(
        maxAttempts: config.maxCaptivePollingAttempts
    )

    private var healthCheckStartTime: Date?

    private var probeTimer: DispatchSourceTimer?

    private let stateQueue = DispatchQueue(label: "app.macdns.captive.state", qos: .userInitiated)
    private let directProbeQueue = DispatchQueue(
        label: "app.macdns.captive.direct-doh",
        qos: .userInitiated
    )

    // The agent is on the extension's passthrough list, so this HTTP probe
    // bypasses the DNS proxy.
    private let appleProbeURL = URL(string: "http://captive.apple.com/hotspot-detect.html")!
    private let expectedResponse = "<TITLE>Success</TITLE>"

    private lazy var probeSession: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 5.0
        config.timeoutIntervalForResource = 10.0
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpShouldSetCookies = false
        config.httpCookieAcceptPolicy = .never
        return URLSession(configuration: config, delegate: RedirectBlocker(), delegateQueue: nil)
    }()

    #if DEBUG
        // Debug builds only: the detector reports a captive portal while this file
        // exists. /tmp is writable by every local account, so a release build must
        // never honor it.
        private let debugCaptiveFile = "/tmp/macdns-captive"
    #endif

    private init() {}

    // MARK: - Public API

    func invalidateForNetworkTransition() {
        stateQueue.sync {
            probeGeneration &+= 1
            cancelTimer()
            phase = .idle
            currentStatus = .unknown
            confirmationTracker.invalidateNetwork()
            resetCounters()
        }
    }

    func getCurrentStatus() -> CaptivePortalStatus {
        stateQueue.sync { currentStatus }
    }

    func forceRecheck(
        trigger: CaptivePortalRecheckTrigger,
        callbackLifecycleGeneration: UInt64
    ) {
        stateQueue.async { [weak self] in
            guard let self = self else { return }

            self.probeGeneration &+= 1
            self.callbackLifecycleGeneration = callbackLifecycleGeneration
            self.activeTrigger = trigger
            self.cancelTimer()
            self.resetCounters()
            self.phase = .determining

            AgentLogger.shared.debug("Captive portal recheck initiated trigger=\(trigger.rawValue)")
            self.executeProbe(generation: self.probeGeneration)
        }
    }

    func scheduleRetryAfterResolverPreparationFailure(
        callbackLifecycleGeneration: UInt64,
        failureCount: Int,
        maxFailures: Int
    ) {
        stateQueue.async { [weak self] in
            guard let self else { return }
            self.probeGeneration &+= 1
            self.callbackLifecycleGeneration = callbackLifecycleGeneration
            self.activeTrigger = .serviceStart
            self.cancelTimer()
            self.confirmationTracker.resetCandidate()
            self.preparationRequestedGeneration = nil
            guard failureCount < maxFailures else {
                self.phase = .idle
                AgentLogger.shared.error(
                    "Resolver preparation retry budget exhausted; preserving approved captive bypass"
                )
                return
            }
            self.phase = .determining
            self.consecutiveErrorCount = failureCount
            self.determinationAttempts = failureCount
            self.scheduleNextProbe(interval: self.config.errorRetryInterval)
        }
    }

    // MARK: - Internal State

    private func resetCounters() {
        confirmationTracker.resetCandidate()
        consecutiveErrorCount = 0
        determinationAttempts = 0
        preparationRequestedGeneration = nil
        captivePolling.reset()
        healthCheckStartTime = nil
    }

    private func cancelTimer() {
        probeTimer?.cancel()
        probeTimer = nil
    }

    // MARK: - Probe Execution

    private func executeProbe(generation: UInt64) {
        guard phase != .idle, probeGeneration == generation else { return }

        determinationAttempts += 1

        #if DEBUG
            if FileManager.default.fileExists(atPath: debugCaptiveFile) {
                AgentLogger.shared.debug("Simulating captive portal (\(debugCaptiveFile) exists)")
                handleProbeEvidence(
                    httpResult: .captive,
                    directDoH: .notRun,
                    networkDNS: .notRun,
                    resolver: .unavailable,
                    generation: generation
                )
                return
            }
        #endif

        probeHTTP { [weak self] httpResult in
            guard let self else { return }
            if httpResult.evidence == .captive {
                self.stateQueue.async {
                    self.handleProbeEvidence(
                        httpResult: httpResult,
                        directDoH: .notRun,
                        networkDNS: .notRun,
                        resolver: .unavailable,
                        generation: generation
                    )
                }
                return
            }

            self.runDirectDoHProbe(
                after: httpResult,
                generation: generation
            )
        }
    }

    private func runDirectDoHProbe(
        after httpResult: HTTPProbeResult,
        generation: UInt64
    ) {
        directProbeQueue.async { [weak self] in
            guard let self else { return }
            let isCurrent = self.stateQueue.sync {
                self.phase != .idle && self.probeGeneration == generation
            }
            guard isCurrent else { return }

            let resolverRunning = ResolverModule.shared.isRunning()
            let resolverWarmingUp = resolverRunning && ResolverModule.shared.isWarmingUp()
            guard resolverRunning else {
                self.stateQueue.async {
                    self.handleProbeEvidence(
                        httpResult: httpResult,
                        directDoH: .notRun,
                        networkDNS: .notRun,
                        resolver: .unavailable,
                        generation: generation
                    )
                }
                return
            }

            let directDoHWorked = ResolverModule.shared.probeRecursiveResolution()
            let resolverStillRunning = ResolverModule.shared.isRunning()
            let directDoH: DirectDoHProbeEvidence =
                resolverStillRunning ? (directDoHWorked ? .success : .failure) : .notRun
            let resolver: ResolverProbeAvailability =
                resolverStillRunning ? .available(warmingUp: resolverWarmingUp) : .unavailable
            let networkDNS = self.probeNetworkDNSIfNeeded(
                http: httpResult.evidence,
                directDoH: directDoH,
                resolver: resolver
            )
            self.stateQueue.async {
                self.handleProbeEvidence(
                    httpResult: httpResult,
                    directDoH: directDoH,
                    networkDNS: networkDNS,
                    resolver: resolver,
                    generation: generation
                )
            }
        }
    }

    /// Runs on `directProbeQueue`. Probes the same resolvers that
    /// compatibility forwarding would use, and only when compatibility is the
    /// candidate, so a healthy network never pays for the extra query.
    private func probeNetworkDNSIfNeeded(
        http: CaptiveHTTPProbeEvidence,
        directDoH: DirectDoHProbeEvidence,
        resolver: ResolverProbeAvailability
    ) -> NetworkDNSProbeEvidence {
        guard
            CaptiveConnectivityPolicy.needsNetworkDNSProbe(
                http: http,
                directDoH: directDoH,
                resolver: resolver
            )
        else {
            return .notRun
        }
        let servers = NetworkMonitor.getDHCPDNSServers()
        guard !servers.isEmpty else { return .unanswered }
        return ResolverModule.shared.probeNetworkDNS(servers: servers) ? .answered : .unanswered
    }

    // MARK: - HTTP Probe

    /// Probes Apple's captive portal detection endpoint.
    /// Normal network: returns 200 with "Success" body.
    /// Captive portal: returns 302/307 redirect OR 200 with portal HTML.
    private func probeHTTP(completion: @escaping (HTTPProbeResult) -> Void) {
        var request = URLRequest(url: appleProbeURL)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = config.httpProbeTimeout

        let task = probeSession.dataTask(with: request) { [weak self] data, response, error in
            guard let self = self else {
                completion(.error(reason: "Detector deallocated"))
                return
            }

            if let error = error {
                let nsError = error as NSError
                if nsError.domain == NSURLErrorDomain
                    && nsError.code == NSURLErrorHTTPTooManyRedirects
                {
                    completion(.captive)
                    return
                }
                completion(.error(reason: error.localizedDescription))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.error(reason: "No HTTP response"))
                return
            }

            // RedirectBlocker stops redirects from being followed, so a
            // portal's redirect arrives here as a 3xx.
            if (300...399).contains(httpResponse.statusCode) {
                completion(.captive)
                return
            }

            guard httpResponse.statusCode == 200 else {
                completion(.inconclusive(reason: "HTTP \(httpResponse.statusCode)"))
                return
            }

            guard let data = data, let body = String(data: data, encoding: .utf8) else {
                completion(.inconclusive(reason: "Empty response body"))
                return
            }

            if body.contains(self.expectedResponse) {
                completion(.normal)
            } else {
                // A 200 with another body is a portal serving its own page.
                completion(.captive)
            }
        }
        task.resume()
    }

    // MARK: - Result Handling

    private func handleProbeEvidence(
        httpResult: HTTPProbeResult,
        directDoH: DirectDoHProbeEvidence,
        networkDNS: NetworkDNSProbeEvidence,
        resolver: ResolverProbeAvailability,
        generation: UInt64
    ) {
        guard phase != .idle, probeGeneration == generation else { return }

        let decision = CaptiveConnectivityPolicy.decide(
            http: httpResult.evidence,
            directDoH: directDoH,
            networkDNS: networkDNS,
            resolver: resolver
        )
        let oldOutcome = confirmationTracker.confirmedOutcome

        switch confirmationTracker.consume(decision) {
        case .pending:
            consecutiveErrorCount = 0
            scheduleDeterminationProbe()
        case .retry:
            consecutiveErrorCount += 1
            scheduleRetry()
        case .prepareResolver:
            requestResolverPreparation(generation: generation)
        case .confirmed(let outcome, let changed):
            consecutiveErrorCount = 0
            confirmOutcome(
                outcome,
                from: oldOutcome,
                changed: changed,
                http: httpResult.evidence,
                directDoH: directDoH,
                networkDNS: networkDNS,
                resolver: resolver
            )
        }
    }

    private func scheduleDeterminationProbe() {
        guard determinationAttempts < config.maxDeterminationAttempts else {
            AgentLogger.shared.warning(
                "Captive detection exhausted determination attempts; preserving last confirmed outcome"
            )
            transitionToHealthCheck()
            return
        }
        scheduleNextProbe(interval: config.determinationInterval)
    }

    private func scheduleRetry() {
        if consecutiveErrorCount >= config.maxConsecutiveErrors
            || determinationAttempts >= config.maxDeterminationAttempts
        {
            AgentLogger.shared.warning(
                "Captive detection exhausted retry budget; preserving last confirmed outcome"
            )
            transitionToHealthCheck()
            return
        }

        scheduleNextProbe(interval: config.errorRetryInterval)
    }

    private func requestResolverPreparation(generation: UInt64) {
        guard preparationRequestedGeneration != generation else { return }
        preparationRequestedGeneration = generation
        cancelTimer()

        let lifecycleGeneration = callbackLifecycleGeneration
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.stateQueue.sync {
                guard self.phase != .idle else { return }
                guard self.probeGeneration == generation else { return }
                self.delegate?.captivePortalResolverPreparationRequested(
                    probeGeneration: generation,
                    callbackLifecycleGeneration: lifecycleGeneration
                )
            }
        }
    }

    private func confirmOutcome(
        _ newOutcome: CaptiveConnectivityOutcome,
        from oldOutcome: CaptiveConnectivityOutcome?,
        changed: Bool,
        http: CaptiveHTTPProbeEvidence,
        directDoH: DirectDoHProbeEvidence,
        networkDNS: NetworkDNSProbeEvidence,
        resolver: ResolverProbeAvailability
    ) {
        currentStatus = newOutcome.status
        confirmationTracker.resetCandidate()

        if changed {
            let warmingUp: Bool
            if case .available(let warming) = resolver {
                warmingUp = warming
            } else {
                warmingUp = false
            }
            AgentLogger.shared.notice(
                "Captive connectivity transition http=\(http.rawValue) direct-doh=\(directDoH.rawValue) network-dns=\(networkDNS.rawValue) warming=\(warmingUp) old=\(oldOutcome?.description ?? "unknown") new=\(newOutcome.description) status=\(newOutcome.status.rawValue) trigger=\(activeTrigger.rawValue) generation=\(probeGeneration)"
            )
        }

        switch newOutcome {
        case .healthy, .compatibilityRequired:
            transitionToHealthCheck()
        case .captive:
            let decision = captivePolling.confirmCaptive(
                statusChanged: changed,
                isPolling: phase == .captivePolling
            )
            switch decision {
            case .enterIntensivePolling:
                transitionToCaptivePolling(announcing: true)
            case .continueIntensivePolling:
                transitionToCaptivePolling(announcing: false)
            case .remainInHealthCheck:
                transitionToHealthCheck()
            }
        }

        if changed {
            let lifecycleGeneration = callbackLifecycleGeneration
            let callbackProbeGeneration = probeGeneration
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.stateQueue.sync {
                    guard self.probeGeneration == callbackProbeGeneration else { return }
                    self.delegate?.captiveConnectivityOutcomeConfirmed(
                        from: oldOutcome,
                        to: newOutcome,
                        callbackLifecycleGeneration: lifecycleGeneration
                    )
                }
            }
        }
    }

    private func transitionToHealthCheck() {
        let enteringFromOtherPhase = phase != .healthCheck
        phase = .healthCheck
        determinationAttempts = 0
        confirmationTracker.resetCandidate()

        // A recheck inside health check keeps the running warm window.
        if enteringFromOtherPhase {
            healthCheckStartTime = Date()
            let warm = Int(config.healthCheckWarmInterval)
            let cold = Int(config.healthCheckColdInterval)
            AgentLogger.shared.info("Health check started (warm \(warm)s → cold \(cold)s)")
        }

        let elapsed = Date().timeIntervalSince(healthCheckStartTime ?? Date())
        let interval =
            elapsed < config.healthCheckWarmDuration
            ? config.healthCheckWarmInterval
            : config.healthCheckColdInterval

        scheduleNextProbe(interval: interval)
    }

    private func transitionToCaptivePolling(announcing: Bool) {
        phase = .captivePolling
        determinationAttempts = 0
        confirmationTracker.resetCandidate()

        if announcing {
            AgentLogger.shared.notice("Captive portal detected, polling every \(Int(config.captivePollingInterval))s")
        }

        scheduleNextProbe(interval: config.captivePollingInterval)
    }

    // MARK: - Timer Management

    private func scheduleNextProbe(interval: TimeInterval) {
        cancelTimer()
        let generation = probeGeneration

        let timer = DispatchSource.makeTimerSource(queue: stateQueue)
        timer.schedule(deadline: .now() + interval)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            guard self.probeGeneration == generation else { return }

            switch self.phase {
            case .idle:
                return

            case .determining:
                self.executeProbe(generation: generation)

            case .healthCheck:
                self.determinationAttempts = 0
                self.executeProbe(generation: generation)

            case .captivePolling:
                guard self.captivePolling.recordAttempt() else {
                    AgentLogger.shared.info("Captive polling timeout, continuing health checks")
                    self.transitionToHealthCheck()
                    return
                }

                self.determinationAttempts = 0
                self.executeProbe(generation: generation)
            }
        }

        probeTimer = timer
        timer.resume()
    }

}
