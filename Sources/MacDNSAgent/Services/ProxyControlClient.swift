// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

/// Locked hand-off for a bounded XPC wait. When the wait times out, a late reply
/// writes the slot concurrently with the caller's read. An unprotected
/// refcounted optional makes that undefined ARC behaviour in the agent process
/// that owns the resolver.
final class ProxyControlStateReportBox: @unchecked Sendable {
    private let lock = NSLock()
    private var report: ProxyControlStateReport?

    func store(_ value: ProxyControlStateReport?) {
        lock.withLock { report = value }
    }

    var value: ProxyControlStateReport? {
        lock.withLock { report }
    }
}

final class ProxyControlClient {
    static let shared = ProxyControlClient()

    private let lock = NSLock()
    private var connection: NSXPCConnection?
    /// While `connection` is non-nil it owns `generations.current`. Both only
    /// ever change together under `lock`.
    private var generations = ProxyControlConnectionGenerationPolicy()
    private var backoffSeconds: Double = 1
    private var consecutiveFailures = 0
    private var firstFailureAt: Date?
    private var outageSignaled = false

    func connect() {
        connect(claiming: nil)
    }

    /// Opens a link. A scheduled retry passes the generation it was minted with
    /// and connects only while that generation is still current.
    private func connect(claiming retryGeneration: UInt64?) {
        lock.lock()
        guard connection == nil else {
            lock.unlock()
            return
        }
        if let retryGeneration, !generations.isCurrent(retryGeneration) {
            lock.unlock()
            return
        }
        let generation = generations.begin()
        let conn = NSXPCConnection(machServiceName: proxyControlMachServiceName)
        conn.remoteObjectInterface = NSXPCInterface(with: MacDNSProxyControlProtocol.self)
        conn.setCodeSigningRequirement(proxyControlProviderRequirement)
        conn.invalidationHandler = { [weak self] in
            self?.handleDrop(generation: generation)
        }
        conn.interruptionHandler = { [weak self] in
            self?.handleDrop(generation: generation)
        }
        conn.resume()
        connection = conn
        lock.unlock()

        beginSession(generation: generation)
    }

    /// Ensures the resolver has a control session that matches a live provider
    /// session. Call after every resolver (re)start. `dns_init` wipes the
    /// resolver key, so a still-alive XPC connection would otherwise hold a
    /// session the resolver no longer has (permanent bypass). Connects if the
    /// link is down, otherwise re-fetches a fresh session over the live link.
    func ensureSessionInstalled() {
        let liveGeneration = lock.withLock { () -> UInt64? in
            connection != nil ? generations.current : nil
        }
        if let liveGeneration {
            beginSession(generation: liveGeneration)
        } else {
            connect()
        }
    }

    func disconnect() {
        lock.lock()
        let conn = connection
        connection = nil
        // Retire every outstanding generation before invalidating. A retry
        // already scheduled must not reconnect after the service stopped, and
        // the dying connection's handlers must not act on a later link.
        generations.retireAll()
        backoffSeconds = 1
        consecutiveFailures = 0
        firstFailureAt = nil
        outageSignaled = false
        lock.unlock()
        conn?.invalidate()
        _ = ResolverModule.shared.clearProxyControl()
    }

    private func beginSession(generation: UInt64) {
        let proxy = lock.withLock { () -> MacDNSProxyControlProtocol? in
            guard generations.isCurrent(generation) else { return nil }
            return connection?.remoteObjectProxyWithErrorHandler { [weak self] error in
                AgentLogger.shared.warning(
                    "beginControlSession failed: \(error.localizedDescription)")
                self?.handleDrop(generation: generation)
            } as? MacDNSProxyControlProtocol
        }
        proxy?.beginControlSession { [weak self] data in
            self?.installSession(data, generation: generation)
        }
    }

    private func installSession(_ data: Data?, generation: UInt64) {
        guard let data,
            data.count <= proxyControlMaxPayloadBytes,
            var boot = try? JSONDecoder().decode(ProxyControlBootstrap.self, from: data),
            boot.version == proxyControlVersion,
            boot.sessionID.count == 16, boot.hmacKey.count == 32
        else {
            AgentLogger.shared.warning("Invalid control bootstrap; retrying")
            handleDrop(generation: generation)
            return
        }
        // Installed under the lock so a bootstrap that lost the link mid-flight
        // cannot overwrite the session of a newer connection.
        let installed = lock.withLock { () -> Bool? in
            guard generations.isCurrent(generation) else { return nil }
            return ResolverModule.shared.configureProxyControl(
                sessionID: boot.sessionID, key: boot.hmacKey)
        }
        // The resolver owns the key from here on. The agent keeps no copy.
        boot.hmacKey.resetBytes(in: 0..<boot.hmacKey.count)
        guard let installed else { return }
        if installed {
            lock.withLock {
                backoffSeconds = 1
                consecutiveFailures = 0
                firstFailureAt = nil
                outageSignaled = false
            }
            AgentLogger.shared.info("Proxy control session installed")
            // Wake the provider now that the resolver has the key, so it
            // re-challenges immediately instead of waiting for the 5 s health
            // timer. The provider's own onSessionIssued fires before this
            // install completes and therefore challenges a keyless resolver.
            CFNotificationCenterPostNotification(
                CFNotificationCenterGetDarwinNotifyCenter(),
                CFNotificationName(DarwinNotifications.bypassDisable),
                nil, nil, true)
        } else {
            AgentLogger.shared.error("Failed to install control session into resolver")
            handleDrop(generation: generation)
        }
    }

    func currentProviderStateReport(timeout: TimeInterval) -> ProxyControlStateReport? {
        let sem = DispatchSemaphore(value: 0)
        // Signal on the error path too. On a dead or interrupted connection
        // XPC calls the error handler and not the reply, so without this the
        // wait would always burn the full timeout and return nil.
        let proxy = lock.withLock {
            connection?.remoteObjectProxyWithErrorHandler { _ in sem.signal() }
                as? MacDNSProxyControlProtocol
        }
        guard let proxy else { return nil }
        let box = ProxyControlStateReportBox()
        proxy.currentProviderState { data in
            if let data, data.count <= proxyControlMaxPayloadBytes {
                box.store(try? JSONDecoder().decode(ProxyControlStateReport.self, from: data))
            }
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + timeout)
        return box.value
    }

    /// Drops the link owned by `generation`. A callback from a link that was
    /// already replaced or disconnected carries a retired generation and is
    /// ignored, so it cannot clear the session of the connection that took its
    /// place. The current link is still torn down immediately.
    private func handleDrop(generation: UInt64) {
        lock.lock()
        guard generations.isCurrent(generation) else {
            lock.unlock()
            return
        }
        let conn = connection
        connection = nil
        _ = ResolverModule.shared.clearProxyControl()
        let resolverRunning = ResolverModule.shared.isRunning()
        var shouldSignalOutage = false
        if resolverRunning, conn != nil {
            consecutiveFailures += 1
            if firstFailureAt == nil { firstFailureAt = Date() }
            let persistent = ProxyControlOutagePolicy(
                resolverRunning: true,
                consecutiveFailures: consecutiveFailures,
                firstFailureAt: firstFailureAt,
                now: Date()
            ).isPersistentOutage
            if persistent && !outageSignaled {
                outageSignaled = true
                shouldSignalOutage = true
            }
        }
        guard resolverRunning else {
            generations.retireAll()
            lock.unlock()
            // Invalidate outside the lock. Invalidation handlers can re-enter
            // handleDrop, which would deadlock a non-recursive lock.
            conn?.invalidate()
            postOutageHintIfNeeded(shouldSignalOutage)
            return
        }
        // The pending retry owns the link until it fires, so this drop cannot be
        // scheduled twice and a later disconnect can retire it.
        let retryGeneration = generations.begin()
        let delay = min(backoffSeconds, 30)
        backoffSeconds = min(backoffSeconds * 2, 30)
        lock.unlock()
        conn?.invalidate()
        postOutageHintIfNeeded(shouldSignalOutage)
        // Jitter avoids a reconnect stampede after a provider replacement.
        let jitter = Double.random(in: 0...0.5)
        DispatchQueue.global().asyncAfter(deadline: .now() + delay + jitter) { [weak self] in
            self?.connect(claiming: retryGeneration)
        }
    }

    private func postOutageHintIfNeeded(_ shouldSignal: Bool) {
        guard shouldSignal else { return }
        AgentLogger.shared.error(
            "Proxy control endpoint unreachable persistently; requesting App-side recovery")
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(DarwinNotifications.proxyControlOutageChanged),
            nil, nil, true)
    }

    /// True while control-session bootstraps have been failing long enough to
    /// indicate a lost Mach endpoint rather than a provider restart.
    var persistentOutageActive: Bool {
        lock.withLock {
            ProxyControlOutagePolicy(
                resolverRunning: ResolverModule.shared.isRunning(),
                consecutiveFailures: consecutiveFailures,
                firstFailureAt: firstFailureAt,
                now: Date()
            ).isPersistentOutage
        }
    }
}
