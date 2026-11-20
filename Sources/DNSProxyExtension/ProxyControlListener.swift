// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import os.log

// The DNS Proxy is compiled by a bare `swiftc Sources/DNSProxyExtension/*.swift`
// (see Sources/MacDNS/Makefile) and cannot import `Shared`, so these constants
// are a second copy of the ones in `Shared/ProxyControlProtocol.swift`. They are
// internal rather than private so `ProxyControlReportInteropTests` can assert
// the two copies still agree. A silent divergence leaves the provider in
// permanent bypass with no failing build.
//
// Must stay prefixed by the App Group in the extension entitlements. sysextd
// category validation rejects the extension otherwise (NE error Code=6).
let machServiceName = "group.app.macdns.proxy-control"
let proxyControlAgentRequirement =
    "identifier \"app.macdns.agent\" and anchor apple generic and "
    + "certificate leaf[subject.OU] = \"MY427949GW\""
let maxPayloadBytes = 4096

@objc protocol MacDNSProxyControlProtocol {
    func beginControlSession(withReply reply: @escaping (Data?) -> Void)
    func currentProviderState(withReply reply: @escaping (Data?) -> Void)
}

final class ProxyControlListener: NSObject, NSXPCListenerDelegate, MacDNSProxyControlProtocol {
    private let logger: Logger
    private let listener: ProxyControlListenerEndpoint
    /// This extension process's own version, reported to the App so it can detect
    /// a stale provider still running after an update (restart required).
    private let providerVersion =
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion")
        as? String
    private let lock = NSLock()
    private var activeConnection: ProxyControlConnection?
    private var session: ProxyControlSession?
    private var state: ProxyInterceptionState = .bypass(.starting)

    /// Called when a new session is issued so the provider clears any stale
    /// bypass and re-evaluates. Set by DNSProxyProvider.
    var onSessionIssued: ((ProxyControlSession) -> Void)?

    /// Invoked outside the listener lock as soon as the live session stops being
    /// authoritative (the control connection was interrupted or invalidated, or a
    /// new bootstrap replaced the session), so the provider forces bypass
    /// immediately instead of forwarding in interception mode until the next
    /// evaluation.
    var onSessionLost: (() -> Void)?

    convenience init(logger: Logger) {
        self.init(logger: logger, listener: NSXPCListener(machServiceName: machServiceName))
    }

    init(logger: Logger, listener: ProxyControlListenerEndpoint) {
        self.logger = logger
        self.listener = listener
        super.init()
        self.listener.delegate = self
    }

    func start() {
        // Filter unauthorized peers at the listener, before delegate admission.
        // Without this a same-user process can occupy the single connection slot
        // faster than its per-connection signing failure is delivered, starving
        // the agent and holding protection in permanent bypass.
        listener.setConnectionCodeSigningRequirement(proxyControlAgentRequirement)
        listener.resume()
    }

    func stop() {
        setState(.bypass(.stopping))
        let owned = lock.withLock { () -> ProxyControlConnection? in
            let connection = activeConnection
            activeConnection = nil
            session = nil
            return connection
        }
        // Lifecycle callbacks run on the connection's message queue with no
        // documented asynchrony, so invalidate outside the non-recursive lock.
        owned?.invalidate()
        listener.invalidate()
    }

    var currentSession: ProxyControlSession? { lock.withLock { session } }
    var currentState: ProxyInterceptionState { lock.withLock { state } }

    /// True while `sessionID` still identifies the live control session. A probe
    /// result only applies to the session that produced it.
    func isCurrentSession(_ sessionID: String) -> Bool {
        lock.withLock { session?.sessionIDHex == sessionID }
    }

    func setState(_ newState: ProxyInterceptionState) {
        lock.withLock { state = newState }
    }

    /// Publishes `intercepting` only while `sessionID` still identifies the live
    /// session, running `leaveBypass` in the same critical section that checks
    /// it. A session cleared between a probe and its decision therefore cannot
    /// be overwritten by the stale result: either the whole commit lands first
    /// and the loss forces bypass right after it, or the commit is refused.
    func commitIntercepting(sessionID: String, leaveBypass: () -> Void) -> Bool {
        lock.withLock {
            guard session?.sessionIDHex == sessionID else { return false }
            leaveBypass()
            state = .intercepting(sessionID: sessionID)
            return true
        }
    }

    func listener(
        _ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        accept(newConnection)
    }

    /// Claims the single control slot under the lock, then configures and resumes
    /// outside it. The listener lock must never be held across a connection
    /// lifecycle callback.
    func accept(_ newConnection: ProxyControlConnection) -> Bool {
        let claimed: Bool = lock.withLock {
            guard activeConnection == nil else { return false }
            activeConnection = newConnection
            return true
        }
        guard claimed else {
            logger.notice("Control connection rejected")
            return false
        }
        // Defence in depth: the listener already filtered this peer.
        newConnection.setCodeSigningRequirement(proxyControlAgentRequirement)
        newConnection.exportedInterface = NSXPCInterface(with: MacDNSProxyControlProtocol.self)
        newConnection.exportedObject = self
        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            self?.handleConnectionLost(newConnection)
        }
        newConnection.interruptionHandler = { [weak self, weak newConnection] in
            self?.handleConnectionLost(newConnection)
        }
        newConnection.resume()
        return true
    }

    private func handleConnectionLost(_ connection: ProxyControlConnection?) {
        let owned: Bool = lock.withLock {
            guard let connection, activeConnection === connection else { return false }
            activeConnection = nil
            session = nil
            state = .bypass(.agentUnavailable)
            return true
        }
        guard owned else { return }
        logger.warning("Control connection lost; session cleared, bypass forced")
        onSessionLost?()
    }

    /// Retires the live session before a replacement is published. Every
    /// decision taken under it, including an active interception, was proven
    /// by challenges the replacement cannot answer until the agent installs it
    /// in the resolver, so bypass is forced here exactly as on a session loss.
    private func retireSessionForReplacement() {
        let replaced: Bool = lock.withLock {
            guard session != nil else { return false }
            session = nil
            state = .bypass(.sessionUnavailable)
            return true
        }
        guard replaced else { return }
        logger.notice("Control session replaced; bypass forced")
        onSessionLost?()
    }

    func beginControlSession(withReply reply: @escaping (Data?) -> Void) {
        guard let newSession = ProxyControlSession.generate() else {
            logger.error("Failed to generate control session")
            reply(nil)
            return
        }
        retireSessionForReplacement()
        lock.withLock { session = newSession }
        // Match Shared.ProxyControlBootstrap Codable JSON (Data encodes base64).
        // The staged copy of the raw key is wiped as soon as it is encoded.
        let keyBase64 = newSession.hmacKey.withUnsafeBytes { raw -> String in
            var staged = Data(raw)
            defer { staged.resetBytes(in: 0..<staged.count) }
            return staged.base64EncodedString()
        }
        let boot: [String: Any] = [
            "version": Int(newSession.version),
            "sessionID": newSession.sessionID.base64EncodedString(),
            "hmacKey": keyBase64,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: boot),
            data.count <= maxPayloadBytes
        else {
            reply(nil)
            return
        }
        logger.notice("Issued control session \(newSession.sessionIDHex.prefix(8), privacy: .public)")
        onSessionIssued?(newSession)
        reply(data)
    }

    func currentProviderState(withReply reply: @escaping (Data?) -> Void) {
        reply(currentState.encodedReport(providerVersion: providerVersion))
    }
}
