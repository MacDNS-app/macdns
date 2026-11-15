// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest
import os.log

@testable import DNSProxyExtension

/// Fake XPC connection. `signingIdentity` is the requirement string this peer
/// would satisfy, so the fake listener can model runtime-level filtering.
private final class FakeControlConnection: ProxyControlConnection {
    let signingIdentity: String
    var exportedInterface: NSXPCInterface?
    var exportedObject: Any?
    var invalidationHandler: (() -> Void)?
    var interruptionHandler: (() -> Void)?
    private(set) var requirement: String?
    private(set) var resumeCount = 0
    private(set) var invalidateCount = 0
    /// Apple never documents lifecycle callbacks as asynchronous, so the fake
    /// runs them synchronously on the calling thread.
    var dropsOnResume = false
    var invalidatesSynchronously = false

    init(signingIdentity: String) {
        self.signingIdentity = signingIdentity
    }

    func setCodeSigningRequirement(_ requirement: String) {
        self.requirement = requirement
    }

    func resume() {
        resumeCount += 1
        if dropsOnResume { invalidationHandler?() }
    }

    func invalidate() {
        invalidateCount += 1
        if invalidatesSynchronously { invalidationHandler?() }
    }
}

/// Stands in for the provider's bypass flag, which is written from the commit
/// path and from the session-loss callback on different threads.
private final class BypassFlagBox: @unchecked Sendable {
    private let lock = NSLock()
    private var bypass: Bool

    init(bypass: Bool) {
        self.bypass = bypass
    }

    func set(_ value: Bool) {
        lock.withLock { bypass = value }
    }

    var value: Bool {
        lock.withLock { bypass }
    }
}

private final class FakeListenerEndpoint: ProxyControlListenerEndpoint {
    weak var delegate: NSXPCListenerDelegate?
    private(set) var connectionRequirement: String?
    private(set) var requirementInstalledBeforeResume = false
    private(set) var resumeCount = 0
    private(set) var invalidateCount = 0
    var admit: ((FakeControlConnection) -> Bool)?

    func setConnectionCodeSigningRequirement(_ requirement: String) {
        connectionRequirement = requirement
    }

    func resume() {
        requirementInstalledBeforeResume = connectionRequirement != nil
        resumeCount += 1
    }

    func invalidate() {
        invalidateCount += 1
    }

    /// Models the XPC runtime: a listener-level requirement filters peers before
    /// delegate admission. Without one every peer reaches the delegate.
    func deliver(_ connection: FakeControlConnection) -> Bool {
        guard resumeCount > 0 else { return false }
        if let connectionRequirement, connection.signingIdentity != connectionRequirement {
            return false
        }
        return admit?(connection) ?? false
    }
}

final class ProxyControlListenerTests: XCTestCase {
    private let logger = Logger(subsystem: "app.macdns.dnsproxy.tests", category: "control")

    private func makeListener() -> (ProxyControlListener, FakeListenerEndpoint) {
        let endpoint = FakeListenerEndpoint()
        let listener = ProxyControlListener(logger: logger, listener: endpoint)
        endpoint.admit = { listener.accept($0) }
        return (listener, endpoint)
    }

    private func agentConnection() -> FakeControlConnection {
        FakeControlConnection(signingIdentity: proxyControlAgentRequirement)
    }

    private func unauthorizedConnection() -> FakeControlConnection {
        FakeControlConnection(signingIdentity: "identifier \"app.attacker.helper\"")
    }

    // MARK: - Listener-level peer filtering

    func testListenerInstallsSigningRequirementBeforeResume() {
        let (listener, endpoint) = makeListener()

        listener.start()

        XCTAssertEqual(endpoint.connectionRequirement, proxyControlAgentRequirement)
        XCTAssertTrue(
            endpoint.requirementInstalledBeforeResume,
            "the requirement must be installed before resume, otherwise unauthorized peers "
                + "reach the delegate")
    }

    func testUnauthorizedFloodCannotOccupyTheSingleConnectionSlot() {
        let (listener, endpoint) = makeListener()
        listener.start()

        for _ in 0..<32 {
            XCTAssertFalse(endpoint.deliver(unauthorizedConnection()))
        }

        let agent = agentConnection()
        XCTAssertTrue(endpoint.deliver(agent))
        XCTAssertEqual(agent.resumeCount, 1)
        XCTAssertEqual(agent.requirement, proxyControlAgentRequirement)
    }

    func testSecondAuthorizedConnectionIsRejectedWhileTheSlotIsOwned() {
        let (listener, endpoint) = makeListener()
        listener.start()

        XCTAssertTrue(endpoint.deliver(agentConnection()))
        XCTAssertFalse(endpoint.deliver(agentConnection()))
    }

    // MARK: - Lock ownership

    func testStopInvalidatesTheConnectionOutsideTheLock() {
        let (listener, endpoint) = makeListener()
        listener.start()
        let agent = agentConnection()
        agent.invalidatesSynchronously = true
        XCTAssertTrue(endpoint.deliver(agent))

        let finished = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            listener.stop()
            finished.signal()
        }

        XCTAssertEqual(
            finished.wait(timeout: .now() + 2), .success,
            "stop() deadlocked: invalidate must run outside the listener lock")
        XCTAssertEqual(endpoint.invalidateCount, 1)
    }

    func testAcceptResumesTheConnectionOutsideTheLock() {
        let (listener, endpoint) = makeListener()
        listener.start()
        let agent = agentConnection()
        agent.dropsOnResume = true

        let finished = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            _ = endpoint.deliver(agent)
            finished.signal()
        }

        XCTAssertEqual(
            finished.wait(timeout: .now() + 2), .success,
            "accept() deadlocked: resume must run outside the listener lock")
        XCTAssertNil(listener.currentSession)
    }

    // MARK: - Immediate bypass on session loss

    func testInterruptionClearsTheSessionAndReportsLoss() {
        let (listener, endpoint) = makeListener()
        listener.start()
        let agent = agentConnection()
        XCTAssertTrue(endpoint.deliver(agent))
        installSession(on: listener)

        var lostCount = 0
        listener.onSessionLost = { lostCount += 1 }
        XCTAssertNotNil(
            agent.interruptionHandler,
            "an interrupted control connection must be reported, not only an invalidated one")
        agent.interruptionHandler?()

        XCTAssertEqual(lostCount, 1)
        XCTAssertNil(listener.currentSession)
        XCTAssertEqual(listener.currentState, .bypass(.agentUnavailable))
    }

    func testSessionLossCallbackRunsOutsideTheLock() {
        let (listener, endpoint) = makeListener()
        listener.start()
        let agent = agentConnection()
        XCTAssertTrue(endpoint.deliver(agent))
        installSession(on: listener)

        let reported = DispatchSemaphore(value: 0)
        var observedState: ProxyInterceptionState?
        listener.onSessionLost = {
            observedState = listener.currentState
            reported.signal()
        }

        DispatchQueue.global().async { agent.invalidationHandler?() }

        XCTAssertEqual(
            reported.wait(timeout: .now() + 2), .success,
            "onSessionLost deadlocked: it must be invoked outside the listener lock")
        XCTAssertEqual(observedState, .bypass(.agentUnavailable))
    }

    func testProbeResultFromALostSessionIsNoLongerCurrent() {
        let (listener, endpoint) = makeListener()
        listener.start()
        let agent = agentConnection()
        XCTAssertTrue(endpoint.deliver(agent))
        let session = installSession(on: listener)

        XCTAssertTrue(listener.isCurrentSession(session.sessionIDHex))
        agent.invalidationHandler?()
        XCTAssertFalse(listener.isCurrentSession(session.sessionIDHex))
    }

    func testStaleConnectionLossDoesNotClearTheCurrentSession() {
        let (listener, endpoint) = makeListener()
        listener.start()
        let first = agentConnection()
        XCTAssertTrue(endpoint.deliver(first))
        first.invalidationHandler?()

        let second = agentConnection()
        XCTAssertTrue(endpoint.deliver(second))
        let session = installSession(on: listener)

        first.invalidationHandler?()

        XCTAssertTrue(listener.isCurrentSession(session.sessionIDHex))
    }

    // MARK: - Atomic interception commit

    /// A health evaluation that validated the session, then lost it before
    /// applying its decision, must not be able to claim interception.
    func testInterceptCommitIsRefusedWhenTheSessionIsLostAfterValidation() {
        let (listener, endpoint) = makeListener()
        listener.start()
        let agent = agentConnection()
        XCTAssertTrue(endpoint.deliver(agent))
        let session = installSession(on: listener)

        XCTAssertTrue(listener.isCurrentSession(session.sessionIDHex))
        agent.invalidationHandler?()

        var leftBypass = false
        XCTAssertFalse(
            listener.commitIntercepting(sessionID: session.sessionIDHex) { leftBypass = true },
            "a decision computed for a session that is gone must not be committed")
        XCTAssertFalse(leftBypass)
        XCTAssertEqual(listener.currentState, .bypass(.agentUnavailable))
    }

    /// Drives the interleaving directly: the control connection is lost while a
    /// decision computed for the live session is being committed. Whoever wins,
    /// interception must never stay published once the session is cleared.
    func testSessionLostDuringACommitNeverLeavesInterceptionPublished() {
        let (listener, endpoint) = makeListener()
        listener.start()
        let agent = agentConnection()
        XCTAssertTrue(endpoint.deliver(agent))
        let session = installSession(on: listener)

        let bypassed = BypassFlagBox(bypass: false)
        let lossReported = BypassFlagBox(bypass: false)
        let lossGate = DispatchSemaphore(value: 0)
        listener.onSessionLost = {
            bypassed.set(true)
            lossReported.set(true)
            lossGate.signal()
        }

        let committing = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            _ = listener.commitIntercepting(sessionID: session.sessionIDHex) {
                bypassed.set(false)
                // Hands over to the connection loss from inside the commit,
                // the window a check-then-apply sequence leaves open.
                committing.signal()
                _ = lossGate.wait(timeout: .now() + 0.2)
            }
            finished.signal()
        }

        XCTAssertEqual(committing.wait(timeout: .now() + 2), .success)
        agent.invalidationHandler?()
        XCTAssertEqual(finished.wait(timeout: .now() + 2), .success)

        XCTAssertTrue(lossReported.value)
        XCTAssertNil(listener.currentSession)
        XCTAssertNotEqual(
            listener.currentState, .intercepting(sessionID: session.sessionIDHex),
            "interception stayed published after the session was cleared")
        XCTAssertTrue(bypassed.value, "bypass must be forced once the session is gone")
    }

    // MARK: - Session replacement

    /// Replacing a live session while the provider intercepts must force bypass
    /// synchronously, before the replacement is published and long before the
    /// agent installs it in the resolver.
    func testReplacingALiveSessionForcesBypassBeforeTheReply() {
        let (listener, endpoint) = makeListener()
        listener.start()
        XCTAssertTrue(endpoint.deliver(agentConnection()))
        let first = installSession(on: listener)

        var leftBypass = false
        XCTAssertTrue(
            listener.commitIntercepting(sessionID: first.sessionIDHex) { leftBypass = true })
        XCTAssertTrue(leftBypass)
        XCTAssertEqual(listener.currentState, .intercepting(sessionID: first.sessionIDHex))

        var replied = false
        var lostCount = 0
        var lostBeforeReply = false
        listener.onSessionLost = {
            lostCount += 1
            lostBeforeReply = !replied
            leftBypass = false
        }

        let issued = expectation(description: "replacement session issued")
        listener.beginControlSession { data in
            XCTAssertNotNil(data)
            replied = true
            issued.fulfill()
        }
        wait(for: [issued], timeout: 2)

        XCTAssertEqual(lostCount, 1, "replacing a live session must report it as lost")
        XCTAssertTrue(lostBeforeReply, "bypass must be forced before the bootstrap is replied")
        XCTAssertFalse(leftBypass)
        XCTAssertEqual(listener.currentState, .bypass(.sessionUnavailable))
        guard let second = listener.currentSession else {
            return XCTFail("expected the replacement session to be installed")
        }
        XCTAssertNotEqual(second.sessionIDHex, first.sessionIDHex)
        XCTAssertFalse(
            listener.isCurrentSession(first.sessionIDHex),
            "the replaced session must stop being current")
    }

    /// The first bootstrap of a connection replaces nothing, so it must not
    /// report a session loss.
    func testFirstSessionIssueDoesNotReportALoss() {
        let (listener, endpoint) = makeListener()
        listener.start()
        XCTAssertTrue(endpoint.deliver(agentConnection()))

        var lostCount = 0
        listener.onSessionLost = { lostCount += 1 }
        installSession(on: listener)

        XCTAssertEqual(lostCount, 0)
    }

    @discardableResult
    private func installSession(on listener: ProxyControlListener) -> ProxyControlSession {
        let replied = expectation(description: "session issued")
        listener.beginControlSession { data in
            XCTAssertNotNil(data)
            replied.fulfill()
        }
        wait(for: [replied], timeout: 2)
        guard let session = listener.currentSession else {
            XCTFail("expected an installed session")
            return ProxyControlSession(version: 1, sessionID: Data(), hmacKey: Data())
        }
        return session
    }
}
