// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import DNSProxyExtension

final class DNSProxyHealthPolicyTests: XCTestCase {
    private func inputs(
        session: Bool = true, udp: Bool = true, tcp: Bool = true,
        ready: Bool = true, dns: Bool = true
    ) -> DNSProxyHealthInputs {
        DNSProxyHealthInputs(
            sessionInstalled: session, udpVerified: udp, tcpVerified: tcp,
            readyBit: ready, dnsDestinationsPresent: dns)
    }

    private func decide(_ i: DNSProxyHealthInputs) -> DNSProxyHealthDecision {
        DNSProxyHealthEvaluator.decide(i, sessionID: "abcd")
    }

    func testAllGoodIntercepts() {
        guard case .intercept(let id) = decide(inputs()) else {
            return XCTFail("expected intercept")
        }
        XCTAssertEqual(id, "abcd")
    }

    func testMissingSessionBypasses() {
        guard case .bypass(.sessionUnavailable) = decide(inputs(session: false)) else {
            return XCTFail("expected sessionUnavailable")
        }
    }

    /// Both transports authenticated, and both signed `ready = 0`. That is the
    /// only shape in which the resolver itself is the root cause.
    func testAuthenticatedReadyZeroBlamesTheResolver() {
        guard case .bypass(.resolverNotReady) = decide(inputs(ready: false)) else {
            return XCTFail("expected resolverNotReady")
        }
    }

    /// A transport that never authenticated cannot report readiness, so the
    /// production input always carries `ready: false` with it.
    func testUDPTransportFailureBlamesTheProbe() {
        guard case .bypass(.probeFailed) = decide(inputs(udp: false, ready: false)) else {
            return XCTFail("expected probeFailed")
        }
    }

    func testTCPTransportFailureBlamesTheProbe() {
        guard case .bypass(.probeFailed) = decide(inputs(tcp: false, ready: false)) else {
            return XCTFail("expected probeFailed")
        }
    }

    func testBothTransportsFailingBlamesTheProbe() {
        guard case .bypass(.probeFailed) = decide(inputs(udp: false, tcp: false, ready: false))
        else {
            return XCTFail("expected probeFailed")
        }
    }

    func testEmptyDNSBypasses() {
        guard case .bypass(.dnsDestinationsUnavailable) = decide(inputs(dns: false)) else {
            return XCTFail("expected dnsDestinationsUnavailable")
        }
    }

    // MARK: - Probe outcome mapping

    private func decide(
        udp: ProxyControlChallengeOutcome, tcp: ProxyControlChallengeOutcome
    ) -> DNSProxyHealthDecision {
        decide(
            DNSProxyHealthInputs(
                sessionInstalled: true, udp: udp, tcp: tcp, dnsDestinationsPresent: true))
    }

    func testUnreachableTransportIsReportedAsAProbeFailure() {
        let failed = ProxyControlChallengeOutcome.failed(
            .init(stage: .readBody, reason: .timeout))
        guard case .bypass(.probeFailed) = decide(udp: failed, tcp: .ready) else {
            return XCTFail("expected probeFailed for an unauthenticated UDP transport")
        }
        guard case .bypass(.probeFailed) = decide(udp: .ready, tcp: failed) else {
            return XCTFail("expected probeFailed for an unauthenticated TCP transport")
        }
    }

    func testAuthenticatedNotReadyIsReportedAsResolverNotReady() {
        guard case .bypass(.resolverNotReady) = decide(udp: .notReady, tcp: .notReady) else {
            return XCTFail("expected resolverNotReady")
        }
        guard case .bypass(.resolverNotReady) = decide(udp: .ready, tcp: .notReady) else {
            return XCTFail("expected resolverNotReady when one transport signed zero")
        }
    }

    func testBothTransportsReadyIntercepts() {
        guard case .intercept = decide(udp: .ready, tcp: .ready) else {
            return XCTFail("expected intercept")
        }
    }

    // MARK: - Unanswered probe rounds

    private func report(
        udp: ProxyControlChallengeOutcome, tcp: ProxyControlChallengeOutcome
    ) -> ProxyProbeReport {
        ProxyProbeReport(
            udp: ProxyProbeResult(outcome: udp, elapsedMilliseconds: 0),
            tcp: ProxyProbeResult(outcome: tcp, elapsedMilliseconds: 0))
    }

    private let unanswered = ProxyControlChallengeOutcome.failed(
        .init(stage: .readBody, reason: .timeout))

    func testFirstUnansweredRoundWhileInterceptingIsRepeated() {
        var policy = DNSProxyProbeRetryPolicy()
        XCTAssertTrue(
            policy.shouldRepeat(
                .bypass(.probeFailed), probes: report(udp: unanswered, tcp: .ready),
                intercepting: true))
    }

    func testSecondUnansweredRoundBypasses() {
        var policy = DNSProxyProbeRetryPolicy()
        let probes = report(udp: .ready, tcp: unanswered)
        _ = policy.shouldRepeat(.bypass(.probeFailed), probes: probes, intercepting: true)
        XCTAssertFalse(
            policy.shouldRepeat(.bypass(.probeFailed), probes: probes, intercepting: true))
    }

    func testAnAnsweredRoundStartsTheCountAgain() {
        var policy = DNSProxyProbeRetryPolicy()
        let failed = report(udp: unanswered, tcp: unanswered)
        _ = policy.shouldRepeat(.bypass(.probeFailed), probes: failed, intercepting: true)
        XCTAssertFalse(
            policy.shouldRepeat(
                .intercept(sessionID: "abcd"), probes: report(udp: .ready, tcp: .ready),
                intercepting: true))
        XCTAssertTrue(
            policy.shouldRepeat(.bypass(.probeFailed), probes: failed, intercepting: true))
    }

    /// An answer that fails validation may come from something else listening
    /// on the resolver port, so no more queries go there.
    func testARejectedAnswerIsNeverRepeated() {
        for reason: ProxyProbeFailure.Reason in [
            .authenticationMismatch, .invalidResponse, .invalidResponseLength,
        ] {
            var policy = DNSProxyProbeRetryPolicy()
            let rejected = ProxyControlChallengeOutcome.failed(
                .init(stage: .authentication, reason: reason))
            XCTAssertFalse(
                policy.shouldRepeat(
                    .bypass(.probeFailed), probes: report(udp: rejected, tcp: unanswered),
                    intercepting: true),
                "\(reason) must bypass at once")
        }
    }

    func testAnAuthenticatedNotReadyIsNeverRepeated() {
        var policy = DNSProxyProbeRetryPolicy()
        XCTAssertFalse(
            policy.shouldRepeat(
                .bypass(.resolverNotReady), probes: report(udp: .notReady, tcp: .notReady),
                intercepting: true))
    }

    /// One transport signing `ready = 0` is the resolver's answer, whatever
    /// happened to the other transport.
    func testANotReadyOnOneTransportIsNeverRepeated() {
        for (udp, tcp) in [(.notReady, unanswered), (unanswered, .notReady)] {
            var policy = DNSProxyProbeRetryPolicy()
            XCTAssertFalse(
                policy.shouldRepeat(
                    .bypass(.probeFailed), probes: report(udp: udp, tcp: tcp),
                    intercepting: true),
                "udp=\(udp) tcp=\(tcp) must bypass at once")
        }
    }

    func testAnUnansweredRoundInBypassIsNotRepeated() {
        var policy = DNSProxyProbeRetryPolicy()
        XCTAssertFalse(
            policy.shouldRepeat(
                .bypass(.probeFailed), probes: report(udp: unanswered, tcp: unanswered),
                intercepting: false))
    }
}
