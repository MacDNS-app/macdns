// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import XCTest

@testable import DNSProxyExtension

final class ProxyProbeDiagnosticsTests: XCTestCase {
    private func report(
        udp: ProxyControlChallengeOutcome = .ready,
        tcp: ProxyControlChallengeOutcome = .ready,
        elapsed: UInt64 = 12
    ) -> ProxyProbeReport {
        ProxyProbeReport(
            udp: .init(outcome: udp, elapsedMilliseconds: elapsed),
            tcp: .init(outcome: tcp, elapsedMilliseconds: elapsed + 3))
    }

    func testRepeatedFailureDoesNotLogAgainWhenOnlyDurationChanges() {
        var diagnostics = ProxyProbeDiagnostics()
        let failure = ProxyControlChallengeOutcome.failed(
            .init(stage: .readBody, reason: .timeout))

        XCTAssertTrue(diagnostics.record(report(tcp: failure)))
        XCTAssertFalse(diagnostics.record(report(tcp: failure, elapsed: 2000)))
        XCTAssertFalse(diagnostics.record(report(tcp: failure, elapsed: 2001)))
    }

    func testChangedFailureAndRecoveryAllowTheNextFailureToBeLogged() {
        var diagnostics = ProxyProbeDiagnostics()
        let timeout = ProxyControlChallengeOutcome.failed(
            .init(stage: .readBody, reason: .timeout))
        let refused = ProxyControlChallengeOutcome.failed(
            .init(stage: .connect, reason: .systemError(ECONNREFUSED)))

        XCTAssertTrue(diagnostics.record(report(tcp: timeout)))
        XCTAssertTrue(diagnostics.record(report(tcp: refused)))
        XCTAssertFalse(diagnostics.record(report(tcp: refused)))
        XCTAssertTrue(diagnostics.record(report()))
        XCTAssertFalse(diagnostics.record(report()))
        XCTAssertTrue(diagnostics.record(report(tcp: refused)))
    }

    func testUnauthenticatedTransportAndSignedNotReadyRemainDistinct() {
        var diagnostics = ProxyProbeDiagnostics()
        let failed = ProxyControlChallengeOutcome.failed(
            .init(stage: .authentication, reason: .authenticationMismatch))

        XCTAssertTrue(diagnostics.record(report(udp: failed)))
        XCTAssertTrue(diagnostics.record(report(udp: .notReady)))
        XCTAssertFalse(diagnostics.record(report(udp: .notReady)))
    }

    func testSessionLossResetsFailureDeduplication() {
        var diagnostics = ProxyProbeDiagnostics()
        let failed = report(tcp: .failed(.init(stage: .connect, reason: .timeout)))

        XCTAssertTrue(diagnostics.record(failed))
        XCTAssertFalse(diagnostics.record(failed))
        XCTAssertTrue(diagnostics.record(nil))
        XCTAssertTrue(diagnostics.record(failed))
    }

    func testDiagnosticSummaryIncludesBothTransportsWithoutResponseMaterial() {
        let result = report(
            tcp: .failed(.init(stage: .send, reason: .systemError(EPIPE))), elapsed: 15)

        XCTAssertEqual(
            result.summary,
            "udp=ready elapsed_ms=15 tcp=failed stage=send reason=systemError errno=32 elapsed_ms=18")
    }
}

final class BSDUDPProbeTests: XCTestCase {
    func testSilentLocalPeerReportsReceiveTimeout() throws {
        let peer = try LoopbackUDPSocket()

        let started = DispatchTime.now().uptimeNanoseconds
        let result = BSDUDPProbe.exchange(
            query: Data([0x12, 0x34]), address: peer.address, timeout: 0.03)
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000_000

        XCTAssertEqual(result, .failure(.init(stage: .readBody, reason: .timeout)))
        XCTAssertLessThan(elapsed, 0.5)
        XCTAssertEqual(peer.receive(), [0x12, 0x34])
    }

    func testLocalResponseIsReturnedUnchangedForAuthentication() throws {
        let peer = try LoopbackUDPSocket()
        let responded = expectation(description: "Peer answered the probe")
        DispatchQueue.global().async {
            defer { responded.fulfill() }
            guard let received = peer.receiveWithSender() else {
                XCTFail("Expected the probe query")
                return
            }
            XCTAssertEqual(received.bytes, [0x12, 0x34])
            peer.send([0x12, 0x34, 0x81, 0x80], to: received.sender)
        }

        let result = BSDUDPProbe.exchange(
            query: Data([0x12, 0x34]), address: peer.address, timeout: 1)

        XCTAssertEqual(result, .success(Data([0x12, 0x34, 0x81, 0x80])))
        wait(for: [responded], timeout: 1)
    }
}
