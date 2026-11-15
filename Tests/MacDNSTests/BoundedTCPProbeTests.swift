// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import XCTest

@testable import DNSProxyExtension

/// Fake transport driving the probe against the two shapes socket timeouts
/// cannot bound: a connect that never completes (Darwin ignores `SO_SNDTIMEO`
/// for `connect`) and a peer dribbling bytes forever (`SO_RCVTIMEO` restarts on
/// every partial read).
private final class FakeProbeTransport: BoundedTCPProbeTransport {
    enum Behaviour {
        case connectNeverCompletes
        case dribblesForever
        case respondsFully(Data)
        case connectRefused
        case sendFails
        case closesBeforeLength
        case closesDuringBody
        case invalidLength
    }

    private let behaviour: Behaviour
    private var response = Data()
    /// Length prefix the dribbling peer promises before trickling the payload.
    private var promisedLengthPrefix = Data([0x10, 0x00])
    private(set) var sentBytes = Data()
    private(set) var closeCount = 0
    private(set) var failureReason = ProxyProbeFailure.Reason.unavailable

    init(_ behaviour: Behaviour) {
        self.behaviour = behaviour
        if case .respondsFully(let payload) = behaviour {
            response = Data([UInt8(payload.count >> 8), UInt8(payload.count & 0xFF)])
            response.append(payload)
        } else if case .closesDuringBody = behaviour {
            response = Data([0x00, 0x04, 0xAA])
        } else if case .invalidLength = behaviour {
            response = Data([0x10, 0x01])
        }
    }

    func startConnect() -> Bool {
        if case .connectRefused = behaviour {
            failureReason = .systemError(ECONNREFUSED)
            return false
        }
        return true
    }

    func waitWritable(milliseconds: Int32) -> ProbeWaitOutcome {
        if case .connectNeverCompletes = behaviour {
            // Model poll() burning the whole budget it was handed.
            sleepMilliseconds(milliseconds)
            return .timedOut
        }
        return .ready
    }

    func pendingConnectError() -> Int32 { 0 }

    func send(_ data: Data) -> Int {
        if case .sendFails = behaviour {
            failureReason = .systemError(EPIPE)
            return -1
        }
        sentBytes.append(data)
        return data.count
    }

    func waitReadable(milliseconds: Int32) -> ProbeWaitOutcome {
        sleepMilliseconds(min(milliseconds, 1))
        return .ready
    }

    func receive(maxLength: Int) -> Data? {
        switch behaviour {
        case .dribblesForever:
            // Announce a 4096-byte answer, then trickle one byte per read forever.
            if let next = promisedLengthPrefix.first {
                promisedLengthPrefix = Data(promisedLengthPrefix.dropFirst())
                return Data([next])
            }
            return Data([0xAB])
        case .respondsFully, .closesDuringBody, .invalidLength:
            guard !response.isEmpty else {
                failureReason = .connectionClosed
                return nil
            }
            let count = min(maxLength, response.count)
            let chunk = response.prefix(count)
            response = Data(response.dropFirst(count))
            return Data(chunk)
        default:
            failureReason = .connectionClosed
            return nil
        }
    }

    func close() {
        closeCount += 1
    }

    private func sleepMilliseconds(_ milliseconds: Int32) {
        guard milliseconds > 0 else { return }
        usleep(useconds_t(milliseconds) * 1000)
    }
}

final class BoundedTCPProbeTests: XCTestCase {
    private let timeout: TimeInterval = 0.2
    private let query = Data([0x12, 0x34, 0x01, 0x00])

    private func exchange(_ transport: FakeProbeTransport) -> (Data?, TimeInterval) {
        let started = Date()
        let result = BoundedTCPProbe.exchange(
            transport: transport, query: query,
            deadline: ProbeDeadline(timeout: timeout), maxResponseBytes: 4096)
        return (try? result.get(), Date().timeIntervalSince(started))
    }

    func testNeverCompletingConnectFinishesWithinTheDeadline() {
        let transport = FakeProbeTransport(.connectNeverCompletes)

        let (result, elapsed) = exchange(transport)

        XCTAssertNil(result)
        XCTAssertLessThan(
            elapsed, timeout * 2,
            "a stalled connect must be bounded by the probe deadline, not by XNU's ~75s TCP timeout")
        XCTAssertEqual(transport.closeCount, 1)
    }

    func testByteDribblingPeerFinishesWithinTheDeadline() {
        let transport = FakeProbeTransport(.dribblesForever)

        let (result, elapsed) = exchange(transport)

        XCTAssertNil(result)
        XCTAssertLessThan(
            elapsed, timeout * 2,
            "every read must share one absolute deadline; a per-read inactivity timeout never expires")
        XCTAssertEqual(transport.closeCount, 1)
    }

    func testFullResponseIsReturnedAndFramedQueryIsSent() {
        let payload = Data((0..<48).map { UInt8($0) })
        let transport = FakeProbeTransport(.respondsFully(payload))

        let (result, _) = exchange(transport)

        XCTAssertEqual(result, payload)
        XCTAssertEqual(
            transport.sentBytes,
            Data([0x00, UInt8(query.count)]) + query,
            "DNS-over-TCP requires the 2-byte big-endian length prefix")
        XCTAssertEqual(transport.closeCount, 1)
    }

    func testImmediateConnectFailureClosesTheSocket() {
        let transport = FakeProbeTransport(.connectRefused)

        let (result, _) = exchange(transport)

        XCTAssertNil(result)
        XCTAssertEqual(transport.closeCount, 1)
    }

    func testFailureDiagnosticsIdentifyTheTransportStageAndCause() {
        let cases: [(FakeProbeTransport.Behaviour, ProxyProbeFailure)] = [
            (.connectNeverCompletes, .init(stage: .connect, reason: .timeout)),
            (.connectRefused, .init(stage: .connect, reason: .systemError(ECONNREFUSED))),
            (.sendFails, .init(stage: .send, reason: .systemError(EPIPE))),
            (.closesBeforeLength, .init(stage: .readLength, reason: .connectionClosed)),
            (.closesDuringBody, .init(stage: .readBody, reason: .connectionClosed)),
            (.invalidLength, .init(stage: .readLength, reason: .invalidResponseLength)),
            (.dribblesForever, .init(stage: .readBody, reason: .timeout)),
        ]

        for (behaviour, expectedFailure) in cases {
            let transport = FakeProbeTransport(behaviour)
            let result = BoundedTCPProbe.exchange(
                transport: transport, query: query,
                deadline: ProbeDeadline(timeout: 0.03), maxResponseBytes: 4096)

            XCTAssertEqual(result, .failure(expectedFailure))
            XCTAssertEqual(transport.closeCount, 1)
        }
    }

    func testDeadlineExpiresAndNeverReportsRemainingBudget() {
        let now: UInt64 = 1_000_000_000
        let deadline = ProbeDeadline(timeout: 2, now: now)

        XCTAssertEqual(deadline.remainingMilliseconds(now: now), 2000)
        XCTAssertEqual(deadline.remainingMilliseconds(now: now + 1_500_000_000), 500)
        XCTAssertNil(deadline.remainingMilliseconds(now: now + 2_000_000_000))
        XCTAssertNil(deadline.remainingMilliseconds(now: now + 90_000_000_000))
    }
}

final class BSDBoundedTCPProbeTransportTests: XCTestCase {
    private func loopbackAddress() -> sockaddr_in {
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(5335).bigEndian
        address.sin_len = __uint8_t(MemoryLayout<sockaddr_in>.size)
        _ = inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)
        return address
    }

    func testProbeSocketIsConfiguredToRaiseEPIPEInsteadOfSIGPIPE() {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { Darwin.close(fd) }

        XCTAssertTrue(BSDBoundedTCPProbeTransport.configureSocket(fd))

        var noSigpipe: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        XCTAssertEqual(getsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe, &length), 0)
        XCTAssertNotEqual(
            noSigpipe, 0,
            "without SO_NOSIGPIPE a resolver reset mid-probe kills the DNS Proxy process")
        XCTAssertNotEqual(
            fcntl(fd, F_GETFL, 0) & O_NONBLOCK, 0,
            "the probe drives the socket with poll() and requires non-blocking mode")
    }

    func testConfigurationFailureIsReportedInsteadOfLeavingSIGPIPEEnabled() {
        XCTAssertFalse(
            BSDBoundedTCPProbeTransport.configureSocket(-1),
            "a socket whose options cannot be set must fail transport creation")
    }

    func testTransportIsCreatedWhenTheSocketCanBeConfigured() {
        XCTAssertNotNil(
            try? BSDBoundedTCPProbeTransport(address: loopbackAddress()),
            "the configuration guard must not reject usable sockets and disable every TCP probe")
    }
}
