// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import XCTest

@testable import DNSProxyExtension

final class ResolverSocketPoolTests: XCTestCase {
    private let queue = DispatchQueue(label: "app.macdns.tests.resolver-pool")

    private func makePool(resolver: LoopbackUDPSocket, poolSize: Int = 2) throws -> ResolverSocketPool {
        try XCTUnwrap(
            ResolverSocketPool(host: "127.0.0.1", port: resolver.port, poolSize: poolSize, queue: queue))
    }

    private func replyEchoing(_ received: [UInt8]) -> [UInt8] {
        var reply = received
        reply[2] = DNSWire.responseFlags.0
        reply[3] = DNSWire.responseFlags.1
        return reply
    }

    func testPoolWithoutAnyConnectedSocketIsNotCreated() throws {
        let resolver = try LoopbackUDPSocket()

        XCTAssertNil(ResolverSocketPool(host: "127.0.0.1", port: resolver.port, poolSize: 0, queue: queue))
    }

    func testPoolWithAnUnparsableHostIsNotCreated() {
        XCTAssertNil(ResolverSocketPool(host: "resolver.invalid", port: 5335, poolSize: 2, queue: queue))
    }

    func testResponseIsReturnedWithTheClientTransactionIDRestored() throws {
        let resolver = try LoopbackUDPSocket()
        let pool = try makePool(resolver: resolver)
        defer { pool.shutdown() }
        let query = DNSWire.message(id: 0x1234, flags: DNSWire.queryFlags, name: "example.com")
        let delivered = expectation(description: "response delivered")
        var response: Data?

        pool.query(query, timeout: 1.0) { data in
            response = data
            delivered.fulfill()
        }
        let received = try XCTUnwrap(resolver.receiveWithSender())
        resolver.send(replyEchoing(received.bytes), to: received.sender)

        wait(for: [delivered], timeout: 2.0)
        let answer = try XCTUnwrap(response)
        XCTAssertEqual(Array(answer.prefix(2)), [0x12, 0x34])
        XCTAssertEqual(Array(answer.dropFirst(12)), DNSWire.question(name: "example.com"))
    }

    func testResponseForAnotherQuestionIsHeldBackUntilTheRealAnswerArrives() throws {
        let resolver = try LoopbackUDPSocket()
        let pool = try makePool(resolver: resolver)
        defer { pool.shutdown() }
        let query = DNSWire.message(id: 0x1234, flags: DNSWire.queryFlags, name: "example.com")
        let delivered = expectation(description: "response delivered")
        var response: Data?

        pool.query(query, timeout: 1.0) { data in
            response = data
            delivered.fulfill()
        }
        let received = try XCTUnwrap(resolver.receiveWithSender())
        let resolverID = UInt16(received.bytes[0]) << 8 | UInt16(received.bytes[1])
        let stray = DNSWire.message(id: resolverID, flags: DNSWire.responseFlags, name: "attacker.example")
        resolver.send([UInt8](stray), to: received.sender)
        resolver.send(replyEchoing(received.bytes), to: received.sender)

        wait(for: [delivered], timeout: 2.0)
        let answer = try XCTUnwrap(response)
        XCTAssertEqual(Array(answer.dropFirst(12)), DNSWire.question(name: "example.com"))
    }

    func testQueryWithoutAParsableQuestionIsRefusedBeforeSend() throws {
        let resolver = try LoopbackUDPSocket()
        let pool = try makePool(resolver: resolver)
        defer { pool.shutdown() }
        let query = DNSWire.message(
            id: 0x0042, flags: DNSWire.queryFlags, questionCount: 0, name: "example.com")
        let completed = expectation(description: "query refused")
        var response: Data? = Data([0xFF])

        pool.query(query, timeout: 1.0) { data in
            response = data
            completed.fulfill()
        }

        wait(for: [completed], timeout: 1.0)
        XCTAssertNil(response)
        XCTAssertNil(resolver.receive(), "an uncorrelatable query must never reach the shared socket")
    }

    func testQueryThatIsNeverAnsweredCompletesWithNil() throws {
        let resolver = try LoopbackUDPSocket()
        let pool = try makePool(resolver: resolver)
        defer { pool.shutdown() }
        let query = DNSWire.message(id: 0x1234, flags: DNSWire.queryFlags, name: "example.com")
        let completed = expectation(description: "query completed")
        var response: Data? = Data([0xFF])

        pool.query(query, timeout: 0.1) { data in
            response = data
            completed.fulfill()
        }
        XCTAssertNotNil(resolver.receive())

        wait(for: [completed], timeout: 2.0)
        XCTAssertNil(response)
    }
}
