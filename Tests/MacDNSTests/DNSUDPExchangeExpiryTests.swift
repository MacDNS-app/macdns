// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation
import XCTest

@testable import DNSProxyExtension

final class DNSUDPExchangeExpiryTests: XCTestCase {
    func testExpiryBeforeSendCompletesLateHandlerAndClosesOnlyOnce() throws {
        let queue = DispatchQueue(label: "test.udp-expiry")
        let budget = ProxyResourceBudget(capacity: 1)
        let registry = DNSProxyProvider.DNSUDPExchangeRegistry(queue: queue, budget: budget, timeout: 0)
        XCTAssertTrue(registry.acquireSlot())
        var closes = 0
        let exchange = try XCTUnwrap(
            DNSProxyProvider.DNSUDPExchange(
                host: "127.0.0.1", queue: queue,
                onDescriptorClosed: {
                    closes += 1
                    registry.releaseSlot()
                }))
        registry.track(exchange)
        registry.expireOverdueExchanges()
        XCTAssertEqual(budget.inUse, 0)
        XCTAssertEqual(closes, 1)
        var results: [Data?] = []
        exchange.sendQuery(Data(), port: 9) { results.append($0) }
        exchange.expire()
        registry.shutdown()
        XCTAssertEqual(results.count, 1)
        if let result = results.first { XCTAssertNil(result) }
        XCTAssertEqual(closes, 1)
        XCTAssertEqual(budget.inUse, 0)
    }

    func testExpiryAfterSendCancelsSourceAndReturnsSlotOnce() async throws {
        let peer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(peer, 0)
        defer { close(peer) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(peer, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        XCTAssertEqual(bound, 0)
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(peer, $0, &length)
            }
        }
        XCTAssertEqual(named, 0)
        let port = UInt16(bigEndian: address.sin_port)
        let queue = DispatchQueue(label: "test.udp-active-expiry")
        let budget = ProxyResourceBudget(capacity: 1)
        let registry = DNSProxyProvider.DNSUDPExchangeRegistry(queue: queue, budget: budget, timeout: 0)
        XCTAssertTrue(registry.acquireSlot())
        let closed = expectation(description: "descriptor closed exactly once")
        closed.assertForOverFulfill = true
        let exchange = try XCTUnwrap(
            DNSProxyProvider.DNSUDPExchange(
                host: "127.0.0.1", queue: queue,
                onDescriptorClosed: {
                    registry.releaseSlot()
                    closed.fulfill()
                }))
        let token = registry.track(exchange)
        let query = Data([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 97, 0, 0, 1, 0, 1])
        var completions = 0
        exchange.sendQuery(query, port: port) { response in
            completions += 1
            XCTAssertNil(response)
            registry.finish(token)
        }
        XCTAssertEqual(completions, 0)
        XCTAssertEqual(budget.inUse, 1)
        registry.expireOverdueExchanges()
        exchange.expire()
        registry.shutdown()
        XCTAssertEqual(completions, 1)
        await fulfillment(of: [closed], timeout: 2)
        XCTAssertEqual(budget.inUse, 0)
    }

    func testSweepRemovesExpiredExchangeWithoutInstalledHandler() throws {
        let queue = DispatchQueue(label: "test.udp-registry-expiry")
        let budget = ProxyResourceBudget(capacity: 1)
        let registry = DNSProxyProvider.DNSUDPExchangeRegistry(queue: queue, budget: budget, timeout: 0)
        XCTAssertTrue(registry.acquireSlot())
        var exchange =
            try XCTUnwrap(
                DNSProxyProvider.DNSUDPExchange(
                    host: "127.0.0.1", queue: queue, onDescriptorClosed: { registry.releaseSlot() }))
            as DNSProxyProvider.DNSUDPExchange?
        let retained = { [weak exchange] in exchange }
        registry.track(try XCTUnwrap(exchange))
        exchange = nil
        XCTAssertNotNil(retained())
        registry.expireOverdueExchanges()
        XCTAssertNil(retained())
        XCTAssertEqual(budget.inUse, 0)
        registry.expireOverdueExchanges()
        registry.shutdown()
        XCTAssertEqual(budget.inUse, 0)
    }
}
