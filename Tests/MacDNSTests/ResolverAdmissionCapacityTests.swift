// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import DNSProxyExtension
@testable import MacDNSAgent

/// The DNS Proxy forwards everything it accepted to the resolver, and the
/// health probe travels the same path. A resolver that admits fewer queries
/// than the proxy can have pending drops the probe under load, and a dropped
/// probe ends interception.
final class ResolverAdmissionCapacityTests: XCTestCase {

    func testResolverAdmitsMoreUDPQueriesThanTheProxyCanHavePending() throws {
        let limit = try listenerConstant("UDP_MAX_IN_FLIGHT")
        XCTAssertGreaterThan(limit, ResolverSocketPool.maxPendingQueries)
    }

    /// A query forwarded over UDP holds its own upstream socket, and a TCP
    /// client holds its connection plus an upstream one.
    func testAgentDescriptorLimitCoversEveryQueryTheResolverAdmits() throws {
        let udpQueries = try listenerConstant("UDP_MAX_IN_FLIGHT")
        let connections = try listenerConstant("TCP_MAX_CONNECTIONS")
        XCTAssertGreaterThanOrEqual(
            Int(AgentFileDescriptorLimit.target), udpQueries + connections * 2 + 256,
            "the Agent also holds listeners, databases, logs and XPC")
    }

    /// macOS refuses a soft descriptor limit above `OPEN_MAX`.
    func testAgentDescriptorLimitIsOneMacOSAccepts() {
        XCTAssertLessThanOrEqual(AgentFileDescriptorLimit.target, rlim_t(OPEN_MAX))
    }

    func testRaisingTheDescriptorLimitReachesTheTargetOrTheHardLimit() {
        var before = rlimit()
        XCTAssertEqual(getrlimit(RLIMIT_NOFILE, &before), 0)

        let inForce = AgentFileDescriptorLimit.raise()

        var after = rlimit()
        XCTAssertEqual(getrlimit(RLIMIT_NOFILE, &after), 0)
        XCTAssertEqual(inForce, after.rlim_cur)
        XCTAssertGreaterThanOrEqual(
            after.rlim_cur, min(AgentFileDescriptorLimit.target, before.rlim_max))
        XCTAssertGreaterThanOrEqual(after.rlim_cur, before.rlim_cur)
    }

    private func listenerConstant(_ name: String, from filePath: String = #filePath) throws -> Int {
        var directory = URL(fileURLWithPath: filePath).deletingLastPathComponent()
        var source: String?
        while directory.path != "/" {
            let candidate = directory.appendingPathComponent(
                "rust-resolver/crates/macdns-resolver/src/listener.rs")
            if FileManager.default.fileExists(atPath: candidate.path) {
                source = try String(contentsOf: candidate, encoding: .utf8)
                break
            }
            directory = directory.deletingLastPathComponent()
        }
        let listener = try XCTUnwrap(source, "listener.rs not found above the test source path")
        let prefix = "const \(name): usize = "
        let start = try XCTUnwrap(listener.range(of: prefix), "\(name) not found in listener.rs")
        let digits = listener[start.upperBound...].prefix { $0.isNumber || $0 == "_" }
        return try XCTUnwrap(Int(digits.replacingOccurrences(of: "_", with: "")))
    }
}
