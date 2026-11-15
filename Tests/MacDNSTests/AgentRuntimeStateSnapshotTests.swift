// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

final class AgentRuntimeStateSnapshotTests: XCTestCase {
    func testSnapshotRoundTripsAllLifecycleFields() throws {
        let snapshot = AgentRuntimeStateSnapshot(
            servicesRunning: true,
            captivePortalDetected: false,
            forwarding: true,
            lifecycleGeneration: 42,
            transitionInProgress: true
        )

        let data = try JSONCoding.encoder.encode(snapshot)
        let decoded = try JSONCoding.decoder.decode(
            AgentRuntimeStateSnapshot.self,
            from: data
        )

        XCTAssertEqual(decoded, snapshot)
    }

    func testSnapshotCarriesOptionalProviderState() throws {
        let snapshot = AgentRuntimeStateSnapshot(
            servicesRunning: true, captivePortalDetected: false, forwarding: false,
            lifecycleGeneration: 3, transitionInProgress: false,
            proxyInterceptionState: "intercepting", proxyInterceptionReason: nil)
        let data = try JSONEncoder().encode(snapshot)
        let back = try JSONDecoder().decode(AgentRuntimeStateSnapshot.self, from: data)
        XCTAssertEqual(back.proxyInterceptionState, "intercepting")
        XCTAssertNil(back.proxyInterceptionReason)
    }

    func testOldPayloadDecodesWithNilProviderState() throws {
        let json = """
            {"servicesRunning":true,"captivePortalDetected":false,"forwarding":false,\
            "lifecycleGeneration":1,"transitionInProgress":false}
            """.data(using: .utf8)!
        let back = try JSONDecoder().decode(AgentRuntimeStateSnapshot.self, from: json)
        XCTAssertNil(back.proxyInterceptionState)
    }

    func testLegacyPayloadWithoutProxyControlUnreachableDecodesAsNil() throws {
        let legacyJSON = """
            {"servicesRunning":true,"captivePortalDetected":false,"forwarding":true,
             "lifecycleGeneration":7,"transitionInProgress":false}
            """.data(using: .utf8)!
        let snapshot = try JSONDecoder().decode(AgentRuntimeStateSnapshot.self, from: legacyJSON)
        XCTAssertNil(snapshot.proxyControlUnreachable)
    }

    func testProxyControlUnreachableRoundTrips() throws {
        let snapshot = AgentRuntimeStateSnapshot(
            servicesRunning: true,
            captivePortalDetected: false,
            forwarding: true,
            lifecycleGeneration: 1,
            transitionInProgress: false,
            proxyControlUnreachable: true
        )
        let decoded = try JSONDecoder().decode(
            AgentRuntimeStateSnapshot.self, from: JSONEncoder().encode(snapshot))
        XCTAssertEqual(decoded.proxyControlUnreachable, true)
    }

    func testResolverStatsRoundTripEveryCounter() throws {
        let stats = ResolverStatsSnapshot(
            queriesTotal: 1, cacheHits: 2, cacheMisses: 3, blocked: 4, servfail: 5,
            prefetchRefills: 6, staleServed: 7, rebindingFiltered: 8, belowNXDomainHits: 9,
            udpOverloadDrops: 10, tcpOverloadDrops: 11)
        let snapshot = AgentRuntimeStateSnapshot(
            servicesRunning: true,
            captivePortalDetected: false,
            forwarding: false,
            lifecycleGeneration: 2,
            transitionInProgress: false,
            resolverStats: stats
        )

        let decoded = try JSONCoding.decoder.decode(
            AgentRuntimeStateSnapshot.self, from: JSONCoding.encoder.encode(snapshot))

        XCTAssertEqual(decoded.resolverStats, stats)
    }

    func testLegacyPayloadWithoutResolverStatsDecodesAsNil() throws {
        let legacyJSON = """
            {"servicesRunning":true,"captivePortalDetected":false,"forwarding":true,
             "lifecycleGeneration":9,"transitionInProgress":false}
            """.data(using: .utf8)!

        let snapshot = try JSONDecoder().decode(AgentRuntimeStateSnapshot.self, from: legacyJSON)

        XCTAssertNil(snapshot.resolverStats)
    }
}
