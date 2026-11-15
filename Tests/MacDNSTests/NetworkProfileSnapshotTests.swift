// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent

private final class StubProfileReader: NetworkConfigurationReading {
    private let values: [String: [String: Any]]

    init(values: [String: [String: Any]]) {
        self.values = values
    }

    func copyValue(forKey key: String) -> [String: Any]? {
        values[key]
    }
}

final class NetworkProfileSnapshotTests: XCTestCase {
    private let serviceID = "EDF52AFC-9A8F-4244-8865-F58ED35DFBDC"

    /// The iPhone hotspot as configd reports it: dual-stack, with the
    /// hotspot's IPv4 resolver and an unscoped link-local IPv6 resolver.
    private func hotspotValues(globalDNS: [String] = ["100.100.100.100"]) -> [String: [String: Any]] {
        [
            "State:/Network/Global/IPv4": [
                "PrimaryInterface": "en0",
                "PrimaryService": serviceID,
                "Router": "172.20.10.1",
            ],
            "State:/Network/Global/IPv6": [
                "PrimaryInterface": "en0",
                "PrimaryService": serviceID,
                "Router": "fe80::f004:e1ff:fe89:4364",
            ],
            "State:/Network/Global/DNS": ["ServerAddresses": globalDNS],
            "State:/Network/Service/\(serviceID)/DNS": [
                "ServerAddresses": ["172.20.10.1", "fe80::f004:e1ff:fe89:4364"]
            ],
        ]
    }

    func testReadsThePrimaryServiceResolversNotTheGlobalOverride() {
        let snapshot = NetworkProfileSnapshot.read(
            using: StubProfileReader(values: hotspotValues())
        )

        XCTAssertTrue(snapshot.hasIPv4)
        XCTAssertTrue(snapshot.hasIPv6)
        XCTAssertEqual(snapshot.interface, "en0")
        XCTAssertEqual(snapshot.resolvers, ["172.20.10.1", "fe80::f004:e1ff:fe89:4364"])
    }

    func testIPv6OnlyNetworkUsesTheIPv6PrimaryService() {
        var values = hotspotValues()
        values["State:/Network/Global/IPv4"] = nil

        let snapshot = NetworkProfileSnapshot.read(using: StubProfileReader(values: values))

        XCTAssertFalse(snapshot.hasIPv4)
        XCTAssertTrue(snapshot.hasIPv6)
        XCTAssertEqual(snapshot.interface, "en0")
        XCTAssertEqual(snapshot.resolvers.count, 2)
    }

    func testScopedAndUnusableResolversAreNormalized() {
        let snapshot = NetworkProfileSnapshot(
            globalIPv4: ["PrimaryInterface": "en0", "Router": "192.0.2.1"],
            globalIPv6: nil,
            serviceDNS: [
                "ServerAddresses": [
                    "fe80::1%en0", "fe80::1", "0.0.0.0", "ff02::fb", "not-an-ip", "192.0.2.53",
                ]
            ],
            interfaceIndex: { $0 == "en0" ? 11 : 0 }
        )

        XCTAssertEqual(snapshot.resolvers, ["fe80::1", "192.0.2.53"])
        XCTAssertEqual(snapshot.interfaceIndex, 11)
    }

    /// The resolver refuses a snapshot with more servers than it queries, so
    /// a network that hands out a long list must still be published.
    func testResolverListIsCappedAtTheResolverLimit() {
        let servers = (1...10).map { "192.0.2.\($0)" }
        let snapshot = NetworkProfileSnapshot(
            globalIPv4: ["PrimaryInterface": "en0", "Router": "192.0.2.1"],
            globalIPv6: nil,
            serviceDNS: ["ServerAddresses": servers],
            interfaceIndex: { _ in 11 }
        )

        XCTAssertEqual(snapshot.resolvers, Array(servers.prefix(8)))
    }

    func testDisconnectedSnapshotCarriesNoResolvers() {
        let snapshot = NetworkProfileSnapshot.read(using: StubProfileReader(values: [:]))

        XCTAssertEqual(snapshot, .disconnected)
        XCTAssertFalse(snapshot.hasIPv4)
        XCTAssertFalse(snapshot.hasIPv6)
        XCTAssertTrue(snapshot.resolvers.isEmpty)
    }

    func testPayloadMatchesTheResolverContract() throws {
        let snapshot = NetworkProfileSnapshot(
            globalIPv4: ["PrimaryInterface": "en0", "Router": "172.20.10.1"],
            globalIPv6: ["PrimaryInterface": "en0", "Router": "fe80::1"],
            serviceDNS: ["ServerAddresses": ["172.20.10.1"]],
            interfaceIndex: { _ in 11 }
        )

        let data = try JSONSerialization.data(withJSONObject: snapshot.payload)
        let decoded = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(
            Set(decoded.keys),
            ["ipv4", "ipv6", "interface", "interfaceIndex", "resolvers"]
        )
        XCTAssertEqual(decoded["ipv4"] as? Bool, true)
        XCTAssertEqual(decoded["interfaceIndex"] as? Int, 11)
        XCTAssertEqual(decoded["resolvers"] as? [String], ["172.20.10.1"])
    }
}
