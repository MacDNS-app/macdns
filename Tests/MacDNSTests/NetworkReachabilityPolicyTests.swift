// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent

private final class StubConfigurationReader: NetworkConfigurationReading {
    private let values: [String: [String: Any]]
    private(set) var readKeys: [String] = []

    init(values: [String: [String: Any]]) {
        self.values = values
    }

    func copyValue(forKey key: String) -> [String: Any]? {
        readKeys.append(key)
        return values[key]
    }
}

final class NetworkReachabilityPolicyTests: XCTestCase {
    func testIPv6OnlyConfigurationIsConnected() {
        let snapshot = NetworkReachabilitySnapshot(
            ipv4: nil,
            ipv6: ["PrimaryInterface": "en0", "PrimaryService": "SVC-IPV6"]
        )

        XCTAssertTrue(snapshot.isConnected)
        XCTAssertEqual(snapshot.ipv6Interface, "en0")
        XCTAssertEqual(snapshot.ipv6Service, "SVC-IPV6")
    }

    func testDualStackLossDisconnects() {
        let connected = NetworkReachabilitySnapshot(
            ipv4: ["PrimaryInterface": "en0", "PrimaryService": "SVC-IPV4"],
            ipv6: ["PrimaryInterface": "en0", "PrimaryService": "SVC-IPV6"]
        )
        XCTAssertTrue(connected.isConnected)

        let lost = NetworkReachabilitySnapshot(ipv4: [:], ipv6: [:])
        XCTAssertFalse(lost.isConnected)
        XCTAssertEqual(lost, .disconnected)
        XCTAssertEqual(NetworkReachabilitySnapshot(ipv4: nil, ipv6: nil), .disconnected)
    }

    func testConnectedInterfaceReplacementChangesIdentity() {
        let wifi = NetworkReachabilitySnapshot(
            ipv4: ["PrimaryInterface": "en0", "PrimaryService": "SVC-WIFI"],
            ipv6: nil
        )
        let ethernet = NetworkReachabilitySnapshot(
            ipv4: ["PrimaryInterface": "en5", "PrimaryService": "SVC-ETHERNET"],
            ipv6: nil
        )

        XCTAssertTrue(wifi.isConnected)
        XCTAssertTrue(ethernet.isConnected)
        XCTAssertNotEqual(wifi, ethernet)
    }

    func testSnapshotReadsBothGlobalAddressFamilies() {
        let reader = StubConfigurationReader(values: [
            NetworkReachabilitySnapshot.ipv6GlobalKey: [
                "PrimaryInterface": "en0",
                "PrimaryService": "SVC-IPV6",
            ]
        ])

        let snapshot = NetworkReachabilitySnapshot.read(using: reader)

        XCTAssertEqual(
            reader.readKeys,
            [
                NetworkReachabilitySnapshot.ipv4GlobalKey,
                NetworkReachabilitySnapshot.ipv6GlobalKey,
            ]
        )
        XCTAssertTrue(snapshot.isConnected)
        XCTAssertNil(snapshot.ipv4Interface)
        XCTAssertEqual(snapshot.ipv6Interface, "en0")
    }
}

final class NetworkIdentitySnapshotTests: XCTestCase {
    private func reader(
        interface: String = "en0",
        service: String = "SVC-WIFI",
        router: String? = nil,
        resolvers: [String] = []
    ) -> StubConfigurationReader {
        var values: [String: [String: Any]] = [
            NetworkReachabilitySnapshot.ipv4GlobalKey: [
                "PrimaryInterface": interface,
                "PrimaryService": service,
            ]
        ]
        if let router {
            values[NetworkIdentitySnapshot.ipv4ServiceKey(service)] = [
                "Router": router
            ]
        }
        if !resolvers.isEmpty {
            values[NetworkIdentitySnapshot.globalDNSKey] = [
                "ServerAddresses": resolvers
            ]
        }
        return StubConfigurationReader(values: values)
    }

    func testIdentityBindsToPrimaryServiceAndInterface() {
        let wifi = NetworkIdentitySnapshot.read(using: reader())
        let ethernet = NetworkIdentitySnapshot.read(
            using: reader(interface: "en5", service: "SVC-ETHERNET")
        )

        XCTAssertEqual(wifi.identity, "SVC-WIFI|en0||||")
        XCTAssertNotEqual(wifi.identity, ethernet.identity)
    }

    func testDisconnectedNetworkHasNoIdentity() {
        let disconnected = NetworkIdentitySnapshot.read(
            using: StubConfigurationReader(values: [:])
        )

        XCTAssertNil(disconnected.identity)
    }

    /// Joining two different Wi-Fi networks through the same configured service
    /// on the same interface produces a byte-identical service/interface tuple.
    /// A bypass approval granted on one of them must not cover the other, so
    /// the identity has to carry the attributes that do differ.
    func testTwoNetworksSharingServiceAndInterfaceGetDistinctIdentities() {
        func identity(router: String, resolver: String) -> String? {
            NetworkIdentitySnapshot.read(
                using: self.reader(router: router, resolvers: [resolver])
            ).identity
        }

        let hotspot = identity(router: "192.168.1.1", resolver: "192.168.1.1")
        let otherHotspot = identity(router: "10.0.0.1", resolver: "10.0.0.1")

        XCTAssertNotNil(hotspot)
        XCTAssertNotEqual(hotspot, otherHotspot)
        XCTAssertEqual(
            hotspot,
            identity(router: "192.168.1.1", resolver: "192.168.1.1"),
            "the same network must keep a stable identity across reads"
        )
    }

    /// The order a network hands its resolvers out is not stable. Treating a
    /// reordered but otherwise identical set as another network would revoke a
    /// live approval in the middle of a portal sign-in.
    func testIdentityIsStableAcrossReorderedResolvers() {
        func identity(_ resolvers: [String]) -> String? {
            NetworkIdentitySnapshot.read(
                using: self.reader(router: "192.168.1.1", resolvers: resolvers)
            ).identity
        }

        XCTAssertNotNil(identity(["192.168.1.1", "192.168.1.2"]))
        XCTAssertEqual(
            identity(["192.168.1.1", "192.168.1.2"]),
            identity(["192.168.1.2", "192.168.1.1"])
        )
    }

    func testIdentityIgnoresResolverAddressesTheStoreCannotParse() {
        let snapshot = NetworkIdentitySnapshot.read(
            using: reader(
                router: "192.168.1.1",
                resolvers: ["not-an-ip", "192.168.1.1"]
            )
        )

        XCTAssertEqual(snapshot.identity, "SVC-WIFI|en0|||192.168.1.1|192.168.1.1")
    }

    func testIdentityReadsTheRouterOfThePrimaryIPv4Service() {
        let store = reader(router: "192.168.1.1")

        let snapshot = NetworkIdentitySnapshot.read(using: store)

        XCTAssertEqual(
            store.readKeys,
            [
                NetworkReachabilitySnapshot.ipv4GlobalKey,
                NetworkReachabilitySnapshot.ipv6GlobalKey,
                NetworkIdentitySnapshot.ipv4ServiceKey("SVC-WIFI"),
                NetworkIdentitySnapshot.globalDNSKey,
            ]
        )
        XCTAssertEqual(snapshot.router, "192.168.1.1")
    }
}
