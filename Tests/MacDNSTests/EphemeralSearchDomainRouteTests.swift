// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent

private final class StubGlobalDNSReader: NetworkConfigurationReading {
    private let values: [String: [String: Any]]

    init(values: [String: [String: Any]]) {
        self.values = values
    }

    func copyValue(forKey key: String) -> [String: Any]? {
        values[key]
    }
}

final class EphemeralSearchDomainRouteTests: XCTestCase {
    func testDiscoveredSearchDomainsPairWithTheNetworkResolver() {
        let routes = EphemeralSearchDomainRoutes(
            searchDomains: ["lan", "office.corp"],
            resolvers: ["192.0.2.53", "192.0.2.54"]
        )

        XCTAssertEqual(
            routes.routes,
            [
                EphemeralSearchDomainRoutes.Route(domain: "lan", forwardIP: "192.0.2.53"),
                EphemeralSearchDomainRoutes.Route(domain: "office.corp", forwardIP: "192.0.2.53"),
            ]
        )
    }

    func testMissingResolverOrSearchDomainProducesNoRoutes() {
        XCTAssertTrue(
            EphemeralSearchDomainRoutes(searchDomains: ["lan"], resolvers: []).routes.isEmpty
        )
        XCTAssertTrue(
            EphemeralSearchDomainRoutes(searchDomains: [], resolvers: ["192.0.2.53"]).routes.isEmpty
        )
    }

    func testSearchDomainsAreNormalizedAndDeduplicated() {
        let routes = EphemeralSearchDomainRoutes(
            searchDomains: ["LAN.", " lan ", "", ".", "office.CORP"],
            resolvers: ["192.0.2.53"]
        )

        XCTAssertEqual(routes.routes.map(\.domain), ["lan", "office.corp"])
    }

    func testReadsSearchDomainsAndResolversFromGlobalDNS() {
        let reader = StubGlobalDNSReader(values: [
            EphemeralSearchDomainRoutes.globalDNSKey: [
                "SearchDomains": ["lan"],
                "DomainName": "office.corp",
                "ServerAddresses": ["192.0.2.53"],
            ]
        ])

        let routes = EphemeralSearchDomainRoutes.read(using: reader)

        XCTAssertEqual(routes.routes.map(\.domain), ["lan", "office.corp"])
        XCTAssertEqual(routes.routes.map(\.forwardIP), ["192.0.2.53", "192.0.2.53"])
    }

    func testAbsentGlobalDNSProducesNoRoutes() {
        let routes = EphemeralSearchDomainRoutes.read(
            using: StubGlobalDNSReader(values: [:])
        )

        XCTAssertTrue(routes.routes.isEmpty)
    }
}
