// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

final class DNSResolverAddressParserTests: XCTestCase {
    func testServerAddressesIncludeIPv6FromGlobalDNSAndDeduplicateDHCPIPv4() {
        let dhcpOption6 = Data([192, 168, 1, 1, 8, 8, 8, 8])
        let globalDNS: [String: Any] = [
            "ServerAddresses": [
                "2001:4860:4860::8888",
                "192.168.1.1",
                "not-an-ip",
            ]
        ]

        let servers = DNSResolverAddressParser.serverAddresses(
            globalDNS: globalDNS,
            dhcpOption6: dhcpOption6
        )

        XCTAssertEqual(servers, ["2001:4860:4860::8888", "192.168.1.1", "8.8.8.8"])
    }

    func testDHCPOption6IgnoresTrailingPartialIPv4Address() {
        let dhcpOption6 = Data([1, 1, 1, 1, 8, 8])

        XCTAssertEqual(
            DNSResolverAddressParser.ipv4Addresses(fromDHCPOption6: dhcpOption6),
            ["1.1.1.1"]
        )
    }

    /// A hotspot that advertises an address which can never answer would
    /// otherwise become the captive forwarding target and black-hole every
    /// query. Dropping it here leaves the usable servers, and leaves the agent
    /// on its existing no-servers path (bypass) when none remain.
    func testUnusableResolversAreDropped() {
        let servers = DNSResolverAddressParser.serverAddresses(
            globalDNS: [
                "ServerAddresses": [
                    "0.0.0.0",
                    "255.255.255.255",
                    "224.0.0.251",
                    "::",
                    "ff02::fb",
                    "192.168.1.1",
                ]
            ],
            dhcpOption6: Data([0, 0, 0, 0, 8, 8, 8, 8])
        )

        XCTAssertEqual(servers, ["192.168.1.1", "8.8.8.8"])
    }

    func testDHCPOption6PaddingIsNotConfiguredAsAResolver() {
        XCTAssertEqual(
            DNSResolverAddressParser.ipv4Addresses(
                fromDHCPOption6: Data([0, 0, 0, 0, 0, 0, 0, 0])
            ),
            []
        )
    }
}
