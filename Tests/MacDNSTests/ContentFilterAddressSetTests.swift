// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import ContentFilterExtension

final class ContentFilterAddressSetTests: XCTestCase {
    private let providers = ContentFilterProvider.dohProviders

    func testYandexIPv6MatchesInCanonicalSpelling() {
        XCTAssertTrue(providers.contains("2a02:6b8::feed:ff"))
        XCTAssertTrue(providers.contains("2a02:6b8:0:1::feed:ff"))
    }

    func testSpellingOfTheFlowAddressDoesNotMatter() {
        XCTAssertTrue(providers.contains("2a02:06b8:0000:0000:0000:0000:feed:00ff"))
        XCTAssertTrue(providers.contains("2001:4860:4860:0:0:0:0:8888"))
        XCTAssertTrue(providers.contains("2606:4700:4700::1111"))
    }

    func testIPv4ProviderMatches() {
        XCTAssertTrue(providers.contains("8.8.8.8"))
        XCTAssertTrue(providers.contains("77.88.8.8"))
    }

    /// A dual-stack socket reaches an IPv4 server through its IPv4-mapped
    /// IPv6 address, which is the same address.
    func testIPv4MappedProviderMatches() {
        XCTAssertTrue(providers.contains("::ffff:1.1.1.1"))
        XCTAssertTrue(providers.contains("::ffff:808:808"))
        XCTAssertTrue(providers.contains("0:0:0:0:0:ffff:4d58:808"))
        XCTAssertFalse(providers.contains("::ffff:192.0.2.1"))
    }

    func testUnlistedAndUnparseableAddressesDoNotMatch() {
        XCTAssertFalse(providers.contains("192.0.2.1"))
        XCTAssertFalse(providers.contains("2001:db8::1"))
        XCTAssertFalse(providers.contains("dns.google"))
        XCTAssertFalse(providers.contains(""))
    }

    func testEveryListedLiteralParsesIntoItsAddressFamily() {
        for literal in ContentFilterProvider.dohIPv4 {
            XCTAssertEqual(ContentFilterAddressSet.addressBytes(literal)?.count, 4, literal)
        }
        for literal in ContentFilterProvider.dohIPv6 {
            XCTAssertEqual(ContentFilterAddressSet.addressBytes(literal)?.count, 16, literal)
        }
    }

    func testNoTwoLiteralsNameTheSameAddress() {
        let literals = ContentFilterProvider.dohIPv4.union(ContentFilterProvider.dohIPv6)

        XCTAssertEqual(
            Set(literals.compactMap(ContentFilterAddressSet.addressBytes)).count,
            literals.count
        )
    }
}
