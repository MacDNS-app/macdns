// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

@testable import MacDNS

final class DomainValidatorTests: XCTestCase {
    func testTXTRejectsPayloadOver255UTF8Bytes() {
        let result = DomainValidator.validateOverrideValue(
            String(repeating: "😀", count: 64),
            forType: "TXT"
        )

        guard case .failure = result else {
            return XCTFail("TXT payload larger than one DNS character-string was accepted")
        }
    }

    // MARK: - Parity vectors shared with rust-resolver/src/domain_name.rs

    func testEmptyLabelsAreRejected() {
        for candidate in ["a..b.com", ".a.com", "a.com..", "."] {
            XCTAssertFalse(DomainValidator.isValid(candidate), "\(candidate) must be rejected")
        }
    }

    func testLongIDNLabelIsRejectedOnEncodedOctets() {
        // 30 spread-out CJK code points stay under the 63-character limit a
        // per-Character check would apply, but exceed 63 punycode octets.
        let longLabel = idnLabel(count: 30)
        XCTAssertEqual(longLabel.count, 30)
        XCTAssertFalse(DomainValidator.isValid("\(longLabel).de"))

        let shortLabel = idnLabel(count: 20)
        XCTAssertTrue(DomainValidator.isValid("\(shortLabel).de"))
    }

    func testIDNAndPunycodeShareOneCanonicalForm() {
        XCTAssertEqual(DomainValidator.canonicalHost("münchen.de"), "xn--mnchen-3ya.de")
        XCTAssertEqual(
            DomainValidator.canonicalHost("MÜNCHEN.DE"),
            DomainValidator.canonicalHost("xn--mnchen-3ya.de")
        )
    }

    func testIDNDuplicatePairIsRejectedByTheUI() {
        let existing = [DNSOverride(domain: "münchen.de", value: "10.0.0.1", qtype: "A")]

        XCTAssertNotNil(
            DomainValidator.validateCNAMEExclusivity(
                domain: "xn--mnchen-3ya.de",
                qtype: "A",
                existingOverrides: existing
            ),
            "the punycode form of an existing IDN override must be reported as a duplicate"
        )
        XCTAssertNil(
            DomainValidator.validateCNAMEExclusivity(
                domain: "other.de",
                qtype: "A",
                existingOverrides: existing
            )
        )
    }

    func testSingleLabelDomainsAreLimitedToReservedTLDs() {
        XCTAssertTrue(DomainValidator.isValid("intranet"))
        XCTAssertTrue(DomainValidator.isValid("corp"))
        XCTAssertFalse(DomainValidator.isValid("com"))
    }

    func testOverrideOwnersAcceptAnySingleLabelHost() {
        XCTAssertTrue(DomainValidator.isValid("server", allowsSingleLabelHost: true))
        XCTAssertFalse(DomainValidator.isValid("server"))
        XCTAssertFalse(DomainValidator.isValid("*.server", allowsSingleLabelHost: true))
        XCTAssertFalse(DomainValidator.isValid("123", allowsSingleLabelHost: true))
    }

    func testPublicTLDWarningOnlyForSingleLabelsThatArePublicTLDs() {
        XCTAssertNil(DomainValidator.publicTLDWarning(forOverrideDomain: "server"))
        XCTAssertNil(DomainValidator.publicTLDWarning(forOverrideDomain: "test"))
        XCTAssertNil(DomainValidator.publicTLDWarning(forOverrideDomain: "api.dev"))
        XCTAssertEqual(
            DomainValidator.publicTLDWarning(forOverrideDomain: "Dev"),
            "\"dev\" is also a public top-level domain. Only the bare name dev is overridden. Sites under .dev keep resolving."
        )
        XCTAssertEqual(
            DomainValidator.publicTLDWarning(forOverrideDomain: "box"),
            "\"box\" is also a public top-level domain. Only the bare name box is overridden. Sites under .box keep resolving."
        )
        XCTAssertNil(DomainValidator.publicTLDWarning(forOverrideDomain: "*.dev"))
    }

    /// A reserved TLD claims every name under it and may be a single-label
    /// wildcard or forward zone, so it must never be a delegated public TLD.
    func testReservedTLDsAreNotDelegatedPublicTLDs() {
        XCTAssertEqual(DomainValidator.reservedTLDs.intersection(PublicTopLevelDomains.all), [])
    }

    func testSingleLabelWildcardsAreLimitedToReservedTLDs() {
        XCTAssertTrue(DomainValidator.isValid("*.test"))
        XCTAssertFalse(DomainValidator.isValid("*.com"))
        XCTAssertTrue(DomainValidator.isValid("*.example.com"))
    }

    func testPurelyNumericTLDIsRejected() {
        XCTAssertFalse(DomainValidator.isValid("example.123"))
        XCTAssertTrue(DomainValidator.isValid("123.example.com"))
    }

    func testNonASCIILabelSeparatorIsRejected() {
        XCTAssertFalse(DomainValidator.isValid("example。com"))
    }

    // MARK: - Forward target addresses

    func testUnusableForwardTargetsAreRejected() {
        for ip in ["0.0.0.0", "255.255.255.255", "224.0.0.251", "::", "ff02::fb"] {
            guard case .failure = DomainValidator.validateIP(ip) else {
                return XCTFail("\(ip) must not be accepted as a forward target")
            }
        }
    }

    func testLoopbackAndHostOwnedForwardTargetsAreAccepted() {
        for ip in ["127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "2001:db8::53"] {
            guard case .success = DomainValidator.validateIP(ip) else {
                return XCTFail("\(ip) must remain a valid forward target")
            }
        }
    }

    func testBlackholeOverrideValuesStayValid() {
        // 0.0.0.0 is a legitimate A override value even though it is not a
        // usable forward target.
        guard case .success = DomainValidator.validateOverrideValue("0.0.0.0", forType: "A") else {
            return XCTFail("0.0.0.0 must remain a valid A override value")
        }
    }

    private func idnLabel(count: UInt32) -> String {
        String(
            String.UnicodeScalarView(
                (0..<count).compactMap { Unicode.Scalar(0x4E00 + $0 * 0x40) }
            ))
    }
}
