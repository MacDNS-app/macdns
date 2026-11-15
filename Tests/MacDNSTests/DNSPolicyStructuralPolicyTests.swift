// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNS

final class DNSPolicyStructuralPolicyTests: XCTestCase {
    func testMissingCollectionsNormalizeToEmptyArrays() throws {
        let validated = try XCTUnwrap(
            DNSPolicyStructuralPolicy.validateAndNormalize(["isEnabled": true])
        )

        XCTAssertTrue(validated.customZones.isEmpty)
        XCTAssertTrue(validated.dnsOverrides.isEmpty)
        XCTAssertEqual(
            (validated.normalizedConfig["customZones"] as? [Any])?.count,
            0
        )
        XCTAssertEqual(
            (validated.normalizedConfig["dnsOverrides"] as? [Any])?.count,
            0
        )
    }

    func testValidCandidateParsesEveryEntryAndCanonicalizesUUIDs() throws {
        let zoneID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        let overrideID = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!
        let validated = try XCTUnwrap(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "customZones": [validZone(id: zoneID.uuidString.lowercased())],
                "dnsOverrides": [validOverride(id: overrideID.uuidString.lowercased())],
            ])
        )

        XCTAssertEqual(validated.customZones.map(\.id), [zoneID])
        XCTAssertEqual(validated.dnsOverrides.map(\.id), [overrideID])
        XCTAssertEqual(
            (validated.normalizedConfig["customZones"] as? [[String: Any]])?
                .first?["id"] as? String,
            zoneID.uuidString
        )
        XCTAssertEqual(
            (validated.normalizedConfig["dnsOverrides"] as? [[String: Any]])?
                .first?["id"] as? String,
            overrideID.uuidString
        )
    }

    func testRejectsInvalidTopLevelAndEntryShapesAtomically() {
        XCTAssertNil(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "customZones": "not-an-array"
            ])
        )
        XCTAssertNil(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "customZones": [validZone(), "not-a-dictionary"]
            ])
        )

        var missingField = validZone()
        missingField.removeValue(forKey: "forwardIP")
        XCTAssertNil(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "customZones": [validZone(), missingField]
            ])
        )

        var missingOverrideField = validOverride()
        missingOverrideField.removeValue(forKey: "qtype")
        XCTAssertNil(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "dnsOverrides": [missingOverrideField]
            ])
        )
    }

    /// A newer build may add fields to an entry. Rejecting the whole file on a
    /// downgrade would brick the agent, so unknown fields are carried through
    /// untouched while every known field stays mandatory.
    func testPreservesUnknownEntryFieldsWrittenByNewerBuilds() throws {
        var zone = validZone()
        zone["ttlSeconds"] = 30
        var override = validOverride()
        override["comment"] = "from a newer build"

        let validated = try XCTUnwrap(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "customZones": [zone],
                "dnsOverrides": [override],
            ])
        )

        XCTAssertEqual(
            (validated.normalizedConfig["customZones"] as? [[String: Any]])?
                .first?["ttlSeconds"] as? Int,
            30
        )
        XCTAssertEqual(
            (validated.normalizedConfig["dnsOverrides"] as? [[String: Any]])?
                .first?["comment"] as? String,
            "from a newer build"
        )
        XCTAssertEqual(validated.customZones.first?.domain, "corp.example")
        XCTAssertEqual(validated.dnsOverrides.first?.qtype, "A")
    }

    func testRejectsInvalidOrDuplicateUUIDsAcrossCompleteCandidate() {
        XCTAssertNil(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "customZones": [validZone(id: "not-a-uuid")]
            ])
        )

        let duplicateID = "00000000-0000-0000-0000-000000000010"
        XCTAssertNil(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "customZones": [validZone(id: duplicateID)],
                "dnsOverrides": [validOverride(id: duplicateID)],
            ])
        )
    }

    func testRejectsNonBooleanEnabledValues() {
        var zone = validZone()
        zone["enabled"] = 1
        XCTAssertNil(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "customZones": [zone]
            ])
        )

        var override = validOverride()
        override["enabled"] = "true"
        XCTAssertNil(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "dnsOverrides": [override]
            ])
        )
    }

    func testRejectsEmptyOrUntrimmedRequiredStrings() {
        for invalid in ["", " ", " corp.example", "corp.example\n"] {
            var zone = validZone()
            zone["domain"] = invalid
            XCTAssertNil(
                DNSPolicyStructuralPolicy.validateAndNormalize([
                    "customZones": [zone]
                ]),
                "zone domain should reject \(invalid.debugDescription)"
            )
        }

        for key in ["domain", "qtype"] {
            var override = validOverride()
            override[key] = " value "
            XCTAssertNil(
                DNSPolicyStructuralPolicy.validateAndNormalize([
                    "dnsOverrides": [override]
                ]),
                "override \(key) should reject surrounding whitespace"
            )
        }

        var zone = validZone()
        zone["forwardIP"] = "\t"
        XCTAssertNil(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "customZones": [zone]
            ])
        )
    }

    func testOverrideValueWithSurroundingWhitespaceIsPreservedByteForByte() throws {
        var override = validOverride()
        override["value"] = "  v=spf1 -all "

        let validated = try XCTUnwrap(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "dnsOverrides": [override]
            ])
        )

        XCTAssertEqual(validated.dnsOverrides.first?.value, "  v=spf1 -all ")
        let entry =
            (validated.normalizedConfig["dnsOverrides"] as? [[String: Any]])?.first
        XCTAssertEqual(entry?["value"] as? String, "  v=spf1 -all ")
    }

    func testWhitespaceOnlyOverrideValueIsAccepted() {
        var override = validOverride()
        override["value"] = "   "

        XCTAssertNotNil(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "dnsOverrides": [override]
            ])
        )
    }

    func testNonStringOverrideValueIsStillRejected() {
        var override = validOverride()
        override["value"] = 42

        XCTAssertNil(
            DNSPolicyStructuralPolicy.validateAndNormalize([
                "dnsOverrides": [override]
            ])
        )
    }

    private func validZone(
        id: String = "00000000-0000-0000-0000-000000000001"
    ) -> [String: Any] {
        [
            "id": id,
            "domain": "corp.example",
            "forwardIP": "10.0.0.53",
            "enabled": true,
        ]
    }

    private func validOverride(
        id: String = "00000000-0000-0000-0000-000000000002"
    ) -> [String: Any] {
        [
            "id": id,
            "domain": "host.example",
            "value": "10.0.0.10",
            "qtype": "A",
            "enabled": true,
        ]
    }
}

/// Fixture documents in `PolicySnapshotDto` shape, taken verbatim from the
/// `policy.rs` and `domain_name.rs` test modules. The Swift semantic policy has
/// to agree with the resolver on every one of them. When a Rust case changes,
/// the same JSON is updated here.
private struct PolicySnapshotFixture: Decodable {
    struct Override: Decodable {
        let domain: String
        let qtype: String
        let value: String
    }

    struct Zone: Decodable {
        let domain: String
        let forwardIP: String
    }

    var overrides: [Override] = []
    var forwardZones: [Zone] = []

    var parsedOverrides: [DNSOverride] {
        overrides.map {
            DNSOverride(domain: $0.domain, value: $0.value, qtype: $0.qtype)
        }
    }

    var parsedZones: [ForwardZone] {
        forwardZones.map { ForwardZone(domain: $0.domain, forwardIP: $0.forwardIP) }
    }
}

final class DNSPolicySemanticPolicyTests: XCTestCase {
    func testRejectsEverySnapshotTheResolverRejects() throws {
        for json in Self.rejectedFixtures {
            let fixture = try Self.decode(json)
            XCTAssertNotNil(
                DNSPolicySemanticPolicy.rejection(
                    zones: fixture.parsedZones,
                    overrides: fixture.parsedOverrides
                ),
                "accepted \(json)"
            )
        }
    }

    func testAcceptsEverySnapshotTheResolverAccepts() throws {
        for json in Self.acceptedFixtures {
            let fixture = try Self.decode(json)
            XCTAssertNil(
                DNSPolicySemanticPolicy.rejection(
                    zones: fixture.parsedZones,
                    overrides: fixture.parsedOverrides
                )?.reason,
                "rejected \(json)"
            )
        }
    }

    func testAcceptsEveryOverrideTypeTheUISupports() {
        for (qtype, value) in [
            ("A", "192.0.2.1"),
            ("AAAA", "2001:db8::1"),
            ("CNAME", "target.example."),
            ("MX", "10 mail.example."),
            ("TXT", "verification-token"),
            ("PTR", "target.example."),
            ("NS", "ns.example."),
        ] {
            XCTAssertNil(
                DNSPolicySemanticPolicy.rejection(
                    zones: [],
                    overrides: [
                        DNSOverride(
                            domain: "record.example",
                            value: value,
                            qtype: qtype
                        )
                    ]
                )?.reason,
                "\(qtype) override rejected"
            )
        }
    }

    func testRejectsTXTPayloadOver255UTF8Bytes() {
        XCTAssertNotNil(
            DNSPolicySemanticPolicy.rejection(
                zones: [],
                overrides: [
                    DNSOverride(
                        domain: "txt.example",
                        value: String(repeating: "😀", count: 64),
                        qtype: "TXT"
                    )
                ]
            )
        )
    }

    func testRejectsSRVOverridesExplicitly() {
        for value in ["10 60 5060 sip.example.com.", "10 60 sip.example"] {
            XCTAssertNotNil(
                DNSPolicySemanticPolicy.rejection(
                    zones: [],
                    overrides: [
                        DNSOverride(
                            domain: "record.example",
                            value: value,
                            qtype: "SRV"
                        )
                    ]
                ),
                "SRV \(value) must stay unreachable"
            )
        }
    }

    func testDisabledRecordsAreNotValidated() {
        XCTAssertNil(
            DNSPolicySemanticPolicy.rejection(
                zones: [
                    ForwardZone(
                        domain: "corp.example",
                        forwardIP: "nope",
                        enabled: false
                    )
                ],
                overrides: [
                    DNSOverride(
                        domain: "host.example",
                        value: "not-an-ip",
                        qtype: "A",
                        enabled: false
                    )
                ]
            )?.reason
        )
    }

    func testCanonicalizeMatchesDomainNameRules() {
        for invalid in ["a..b.com", ".a.com", "a.com..", "example.123", "example。com", "com"] {
            XCTAssertNil(
                try? DNSPolicySemanticPolicy.canonicalName(
                    invalid,
                    role: .forwardZone
                ).get(),
                "\(invalid) must be rejected"
            )
        }

        XCTAssertEqual(
            try? DNSPolicySemanticPolicy.canonicalName(
                "intranet",
                role: .forwardZone
            ).get(),
            "intranet"
        )
        XCTAssertEqual(
            try? DNSPolicySemanticPolicy.canonicalName(
                "123.example.com",
                role: .forwardZone
            ).get(),
            "123.example.com"
        )
        XCTAssertEqual(
            try? DNSPolicySemanticPolicy.canonicalName(
                "münchen.de",
                role: .forwardZone
            ).get(),
            try? DNSPolicySemanticPolicy.canonicalName(
                "xn--mnchen-3ya.de",
                role: .forwardZone
            ).get()
        )
    }

    func testSingleLabelHostIsAcceptedOnlyAsAnExactOverrideOwner() {
        XCTAssertEqual(
            try? DNSPolicySemanticPolicy.canonicalName("Server", role: .overrideOwner).get(),
            "server"
        )
        XCTAssertNil(
            try? DNSPolicySemanticPolicy.canonicalName("server", role: .forwardZone).get(),
            "a single-label forward zone would route a whole TLD"
        )
        XCTAssertNil(
            try? DNSPolicySemanticPolicy.canonicalName("*.server", role: .overrideOwner).get(),
            "a single-label wildcard would capture a whole TLD"
        )
    }

    func testWildcardsFollowTheSameReservedTLDRule() {
        XCTAssertEqual(
            try? DNSPolicySemanticPolicy.canonicalName("*.test", role: .overrideOwner).get(),
            "*.test"
        )
        XCTAssertNil(
            try? DNSPolicySemanticPolicy.canonicalName("*.com", role: .overrideOwner).get()
        )
        XCTAssertEqual(
            try? DNSPolicySemanticPolicy.canonicalName("*.example.com", role: .overrideOwner).get(),
            "*.example.com"
        )
        XCTAssertNil(
            try? DNSPolicySemanticPolicy.canonicalName("*.example.com", role: .forwardZone).get(),
            "forward zones cannot be wildcards"
        )
    }

    func testIDNLabelLimitsUseEncodedOctets() {
        let long = Self.cjkLabel(count: 30)
        XCTAssertNil(
            try? DNSPolicySemanticPolicy.canonicalName("\(long).de", role: .forwardZone).get()
        )
        let short = Self.cjkLabel(count: 20)
        XCTAssertNotNil(
            try? DNSPolicySemanticPolicy.canonicalName("\(short).de", role: .forwardZone).get()
        )
    }

    /// The App validates the same names before they reach either writer, so the
    /// UI must not accept a name the writers reject, nor show as distinct two
    /// names that collide once canonical.
    ///
    /// Both sides share one A-label encoder (`DomainNameCoding`). This guards
    /// what stays separate around it: wildcard and trailing-root handling,
    /// label splitting, and the per-label octet cap that only the writer side
    /// applies.
    func testCanonicalFormMatchesTheAppDomainValidator() {
        for domain in [
            "corp.example",
            "CORP.Example.",
            "münchen.de",
            "xn--mnchen-3ya.de",
            "*.example.com",
            "123.example.com",
            Self.cjkLabel(count: 20) + ".de",
        ] {
            XCTAssertEqual(
                try? DNSPolicySemanticPolicy.canonicalName(domain, role: .overrideOwner).get(),
                DomainValidator.canonicalHost(domain),
                "canonical form diverged for \(domain)"
            )
        }
    }

    /// `policy::build_snapshot` names the offending entry in every rejection.
    /// The preflight runs earlier and far more often, so a less specific reason
    /// here means the common path gives the worse message.
    func testEveryRejectionNamesTheOffendingEntry() {
        let cases: [(String, [ForwardZone], [DNSOverride])] = [
            (
                "override  A: domain is empty",
                [],
                [DNSOverride(domain: "", value: "10.0.0.1", qtype: "A")]
            ),
            (
                "override a..b.example A: invalid domain",
                [],
                [DNSOverride(domain: "a..b.example", value: "10.0.0.1", qtype: "A")]
            ),
            (
                "override host.example A: invalid A value not-an-ip: not an IPv4 address",
                [],
                [DNSOverride(domain: "host.example", value: "not-an-ip", qtype: "A")]
            ),
            (
                "override a.example A: duplicate entry",
                [],
                [
                    DNSOverride(domain: "a.example", value: "10.0.0.1", qtype: "A"),
                    DNSOverride(domain: "a.example", value: "10.0.0.2", qtype: "A"),
                ]
            ),
            (
                "override a.example CNAME: CNAME cannot coexist with other records at a.example",
                [],
                [
                    DNSOverride(domain: "a.example", value: "10.0.0.1", qtype: "A"),
                    DNSOverride(domain: "a.example", value: "target.example.", qtype: "CNAME"),
                ]
            ),
            (
                "forward zone *.corp.example: wildcard is not allowed",
                [ForwardZone(domain: "*.corp.example", forwardIP: "10.0.0.53")],
                []
            ),
            (
                "forward zone corp.example: invalid forward target nope",
                [ForwardZone(domain: "corp.example", forwardIP: "nope")],
                []
            ),
            (
                "forward zone corp.example: duplicate entry",
                [
                    ForwardZone(domain: "corp.example", forwardIP: "10.0.0.53"),
                    ForwardZone(domain: "corp.example", forwardIP: "10.0.0.54"),
                ],
                []
            ),
        ]

        for (expected, zones, overrides) in cases {
            XCTAssertEqual(
                DNSPolicySemanticPolicy.rejection(
                    zones: zones,
                    overrides: overrides
                )?.reason,
                expected
            )
        }
    }

    private static func cjkLabel(count: UInt32) -> String {
        String(
            String.UnicodeScalarView(
                (0..<count).compactMap { UnicodeScalar(0x4E00 + $0 * 0x40) }
            )
        )
    }

    private static func decode(_ json: String) throws -> PolicySnapshotFixture {
        try JSONDecoder().decode(
            PolicySnapshotFixture.self,
            from: Data(json.utf8)
        )
    }

    private static let acceptedFixtures = [
        """
        {"overrides": [{"domain":"a.example","qtype":"A","value":"10.0.0.1"}],
         "forwardZones": [{"domain":"corp.local","forwardIP":"10.0.0.53"}]}
        """,
        """
        {"overrides": [{"domain":"record.example","qtype":"MX","value":"mail.example."}],
         "forwardZones": []}
        """,
        """
        {"overrides": [{"domain":"cs--poligon.example","qtype":"A","value":"10.0.0.1"}],
         "forwardZones": [{"domain":"tx--gateway.example","forwardIP":"10.0.0.53"}]}
        """,
    ]

    private static let rejectedFixtures = [
        """
        {"overrides": [
            {"domain":"good.example","qtype":"A","value":"10.0.0.1"},
            {"domain":"bad.example","qtype":"A","value":"not-an-ip"}],
         "forwardZones": []}
        """,
        """
        {"overrides": [], "forwardZones": [{"domain":"corp.local","forwardIP":"nope"}]}
        """,
        """
        {"overrides": [
            {"domain":"a.example","qtype":"A","value":"10.0.0.1"},
            {"domain":"A.EXAMPLE","qtype":"A","value":"10.0.0.2"}],
         "forwardZones": []}
        """,
        """
        {"overrides": [], "forwardZones": [
            {"domain":"corp.local","forwardIP":"10.0.0.53"},
            {"domain":"CORP.LOCAL","forwardIP":"10.0.0.54"}]}
        """,
        """
        {"overrides": [
            {"domain":"a.example","qtype":"A","value":"10.0.0.1"},
            {"domain":"a.example.","qtype":"A","value":"10.0.0.2"}],
         "forwardZones": []}
        """,
        """
        {"overrides": [
            {"domain":"münchen.de","qtype":"A","value":"10.0.0.1"},
            {"domain":"xn--mnchen-3ya.de","qtype":"A","value":"10.0.0.2"}],
         "forwardZones": []}
        """,
        """
        {"overrides": [], "forwardZones": [
            {"domain":"corp.local","forwardIP":"10.0.0.53"},
            {"domain":"corp.local.","forwardIP":"10.0.0.54"}]}
        """,
        """
        {"overrides": [], "forwardZones": [
            {"domain":"münchen.de","forwardIP":"10.0.0.53"},
            {"domain":"xn--mnchen-3ya.de","forwardIP":"10.0.0.54"}]}
        """,
        """
        {"overrides": [
            {"domain":"alias.example","qtype":"CNAME","value":"target.example"},
            {"domain":"alias.example","qtype":"A","value":"10.0.0.1"}],
         "forwardZones": []}
        """,
        """
        {"overrides": [
            {"domain":"alias.example","qtype":"A","value":"10.0.0.1"},
            {"domain":"alias.example","qtype":"CNAME","value":"target.example"}],
         "forwardZones": []}
        """,
        """
        {"overrides": [{"domain":"a.example","qtype":"NOTAREALTYPE","value":"value"}],
         "forwardZones": []}
        """,
        """
        {"overrides": [{"domain":"a.example","qtype":"AAAA","value":"10.0.0.1"}],
         "forwardZones": []}
        """,
        """
        {"overrides": [], "forwardZones": [{"domain":"corp.local","forwardIP":"224.0.0.251"}]}
        """,
        """
        {"overrides": [], "forwardZones": [{"domain":"corp.local","forwardIP":"0.0.0.0"}]}
        """,
    ]
}
