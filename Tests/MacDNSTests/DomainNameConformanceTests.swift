// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNS

/// Swift half of the cross-language conformance vectors in
/// `Tests/Fixtures/domain-name-conformance.json`. The Rust half lives in
/// `rust-resolver/crates/macdns-resolver/src/domain_name.rs` and reads the same
/// file, so a name cannot pass one language and fail the other without a test
/// naming it.
final class DomainNameConformanceTests: XCTestCase {
    func testOwnerVectorsMatchTheSharedValidator() throws {
        for owner in try Self.vectors().owners {
            let canonical = try? DNSPolicySemanticPolicy.canonicalName(
                owner.input,
                role: owner.role.policyRole
            ).get()

            XCTAssertEqual(
                canonical != nil,
                owner.swift.accept,
                "\(owner.input) acceptance diverged from the fixture"
            )
            if owner.swift.accept {
                XCTAssertEqual(
                    canonical,
                    owner.swift.canonical,
                    "canonical form diverged for \(owner.input)"
                )
            }
        }
    }

    /// The UI must reach the same verdict as the writers, or it accepts names
    /// that only fail once the resolver replays them. Wildcard inputs for
    /// forward zones are skipped: refusing a wildcard is a writer rule the UI
    /// applies per field, not a name rule.
    func testOwnerVectorsMatchTheAppValidator() throws {
        for owner in try Self.vectors().owners {
            let uiAccepted: Bool
            switch owner.role {
            case .override:
                uiAccepted = DomainValidator.isValid(owner.input, allowsSingleLabelHost: true)
            case .forwardZone:
                guard !owner.input.hasPrefix("*.") else { continue }
                uiAccepted = DomainValidator.isValid(owner.input)
            }
            XCTAssertEqual(
                uiAccepted,
                owner.swift.accept,
                "the App validator diverged for \(owner.input)"
            )
        }
    }

    func testTargetVectorsMatchTheSharedValidator() throws {
        for target in try Self.vectors().targets {
            XCTAssertEqual(
                DNSPolicySemanticPolicy.targetNameRejection(target.input) == nil,
                target.swift.accept,
                "RDATA target \(target.input) diverged from the fixture"
            )

            let uiAccepted: Bool
            switch DomainValidator.validateOverrideValue(target.input, forType: "CNAME") {
            case .success: uiAccepted = true
            case .failure: uiAccepted = false
            }
            XCTAssertEqual(
                uiAccepted,
                target.swift.accept,
                "the App validator diverged for CNAME target \(target.input)"
            )
        }
    }

    func testForwardTargetVectorsMatchTheSharedParser() throws {
        for target in try Self.vectors().forwardTargets {
            XCTAssertEqual(
                DNSResolverAddressParser.isIPAddress(target.input),
                target.isAddress,
                "\(target.input) address parsing diverged from the fixture"
            )
            XCTAssertEqual(
                DNSResolverAddressParser.unusableForwardTargetKind(target.input),
                target.kind,
                "\(target.input) unusable kind diverged from the fixture"
            )
            XCTAssertEqual(
                DNSResolverAddressParser.isUsableForwardTarget(target.input),
                target.usable,
                "\(target.input) usability diverged from the fixture"
            )

            let uiAccepted: Bool
            switch DomainValidator.validateIP(target.input) {
            case .success: uiAccepted = true
            case .failure: uiAccepted = false
            }
            XCTAssertEqual(
                uiAccepted,
                target.usable,
                "the App validator diverged for forward target \(target.input)"
            )

            XCTAssertEqual(
                DNSPolicySemanticPolicy.rejection(
                    zones: [
                        ForwardZone(domain: "corp.example", forwardIP: target.input)
                    ],
                    overrides: []
                ) == nil,
                target.usable,
                "the save gate diverged for forward target \(target.input)"
            )
        }
    }

    /// Swift is allowed to be stricter than the resolver: a name the App
    /// refuses never reaches `state.json`. The reverse is the outage this
    /// fixture guards against. A name the App accepts and the resolver rejects
    /// fails the entire policy snapshot and can keep DNS from starting.
    func testFixtureKeepsSwiftNoMorePermissiveThanRust() throws {
        let vectors = try Self.vectors()
        for owner in vectors.owners where owner.swift.accept {
            XCTAssertTrue(
                owner.rust.accept,
                "\(owner.input) is accepted by Swift only"
            )
            XCTAssertEqual(
                owner.swift.canonical,
                owner.rust.canonical,
                "canonical columns disagree for \(owner.input)"
            )
        }
        for target in vectors.targets where target.swift.accept {
            XCTAssertTrue(
                target.rust.accept,
                "RDATA target \(target.input) is accepted by Swift only"
            )
        }
    }

    // MARK: - Fixtures

    private struct Vectors: Decodable {
        struct Expectation: Decodable {
            let accept: Bool
            let canonical: String?
        }

        enum Role: String, Decodable {
            case override
            case forwardZone

            var policyRole: DNSPolicyNameRole {
                switch self {
                case .override: return .overrideOwner
                case .forwardZone: return .forwardZone
                }
            }
        }

        struct Owner: Decodable {
            let input: String
            let role: Role
            let swift: Expectation
            let rust: Expectation
        }

        struct Target: Decodable {
            let input: String
            let swift: Expectation
            let rust: Expectation
        }

        struct ForwardTarget: Decodable {
            let input: String
            let isAddress: Bool
            let usable: Bool
            let kind: String?
        }

        let owners: [Owner]
        let targets: [Target]
        let forwardTargets: [ForwardTarget]
    }

    private static func vectors(file: StaticString = #filePath) throws -> Vectors {
        let url = URL(fileURLWithPath: "\(file)")
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures/domain-name-conformance.json")
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
    }
}
