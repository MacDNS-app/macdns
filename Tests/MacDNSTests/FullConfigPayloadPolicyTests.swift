// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNS

final class FullConfigPayloadPolicyTests: XCTestCase {

    // MARK: - Payload validation

    func testRejectsAllowedButNonJSONFoundationValues() {
        XCTAssertFalse(
            FullConfigPayloadPolicy.isValidPayload(["timestamp": Date()])
        )
        XCTAssertFalse(
            FullConfigPayloadPolicy.isValidPayload(["allowlist": Data([0x01])])
        )
        XCTAssertFalse(
            FullConfigPayloadPolicy.isValidPayload(
                ["dohProviders": URL(fileURLWithPath: "/tmp/x")]
            )
        )
        XCTAssertFalse(
            FullConfigPayloadPolicy.isValidPayload(["dohProviders": NSSet(array: ["a"])])
        )
        XCTAssertFalse(
            FullConfigPayloadPolicy.isValidPayload(["cacheTTL": Double.nan])
        )
        XCTAssertFalse(
            FullConfigPayloadPolicy.isValidPayload(["cacheTTL": Double.infinity])
        )
    }

    func testRejectsNonJSONValuesNestedInsidePolicyRecords() {
        XCTAssertFalse(
            FullConfigPayloadPolicy.isValidPayload(
                ["dnsOverrides": [["domain": "a.example", "createdAt": Date()]]]
            )
        )
    }

    func testRejectsNonStringDictionaryKeys() {
        let nonStringKeys: NSDictionary = [NSNumber(value: 1): "value"]
        XCTAssertFalse(
            FullConfigPayloadPolicy.isValidPayload(["forwardZones": nonStringKeys])
        )
    }

    func testAcceptsAJSONCompatiblePayload() {
        XCTAssertTrue(
            FullConfigPayloadPolicy.isValidPayload(
                [
                    "isEnabled": true,
                    "configRevision": 7,
                    "dohProviders": ["cloudflare"],
                    "dnsOverrides": [["domain": "a.example", "value": "10.0.0.1"]],
                    "timestamp": 1_700_000_000.0,
                ]
            )
        )
    }

    // MARK: - Transport class allowlist

    func testDefaultInterfaceWouldTransportNonJSONClasses() {
        let interface = NSXPCInterface(with: MacDNSXPCProtocol.self)
        let unrestricted = savedConfigClasses(of: interface) as NSSet
        XCTAssertTrue(unrestricted.contains(NSDate.self))
        XCTAssertTrue(unrestricted.contains(NSData.self))
        XCTAssertTrue(unrestricted.contains(NSSet.self))
    }

    func testRestrictedInterfaceRefusesNonJSONClasses() {
        let interface = NSXPCInterface(with: MacDNSXPCProtocol.self)
        FullConfigPayloadPolicy.restrictPayloadClasses(on: interface)

        let allowed = savedConfigClasses(of: interface) as NSSet
        XCTAssertFalse(allowed.contains(NSDate.self))
        XCTAssertFalse(allowed.contains(NSData.self))
        XCTAssertFalse(allowed.contains(NSSet.self))
        XCTAssertFalse(allowed.contains(NSOrderedSet.self))
        XCTAssertFalse(allowed.contains(NSURL.self))
        XCTAssertTrue(allowed.contains(NSDictionary.self))
        XCTAssertTrue(allowed.contains(NSString.self))
        XCTAssertTrue(allowed.contains(NSNumber.self))
    }

    func testRestrictedInterfaceCoversBothDirections() {
        let interface = NSXPCInterface(with: MacDNSXPCProtocol.self)
        FullConfigPayloadPolicy.restrictPayloadClasses(on: interface)

        XCTAssertEqual(
            savedConfigClasses(of: interface),
            FullConfigPayloadPolicy.allowedClasses
        )
        XCTAssertEqual(
            interface.classes(
                for: #selector(MacDNSXPCProtocol.getFullConfig(withReply:)),
                argumentIndex: 0,
                ofReply: true
            ),
            FullConfigPayloadPolicy.allowedClasses
        )
    }

    // MARK: - Client boundary

    func testSaveRejectsANonJSONPayloadWithoutStartingATransaction() async {
        let startedAt = Date()
        let result = await XPCClient.shared.saveFullConfigAsync(
            config: ["isEnabled": true, "timestamp": Date()]
        )
        let elapsed = Date().timeIntervalSince(startedAt)

        guard case .success(let response) = result else {
            return XCTFail("Expected a rejected transaction, got \(result)")
        }
        XCTAssertEqual(response.status, .rejected)
        XCTAssertEqual(response.rejectionReason, .invalidConfiguration)
        XCTAssertFalse(response.isPersisted)
        XCTAssertLessThan(elapsed, 5, "Payload must be refused before any XPC round trip")
    }

    private func savedConfigClasses(of interface: NSXPCInterface) -> Set<AnyHashable> {
        interface.classes(
            for: #selector(MacDNSXPCProtocol.saveFullConfig(config:withReply:)),
            argumentIndex: 0,
            ofReply: false
        )
    }
}
