// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNSAgent

final class ConfigSchemaPolicyTests: XCTestCase {
    func testDocumentWithoutVersionIsCurrent() {
        XCTAssertEqual(
            ConfigSchemaPolicy.compatibility(of: ["isEnabled": true]),
            .current
        )
    }

    func testCurrentVersionIsAcceptedAsIs() {
        XCTAssertEqual(
            ConfigSchemaPolicy.compatibility(of: [
                "schemaVersion": ConfigSchemaPolicy.currentVersion
            ]),
            .current
        )
    }

    func testNewerSchemaIsReportedAsIncompatibleWithItsVersion() {
        XCTAssertEqual(
            ConfigSchemaPolicy.compatibility(of: [
                "schemaVersion": ConfigSchemaPolicy.currentVersion + 3
            ]),
            .incompatible(version: ConfigSchemaPolicy.currentVersion + 3)
        )
    }

    func testNonIntegerSchemaVersionIsMalformed() {
        for rawValue in ["1", 1.5, true, -1] as [Any] {
            XCTAssertEqual(
                ConfigSchemaPolicy.compatibility(of: ["schemaVersion": rawValue]),
                .malformed,
                "\(rawValue) should not parse as a schema version"
            )
        }
    }

    /// No build ever wrote a version below the current one.
    func testVersionBelowCurrentIsMalformed() {
        XCTAssertEqual(
            ConfigSchemaPolicy.compatibility(of: [
                "schemaVersion": ConfigSchemaPolicy.currentVersion - 1
            ]),
            .malformed
        )
    }

    func testWritableStampsTheVersionAndKeepsEveryField() throws {
        let writable = try XCTUnwrap(
            ConfigSchemaPolicy.writable([
                "isEnabled": true,
                "fieldFromANewerBuild": "keep-me",
            ])
        )

        XCTAssertEqual(writable["isEnabled"] as? Bool, true)
        XCTAssertEqual(writable["fieldFromANewerBuild"] as? String, "keep-me")
        XCTAssertNil(writable["blockDohDotEnabled"])
        XCTAssertEqual(
            writable["schemaVersion"] as? Int,
            ConfigSchemaPolicy.currentVersion
        )
    }

    func testIncompatibleAndMalformedStateIsNeverRewritten() {
        for version in [
            ConfigSchemaPolicy.currentVersion + 1, "1", ConfigSchemaPolicy.currentVersion - 1,
        ] as [Any] {
            XCTAssertNil(ConfigSchemaPolicy.writable(["schemaVersion": version]))
        }
    }
}

final class PersistedStateRecoveryPolicyTests: XCTestCase {
    func testMissingStateCreatesDefaults() {
        XCTAssertEqual(
            PersistedStateRecoveryPolicy.decision(for: .missing),
            .createDefaults
        )
    }

    func testUnreadableStateIsLeftUntouched() {
        XCTAssertEqual(
            PersistedStateRecoveryPolicy.decision(
                for: .ioFailure("permission denied")
            ),
            .refuseUnreadable(reason: "permission denied")
        )
    }

    func testSyntacticallyBrokenStateIsQuarantinedAndReplaced() {
        XCTAssertEqual(
            PersistedStateRecoveryPolicy.decision(for: .invalid("truncated JSON")),
            .quarantineThenCreateDefaults(
                quarantineName: "state.json.quarantine-0",
                reason: "truncated JSON"
            )
        )
    }

    func testStructurallyInvalidStateIsQuarantinedUnderItsOwnRevision() {
        let decision = PersistedStateRecoveryPolicy.decision(
            for: .valid([
                "configRevision": 7,
                "dnsOverrides": ["not-a-dictionary"],
            ])
        )

        guard
            case .quarantineThenCreateDefaults(let quarantineName, _) = decision
        else {
            return XCTFail("expected quarantine, got \(decision)")
        }
        XCTAssertEqual(quarantineName, "state.json.quarantine-7")
    }

    func testQuarantineNamesNeverOverwriteAnEarlierQuarantine() {
        let decision = PersistedStateRecoveryPolicy.decision(
            for: .invalid("truncated JSON"),
            existingNames: ["state.json.quarantine-0", "state.json.quarantine-0-2"]
        )

        guard
            case .quarantineThenCreateDefaults(let quarantineName, _) = decision
        else {
            return XCTFail("expected quarantine, got \(decision)")
        }
        XCTAssertEqual(quarantineName, "state.json.quarantine-0-3")
    }

    func testNewerSchemaIsPreservedInsteadOfQuarantined() {
        XCTAssertEqual(
            PersistedStateRecoveryPolicy.decision(
                for: .valid([
                    "schemaVersion": ConfigSchemaPolicy.currentVersion + 1,
                    "dnsOverrides": ["not-a-dictionary"],
                ])
            ),
            .refuseIncompatible(version: ConfigSchemaPolicy.currentVersion + 1)
        )
    }

    func testValidStateIsKeptWithOrWithoutTheVersion() {
        XCTAssertEqual(
            PersistedStateRecoveryPolicy.decision(
                for: .valid([
                    "schemaVersion": ConfigSchemaPolicy.currentVersion,
                    "isEnabled": true,
                ])
            ),
            .useExisting
        )
        XCTAssertEqual(
            PersistedStateRecoveryPolicy.decision(for: .valid(["isEnabled": true])),
            .useExisting
        )
    }

    func testVersionBelowCurrentIsQuarantined() {
        XCTAssertEqual(
            PersistedStateRecoveryPolicy.decision(
                for: .valid([
                    "configRevision": 3,
                    "schemaVersion": ConfigSchemaPolicy.currentVersion - 1,
                ])
            ),
            .quarantineThenCreateDefaults(
                quarantineName: "state.json.quarantine-3",
                reason: "unreadable schemaVersion"
            )
        )
    }
}
