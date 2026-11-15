// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

@testable import MacDNS
@testable import MacDNSAgent

final class FullConfigReadResponseTests: XCTestCase {

    // MARK: - Wire contract

    func testLoadedRoundTripsTheConfiguration() throws {
        let config: [String: Any] = [
            "configRevision": 7,
            "isEnabled": true,
            "dohProviders": ["cloudflare", "quad9"],
            "customZones": [["domain": "corp.example", "servers": ["10.0.0.1"]]],
        ]
        let response = try XCTUnwrap(FullConfigReadResponse.loaded(config))
        let decoded = try XCTUnwrap(
            FullConfigReadResponse.decoded(from: try response.encoded())
        )

        XCTAssertEqual(decoded.status, .loaded)
        XCTAssertEqual(
            try XCTUnwrap(decoded.config) as NSDictionary,
            config as NSDictionary
        )
    }

    func testFailureStatusesRoundTripWithoutAConfiguration() throws {
        for status in [
            FullConfigReadResponse.Status.invalid, .ioFailure, .incompatibleSchema,
        ] {
            let decoded = try XCTUnwrap(
                FullConfigReadResponse.decoded(
                    from: try FullConfigReadResponse(status: status).encoded()
                )
            )

            XCTAssertEqual(decoded.status, status)
            XCTAssertNil(decoded.config)
        }
    }

    func testStatusNamesOnTheWireAreStable() {
        XCTAssertEqual(FullConfigReadResponse.Status.loaded.rawValue, "loaded")
        XCTAssertEqual(FullConfigReadResponse.Status.invalid.rawValue, "invalid")
        XCTAssertEqual(FullConfigReadResponse.Status.ioFailure.rawValue, "ioFailure")
        XCTAssertEqual(
            FullConfigReadResponse.Status.incompatibleSchema.rawValue,
            "incompatibleSchema"
        )
    }

    func testUndecodableReplyIsNotAResponse() {
        XCTAssertNil(FullConfigReadResponse.decoded(from: nil))
        XCTAssertNil(FullConfigReadResponse.decoded(from: Data("{}".utf8)))
        XCTAssertNil(
            FullConfigReadResponse.decoded(
                from: Data(#"{"status":"somethingNewer"}"#.utf8)
            )
        )
    }

    func testNonJSONConfigurationCannotBeSent() {
        XCTAssertNil(FullConfigReadResponse.loaded(["timestamp": Date()]))
    }

    // MARK: - Agent classification

    func testAgentServesTheSamePayloadAsGetFullConfig() throws {
        let state: [String: Any] = [
            "schemaVersion": ConfigSchemaPolicy.currentVersion,
            "configRevision": 12,
            "isEnabled": true,
            "dnssecEnabled": false,
            BlocklistSettingsTransactionPolicy.stateKey: ["enabled": true],
        ]
        let expected = BlocklistSettingsTransactionPolicy.configWithoutSettings(
            try XCTUnwrap(FullConfigNormalizationPolicy.normalized(state))
        )

        let response = MacDNSAgent.fullConfigReadResponse(for: .valid(state))

        XCTAssertEqual(response.status, .loaded)
        let served = try XCTUnwrap(response.config)
        XCTAssertEqual(served as NSDictionary, expected as NSDictionary)
        XCTAssertNil(served[BlocklistSettingsTransactionPolicy.stateKey])
        XCTAssertEqual(ConfigRevisionPolicy.revision(from: served), 12)
    }

    func testAgentServesDefaultsWhenStateFileIsMissing() throws {
        let response = MacDNSAgent.fullConfigReadResponse(for: .missing)

        XCTAssertEqual(response.status, .loaded)
        XCTAssertEqual(
            try XCTUnwrap(response.config) as NSDictionary,
            FullConfigNormalizationPolicy.defaults() as NSDictionary
        )
    }

    func testAgentReportsWhyTheStateFileCannotBeServed() {
        XCTAssertEqual(
            MacDNSAgent.fullConfigReadResponse(for: .ioFailure("EIO")),
            FullConfigReadResponse(status: .ioFailure)
        )
        XCTAssertEqual(
            MacDNSAgent.fullConfigReadResponse(for: .invalid("not JSON")),
            FullConfigReadResponse(status: .invalid)
        )
        XCTAssertEqual(
            MacDNSAgent.fullConfigReadResponse(
                for: .valid(["customZones": "not a list"])
            ),
            FullConfigReadResponse(status: .invalid)
        )
        XCTAssertEqual(
            MacDNSAgent.fullConfigReadResponse(
                for: .valid([
                    "schemaVersion": ConfigSchemaPolicy.currentVersion + 1
                ])
            ),
            FullConfigReadResponse(status: .incompatibleSchema)
        )
    }

    // MARK: - App reading

    func testAppAcceptsALoadedConfiguration() throws {
        let response = try XCTUnwrap(
            FullConfigReadResponse.loaded(["configRevision": 3, "isEnabled": true])
        )

        guard case .success(let config) = response.loadResult else {
            return XCTFail("Expected the configuration, got \(response.loadResult)")
        }
        XCTAssertEqual(ConfigRevisionPolicy.revision(from: config), 3)
        XCTAssertEqual(config["isEnabled"] as? Bool, true)
    }

    func testAppRetriesAnAgentReportedIOFailure() {
        guard
            case .failure(let error) =
                FullConfigReadResponse(status: .ioFailure).loadResult
        else {
            return XCTFail("An I/O failure carries no configuration")
        }

        for canUseStateFileFallback in [true, false] {
            XCTAssertEqual(
                PersistedStateLoadPolicy.decision(
                    for: error,
                    canUseStateFileFallback: canUseStateFileFallback
                ),
                .retry(.stateReadFailure)
            )
        }
    }

    func testAppTreatsInvalidAndIncompatibleStateAsInvalidConfiguration() {
        for status in [FullConfigReadResponse.Status.invalid, .incompatibleSchema] {
            guard
                case .failure(let error) =
                    FullConfigReadResponse(status: status).loadResult
            else {
                return XCTFail("\(status) carries no configuration")
            }

            XCTAssertEqual(
                PersistedStateLoadPolicy.decision(
                    for: error,
                    canUseStateFileFallback: true
                ),
                .invalidConfiguration,
                status.rawValue
            )
        }
    }

    func testAppRejectsALoadedAnswerWithoutAConfiguration() {
        let response = FullConfigReadResponse(status: .loaded)

        guard case .failure(.decodingFailed) = response.loadResult else {
            return XCTFail("Expected a decoding failure, got \(response.loadResult)")
        }
    }

    func testReadMethodIsPartOfTheXPCProtocol() {
        let description = protocol_getMethodDescription(
            MacDNSXPCProtocol.self,
            #selector(MacDNSXPCProtocol.readFullConfig(withReply:)),
            true,
            true
        )

        XCTAssertNotNil(description.name)
    }
}
