// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

final class ConfigRevisionTests: XCTestCase {
    func testMissingAndInvalidRevisionNormalizeToZero() {
        XCTAssertEqual(ConfigRevisionPolicy.revision(from: [:]), 0)
        XCTAssertEqual(
            ConfigRevisionPolicy.revision(from: ["configRevision": -1]),
            0
        )
        XCTAssertEqual(
            ConfigRevisionPolicy.revision(from: ["configRevision": "bad"]),
            0
        )
        XCTAssertEqual(
            ConfigRevisionPolicy.revision(from: ["configRevision": true]),
            0
        )
        XCTAssertEqual(
            ConfigRevisionPolicy.revision(from: ["configRevision": 1.5]),
            0
        )
        XCTAssertEqual(
            ConfigRevisionPolicy.revision(from: [
                "configRevision": UInt64(Int64.max) + 1
            ]),
            0
        )
        XCTAssertEqual(
            ConfigRevisionPolicy.revision(from: [
                "configRevision": UInt64.max
            ]),
            0
        )
    }

    func testJSONRevisionAboveInt64MaximumNormalizesToZero() throws {
        let data = Data(
            #"{"configRevision":9223372036854775808}"#.utf8
        )
        let config = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )

        XCTAssertEqual(ConfigRevisionPolicy.revision(from: config), 0)
    }

    func testCanonicalPayloadIgnoresTimestampAndRevision() throws {
        let left: [String: Any] = [
            "isEnabled": true,
            "timestamp": 1.0,
            "configRevision": 3,
        ]
        let right: [String: Any] = [
            "configRevision": 8,
            "timestamp": 9.0,
            "isEnabled": true,
        ]

        XCTAssertEqual(
            try ConfigRevisionPolicy.canonicalPayload(left),
            try ConfigRevisionPolicy.canonicalPayload(right)
        )
    }

    func testCurrentRevisionAcceptsExactlyOneIncrement() {
        XCTAssertEqual(
            ConfigRevisionPolicy.classify(
                expected: 4,
                current: 4,
                incoming: Data("incoming".utf8),
                persisted: Data("persisted".utf8)
            ),
            .accept(nextRevision: 5)
        )
    }

    func testIdenticalRetryAtConsumedRevisionIsIdempotent() {
        let payload = Data("same".utf8)

        XCTAssertEqual(
            ConfigRevisionPolicy.classify(
                expected: 4,
                current: 5,
                incoming: payload,
                persisted: payload
            ),
            .idempotentSuccess
        )
    }

    func testStaleDifferentPayloadIsConflict() {
        XCTAssertEqual(
            ConfigRevisionPolicy.classify(
                expected: 4,
                current: 5,
                incoming: Data("new".utf8),
                persisted: Data("old".utf8)
            ),
            .conflict
        )
    }

    func testFutureRevisionIsConflict() {
        XCTAssertEqual(
            ConfigRevisionPolicy.classify(
                expected: 6,
                current: 5,
                incoming: Data(),
                persisted: Data()
            ),
            .conflict
        )
    }

    func testMaximumCurrentRevisionDoesNotOverflow() {
        XCTAssertEqual(
            ConfigRevisionPolicy.classify(
                expected: .max,
                current: .max,
                incoming: Data(),
                persisted: Data()
            ),
            .conflict
        )
    }
}
