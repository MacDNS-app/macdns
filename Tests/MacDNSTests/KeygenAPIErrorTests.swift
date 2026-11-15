// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNSAgent

final class KeygenAPIErrorTests: XCTestCase {
    func testParsesStructuredCodeAndPointerOfEveryError() {
        let body = Data(
            #"{"errors":[{"title":"Unprocessable resource","detail":"has already been taken","code":"KEY_TAKEN","source":{"pointer":"/data/attributes/key"}},{"title":"Unprocessable resource","detail":"machine count has exceeded maximum allowed for license (3)","code":"MACHINE_LIMIT_EXCEEDED","source":{"pointer":"/data"}}]}"#
                .utf8
        )

        XCTAssertEqual(
            KeygenAPIError.errors(in: body),
            [
                KeygenAPIError(
                    code: "KEY_TAKEN",
                    pointer: "/data/attributes/key",
                    detail: "has already been taken"
                ),
                KeygenAPIError(
                    code: "MACHINE_LIMIT_EXCEEDED",
                    pointer: "/data",
                    detail: "machine count has exceeded maximum allowed for license (3)"
                ),
            ]
        )
    }

    func testMissingFieldsStayNil() {
        XCTAssertEqual(
            KeygenAPIError.errors(in: Data(#"{"errors":[{"title":"Bad"}]}"#.utf8)),
            [KeygenAPIError(code: nil, pointer: nil, detail: nil)]
        )
    }

    func testMalformedBodyHasNoErrors() {
        XCTAssertEqual(KeygenAPIError.errors(in: Data("not-json".utf8)), [])
        XCTAssertEqual(KeygenAPIError.errors(in: Data(#"{"errors":"x"}"#.utf8)), [])
    }

    /// Only the structured code and pointer decide. A detail that merely
    /// mentions "key" or "taken" must never match.
    func testMatchingRequiresCodeAndPointer() {
        let errors = [
            KeygenAPIError(code: "KEY_TAKEN", pointer: "/data/attributes/key", detail: nil),
            KeygenAPIError(code: "NAME_INVALID", pointer: "/data/attributes/name", detail: "key taken"),
        ]

        XCTAssertTrue(errors.contains(code: "KEY_TAKEN", pointer: "/data/attributes/key"))
        XCTAssertFalse(errors.contains(code: "KEY_TAKEN", pointer: "/data/attributes/name"))
        XCTAssertFalse(errors.contains(code: "NAME_TAKEN", pointer: "/data/attributes/key"))
    }

    func testMachineLimitIsReadFromTheDetail() {
        let error = KeygenAPIError(
            code: "MACHINE_LIMIT_EXCEEDED",
            pointer: "/data",
            detail: "machine count has exceeded maximum allowed for license (3)"
        )

        XCTAssertEqual(error.trailingLimit, 3)
        XCTAssertNil(KeygenAPIError(code: nil, pointer: nil, detail: "no number").trailingLimit)
    }
}
