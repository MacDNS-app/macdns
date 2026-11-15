// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent

final class LicenseHTTPClassificationTests: XCTestCase {

    func testTimeoutIsTransient() {
        XCTAssertTrue(LicenseHTTPClassification.isTransient(408))
    }

    func testRateLimitIsTransient() {
        XCTAssertTrue(LicenseHTTPClassification.isTransient(429))
    }

    func testServerErrorsAreTransient() {
        for status in [500, 502, 503, 504, 599] {
            XCTAssertTrue(
                LicenseHTTPClassification.isTransient(status),
                "expected \(status) to be transient"
            )
        }
    }

    func testAuthorizationAndValidationErrorsAreTerminal() {
        for status in [400, 401, 403, 404, 409, 422] {
            XCTAssertFalse(
                LicenseHTTPClassification.isTransient(status),
                "expected \(status) to be terminal"
            )
        }
    }

    func testSuccessStatusesAreNotTransient() {
        XCTAssertFalse(LicenseHTTPClassification.isTransient(200))
        XCTAssertFalse(LicenseHTTPClassification.isTransient(201))
    }
}
