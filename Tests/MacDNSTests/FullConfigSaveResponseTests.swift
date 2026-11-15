// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import Shared

final class FullConfigSaveResponseTests: XCTestCase {

    func testCommittedRoundTripsWithAuthoritativeRevision() throws {
        let response = FullConfigSaveResponse(
            status: .committed,
            authoritativeRevision: 42
        )
        let data = try response.encoded()
        let decoded = try XCTUnwrap(FullConfigSaveResponse.decoded(from: data))

        XCTAssertEqual(decoded.status, .committed)
        XCTAssertEqual(decoded.authoritativeRevision, 42)
        XCTAssertNil(decoded.rejectionReason)
    }

    func testRejectionCarriesTypedReason() throws {
        let response = FullConfigSaveResponse(
            status: .rejected,
            authoritativeRevision: 7,
            rejectionReason: .runtimeApplyFailure
        )
        let decoded = try XCTUnwrap(
            FullConfigSaveResponse.decoded(from: try response.encoded())
        )

        XCTAssertEqual(decoded.status, .rejected)
        XCTAssertEqual(decoded.rejectionReason, .runtimeApplyFailure)
    }

    func testCommittedAndIdempotentCountAsPersisted() {
        XCTAssertTrue(FullConfigSaveResponse(status: .committed).isPersisted)
        XCTAssertTrue(
            FullConfigSaveResponse(status: .alreadyCommitted).isPersisted
        )
        XCTAssertFalse(
            FullConfigSaveResponse(status: .lifecycleBusy).isPersisted
        )
        XCTAssertFalse(FullConfigSaveResponse(status: .conflict).isPersisted)
        XCTAssertFalse(FullConfigSaveResponse(status: .rejected).isPersisted)
    }

    func testDecodingGarbageReturnsNil() {
        XCTAssertNil(FullConfigSaveResponse.decoded(from: Data("nope".utf8)))
        XCTAssertNil(FullConfigSaveResponse.decoded(from: nil))
    }
}
