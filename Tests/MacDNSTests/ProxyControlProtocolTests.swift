// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import Shared

final class ProxyControlProtocolTests: XCTestCase {
    func testBootstrapRoundTrips() throws {
        let boot = ProxyControlBootstrap(
            version: 1, sessionID: Data(repeating: 1, count: 16),
            hmacKey: Data(repeating: 2, count: 32))
        let data = try JSONEncoder().encode(boot)
        let back = try JSONDecoder().decode(ProxyControlBootstrap.self, from: data)
        XCTAssertEqual(boot, back)
    }

    func testStateReportBypassRoundTrips() throws {
        let report = ProxyControlStateReport(state: "bypass", reason: "starting")
        let data = try JSONEncoder().encode(report)
        let back = try JSONDecoder().decode(ProxyControlStateReport.self, from: data)
        XCTAssertEqual(report, back)
    }

    func testInterceptingReportHasNoReason() {
        let report = ProxyInterceptionState.intercepting(sessionID: "abcd").toReport()
        XCTAssertEqual(report.state, "intercepting")
        XCTAssertNil(report.reason)
    }

    func testBypassReasonRoundTripsThroughReport() {
        let state = ProxyInterceptionState.bypass(.probeFailed)
        let back = ProxyInterceptionState(report: state.toReport())
        XCTAssertEqual(back, state)
    }

    func testUnknownReasonStringIsRejected() {
        let report = ProxyControlStateReport(state: "bypass", reason: "bogus")
        XCTAssertNil(ProxyInterceptionState(report: report))
    }
}
