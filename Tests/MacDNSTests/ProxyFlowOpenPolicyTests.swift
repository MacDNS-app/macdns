// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import NetworkExtension
import XCTest

@testable import DNSProxyExtension

/// Stands in for an `NEAppProxyUDPFlow` / `NEAppProxyTCPFlow` whose `open`
/// completion reported an error.
private final class FakeProxyFlow: ProxyFlowHandle {
    private(set) var closeReadErrors: [Error?] = []
    private(set) var closeWriteErrors: [Error?] = []

    func closeReadWithError(_ error: Error?) {
        closeReadErrors.append(error)
    }

    func closeWriteWithError(_ error: Error?) {
        closeWriteErrors.append(error)
    }
}

final class ProxyFlowOpenPolicyTests: XCTestCase {
    private let openError = NSError(
        domain: "NEAppProxyFlowErrorDomain", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "flow not connected"])

    func testUDPOpenFailureClosesBothHalvesExactlyOnce() {
        let flow = FakeProxyFlow()

        ProxyFlowOpenPolicy.closeAfterOpenFailure(flow, error: openError)

        XCTAssertEqual(flow.closeReadErrors.count, 1)
        XCTAssertEqual(flow.closeWriteErrors.count, 1)
        XCTAssertEqual(flow.closeReadErrors.first.flatMap { $0 } as NSError?, openError)
        XCTAssertEqual(flow.closeWriteErrors.first.flatMap { $0 } as NSError?, openError)
    }

    func testTCPOpenFailureClosesBothHalvesExactlyOnce() {
        let flow = FakeProxyFlow()

        ProxyFlowOpenPolicy.closeAfterOpenFailure(flow, error: openError)

        XCTAssertEqual(flow.closeReadErrors.count, 1)
        XCTAssertEqual(flow.closeWriteErrors.count, 1)
    }

    func testEachFailedFlowIsReleasedIndependently() {
        let first = FakeProxyFlow()
        let second = FakeProxyFlow()

        ProxyFlowOpenPolicy.closeAfterOpenFailure(first, error: openError)
        ProxyFlowOpenPolicy.closeAfterOpenFailure(second, error: openError)

        for flow in [first, second] {
            XCTAssertEqual(flow.closeReadErrors.count, 1)
            XCTAssertEqual(flow.closeWriteErrors.count, 1)
        }
    }

    func testPeerResetAndAbortedOpenFailuresAreRoutine() {
        XCTAssertTrue(ProxyFlowOpenPolicy.isRoutineOpenFailure(NEAppProxyFlowError(.peerReset)))
        XCTAssertTrue(ProxyFlowOpenPolicy.isRoutineOpenFailure(NEAppProxyFlowError(.aborted)))
    }

    func testOtherOpenFailuresAreNotRoutine() {
        XCTAssertFalse(ProxyFlowOpenPolicy.isRoutineOpenFailure(NEAppProxyFlowError(.notConnected)))
        XCTAssertFalse(ProxyFlowOpenPolicy.isRoutineOpenFailure(NSError(domain: NSPOSIXErrorDomain, code: 2)))
    }
}
