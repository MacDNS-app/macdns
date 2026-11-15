// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

@testable import MacDNS

/// Which connection the App keeps when XPC reports one interrupted or
/// invalidated. No message is sent, so the Agent requirement is never checked.
final class XPCClientConnectionTests: XCTestCase {
    private var listener: NSXPCListener!
    private var client: XPCClient!

    override func setUp() {
        super.setUp()
        let listener = NSXPCListener.anonymous()
        listener.resume()
        self.listener = listener
        client = XPCClient(makeConnection: {
            NSXPCConnection(listenerEndpoint: listener.endpoint)
        })
    }

    override func tearDown() {
        client.resetConnection()
        listener.invalidate()
        super.tearDown()
    }

    /// An interrupted connection reaches the relaunched Agent on its next
    /// message. Dropping it without invalidating it would leak it.
    func testInterruptedConnectionIsKept() throws {
        let first = client.getConnection()

        try XCTUnwrap(first.interruptionHandler)()

        XCTAssertTrue(client.getConnection() === first)
    }

    /// A license call the App gives up on while the Agent still works reports a
    /// failure the Agent never had, and turns protection off.
    func testLicenseCallsOutwaitTheLongestLicenseOperation() {
        XCTAssertGreaterThan(XPCClient.licenseReplyTimeout, LicenseRequestBudget.operation)
    }

    func testInvalidatedConnectionIsReplaced() throws {
        let first = client.getConnection()

        try XCTUnwrap(first.invalidationHandler)()

        XCTAssertFalse(client.getConnection() === first)
    }

    /// The invalidation of a connection that was reset arrives later, on an
    /// XPC thread. By then the App may already hold the next connection.
    func testInvalidationOfAReplacedConnectionKeepsItsSuccessor() throws {
        let first = client.getConnection()
        let lateInvalidation = try XCTUnwrap(first.invalidationHandler)
        client.resetConnection()
        let second = client.getConnection()
        XCTAssertFalse(second === first)

        lateInvalidation()

        XCTAssertTrue(client.getConnection() === second)
    }
}
