// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import XCTest

@testable import DNSProxyExtension

/// Builds DNS wire messages so the correlator can be exercised on real bytes
/// rather than on a mock of itself.
final class DNSResponseCorrelatorTests: XCTestCase {

    private func query(
        id: UInt16 = 0x1234,
        name: String = "example.com",
        type: UInt16 = 1
    ) -> Data {
        DNSWire.message(id: id, flags: DNSWire.queryFlags, name: name, type: type)
    }

    // MARK: - Question extraction

    func testQuestionIsReadFromAWellFormedQuery() {
        let outstanding = DNSResponseCorrelator.question(inQuery: query())

        XCTAssertEqual(outstanding?.transactionID, 0x1234)
        XCTAssertEqual(outstanding?.wire, DNSWire.question(name: "example.com"))
    }

    func testQuestionIsRefusedWhenTheQueryCarriesNoSingleQuestion() {
        let noQuestion = DNSWire.message(
            id: 1, flags: DNSWire.queryFlags, questionCount: 0, name: "example.com")
        let twoQuestions = DNSWire.message(
            id: 1, flags: DNSWire.queryFlags, questionCount: 2, name: "example.com")

        XCTAssertNil(DNSResponseCorrelator.question(inQuery: noQuestion))
        XCTAssertNil(DNSResponseCorrelator.question(inQuery: twoQuestions))
    }

    func testQuestionIsRefusedWhenTheNameUsesACompressionPointer() {
        var wire = Data(query().prefix(DNSResponseCorrelator.headerLength))
        wire.append(contentsOf: [0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01])

        XCTAssertNil(DNSResponseCorrelator.question(inQuery: wire))
    }

    func testQuestionIsRefusedWhenTheMessageIsTruncatedMidName() {
        var wire = Data(query().prefix(DNSResponseCorrelator.headerLength))
        wire.append(contentsOf: [0x07, 0x65, 0x78])

        XCTAssertNil(DNSResponseCorrelator.question(inQuery: wire))
    }

    // MARK: - Response matching

    func testResponseMatchesTheOutstandingTransaction() {
        let outstanding = DNSResponseCorrelator.question(inQuery: query())!
        let response = DNSWire.message(
            id: 0x1234, flags: DNSWire.responseFlags, name: "example.com")

        XCTAssertTrue(DNSResponseCorrelator.matches(response: response, question: outstanding))
    }

    func testResponseWithADifferentTransactionIDIsRejected() {
        let outstanding = DNSResponseCorrelator.question(inQuery: query())!
        let response = DNSWire.message(
            id: 0x1235, flags: DNSWire.responseFlags, name: "example.com")

        XCTAssertFalse(DNSResponseCorrelator.matches(response: response, question: outstanding))
    }

    func testQueryShapedDatagramIsRejectedAsAResponse() {
        let outstanding = DNSResponseCorrelator.question(inQuery: query())!
        let response = DNSWire.message(
            id: 0x1234, flags: DNSWire.queryFlags, name: "example.com")

        XCTAssertFalse(DNSResponseCorrelator.matches(response: response, question: outstanding))
    }

    func testResponseForADifferentNameIsRejected() {
        let outstanding = DNSResponseCorrelator.question(inQuery: query())!
        let response = DNSWire.message(
            id: 0x1234, flags: DNSWire.responseFlags, name: "example.net")

        XCTAssertFalse(DNSResponseCorrelator.matches(response: response, question: outstanding))
    }

    func testResponseForADifferentTypeOrClassIsRejected() {
        let outstanding = DNSResponseCorrelator.question(inQuery: query())!
        let otherType = DNSWire.message(
            id: 0x1234, flags: DNSWire.responseFlags, name: "example.com", type: 28)
        let otherClass = DNSWire.message(
            id: 0x1234, flags: DNSWire.responseFlags, name: "example.com", klass: 3)

        XCTAssertFalse(DNSResponseCorrelator.matches(response: otherType, question: outstanding))
        XCTAssertFalse(DNSResponseCorrelator.matches(response: otherClass, question: outstanding))
    }

    func testResponseEchoingDifferentLabelCasingStillMatches() {
        let outstanding = DNSResponseCorrelator.question(inQuery: query(name: "ExAmPlE.CoM"))!
        let response = DNSWire.message(
            id: 0x1234, flags: DNSWire.responseFlags, name: "example.com")

        XCTAssertTrue(DNSResponseCorrelator.matches(response: response, question: outstanding))
    }

    func testResponseWithoutAQuestionSectionIsRejected() {
        let outstanding = DNSResponseCorrelator.question(inQuery: query())!
        let response = DNSWire.message(
            id: 0x1234, flags: DNSWire.responseFlags, questionCount: 0, name: "example.com")

        XCTAssertFalse(DNSResponseCorrelator.matches(response: response, question: outstanding))
    }

    // MARK: - Truncation

    func testTruncatedResponseSetsTCAndDropsEveryRecordSection() {
        let outstanding = DNSResponseCorrelator.question(inQuery: query())!
        let oversized = DNSWire.message(
            id: 0x1234, flags: DNSWire.responseFlags, name: "example.com", answerCount: 12)

        let truncated = DNSResponseCorrelator.truncatedResponse(
            from: oversized, question: outstanding)!
        let bytes = [UInt8](truncated)

        XCTAssertEqual(UInt16(bytes[0]) << 8 | UInt16(bytes[1]), 0x1234)
        XCTAssertEqual(bytes[2] & 0x02, 0x02, "TC must be set")
        XCTAssertEqual(bytes[2] & 0x80, 0x80, "QR must stay set")
        XCTAssertEqual(bytes[3], DNSWire.responseFlags.1, "RA and RCODE must be preserved")
        XCTAssertEqual(Array(bytes[4..<12]), [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        XCTAssertEqual(Array(bytes[12...]), outstanding.wire)
    }

    func testTruncatedResponseStaysCorrelatableAndKeepsTheClientLabelCasing() {
        let outstanding = DNSResponseCorrelator.question(inQuery: query(name: "ExAmPlE.CoM"))!
        let oversized = DNSWire.message(
            id: 0x1234, flags: DNSWire.responseFlags, name: "example.com", answerCount: 40)

        let truncated = DNSResponseCorrelator.truncatedResponse(
            from: oversized, question: outstanding)!

        XCTAssertTrue(DNSResponseCorrelator.matches(response: truncated, question: outstanding))
        XCTAssertEqual(Array([UInt8](truncated)[12...]), DNSWire.question(name: "ExAmPlE.CoM"))
    }

    func testTruncatedResponseCarriesOneOPTWhenTheQueryUsedEDNS() throws {
        var query = DNSWire.message(id: 0x1234, flags: DNSWire.queryFlags, name: "example.com")
        query[11] = 0x01
        query.append(contentsOf: DNSWire.opt(payloadSize: 1232, dnssecOK: true))
        let question = try XCTUnwrap(DNSResponseCorrelator.question(inQuery: query))
        let response = DNSWire.message(id: 0x1234, flags: DNSWire.responseFlags, name: "example.com")

        let truncated = try XCTUnwrap(DNSResponseCorrelator.truncatedResponse(from: response, question: question))

        XCTAssertEqual(Array(truncated[10...11]), [0x00, 0x01])
        XCTAssertEqual(Array(truncated.dropFirst(12).dropLast(11)), DNSWire.question(name: "example.com"))
        XCTAssertEqual(Array(truncated.suffix(11)), DNSWire.opt(payloadSize: 4096, dnssecOK: true))
    }

    func testTruncatedResponseOPTLeavesDOClearWhenTheQueryDidNotSetIt() throws {
        var query = DNSWire.message(id: 0x1234, flags: DNSWire.queryFlags, name: "example.com")
        query[11] = 0x01
        query.append(contentsOf: DNSWire.opt(payloadSize: 1232, dnssecOK: false))
        let question = try XCTUnwrap(DNSResponseCorrelator.question(inQuery: query))
        let response = DNSWire.message(id: 0x1234, flags: DNSWire.responseFlags, name: "example.com")

        let truncated = try XCTUnwrap(DNSResponseCorrelator.truncatedResponse(from: response, question: question))

        XCTAssertEqual(Array(truncated.suffix(11)), DNSWire.opt(payloadSize: 4096, dnssecOK: false))
    }

    func testTruncatedResponseNeedsAtLeastAHeader() {
        let outstanding = DNSResponseCorrelator.question(inQuery: query())!

        XCTAssertNil(
            DNSResponseCorrelator.truncatedResponse(
                from: Data([0x12, 0x34]), question: outstanding))
    }

    // MARK: - Source correlation

    /// The source-endpoint half of RFC 5452 section 9.1 is delegated to the
    /// kernel by connecting the exchange socket. This pins that delegation: an
    /// off-path datagram must never reach the exchange's receive queue.
    func testConnectedSocketNeverDeliversAnOffPathDatagram() throws {
        let destination = try LoopbackUDPSocket()
        let offPath = try LoopbackUDPSocket()
        let exchange = try LoopbackUDPSocket()
        try exchange.connect(to: destination.address)

        offPath.send([0xDE, 0xAD], to: exchange.address)
        destination.send([0xBE, 0xEF], to: exchange.address)

        XCTAssertEqual(exchange.receive(), [0xBE, 0xEF])
        XCTAssertNil(exchange.receive(), "only the connected peer may be received from")
    }
}
