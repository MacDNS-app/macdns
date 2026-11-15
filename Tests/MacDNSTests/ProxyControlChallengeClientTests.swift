// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import DNSProxyExtension

/// Immutable cross-language golden vector. The identical session id, key, nonce,
/// question wire and MACs are asserted against the Rust producer in
/// `rust-resolver/crates/macdns-resolver/src/proxy_control.rs`
/// (`golden_vector_matches_the_cross_language_wire_contract`). Nothing here
/// recomputes a MAC (only the production verifier derives one), so a one-sided
/// change to the signing payload fails in exactly one language instead of
/// silently shipping an extension that rejects every valid MAC.
private enum GoldenVector {
    static let sessionID = Data((0..<16).map { UInt8($0) })
    static let hmacKey = Data((0..<32).map { UInt8(0x40 + $0) })
    static let nonce = Data((0..<32).map { UInt8(0x80 + $0) })
    static let transactionID: UInt16 = 0x4321
    static let sessionHex = "000102030405060708090a0b0c0d0e0f"
    static let nameUDP =
        "808182838485868788898a8b8c8d8e8f.909192939495969798999a9b9c9d9e9f.u._probe.macdns."
    static let nameTCP =
        "808182838485868788898a8b8c8d8e8f.909192939495969798999a9b9c9d9e9f.t._probe.macdns."
    static let questionUDPHex =
        "2038303831383238333834383538363837383838393861386238633864386538"
        + "6620393039313932393339343935393639373938393939613962396339643965"
        + "39660175065f70726f6265066d6163646e730000100001"
    static let questionTCPHex =
        "2038303831383238333834383538363837383838393861386238633864386538"
        + "6620393039313932393339343935393639373938393939613962396339643965"
        + "39660174065f70726f6265066d6163646e730000100001"
    static let macUDPReady =
        "932f0757f407dddec98e0e50f5eda85c9f6353f6d024fe959b84aa270ab4fbc4"
    static let macTCPReady =
        "748a6996702f4bbcdce1d813fe1bd5c8a0b0a33a251e916043517590c7668062"
    static let macUDPNotReady =
        "bd968864578c6298a2a60ec0ccc7a96ed47e1593fc9951086e2009c46fdf4b9e"
}

/// Interop guard for the PRODUCTION verifier (`ProxyControlChallengeClient`)
/// used by the DNS Proxy. It builds a response in the exact byte layout the
/// Rust resolver + hickory produce (compression pointer 0xC00C, single TXT
/// character-string, no OPT) and asserts that verify() accepts it and rejects
/// every tamper. A drift here is the "permanent bypass" failure class.
final class ProxyControlChallengeClientTests: XCTestCase {
    private let session = ProxyControlSession(
        version: 1, sessionID: GoldenVector.sessionID, hmacKey: GoldenVector.hmacKey)

    func testQueryNameMatchesGoldenVector() {
        XCTAssertEqual(
            ProxyControlChallengeClient.queryName(nonce: GoldenVector.nonce, transport: .udp),
            GoldenVector.nameUDP)
        XCTAssertEqual(
            ProxyControlChallengeClient.queryName(nonce: GoldenVector.nonce, transport: .tcp),
            GoldenVector.nameTCP)
    }

    func testQuestionWireMatchesGoldenVector() {
        XCTAssertEqual(
            ProxyControlChallengeClient.questionWire(name: GoldenVector.nameUDP).goldenHex,
            GoldenVector.questionUDPHex)
        XCTAssertEqual(
            ProxyControlChallengeClient.questionWire(name: GoldenVector.nameTCP).goldenHex,
            GoldenVector.questionTCPHex)
    }

    func testVerifyAcceptsGoldenUDPResponse() {
        let c = challenge(transport: .udp)
        XCTAssertEqual(
            ProxyControlChallengeClient.verify(
                response: makeResponse(c, ready: true, macHex: GoldenVector.macUDPReady),
                transactionID: c.txID, session: session, transport: .udp,
                nonce: c.nonce, question: c.question), .ready)
    }

    func testVerifyAcceptsGoldenTCPResponse() {
        let c = challenge(transport: .tcp)
        XCTAssertEqual(
            ProxyControlChallengeClient.verify(
                response: makeResponse(c, ready: true, macHex: GoldenVector.macTCPReady),
                transactionID: c.txID, session: session, transport: .tcp,
                nonce: c.nonce, question: c.question), .ready)
    }

    func testVerifyRejectsCorruptMAC() {
        let c = challenge(transport: .udp)
        XCTAssertEqual(
            ProxyControlChallengeClient.verify(
                response: makeResponse(
                    c, ready: true, macHex: Self.corrupted(GoldenVector.macUDPReady)),
                transactionID: c.txID, session: session, transport: .udp,
                nonce: c.nonce, question: c.question),
            .failed(.init(stage: .authentication, reason: .authenticationMismatch)))
    }

    /// An authenticated zero is still a bypass, but it must be distinguishable
    /// from an unauthenticated response so the reason reported is the resolver,
    /// not the transport.
    func testVerifyReportsAuthenticatedReadyZeroAsNotReady() {
        let c = challenge(transport: .udp)
        XCTAssertEqual(
            ProxyControlChallengeClient.verify(
                response: makeResponse(c, ready: false, macHex: GoldenVector.macUDPNotReady),
                transactionID: c.txID, session: session, transport: .udp,
                nonce: c.nonce, question: c.question), .notReady)
    }

    func testVerifyRejectsUnauthenticatedReadyZero() {
        let c = challenge(transport: .udp)
        XCTAssertEqual(
            ProxyControlChallengeClient.verify(
                response: makeResponse(
                    c, ready: false, macHex: Self.corrupted(GoldenVector.macUDPNotReady)),
                transactionID: c.txID, session: session, transport: .udp,
                nonce: c.nonce, question: c.question),
            .failed(.init(stage: .authentication, reason: .authenticationMismatch)))
    }

    func testVerifyRejectsWrongTransportExpectation() {
        // A UDP-format response cannot satisfy a TCP check.
        let c = challenge(transport: .udp)
        XCTAssertEqual(
            ProxyControlChallengeClient.verify(
                response: makeResponse(c, ready: true, macHex: GoldenVector.macUDPReady),
                transactionID: c.txID, session: session, transport: .tcp,
                nonce: c.nonce, question: c.question),
            .failed(.init(stage: .response, reason: .invalidResponse)))
    }

    func testVerifyRejectsWrongTransactionID() {
        let c = challenge(transport: .udp)
        XCTAssertEqual(
            ProxyControlChallengeClient.verify(
                response: makeResponse(c, ready: true, macHex: GoldenVector.macUDPReady),
                transactionID: c.txID &+ 1, session: session, transport: .udp,
                nonce: c.nonce, question: c.question),
            .failed(.init(stage: .response, reason: .invalidResponse)))
    }

    func testVerifyRejectsTrailingAdditionalRecord() {
        // An appended OPT/additional record (ARCOUNT!=0) must be rejected. The
        // parser requires the TXT answer to be the last bytes on the wire.
        let c = challenge(transport: .udp)
        XCTAssertEqual(
            ProxyControlChallengeClient.verify(
                response: makeResponse(
                    c, ready: true, macHex: GoldenVector.macUDPReady, extraAR: true),
                transactionID: c.txID, session: session, transport: .udp,
                nonce: c.nonce, question: c.question),
            .failed(.init(stage: .response, reason: .invalidResponse)))
    }

    func testMalformedReplyIsIdentifiedBeforeAuthentication() {
        let c = challenge(transport: .udp)

        XCTAssertEqual(
            ProxyControlChallengeClient.verify(
                response: Data([0x43, 0x21]), transactionID: c.txID,
                session: session, transport: .udp, nonce: c.nonce, question: c.question),
            .failed(.init(stage: .response, reason: .invalidResponse)))
    }

    // MARK: - Rust-format response construction

    private struct Challenge {
        let nonce: Data
        let question: Data
        let txID: UInt16
        let transport: ProxyControlChallengeClientTransport
    }

    /// The question is built by the production encoder, so a drift between the
    /// Swift name/wire encoding and the wire the golden MAC was signed over also
    /// fails the verify tests, not only the wire assertion above.
    private func challenge(transport: ProxyControlChallengeClientTransport) -> Challenge {
        let name = ProxyControlChallengeClient.queryName(
            nonce: GoldenVector.nonce, transport: transport)
        return Challenge(
            nonce: GoldenVector.nonce,
            question: ProxyControlChallengeClient.questionWire(name: name),
            txID: GoldenVector.transactionID,
            transport: transport)
    }

    /// Flips one hex digit so the MAC stays well-formed but no longer verifies.
    private static func corrupted(_ macHex: String) -> String {
        (macHex.first == "0" ? "1" : "0") + macHex.dropFirst()
    }

    /// Replicates the hickory/`finalize_wire` TXT answer encoding byte-for-byte
    /// around a MAC taken verbatim from the golden vector.
    private func makeResponse(
        _ c: Challenge, ready: Bool, macHex: String, extraAR: Bool = false
    ) -> Data {
        let txt = "v1 \(GoldenVector.sessionHex) \(c.transport.label) \(ready ? "1" : "0") \(macHex)"

        var wire = Data()
        wire.append(contentsOf: [UInt8(c.txID >> 8), UInt8(c.txID & 0xFF)])
        wire.append(contentsOf: [0x81, 0x80])  // QR=1, RD=1, RA=1, RCODE=0
        wire.append(contentsOf: [0x00, 0x01])  // QDCOUNT
        wire.append(contentsOf: [0x00, 0x01])  // ANCOUNT
        wire.append(contentsOf: [0x00, 0x00])  // NSCOUNT
        wire.append(contentsOf: extraAR ? [0x00, 0x01] : [0x00, 0x00])  // ARCOUNT
        wire.append(c.question)
        wire.append(contentsOf: [0xC0, 0x0C])  // name pointer to question
        wire.append(contentsOf: [0x00, 0x10, 0x00, 0x01])  // TYPE TXT, CLASS IN
        wire.append(contentsOf: [0x00, 0x00, 0x00, 0x00])  // TTL 0
        let txtBytes = Array(txt.utf8)
        let rdlen = UInt16(txtBytes.count + 1)
        wire.append(contentsOf: [UInt8(rdlen >> 8), UInt8(rdlen & 0xFF)])
        wire.append(UInt8(txtBytes.count))
        wire.append(contentsOf: txtBytes)
        if extraAR {
            // A minimal OPT record in the additional section.
            wire.append(0x00)  // root name
            wire.append(contentsOf: [0x00, 0x29])  // TYPE OPT
            wire.append(contentsOf: [0x10, 0x00])  // UDP size 4096
            wire.append(contentsOf: [0x00, 0x00, 0x00, 0x00])  // ext-rcode/flags
            wire.append(contentsOf: [0x00, 0x00])  // RDLEN 0
        }
        return wire
    }
}

extension Data {
    fileprivate var goldenHex: String { map { String(format: "%02x", $0) }.joined() }
}
