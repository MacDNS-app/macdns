// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// The single Question a passthrough UDP exchange is waiting for.
///
/// `wire` keeps the bytes exactly as they were sent, so a synthesized reply
/// echoes the client's own label casing. `normalized` lowercases the QNAME so a
/// resolver that answers with different casing still matches.
struct DNSQuestion: Equatable {
    let transactionID: UInt16
    let wire: [UInt8]
    let normalized: [UInt8]
    /// Nil when the query carried no EDNS(0) OPT record.
    let edns: DNSEDNS?
}

/// What a synthesized reply must echo from the query's OPT record.
struct DNSEDNS: Equatable {
    let dnssecOK: Bool
}

/// Matches passthrough UDP responses against the query still in flight, and
/// rebuilds a datagram that did not fit the receive buffer as a truncated reply.
///
/// RFC 5452 section 9.1 requires the transaction ID and the Question to match
/// before a response is accepted. The connected socket covers the source address
/// and port.
enum DNSResponseCorrelator {
    static let headerLength = 12

    private static let maximumNameLength = 255
    private static let maximumLabelLength = 63
    private static let responseFlag: UInt8 = 0x80
    private static let truncatedFlag: UInt8 = 0x02
    private static let optType: UInt8 = 41
    private static let optRecordLength = 11
    private static let dnssecOKFlag: UInt8 = 0x80
    /// RFC 6891 section 6.2.5 starting point for a responder's payload size.
    private static let advertisedUDPPayloadSize: UInt16 = 4096

    /// Reads the Question of an outgoing query. Returns nil for anything this
    /// exchange cannot correlate later, which the caller must fail rather than
    /// forward blindly.
    static func question(inQuery query: Data) -> DNSQuestion? {
        let bytes = [UInt8](query)
        guard bytes.count >= headerLength else { return nil }
        guard bytes[2] & responseFlag == 0 else { return nil }
        guard questionCount(bytes) == 1 else { return nil }
        guard let parsed = parseQuestion(bytes) else { return nil }
        return DNSQuestion(
            transactionID: transactionID(bytes),
            wire: parsed.wire,
            normalized: parsed.normalized,
            edns: parseEDNS(bytes, after: parsed.end)
        )
    }

    static func matches(response: Data, question: DNSQuestion) -> Bool {
        let bytes = [UInt8](response)
        guard bytes.count >= headerLength else { return false }
        guard transactionID(bytes) == question.transactionID else { return false }
        guard bytes[2] & responseFlag != 0 else { return false }
        guard questionCount(bytes) == 1 else { return false }
        guard let parsed = parseQuestion(bytes) else { return false }
        return parsed.normalized == question.normalized
    }

    /// Rebuilds `response` as an empty `TC=1` answer, keeping its opcode, RD, RA,
    /// and RCODE, plus one OPT record when the query used EDNS(0) so the client
    /// still sees an EDNS-aware responder. A datagram larger than the receive
    /// buffer must never be forwarded as a prefix: the client would parse a
    /// malformed message instead of retrying over TCP.
    static func truncatedResponse(from response: Data, question: DNSQuestion) -> Data? {
        let bytes = [UInt8](response)
        guard bytes.count >= headerLength else { return nil }

        var wire = Data()
        wire.append(UInt8(question.transactionID >> 8))
        wire.append(UInt8(question.transactionID & 0x00FF))
        wire.append(bytes[2] | responseFlag | truncatedFlag)
        wire.append(bytes[3])
        wire.append(contentsOf: [0x00, 0x01])
        wire.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        wire.append(contentsOf: question.edns == nil ? [0x00, 0x00] : [0x00, 0x01])
        wire.append(contentsOf: question.wire)
        if let edns = question.edns {
            wire.append(contentsOf: optRecord(dnssecOK: edns.dnssecOK))
        }
        return wire
    }

    private static func transactionID(_ bytes: [UInt8]) -> UInt16 {
        UInt16(bytes[0]) << 8 | UInt16(bytes[1])
    }

    private static func questionCount(_ bytes: [UInt8]) -> Int {
        recordCount(bytes, at: 4)
    }

    private static func recordCount(_ bytes: [UInt8], at offset: Int) -> Int {
        Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
    }

    /// The OPT record of a query whose only extra record is EDNS(0). Any other
    /// layout leaves the synthesized reply without OPT, which the client reads
    /// as a plain DNS answer.
    private static func parseEDNS(_ bytes: [UInt8], after questionEnd: Int) -> DNSEDNS? {
        guard recordCount(bytes, at: 6) == 0, recordCount(bytes, at: 8) == 0 else { return nil }
        guard recordCount(bytes, at: 10) == 1 else { return nil }
        guard questionEnd + optRecordLength <= bytes.count else { return nil }
        guard bytes[questionEnd] == 0x00, bytes[questionEnd + 1] == 0x00, bytes[questionEnd + 2] == optType
        else { return nil }
        return DNSEDNS(dnssecOK: bytes[questionEnd + 7] & dnssecOKFlag != 0)
    }

    private static func optRecord(dnssecOK: Bool) -> [UInt8] {
        [
            0x00, 0x00, optType,
            UInt8(advertisedUDPPayloadSize >> 8), UInt8(advertisedUDPPayloadSize & 0x00FF),
            0x00, 0x00, dnssecOK ? dnssecOKFlag : 0x00, 0x00,
            0x00, 0x00,
        ]
    }

    private static func parseQuestion(_ bytes: [UInt8]) -> (wire: [UInt8], normalized: [UInt8], end: Int)? {
        let start = headerLength
        var index = start
        var nameLength = 0
        var normalized: [UInt8] = []

        while true {
            guard index < bytes.count else { return nil }
            // Rejects compression pointers too: their first octet is >= 0xC0,
            // and the first Question has nothing before it to point at.
            let labelLength = Int(bytes[index])
            guard labelLength <= maximumLabelLength else { return nil }
            nameLength += labelLength + 1
            guard nameLength <= maximumNameLength else { return nil }
            normalized.append(bytes[index])
            index += 1
            if labelLength == 0 { break }
            guard index + labelLength <= bytes.count else { return nil }
            for offset in index..<(index + labelLength) {
                normalized.append(lowercased(bytes[offset]))
            }
            index += labelLength
        }

        let end = index + 4
        guard end <= bytes.count else { return nil }
        normalized.append(contentsOf: bytes[index..<end])
        return (wire: Array(bytes[start..<end]), normalized: normalized, end: end)
    }

    private static func lowercased(_ byte: UInt8) -> UInt8 {
        (byte >= 0x41 && byte <= 0x5A) ? byte + 0x20 : byte
    }
}
