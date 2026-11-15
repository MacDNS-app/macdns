// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// Minimal DNS wire builder shared by the exchange, correlator, and pool tests.
enum DNSWire {
    static func message(
        id: UInt16,
        flags: (UInt8, UInt8),
        questionCount: UInt16 = 1,
        name: String,
        type: UInt16 = 1,
        klass: UInt16 = 1,
        answerCount: UInt16 = 0
    ) -> Data {
        var wire = Data()
        wire.append(contentsOf: [UInt8(id >> 8), UInt8(id & 0x00FF)])
        wire.append(contentsOf: [flags.0, flags.1])
        wire.append(contentsOf: [UInt8(questionCount >> 8), UInt8(questionCount & 0x00FF)])
        wire.append(contentsOf: [UInt8(answerCount >> 8), UInt8(answerCount & 0x00FF)])
        wire.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        wire.append(contentsOf: question(name: name, type: type, klass: klass))
        return wire
    }

    static func question(name: String, type: UInt16 = 1, klass: UInt16 = 1) -> [UInt8] {
        var wire: [UInt8] = []
        for label in name.split(separator: ".") {
            wire.append(UInt8(label.count))
            wire.append(contentsOf: Array(label.utf8))
        }
        wire.append(0x00)
        wire.append(contentsOf: [UInt8(type >> 8), UInt8(type & 0x00FF)])
        wire.append(contentsOf: [UInt8(klass >> 8), UInt8(klass & 0x00FF)])
        return wire
    }

    /// One EDNS(0) OPT pseudo-record: root name, type 41, UDP payload size as
    /// class, extended RCODE 0, version 0, DO flag, no options.
    static func opt(payloadSize: UInt16, dnssecOK: Bool) -> [UInt8] {
        [
            0x00, 0x00, 0x29,
            UInt8(payloadSize >> 8), UInt8(payloadSize & 0x00FF),
            0x00, 0x00, dnssecOK ? 0x80 : 0x00, 0x00,
            0x00, 0x00,
        ]
    }

    static let queryFlags: (UInt8, UInt8) = (0x01, 0x00)
    static let responseFlags: (UInt8, UInt8) = (0x81, 0x80)
}
