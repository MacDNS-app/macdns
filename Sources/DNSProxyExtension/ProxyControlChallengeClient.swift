// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import CryptoKit
import Foundation

enum ProxyControlChallengeClientTransport {
    case udp, tcp
    var label: String { self == .udp ? "u" : "t" }
    var tag: UInt8 { self == .udp ? 0x75 : 0x74 }
}

/// Result of one challenge exchange. Separating an authenticated `ready = 0`
/// from a transport or authentication failure is what lets the health decision
/// report the real root cause instead of always blaming the resolver.
enum ProxyControlChallengeOutcome: Equatable {
    /// Authenticated response signed over `ready = 1`.
    case ready
    /// Authenticated response signed over `ready = 0`.
    case notReady
    case failed(ProxyProbeFailure)

    var isAuthenticated: Bool {
        if case .failed = self { return false }
        return true
    }
}

enum ProxyControlChallengeClient {
    private static let domainSeparator = "macdns-proxy-control-v1"
    private static let version: UInt16 = 1

    /// Returns nil if the system RNG fails, so the caller fails the probe
    /// closed (bypass) rather than sending a predictable all-zero nonce that
    /// would weaken the replay defense.
    static func randomNonce() -> Data? {
        var nonce = Data(count: 32)
        let ok = nonce.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        guard ok == errSecSuccess else { return nil }
        return nonce
    }

    static func queryName(nonce: Data, transport: ProxyControlChallengeClientTransport) -> String {
        let first = nonce.prefix(16).map { String(format: "%02x", $0) }.joined()
        let second = nonce.suffix(16).map { String(format: "%02x", $0) }.joined()
        return "\(first).\(second).\(transport.label)._probe.macdns."
    }

    static func questionWire(name: String) -> Data {
        var wire = Data()
        for label in name.split(separator: ".") {
            wire.append(UInt8(label.count))
            wire.append(contentsOf: label.utf8)
        }
        wire.append(0x00)
        wire.append(contentsOf: [0x00, 0x10, 0x00, 0x01])
        return wire
    }

    static func verify(
        response: Data, transactionID: UInt16, session: ProxyControlSession,
        transport: ProxyControlChallengeClientTransport, nonce: Data, question: Data
    ) -> ProxyControlChallengeOutcome {
        let invalidResponse = ProxyControlChallengeOutcome.failed(
            .init(stage: .response, reason: .invalidResponse))
        let header = 12
        guard response.count >= header + question.count else { return invalidResponse }
        let bytes = [UInt8](response)
        guard UInt16(bytes[0]) << 8 | UInt16(bytes[1]) == transactionID else { return invalidResponse }
        guard bytes[2] & 0x80 != 0, bytes[3] & 0x0F == 0 else { return invalidResponse }
        guard UInt16(bytes[4]) << 8 | UInt16(bytes[5]) == 1 else { return invalidResponse }
        guard UInt16(bytes[6]) << 8 | UInt16(bytes[7]) == 1 else { return invalidResponse }
        guard UInt16(bytes[8]) << 8 | UInt16(bytes[9]) == 0 else { return invalidResponse }
        guard UInt16(bytes[10]) << 8 | UInt16(bytes[11]) == 0 else { return invalidResponse }
        let respQuestion = response.subdata(in: header..<(header + question.count))
        guard respQuestion == question else { return invalidResponse }
        guard let txt = Self.singleTXT(response, offset: header + question.count) else {
            return invalidResponse
        }
        let tokens = txt.split(separator: " ", omittingEmptySubsequences: false)
        guard tokens.count == 5, tokens[0] == "v1",
            tokens[1] == session.sessionIDHex, tokens[2] == transport.label,
            let readyByte = Self.readyByte(String(tokens[3])), tokens[4].count == 64,
            let mac = Data(challengeHexLower: String(tokens[4]))
        else { return invalidResponse }

        var payload = Data(domainSeparator.utf8)
        payload.append(contentsOf: [UInt8(version >> 8), UInt8(version & 0xFF)])
        payload.append(session.sessionID)
        payload.append(transport.tag)
        payload.append(readyByte)
        payload.append(nonce)
        payload.append(contentsOf: SHA256.hash(data: question))
        let expected = Data(
            HMAC<SHA256>.authenticationCode(for: payload, using: session.hmacKey))
        guard constantTimeEquals(mac, expected) else {
            return .failed(.init(stage: .authentication, reason: .authenticationMismatch))
        }
        return readyByte == 0x01 ? .ready : .notReady
    }

    /// Only the two wire-defined ready values are accepted. Anything else is an
    /// unauthenticated malformed response, not a not-ready report.
    private static func readyByte(_ token: String) -> UInt8? {
        switch token {
        case "1": return 0x01
        case "0": return 0x00
        default: return nil
        }
    }

    private static func singleTXT(_ response: Data, offset: Int) -> String? {
        let bytes = [UInt8](response)
        var i = offset
        guard i + 12 <= bytes.count, bytes[i] == 0xC0, bytes[i + 1] == 0x0C else { return nil }
        i += 2
        guard bytes[i] == 0x00, bytes[i + 1] == 0x10, bytes[i + 2] == 0x00, bytes[i + 3] == 0x01
        else { return nil }
        i += 4 + 4  // type/class + TTL
        let rdlen = Int(bytes[i]) << 8 | Int(bytes[i + 1])
        i += 2
        guard i + rdlen == bytes.count, rdlen >= 1 else { return nil }
        let strLen = Int(bytes[i])
        i += 1
        guard strLen == rdlen - 1, i + strLen == bytes.count else { return nil }
        return String(bytes: bytes[i..<(i + strLen)], encoding: .utf8)
    }

    private static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }
}

extension Data {
    fileprivate init?(challengeHexLower string: String) {
        let chars = Array(string)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = chars[i].hexDigitValue, let lo = chars[i + 1].hexDigitValue
            else { return nil }
            out.append(UInt8(hi << 4 | lo))
            i += 2
        }
        self = out
    }
}
