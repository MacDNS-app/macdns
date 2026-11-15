// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import CryptoKit
import Foundation
import Shared

// MARK: - Keygen account verify key

/// Ed25519 verify key of the Keygen account, hex-encoded (32 bytes / 64 hex chars).
///
/// Public by design and pinned in the binary, because it is what stops an
/// on-path proxy from forging an "active license" response. It is bound to the
/// account in `LicenseManager.KeygenConfig.accountId`, so pointing the agent at
/// a different account requires replacing this value too.
///
/// A value that does not decode to a valid 32-byte key makes
/// `LicenseResponseVerifier` report `verifyKeyNotConfigured` for every response,
/// so nothing is ever authoritative, no verdict is persisted as terminal and the
/// fail-closed latch can never be cleared.
enum KeygenVerifyKey {
    static let accountPublicKeyHex =
        "c75b0a46d210204b8d34284bebed270a90b2592daf930b530a53e47ccaeec7c1"

    static func publicKey(
        hex: String = accountPublicKeyHex
    ) -> Curve25519.Signing.PublicKey? {
        guard
            let raw = Data(licenseHexEncoded: hex),
            raw.count == 32,
            let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw)
        else {
            return nil
        }
        return key
    }
}

// MARK: - Authoritative evidence

/// Cryptographic proof that a license API response really came from the Keygen
/// account: response signature, body digest, signed request target, signed
/// server date freshness and, where the endpoint supports it, the validation
/// nonce were all verified.
///
/// Only `LicenseResponseVerifier` can build one. The initializer is private to
/// this file. Every durable authoritative license transition requires this
/// value, so a forged or unverified response can never clear the fail-closed
/// latch nor persist a terminal verdict.
struct AuthoritativeEvidence: Equatable, Sendable {
    /// Signed server time taken from the verified `Date` header.
    let serverTime: Date
    /// Signed request target the response was bound to.
    let requestTarget: String
    /// The answer itself, when it is bound to a nonce. `validate-key` is the
    /// only endpoint that echoes one, so only its answers can be stored and
    /// verified again offline.
    let receipt: LicenseValidationReceipt?

    fileprivate init(
        serverTime: Date,
        requestTarget: String,
        receipt: LicenseValidationReceipt?
    ) {
        self.serverTime = serverTime
        self.requestTarget = requestTarget
        self.receipt = receipt
    }
}

// MARK: - Failures

/// Why a license API response could not be trusted. Every case is a
/// transport or protocol failure, retryable and never authoritative.
enum LicenseResponseVerificationFailure: Error, Equatable, Sendable,
    CustomStringConvertible
{
    case verifyKeyNotConfigured
    case unexpectedHost(String)
    case malformedRequestTarget
    case missingSignatureHeader
    case malformedSignatureHeader
    case unsupportedAlgorithm(String)
    case keyIdMismatch
    case signedHeadersMismatch(String)
    case missingDigestHeader
    case digestMismatch
    case missingDateHeader
    case malformedDateHeader
    case staleResponse
    case freshnessUnverifiable
    case signatureMismatch
    case nonceMismatch

    var description: String {
        switch self {
        case .verifyKeyNotConfigured:
            return "Keygen account verify key is not configured"
        case .unexpectedHost(let host):
            return "Unexpected license API host: \(host)"
        case .malformedRequestTarget:
            return "License response has no usable request target"
        case .missingSignatureHeader:
            return "License response is unsigned"
        case .malformedSignatureHeader:
            return "License response signature header is malformed"
        case .unsupportedAlgorithm(let algorithm):
            return "Unsupported license response signature algorithm: \(algorithm)"
        case .keyIdMismatch:
            return "License response was signed for another Keygen account"
        case .signedHeadersMismatch(let headers):
            return "License response signed unexpected headers: \(headers)"
        case .missingDigestHeader:
            return "License response has no body digest"
        case .digestMismatch:
            return "License response body does not match its digest"
        case .missingDateHeader:
            return "License response has no date"
        case .malformedDateHeader:
            return "License response date is malformed"
        case .staleResponse:
            return "License response is outside the accepted freshness window"
        case .freshnessUnverifiable:
            return
                "License response freshness cannot be verified: the local clock is not trusted and the response carries no nonce"
        case .signatureMismatch:
            return "License response signature is invalid"
        case .nonceMismatch:
            return "License response replayed a stale validation nonce"
        }
    }
}

// MARK: - Verifier

/// Verifies Keygen response signatures before any response body is interpreted.
///
/// Keygen signs responses following the draft HTTP signatures specification:
/// `Keygen-Signature: keyid="<account>", algorithm="ed25519",
/// signature="<base64>", headers="(request-target) host date digest"` over
///
///     (request-target): <lowercased method> <path>[?<query>]
///     host: <host>
///     date: <Date header>
///     digest: <Digest header>
///
/// joined by `\n` with no trailing newline, where `Digest` is
/// `sha-256=<base64(sha256(body))>` computed over the raw bytes before JSON
/// decoding.
struct LicenseResponseVerifier: Sendable {
    static let signedHeaders = "(request-target) host date digest"
    static let defaultFreshnessTolerance: TimeInterval = 5 * 60
    static let expectedHost = "api.keygen.sh"

    private let publicKey: Curve25519.Signing.PublicKey?
    private let accountId: String
    private let host: String
    private let freshnessTolerance: TimeInterval

    init(
        accountId: String,
        publicKeyHex: String = KeygenVerifyKey.accountPublicKeyHex,
        host: String = LicenseResponseVerifier.expectedHost,
        freshnessTolerance: TimeInterval = LicenseResponseVerifier
            .defaultFreshnessTolerance
    ) {
        self.publicKey = KeygenVerifyKey.publicKey(hex: publicKeyHex)
        self.accountId = accountId
        self.host = host
        self.freshnessTolerance = freshnessTolerance
    }

    var isConfigured: Bool { publicKey != nil }

    /// Generates a fresh validation nonce. Bounded to 2^53-1 so it survives any
    /// JSON number round-trip on the server side.
    static func makeNonce() -> Int {
        Int.random(in: 1...9_007_199_254_740_991)
    }

    /// Verifies a response against `now`, the caller's *trusted* instant.
    ///
    /// A response bound to a fresh `expectedNonce`, which the signed body
    /// echoes, answers this request and cannot be a captured reply, so it is
    /// fresh by construction and skips the time window. A wrong local clock
    /// therefore never blocks it. Every nonce-less response must fall within
    /// `freshnessTolerance` of `now`.
    ///
    /// `now` is nil when the trusted-clock layer refused to produce one, i.e. it
    /// positively detected a clock rollback. Freshness is then unverifiable, and
    /// the untrusted wall clock must never be substituted for it, because a response
    /// captured at the rolled-back instant would replay cleanly. Every
    /// nonce-less response is refused in that case.
    func verify(
        request: URLRequest,
        response: HTTPURLResponse,
        body: Data,
        expectedNonce: Int?,
        now: Date?
    ) -> Result<AuthoritativeEvidence, LicenseResponseVerificationFailure> {
        guard let publicKey else { return .failure(.verifyKeyNotConfigured) }

        // Bound to the request we made, never to `response.url`. A redirected
        // or spoofed response URL must not choose which request target the
        // signature is checked against.
        return signedRequest(method: request.httpMethod, url: request.url).flatMap {
            verify(
                requestTarget: $0.target,
                requestHost: $0.host,
                signatureHeader: response.value(forHTTPHeaderField: "Keygen-Signature"),
                digestHeader: response.value(forHTTPHeaderField: "Digest"),
                dateHeader: response.value(forHTTPHeaderField: "Date"),
                body: body,
                freshness: expectedNonce.map(Freshness.nonce) ?? .window(now: now),
                publicKey: publicKey
            )
        }
    }

    /// Verifies a stored answer against the request it must have answered.
    ///
    /// Nothing here judges its age. The caller reads it from the signed date
    /// in the evidence.
    func verify(
        stored receipt: LicenseValidationReceipt,
        method: String,
        url: URL
    ) -> Result<AuthoritativeEvidence, LicenseResponseVerificationFailure> {
        guard let publicKey else { return .failure(.verifyKeyNotConfigured) }
        return signedRequest(method: method, url: url).flatMap {
            verify(
                requestTarget: $0.target,
                requestHost: $0.host,
                signatureHeader: receipt.signature,
                digestHeader: Self.digest(of: receipt.body),
                dateHeader: receipt.date,
                body: receipt.body,
                freshness: .stored,
                publicKey: publicKey
            )
        }
    }

    private enum Freshness {
        /// Bound to the nonce of the request it answers.
        case nonce(Int)
        /// Within the tolerance of a trusted instant. Nil when there is none.
        case window(now: Date?)
        /// A stored answer, whose age the caller judges.
        case stored
    }

    private func signedRequest(
        method: String?,
        url: URL?
    ) -> Result<(target: String, host: String), LicenseResponseVerificationFailure> {
        guard let url, let requestHost = url.host else {
            return .failure(.malformedRequestTarget)
        }
        guard requestHost.caseInsensitiveCompare(host) == .orderedSame else {
            return .failure(.unexpectedHost(requestHost))
        }
        guard let requestTarget = Self.requestTarget(method: method, url: url) else {
            return .failure(.malformedRequestTarget)
        }
        return .success((requestTarget, requestHost))
    }

    private func verify(
        requestTarget: String,
        requestHost: String,
        signatureHeader: String?,
        digestHeader: String?,
        dateHeader: String?,
        body: Data,
        freshness: Freshness,
        publicKey: Curve25519.Signing.PublicKey
    ) -> Result<AuthoritativeEvidence, LicenseResponseVerificationFailure> {
        guard let rawSignature = signatureHeader else {
            return .failure(.missingSignatureHeader)
        }
        guard let parameters = Self.parseSignatureHeader(rawSignature) else {
            return .failure(.malformedSignatureHeader)
        }
        guard let algorithm = parameters["algorithm"] else {
            return .failure(.malformedSignatureHeader)
        }
        guard algorithm == "ed25519" else {
            return .failure(.unsupportedAlgorithm(algorithm))
        }
        guard parameters["keyid"] == accountId else {
            return .failure(.keyIdMismatch)
        }
        let signedHeaders = parameters["headers"] ?? ""
        guard signedHeaders == Self.signedHeaders else {
            return .failure(.signedHeadersMismatch(signedHeaders))
        }
        guard
            let encodedSignature = parameters["signature"],
            let signature = Data(base64Encoded: encodedSignature)
        else {
            return .failure(.malformedSignatureHeader)
        }

        guard let digestHeader else {
            return .failure(.missingDigestHeader)
        }
        guard Self.digest(of: body) == digestHeader else {
            return .failure(.digestMismatch)
        }

        guard let dateHeader else {
            return .failure(.missingDateHeader)
        }
        guard let serverTime = Self.parseHTTPDate(dateHeader) else {
            return .failure(.malformedDateHeader)
        }
        if case .window(let now) = freshness {
            guard let now else { return .failure(.freshnessUnverifiable) }
            guard abs(serverTime.timeIntervalSince(now)) <= freshnessTolerance else {
                return .failure(.staleResponse)
            }
        }

        let signingString = [
            "(request-target): \(requestTarget)",
            "host: \(requestHost)",
            "date: \(dateHeader)",
            "digest: \(digestHeader)",
        ].joined(separator: "\n")

        guard
            publicKey.isValidSignature(
                signature,
                for: Data(signingString.utf8)
            )
        else {
            return .failure(.signatureMismatch)
        }

        var receipt: LicenseValidationReceipt?
        switch freshness {
        case .nonce(let expectedNonce):
            guard Self.nonce(in: body) == expectedNonce else {
                return .failure(.nonceMismatch)
            }
            fallthrough
        case .stored:
            receipt = LicenseValidationReceipt(
                body: body,
                date: dateHeader,
                signature: rawSignature
            )
        case .window:
            break
        }

        return .success(
            AuthoritativeEvidence(
                serverTime: serverTime,
                requestTarget: requestTarget,
                receipt: receipt
            )
        )
    }

    // MARK: - Signing data

    static func digest(of body: Data) -> String {
        "sha-256=" + Data(SHA256.hash(data: body)).base64EncodedString()
    }

    static func requestTarget(method: String?, url: URL) -> String? {
        guard
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
            !components.percentEncodedPath.isEmpty
        else {
            return nil
        }
        let target: String
        if let query = components.percentEncodedQuery, !query.isEmpty {
            target = "\(components.percentEncodedPath)?\(query)"
        } else {
            target = components.percentEncodedPath
        }
        return "\((method ?? "GET").lowercased()) \(target)"
    }

    static func parseHTTPDate(_ value: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        return formatter.date(from: value)
    }

    static func httpDateString(for date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.string(from: date)
    }

    /// Parses `key="value"` pairs out of a draft HTTP signature header.
    static func parseSignatureHeader(_ raw: String) -> [String: String]? {
        var parameters: [String: String] = [:]
        var index = raw.startIndex

        while index < raw.endIndex {
            while index < raw.endIndex, raw[index] == "," || raw[index].isWhitespace {
                index = raw.index(after: index)
            }
            guard index < raw.endIndex else { break }

            guard let equals = raw[index...].firstIndex(of: "=") else { return nil }
            let key = String(raw[index..<equals]).trimmingCharacters(
                in: .whitespacesAndNewlines
            )
            guard !key.isEmpty else { return nil }

            var cursor = raw.index(after: equals)
            guard cursor < raw.endIndex, raw[cursor] == "\"" else { return nil }
            cursor = raw.index(after: cursor)
            guard let closing = raw[cursor...].firstIndex(of: "\"") else { return nil }

            parameters[key] = String(raw[cursor..<closing])
            index = raw.index(after: closing)
        }

        return parameters.isEmpty ? nil : parameters
    }

    private static func nonce(in body: Data) -> Int? {
        guard
            let json = try? JSONSerialization.jsonObject(with: body)
                as? [String: Any],
            let meta = json["meta"] as? [String: Any],
            let nonce = meta["nonce"] as? NSNumber
        else {
            return nil
        }
        return nonce.intValue
    }
}

// MARK: - Hex decoding

extension Data {
    fileprivate init?(licenseHexEncoded hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self = Data(bytes)
    }
}
