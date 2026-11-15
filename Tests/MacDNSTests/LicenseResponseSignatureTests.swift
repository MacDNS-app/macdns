// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import CryptoKit
import Foundation
import Shared
import XCTest

@testable import MacDNSAgent

/// Signs license API responses the way Keygen does, using a throwaway keypair.
///
/// Tests must never use the production account key: the verifier has to be proven
/// against fixtures we control, including deliberately broken ones.
struct LicenseTestResponseSigner: @unchecked Sendable {
    let accountId: String
    let privateKey: Curve25519.Signing.PrivateKey

    init(
        accountId: String = LicenseManager.KeygenConfig.accountId,
        privateKey: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey()
    ) {
        self.accountId = accountId
        self.privateKey = privateKey
    }

    var publicKeyHex: String {
        privateKey.publicKey.rawRepresentation
            .map { String(format: "%02x", $0) }
            .joined()
    }

    func makeVerifier(
        host: String = LicenseResponseVerifier.expectedHost,
        freshnessTolerance: TimeInterval = LicenseResponseVerifier
            .defaultFreshnessTolerance
    ) -> LicenseResponseVerifier {
        LicenseResponseVerifier(
            accountId: accountId,
            publicKeyHex: publicKeyHex,
            host: host,
            freshnessTolerance: freshnessTolerance
        )
    }

    /// URLSession hands `URLProtocol` stubs a request whose body may have been
    /// converted into a stream, so both shapes must be read.
    static func requestBody(of request: URLRequest) -> Data? {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        let bufferSize = 4096
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: bufferSize)
            guard read > 0 else { break }
            data.append(buffer, count: read)
        }
        return data
    }

    /// Echoes the request nonce and scope into `meta`, exactly like the real API.
    static func echoingRequestMeta(of request: URLRequest, into body: Data) -> Data {
        guard
            let requestBody = requestBody(of: request),
            let requestJSON = try? JSONSerialization.jsonObject(with: requestBody)
                as? [String: Any],
            let requestMeta = requestJSON["meta"] as? [String: Any],
            let nonce = requestMeta["nonce"],
            var json = (try? JSONSerialization.jsonObject(with: body))
                as? [String: Any]
        else {
            return body
        }
        var meta = json["meta"] as? [String: Any] ?? [:]
        meta["nonce"] = nonce
        if let scope = requestMeta["scope"] {
            meta["scope"] = scope
        }
        json["meta"] = meta
        return (try? JSONSerialization.data(withJSONObject: json)) ?? body
    }

    func headers(
        for request: URLRequest,
        body: Data,
        date: Date,
        keyid: String? = nil,
        algorithm: String = "ed25519",
        signedHeaderList: String = LicenseResponseVerifier.signedHeaders,
        signingKey: Curve25519.Signing.PrivateKey? = nil
    ) -> [String: String] {
        let url = request.url!
        let host = url.host ?? LicenseResponseVerifier.expectedHost
        let target =
            LicenseResponseVerifier.requestTarget(
                method: request.httpMethod,
                url: url
            ) ?? ""
        let digest = LicenseResponseVerifier.digest(of: body)
        let dateHeader = LicenseResponseVerifier.httpDateString(for: date)
        let signingString = [
            "(request-target): \(target)",
            "host: \(host)",
            "date: \(dateHeader)",
            "digest: \(digest)",
        ].joined(separator: "\n")
        let key = signingKey ?? privateKey
        let signature =
            (try? key.signature(for: Data(signingString.utf8))) ?? Data()
        return [
            "Content-Type": "application/vnd.api+json",
            "Date": dateHeader,
            "Digest": digest,
            "Keygen-Signature":
                "keyid=\"\(keyid ?? accountId)\", algorithm=\"\(algorithm)\", "
                + "signature=\"\(signature.base64EncodedString())\", "
                + "headers=\"\(signedHeaderList)\"",
        ]
    }

    /// A `validate-key` answer signed at `date`, as `license.json` stores it.
    func receipt(body: String, date: Date) -> LicenseValidationReceipt {
        var request = URLRequest(
            url: URL(
                string:
                    "https://api.keygen.sh/v1/accounts/\(accountId)/licenses/actions/validate-key"
            )!
        )
        request.httpMethod = "POST"
        let payload = Data(body.utf8)
        let signed = headers(for: request, body: payload, date: date)
        return LicenseValidationReceipt(
            body: payload,
            date: signed["Date"] ?? "",
            signature: signed["Keygen-Signature"] ?? ""
        )
    }

    /// A fully signed response, nonce and scope echoed, as the API would answer.
    func response(
        for request: URLRequest,
        statusCode: Int,
        body: String,
        date: Date = Date()
    ) -> (HTTPURLResponse, Data) {
        let payload = Self.echoingRequestMeta(of: request, into: Data(body.utf8))
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: statusCode,
            httpVersion: nil,
            headerFields: headers(for: request, body: payload, date: date)
        )!
        return (response, payload)
    }

    /// Mints real `AuthoritativeEvidence` by running the verifier over a response
    /// this signer produced. There is deliberately no other way to obtain one, so
    /// tests exercise the same provenance rule as production.
    static func makeEvidence(
        accountId: String = "evidence-account",
        serverTime: Date = Date()
    ) throws -> AuthoritativeEvidence {
        let signer = LicenseTestResponseSigner(accountId: accountId)
        var request = URLRequest(
            url: URL(
                string: "https://api.keygen.sh/v1/accounts/\(accountId)/licenses/l"
            )!
        )
        request.httpMethod = "GET"
        let pair = signer.response(
            for: request,
            statusCode: 200,
            body: "{}",
            date: serverTime
        )
        return try signer.makeVerifier().verify(
            request: request,
            response: pair.0,
            body: pair.1,
            expectedNonce: nil,
            now: serverTime
        ).get()
    }

    /// A response with no signature headers at all.
    static func unsignedResponse(
        for request: URLRequest,
        statusCode: Int,
        body: String
    ) -> (HTTPURLResponse, Data) {
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: statusCode,
            httpVersion: nil,
            headerFields: ["Content-Type": "application/vnd.api+json"]
        )!
        return (response, Data(body.utf8))
    }
}

final class LicenseResponseSignatureTests: XCTestCase {
    private let signer = LicenseTestResponseSigner(accountId: "account-1")
    private let now = Date(timeIntervalSince1970: 1_700_000_000)
    private let url = URL(
        string: "https://api.keygen.sh/v1/accounts/account-1/licenses/actions/validate-key"
    )!

    private func request(
        method: String = "POST",
        nonce: Int? = nil,
        url overrideURL: URL? = nil
    ) -> URLRequest {
        var request = URLRequest(url: overrideURL ?? url)
        request.httpMethod = method
        if let nonce {
            request.httpBody = try? JSONSerialization.data(
                withJSONObject: ["meta": ["key": "k", "nonce": nonce]]
            )
        }
        return request
    }

    private func verify(
        _ pair: (HTTPURLResponse, Data),
        request: URLRequest,
        expectedNonce: Int? = nil,
        at instant: Date? = nil,
        verifier: LicenseResponseVerifier? = nil
    ) -> Result<AuthoritativeEvidence, LicenseResponseVerificationFailure> {
        (verifier ?? signer.makeVerifier()).verify(
            request: request,
            response: pair.0,
            body: pair.1,
            expectedNonce: expectedNonce,
            now: instant ?? now
        )
    }

    // MARK: - Happy path

    func testCorrectlySignedResponseVerifiesAndCarriesServerTime() throws {
        let request = request()
        let pair = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"meta":{"valid":true},"data":{"id":"license-1"}}"#,
            date: now
        )

        let evidence = try verify(pair, request: request).get()

        XCTAssertEqual(evidence.serverTime.timeIntervalSince1970, now.timeIntervalSince1970, accuracy: 1)
        XCTAssertEqual(
            evidence.requestTarget,
            "post /v1/accounts/account-1/licenses/actions/validate-key"
        )
    }

    func testSignedResponseWithMatchingNonceVerifies() throws {
        let request = request(nonce: 4242)
        let pair = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"meta":{"valid":true},"data":{"id":"license-1"}}"#,
            date: now
        )

        XCTAssertNoThrow(
            try verify(pair, request: request, expectedNonce: 4242).get()
        )
    }

    // MARK: - Forgery and tampering

    /// Without signature checks, an attacker with a trusted local or corporate
    /// CA plus DNS redirection could serve any verdict.
    func testUnsignedResponseIsRejected() {
        let request = request()
        let pair = LicenseTestResponseSigner.unsignedResponse(
            for: request,
            statusCode: 200,
            body: #"{"meta":{"valid":true},"data":{"id":"license-1"}}"#
        )

        XCTAssertEqual(
            verify(pair, request: request).failure,
            .missingSignatureHeader
        )
    }

    func testBodyAlteredAfterSigningIsRejectedByDigest() {
        let request = request()
        var pair = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"meta":{"valid":false},"data":{"id":"license-1"}}"#,
            date: now
        )
        pair.1 = Data(#"{"meta":{"valid":true},"data":{"id":"license-1"}}"#.utf8)

        XCTAssertEqual(verify(pair, request: request).failure, .digestMismatch)
    }

    /// Recomputing the digest for a forged body does not help: the digest header
    /// is itself covered by the signature.
    func testForgedBodyWithRecomputedDigestIsRejectedBySignature() {
        let request = request()
        let signed = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"meta":{"valid":false},"data":{"id":"license-1"}}"#,
            date: now
        )
        let forgedBody = Data(#"{"meta":{"valid":true},"data":{"id":"l"}}"#.utf8)
        var headers = signed.0.allHeaderFields as! [String: String]
        headers["Digest"] = LicenseResponseVerifier.digest(of: forgedBody)
        let response = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: nil,
            headerFields: headers
        )!

        XCTAssertEqual(
            verify((response, forgedBody), request: request).failure,
            .signatureMismatch
        )
    }

    func testResponseSignedByAnotherKeyIsRejected() {
        let attacker = LicenseTestResponseSigner(accountId: "account-1")
        let request = request()
        let body = Data(#"{"meta":{"valid":true},"data":{"id":"l"}}"#.utf8)
        let response = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: nil,
            headerFields: attacker.headers(for: request, body: body, date: now)
        )!

        XCTAssertEqual(
            verify((response, body), request: request).failure,
            .signatureMismatch
        )
    }

    func testResponseSignedForAnotherAccountIsRejected() {
        let request = request()
        let body = Data(#"{"meta":{"valid":true}}"#.utf8)
        let response = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: nil,
            headerFields: signer.headers(
                for: request,
                body: body,
                date: now,
                keyid: "another-account"
            )
        )!

        XCTAssertEqual(
            verify((response, body), request: request).failure,
            .keyIdMismatch
        )
    }

    func testUnsupportedAlgorithmIsRejected() {
        let request = request()
        let body = Data(#"{"meta":{"valid":true}}"#.utf8)
        let response = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: nil,
            headerFields: signer.headers(
                for: request,
                body: body,
                date: now,
                algorithm: "rsa-pss-sha256"
            )
        )!

        XCTAssertEqual(
            verify((response, body), request: request).failure,
            .unsupportedAlgorithm("rsa-pss-sha256")
        )
    }

    func testNarrowerSignedHeaderSetIsRejected() {
        let request = request()
        let body = Data(#"{"meta":{"valid":true}}"#.utf8)
        let response = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: nil,
            headerFields: signer.headers(
                for: request,
                body: body,
                date: now,
                signedHeaderList: "(request-target) host"
            )
        )!

        XCTAssertEqual(
            verify((response, body), request: request).failure,
            .signedHeadersMismatch("(request-target) host")
        )
    }

    func testStaleResponseOutsideFreshnessWindowIsRejected() {
        let request = request()
        let pair = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"meta":{"valid":true}}"#,
            date: now.addingTimeInterval(-3600)
        )

        XCTAssertEqual(verify(pair, request: request).failure, .staleResponse)
    }

    /// A response bound to this request's nonce is fresh by construction, so a
    /// wrong local clock must not reject it. The nonce still has to match.
    func testNonceBoundResponseVerifiesDespiteLocalClockSkew() throws {
        let request = request(nonce: 4242)
        let serverTime = now.addingTimeInterval(-600)
        let pair = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"meta":{"valid":true},"data":{"id":"license-1"}}"#,
            date: serverTime
        )

        let evidence = try verify(pair, request: request, expectedNonce: 4242, at: now).get()

        XCTAssertEqual(
            evidence.serverTime.timeIntervalSince1970,
            serverTime.timeIntervalSince1970,
            accuracy: 1
        )
        XCTAssertEqual(
            verify(pair, request: request, expectedNonce: 99, at: now).failure,
            .nonceMismatch
        )
    }

    func testResponseFromTheFutureOutsideFreshnessWindowIsRejected() {
        let request = request()
        let pair = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"meta":{"valid":true}}"#,
            date: now.addingTimeInterval(3600)
        )

        XCTAssertEqual(verify(pair, request: request).failure, .staleResponse)
    }

    // MARK: - Untrusted clock

    /// A rejected clock must never stand in for a trusted instant. A captured
    /// response is fresh against the rolled-back clock it was captured at, so
    /// freshness stops being a control.
    func testCapturedResponseLooksFreshAgainstTheClockItWasCapturedAt() {
        let capturedAt = now.addingTimeInterval(-(30 * 24 * 60 * 60))
        let request = request()
        let captured = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"data":{"id":"trial-1"}}"#,
            date: capturedAt
        )

        XCTAssertNil(verify(captured, request: request, at: capturedAt).failure)
    }

    /// With no trusted instant, freshness cannot be judged and a nonce-less
    /// response has nothing left binding it to this request.
    func testNonceLessResponseIsRefusedWithoutATrustedInstant() {
        let capturedAt = now.addingTimeInterval(-(30 * 24 * 60 * 60))
        let request = request()
        let captured = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"data":{"id":"trial-1"}}"#,
            date: capturedAt
        )

        XCTAssertEqual(
            signer.makeVerifier().verify(
                request: request,
                response: captured.0,
                body: captured.1,
                expectedNonce: nil,
                now: nil
            ).failure,
            .freshnessUnverifiable
        )
    }

    /// A nonce binds the response to this very request, so a captured reply can
    /// never satisfy it. That is the one case that stays verifiable without a
    /// freshness reference, and the only way a rolled-back machine recovers.
    func testNonceBoundResponseStillVerifiesWithoutATrustedInstant() throws {
        let request = request(nonce: 4242)
        let pair = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"meta":{"valid":true},"data":{"id":"license-1"}}"#,
            date: now.addingTimeInterval(-(30 * 24 * 60 * 60))
        )

        XCTAssertNoThrow(
            try signer.makeVerifier().verify(
                request: request,
                response: pair.0,
                body: pair.1,
                expectedNonce: 4242,
                now: nil
            ).get()
        )
        XCTAssertEqual(
            signer.makeVerifier().verify(
                request: request,
                response: pair.0,
                body: pair.1,
                expectedNonce: 99,
                now: nil
            ).failure,
            .nonceMismatch
        )
    }

    /// A recorded, correctly signed reply cannot be replayed against a later
    /// request: the nonce lives inside the signed body.
    func testReplayedResponseWithStaleNonceIsRejected() {
        let recorded = request(nonce: 1)
        let pair = signer.response(
            for: recorded,
            statusCode: 200,
            body: #"{"meta":{"valid":true},"data":{"id":"l"}}"#,
            date: now
        )

        XCTAssertEqual(
            verify(pair, request: recorded, expectedNonce: 2).failure,
            .nonceMismatch
        )
    }

    func testResponseWithoutNonceIsRejectedWhenOneIsExpected() {
        let request = request()
        let pair = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"meta":{"valid":true}}"#,
            date: now
        )

        XCTAssertEqual(
            verify(pair, request: request, expectedNonce: 7).failure,
            .nonceMismatch
        )
    }

    func testResponseSignedForAnotherRequestTargetIsRejected() {
        let signedRequest = request()
        let pair = signer.response(
            for: signedRequest,
            statusCode: 200,
            body: #"{"meta":{"valid":true}}"#,
            date: now
        )
        let otherRequest = request(
            url: URL(
                string: "https://api.keygen.sh/v1/accounts/account-1/licenses/other"
            )!
        )

        XCTAssertEqual(
            verify(pair, request: otherRequest).failure,
            .signatureMismatch
        )
    }

    func testResponseFromAnUnexpectedHostIsRejected() {
        let foreignURL = URL(string: "https://evil.example.com/v1/validate")!
        let foreignRequest = request(url: foreignURL)
        let pair = signer.response(
            for: foreignRequest,
            statusCode: 200,
            body: #"{"meta":{"valid":true}}"#,
            date: now
        )

        XCTAssertEqual(
            verify(pair, request: foreignRequest).failure,
            .unexpectedHost("evil.example.com")
        )
    }

    func testMissingDigestHeaderIsRejected() {
        let request = request()
        let body = Data(#"{"meta":{"valid":true}}"#.utf8)
        var headers = signer.headers(for: request, body: body, date: now)
        headers.removeValue(forKey: "Digest")
        let response = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: nil,
            headerFields: headers
        )!

        XCTAssertEqual(
            verify((response, body), request: request).failure,
            .missingDigestHeader
        )
    }

    func testMissingDateHeaderIsRejected() {
        let request = request()
        let body = Data(#"{"meta":{"valid":true}}"#.utf8)
        var headers = signer.headers(for: request, body: body, date: now)
        headers.removeValue(forKey: "Date")
        let response = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: nil,
            headerFields: headers
        )!

        XCTAssertEqual(
            verify((response, body), request: request).failure,
            .missingDateHeader
        )
    }

    func testMalformedSignatureHeaderIsRejected() {
        let request = request()
        let body = Data(#"{"meta":{"valid":true}}"#.utf8)
        var headers = signer.headers(for: request, body: body, date: now)
        headers["Keygen-Signature"] = "keyid=account-1 algorithm=ed25519"
        let response = HTTPURLResponse(
            url: url,
            statusCode: 200,
            httpVersion: nil,
            headerFields: headers
        )!

        XCTAssertEqual(
            verify((response, body), request: request).failure,
            .malformedSignatureHeader
        )
    }

    // MARK: - Pinned production key

    /// The pinned key must decode and must reject a correctly formed response
    /// signed by anyone else.
    ///
    /// This does *not* prove the pin is the key of the configured Keygen
    /// account: any other well-formed Ed25519 public key passes exactly the same
    /// way. Closing that gap needs a response captured from the account and its
    /// real `Keygen-Signature` as a fixture, verified against the pin.
    func testProductionVerifyKeyIsPinnedAndRejectsForeignSignatures() {
        XCTAssertEqual(KeygenVerifyKey.accountPublicKeyHex.count, 64)
        // publicKey(hex:) only returns a key for exactly 32 decoded bytes.
        XCTAssertNotNil(
            KeygenVerifyKey.publicKey(),
            "the pinned account key must decode to a 32-byte Ed25519 key"
        )

        let production = LicenseResponseVerifier(accountId: "account-1")
        XCTAssertTrue(production.isConfigured)

        let request = request()
        let pair = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"meta":{"valid":true}}"#,
            date: now
        )

        // Signed by the test key, not the account key: a valid signature from
        // the wrong signer must not verify.
        XCTAssertEqual(
            verify(pair, request: request, verifier: production).failure,
            .signatureMismatch
        )
    }

    /// A build whose key does not decode must fail closed rather than skip
    /// verification, so every response stays non-authoritative.
    func testUndecodableVerifyKeyFailsClosed() {
        let unconfigured = LicenseResponseVerifier(
            accountId: "account-1",
            publicKeyHex: "not-a-valid-ed25519-key"
        )
        XCTAssertFalse(unconfigured.isConfigured)

        let request = request()
        let pair = signer.response(
            for: request,
            statusCode: 200,
            body: #"{"meta":{"valid":true}}"#,
            date: now
        )

        XCTAssertEqual(
            verify(pair, request: request, verifier: unconfigured).failure,
            .verifyKeyNotConfigured
        )
    }

    func testNoncesAreNotRepeated() {
        let nonces = Set((0..<64).map { _ in LicenseResponseVerifier.makeNonce() })
        XCTAssertEqual(nonces.count, 64)
        XCTAssertTrue(nonces.allSatisfy { $0 > 0 && $0 <= 9_007_199_254_740_991 })
    }

    // MARK: - Request target derivation

    // MARK: - Stored answers

    func testNonceBoundAnswerCarriesAReceiptThatVerifiesWithoutAClock() throws {
        let request = request(nonce: 7)
        let evidence = try verify(
            signer.response(for: request, statusCode: 200, body: #"{"meta":{"valid":true}}"#, date: now),
            request: request,
            expectedNonce: 7
        ).get()

        let receipt = try XCTUnwrap(evidence.receipt)
        let stored = try signer.makeVerifier()
            .verify(stored: receipt, method: "POST", url: url)
            .get()

        XCTAssertEqual(stored.serverTime, now)
        XCTAssertEqual(stored.requestTarget, evidence.requestTarget)
    }

    /// Only `validate-key` echoes a nonce, so no other answer can be stored.
    func testNonceLessAnswerCarriesNoReceipt() throws {
        let request = request(method: "GET")
        let evidence = try verify(
            signer.response(for: request, statusCode: 200, body: "{}", date: now),
            request: request
        ).get()

        XCTAssertNil(evidence.receipt)
    }

    func testStoredAnswerWithAnAlteredBodyIsRejected() {
        let genuine = signer.receipt(body: #"{"meta":{"valid":false}}"#, date: now)
        let forged = LicenseValidationReceipt(
            body: Data(#"{"meta":{"valid":true}}"#.utf8),
            date: genuine.date,
            signature: genuine.signature
        )

        XCTAssertEqual(
            signer.makeVerifier().verify(stored: forged, method: "POST", url: url).failure,
            .signatureMismatch
        )
    }

    /// The date is what offline grace counts from, so it must be the signed one.
    func testStoredAnswerWithAnAlteredDateIsRejected() {
        let genuine = signer.receipt(body: #"{"meta":{"valid":true}}"#, date: now)
        let forged = LicenseValidationReceipt(
            body: genuine.body,
            date: LicenseResponseVerifier.httpDateString(for: now.addingTimeInterval(86_400)),
            signature: genuine.signature
        )

        XCTAssertEqual(
            signer.makeVerifier().verify(stored: forged, method: "POST", url: url).failure,
            .signatureMismatch
        )
    }

    func testStoredAnswerOfAnotherRequestIsRejected() throws {
        let machines = URL(string: "https://api.keygen.sh/v1/accounts/account-1/machines")!
        let receipt = signer.receipt(body: #"{"meta":{"valid":true}}"#, date: now)

        XCTAssertEqual(
            signer.makeVerifier().verify(stored: receipt, method: "POST", url: machines).failure,
            .signatureMismatch
        )
    }

    func testStoredAnswerSignedByAnotherKeyIsRejected() {
        let receipt = LicenseTestResponseSigner(accountId: "account-1")
            .receipt(body: #"{"meta":{"valid":true}}"#, date: now)

        XCTAssertEqual(
            signer.makeVerifier().verify(stored: receipt, method: "POST", url: url).failure,
            .signatureMismatch
        )
    }

    func testRequestTargetIncludesQueryAndLowercasedMethod() {
        XCTAssertEqual(
            LicenseResponseVerifier.requestTarget(
                method: "GET",
                url: URL(string: "https://api.keygen.sh/v1/machines?limit=100")!
            ),
            "get /v1/machines?limit=100"
        )
    }
}

extension Result {
    /// Failure of a verification result, or nil when it succeeded.
    fileprivate var failure: Failure? {
        switch self {
        case .success: return nil
        case .failure(let failure): return failure
        }
    }
}
