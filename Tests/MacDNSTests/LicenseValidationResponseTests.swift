// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared
import XCTest

@testable import MacDNSAgent

final class LicenseValidationResponseTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func keyVerdict(
        _ json: String,
        statusCode: Int = 200
    ) -> LicenseManager.KeyValidationVerdict {
        LicenseManager.parseKeyValidationVerdict(
            data: Data(json.utf8),
            statusCode: statusCode,
            now: now,
            key: "paid-key"
        )
    }

    private func trialLookup(
        _ json: String,
        statusCode: Int = 200
    ) -> LicenseManager.TrialLookupVerdict {
        LicenseManager.parseTrialLookupVerdict(
            data: Data(json.utf8),
            statusCode: statusCode,
            now: now,
            fingerprint: "fp",
            policyId: "trial-policy"
        )
    }

    // MARK: - Signed answer identity

    /// Keygen signs its response, not our request body. A proxy that reads the
    /// nonce can ask about a donor license and relay that signed answer to turn
    /// an ended trial back into an active one.
    func testTrialLookupAboutAnotherKeyIsRejected() {
        guard
            case .protocolFailure = trialLookup(
                #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"id":"donor","relationships":{"policy":{"data":{"type":"policies","id":"trial-policy"}}},"attributes":{"key":"donor-fp","expiry":"2030-01-01T00:00:00Z"}}}"#
            )
        else {
            return XCTFail("A signed answer about another key must not become a verdict")
        }
    }

    func testTrialLookupOfALicenseUnderAnotherPolicyIsRejected() {
        guard
            case .protocolFailure = trialLookup(
                #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"id":"paid","relationships":{"policy":{"data":{"type":"policies","id":"paid-policy"}}},"attributes":{"key":"fp","expiry":"2030-01-01T00:00:00Z"}}}"#
            )
        else {
            return XCTFail("A license under another policy is not this machine's trial")
        }
    }

    func testTrialLookupWithoutASignedKeyIsRejected() {
        guard
            case .protocolFailure = trialLookup(
                #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"trial-policy"}}},"attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
            )
        else {
            return XCTFail("A trial answer that does not name its key proves nothing")
        }
    }

    func testKeyValidationAboutAnotherKeyIsRejected() {
        guard
            case .protocolFailure = keyVerdict(
                #"{"meta":{"valid":true},"data":{"id":"donor","attributes":{"key":"donor-key","expiry":"2030-01-01T00:00:00Z"}}}"#
            )
        else {
            return XCTFail("A signed answer about another key must not validate this one")
        }
    }

    /// Keygen omits `key` only for legacy-encrypted licenses. Rejecting those
    /// would lock out every customer on such a policy.
    func testKeyValidationWithoutASignedKeyIsAccepted() {
        guard
            case .valid = keyVerdict(
                #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
            )
        else {
            return XCTFail("A legacy answer without a key must still validate")
        }
    }

    func testNoMachineRequiresActivationInsteadOfSuccess() throws {
        let result = keyVerdict(
            #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
        )

        guard case .machineActivationRequired(let id, let expiry) = result else {
            return XCTFail("NO_MACHINE must require activation")
        }
        XCTAssertEqual(id, "license-1")
        XCTAssertNotNil(expiry)
    }

    func testNoMachinesWithoutLicenseIDIsProtocolFailure() {
        let result = keyVerdict(
            #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"attributes":{}}}"#
        )

        guard case .protocolFailure = result else {
            return XCTFail("Malformed NO_MACHINES must not become valid")
        }
    }

    func testValidPerpetualLicenseKeepsNilExpiry() {
        let result = keyVerdict(
            #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{}}}"#
        )

        guard case .valid(let id, let expiry) = result else {
            return XCTFail("Valid response must remain valid")
        }
        XCTAssertEqual(id, "license-1")
        XCTAssertNil(expiry)
    }

    func testMalformedExpiryDoesNotBecomePerpetual() {
        let result = keyVerdict(
            #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{"expiry":"not-a-date"}}}"#
        )

        guard case .protocolFailure = result else {
            return XCTFail("Malformed expiry must not be treated as perpetual")
        }
    }

    func testNonStringExpiryDoesNotBecomePerpetual() {
        let result = keyVerdict(
            #"{"meta":{"valid":true},"data":{"id":"license-1","attributes":{"expiry":123}}}"#
        )

        guard case .protocolFailure = result else {
            return XCTFail("Non-string expiry must not be treated as perpetual")
        }
    }

    /// Keygen answers `NO_MACHINE` only while the license has no machines at all.
    /// Once another Mac holds a seat, a new Mac gets `FINGERPRINT_SCOPE_MISMATCH`,
    /// which still means "activate this machine", not "invalid key".
    func testFingerprintMismatchRequiresActivation() {
        let result = keyVerdict(
            #"{"meta":{"valid":false,"code":"FINGERPRINT_SCOPE_MISMATCH"},"data":{"id":"license-1","attributes":{"expiry":"2030-01-01T00:00:00Z"}}}"#
        )

        guard case .machineActivationRequired(let id, let expiry) = result else {
            return XCTFail("FINGERPRINT_SCOPE_MISMATCH must require activation, got \(result)")
        }
        XCTAssertEqual(id, "license-1")
        XCTAssertNotNil(expiry)
    }

    func testExpiredFingerprintMismatchDoesNotRequestActivation() {
        let result = keyVerdict(
            #"{"meta":{"valid":false,"code":"FINGERPRINT_SCOPE_MISMATCH"},"data":{"id":"license-1","attributes":{"expiry":"2000-01-01T00:00:00Z"}}}"#
        )

        XCTAssertEqual(result, .expired)
    }

    func testOtherScopeRejectionsStayInvalid() {
        for code in ["PRODUCT_SCOPE_MISMATCH", "TOO_MANY_MACHINES", "BANNED", "NOT_FOUND"] {
            XCTAssertEqual(
                keyVerdict(
                    #"{"meta":{"valid":false,"code":"\#(code)"},"data":{"id":"license-1","attributes":{}}}"#
                ),
                .invalid,
                code
            )
        }
    }

    /// Keygen answers real license rejections with `200` + `meta.valid`, so a 4xx
    /// is an availability or routing problem. Terminalizing it would let a
    /// single misrouted request disable the fleet permanently.
    func testTerminalClientErrorStaysRetryable() {
        for statusCode in [400, 401, 403, 404, 407, 422] {
            let result = LicenseManager.parseKeyValidationVerdict(
                data: Data(),
                statusCode: statusCode,
                now: now,
                key: "paid-key"
            )

            guard case .protocolFailure = result else {
                return XCTFail("HTTP \(statusCode) must stay retryable, got \(result)")
            }
        }
    }

    func testServerErrorRemainsRetryable() {
        let result = LicenseManager.parseKeyValidationVerdict(
            data: Data(),
            statusCode: 503,
            now: now,
            key: "paid-key"
        )

        guard case .protocolFailure = result else {
            return XCTFail("Server errors must remain retryable")
        }
    }

    func testTrialLookupNonSuccessResponsesStayRetryable() {
        for statusCode in [201, 301, 400, 404, 408, 422, 429, 500, 503, 599] {
            guard case .protocolFailure = trialLookup("{}", statusCode: statusCode) else {
                return XCTFail("Trial lookup HTTP \(statusCode) must stay retryable")
            }
        }
    }

    func testTrialLookupOfUnknownFingerprintIsNotFound() {
        XCTAssertEqual(
            trialLookup(#"{"meta":{"valid":false,"code":"NOT_FOUND"},"data":null}"#),
            .notFound
        )
    }

    /// The trial policy requires machines that onboarding never activates, so a
    /// live trial always answers `NO_MACHINES`. Only the expiry decides.
    func testTrialLookupWithFutureExpiryIsActive() {
        XCTAssertEqual(
            trialLookup(
                #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"trial-policy"}}},"attributes":{"key":"fp","expiry":"2030-01-01T00:00:00Z"}}}"#
            ),
            .active(
                licenseId: "trial-1",
                expiresAt: Date(timeIntervalSince1970: 1_893_456_000)
            )
        )
    }

    func testTrialLookupWithPastExpiryIsExpired() {
        for code in ["EXPIRED", "NO_MACHINES"] {
            XCTAssertEqual(
                trialLookup(
                    #"{"meta":{"valid":false,"code":"\#(code)"},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"trial-policy"}}},"attributes":{"key":"fp","expiry":"2000-01-01T00:00:00Z"}}}"#
                ),
                .expired(licenseId: "trial-1"),
                code
            )
        }
    }

    func testSuspendedOrBannedTrialIsRevokedEvenBeforeExpiry() {
        for code in ["SUSPENDED", "BANNED"] {
            XCTAssertEqual(
                trialLookup(
                    #"{"meta":{"valid":false,"code":"\#(code)"},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"trial-policy"}}},"attributes":{"key":"fp","expiry":"2030-01-01T00:00:00Z"}}}"#
                ),
                .revoked(licenseId: "trial-1"),
                code
            )
        }
    }

    /// A key equal to this fingerprint under another policy is not a trial this
    /// machine owns. No verdict exists, so nothing may be persisted from it.
    func testTrialLookupUnderAnotherPolicyStaysRetryable() {
        guard
            case .protocolFailure = trialLookup(
                #"{"meta":{"valid":false,"code":"POLICY_SCOPE_MISMATCH"},"data":{"id":"other","attributes":{}}}"#
            )
        else {
            return XCTFail("A foreign policy must not become a trial verdict")
        }
    }

    func testTrialWithMissingExpiryRemainsActiveAcrossParserStateAndAdmission() throws {
        let result = trialLookup(
            #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"trial-policy"}}},"attributes":{"key":"fp"}}}"#
        )

        XCTAssertEqual(result, .active(licenseId: "trial-1", expiresAt: nil))

        let stateData = try JSONCoding.encoder.encode(
            LicenseState(
                licenseId: "trial-1",
                status: .trial,
                expiresAt: nil,
                lastValidatedAt: Date()
            )
        )
        let persistedState = try JSONCoding.decoder.decode(
            LicenseState.self,
            from: stateData
        )

        XCTAssertTrue(persistedState.isActive)
        XCTAssertTrue(LicenseFailClosedPolicy.allowsService(persistedState))
    }

    func testTrialWithNullExpiryRemainsActive() {
        XCTAssertEqual(
            trialLookup(
                #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"trial-policy"}}},"attributes":{"key":"fp","expiry":null}}}"#
            ),
            .active(licenseId: "trial-1", expiresAt: nil)
        )
    }

    /// A garbled or injected body is not proof that the trial ended. It must
    /// stay retryable so an active trial cannot be permanently disabled by one
    /// bad response.
    func testMalformedTrialLookupStaysRetryable() {
        let bodies = [
            "not-json",
            #"{"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"trial-policy"}}},"attributes":{"key":"fp"}}}"#,
            #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"attributes":{}}}"#,
            #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"trial-policy"}}},"attributes":{"key":"fp","expiry":"not-a-date"}}}"#,
            #"{"meta":{"valid":false,"code":"NO_MACHINES"},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"trial-policy"}}},"attributes":{"key":"fp","expiry":123}}}"#,
        ]
        for body in bodies {
            guard case .protocolFailure = trialLookup(body) else {
                return XCTFail("Malformed trial lookup must stay retryable: \(body)")
            }
        }
    }

    func testExpiredNoMachineDoesNotRequestActivation() {
        let result = keyVerdict(
            #"{"meta":{"valid":false,"code":"NO_MACHINE"},"data":{"id":"license-1","attributes":{"expiry":"2000-01-01T00:00:00Z"}}}"#
        )

        XCTAssertEqual(result, .expired, "Expired license must not reactivate a machine")
    }

    func testSuspendedLicenseIsSuspended() {
        XCTAssertEqual(
            keyVerdict(#"{"meta":{"valid":false,"code":"SUSPENDED"},"data":{"id":"l"}}"#),
            .suspended
        )
    }

    func testMalformedKeyValidationBodyStaysRetryable() {
        guard case .protocolFailure = keyVerdict("not-json") else {
            return XCTFail("Malformed validate-key body must stay retryable")
        }
    }
}
