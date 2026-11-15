// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNSAgent

/// What a stored `validate-key` answer proves, once its signature verified.
final class LicenseOfflineProofTests: XCTestCase {
    private let validatedAt = Date(timeIntervalSince1970: 1_800_000_000)
    private let expiry = Date(timeIntervalSince1970: 1_893_456_000)
    private let product = LicenseManager.KeygenConfig.productId
    private let trialPolicy = LicenseManager.KeygenConfig.trialPolicyId

    private func proof(
        _ body: String,
        licenseKey: String?,
        fingerprint: String = "this-mac"
    ) -> LicenseOfflineProof? {
        LicenseManager.offlineProof(
            in: Data(body.utf8),
            validatedAt: validatedAt,
            licenseKey: licenseKey,
            fingerprint: fingerprint
        )
    }

    private func paidAnswer(
        valid: Bool = true,
        code: String = "VALID",
        scope: String? = nil,
        key: String = "paid-key",
        expiry: String = #""2030-01-01T00:00:00Z""#
    ) -> String {
        let scope = scope ?? #"{"fingerprint":"this-mac","product":"\#(product)"}"#
        return
            #"{"meta":{"valid":\#(valid),"code":"\#(code)","scope":\#(scope)},"data":{"id":"license-1","attributes":{"key":"\#(key)","expiry":\#(expiry)}}}"#
    }

    private func trialAnswer(
        code: String = "NO_MACHINES",
        key: String = "this-mac",
        policy: String? = nil,
        expiry: String = "2030-01-01T00:00:00Z"
    ) -> String {
        #"{"meta":{"valid":false,"code":"\#(code)"},"data":{"id":"trial-1","relationships":{"policy":{"data":{"type":"policies","id":"\#(policy ?? trialPolicy)"}}},"attributes":{"key":"\#(key)","expiry":"\#(expiry)"}}}"#
    }

    // MARK: - Paid

    func testValidAnswerScopedToThisMachineProvesThePaidLicense() {
        XCTAssertEqual(
            proof(paidAnswer(), licenseKey: "paid-key"),
            LicenseOfflineProof(validatedAt: validatedAt, expiresAt: expiry)
        )
    }

    func testPerpetualLicenseProvesNoExpiry() {
        XCTAssertEqual(
            proof(paidAnswer(expiry: "null"), licenseKey: "paid-key"),
            LicenseOfflineProof(validatedAt: validatedAt, expiresAt: nil)
        )
    }

    /// A valid answer copied from a Mac that holds a seat must not run this one.
    func testAnswerScopedToAnotherMachineProvesNothing() {
        let donor = #"{"fingerprint":"donor-mac","product":"\#(product)"}"#

        XCTAssertNil(proof(paidAnswer(scope: donor), licenseKey: "paid-key"))
    }

    /// Without the echoed scope nothing says which machine Keygen validated.
    func testAnswerWithoutAScopeProvesNothing() {
        XCTAssertNil(proof(paidAnswer(scope: "null"), licenseKey: "paid-key"))
        XCTAssertNil(
            proof(paidAnswer(scope: #"{"product":"\#(product)"}"#), licenseKey: "paid-key")
        )
    }

    func testAnswerScopedToAnotherProductProvesNothing() {
        let other = #"{"fingerprint":"this-mac","product":"another-product"}"#

        XCTAssertNil(proof(paidAnswer(scope: other), licenseKey: "paid-key"))
    }

    func testAnswerThatIsNotValidProvesNothing() {
        for code in ["NO_MACHINE", "FINGERPRINT_SCOPE_MISMATCH", "SUSPENDED", "EXPIRED"] {
            XCTAssertNil(
                proof(paidAnswer(valid: false, code: code), licenseKey: "paid-key"),
                code
            )
        }
    }

    func testAnswerAboutAnotherKeyProvesNothing() {
        XCTAssertNil(proof(paidAnswer(key: "another-key"), licenseKey: "paid-key"))
    }

    func testTrialAnswerDoesNotProveAPaidLicense() {
        XCTAssertNil(proof(trialAnswer(), licenseKey: "paid-key"))
    }

    // MARK: - Trial

    func testLiveTrialOfThisMachineProvesTheTrial() {
        XCTAssertEqual(
            proof(trialAnswer(), licenseKey: nil),
            LicenseOfflineProof(validatedAt: validatedAt, expiresAt: expiry)
        )
    }

    func testTrialOfAnotherMachineProvesNothing() {
        XCTAssertNil(proof(trialAnswer(key: "donor-mac"), licenseKey: nil))
    }

    func testLicenseOfAnotherPolicyProvesNoTrial() {
        XCTAssertNil(proof(trialAnswer(policy: "another-policy"), licenseKey: nil))
        XCTAssertNil(proof(paidAnswer(key: "this-mac"), licenseKey: nil))
    }

    func testTrialThatHadEndedWhenItWasValidatedProvesNothing() {
        XCTAssertNil(proof(trialAnswer(expiry: "2020-01-01T00:00:00Z"), licenseKey: nil))
        XCTAssertNil(proof(trialAnswer(code: "SUSPENDED"), licenseKey: nil))
        XCTAssertNil(
            proof(#"{"meta":{"valid":false,"code":"NOT_FOUND"},"data":null}"#, licenseKey: nil)
        )
    }

    func testBodyThatIsNotAnAnswerProvesNothing() {
        XCTAssertNil(proof("not json", licenseKey: "paid-key"))
        XCTAssertNil(proof("{}", licenseKey: nil))
    }
}
