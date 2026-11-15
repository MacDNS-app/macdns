// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS
@testable import Shared

final class LicenseActivationFeedbackTests: XCTestCase {
    /// "Invalid license key" contains "valid", so a keyword match would render
    /// it in green.
    func testInvalidKeyIsAFailure() {
        let feedback = LicenseActivationFeedback(outcome: .success(.invalidKey))

        XCTAssertFalse(feedback.isSuccess)
        XCTAssertEqual(feedback.message, "Invalid license key")
    }

    func testOnlyActivationsAreSuccesses() {
        XCTAssertTrue(LicenseActivationFeedback(outcome: .success(.success(message: "done"))).isSuccess)
        XCTAssertTrue(LicenseActivationFeedback(outcome: .success(.alreadyActivated)).isSuccess)

        for result: LicenseActivationResult in [
            .error(message: "License has expired"),
            .machineLimit(limit: 2),
            .networkError(message: "offline"),
        ] {
            XCTAssertFalse(LicenseActivationFeedback(outcome: .success(result)).isSuccess, "\(result)")
        }
    }

    func testMissingAgentReplyIsAFailure() {
        let feedback = LicenseActivationFeedback(outcome: .failure(.agentNotResponding))

        XCTAssertFalse(feedback.isSuccess)
        XCTAssertEqual(feedback.message, "Failed to connect to agent")
    }

    /// The agent may still finish the activation after the App stops waiting,
    /// so a timeout must not read as a rejected key.
    func testTimeoutPointsToRefreshInsteadOfReportingARejection() {
        let feedback = LicenseActivationFeedback(outcome: .failure(.timeout))

        XCTAssertFalse(feedback.isSuccess)
        XCTAssertEqual(
            feedback.message,
            "MacDNS did not answer in time. Press Refresh to see if the key was activated."
        )
    }

    func testAgentMessagesArePassedThrough() {
        XCTAssertEqual(
            LicenseActivationFeedback(outcome: .success(.error(message: "License has expired"))).message,
            "License has expired"
        )
    }
}
