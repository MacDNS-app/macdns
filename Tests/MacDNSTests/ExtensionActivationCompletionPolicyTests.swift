// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import XCTest

final class ExtensionActivationCompletionPolicyTests: XCTestCase {
    func testLateActivationCompletionRegistersProviderWhenNoWaiterAndProviderMissing() {
        let policy = ExtensionActivationCompletionPolicy(
            hadWaitingContinuations: false,
            providerConfigured: false,
            registrationDeferred: false
        )

        XCTAssertTrue(policy.shouldRegisterProviderAfterCompletion)
    }

    func testActivationCompletionDoesNotDoubleRegisterWhenWaiterWillContinue() {
        let policy = ExtensionActivationCompletionPolicy(
            hadWaitingContinuations: true,
            providerConfigured: false,
            registrationDeferred: false
        )

        XCTAssertFalse(policy.shouldRegisterProviderAfterCompletion)
    }

    func testActivationCompletionDoesNotRegisterWhenProviderAlreadyConfigured() {
        let policy = ExtensionActivationCompletionPolicy(
            hadWaitingContinuations: false,
            providerConfigured: true,
            registrationDeferred: false
        )

        XCTAssertFalse(policy.shouldRegisterProviderAfterCompletion)
    }

    func testDeferredRegistrationSkipsLateRegistration() {
        let policy = ExtensionActivationCompletionPolicy(
            hadWaitingContinuations: false,
            providerConfigured: false,
            registrationDeferred: true
        )

        XCTAssertFalse(policy.shouldRegisterProviderAfterCompletion)
    }
}
