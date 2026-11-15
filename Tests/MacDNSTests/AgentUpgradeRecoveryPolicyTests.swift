// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class AgentUpgradeRecoveryPolicyTests: XCTestCase {
    func testFirstUnavailableLoadResetsConnectionWithoutRegistration() {
        XCTAssertEqual(
            action(
                elapsed: 0,
                agentRegistered: false,
                didResetConnection: false
            ),
            .resetConnection
        )
    }

    func testRegisteredAgentIsNotReplacedBeforeMinimumDelay() {
        XCTAssertEqual(
            action(
                elapsed: AgentUpgradeRecoveryPolicy.replacementMinimumSeconds - 0.1,
                agentRegistered: true,
                didResetConnection: true
            ),
            .none
        )
    }

    func testRegisteredAgentIsReplacedAfterResetAndMinimumDelay() {
        XCTAssertEqual(
            action(
                elapsed: AgentUpgradeRecoveryPolicy.replacementMinimumSeconds,
                agentRegistered: true,
                didResetConnection: true
            ),
            .replaceAgent
        )
    }

    func testUnregisteredAgentIsNotReplaced() {
        XCTAssertEqual(
            action(
                elapsed: AgentUpgradeRecoveryPolicy.replacementMinimumSeconds,
                agentRegistered: false,
                didResetConnection: true
            ),
            .none
        )
    }

    func testCompletedStartupDisablesRecovery() {
        XCTAssertEqual(
            action(
                elapsed: AgentUpgradeRecoveryPolicy.replacementMinimumSeconds,
                agentRegistered: true,
                authoritativeStartupCompleted: true,
                didResetConnection: true
            ),
            .none
        )
    }

    func testReplacementIsAttemptedOnlyOncePerAppProcess() {
        XCTAssertEqual(
            action(
                elapsed: AgentUpgradeRecoveryPolicy.replacementMinimumSeconds,
                agentRegistered: true,
                didResetConnection: true,
                didAttemptReplacement: true
            ),
            .none
        )
    }

    /// The Agent answered and could not read `state.json`. Neither a new
    /// connection nor a new Agent can fix that read.
    func testAgentThatAnsweredIsNeitherResetNorReplaced() {
        XCTAssertEqual(
            action(
                reason: .stateReadFailure,
                elapsed: 0,
                agentRegistered: true,
                didResetConnection: false
            ),
            .none
        )
        XCTAssertEqual(
            action(
                reason: .stateReadFailure,
                elapsed: AgentUpgradeRecoveryPolicy.replacementMinimumSeconds,
                agentRegistered: true,
                didResetConnection: true
            ),
            .none
        )
    }

    func testEveryUnansweredLoadCountsTowardReplacement() {
        for reason: PersistedStateUnavailableReason in [
            .timeout, .agentNotResponding, .connectionInterrupted,
        ] {
            XCTAssertEqual(
                action(
                    reason: reason,
                    elapsed: AgentUpgradeRecoveryPolicy.replacementMinimumSeconds,
                    agentRegistered: true,
                    didResetConnection: true
                ),
                .replaceAgent
            )
        }
    }

    private func action(
        reason: PersistedStateUnavailableReason = .timeout,
        elapsed: TimeInterval,
        agentRegistered: Bool,
        authoritativeStartupCompleted: Bool = false,
        didResetConnection: Bool,
        didAttemptReplacement: Bool = false
    ) -> AgentUpgradeRecoveryAction {
        AgentUpgradeRecoveryPolicy(
            reason: reason,
            elapsed: elapsed,
            agentRegistered: agentRegistered,
            authoritativeStartupCompleted: authoritativeStartupCompleted,
            didResetConnection: didResetConnection,
            didAttemptReplacement: didAttemptReplacement
        ).action
    }
}
