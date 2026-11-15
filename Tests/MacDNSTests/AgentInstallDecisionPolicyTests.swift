// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class AgentInstallDecisionPolicyTests: XCTestCase {
    func testEnabledRunningAgentIsNoOp() {
        XCTAssertEqual(
            AgentInstallDecisionPolicy(status: .enabled, isJobRunning: true).decision,
            .alreadyRunning
        )
    }

    func testEnabledStoppedAgentIsReregistered() {
        XCTAssertEqual(
            AgentInstallDecisionPolicy(status: .enabled, isJobRunning: false).decision,
            .reregister
        )
    }

    func testUnregisteredAgentIsRegistered() {
        XCTAssertEqual(
            AgentInstallDecisionPolicy(status: .notRegistered, isJobRunning: false).decision,
            .register
        )
        XCTAssertEqual(
            AgentInstallDecisionPolicy(status: .notFound, isJobRunning: false).decision,
            .register
        )
    }

    func testApprovalStatusNeverTouchesRegistration() {
        XCTAssertEqual(
            AgentInstallDecisionPolicy(status: .requiresApproval, isJobRunning: false).decision,
            .requiresApproval
        )
    }

    func testUnknownStatusFailsClosed() {
        XCTAssertEqual(
            AgentInstallDecisionPolicy(status: .unknown, isJobRunning: true).decision,
            .unknownStatus
        )
    }
}

final class AgentUninstallDecisionPolicyTests: XCTestCase {
    func testEnabledAgentIsUnregistered() {
        XCTAssertTrue(AgentUninstallDecisionPolicy.shouldUnregister(for: .enabled))
    }

    func testAgentWaitingForApprovalIsUnregistered() {
        XCTAssertTrue(AgentUninstallDecisionPolicy.shouldUnregister(for: .requiresApproval))
    }

    func testUnknownStatusAttemptsTheUnregister() {
        XCTAssertTrue(AgentUninstallDecisionPolicy.shouldUnregister(for: .unknown))
    }

    func testAbsentRegistrationIsLeftAlone() {
        XCTAssertFalse(AgentUninstallDecisionPolicy.shouldUnregister(for: .notRegistered))
        XCTAssertFalse(AgentUninstallDecisionPolicy.shouldUnregister(for: .notFound))
    }
}
