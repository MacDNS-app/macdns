// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class AgentLaunchctlListPolicyTests: XCTestCase {
    private let label = "app.macdns.agent"

    private let table = """
        PID\tStatus\tLabel
        -\t0\tio.tailscale.ipn.macsys.login-item-helper
        810\t0\tapp.macdns.agent
        831\t0\tapplication.app.macdns.353325123.353325131
        """

    func testRunningJobWithNumericPIDIsReportedRunning() {
        XCTAssertTrue(AgentLaunchctlListPolicy.isJobRunning(output: table, label: label))
    }

    func testLoadedJobWithoutPIDIsReportedStopped() {
        let output = """
            PID\tStatus\tLabel
            -\t0\tapp.macdns.agent
            """
        XCTAssertFalse(AgentLaunchctlListPolicy.isJobRunning(output: output, label: label))
    }

    func testUnrelatedLabelsAreNotMatched() {
        let output = """
            PID\tStatus\tLabel
            810\t0\tapplication.app.macdns.353325123.353325131
            811\t0\tapp.macdns.agent.helper
            """
        XCTAssertFalse(AgentLaunchctlListPolicy.isJobRunning(output: output, label: label))
    }

    func testLegacyPerLabelDictionaryOutputFailsClosed() {
        // `launchctl list <label>` prints this regardless of whether a PID
        // exists, so it must never be read as proof the job is running.
        let output = """
            {
            \t"Label" = "app.macdns.agent";
            \t"PID" = 810;
            };
            """
        XCTAssertFalse(AgentLaunchctlListPolicy.isJobRunning(output: output, label: label))
    }

    func testMalformedOutputFailsClosed() {
        XCTAssertFalse(AgentLaunchctlListPolicy.isJobRunning(output: "", label: label))
        XCTAssertFalse(AgentLaunchctlListPolicy.isJobRunning(output: "PID\tStatus\tLabel", label: label))
        XCTAssertFalse(
            AgentLaunchctlListPolicy.isJobRunning(output: "app.macdns.agent", label: label)
        )
        XCTAssertFalse(
            AgentLaunchctlListPolicy.isJobRunning(output: "0\tapp.macdns.agent", label: label)
        )
        XCTAssertFalse(
            AgentLaunchctlListPolicy.isJobRunning(output: "abc\t0\tapp.macdns.agent", label: label)
        )
        XCTAssertFalse(
            AgentLaunchctlListPolicy.isJobRunning(output: "0\t0\tapp.macdns.agent", label: label)
        )
    }

    func testEmptyLabelFailsClosed() {
        XCTAssertFalse(AgentLaunchctlListPolicy.isJobRunning(output: table, label: ""))
    }
}
