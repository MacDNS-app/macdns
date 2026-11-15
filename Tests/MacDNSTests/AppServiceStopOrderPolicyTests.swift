// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class AppServiceStopOrderPolicyTests: XCTestCase {
    func testUnexpectedResolverPathStopsAgentBeforeDisablingProxy() async {
        var steps: [AppServiceStopStep] = []

        let outcome = await AppServiceStopOrderPolicy.execute { step in
            steps.append(step)
            return true
        }

        XCTAssertEqual(steps, [.stopAgentServices, .disableDNSProxy])
        XCTAssertEqual(
            outcome,
            AppServiceStopOutcome(agentStopped: true, proxyDisabled: true)
        )
    }

    func testStaleStartPathDisablesProxyEvenWhenAgentStopFails() async {
        var steps: [AppServiceStopStep] = []

        let outcome = await AppServiceStopOrderPolicy.execute { step in
            steps.append(step)
            return step == .disableDNSProxy
        }

        XCTAssertEqual(steps, [.stopAgentServices, .disableDNSProxy])
        XCTAssertEqual(
            outcome,
            AppServiceStopOutcome(agentStopped: false, proxyDisabled: true)
        )
    }

    func testPersistedStateUnavailablePathNeverSkipsTheProxyStep() async {
        var steps: [AppServiceStopStep] = []

        // Neither step succeeds: the proxy step must still be attempted, and
        // the caller must be able to see that nothing was reconciled.
        let outcome = await AppServiceStopOrderPolicy.execute { step in
            steps.append(step)
            return false
        }

        XCTAssertEqual(steps, [.stopAgentServices, .disableDNSProxy])
        XCTAssertEqual(
            outcome,
            AppServiceStopOutcome(agentStopped: false, proxyDisabled: false)
        )
    }

    func testProxyStepNeverRunsBeforeTheAgentStopCompletes() async {
        var agentStopCompleted = false
        var proxyRanBeforeAgentStop = false

        _ = await AppServiceStopOrderPolicy.execute { step in
            switch step {
            case .stopAgentServices:
                await Task.yield()
                agentStopCompleted = true
                return true
            case .disableDNSProxy:
                proxyRanBeforeAgentStop = !agentStopCompleted
                return true
            }
        }

        XCTAssertFalse(proxyRanBeforeAgentStop)
    }
}
