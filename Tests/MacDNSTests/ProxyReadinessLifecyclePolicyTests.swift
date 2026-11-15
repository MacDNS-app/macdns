// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNSAgent

final class ProxyReadinessLifecyclePolicyTests: XCTestCase {
    func testStartPublishesProxyBeforeAuthenticatedReadinessWakeup() {
        XCTAssertEqual(
            ProxyReadinessLifecyclePolicy.startActions(keepProxyBypass: false),
            [
                .notifyProxyEnable,
                .setBypassRequested(false),
                .wakeBypassProbe,
            ]
        )
    }

    func testCaptiveRestartKeepsBypassUntilFinalCommit() {
        let actions = ProxyReadinessLifecyclePolicy.startActions(
            keepProxyBypass: true
        )

        XCTAssertEqual(
            actions,
            [
                .notifyProxyEnable,
                .setBypassRequested(true),
                .wakeBypassProbe,
            ]
        )
        XCTAssertFalse(actions.contains(.setBypassRequested(false)))
    }

    func testCaptivePortalWakesBypassBeforeFailureCanStopResolver() {
        XCTAssertEqual(
            ProxyReadinessLifecyclePolicy.captivePortalBypassActions,
            [
                .setBypassRequested(true),
                .wakeBypassProbe,
            ]
        )
    }

    func testStopRequestsBypassBeforeProxyDisable() {
        XCTAssertEqual(
            ProxyReadinessLifecyclePolicy.stopActions,
            [
                .setBypassRequested(true),
                .wakeBypassProbe,
                .notifyProxyDisable,
            ]
        )
    }
}
