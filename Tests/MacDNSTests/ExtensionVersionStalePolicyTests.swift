// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class ExtensionVersionStalePolicyTests: XCTestCase {
    func testStaleWhenRunningOlderThanBundled() {
        let policy = ExtensionVersionStalePolicy(
            runningVersion: "1.2.0.517",
            bundledVersion: "1.2.0.519",
            proxyEnabled: true,
            activationInProgress: false
        )
        XCTAssertTrue(policy.isStale)
    }

    func testNotStaleWhenVersionsMatch() {
        let policy = ExtensionVersionStalePolicy(
            runningVersion: "1.2.0.519",
            bundledVersion: "1.2.0.519",
            proxyEnabled: true,
            activationInProgress: false
        )
        XCTAssertFalse(policy.isStale)
    }

    func testNotStaleWhenRunningVersionUnknown() {
        // An unreachable provider or a pre-feature build reports no version. The
        // not-protected signal covers that case, so do not claim restart needed.
        let policy = ExtensionVersionStalePolicy(
            runningVersion: nil,
            bundledVersion: "1.2.0.519",
            proxyEnabled: true,
            activationInProgress: false
        )
        XCTAssertFalse(policy.isStale)
    }

    func testNotStaleWhenBundledVersionUnknown() {
        let policy = ExtensionVersionStalePolicy(
            runningVersion: "1.2.0.517",
            bundledVersion: nil,
            proxyEnabled: true,
            activationInProgress: false
        )
        XCTAssertFalse(policy.isStale)
    }

    func testNotStaleWhenProxyDisabled() {
        let policy = ExtensionVersionStalePolicy(
            runningVersion: "1.2.0.517",
            bundledVersion: "1.2.0.519",
            proxyEnabled: false,
            activationInProgress: false
        )
        XCTAssertFalse(policy.isStale)
    }

    func testNotStaleDuringActivationToAvoidReplaceFlicker() {
        let policy = ExtensionVersionStalePolicy(
            runningVersion: "1.2.0.517",
            bundledVersion: "1.2.0.519",
            proxyEnabled: true,
            activationInProgress: true
        )
        XCTAssertFalse(policy.isStale)
    }
}
