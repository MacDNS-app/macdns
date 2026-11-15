// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import XCTest

final class ProxyEnableResultTests: XCTestCase {
    func testCaptivePortalBypassKeepsBypassResolverModeText() {
        XCTAssertEqual(ProxyEnableResult.captivePortalBypass.resolverModeText, "Paused for Wi-Fi sign-in")
        XCTAssertEqual(ProxyEnableResult.inactive.resolverModeText, "MacDNS isn't receiving lookups")
    }

    func testCaptivePortalResolveAttemptClearsOnlyAfterProxyEnableSucceeds() {
        XCTAssertFalse(ProxyEnableResult.enabled.captivePortalDetectedAfterResolveAttempt)
        XCTAssertFalse(ProxyEnableResult.inactive.captivePortalDetectedAfterResolveAttempt)
        XCTAssertTrue(ProxyEnableResult.captivePortalBypass.captivePortalDetectedAfterResolveAttempt)
    }
}
