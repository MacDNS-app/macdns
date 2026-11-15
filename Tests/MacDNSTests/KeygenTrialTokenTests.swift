// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import XCTest

@testable import MacDNSAgent

/// The trial token reaches the Agent only through its embedded Info.plist, and
/// a build without one must never send a bearer token.
final class KeygenTrialTokenTests: XCTestCase {
    private typealias Config = LicenseManager.KeygenConfig

    func testReadsTheTokenTheBuildInjected() {
        let info: [String: Any] = [Config.trialTokenInfoKey: "prod-abc123v3"]

        XCTAssertEqual(Config.trialToken(from: info), "prod-abc123v3")
    }

    func testABuildWithoutATokenHasNone() {
        XCTAssertNil(Config.trialToken(from: nil))
        XCTAssertNil(Config.trialToken(from: [:]))
        XCTAssertNil(Config.trialToken(from: [Config.trialTokenInfoKey: ""]))
    }

    func testAnUnsubstitutedPlaceholderIsNotAToken() {
        let info: [String: Any] = [Config.trialTokenInfoKey: "@@KEYGEN_TRIAL_TOKEN@@"]

        XCTAssertNil(Config.trialToken(from: info))
    }

    func testANonStringValueIsNotAToken() {
        XCTAssertNil(Config.trialToken(from: [Config.trialTokenInfoKey: 42]))
    }
}
