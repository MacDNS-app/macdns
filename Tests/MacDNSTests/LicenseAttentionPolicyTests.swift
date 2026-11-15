// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import Shared
import XCTest

final class LicenseAttentionPolicyTests: XCTestCase {
    func testNeedsAttention() {
        for status in [LicenseStatus.expired, .trialExpired, .invalid] {
            XCTAssertTrue(LicenseAttentionPolicy.needsAttention(status), "\(status)")
        }
        for status in [LicenseStatus.trial, .valid, .unknown] {
            XCTAssertFalse(LicenseAttentionPolicy.needsAttention(status), "\(status)")
        }
        XCTAssertFalse(LicenseAttentionPolicy.needsAttention(nil))
    }

    func testBadge() {
        XCTAssertEqual(LicenseAttentionPolicy.badge(licenseStatus: .expired, updateAvailable: true), "!")
        XCTAssertEqual(LicenseAttentionPolicy.badge(licenseStatus: .valid, updateAvailable: true), "1")
        XCTAssertNil(LicenseAttentionPolicy.badge(licenseStatus: .trial, updateAvailable: false))
    }
}
