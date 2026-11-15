// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class ExtensionNoticeTests: XCTestCase {
    func testRestartRequiredSurvivesApprovalStatusUpdates() {
        var notice = ExtensionNotice.restartRequired

        notice.applyApprovalStatus(proxyNeedsApproval: true, filterNeedsApproval: false)
        XCTAssertEqual(notice, .restartRequired)

        notice.applyApprovalStatus(proxyNeedsApproval: false, filterNeedsApproval: false)
        XCTAssertEqual(notice, .restartRequired)
    }

    func testRestartRequiredClearsWhenRestartNoLongerRequired() {
        var notice = ExtensionNotice.restartRequired

        notice.clearRestartRequiredIfResolved(
            proxyRequiresRestart: false, filterRequiresRestart: false, versionStale: false,
            recoveryExhausted: false)

        XCTAssertEqual(notice, .none)
    }

    func testRestartRequiredSurvivesWhenAnyExtensionStillRequiresRestart() {
        var notice = ExtensionNotice.restartRequired

        notice.clearRestartRequiredIfResolved(
            proxyRequiresRestart: false, filterRequiresRestart: true, versionStale: false,
            recoveryExhausted: false)

        XCTAssertEqual(notice, .restartRequired)
    }

    func testRestartRequiredSurvivesWhileProviderVersionStale() {
        var notice = ExtensionNotice.restartRequired

        notice.clearRestartRequiredIfResolved(
            proxyRequiresRestart: false, filterRequiresRestart: false, versionStale: true,
            recoveryExhausted: false)

        XCTAssertEqual(notice, .restartRequired)
    }

    func testProxyApprovalBlocksProtectionStatus() {
        var notice = ExtensionNotice.none

        notice.applyApprovalStatus(proxyNeedsApproval: true, filterNeedsApproval: true)

        XCTAssertEqual(notice, .proxyApprovalRequired)
        XCTAssertEqual(notice.statusMessageOverride(isProtectionActive: true), "Approval Required")
    }

    func testFilterApprovalDoesNotOverrideActiveDNSProtectionStatus() {
        var notice = ExtensionNotice.none

        notice.applyApprovalStatus(proxyNeedsApproval: false, filterNeedsApproval: true)

        XCTAssertEqual(notice, .filterApprovalRequired)
        XCTAssertNil(notice.statusMessageOverride(isProtectionActive: true))
        XCTAssertEqual(notice.statusMessageOverride(isProtectionActive: false), "Approval Required")
    }

    func testFilterApprovalStillShowsBannerWhenDNSProtectionIsActive() {
        var notice = ExtensionNotice.none

        notice.applyApprovalStatus(proxyNeedsApproval: false, filterNeedsApproval: true)

        XCTAssertEqual(
            notice.permissionBannerMessage(isProtectionActive: true),
            "Approve Content Filter to block DoH/DoT"
        )
    }

    func testApprovalRequiredClearsWhenApprovalNoLongerNeeded() {
        var notice = ExtensionNotice.filterApprovalRequired

        notice.applyApprovalStatus(proxyNeedsApproval: false, filterNeedsApproval: false)

        XCTAssertEqual(notice, .none)
    }

    func testAgentApprovalFallbackShowsGenericBanner() {
        let notice = ExtensionNotice.none

        XCTAssertEqual(
            notice.permissionBannerMessage(isProtectionActive: false, fallbackNeedsApproval: true),
            "Approval required in System Settings"
        )
        XCTAssertNil(notice.permissionBannerMessage(isProtectionActive: false, fallbackNeedsApproval: false))
    }

    func testExtensionNoticeMessageWinsOverAgentApprovalFallback() {
        let notice = ExtensionNotice.filterApprovalRequired

        XCTAssertEqual(
            notice.permissionBannerMessage(isProtectionActive: true, fallbackNeedsApproval: true),
            "Approve Content Filter to block DoH/DoT"
        )
    }

    func testAgentApprovalFallbackShowsStatusOverrideOnlyWithoutExtensionNotice() {
        XCTAssertEqual(
            ExtensionNotice.none.statusMessageOverride(isProtectionActive: true, fallbackNeedsApproval: true),
            "Approval Required"
        )
        XCTAssertNil(
            ExtensionNotice.filterApprovalRequired.statusMessageOverride(
                isProtectionActive: true,
                fallbackNeedsApproval: true
            )
        )
    }

    func testRestartRequiredPersistsWhileRecoveryExhausted() {
        var notice = ExtensionNotice.restartRequired
        notice.clearRestartRequiredIfResolved(
            proxyRequiresRestart: false,
            filterRequiresRestart: false,
            versionStale: false,
            recoveryExhausted: true
        )
        XCTAssertEqual(notice, .restartRequired)
    }

    func testRestartRequiredClearsWhenRecoveryAlsoResolved() {
        var notice = ExtensionNotice.restartRequired
        notice.clearRestartRequiredIfResolved(
            proxyRequiresRestart: false,
            filterRequiresRestart: false,
            versionStale: false,
            recoveryExhausted: false
        )
        XCTAssertEqual(notice, .none)
    }
}
