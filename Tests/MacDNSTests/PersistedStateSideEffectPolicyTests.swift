// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class PersistedStateSideEffectPolicyTests: XCTestCase {
    func testBlockToggleReloadDoesNotClearRestartNotice() {
        var notice: ExtensionNotice = .restartRequired

        // Applying a persisted `false` must not schedule any runtime work.
        let sideEffect = PersistedStateSideEffectPolicy.blockDohDotSideEffect(
            oldValue: true,
            newValue: false,
            isApplyingPersistedState: true
        )
        if sideEffect == .disableContentFilter {
            // Mirrors cancelPendingContentFilterEnable().
            notice = .none
        }

        XCTAssertEqual(sideEffect, .none)
        XCTAssertEqual(notice, .restartRequired)
    }

    func testGuardEvaluatedAfterTheApplyWouldClearTheRestartNotice() {
        var notice: ExtensionNotice = .restartRequired

        // `isApplyingPersistedState` is already false by the time a deferred
        // guard runs inside the Task body.
        let deferredSideEffect = PersistedStateSideEffectPolicy.blockDohDotSideEffect(
            oldValue: true,
            newValue: false,
            isApplyingPersistedState: false
        )
        if deferredSideEffect == .disableContentFilter {
            notice = .none
        }

        XCTAssertEqual(deferredSideEffect, .disableContentFilter)
        XCTAssertEqual(notice, .none)
    }

    func testUserToggleStillDrivesContentFilter() {
        XCTAssertEqual(
            PersistedStateSideEffectPolicy.blockDohDotSideEffect(
                oldValue: false,
                newValue: true,
                isApplyingPersistedState: false
            ),
            .enableContentFilter
        )
        XCTAssertEqual(
            PersistedStateSideEffectPolicy.blockDohDotSideEffect(
                oldValue: true,
                newValue: false,
                isApplyingPersistedState: false
            ),
            .disableContentFilter
        )
    }

    func testUnchangedValueNeverTriggersSideEffects() {
        XCTAssertEqual(
            PersistedStateSideEffectPolicy.blockDohDotSideEffect(
                oldValue: true,
                newValue: true,
                isApplyingPersistedState: false
            ),
            .none
        )
        XCTAssertEqual(
            PersistedStateSideEffectPolicy.blockDohDotSideEffect(
                oldValue: false,
                newValue: false,
                isApplyingPersistedState: true
            ),
            .none
        )
    }
}
