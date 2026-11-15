// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import XCTest

@testable import MacDNS

final class AgentRuntimeStateMappingTests: XCTestCase {
    func testSnapshotMappingCarriesProxyControlUnreachable() {
        let snapshot = AgentRuntimeStateSnapshot(
            servicesRunning: true,
            captivePortalDetected: false,
            forwarding: true,
            lifecycleGeneration: 3,
            transitionInProgress: false,
            proxyControlUnreachable: true
        )
        XCTAssertEqual(AgentRuntimeState(snapshot: snapshot).proxyControlUnreachable, true)
    }

    func testSnapshotMappingKeepsUnknownOutageAsNil() {
        let snapshot = AgentRuntimeStateSnapshot(
            servicesRunning: true,
            captivePortalDetected: false,
            forwarding: false,
            lifecycleGeneration: 3,
            transitionInProgress: false
        )
        XCTAssertNil(AgentRuntimeState(snapshot: snapshot).proxyControlUnreachable)
    }
}
