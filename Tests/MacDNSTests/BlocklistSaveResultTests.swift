// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import MacDNS

final class BlocklistSaveResultTests: XCTestCase {
    func testRunnableAgentRefusesFallbackAfterTransportFailure() {
        let result = BlocklistSaveResult.agentUnavailable
        XCTAssertFalse(
            result.shouldFallbackToFile(agentAllowsFallback: AgentStateFileFallbackPolicy.canUseFallback(for: .enabled))
        )
        XCTAssertFalse(
            result.shouldFallbackToFile(agentAllowsFallback: AgentStateFileFallbackPolicy.canUseFallback(for: .unknown))
        )
        XCTAssertTrue(
            result.shouldFallbackToFile(
                agentAllowsFallback: AgentStateFileFallbackPolicy.canUseFallback(for: .notRegistered)))
    }

    func testTimeoutNeverFallsBackBecauseMutationMayHaveCommitted() {
        XCTAssertFalse(BlocklistSaveResult.timedOut.shouldFallbackToFile(agentAllowsFallback: true))
    }

    func testFallsBackToFileOnlyWhenAgentIsUnavailable() {
        XCTAssertTrue(BlocklistSaveResult.agentUnavailable.shouldFallbackToFile(agentAllowsFallback: true))
        XCTAssertFalse(BlocklistSaveResult.saved.shouldFallbackToFile(agentAllowsFallback: true))
        XCTAssertFalse(BlocklistSaveResult.rejectedByAgent.shouldFallbackToFile(agentAllowsFallback: true))
        XCTAssertFalse(BlocklistSaveResult.encodingFailed.shouldFallbackToFile(agentAllowsFallback: true))
    }
}
