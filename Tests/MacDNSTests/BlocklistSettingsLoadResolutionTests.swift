// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import Shared
import XCTest

final class BlocklistSettingsLoadResolutionTests: XCTestCase {
    func testAgentSettingsApplyWithoutConsultingFileFallback() {
        var agentSettings = BlocklistSettings()
        agentSettings.enabled = true
        var fileFallbackCalls = 0

        let resolution = BlocklistSettingsLoadResolution.resolve(
            agentSettings: agentSettings,
            fileSettings: {
                fileFallbackCalls += 1
                return BlocklistSettings()
            }
        )

        XCTAssertEqual(resolution, .apply(agentSettings))
        XCTAssertEqual(fileFallbackCalls, 0)
    }

    func testFileFallbackAppliesWhenAgentSettingsAreMissing() {
        var fileSettings = BlocklistSettings()
        fileSettings.enabled = true

        let resolution = BlocklistSettingsLoadResolution.resolve(
            agentSettings: nil,
            fileSettings: { fileSettings }
        )

        XCTAssertEqual(resolution, .apply(fileSettings))
    }

    func testDoubleFailureKeepsSettingsUnavailable() {
        let resolution = BlocklistSettingsLoadResolution.resolve(
            agentSettings: nil,
            fileSettings: { nil }
        )

        XCTAssertEqual(resolution, .keepUnavailable)
    }
}
