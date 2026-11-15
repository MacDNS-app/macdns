// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import Shared
import XCTest

final class SettingsStatusToneTests: XCTestCase {
    func testLoadedActiveAndDegraded() {
        XCTAssertEqual(SettingsStatusTone.tone(availability: .loaded, status: .active), .active)
        XCTAssertEqual(SettingsStatusTone.tone(availability: .loaded, status: .degradedForwarding), .degraded)
    }

    func testLoadedOtherStatusesAreInactive() {
        let others: [ProtectionStatusPolicy.Status] = [
            .ready, .starting, .dnsProxyInactive, .captiveBypass,
            .providerBypass(reason: "resolverNotReady"), .providerUnknown,
        ]
        for status in others {
            XCTAssertEqual(SettingsStatusTone.tone(availability: .loaded, status: status), .inactive, "\(status)")
        }
    }

    func testLoadingAndUnavailableAreWaiting() {
        XCTAssertEqual(SettingsStatusTone.tone(availability: .loading, status: .active), .waiting)
        XCTAssertEqual(SettingsStatusTone.tone(availability: .unavailable, status: .ready), .waiting)
    }

    func testInvalidConfigurationIsConfigurationError() {
        XCTAssertEqual(
            SettingsStatusTone.tone(availability: .invalidConfiguration, status: .active),
            .configurationError
        )
    }

    func testAgentSetupRequiredIsInactiveNotWaiting() {
        XCTAssertEqual(SettingsStatusTone.tone(availability: .agentSetupRequired, status: .ready), .inactive)
        XCTAssertTrue(PersistedStateAvailability.agentSetupRequired.showsProtectionToggle)
    }
}
