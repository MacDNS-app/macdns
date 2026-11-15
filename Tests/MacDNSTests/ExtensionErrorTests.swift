// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

@testable import MacDNS
import XCTest

final class ExtensionErrorTests: XCTestCase {
    func testActivationRequiresRebootHasActionableMessage() {
        XCTAssertEqual(
            ExtensionError.activationRequiresReboot.errorDescription,
            "System Extension activation requires restart"
        )
    }
}
