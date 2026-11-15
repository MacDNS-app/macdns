// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import XCTest

@testable import Shared

final class ProxyControlClientDecodeTests: XCTestCase {
    // Proves the provider's JSONSerialization dictionary decodes into the
    // Shared Codable the agent uses. Guards the base64 Data interop.
    func testProviderDictionaryDecodesAsBootstrap() throws {
        let sessionID = Data(repeating: 0xAB, count: 16)
        let key = Data(repeating: 0xCD, count: 32)
        let providerDict: [String: Any] = [
            "version": 1,
            "sessionID": sessionID.base64EncodedString(),
            "hmacKey": key.base64EncodedString(),
        ]
        let data = try JSONSerialization.data(withJSONObject: providerDict)
        let boot = try JSONDecoder().decode(ProxyControlBootstrap.self, from: data)
        XCTAssertEqual(boot.version, 1)
        XCTAssertEqual(boot.sessionID, sessionID)
        XCTAssertEqual(boot.hmacKey, key)
    }
}
