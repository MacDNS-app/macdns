// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import CryptoKit
import Foundation
import Security

/// Ephemeral, in-memory control session material. Never persisted or logged.
///
/// The HMAC key is held as a `SymmetricKey`, whose backing store CryptoKit
/// wipes when the last reference is released. A plain `Data` would leave the
/// key readable in freed memory after the control connection drops.
struct ProxyControlSession {
    let version: UInt16
    let sessionID: Data  // 16 bytes
    let hmacKey: SymmetricKey  // 32 bytes

    init(version: UInt16, sessionID: Data, hmacKey: Data) {
        self.init(version: version, sessionID: sessionID, key: SymmetricKey(data: hmacKey))
    }

    private init(version: UInt16, sessionID: Data, key: SymmetricKey) {
        self.version = version
        self.sessionID = sessionID
        self.hmacKey = key
    }

    static func generate() -> ProxyControlSession? {
        var id = Data(count: 16)
        let idOK = id.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        guard idOK == errSecSuccess else { return nil }
        // Generated straight into CryptoKit's wiping storage, so the raw key
        // never exists in an unwipeable buffer.
        return ProxyControlSession(version: 1, sessionID: id, key: SymmetricKey(size: .bits256))
    }

    var sessionIDHex: String {
        sessionID.map { String(format: "%02x", $0) }.joined()
    }
}
