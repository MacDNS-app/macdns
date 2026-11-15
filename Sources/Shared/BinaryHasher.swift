// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import CryptoKit
import Foundation

public enum BinaryHasher {
    /// Lowercase hex SHA-256 of the file, or nil when it cannot be read.
    public static func sha256(ofFileAt path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path) else {
            return nil
        }
        let hash = SHA256.hash(data: data)
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    public static func currentExecutableHash() -> String? {
        guard let path = Bundle.main.executablePath else { return nil }
        return sha256(ofFileAt: path)
    }
}
