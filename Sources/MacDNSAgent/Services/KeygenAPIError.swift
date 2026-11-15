// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

/// One JSON:API error object from a Keygen 4xx response.
///
/// Keygen derives `code` from the failing attribute and validation, for example
/// `KEY_TAKEN` on `/data/attributes/key`, `FINGERPRINT_TAKEN` on
/// `/data/attributes/fingerprint` or `MACHINE_LIMIT_EXCEEDED` on `/data`.
/// Decisions use these structured fields, never the human-readable `detail`.
struct KeygenAPIError: Equatable, Sendable {
    let code: String?
    let pointer: String?
    let detail: String?

    static func errors(in body: Data) -> [KeygenAPIError] {
        guard
            let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
            let errors = json["errors"] as? [[String: Any]]
        else {
            return []
        }
        return errors.map { error in
            KeygenAPIError(
                code: error["code"] as? String,
                pointer: (error["source"] as? [String: Any])?["pointer"] as? String,
                detail: error["detail"] as? String
            )
        }
    }

    /// The number Keygen appends to limit errors, as in "... for license (3)".
    var trailingLimit: Int? {
        guard
            let detail,
            let open = detail.lastIndex(of: "("),
            let close = detail.lastIndex(of: ")"),
            open < close
        else {
            return nil
        }
        return Int(detail[detail.index(after: open)..<close])
    }
}

extension Array where Element == KeygenAPIError {
    func contains(code: String, pointer: String) -> Bool {
        contains { $0.code == code && $0.pointer == pointer }
    }

    func first(code: String) -> KeygenAPIError? {
        first { $0.code == code }
    }
}
