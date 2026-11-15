// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

enum AgentAllowlistConfigClassification {
    case missing
    case valid(
        dictionaries: [[String: Any]],
        domains: [AllowedDomain]
    )
    case invalid
}

enum AgentAllowlistConfigPolicy {
    static func classify(
        _ config: [String: Any]
    ) -> AgentAllowlistConfigClassification {
        guard let rawAllowlist = config["allowlist"] else {
            return .missing
        }
        guard let dictionaries = rawAllowlist as? [[String: Any]] else {
            return .invalid
        }
        let domains = dictionaries.compactMap { dictionary -> AllowedDomain? in
            guard
                let idValue = dictionary["id"] as? String,
                let id = UUID(uuidString: idValue),
                let domain = dictionary["domain"] as? String,
                !domain.isEmpty,
                domain == domain.trimmingCharacters(in: .whitespacesAndNewlines),
                let enabled = dictionary["enabled"] as? Bool
            else {
                return nil
            }
            return AllowedDomain(
                id: id,
                domain: domain,
                enabled: enabled
            )
        }
        guard domains.count == dictionaries.count else {
            return .invalid
        }
        return .valid(
            dictionaries: dictionaries,
            domains: domains
        )
    }
}
