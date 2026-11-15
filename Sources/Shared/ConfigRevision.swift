// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation

public typealias ConfigRevision = Int64

public enum ConfigSaveRequestClassification: Equatable {
    case accept(nextRevision: ConfigRevision)
    case idempotentSuccess
    case conflict
}

public enum ConfigRevisionPolicy {
    public static func revision(
        from config: [String: Any]
    ) -> ConfigRevision {
        guard let value = config["configRevision"] as? NSNumber,
            CFGetTypeID(value) != CFBooleanGetTypeID(),
            let revision = ConfigRevision(value.stringValue),
            revision >= 0
        else {
            return 0
        }
        return revision
    }

    public static func canonicalPayload(
        _ config: [String: Any]
    ) throws -> Data {
        var payload = config
        payload.removeValue(forKey: "timestamp")
        payload.removeValue(forKey: "configRevision")
        return try JSONSerialization.data(
            withJSONObject: payload,
            options: [.sortedKeys]
        )
    }

    public static func classify(
        expected: ConfigRevision,
        current: ConfigRevision,
        incoming: Data,
        persisted: Data
    ) -> ConfigSaveRequestClassification {
        if expected == current, current < .max {
            return .accept(nextRevision: current + 1)
        }
        if expected < .max,
            expected + 1 == current,
            incoming == persisted
        {
            return .idempotentSuccess
        }
        return .conflict
    }
}
