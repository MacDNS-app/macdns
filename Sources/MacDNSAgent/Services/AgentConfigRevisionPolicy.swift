// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

enum AgentConfigRevisionPolicy {
    static func classify(
        incoming: [String: Any],
        persisted: [String: Any]
    ) throws -> ConfigSaveRequestClassification {
        try ConfigRevisionPolicy.classify(
            expected: ConfigRevisionPolicy.revision(from: incoming),
            current: ConfigRevisionPolicy.revision(from: persisted),
            incoming: ConfigRevisionPolicy.canonicalPayload(incoming),
            persisted: ConfigRevisionPolicy.canonicalPayload(persisted)
        )
    }

    static func rollbackConfig(
        restoring oldConfig: [String: Any],
        consumedRevision: ConfigRevision
    ) -> [String: Any] {
        var rollback = oldConfig
        rollback["configRevision"] = consumedRevision
        return rollback
    }

    static func configForAgentOwnedMutation(
        _ config: [String: Any]
    ) -> [String: Any]? {
        let currentRevision = ConfigRevisionPolicy.revision(from: config)
        guard currentRevision < .max else {
            return nil
        }
        var updated = config
        updated["configRevision"] = currentRevision + 1
        return updated
    }
}
