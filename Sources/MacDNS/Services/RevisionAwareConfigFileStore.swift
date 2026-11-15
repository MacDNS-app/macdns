// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

enum RevisionAwareConfigFileStore {
    static func save(
        snapshot: [String: Any],
        expectedRevision: ConfigRevision,
        stateFile: URL,
        timestamp: TimeInterval = Date().timeIntervalSinceReferenceDate
    ) -> ConfigRevision? {
        guard
            expectedRevision < .max,
            FullConfigPayloadPolicy.isValidPayload(snapshot),
            let validatedSnapshot =
                DNSPolicyStructuralPolicy.validateAndNormalize(snapshot),
            DNSPolicySemanticPolicy.rejection(
                zones: validatedSnapshot.customZones,
                overrides: validatedSnapshot.dnsOverrides
            ) == nil
        else {
            return nil
        }

        do {
            try FileManager.default.createDirectory(
                at: stateFile.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            return try StateFileLock.withExclusiveLock(
                stateFile: stateFile
            ) {
                let currentConfig: [String: Any]
                switch StateFileLock.loadUnlocked(stateFile: stateFile) {
                case .missing:
                    currentConfig = [:]
                case .valid(let persisted):
                    currentConfig = persisted
                case .invalid, .ioFailure:
                    return nil
                }
                guard
                    DNSPolicyStructuralPolicy.validateAndNormalize(currentConfig)
                        != nil,
                    ConfigRevisionPolicy.revision(from: currentConfig)
                        == expectedRevision,
                    // A file written by a newer build is never rewritten, and a
                    // field this build does not know about is carried through
                    // instead of being dropped by the snapshot.
                    let writableCurrent = ConfigSchemaPolicy.writable(currentConfig)
                else {
                    return nil
                }

                let nextRevision = expectedRevision + 1
                var persisted = writableCurrent
                for (key, value) in validatedSnapshot.normalizedConfig {
                    persisted[key] = value
                }
                persisted["configRevision"] = nextRevision
                persisted["timestamp"] = timestamp

                let data = try JSONSerialization.data(
                    withJSONObject: persisted,
                    options: [.prettyPrinted, .sortedKeys]
                )
                try data.write(to: stateFile, options: .atomic)
                return nextRevision
            }
        } catch {
            return nil
        }
    }
}
