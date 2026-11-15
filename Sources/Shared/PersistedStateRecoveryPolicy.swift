// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import CoreFoundation
import Foundation

/// Versioning of the persisted `state.json` document.
///
/// A document without `schemaVersion` is the current version: client payloads
/// and the empty document of a missing file carry none. A file written by a
/// newer build is never repaired or overwritten. It is reported as incompatible
/// so the downgrade is visible instead of destructive. A version this build
/// cannot read, including one below the current version, is malformed.
public enum ConfigSchemaPolicy {
    public static let currentVersion = 1
    public static let versionKey = "schemaVersion"

    public enum Compatibility: Equatable {
        case current
        case incompatible(version: Int)
        case malformed
    }

    public static func compatibility(
        of config: [String: Any]
    ) -> Compatibility {
        guard let rawValue = config[versionKey] else {
            return .current
        }
        guard let version = parseVersion(rawValue), version >= currentVersion else {
            return .malformed
        }
        return version == currentVersion ? .current : .incompatible(version: version)
    }

    /// The document stamped with the current version, or `nil` for a document
    /// this build must not rewrite.
    public static func writable(_ config: [String: Any]) -> [String: Any]? {
        guard compatibility(of: config) == .current else {
            return nil
        }
        return stamped(config)
    }

    public static func stamped(_ config: [String: Any]) -> [String: Any] {
        var stamped = config
        stamped[versionKey] = currentVersion
        return stamped
    }

    private static func parseVersion(_ rawValue: Any) -> Int? {
        guard
            let number = rawValue as? NSNumber,
            CFGetTypeID(number as CFTypeRef) != CFBooleanGetTypeID(),
            number == NSNumber(value: number.intValue),
            number.intValue >= 0
        else {
            return nil
        }
        return number.intValue
    }
}

public enum PersistedStateRecovery: Equatable {
    case useExisting
    case createDefaults
    case quarantineThenCreateDefaults(quarantineName: String, reason: String)
    case refuseIncompatible(version: Int)
    case refuseUnreadable(reason: String)
}

/// Decides what to do with a persisted `state.json` that could not be used as
/// is. Content this build cannot parse is moved aside so the agent can boot on
/// defaults, while an unreadable file (I/O error) and a newer schema are both
/// left exactly where they are.
public enum PersistedStateRecoveryPolicy {
    public static func decision(
        for load: StateFileLoadResult,
        existingNames: Set<String> = [],
        stateFileName: String = "state.json"
    ) -> PersistedStateRecovery {
        switch load {
        case .missing:
            return .createDefaults
        case .ioFailure(let reason):
            return .refuseUnreadable(reason: reason)
        case .invalid(let reason):
            return quarantine(
                revision: 0,
                reason: reason,
                existingNames: existingNames,
                stateFileName: stateFileName
            )
        case .valid(let config):
            return decision(
                forParsed: config,
                existingNames: existingNames,
                stateFileName: stateFileName
            )
        }
    }

    public static func quarantineName(
        revision: ConfigRevision,
        existingNames: Set<String>,
        stateFileName: String = "state.json"
    ) -> String {
        let base = "\(stateFileName).quarantine-\(revision)"
        guard existingNames.contains(base) else {
            return base
        }
        var attempt = 2
        while existingNames.contains("\(base)-\(attempt)") {
            attempt += 1
        }
        return "\(base)-\(attempt)"
    }

    private static func decision(
        forParsed config: [String: Any],
        existingNames: Set<String>,
        stateFileName: String
    ) -> PersistedStateRecovery {
        switch ConfigSchemaPolicy.compatibility(of: config) {
        case .incompatible(let version):
            return .refuseIncompatible(version: version)
        case .malformed:
            return quarantine(
                revision: ConfigRevisionPolicy.revision(from: config),
                reason: "unreadable \(ConfigSchemaPolicy.versionKey)",
                existingNames: existingNames,
                stateFileName: stateFileName
            )
        case .current:
            guard
                DNSPolicyStructuralPolicy.validateAndNormalize(config) != nil
            else {
                return quarantine(
                    revision: ConfigRevisionPolicy.revision(from: config),
                    reason: "malformed customZones or dnsOverrides",
                    existingNames: existingNames,
                    stateFileName: stateFileName
                )
            }
            return .useExisting
        }
    }

    private static func quarantine(
        revision: ConfigRevision,
        reason: String,
        existingNames: Set<String>,
        stateFileName: String
    ) -> PersistedStateRecovery {
        .quarantineThenCreateDefaults(
            quarantineName: quarantineName(
                revision: revision,
                existingNames: existingNames,
                stateFileName: stateFileName
            ),
            reason: reason
        )
    }
}
