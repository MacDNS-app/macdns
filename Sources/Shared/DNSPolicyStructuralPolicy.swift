// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import CoreFoundation
import Foundation

public struct ValidatedDNSPolicyConfig {
    public let normalizedConfig: [String: Any]
    public let customZones: [ForwardZone]
    public let dnsOverrides: [DNSOverride]
}

public enum DNSPolicyStructuralPolicy {
    private static let zoneFields: Set<String> = [
        "id", "domain", "forwardIP", "enabled",
    ]
    private static let overrideFields: Set<String> = [
        "id", "domain", "value", "qtype", "enabled",
    ]

    public static func validateAndNormalize(
        _ candidate: [String: Any]
    ) -> ValidatedDNSPolicyConfig? {
        var seenIDs = Set<UUID>()
        guard
            let customZones = parseCustomZones(
                candidate["customZones"],
                seenIDs: &seenIDs
            ),
            let dnsOverrides = parseDNSOverrides(
                candidate["dnsOverrides"],
                seenIDs: &seenIDs
            )
        else {
            return nil
        }

        var normalized = candidate
        normalized["customZones"] = customZones.map(\.normalizedEntry)
        normalized["dnsOverrides"] = dnsOverrides.map(\.normalizedEntry)
        return ValidatedDNSPolicyConfig(
            normalizedConfig: normalized,
            customZones: customZones.map(\.model),
            dnsOverrides: dnsOverrides.map(\.model)
        )
    }

    /// A parsed entry plus the exact dictionary that will be persisted for it.
    /// Fields this build does not know about are carried through untouched so a
    /// file written by a newer build survives a downgrade round-trip.
    private struct ParsedEntry<Model> {
        let model: Model
        let normalizedEntry: [String: Any]
    }

    private static func parseCustomZones(
        _ rawValue: Any?,
        seenIDs: inout Set<UUID>
    ) -> [ParsedEntry<ForwardZone>]? {
        guard let entries = collectionEntries(rawValue) else { return nil }
        var zones: [ParsedEntry<ForwardZone>] = []
        zones.reserveCapacity(entries.count)

        for entry in entries {
            guard
                let dictionary = entry as? [String: Any],
                zoneFields.isSubset(of: dictionary.keys),
                let id = parseUniqueID(dictionary["id"], seenIDs: &seenIDs),
                let domain = parseRequiredString(dictionary["domain"]),
                let forwardIP = parseRequiredString(dictionary["forwardIP"]),
                let enabled = parseBool(dictionary["enabled"])
            else {
                return nil
            }
            let zone = ForwardZone(
                id: id,
                domain: domain,
                forwardIP: forwardIP,
                enabled: enabled
            )
            zones.append(
                ParsedEntry(
                    model: zone,
                    normalizedEntry: normalizedEntry(
                        canonical: zone.toDictionary(),
                        raw: dictionary
                    )
                )
            )
        }
        return zones
    }

    private static func parseDNSOverrides(
        _ rawValue: Any?,
        seenIDs: inout Set<UUID>
    ) -> [ParsedEntry<DNSOverride>]? {
        guard let entries = collectionEntries(rawValue) else { return nil }
        var overrides: [ParsedEntry<DNSOverride>] = []
        overrides.reserveCapacity(entries.count)

        for entry in entries {
            guard
                let dictionary = entry as? [String: Any],
                overrideFields.isSubset(of: dictionary.keys),
                let id = parseUniqueID(dictionary["id"], seenIDs: &seenIDs),
                let domain = parseRequiredString(dictionary["domain"]),
                // Override data is opaque. TXT whitespace is significant.
                let value = dictionary["value"] as? String,
                let qtype = parseRequiredString(dictionary["qtype"]),
                let enabled = parseBool(dictionary["enabled"])
            else {
                return nil
            }
            let override = DNSOverride(
                id: id,
                domain: domain,
                value: value,
                qtype: qtype,
                enabled: enabled
            )
            overrides.append(
                ParsedEntry(
                    model: override,
                    normalizedEntry: normalizedEntry(
                        canonical: override.toDictionary(),
                        raw: dictionary
                    )
                )
            )
        }
        return overrides
    }

    private static func normalizedEntry(
        canonical: [String: Any],
        raw: [String: Any]
    ) -> [String: Any] {
        var entry = raw
        for (key, value) in canonical {
            entry[key] = value
        }
        return entry
    }

    private static func collectionEntries(_ rawValue: Any?) -> [Any]? {
        guard let rawValue else { return [] }
        return rawValue as? [Any]
    }

    private static func parseUniqueID(
        _ rawValue: Any?,
        seenIDs: inout Set<UUID>
    ) -> UUID? {
        guard
            let rawID = rawValue as? String,
            rawID == rawID.trimmingCharacters(in: .whitespacesAndNewlines),
            let id = UUID(uuidString: rawID),
            seenIDs.insert(id).inserted
        else {
            return nil
        }
        return id
    }

    private static func parseRequiredString(_ rawValue: Any?) -> String? {
        guard let value = rawValue as? String else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, value == trimmed else { return nil }
        return value
    }

    private static func parseBool(_ rawValue: Any?) -> Bool? {
        guard
            let rawValue,
            CFGetTypeID(rawValue as CFTypeRef) == CFBooleanGetTypeID()
        else {
            return nil
        }
        return rawValue as? Bool
    }
}
