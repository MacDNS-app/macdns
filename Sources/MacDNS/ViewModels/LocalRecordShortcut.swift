// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Shared

/// Block and Add Local Record on the Queries page. Both write Local Records:
/// blocking a host adds A 0.0.0.0 and AAAA ::, so it can be undone from the
/// same row or from the Local Records page.
enum LocalRecordShortcut {
    /// The record types the Local Records page edits.
    static let recordTypes = ["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS"]

    private static let blockingRecords: [(qtype: String, value: String)] = [("A", "0.0.0.0"), ("AAAA", "::")]

    enum Block: Equatable {
        case available
        case blocked
        /// Blocking would conflict with the host's own records, or the name is not a valid Local Record name.
        case unavailable(reason: String)
    }

    static func block(for host: String, in overrides: [DNSOverride]) -> Block {
        if isBlocked(host, in: overrides) { return .blocked }
        if case .failure(let error) = DomainValidator.validate(host, allowsSingleLabelHost: true) {
            return .unavailable(reason: error.localizedDescription)
        }
        for record in blockingRecords
        where !overrides.contains(where: { $0.enabled && isBlocking($0, host: host, record: record) }) {
            if let conflict = DomainValidator.validateCNAMEExclusivity(
                domain: host, qtype: record.qtype, existingOverrides: overrides)
            {
                return .unavailable(reason: conflict)
            }
        }
        return .available
    }

    /// `overrides` with both blocking records of `host` on. A matching record
    /// that is off is turned on instead of being added twice. `nil` unless
    /// `block(for:in:)` is `.available`.
    static func blocking(_ host: String, in overrides: [DNSOverride]) -> [DNSOverride]? {
        guard block(for: host, in: overrides) == .available else { return nil }
        var result = overrides
        for record in blockingRecords {
            if let index = result.firstIndex(where: { isBlocking($0, host: host, record: record) }) {
                result[index].enabled = true
            } else {
                result.append(DNSOverride(domain: host, value: record.value, qtype: record.qtype))
            }
        }
        return result
    }

    /// `overrides` without the blocking records of `host`. Its other records stay.
    static func unblocking(_ host: String, in overrides: [DNSOverride]) -> [DNSOverride] {
        overrides.filter { override in
            !blockingRecords.contains { isBlocking(override, host: host, record: $0) }
        }
    }

    /// Why `value` cannot be added as a `qtype` record of `host`, checked like
    /// the Local Records editor does. An empty value has no message yet.
    static func addError(host: String, qtype: String, value: String, in overrides: [DNSOverride]) -> String? {
        if case .failure(let error) = DomainValidator.validate(host, allowsSingleLabelHost: true) {
            return error.localizedDescription
        }
        if let conflict = DomainValidator.validateCNAMEExclusivity(
            domain: host, qtype: qtype, existingOverrides: overrides)
        {
            return conflict
        }
        guard !value.isEmpty else { return nil }
        if case .failure(let error) = DomainValidator.validateOverrideValue(value, forType: qtype) {
            return error.localizedDescription
        }
        return nil
    }

    /// `overrides` with the new record, or `nil` when the value is empty or has an error.
    static func adding(host: String, qtype: String, value: String, to overrides: [DNSOverride]) -> [DNSOverride]? {
        guard !value.isEmpty, addError(host: host, qtype: qtype, value: value, in: overrides) == nil else {
            return nil
        }
        return overrides + [DNSOverride(domain: host, value: value, qtype: qtype)]
    }

    /// The type the add form starts with: the looked-up type when Local Records support it.
    static func initialType(forLookupType lookupType: String?) -> String {
        guard let lookupType, recordTypes.contains(lookupType) else { return "A" }
        return lookupType
    }

    private static func isBlocked(_ host: String, in overrides: [DNSOverride]) -> Bool {
        blockingRecords.allSatisfy { record in
            overrides.contains { $0.enabled && isBlocking($0, host: host, record: record) }
        }
    }

    private static func isBlocking(
        _ override: DNSOverride, host: String, record: (qtype: String, value: String)
    ) -> Bool {
        override.qtype == record.qtype && override.value == record.value
            && DomainValidator.comparableDomain(override.domain) == DomainValidator.comparableDomain(host)
    }
}
