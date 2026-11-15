// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Darwin
import Foundation

/// Why a DNS policy snapshot cannot be published to the resolver.
public struct DNSPolicySemanticRejection: Error, Equatable {
    public let reason: String

    public init(_ reason: String) {
        self.reason = reason
    }
}

/// Where a validated name is used. Mirrors `domain_name::NameRole`.
public enum DNSPolicyNameRole: Sendable {
    /// Override owner. Wildcards are accepted, and so is any single-label host
    /// such as `server`, because the resolver answers an exact single-label
    /// owner only for itself and never claims the names under it.
    case overrideOwner
    /// Forward-zone apex. A zone routes every name under it, so a single label
    /// is limited to a reserved TLD.
    case forwardZone
}

/// Semantic gate for the overrides and forward zones the resolver will be asked
/// to publish. Both writers run it before committing to `state.json`.
///
/// `DNSPolicyStructuralPolicy` only proves the JSON shape. The meaning lives in
/// `rust-resolver/crates/macdns-resolver/src/policy.rs` (`build_snapshot`),
/// `domain_name.rs` (`canonicalize`) and `lib.rs` (`parse_override`), and that
/// code never runs while the resolver is stopped. Without this gate a
/// structurally valid but semantically invalid entry would commit to
/// `state.json` and then block the next start.
///
/// Alignment rule: this validator must never reject what the resolver accepts,
/// with one deliberate exception, code points that UTS-46 *maps* onto another
/// name (`DomainNameCoding.isMappedByUTS46`). Encoding those would let two
/// entries look distinct here and collide inside the resolver, which rejects
/// the whole snapshot. Refusing them keeps the collision out of `state.json`.
///
/// Where the resolver defers to hickory's zonefile presentation parser, so does
/// this policy: the record type must be nameable, and the resolver still
/// rejects the whole snapshot if it cannot parse the value. Only enabled
/// records are checked, because only enabled records are handed to the resolver
/// (`applyOverridesAndZonesToModule`).
public enum DNSPolicySemanticPolicy {
    /// TLDs reserved for local, testing and internal use. Must stay identical to
    /// `RESERVED_TLDS` in `rust-resolver/crates/macdns-resolver/src/domain_name.rs`
    /// and to `DomainValidator.reservedTLDs`.
    private static let reservedTLDs: Set<String> = [
        "cluster",
        "corp",
        "docker",
        "example",
        "home",
        "internal",
        "intranet",
        "invalid",
        "k8s",
        "lan",
        "local",
        "localdomain",
        "localhost",
        "onion",
        "pod",
        "private",
        "svc",
        "test",
    ]

    /// Record types hickory 0.26.1 `RecordType::from_str` can name. A type
    /// outside this set makes `parse_override`'s generic fallback fail, so the
    /// resolver would reject the snapshot.
    private static let nameableRecordTypes: Set<String> = [
        "A", "AAAA", "ANAME", "ANY", "AXFR", "CAA", "CDNSKEY", "CDS", "CERT",
        "CNAME", "CSYNC", "DNSKEY", "DS", "HINFO", "HTTPS", "KEY", "MX",
        "NAPTR", "NS", "NSEC", "NSEC3", "NSEC3PARAM", "NULL", "OPENPGPKEY",
        "PTR", "RRSIG", "SIG", "SMIMEA", "SOA", "SRV", "SSHFP", "SVCB", "TLSA",
        "TSIG", "TXT", "*",
    ]

    /// Mirrors `policy::build_snapshot`: the first rejected record aborts the
    /// whole candidate so a partially valid policy can never be published, and
    /// every rejection names the offending entry as the user wrote it.
    public static func rejection(
        zones: [ForwardZone],
        overrides: [DNSOverride]
    ) -> DNSPolicySemanticRejection? {
        var accepted = AcceptedEntries()

        for override in overrides where override.enabled {
            if let rejection = accepted.accept(override) {
                return rejection
            }
        }
        for zone in zones where zone.enabled {
            if let rejection = accepted.accept(zone) {
                return rejection
            }
        }

        return nil
    }

    /// The owner bookkeeping `build_snapshot` keeps while it walks a candidate.
    /// Only an accepted entry is recorded, so a dropped one cannot make the
    /// next entry look like a duplicate or a CNAME conflict.
    private struct AcceptedEntries {
        private var overrideKeys = Set<String>()
        private var cnameOwners = Set<String>()
        private var otherOwners = Set<String>()
        private var zoneApexes = Set<String>()

        mutating func accept(
            _ override: DNSOverride
        ) -> DNSPolicySemanticRejection? {
            let identify = { (reason: String) in
                DNSPolicySemanticRejection(
                    "override \(override.domain) \(override.qtype): \(reason)"
                )
            }
            if let rejection = DNSPolicySemanticPolicy.overrideValueRejection(
                qtype: override.qtype,
                value: override.value
            ) {
                return identify(rejection.reason)
            }
            let domain: String
            switch DNSPolicySemanticPolicy.canonicalName(override.domain, role: .overrideOwner) {
            case .success(let canonical):
                domain = canonical
            case .failure(let rejection):
                return identify(rejection.reason)
            }
            let key = "\(domain)\u{0}\(override.qtype)"
            guard !overrideKeys.contains(key) else {
                return identify("duplicate entry")
            }
            if override.qtype == "CNAME" {
                guard !otherOwners.contains(domain) else {
                    return identify(DNSPolicySemanticPolicy.cnameConflict(override.domain))
                }
                cnameOwners.insert(domain)
            } else {
                guard !cnameOwners.contains(domain) else {
                    return identify(DNSPolicySemanticPolicy.cnameConflict(override.domain))
                }
                otherOwners.insert(domain)
            }
            overrideKeys.insert(key)
            return nil
        }

        mutating func accept(
            _ zone: ForwardZone
        ) -> DNSPolicySemanticRejection? {
            let identify = { (reason: String) in
                DNSPolicySemanticRejection("forward zone \(zone.domain): \(reason)")
            }
            let domain: String
            switch DNSPolicySemanticPolicy.canonicalName(zone.domain, role: .forwardZone) {
            case .success(let canonical):
                domain = canonical
            case .failure(let rejection):
                return identify(rejection.reason)
            }
            guard !zoneApexes.contains(domain) else {
                return identify("duplicate entry")
            }
            if let rejection = DNSPolicySemanticPolicy.forwardTargetRejection(zone.forwardIP) {
                return identify(rejection.reason)
            }
            zoneApexes.insert(domain)
            return nil
        }
    }

    /// Canonical wire form used for duplicate detection and length limits.
    /// Mirrors `domain_name::canonicalize`.
    public static func canonicalName(
        _ input: String,
        role: DNSPolicyNameRole
    ) -> Result<String, DNSPolicySemanticRejection> {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return .failure(DNSPolicySemanticRejection("domain is empty"))
        }
        guard !trimmed.hasSuffix("..") else {
            return .failure(
                DNSPolicySemanticRejection("domain has consecutive dots")
            )
        }

        let withoutRoot =
            trimmed.hasSuffix(".") ? String(trimmed.dropLast()) : trimmed
        let prefix: String
        let body: String
        if withoutRoot.hasPrefix("*.") {
            guard role == .overrideOwner else {
                return .failure(
                    DNSPolicySemanticRejection("wildcard is not allowed")
                )
            }
            prefix = "*."
            body = String(withoutRoot.dropFirst(2))
        } else {
            prefix = ""
            body = withoutRoot
        }

        guard !body.isEmpty, !body.contains("*"), !body.contains("..") else {
            return .failure(DNSPolicySemanticRejection("invalid domain"))
        }

        let labels = body.split(
            separator: ".",
            omittingEmptySubsequences: false
        ).map(String.init)
        for label in labels {
            guard isValidLabel(label) else {
                return .failure(
                    DNSPolicySemanticRejection("invalid domain label \(label)")
                )
            }
        }
        guard let asciiLabels = asciiForm(labels) else {
            return .failure(DNSPolicySemanticRejection("invalid IDN domain"))
        }
        // The wildcard is a label of its own on the wire, so it is counted here
        // even though it was stripped before the per-label checks.
        let wireLabels = prefix.isEmpty ? asciiLabels : ["*"] + asciiLabels
        guard DomainNameCoding.wireLength(asciiLabels: wireLabels) <= 255 else {
            return .failure(
                DNSPolicySemanticRejection("domain exceeds 255 octets on the wire")
            )
        }
        let ascii = asciiLabels.joined(separator: ".")

        let tld = asciiLabels[asciiLabels.count - 1]
        guard !tld.utf8.allSatisfy(isASCIIDigit) else {
            return .failure(
                DNSPolicySemanticRejection(
                    "top-level domain cannot be purely numeric"
                )
            )
        }
        let isSingleLabelHost = prefix.isEmpty && role == .overrideOwner
        guard labels.count > 1 || isSingleLabelHost || reservedTLDs.contains(tld) else {
            return .failure(
                DNSPolicySemanticRejection(
                    "single-label domain \(tld) is only allowed for a reserved TLD"
                )
            )
        }

        return .success(prefix + ascii)
    }

    private static func cnameConflict(_ domain: String) -> String {
        "CNAME cannot coexist with other records at \(domain)"
    }

    /// Mirrors `parse_override`. `SRV` is rejected explicitly because its owner
    /// names need underscore labels that `canonicalName` refuses, so an SRV
    /// override can never be addressed.
    private static func overrideValueRejection(
        qtype: String,
        value: String
    ) -> DNSPolicySemanticRejection? {
        switch qtype {
        case "A":
            guard parsesAs(family: AF_INET, value: value) else {
                return DNSPolicySemanticRejection(
                    "invalid A value \(value): not an IPv4 address"
                )
            }
        case "AAAA":
            guard parsesAs(family: AF_INET6, value: value) else {
                return DNSPolicySemanticRejection(
                    "invalid AAAA value \(value): not an IPv6 address"
                )
            }
        case "CNAME", "PTR", "NS":
            return identifiedTargetRejection(value, qtype: qtype)
        case "MX":
            let parts = value.split(whereSeparator: \.isWhitespace)
            switch parts.count {
            case 1:
                return identifiedTargetRejection(String(parts[0]), qtype: qtype)
            case 2:
                guard UInt16(parts[0]) != nil else {
                    return DNSPolicySemanticRejection(
                        "invalid MX preference \(parts[0])"
                    )
                }
                return identifiedTargetRejection(String(parts[1]), qtype: qtype)
            default:
                return DNSPolicySemanticRejection("MX: [priority] hostname")
            }
        case "TXT":
            guard value.utf8.count <= 255 else {
                return DNSPolicySemanticRejection(
                    "TXT value exceeds 255 UTF-8 bytes"
                )
            }
        case "SRV":
            return DNSPolicySemanticRejection(
                "SRV overrides are not supported"
            )
        default:
            guard nameableRecordTypes.contains(qtype) else {
                return DNSPolicySemanticRejection("unsupported qtype \(qtype)")
            }
        }
        return nil
    }

    private static func identifiedTargetRejection(
        _ value: String,
        qtype: String
    ) -> DNSPolicySemanticRejection? {
        targetNameRejection(value).map {
            DNSPolicySemanticRejection("\(qtype) \($0.reason)")
        }
    }

    /// The one gate for a name that appears in RDATA (CNAME, PTR, NS, MX).
    /// Used by the App UI, the App's file fallback and the agent's save path so
    /// the three cannot drift.
    ///
    /// What hickory's `Name` parser enforces, applied to the A-label form the
    /// resolver actually builds: an empty label is refused outright
    /// (`Label::from_utf8` requires at least one octet), every label carries a
    /// length octet, the name ends with the root label, and the label
    /// characters are the ones `is_safe_ascii` accepts. One trailing root dot
    /// is presentation syntax, not an empty label, so it is dropped first.
    /// Everything else in a presentation-format target is the resolver's to
    /// reject, so refusing more here would block saves the resolver would have
    /// accepted.
    public static func targetNameRejection(
        _ value: String
    ) -> DNSPolicySemanticRejection? {
        let withoutRoot = value.hasSuffix(".") ? String(value.dropLast()) : value
        guard !withoutRoot.isEmpty else {
            return DNSPolicySemanticRejection("target is empty")
        }
        // A presentation escape (`\.`, `\065`) decides for itself where the
        // labels start and end, and only the resolver's parser can resolve it.
        // Such a value skips the character check but keeps the encoding and
        // length checks.
        let escaped = withoutRoot.contains("\\")
        var asciiLabels: [String] = []
        for label in withoutRoot.split(
            separator: ".",
            omittingEmptySubsequences: false
        ) {
            guard !label.isEmpty else {
                return DNSPolicySemanticRejection("target has an empty label")
            }
            guard let ascii = DomainNameCoding.asciiLabel(String(label)) else {
                return DNSPolicySemanticRejection(
                    "target label \(label) cannot be encoded as IDNA ASCII"
                )
            }
            guard ascii.utf8.count <= 63 else {
                return DNSPolicySemanticRejection(
                    "target has a label over 63 octets"
                )
            }
            guard escaped || isSafeLabel(ascii) else {
                return DNSPolicySemanticRejection(
                    "target label \(label) has characters the resolver cannot parse"
                )
            }
            asciiLabels.append(ascii)
        }
        guard DomainNameCoding.wireLength(asciiLabels: asciiLabels) <= 255 else {
            return DNSPolicySemanticRejection(
                "target exceeds 255 octets on the wire"
            )
        }
        return nil
    }

    /// Mirrors hickory's `is_safe_ascii` on an A-label: ASCII alphanumerics,
    /// `_` anywhere (SRV-style labels), `-` anywhere but first, `*` only first.
    private static func isSafeLabel(_ label: String) -> Bool {
        for (index, byte) in label.utf8.enumerated() {
            let isAlphanumeric =
                (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "z"))
                || (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z"))
                || (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
            let isSafe =
                isAlphanumeric
                || byte == UInt8(ascii: "_")
                || (byte == UInt8(ascii: "-") && index > 0)
                || (byte == UInt8(ascii: "*") && index == 0)
            guard isSafe else { return false }
        }
        return true
    }

    /// Mirrors `zones::validate_forward_target`: an unspecified, IPv4 broadcast
    /// or multicast target can never answer, so it would black-hole the routed
    /// namespace.
    private static func forwardTargetRejection(
        _ forwardIP: String
    ) -> DNSPolicySemanticRejection? {
        guard DNSResolverAddressParser.isIPAddress(forwardIP) else {
            return DNSPolicySemanticRejection(
                "invalid forward target \(forwardIP)"
            )
        }
        guard
            let kind = DNSResolverAddressParser.unusableForwardTargetKind(
                forwardIP
            )
        else {
            return nil
        }
        return DNSPolicySemanticRejection(
            "forward target \(forwardIP) is a \(kind) address"
        )
    }

    private static func parsesAs(family: Int32, value: String) -> Bool {
        var buffer = [UInt8](repeating: 0, count: family == AF_INET ? 4 : 16)
        let parsed = value.withCString { text in
            buffer.withUnsafeMutableBytes { storage in
                inet_pton(family, text, storage.baseAddress)
            }
        }
        return parsed == 1
    }

    // MARK: - IDNA canonicalization

    /// Same contract as `DomainValidator.validateLabel`'s character rules: the
    /// resolver maps a label through UTS-46, and the code points it would *map*
    /// rather than encode (including the `。` separators that would change the
    /// label count) are outside the allowed character class.
    private static func isValidLabel(_ label: String) -> Bool {
        guard !label.isEmpty, !label.hasPrefix("-"), !label.hasSuffix("-") else {
            return false
        }
        let allowed = CharacterSet.alphanumerics.union(
            CharacterSet(charactersIn: "-")
        )
        return label.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    private static func isASCIIDigit(_ byte: UInt8) -> Bool {
        (48...57).contains(byte)
    }

    /// Unlike `DomainValidator.asciiForm`, this rejects an over-long label here
    /// rather than in a separate character check, because it is the last gate
    /// before a name reaches the writers.
    private static func asciiForm(_ labels: [String]) -> [String]? {
        guard !DomainNameCoding.violatesIDNAContextRules(labels) else { return nil }
        var encoded: [String] = []
        encoded.reserveCapacity(labels.count)
        for label in labels {
            guard let ascii = DomainNameCoding.asciiLabel(label), ascii.utf8.count <= 63
            else {
                return nil
            }
            encoded.append(ascii)
        }
        return encoded
    }

}
