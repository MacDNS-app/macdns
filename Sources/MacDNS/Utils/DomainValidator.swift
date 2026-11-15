// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
import Network
import Shared

struct DomainValidator {
    enum ValidationError: Error {
        case message(String)

        var localizedDescription: String {
            switch self {
            case .message(let text):
                return text
            }
        }
    }

    // MARK: - Reserved TLDs

    /// TLDs reserved for local and testing use (RFC 2606, RFC 6761) plus common
    /// dev TLDs. Single-label wildcards (*.tld), and single-label names outside
    /// override owners, are allowed only for these TLDs. Must stay identical to
    /// `RESERVED_TLDS` in `rust-resolver/crates/macdns-resolver/src/domain_name.rs`.
    static let reservedTLDs: Set<String> = [
        // RFC 2606 - Reserved for testing
        "test", "example", "invalid", "localhost",
        // RFC 6761 / RFC 7686 - Special use
        "local", "onion",
        // Common development/internal TLDs
        "internal", "lan", "home", "corp", "localdomain", "intranet", "private",
        // Container/orchestration TLDs
        "docker", "k8s", "cluster", "svc", "pod",
    ]

    // MARK: - Main Validation

    /// A leading `*.` makes `domain` a wildcard.
    /// - Parameters:
    ///   - allowsSingleLabelHost: Accepts any exact single-label name such as
    ///     `server`. Only override owners allow it, mirroring
    ///     `DNSPolicyNameRole.overrideOwner`.
    static func validate(_ domain: String, allowsSingleLabelHost: Bool = false) -> Result<Void, ValidationError> {
        guard !domain.isEmpty else {
            return .failure(.message("Domain cannot be empty"))
        }

        if domain.hasPrefix("*.") {
            return validateWildcard(domain)
        } else {
            return validateNormal(domain, allowsSingleLabelHost: allowsSingleLabelHost)
        }
    }

    private static func validateNormal(_ domain: String, allowsSingleLabelHost: Bool) -> Result<Void, ValidationError> {
        let cleanDomain = domain.hasSuffix(".") ? String(domain.dropLast()) : domain

        // Empty labels are kept so "a..b.com", ".a.com" and "a.com.." are
        // rejected instead of silently collapsing into a valid name.
        let labels = cleanDomain.split(separator: ".", omittingEmptySubsequences: false).map(String.init)

        // Outside override owners a single label would capture a whole TLD,
        // so only reserved ones are accepted, the same rule the resolver applies.
        if labels.count == 1 && !allowsSingleLabelHost {
            guard reservedTLDs.contains(labels[0].lowercased()) else {
                return .failure(
                    .message(
                        "Single-label domains only allowed for: \(reservedTLDs.sorted().joined(separator: ", "))"
                    ))
            }
        }

        for (index, label) in labels.enumerated() {
            if let error = validateLabel(label, isTLD: index == labels.count - 1) {
                return .failure(error)
            }
        }

        guard let asciiLabels = asciiForm(labels) else {
            return .failure(.message("Domain cannot be encoded as IDNA ASCII"))
        }

        // 255 is a wire-format limit, so it applies to the encoded octets plus
        // each label-length octet and the root terminator.
        guard DomainNameCoding.wireLength(asciiLabels: asciiLabels) <= 255 else {
            return .failure(.message("Domain name too long (max 255 octets on the wire)"))
        }

        return .success(())
    }

    /// Single-label wildcards (*.test) are allowed only for reserved TLDs.
    /// Multi-label wildcards (*.example.com) are allowed for any domain.
    private static func validateWildcard(_ domain: String) -> Result<Void, ValidationError> {
        let baseDomain = String(domain.dropFirst(2))

        guard !baseDomain.isEmpty else {
            return .failure(.message("Wildcard domain cannot be empty after *."))
        }

        let cleanDomain = baseDomain.hasSuffix(".") ? String(baseDomain.dropLast()) : baseDomain

        let labels = cleanDomain.lowercased().split(separator: ".", omittingEmptySubsequences: false)
            .map(String.init)

        for (index, label) in labels.enumerated() {
            if let error = validateLabel(label, isTLD: index == labels.count - 1) {
                return .failure(error)
            }
        }

        guard let asciiLabels = asciiForm(labels) else {
            return .failure(.message("Domain cannot be encoded as IDNA ASCII"))
        }

        // The wildcard is a label of its own on the wire, so it costs two more
        // octets than the base name it was stripped from.
        guard DomainNameCoding.wireLength(asciiLabels: ["*"] + asciiLabels) <= 255 else {
            return .failure(.message("Domain name too long (max 255 octets on the wire)"))
        }

        // A wildcard such as *.com would match every name under the TLD.
        if labels.count == 1 {
            guard reservedTLDs.contains(labels[0]) else {
                return .failure(
                    .message(
                        "Wildcard '*.\(labels[0])' not allowed. Single-label wildcards only for: \(reservedTLDs.sorted().joined(separator: ", "))"
                    ))
            }
        }

        return .success(())
    }

    private static func validateLabel(_ label: String, isTLD: Bool) -> ValidationError? {
        guard !label.isEmpty else {
            return .message("Domain labels cannot be empty (no leading, trailing or repeated dots)")
        }

        guard !label.hasPrefix("-"), !label.hasSuffix("-") else {
            return .message("Domain labels cannot start or end with hyphen")
        }

        let allowedCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-"))
        guard label.unicodeScalars.allSatisfy({ allowedCharacters.contains($0) }) else {
            return .message("Domain contains invalid characters (only letters, numbers, and hyphens allowed)")
        }

        // 63 is a wire-format limit, so it applies to the IDNA ASCII form of
        // the label rather than to the Character count the user typed.
        guard let ascii = DomainNameCoding.asciiLabel(label) else {
            return .message("Domain label cannot be encoded as IDNA ASCII")
        }
        guard ascii.utf8.count <= 63 else {
            return .message("Each domain label must be 1-63 octets after IDNA encoding")
        }

        if isTLD, ascii.allSatisfy({ $0.isASCII && $0.isNumber }) {
            return .message("Top-level domain cannot be purely numeric")
        }

        return nil
    }

    // MARK: - IDNA Canonicalization

    /// Canonical wire form used for length limits and duplicate detection:
    /// trailing root dot removed, labels lowercased and IDN labels punycode
    /// encoded. Makes `münchen.de` and `xn--mnchen-3ya.de` collide in the UI
    /// exactly as they do in the resolver's policy snapshot.
    static func canonicalHost(_ domain: String) -> String? {
        let withoutRoot = domain.hasSuffix(".") ? String(domain.dropLast()) : domain
        let isWildcard = withoutRoot.hasPrefix("*.")
        let body = isWildcard ? String(withoutRoot.dropFirst(2)) : withoutRoot
        let labels = body.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard let asciiLabels = asciiForm(labels) else { return nil }
        let ascii = asciiLabels.joined(separator: ".")
        return isWildcard ? "*." + ascii : ascii
    }

    static func comparableDomain(_ domain: String) -> String {
        canonicalHost(domain) ?? domain.lowercased()
    }

    /// Per-label length is enforced by `validateLabel`'s character check on the
    /// way in, so this only applies the name-wide IDNA rules and encodes.
    private static func asciiForm(_ labels: [String]) -> [String]? {
        guard !DomainNameCoding.violatesIDNAContextRules(labels) else { return nil }
        var encoded: [String] = []
        encoded.reserveCapacity(labels.count)
        for label in labels {
            guard let ascii = DomainNameCoding.asciiLabel(label) else { return nil }
            encoded.append(ascii)
        }
        return encoded
    }

    // MARK: - Convenience Methods

    static func isValid(_ domain: String, allowsSingleLabelHost: Bool = false) -> Bool {
        switch validate(domain, allowsSingleLabelHost: allowsSingleLabelHost) {
        case .success:
            return true
        case .failure:
            return false
        }
    }

    // MARK: - IP Address Validation

    static func validateIPv4(_ ip: String) -> Result<Void, ValidationError> {
        // Exactly 4 octets. BSD accepts 120.0.2 as 120.0.0.2, MacDNS does not.
        let parts = ip.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else {
            return .failure(.message("IPv4 must have 4 octets (e.g., 192.168.1.1)"))
        }
        guard IPv4Address(ip) != nil else {
            return .failure(.message("Invalid IPv4 address"))
        }
        return .success(())
    }

    static func validateIPv6(_ ip: String) -> Result<Void, ValidationError> {
        // Zone IDs (%interface) are not valid in DNS records.
        guard !ip.contains("%") else {
            return .failure(.message("IPv6 zone IDs (%interface) not allowed for DNS"))
        }
        guard IPv6Address(ip) != nil else {
            return .failure(.message("Invalid IPv6 address"))
        }
        return .success(())
    }

    /// Validates an IP address usable as a DNS forward target (IPv4 or IPv6).
    /// The unusable-target classification comes from the Shared parser, which
    /// mirrors `zones::validate_forward_target` in the Rust resolver: an
    /// unspecified, IPv4 broadcast or multicast address can never answer a
    /// query and would black-hole the routed namespace until the forward
    /// timeout. Loopback and host-owned addresses stay valid, because a local
    /// resolver may legitimately listen on port 53.
    static func validateIP(_ ip: String) -> Result<Void, ValidationError> {
        guard !ip.isEmpty else {
            return .failure(.message("IP address cannot be empty"))
        }
        if !ip.contains(":") {
            if case .failure(let error) = validateIPv4(ip) {
                return .failure(error)
            }
        } else if IPv6Address(ip) == nil {
            return .failure(.message("Invalid IP address"))
        }
        guard let kind = DNSResolverAddressParser.unusableForwardTargetKind(ip) else {
            return .success(())
        }
        return .failure(.message("Forward target cannot be a \(kind) address"))
    }

    @discardableResult
    static func validateIPWithErrorBinding(_ ip: String, errorBinding: inout String?) -> Bool {
        guard !ip.isEmpty else {
            errorBinding = nil
            return false
        }
        switch validateIP(ip) {
        case .success:
            errorBinding = nil
            return true
        case .failure(let error):
            errorBinding = error.localizedDescription
            return false
        }
    }

    // MARK: - DNS Override Value Validation

    static func validateOverrideValue(_ value: String, forType qtype: String) -> Result<Void, ValidationError> {
        guard !value.isEmpty else {
            return .failure(.message("Value cannot be empty"))
        }

        switch qtype {
        case "A":
            return validateIPv4(value)

        case "AAAA":
            return validateIPv6(value)

        case "CNAME", "NS", "PTR":
            return validateHostname(value)

        case "MX":
            // MX is a hostname or "priority hostname".
            let parts = value.split(separator: " ", maxSplits: 1)
            let hostname = parts.count == 2 ? String(parts[1]) : value
            if parts.count == 2 {
                guard let priority = Int(parts[0]), priority >= 0, priority <= 65535 else {
                    return .failure(.message("MX priority must be 0-65535"))
                }
            }
            return validateHostname(hostname)

        case "TXT":
            // Reject characters that would corrupt the TXT record payload
            let forbidden: [(Character, String)] = [
                ("\"", "quotes"),
                ("\\", "backslashes"),
                ("\n", "newlines"),
                ("\r", "carriage returns"),
            ]
            for (char, name) in forbidden where value.contains(char) {
                return .failure(.message("TXT value cannot contain \(name)"))
            }
            // One TXT character-string holds at most 255 octets.
            guard value.utf8.count <= 255 else {
                return .failure(.message("TXT value too long (max 255 UTF-8 bytes)"))
            }
            return .success(())

        default:
            return .success(())
        }
    }

    /// Validates a hostname for use in DNS records (CNAME, MX, NS, PTR).
    ///
    /// Delegates to the Shared gate the agent's save path uses, so the UI can
    /// neither accept a target the writers reject nor reject one they accept.
    private static func validateHostname(_ hostname: String) -> Result<Void, ValidationError> {
        guard let rejection = DNSPolicySemanticPolicy.targetNameRejection(hostname) else {
            return .success(())
        }
        return .failure(.message(rejection.reason))
    }

    @discardableResult
    static func validateOverrideValueWithErrorBinding(
        _ value: String,
        forType qtype: String,
        errorBinding: inout String?
    ) -> Bool {
        guard !value.isEmpty else {
            errorBinding = nil
            return false
        }
        switch validateOverrideValue(value, forType: qtype) {
        case .success:
            errorBinding = nil
            return true
        case .failure(let error):
            errorBinding = error.localizedDescription
            return false
        }
    }

    // MARK: - SwiftUI Binding Helpers

    @discardableResult
    static func validateWithErrorBinding(
        _ domain: String,
        allowsSingleLabelHost: Bool = false,
        errorBinding: inout String?
    ) -> Bool {
        guard !domain.isEmpty else {
            errorBinding = nil
            return false
        }

        switch validate(domain, allowsSingleLabelHost: allowsSingleLabelHost) {
        case .success:
            errorBinding = nil
            return true
        case .failure(let error):
            errorBinding = error.localizedDescription
            return false
        }
    }

    // MARK: - Public TLD Collision Warning

    /// Non-blocking warning for an exact single-label override owner that is
    /// also a delegated public TLD. The resolver answers such an owner only for
    /// the bare name, so names under the TLD keep resolving.
    static func publicTLDWarning(forOverrideDomain domain: String) -> String? {
        guard let label = canonicalHost(domain), !label.contains("."),
            PublicTopLevelDomains.all.contains(label)
        else { return nil }
        return
            "\"\(label)\" is also a public top-level domain. Only the bare name \(label) is overridden. Sites under .\(label) keep resolving."
    }

    // MARK: - CNAME Exclusivity Validation

    /// Validates duplicates, CNAME exclusivity and wildcard/specific conflicts:
    /// - The same name/type pair cannot be configured twice. The resolver
    ///   rejects the whole policy snapshot on a duplicate.
    /// - CNAME cannot coexist with other record types for the same name.
    /// - A wildcard cannot coexist with a specific override for the same base
    ///   domain. The wildcard matches every subdomain, so the pair is ambiguous.
    ///
    /// Names are compared in canonical IDNA form, so `münchen.de` and
    /// `xn--mnchen-3ya.de` collide here instead of only inside the resolver.
    static func validateCNAMEExclusivity(
        domain: String,
        qtype: String,
        existingOverrides: [DNSOverride],
        excludeId: UUID? = nil
    ) -> String? {
        let normalizedDomain = comparableDomain(domain)
        let isWildcard = normalizedDomain.hasPrefix("*.")
        let baseDomain = isWildcard ? String(normalizedDomain.dropFirst(2)) : normalizedDomain

        let existingForDomain = existingOverrides.filter {
            comparableDomain($0.domain) == normalizedDomain && $0.enabled && $0.id != excludeId
        }

        if !existingForDomain.isEmpty {
            if let duplicate = existingForDomain.first(where: { $0.qtype == qtype }) {
                return "Cannot add \(qtype): '\(duplicate.domain)' already has a \(qtype) override"
            }

            let hasCNAME = existingForDomain.contains { $0.qtype == "CNAME" }
            let hasOtherTypes = existingForDomain.contains { $0.qtype != "CNAME" }

            if qtype == "CNAME" && hasOtherTypes {
                let types = existingForDomain.filter { $0.qtype != "CNAME" }.map { $0.qtype }
                let uniqueTypes = Array(Set(types)).sorted().joined(separator: ", ")
                return "CNAME cannot coexist with \(uniqueTypes) records"
            }

            if qtype != "CNAME" && hasCNAME {
                return "Cannot add \(qtype): CNAME already exists for this domain"
            }
        }

        if isWildcard {
            // Adding *.test conflicts with test, a.test and b.c.test.
            let conflictingOverride = existingOverrides.first {
                guard $0.enabled && $0.id != excludeId && !$0.isWildcard else { return false }
                let otherDomain = comparableDomain($0.domain)
                return otherDomain == baseDomain || otherDomain.hasSuffix("." + baseDomain)
            }
            if let conflict = conflictingOverride {
                return "Cannot add wildcard: override for '\(conflict.domain)' already exists"
            }
        } else {
            // Adding a.b.test conflicts with *.a.b.test, *.b.test and *.test.
            let domainParts = normalizedDomain.split(separator: ".").map(String.init)
            for i in 0..<domainParts.count {
                let parentDomain = domainParts[i...].joined(separator: ".")
                let wildcardDomain = "*." + parentDomain
                let wildcardExists = existingOverrides.first {
                    comparableDomain($0.domain) == wildcardDomain && $0.enabled && $0.id != excludeId
                }
                if wildcardExists != nil {
                    return "Cannot add override: wildcard '*.\(parentDomain)' already exists"
                }
            }
        }

        return nil
    }
}
