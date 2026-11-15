// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

/// TLDs reserved for local, testing and internal use. A single-label forward
/// zone or wildcard base is only accepted for one of these, so neither can
/// capture an entire public TLD. Must stay identical to
/// `DomainValidator.reservedTLDs` in `Sources/MacDNS/Utils/DomainValidator.swift`.
const RESERVED_TLDS: &[&str] = &[
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
];

/// Where a validated name is used. The role decides whether a wildcard is
/// accepted and whether a bare single label may be any host name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameRole {
    /// Override owner. Wildcards are accepted, and so is any single-label
    /// host such as `server`, because an exact single-label owner only ever
    /// answers for itself (see `claims_subnames`).
    OverrideOwner,
    /// Forward-zone apex. A zone routes every name under it, so a single
    /// label is limited to a reserved TLD.
    ForwardZone,
}

pub(crate) fn is_reserved_tld(label: &str) -> bool {
    RESERVED_TLDS.contains(&label)
}

/// True when an exact override at `apex` also claims the names under it. A
/// single label that is not a reserved TLD may be a delegated public TLD, so
/// claiming its subnames would answer NXDOMAIN for that whole TLD.
pub(crate) fn claims_subnames(apex: &str) -> bool {
    apex.contains('.') || is_reserved_tld(apex)
}

pub(crate) fn canonicalize(input: &str, role: NameRole) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("domain is empty".into());
    }
    if trimmed.ends_with("..") {
        return Err("domain has consecutive dots".into());
    }

    let without_root = trimmed.strip_suffix('.').unwrap_or(trimmed);
    let (prefix, body) = if let Some(body) = without_root.strip_prefix("*.") {
        if role != NameRole::OverrideOwner {
            return Err("wildcard is not allowed".into());
        }
        ("*.", body)
    } else {
        ("", without_root)
    };

    if body.is_empty() || body.contains('*') || body.contains("..") {
        return Err("invalid domain".into());
    }

    let ascii = if body.is_ascii() {
        for label in body.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err("invalid ASCII domain".into());
            }
        }
        body.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii_strict(body)
            .map_err(|error| format!("invalid IDN domain: {error}"))?
            .to_ascii_lowercase()
    };

    // IDNA maps U+3002 / U+FF0E / U+FF61 onto '.', which would turn a single
    // mistyped label into a multi-label name. The App rejects those code
    // points outright, so a changed separator count is rejected here too.
    let labels: Vec<&str> = ascii.split('.').collect();
    if labels.len() != body.split('.').count() {
        return Err("domain contains a non-ASCII label separator".into());
    }

    // One length octet per label plus the root terminator, the accounting
    // hickory's `Name::extend_name` applies before enforcing `MAX_LENGTH`.
    // `*` is a label of its own, so a wildcard owner spends two more octets
    // than the base name it was stripped from.
    let wildcard_octets = if prefix.is_empty() { 0 } else { 2 };
    let wire_len: usize =
        labels.iter().map(|label| label.len() + 1).sum::<usize>() + 1 + wildcard_octets;
    if wire_len > 255 {
        return Err("domain exceeds 255 octets on the wire".into());
    }

    let tld = labels[labels.len() - 1];
    if !tld.is_empty() && tld.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("top-level domain cannot be purely numeric".into());
    }
    let single_label_host = prefix.is_empty() && role == NameRole::OverrideOwner;
    if labels.len() == 1 && !single_label_host && !is_reserved_tld(tld) {
        return Err(format!(
            "single-label domain {tld:?} is only allowed for a reserved TLD"
        ));
    }

    let canonical = format!("{prefix}{ascii}");
    Ok(canonical)
}

pub(crate) fn canonicalize_lookup(input: &str) -> String {
    input.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_labels_are_rejected() {
        assert!(canonicalize("a..b.com", NameRole::ForwardZone).is_err());
        assert!(canonicalize(".a.com", NameRole::ForwardZone).is_err());
        assert!(canonicalize("a.com..", NameRole::ForwardZone).is_err());
    }

    #[test]
    fn idn_label_over_63_ascii_octets_is_rejected() {
        // 30 spread-out CJK code points stay under the 63-character limit a
        // per-character check would apply, but their punycode form is longer
        // than 63 octets.
        let label: String = (0..30u32)
            .filter_map(|i| char::from_u32(0x4e00 + i * 0x40))
            .collect();
        assert_eq!(label.chars().count(), 30);
        assert!(canonicalize(&format!("{label}.de"), NameRole::ForwardZone).is_err());

        // A shorter label of the same shape stays valid.
        let short: String = (0..20u32)
            .filter_map(|i| char::from_u32(0x4e00 + i * 0x40))
            .collect();
        assert!(canonicalize(&format!("{short}.de"), NameRole::ForwardZone).is_ok());
    }

    #[test]
    fn idn_and_punycode_share_one_canonical_form() {
        assert_eq!(
            canonicalize("münchen.de", NameRole::ForwardZone).unwrap(),
            canonicalize("xn--mnchen-3ya.de", NameRole::ForwardZone).unwrap()
        );
    }

    #[test]
    fn single_label_zone_is_limited_to_reserved_tlds() {
        assert_eq!(
            canonicalize("intranet", NameRole::ForwardZone).unwrap(),
            "intranet"
        );
        assert!(canonicalize("com", NameRole::ForwardZone).is_err());
        assert!(
            canonicalize("box", NameRole::ForwardZone).is_err(),
            "box is a delegated public TLD"
        );
    }

    #[test]
    fn single_label_override_owner_accepts_any_host() {
        assert_eq!(
            canonicalize("Server", NameRole::OverrideOwner).unwrap(),
            "server"
        );
        assert_eq!(
            canonicalize("test", NameRole::OverrideOwner).unwrap(),
            "test"
        );
        assert!(canonicalize("123", NameRole::OverrideOwner).is_err());
    }

    #[test]
    fn only_multi_label_or_reserved_apexes_claim_subnames() {
        assert!(claims_subnames("example.com"));
        assert!(claims_subnames("test"));
        assert!(!claims_subnames("server"));
        assert!(!claims_subnames("dev"));
        assert!(!claims_subnames("box"));
    }

    #[test]
    fn single_label_wildcard_is_limited_to_reserved_tlds() {
        assert_eq!(
            canonicalize("*.test", NameRole::OverrideOwner).unwrap(),
            "*.test"
        );
        assert!(canonicalize("*.com", NameRole::OverrideOwner).is_err());
        assert_eq!(
            canonicalize("*.example.com", NameRole::OverrideOwner).unwrap(),
            "*.example.com",
            "multi-label wildcards stay valid"
        );
    }

    #[test]
    fn purely_numeric_tld_is_rejected() {
        assert!(canonicalize("example.123", NameRole::ForwardZone).is_err());
        assert_eq!(
            canonicalize("123.example.com", NameRole::ForwardZone).unwrap(),
            "123.example.com"
        );
    }

    #[test]
    fn non_ascii_label_separator_is_rejected() {
        assert!(canonicalize("example。com", NameRole::ForwardZone).is_err());
    }
}

/// Rust half of the cross-language conformance vectors in
/// `Tests/Fixtures/domain-name-conformance.json`. The Swift half is
/// `Tests/MacDNSTests/DomainNameConformanceTests.swift` and reads the same
/// file, so a name that passes in one language and fails in the other breaks a
/// named test.
#[cfg(test)]
mod conformance {
    use super::*;
    use std::str::FromStr;

    const FIXTURES: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../Tests/Fixtures/domain-name-conformance.json"
    );

    fn vectors() -> serde_json::Value {
        let text = std::fs::read_to_string(FIXTURES)
            .unwrap_or_else(|e| panic!("cross-language fixtures at {FIXTURES}: {e}"));
        serde_json::from_str(&text).expect("cross-language fixtures must be valid JSON")
    }

    #[test]
    fn owner_vectors_match_canonicalize() {
        for case in vectors()["owners"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let role = match case["role"].as_str().unwrap() {
                "override" => NameRole::OverrideOwner,
                "forwardZone" => NameRole::ForwardZone,
                other => panic!("unknown role {other:?} for {input}"),
            };
            let accepted = case["rust"]["accept"].as_bool().unwrap();

            match canonicalize(input, role) {
                Ok(canonical) => {
                    assert!(accepted, "{input} must be rejected");
                    assert_eq!(
                        canonical,
                        case["rust"]["canonical"].as_str().unwrap(),
                        "canonical form for {input}"
                    );
                }
                Err(e) => assert!(!accepted, "{input} must be accepted: {e}"),
            }
        }
    }

    /// RDATA targets never reach `canonicalize`. `parse_override` hands them
    /// straight to hickory, so hickory is the reference the App must match.
    #[test]
    fn target_vectors_match_hickory_name_parsing() {
        for case in vectors()["targets"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            assert_eq!(
                hickory_proto::rr::Name::from_str(input).is_ok(),
                case["rust"]["accept"].as_bool().unwrap(),
                "RDATA target {input}"
            );
        }
    }

    #[test]
    fn forward_target_vectors_match_zone_validation() {
        for case in vectors()["forwardTargets"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let is_address = case["isAddress"].as_bool().unwrap();

            let Ok(ip) = std::net::IpAddr::from_str(input) else {
                assert!(!is_address, "{input} must parse as an address");
                continue;
            };
            assert!(is_address, "{input} must not parse as an address");
            assert_eq!(
                crate::zones::validate_forward_target(ip).is_ok(),
                case["usable"].as_bool().unwrap(),
                "forward target {input}"
            );
        }
    }

    /// Swift is allowed to be stricter than the resolver: a name the App
    /// refuses never reaches `state.json`. The reverse is the outage this
    /// fixture exists for. A name the App accepts and the resolver rejects
    /// fails the entire policy snapshot and can keep DNS from starting.
    #[test]
    fn swift_column_is_never_more_permissive_than_rust() {
        let vectors = vectors();
        for group in ["owners", "targets"] {
            for case in vectors[group].as_array().unwrap() {
                if !case["swift"]["accept"].as_bool().unwrap() {
                    continue;
                }
                let input = case["input"].as_str().unwrap();
                assert!(
                    case["rust"]["accept"].as_bool().unwrap(),
                    "{input} is accepted by Swift only"
                );
                assert_eq!(
                    case["swift"]["canonical"], case["rust"]["canonical"],
                    "canonical columns disagree for {input}"
                );
            }
        }
    }
}
