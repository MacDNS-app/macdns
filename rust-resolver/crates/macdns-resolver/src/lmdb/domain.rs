// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use super::{BlocklistError, Result};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainName {
    original: String,
}

impl DomainName {
    pub fn new(domain: &str) -> Result<Self> {
        let normalized = Self::normalize(domain)?;
        Ok(Self {
            original: normalized,
        })
    }

    pub fn normalize(domain: &str) -> Result<String> {
        let trimmed = domain.trim();
        if trimmed.is_empty() {
            return Err(BlocklistError::InvalidDomain("empty domain".to_string()));
        }

        // Strip the wildcard before IDN encoding so the `*` byte is never
        // encoded as a label.
        let (had_wildcard, body) = if let Some(rest) = trimmed.strip_prefix("*.") {
            (true, rest)
        } else if trimmed == "*" {
            return Err(BlocklistError::InvalidDomain("wildcard only".to_string()));
        } else {
            (false, trimmed)
        };
        if body.is_empty() {
            return Err(BlocklistError::InvalidDomain(
                "empty domain after wildcard removal".to_string(),
            ));
        }
        if body.contains("..") {
            return Err(BlocklistError::InvalidDomain(
                "consecutive dots".to_string(),
            ));
        }

        let body = body.trim_end_matches('.');
        if body.is_empty() {
            return Err(BlocklistError::InvalidDomain(
                "empty domain after normalization".to_string(),
            ));
        }
        if body.starts_with('.') || body.starts_with('-') {
            return Err(BlocklistError::InvalidDomain(
                "invalid start character".to_string(),
            ));
        }

        // The wildcard is not stored. `check_with_parents` matches every
        // subdomain of the stored name.
        let _ = had_wildcard;

        // RFC 5891: U-label input becomes an A-label (lowercase ASCII
        // punycode) so `münchen.de` matches the wire-form `xn--mnchen-3ya.de`
        // instead of silently missing.
        //
        // ASCII-only input is wire-form already and gets LDH validation only.
        // `domain_to_ascii_strict` would reject the deliberately confusable
        // A-labels that threat-intel feeds publish for blocking, such as
        // `cs--poligon.example` (CheckHyphens) or an `xn--…` label whose
        // Punycode body decodes to a disallowed code point (U+FEFF, U+200D).
        // Those names arrive on the wire exactly as written, so the resolver
        // must store and match them.
        let normalized = if body.is_ascii() {
            normalize_ascii_ldh(body)?
        } else {
            idna::domain_to_ascii_strict(body)
                .map_err(|e| BlocklistError::InvalidDomain(format!("idna: {}", e)))?
        };

        // RFC 1035 §2.3.4: a wire-format name is at most 255 octets, which
        // maps to ≤ 253 octets in presentation form (length prefixes + root
        // null take the remaining 2). Without this guard, parsers can insert
        // keys that no real query will ever match, wasting LMDB pages.
        if normalized.len() > 253 {
            return Err(BlocklistError::InvalidDomain(format!(
                "domain exceeds 253 octets: {}",
                normalized
            )));
        }

        Ok(normalized)
    }

    pub fn reverse(domain: &str) -> String {
        domain.split('.').rev().collect::<Vec<_>>().join(".")
    }

    pub fn as_reversed(&self) -> String {
        Self::reverse(&self.original)
    }

    pub fn as_original(&self) -> &str {
        &self.original
    }

    pub fn as_key_bytes(&self) -> Vec<u8> {
        Self::reverse(&self.original).into_bytes()
    }

    #[cfg(test)]
    pub fn is_subdomain_of(&self, parent: &DomainName) -> bool {
        let self_reversed = Self::reverse(&self.original);
        let parent_reversed = Self::reverse(&parent.original);
        if self_reversed.len() <= parent_reversed.len() {
            return false;
        }

        self_reversed.starts_with(&parent_reversed)
            && self_reversed.as_bytes()[parent_reversed.len()] == b'.'
    }

    pub fn labels(&self) -> Vec<&str> {
        self.original.split('.').collect()
    }

    #[cfg(test)]
    pub fn label_count(&self) -> usize {
        self.original.split('.').count()
    }
}

fn normalize_ascii_ldh(body: &str) -> Result<String> {
    let mut out = String::with_capacity(body.len());
    for label in body.split('.') {
        if label.is_empty() {
            return Err(BlocklistError::InvalidDomain("empty label".to_string()));
        }
        if label.len() > 63 {
            return Err(BlocklistError::InvalidDomain(format!(
                "label exceeds 63 octets: {}",
                label
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(BlocklistError::InvalidDomain(format!(
                "label starts or ends with hyphen: {}",
                label
            )));
        }
        for b in label.bytes() {
            if !(b.is_ascii_alphanumeric() || b == b'-') {
                return Err(BlocklistError::InvalidDomain(format!(
                    "label contains non-LDH byte 0x{:02x}: {}",
                    b, label
                )));
            }
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&label.to_ascii_lowercase());
    }
    Ok(out)
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.original)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize() {
        assert_eq!(
            DomainName::normalize("Example.COM.").unwrap(),
            "example.com"
        );
        assert_eq!(
            DomainName::normalize("  EXAMPLE.com  ").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn test_reverse() {
        assert_eq!(DomainName::reverse("www.example.com"), "com.example.www");
        assert_eq!(DomainName::reverse("com"), "com");
    }

    #[test]
    fn test_domain_name() {
        let domain = DomainName::new("www.example.com").unwrap();
        assert_eq!(domain.as_original(), "www.example.com");
        assert_eq!(domain.as_reversed(), "com.example.www");
    }

    #[test]
    fn test_subdomain_check() {
        let parent = DomainName::new("example.com").unwrap();
        let child = DomainName::new("www.example.com").unwrap();
        let other = DomainName::new("example.org").unwrap();

        assert!(child.is_subdomain_of(&parent));
        assert!(!parent.is_subdomain_of(&child));
        assert!(!other.is_subdomain_of(&parent));
    }

    #[test]
    fn test_invalid_domains() {
        assert!(DomainName::new("").is_err());
        assert!(DomainName::new("..").is_err());
        assert!(DomainName::new(".example.com").is_err());
        assert!(DomainName::new("-example.com").is_err());
    }

    #[test]
    fn test_label_count() {
        let domain = DomainName::new("www.example.com").unwrap();
        assert_eq!(domain.label_count(), 3);

        let labels = domain.labels();
        assert_eq!(labels, vec!["www", "example", "com"]);
    }

    #[test]
    fn test_wildcard_domains() {
        let domain = DomainName::new("*.example.com").unwrap();
        assert_eq!(domain.as_original(), "example.com");
        assert_eq!(domain.as_reversed(), "com.example");

        let domain2 = DomainName::new("*.ads.example.com").unwrap();
        assert_eq!(domain2.as_original(), "ads.example.com");
        assert_eq!(domain2.as_reversed(), "com.example.ads");
    }

    #[test]
    fn test_wildcard_only_invalid() {
        assert!(DomainName::new("*.").is_err());
        assert!(DomainName::new("*").is_err());
    }

    #[test]
    fn idn_input_is_punycode_encoded() {
        let domain = DomainName::new("münchen.de").unwrap();
        assert_eq!(domain.as_original(), "xn--mnchen-3ya.de");
    }

    #[test]
    fn idn_collides_with_explicit_punycode_form() {
        let from_unicode = DomainName::new("MÜNCHEN.DE").unwrap();
        let from_ascii = DomainName::new("xn--mnchen-3ya.de").unwrap();
        assert_eq!(from_unicode.as_key_bytes(), from_ascii.as_key_bytes());
    }

    #[test]
    fn ascii_double_hyphen_label_is_accepted() {
        // CheckHyphens (IDNA 2008) rejects "--" at positions 3-4 because it
        // could be confused with the ACE prefix. Hagezi's threat-intel feeds
        // intentionally publish such labels (e.g. `cs--poligon`), and they
        // must be blocked as written on the wire.
        let domain = DomainName::new("cs--poligon.orgs.biz").unwrap();
        assert_eq!(domain.as_original(), "cs--poligon.orgs.biz");
    }

    #[test]
    fn ascii_xn_label_with_disallowed_punycode_is_accepted() {
        // `xn--wxdget-hk68a` decodes to "U+FEFF wxdget", a zero-width
        // no-break space prefix. IDNA strict refuses to round-trip it,
        // but the malicious authority publishes the A-label as written,
        // so resolvers must be able to store and match it.
        let domain = DomainName::new("xn--wxdget-hk68a.aliyuncs.com").unwrap();
        assert_eq!(domain.as_original(), "xn--wxdget-hk68a.aliyuncs.com");

        // ZWJ-suffix variant, same reasoning.
        let domain = DomainName::new("xn--denizbankiadeleri-ny2j.ws").unwrap();
        assert_eq!(domain.as_original(), "xn--denizbankiadeleri-ny2j.ws");
    }

    #[test]
    fn ascii_underscore_label_is_rejected() {
        // `_` is not LDH and never appears in hagezi feeds, so it stays
        // rejected.
        assert!(DomainName::new("bad_domain.example").is_err());
    }

    #[test]
    fn ascii_label_too_long_is_rejected() {
        let long_label = "a".repeat(64);
        let domain = format!("{}.example", long_label);
        assert!(DomainName::new(&domain).is_err());
    }

    #[test]
    fn ascii_total_length_over_253_is_rejected() {
        // Four 63-char labels joined with dots = 4*63 + 3 = 255 octets,
        // which exceeds the 253-octet presentation-form ceiling.
        let label = "a".repeat(63);
        let domain = format!("{}.{}.{}.{}", label, label, label, label);
        assert!(DomainName::new(&domain).is_err());
    }

    #[test]
    fn ascii_total_length_at_253_is_accepted() {
        let l63 = "a".repeat(63);
        let l61 = "a".repeat(61);
        let domain = format!("{}.{}.{}.{}", l63, l63, l63, l61);
        assert_eq!(domain.len(), 253);
        assert!(DomainName::new(&domain).is_ok());
    }
}
