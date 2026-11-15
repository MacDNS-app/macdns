// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use dashmap::DashMap;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use crate::domain_name::{canonicalize, canonicalize_lookup, NameRole};

/// One entry in the zone table. `is_stub` distinguishes a stub zone
/// (authoritative-only, RD=0 on the wire per RFC 5625) from a forward
/// zone (recursive). Hickory honours `ResolverOpts::recursion_desired`, so
/// stub zones build their own resolver with the bit cleared while forward
/// zones keep the default RD=1.
#[derive(Clone)]
pub struct ZoneEntry {
    pub resolver: Arc<TokioResolver>,
    pub is_stub: bool,
    pub forward_ip: IpAddr,
}

pub struct ForwardZones {
    zones: DashMap<String, ZoneEntry>,
}

impl ForwardZones {
    pub fn new() -> Self {
        Self {
            zones: DashMap::new(),
        }
    }

    pub fn upsert(&self, apex: &str, forward_ip: &str) -> Result<(), String> {
        self.upsert_inner(apex, forward_ip, false)
    }

    /// Registers a forward zone over a resolver the test built, so it can
    /// target a local server on any port.
    #[cfg(test)]
    pub(crate) fn upsert_for_test(&self, apex: &str, resolver: TokioResolver) {
        let apex = canonicalize(apex, NameRole::ForwardZone).unwrap();
        self.zones.insert(
            apex,
            ZoneEntry {
                resolver: Arc::new(resolver),
                is_stub: false,
                forward_ip: IpAddr::from([127, 0, 0, 1]),
            },
        );
    }

    /// Registers a stub zone with RD=0. Uses the same transport as `upsert`,
    /// whose forward-zone resolver sends RD=1.
    pub fn upsert_stub(&self, apex: &str, forward_ip: &str) -> Result<(), String> {
        self.upsert_inner(apex, forward_ip, true)
    }

    fn upsert_inner(&self, apex: &str, forward_ip: &str, is_stub: bool) -> Result<(), String> {
        let ip = IpAddr::from_str(forward_ip).map_err(|e| e.to_string())?;
        validate_forward_target(ip)?;
        let resolver = build_zone_resolver(ip, is_stub)?;
        let apex = canonicalize(apex, NameRole::ForwardZone)?;
        self.zones.insert(
            apex,
            ZoneEntry {
                resolver: Arc::new(resolver),
                is_stub,
                forward_ip: ip,
            },
        );
        Ok(())
    }

    pub fn snapshot_copy(&self) -> Self {
        let copy = Self::new();
        for entry in self.zones.iter() {
            copy.zones
                .insert(entry.key().clone(), entry.value().clone());
        }
        copy
    }

    /// Builds fresh resolver state without mutating a pinned policy snapshot.
    pub fn rebuilt_copy(&self) -> (Self, usize) {
        let copy = Self::new();
        let mut rebuilt = 0usize;
        for entry in self.zones.iter() {
            let mut next = entry.value().clone();
            match build_zone_resolver(entry.forward_ip, entry.is_stub) {
                Ok(r) => {
                    next.resolver = Arc::new(r);
                    rebuilt += 1;
                }
                Err(e) => log::warn!("zone rebuild for {}: {}", entry.key(), e),
            }
            copy.zones.insert(entry.key().clone(), next);
        }
        (copy, rebuilt)
    }

    pub fn remove(&self, apex: &str) {
        if let Ok(apex) = canonicalize(apex, NameRole::ForwardZone) {
            self.zones.remove(&apex);
        }
    }

    pub fn entry_for(&self, domain: &str) -> Option<ZoneEntry> {
        self.entry_with_apex_for(domain).map(|(_, entry)| entry)
    }

    /// Same longest-suffix walk as `entry_for`, but also returns the matched
    /// apex. The query pipeline needs it to compare zone specificity against
    /// a matched override apex, so a `corp.example.com` forward zone keeps
    /// serving `db.corp.example.com` even when an `example.com` override
    /// exists.
    pub fn entry_with_apex_for(&self, domain: &str) -> Option<(String, ZoneEntry)> {
        let d = normalize(domain);
        if let Some(r) = self.zones.get(&d) {
            return Some((d, r.clone()));
        }
        let mut rest = d.as_str();
        while let Some(dot) = rest.find('.') {
            let parent = &rest[dot + 1..];
            if parent.is_empty() {
                break;
            }
            if let Some(r) = self.zones.get(parent) {
                return Some((parent.to_string(), r.clone()));
            }
            rest = parent;
        }
        None
    }

    pub fn clear(&self) {
        self.zones.clear();
    }
}

impl Default for ForwardZones {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize(d: &str) -> String {
    canonicalize_lookup(d)
}

/// Rejects addresses that can never answer a DNS query, so a routed namespace
/// is not black-holed until `FORWARD_LOOKUP_TIMEOUT` expires. Loopback and
/// host-owned addresses stay valid because a local resolver may legitimately
/// listen on port 53. Shared with `forward.rs` so captive and global
/// forwarding apply the same rule as zones. Mirrored by
/// `DNSResolverAddressParser` in the App.
pub(crate) fn validate_forward_target(ip: IpAddr) -> Result<(), String> {
    let kind = match ip {
        IpAddr::V4(v4) if v4.is_unspecified() => Some("unspecified"),
        IpAddr::V4(v4) if v4.is_broadcast() => Some("broadcast"),
        IpAddr::V4(v4) if v4.is_multicast() => Some("multicast"),
        IpAddr::V6(v6) if v6.is_unspecified() => Some("unspecified"),
        IpAddr::V6(v6) if v6.is_multicast() => Some("multicast"),
        _ => None,
    };
    match kind {
        Some(kind) => Err(format!("forward target {ip} is a {kind} address")),
        None => Ok(()),
    }
}

fn build_zone_opts(is_stub: bool) -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    // Forward/stub zones usually target private authorities. Validating their
    // unsigned split-DNS negatives causes bogus SERVFAILs; public DoH remains
    // the DNSSEC validation path.
    opts.validate = false;
    // The resolver owns the DNS cache, so hickory's internal one stays off.
    opts.cache_size = 0;
    opts.case_randomization = false;
    opts.recursion_desired = !is_stub;
    opts
}

fn build_zone_resolver(ip: IpAddr, is_stub: bool) -> Result<TokioResolver, String> {
    let cfg = ResolverConfig::from_parts(None, vec![], vec![NameServerConfig::udp_and_tcp(ip)]);
    TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default())
        .with_options(build_zone_opts(is_stub))
        .build()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_zone_resolver_built_with_rd_off() {
        let opts = build_zone_opts(true);
        assert!(!opts.recursion_desired, "stub zone must build with RD=0");
        let opts = build_zone_opts(false);
        assert!(opts.recursion_desired, "forward zone must keep RD=1");
    }

    #[test]
    fn zone_resolvers_do_not_validate_split_dns() {
        let opts = crate::config::ResolverOptions {
            dnssec: true,
            ..Default::default()
        };
        crate::config::set(opts);
        assert!(!build_zone_opts(false).validate);
        assert!(!build_zone_opts(true).validate);
        crate::config::set(crate::config::ResolverOptions::default());
    }

    #[test]
    fn matches_exact_and_subdomain() {
        let z = ForwardZones::new();
        z.upsert("internal.corp", "10.0.0.1").unwrap();
        assert!(z.entry_for("internal.corp").is_some());
        assert!(z.entry_for("host.internal.corp").is_some());
        assert!(z.entry_for("external.example.com").is_none());
    }

    #[test]
    fn idn_zone_matches_wire_ascii_name() {
        let z = ForwardZones::new();
        z.upsert("münchen.de", "10.0.0.1").unwrap();

        assert!(z.entry_for("host.xn--mnchen-3ya.de").is_some());
    }

    #[test]
    fn idn_zone_can_be_removed_with_original_unicode_name() {
        let z = ForwardZones::new();
        z.upsert("münchen.de", "10.0.0.1").unwrap();

        z.remove("münchen.de");

        assert!(z.entry_for("host.xn--mnchen-3ya.de").is_none());
    }

    #[test]
    fn entry_with_apex_reports_the_longest_matched_suffix() {
        let z = ForwardZones::new();
        z.upsert("example.com", "10.0.0.1").unwrap();
        z.upsert("corp.example.com", "10.0.0.2").unwrap();

        let (apex, entry) = z.entry_with_apex_for("db.corp.example.com").unwrap();
        assert_eq!(apex, "corp.example.com");
        assert_eq!(entry.forward_ip.to_string(), "10.0.0.2");

        let (apex, entry) = z.entry_with_apex_for("www.example.com").unwrap();
        assert_eq!(apex, "example.com");
        assert_eq!(entry.forward_ip.to_string(), "10.0.0.1");

        assert!(z.entry_with_apex_for("example.net").is_none());
    }

    #[test]
    fn remove_zone() {
        let z = ForwardZones::new();
        z.upsert("internal.corp", "10.0.0.1").unwrap();
        z.remove("internal.corp");
        assert!(z.entry_for("internal.corp").is_none());
    }

    #[test]
    fn invalid_ip_rejected() {
        let z = ForwardZones::new();
        assert!(z.upsert("internal.corp", "not-an-ip").is_err());
    }

    #[test]
    fn unusable_forward_targets_rejected() {
        let z = ForwardZones::new();
        for ip in [
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.251",
            "::",
            "ff02::fb",
        ] {
            assert!(
                z.upsert("internal.corp", ip).is_err(),
                "{ip} must not be accepted as a forward target"
            );
            assert!(
                z.upsert_stub("internal.corp", ip).is_err(),
                "{ip} must not be accepted as a stub target"
            );
        }
        assert!(z.entry_for("internal.corp").is_none());
    }

    #[test]
    fn loopback_and_host_owned_forward_targets_accepted() {
        let z = ForwardZones::new();
        assert!(z.upsert("internal.corp", "127.0.0.1").is_ok());
        assert!(z.upsert("v6.corp", "::1").is_ok());
        assert!(z.upsert("host.corp", "10.0.0.1").is_ok());
    }

    #[test]
    fn rebuilt_copy_swaps_resolvers_preserving_mapping() {
        let z = ForwardZones::new();
        z.upsert("internal.corp", "10.0.0.1").unwrap();
        z.upsert_stub("stub.corp", "10.0.0.2").unwrap();

        let before_internal = Arc::as_ptr(&z.entry_for("internal.corp").unwrap().resolver) as usize;
        let before_stub = Arc::as_ptr(&z.entry_for("stub.corp").unwrap().resolver) as usize;

        let (rebuilt_zones, rebuilt) = z.rebuilt_copy();
        assert_eq!(rebuilt, 2);

        let after_internal_entry = rebuilt_zones.entry_for("internal.corp").unwrap();
        let after_stub_entry = rebuilt_zones.entry_for("stub.corp").unwrap();

        assert_ne!(
            before_internal,
            Arc::as_ptr(&after_internal_entry.resolver) as usize
        );
        assert_ne!(
            before_stub,
            Arc::as_ptr(&after_stub_entry.resolver) as usize
        );
        assert!(!after_internal_entry.is_stub);
        assert!(after_stub_entry.is_stub);
        assert_eq!(after_internal_entry.forward_ip.to_string(), "10.0.0.1");
        assert_eq!(after_stub_entry.forward_ip.to_string(), "10.0.0.2");
    }
}
