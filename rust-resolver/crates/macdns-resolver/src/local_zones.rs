// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use std::collections::HashSet;

/// Built-in zones: the special-use names this resolver answers itself
/// instead of sending them to a public recursive resolver.
///
/// RFC 6303 §3 empty zones hold only their own SOA and NS, with NXDOMAIN below
/// the apex. `resolver.arpa` instead returns NODATA throughout (RFC 9462).
/// The query pipeline builds responses, while this module owns the tables
/// and the "which zone claims this name" walk.
///
/// The tables are seeded once at construction and are immutable afterwards.
/// They are protocol invariants, not user state, so they never travel through
/// `state.json` or the `ArcSwap` policy snapshot.
pub struct LocalZones {
    /// Built-in names that must not resolve through a captive-portal
    /// resolver either: `.onion` (RFC 7686, never DNS-resolvable) and the
    /// RFC 1918 reverse zones. Evaluated ahead of blanket captive
    /// forwarding in the query pipeline.
    built_in_captive_protected: HashSet<String>,
    /// RFC 6303 / RFC 6761 / RFC 6762 / RFC 9462 special-use names that must never
    /// leak to a public recursive resolver but do yield to captive
    /// forwarding. `.local` and the router-handed search domains are the
    /// names hotspot portals rely on.
    built_in: HashSet<String>,
}

impl LocalZones {
    pub fn new() -> Self {
        let mut built_in_captive_protected = HashSet::new();
        let mut built_in = HashSet::new();
        seed_built_in_zones(&mut built_in_captive_protected, &mut built_in);
        Self {
            built_in_captive_protected,
            built_in,
        }
    }

    /// Walks the domain upward through the captive-protected built-in
    /// subset only. Called after explicit user forward/stub routes but before
    /// blanket captive forwarding. `.onion` and RFC 1918 reverses never
    /// legitimately resolve through a hotspot, so handing them to the portal
    /// resolver would leak private names for no compatibility gain.
    pub fn lookup_built_in_protected(&self, domain: &str) -> Option<&str> {
        Self::lookup_in(&self.built_in_captive_protected, domain)
    }

    /// Walks the domain upward through the full built-in special-use
    /// table (protected subset included). Called as a last-resort policy
    /// after forward/stub and captive resolution so user routing and portal
    /// compatibility for the same suffix take precedence. When nothing else
    /// handled the query, the built-in zone answers it and the public hedge
    /// never sees the name.
    pub fn lookup_built_in(&self, domain: &str) -> Option<&str> {
        Self::lookup_in(&self.built_in_captive_protected, domain)
            .or_else(|| Self::lookup_in(&self.built_in, domain))
    }

    /// Apex of the zone that claims `domain`, or `None` when the table owns
    /// neither the name nor any of its ancestors. Returning the apex rather
    /// than a bare boolean is what lets the caller tell an apex query from a
    /// below-apex one and put the right owner on the synthesised SOA.
    fn lookup_in<'a>(table: &'a HashSet<String>, domain: &str) -> Option<&'a str> {
        let d = normalize(domain);
        if let Some(apex) = table.get(d.as_str()) {
            return Some(apex.as_str());
        }
        let mut rest = d.as_str();
        while let Some(dot) = rest.find('.') {
            let parent = &rest[dot + 1..];
            if parent.is_empty() {
                break;
            }
            if let Some(apex) = table.get(parent) {
                return Some(apex.as_str());
            }
            rest = parent;
        }
        None
    }
}

impl Default for LocalZones {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize(d: &str) -> String {
    d.trim_end_matches('.').to_lowercase()
}

/// Private-use suffixes a DHCP-discovered search domain may claim an ephemeral
/// forward route for.
///
/// Deliberately narrower than the built-in table: `local` belongs to mDNS,
/// `test`/`invalid`/`example` are documentation names, and the reverse zones
/// plus `.onion` are captive-protected. Restricting the set is what stops a
/// hostile hotspot from handing out a search domain that would capture a
/// public namespace.
const EPHEMERAL_ROUTE_SUFFIXES: &[&str] = &[
    "home.arpa",
    "internal",
    "intranet",
    "lan",
    "corp",
    "private",
];

/// True when `apex` is at or under a private-use suffix that may carry an
/// auto-published route. DHCP is unauthenticated, so this is the only gate
/// between a hotspot's search-domain list and the resolver's route table.
pub fn is_publishable_ephemeral_route(apex: &str) -> bool {
    let apex = normalize(apex);
    EPHEMERAL_ROUTE_SUFFIXES
        .iter()
        .any(|suffix| apex == *suffix || apex.ends_with(&format!(".{suffix}")))
}

/// Special-use DNS names that must never reach a public recursive
/// resolver. Sources:
///
/// * RFC 6761 §6.4/6.2: `invalid.`, `test.`
/// * RFC 6762 §12: `local.` (mDNS, recursive resolvers MUST/SHOULD NX)
/// * RFC 9462 §4/6.1: `resolver.arpa.` (local NODATA, no public forwarding)
/// * RFC 6303 §4: RFC 1918 reverse zones (10/8, 172.16/12, 192.168/16),
///   loopback (127/8), broadcast/this-network (0/8, 255/8), IETF
///   link-local (169.254/16), TEST-NET-1/2/3 (RFC 5737), shared address
///   space (RFC 6598, 100.64/10), IPv6
///   link-local (fe80::/10), ULA (fc00::/7), unspecified (`::`),
///   loopback (::1) and documentation prefix (2001:db8::/32)
///
/// `localhost.` is intentionally not in this list. RFC 6761 §6.3.2
/// requires loopback (127.0.0.1 / ::1) for address queries. The query
/// pipeline synthesises the loopback answer (`build_localhost_response`)
/// so we avoid sending a denial to the few clients that bypass libc's
/// `/etc/hosts` consultation and reach the resolver directly for
/// `localhost`.
///
/// The table is split by how it interacts with captive forwarding.
/// `protected` holds the names a hotspot resolver can never answer
/// legitimately, `.onion` (RFC 7686) and the RFC 1918 reverses, so they are
/// claimed before blanket captive forwarding. Everything else yields to the
/// portal. `.local` and the router-handed search domains are exactly what a
/// captive portal needs to resolve for sign-in to work.
fn seed_built_in_zones(protected: &mut HashSet<String>, yielding: &mut HashSet<String>) {
    const CAPTIVE_PROTECTED_ZONES: &[&str] = &[
        // RFC 7686: `.onion` is resolved by the Tor client, never by DNS.
        "onion",
        // RFC 1918 reverse zones: 10/8, 192.168/16 and 172.16/12
        // (16.172 through 31.172).
        "10.in-addr.arpa",
        "168.192.in-addr.arpa",
        "16.172.in-addr.arpa",
        "17.172.in-addr.arpa",
        "18.172.in-addr.arpa",
        "19.172.in-addr.arpa",
        "20.172.in-addr.arpa",
        "21.172.in-addr.arpa",
        "22.172.in-addr.arpa",
        "23.172.in-addr.arpa",
        "24.172.in-addr.arpa",
        "25.172.in-addr.arpa",
        "26.172.in-addr.arpa",
        "27.172.in-addr.arpa",
        "28.172.in-addr.arpa",
        "29.172.in-addr.arpa",
        "30.172.in-addr.arpa",
        "31.172.in-addr.arpa",
    ];
    const ZONES: &[&str] = &[
        // Special-use names (excluding `localhost`, see above). They stay
        // behind user forward/stub/captive routes in the pipeline.
        "invalid",
        "test",
        "local",
        "home.arpa",
        "resolver.arpa",
        "internal",
        "intranet",
        "lan",
        "corp",
        "private",
        "example",
        "localhost.localdomain",
        // IPv4 reverse: loopback + this-network + broadcast. The RFC 1918
        // reverses live in `CAPTIVE_PROTECTED_ZONES` above.
        "127.in-addr.arpa",
        "0.in-addr.arpa",
        "255.in-addr.arpa",
        // RFC 3927 link-local (169.254/16).
        "254.169.in-addr.arpa",
        // RFC 5737 documentation prefixes, the TEST-NET-1/2/3 reverses.
        // Listed alongside RFC 1918 by RFC 6303 §4 because they MUST NOT
        // resolve outside controlled environments.
        "2.0.192.in-addr.arpa",
        "100.51.198.in-addr.arpa",
        "113.0.203.in-addr.arpa",
        // IPv6 link-local fe80::/10 split across 8/9/a/b.e.f.ip6.arpa.
        "8.e.f.ip6.arpa",
        "9.e.f.ip6.arpa",
        "a.e.f.ip6.arpa",
        "b.e.f.ip6.arpa",
        // IPv6 ULA fc00::/7.
        "c.f.ip6.arpa",
        "d.f.ip6.arpa",
        // IPv6 unspecified address (`::`) reverse, RFC 6303 §4.3. The IPv4
        // counterpart is `0.in-addr.arpa` above. Its 32 zero nibbles are never
        // an ancestor of the `::1` name below, so the two zones stay disjoint.
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        // IPv6 loopback (::1) reverse, RFC 6303 §4.
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        // IPv6 documentation prefix 2001:db8::/32 reverse, RFC 6303 §4.
        "8.b.d.0.1.0.0.2.ip6.arpa",
    ];
    for apex in CAPTIVE_PROTECTED_ZONES {
        protected.insert((*apex).to_string());
    }
    for apex in ZONES {
        yielding.insert((*apex).to_string());
    }
    for second_octet in 64..=127 {
        yielding.insert(format!("{second_octet}.100.in-addr.arpa"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV6_UNSPECIFIED_REVERSE: &str =
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";
    const IPV6_LOOPBACK_REVERSE: &str =
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";

    #[test]
    fn only_private_use_suffixes_accept_an_ephemeral_route() {
        for apex in [
            "lan",
            "corp",
            "private",
            "internal",
            "intranet",
            "home.arpa",
            "office.corp",
        ] {
            assert!(
                is_publishable_ephemeral_route(apex),
                "{apex} must accept a discovered route"
            );
        }
        for apex in [
            "com",
            "example.com",
            "onion",
            "local",
            "test",
            "invalid",
            "example",
            "10.in-addr.arpa",
            "arpa",
            IPV6_UNSPECIFIED_REVERSE,
            "",
        ] {
            assert!(
                !is_publishable_ephemeral_route(apex),
                "{apex} must never be auto-published from DHCP"
            );
        }
    }

    /// The lookup returns the zone apex, not just "matched". Without
    /// it the query pipeline cannot tell an apex question from a below-apex
    /// one, and cannot put the RFC 2308 §3 owner on the synthesised SOA.
    #[test]
    fn built_in_lookup_returns_the_matched_zone_apex() {
        let z = LocalZones::new();
        assert_eq!(z.lookup_built_in("local"), Some("local"));
        assert_eq!(z.lookup_built_in("printer.local"), Some("local"));
        assert_eq!(z.lookup_built_in("a.b.printer.local"), Some("local"));
        assert_eq!(z.lookup_built_in_protected("onion"), Some("onion"));
        assert_eq!(z.lookup_built_in_protected("service.onion"), Some("onion"));
        assert_eq!(
            z.lookup_built_in("1.0.10.in-addr.arpa"),
            Some("10.in-addr.arpa")
        );
    }

    #[test]
    fn built_in_rfc6761_zones_are_claimed_by_default() {
        let z = LocalZones::new();
        // RFC 6761 / 6762 special-use TLDs.
        assert_eq!(z.lookup_built_in("anything.test"), Some("test"));
        assert_eq!(z.lookup_built_in("foo.invalid"), Some("invalid"));
        assert_eq!(z.lookup_built_in("printer.local"), Some("local"));
        // localhost gets a positive loopback answer in the query pipeline,
        // so it is not a built-in empty zone.
        assert_eq!(z.lookup_built_in("localhost"), None);
    }

    #[test]
    fn built_in_privacy_zones_preserve_previous_resolver_policy() {
        let z = LocalZones::new();
        for domain in [
            "service.onion",
            "router.home.arpa",
            "host.internal",
            "host.intranet",
            "host.lan",
            "host.corp",
            "host.private",
            "example.example",
            "host.localhost.localdomain",
        ] {
            assert!(
                z.lookup_built_in(domain).is_some(),
                "{domain} must not leak to public resolvers"
            );
        }
    }

    #[test]
    fn captive_protected_subset_covers_onion_and_rfc1918_reverses_only() {
        let z = LocalZones::new();
        for domain in [
            "service.onion",
            "1.0.10.in-addr.arpa",
            "1.1.168.192.in-addr.arpa",
            "1.0.16.172.in-addr.arpa",
            "1.0.31.172.in-addr.arpa",
        ] {
            assert!(
                z.lookup_built_in_protected(domain).is_some(),
                "{domain} must be protected from captive forwarding"
            );
        }
        // Portal compatibility depends on the hotspot resolver answering
        // these, so they stay behind captive forwarding.
        for domain in [
            "printer.local",
            "router.home.arpa",
            "host.lan",
            "host.corp",
            "host.internal",
            "1.0.0.127.in-addr.arpa",
            "1.0.254.169.in-addr.arpa",
        ] {
            assert_eq!(
                z.lookup_built_in_protected(domain),
                None,
                "{domain} must keep yielding to captive forwarding"
            );
            assert!(
                z.lookup_built_in(domain).is_some(),
                "{domain} must still be claimed once captive forwarding is off"
            );
        }
    }

    #[test]
    fn built_in_rfc6303_reverse_zones_are_claimed_by_default() {
        let z = LocalZones::new();
        // RFC 1918 reverses.
        assert_eq!(
            z.lookup_built_in("1.0.10.in-addr.arpa"),
            Some("10.in-addr.arpa")
        );
        assert_eq!(
            z.lookup_built_in("1.1.168.192.in-addr.arpa"),
            Some("168.192.in-addr.arpa")
        );
        assert_eq!(
            z.lookup_built_in("1.0.20.172.in-addr.arpa"),
            Some("20.172.in-addr.arpa")
        );
        // RFC 6598 shared address space (100.64/10).
        assert_eq!(
            z.lookup_built_in("1.0.64.100.in-addr.arpa"),
            Some("64.100.in-addr.arpa")
        );
        assert_eq!(
            z.lookup_built_in("1.0.127.100.in-addr.arpa"),
            Some("127.100.in-addr.arpa")
        );
        assert_eq!(z.lookup_built_in("1.0.128.100.in-addr.arpa"), None);
        // Link-local and loopback reverses.
        assert_eq!(
            z.lookup_built_in("1.0.254.169.in-addr.arpa"),
            Some("254.169.in-addr.arpa")
        );
        assert_eq!(
            z.lookup_built_in("1.0.0.127.in-addr.arpa"),
            Some("127.in-addr.arpa")
        );
        // RFC 5737 documentation prefixes (TEST-NET-1/2/3).
        assert_eq!(
            z.lookup_built_in("1.2.0.192.in-addr.arpa"),
            Some("2.0.192.in-addr.arpa")
        );
        assert_eq!(
            z.lookup_built_in("1.100.51.198.in-addr.arpa"),
            Some("100.51.198.in-addr.arpa")
        );
        assert_eq!(
            z.lookup_built_in("1.113.0.203.in-addr.arpa"),
            Some("113.0.203.in-addr.arpa")
        );
    }

    #[test]
    fn built_in_ula_reverse_zones_cover_fc_and_fd() {
        let z = LocalZones::new();
        assert_eq!(z.lookup_built_in("1.c.f.ip6.arpa"), Some("c.f.ip6.arpa"));
        assert_eq!(z.lookup_built_in("1.d.f.ip6.arpa"), Some("d.f.ip6.arpa"));
    }

    #[test]
    fn built_in_ipv6_loopback_and_documentation_reverse_zones() {
        let z = LocalZones::new();
        assert_eq!(
            z.lookup_built_in(IPV6_LOOPBACK_REVERSE),
            Some(IPV6_LOOPBACK_REVERSE)
        );
        assert_eq!(
            z.lookup_built_in("1.0.8.b.d.0.1.0.0.2.ip6.arpa"),
            Some("8.b.d.0.1.0.0.2.ip6.arpa")
        );
    }

    /// RFC 6303 §4.3 lists the unspecified address `::/128` next to `::1/128`.
    /// Without its zone, a PTR for `::` escapes the built-in table and reaches
    /// captive forwarding or the public path.
    #[test]
    fn built_in_ipv6_unspecified_reverse_zone_is_served_locally() {
        let z = LocalZones::new();
        assert_eq!(
            z.lookup_built_in(IPV6_UNSPECIFIED_REVERSE),
            Some(IPV6_UNSPECIFIED_REVERSE)
        );
        // Not captive-protected: it yields to the portal exactly like the
        // `::1` and `0.in-addr.arpa` reverses it mirrors.
        assert_eq!(z.lookup_built_in_protected(IPV6_UNSPECIFIED_REVERSE), None);
        // The two 32-nibble zones must stay disjoint. Neither is an ancestor
        // of the other, so `::1` keeps its own apex.
        assert_eq!(
            z.lookup_built_in(IPV6_LOOPBACK_REVERSE),
            Some(IPV6_LOOPBACK_REVERSE)
        );
    }
}
