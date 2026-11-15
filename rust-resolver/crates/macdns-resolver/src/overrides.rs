// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use dashmap::DashMap;
use hickory_proto::rr::{RData, RecordType};
use std::sync::Mutex;

use crate::domain_name::{canonicalize, claims_subnames, NameRole};

#[derive(Clone, Hash, PartialEq, Eq)]
struct Key {
    domain: String,
    qtype: u16,
}

pub struct OverrideStore {
    mutation_lock: Mutex<()>,
    map: DashMap<Key, Vec<RData>>,
    /// Names with at least one record under any qtype. Indexed alongside
    /// `wildcards` so resolve_zone's per-level "is this name claimed?" check
    /// is O(1). Kept in sync through the qtype-count maps below.
    names: DashMap<String, ()>,
    /// Wildcard apexes (without the leading `*.`) that have at least one
    /// record, for the same O(1) check.
    wildcards: DashMap<String, ()>,
    /// Distinct qtypes per name. `set` increments on a fresh (name, qtype)
    /// pair and `remove` decrements. At 0 the name leaves `names`, so the
    /// index stays in lockstep with the map. Counting instead of iterating a
    /// closed qtype set lets any hickory-known qtype work without touching
    /// this struct.
    name_qtype_count: DashMap<String, usize>,
    wildcard_qtype_count: DashMap<String, usize>,
}

/// Zone resolution outcome for a queried name. The query pipeline uses
/// this to decide whether to answer, return NODATA, or return NXDOMAIN
/// without leaking the name upstream. Most-specific match wins
/// (longest label suffix that has either an exact override or a
/// wildcard registered).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneMatch {
    /// No override touches this name. The query falls through to the rest of
    /// the pipeline (local zones, blocklist, cache, hedge).
    None,
    /// The queried name is itself configured (at least one qtype).
    /// Static semantics: exact-qtype hit answers, CNAME chains,
    /// everything else is NODATA at the apex.
    StaticApex { apex: String },
    /// The queried name sits under a static-zone apex on an ancestor.
    /// Sub-names that carry no local-data of their own answer NXDOMAIN, so
    /// operator-claimed zones are never exposed to public DNS.
    StaticSubname { apex: String },
    /// A wildcard is registered at `apex` (stored as `*.apex`). Redirect
    /// semantics: any query at or under `apex` is served from the
    /// wildcard's local-data, owner rewritten to the queried name.
    /// Mismatched qtypes answer NODATA.
    Redirect { apex: String },
}

impl OverrideStore {
    pub fn new() -> Self {
        Self {
            mutation_lock: Mutex::new(()),
            map: DashMap::new(),
            names: DashMap::new(),
            wildcards: DashMap::new(),
            name_qtype_count: DashMap::new(),
            wildcard_qtype_count: DashMap::new(),
        }
    }

    pub fn snapshot_copy(&self) -> Self {
        let copy = Self::new();
        for item in self.map.iter() {
            copy.set(
                &item.key().domain,
                RecordType::from(item.key().qtype),
                item.value().clone(),
            );
        }
        copy
    }

    pub fn set_checked(
        &self,
        domain: &str,
        qtype: RecordType,
        rdata: Vec<RData>,
    ) -> Result<(), String> {
        let normalized = canonicalize(domain, NameRole::OverrideOwner)?;
        let cname_type = u16::from(RecordType::CNAME);
        let conflicts = self.map.iter().any(|item| {
            item.key().domain == normalized
                && ((qtype == RecordType::CNAME && item.key().qtype != cname_type)
                    || (qtype != RecordType::CNAME && item.key().qtype == cname_type))
        });
        if conflicts {
            return Err(format!(
                "CNAME cannot coexist with other records at {domain}"
            ));
        }
        self.set(&normalized, qtype, rdata);
        Ok(())
    }

    /// Inserts or replaces the record set for `(domain, qtype)`. When a name's
    /// qtype count goes from 0 to 1, the names/wildcards index is updated so
    /// resolve_zone keeps O(1) lookups whichever qtype is added. Mutations are
    /// serialized so the map, counters and indexes cannot drift under
    /// concurrent FFI calls.
    pub fn set(&self, domain: &str, qtype: RecordType, rdata: Vec<RData>) {
        let _guard = self.mutation_lock.lock().unwrap_or_else(|p| p.into_inner());
        let normalized = normalize(domain);
        let key = Key {
            domain: normalized.clone(),
            qtype: u16::from(qtype),
        };
        let inserted_new_qtype = !self.map.contains_key(&key);
        self.map.insert(key, rdata);
        if !inserted_new_qtype {
            return;
        }
        let (target_name, counts, index) = if let Some(apex) = normalized.strip_prefix("*.") {
            (
                apex.to_string(),
                &self.wildcard_qtype_count,
                &self.wildcards,
            )
        } else {
            (normalized.clone(), &self.name_qtype_count, &self.names)
        };
        let new_count = {
            let mut e = counts.entry(target_name.clone()).or_insert(0);
            *e += 1;
            *e
        }; // RefMut dropped here before any further DashMap mutation
        if new_count == 1 {
            index.insert(target_name, ());
        }
    }

    /// When a name's qtype count reaches 0, its names/wildcards index entry is
    /// dropped so resolve_zone returns `ZoneMatch::None`. Takes the same
    /// mutation lock as `set`, keeping counters and indexes in sync.
    pub fn remove(&self, domain: &str, qtype: RecordType) {
        let _guard = self.mutation_lock.lock().unwrap_or_else(|p| p.into_inner());
        let normalized = normalize(domain);
        let key = Key {
            domain: normalized.clone(),
            qtype: u16::from(qtype),
        };
        let was_present = self.map.remove(&key).is_some();
        if !was_present {
            return;
        }
        let (target_name, counts, index) = if let Some(apex) = normalized.strip_prefix("*.") {
            (
                apex.to_string(),
                &self.wildcard_qtype_count,
                &self.wildcards,
            )
        } else {
            (normalized.clone(), &self.name_qtype_count, &self.names)
        };
        let new_count = {
            let mut e = counts.entry(target_name.clone()).or_insert(0);
            *e = e.saturating_sub(1);
            *e
        };
        if new_count == 0 {
            counts.remove(&target_name);
            index.remove(&target_name);
        }
    }

    pub fn clear(&self) {
        let _guard = self.mutation_lock.lock().unwrap_or_else(|p| p.into_inner());
        self.map.clear();
        self.names.clear();
        self.wildcards.clear();
        self.name_qtype_count.clear();
        self.wildcard_qtype_count.clear();
    }

    /// Strict exact lookup with no wildcard walk. The query pipeline calls it
    /// after `resolve_zone` has pinned down which name carries the local-data,
    /// so a wildcard at an ancestor cannot bleed into a static zone's reply.
    /// Static zones must shadow wildcards defined above them.
    pub fn get_exact(&self, domain: &str, qtype: RecordType) -> Option<Vec<RData>> {
        self.map
            .get(&Key {
                domain: normalize(domain),
                qtype: u16::from(qtype),
            })
            .map(|v| v.clone())
    }

    /// Walks the label hierarchy from the queried name up to the root,
    /// returning the most-specific zone that claims the name. Exact wins
    /// over wildcard at the same label (more specific). Stops at the first
    /// match. Deeper matches suppress shallower ones, which is how a
    /// static zone at `teste.example.com` shadows a redirect wildcard
    /// at `*.example.com`.
    pub fn resolve_zone(&self, domain: &str) -> ZoneMatch {
        let d = normalize(domain);
        let mut level = d.as_str();
        loop {
            if self.exact_has_any_qtype(level) {
                if level == d.as_str() {
                    return ZoneMatch::StaticApex {
                        apex: level.to_string(),
                    };
                }
                if claims_subnames(level) {
                    return ZoneMatch::StaticSubname {
                        apex: level.to_string(),
                    };
                }
            }
            if self.wildcard_has_any_qtype(level) {
                return ZoneMatch::Redirect {
                    apex: level.to_string(),
                };
            }
            match level.find('.') {
                Some(dot) => {
                    let parent = &level[dot + 1..];
                    if parent.is_empty() {
                        return ZoneMatch::None;
                    }
                    level = parent;
                }
                None => return ZoneMatch::None,
            }
        }
    }

    /// True iff the store has at least one record, of any supported qtype,
    /// stored under `domain` verbatim (no wildcard walk, no `*.` prefix).
    fn exact_has_any_qtype(&self, domain: &str) -> bool {
        self.names.contains_key(domain)
    }

    /// True iff the store has at least one record of any supported qtype
    /// stored under `*.apex`, meaning a wildcard is registered whose base
    /// label equals `apex`.
    fn wildcard_has_any_qtype(&self, apex: &str) -> bool {
        self.wildcards.contains_key(apex)
    }
}

impl Default for OverrideStore {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize(d: &str) -> String {
    canonicalize(d, NameRole::OverrideOwner)
        .unwrap_or_else(|_| d.trim_end_matches('.').to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, RecordType};
    use std::net::Ipv4Addr;

    fn rdata_a(ip: &str) -> RData {
        RData::A(A(ip.parse().unwrap()))
    }

    #[test]
    fn exact_match() {
        let store = OverrideStore::new();
        store.set("example.com", RecordType::A, vec![rdata_a("1.2.3.4")]);
        let got = store.get_exact("example.com", RecordType::A);
        assert_eq!(got.unwrap().len(), 1);
    }

    #[test]
    fn stored_rdata_round_trips_verbatim() {
        let store = OverrideStore::new();
        store.set("api.example.com", RecordType::A, vec![rdata_a("1.2.3.4")]);
        let got = store.get_exact("api.example.com", RecordType::A).unwrap();
        if let RData::A(a) = &got[0] {
            assert_eq!(a.0, Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("wrong rdata")
        }
    }

    #[test]
    fn remove_exact() {
        let store = OverrideStore::new();
        store.set("example.com", RecordType::A, vec![rdata_a("1.2.3.4")]);
        store.remove("example.com", RecordType::A);
        assert!(store.get_exact("example.com", RecordType::A).is_none());
    }

    #[test]
    fn cname_override() {
        let store = OverrideStore::new();
        let cname = RData::CNAME(hickory_proto::rr::rdata::CNAME(
            "target.example.".parse().unwrap(),
        ));
        store.set("alias.example.com", RecordType::CNAME, vec![cname]);
        assert!(store
            .get_exact("alias.example.com", RecordType::CNAME)
            .is_some());
    }

    #[test]
    fn get_exact_ignores_wildcard_walk() {
        // get_exact must not climb the label tree. Only the key literally
        // stored is consulted. That is what stops a parent wildcard from
        // bleeding into a more-specific static zone's reply.
        let store = OverrideStore::new();
        store.set("*.example.com", RecordType::A, vec![rdata_a("9.9.9.9")]);
        assert!(store.get_exact("api.example.com", RecordType::A).is_none());
        assert!(store.get_exact("*.example.com", RecordType::A).is_some());
    }

    #[test]
    fn resolve_zone_none_for_empty_store() {
        let store = OverrideStore::new();
        assert_eq!(store.resolve_zone("example.com"), ZoneMatch::None);
    }

    #[test]
    fn single_label_host_override_does_not_claim_its_subnames() {
        let store = OverrideStore::new();
        store.set("dev", RecordType::A, vec![rdata_a("10.0.0.5")]);
        assert_eq!(
            store.resolve_zone("dev"),
            ZoneMatch::StaticApex {
                apex: "dev".to_string()
            },
        );
        assert_eq!(store.resolve_zone("web.dev"), ZoneMatch::None);
    }

    #[test]
    fn reserved_single_label_override_still_claims_its_subnames() {
        let store = OverrideStore::new();
        store.set("lan", RecordType::A, vec![rdata_a("10.0.0.5")]);
        assert_eq!(
            store.resolve_zone("nas.lan"),
            ZoneMatch::StaticSubname {
                apex: "lan".to_string()
            },
        );
    }

    #[test]
    fn resolve_zone_static_apex_on_exact_override() {
        let store = OverrideStore::new();
        store.set("api.example.com", RecordType::A, vec![rdata_a("1.2.3.4")]);
        assert_eq!(
            store.resolve_zone("api.example.com"),
            ZoneMatch::StaticApex {
                apex: "api.example.com".to_string()
            },
        );
    }

    #[test]
    fn resolve_zone_static_subname_below_exact_override() {
        // A static zone at `api.example.com.` answers NXDOMAIN for names
        // under the apex that carry no local-data.
        let store = OverrideStore::new();
        store.set("api.example.com", RecordType::A, vec![rdata_a("1.2.3.4")]);
        assert_eq!(
            store.resolve_zone("foo.api.example.com"),
            ZoneMatch::StaticSubname {
                apex: "api.example.com".to_string()
            },
        );
    }

    #[test]
    fn resolve_zone_redirect_on_wildcard_apex() {
        // Redirect semantics: `*.example.com A` claims `example.com` itself,
        // not just subdomains. The apex is served from the wildcard's
        // local-data.
        let store = OverrideStore::new();
        store.set("*.example.com", RecordType::A, vec![rdata_a("9.9.9.9")]);
        assert_eq!(
            store.resolve_zone("example.com"),
            ZoneMatch::Redirect {
                apex: "example.com".to_string()
            },
        );
    }

    #[test]
    fn resolve_zone_redirect_on_wildcard_subdomain() {
        let store = OverrideStore::new();
        store.set("*.example.com", RecordType::A, vec![rdata_a("9.9.9.9")]);
        assert_eq!(
            store.resolve_zone("api.example.com"),
            ZoneMatch::Redirect {
                apex: "example.com".to_string()
            },
        );
        assert_eq!(
            store.resolve_zone("deep.nested.example.com"),
            ZoneMatch::Redirect {
                apex: "example.com".to_string()
            },
        );
    }

    #[test]
    fn resolve_zone_static_wins_over_enclosing_redirect() {
        // Critical invariant: when a static zone (`api.example.com`) sits
        // inside a redirect (`*.example.com`), the more specific zone wins.
        // Sub-names of the static zone get NXDOMAIN, never the wildcard's
        // data.
        let store = OverrideStore::new();
        store.set("*.example.com", RecordType::A, vec![rdata_a("9.9.9.9")]);
        store.set("api.example.com", RecordType::A, vec![rdata_a("1.2.3.4")]);
        assert_eq!(
            store.resolve_zone("api.example.com"),
            ZoneMatch::StaticApex {
                apex: "api.example.com".to_string()
            },
        );
        assert_eq!(
            store.resolve_zone("v2.api.example.com"),
            ZoneMatch::StaticSubname {
                apex: "api.example.com".to_string()
            },
        );
        // Outside the static zone but inside the redirect.
        assert_eq!(
            store.resolve_zone("other.example.com"),
            ZoneMatch::Redirect {
                apex: "example.com".to_string()
            },
        );
    }

    #[test]
    fn resolve_zone_none_for_unrelated_name() {
        let store = OverrideStore::new();
        store.set("example.com", RecordType::A, vec![rdata_a("1.2.3.4")]);
        assert_eq!(store.resolve_zone("unrelated.test"), ZoneMatch::None);
    }

    #[test]
    fn resolve_zone_handles_deep_label_chain_quickly() {
        // Not a benchmark. Guards against an accidental quadratic regression
        // in the index path.
        let store = OverrideStore::new();
        for i in 0..100 {
            store.set(
                &format!("name{}.example.test", i),
                RecordType::A,
                vec![rdata_a("1.2.3.4")],
            );
        }
        let outcome = store.resolve_zone("a.b.c.d.e.f.g.h.unrelated.test");
        assert_eq!(outcome, ZoneMatch::None);
    }

    #[test]
    fn override_lookup_normalises_idn() {
        let store = OverrideStore::new();
        store.set("münchen.de", RecordType::A, vec![rdata_a("1.2.3.4")]);
        assert!(store
            .get_exact("xn--mnchen-3ya.de", RecordType::A)
            .is_some());
        assert!(store.get_exact("MÜNCHEN.DE", RecordType::A).is_some());
    }

    #[test]
    fn override_set_remove_keeps_index_in_sync() {
        let store = OverrideStore::new();
        store.set("apex.test", RecordType::A, vec![rdata_a("1.2.3.4")]);
        store.set(
            "apex.test",
            RecordType::AAAA,
            vec![RData::AAAA(hickory_proto::rr::rdata::AAAA(
                "::1".parse().unwrap(),
            ))],
        );
        assert_eq!(
            store.resolve_zone("apex.test"),
            ZoneMatch::StaticApex {
                apex: "apex.test".to_string()
            }
        );
        store.remove("apex.test", RecordType::A);
        // AAAA remains, so the apex stays claimed.
        assert_eq!(
            store.resolve_zone("apex.test"),
            ZoneMatch::StaticApex {
                apex: "apex.test".to_string()
            }
        );
        store.remove("apex.test", RecordType::AAAA);
        // No qtypes left, so the apex is unclaimed.
        assert_eq!(store.resolve_zone("apex.test"), ZoneMatch::None);
    }

    #[test]
    fn override_wildcard_index_in_sync() {
        let store = OverrideStore::new();
        store.set("*.zone.test", RecordType::A, vec![rdata_a("9.9.9.9")]);
        store.set(
            "*.zone.test",
            RecordType::HTTPS,
            parse_override_or_skip("HTTPS", "1 . alpn=h2"),
        );
        assert_eq!(
            store.resolve_zone("any.zone.test"),
            ZoneMatch::Redirect {
                apex: "zone.test".to_string()
            }
        );
        store.remove("*.zone.test", RecordType::A);
        store.remove("*.zone.test", RecordType::HTTPS);
        // Both qtypes removed, so the wildcard apex is unclaimed.
        assert_eq!(store.resolve_zone("any.zone.test"), ZoneMatch::None);
    }

    // Parses a presentation-format value for the index-sync tests without
    // the whole parse_override path. Mirrors the generic fallback branch of
    // lib.rs::parse_override.
    fn parse_override_or_skip(qtype: &str, value: &str) -> Vec<RData> {
        use std::str::FromStr;
        let rtype = RecordType::from_str(qtype).unwrap();
        let rdata = RData::try_from_str(rtype, value).unwrap();
        vec![rdata]
    }
}
