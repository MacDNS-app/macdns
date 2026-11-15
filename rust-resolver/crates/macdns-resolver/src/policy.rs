// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! Atomic runtime policy publication.
//!
//! Overrides and forward zones are user configuration replayed from
//! `state.json`. Applying them by clearing the live stores and re-inserting
//! entry by entry means a rejected entry leaves a half-applied policy active,
//! and the rollback path can fail the same way.
//!
//! Instead, a complete candidate policy is built and fully validated before
//! anything live changes, then published in a single `ArcSwap` store. A query
//! loads one snapshot and uses it for the whole request, so it never observes
//! new overrides combined with old zones.

use crate::domain_name::{canonicalize, NameRole};
use crate::overrides::OverrideStore;
use crate::zones::ForwardZones;
use serde::Deserialize;
use std::sync::Arc;

/// Coherent runtime policy. Published as one unit.
pub struct RuntimePolicySnapshot {
    pub overrides: Arc<OverrideStore>,
    pub zones: Arc<ForwardZones>,
}

#[derive(Debug, Deserialize)]
pub struct OverrideRecord {
    pub domain: String,
    pub qtype: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct ForwardZoneRecord {
    pub domain: String,
    #[serde(rename = "forwardIP")]
    pub forward_ip: String,
}

#[derive(Debug, Deserialize)]
pub struct PolicySnapshotDto {
    #[serde(default)]
    pub overrides: Vec<OverrideRecord>,
    #[serde(default, rename = "forwardZones")]
    pub forward_zones: Vec<ForwardZoneRecord>,
}

/// Builds a complete candidate policy.
///
/// Returns `Err` without touching any live state when any record is invalid or
/// duplicated, so the caller can keep the previous policy active. Every
/// rejection names the offending entry as the user wrote it, because a
/// rejection that does not say which entry to fix gives the user nothing to act
/// on.
pub fn build_snapshot(dto: &PolicySnapshotDto) -> Result<RuntimePolicySnapshot, String> {
    let overrides = OverrideStore::new();
    let mut seen_overrides = std::collections::BTreeSet::new();

    for record in &dto.overrides {
        let identify =
            |error: String| format!("override {} {}: {}", record.domain, record.qtype, error);

        let (qtype, rdata) = crate::parse_override(&record.qtype, &record.value)
            .map_err(|error| identify(format!("invalid value {:?}: {}", record.value, error)))?;

        let domain = canonicalize(&record.domain, NameRole::OverrideOwner).map_err(identify)?;
        let key = (domain.clone(), qtype);
        if !seen_overrides.insert(key) {
            return Err(identify("duplicate entry".into()));
        }
        overrides
            .set_checked(&domain, qtype, vec![rdata])
            .map_err(identify)?;
    }

    let zones = ForwardZones::new();
    let mut seen_zones = std::collections::BTreeSet::new();

    for record in &dto.forward_zones {
        let identify = |error: String| format!("forward zone {}: {}", record.domain, error);

        let domain = canonicalize(&record.domain, NameRole::ForwardZone).map_err(identify)?;
        if !seen_zones.insert(domain.clone()) {
            return Err(identify("duplicate entry".into()));
        }
        zones
            .upsert(&domain, &record.forward_ip)
            .map_err(identify)?;
    }

    Ok(RuntimePolicySnapshot {
        overrides: Arc::new(overrides),
        zones: Arc::new(zones),
    })
}

#[derive(Debug, Deserialize)]
pub struct EphemeralRouteRecord {
    pub domain: String,
    #[serde(rename = "forwardIP")]
    pub forward_ip: String,
}

/// Builds the complete route table implied by the attached network's search
/// domains.
///
/// The input is unauthenticated DHCP data, so records that fall outside the
/// private-use suffixes or that carry an unusable resolver address are skipped
/// with a log line instead of failing the batch. One hostile entry must not
/// stop the router's legitimate private namespaces from resolving. The table
/// is still built whole and published in a single swap.
pub fn build_ephemeral_routes(records: &[EphemeralRouteRecord]) -> ForwardZones {
    let zones = ForwardZones::new();

    for record in records {
        let domain = match canonicalize(&record.domain, NameRole::ForwardZone) {
            Ok(domain) => domain,
            Err(error) => {
                log::warn!("discovered search domain {:?}: {}", record.domain, error);
                continue;
            }
        };
        if !crate::local_zones::is_publishable_ephemeral_route(&domain) {
            log::info!("ignoring discovered search domain {domain}: not a private-use suffix");
            continue;
        }
        if let Err(error) = zones.upsert(&domain, &record.forward_ip) {
            log::warn!("discovered route for {domain}: {error}");
        }
    }

    zones
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{RData, RecordType};
    use std::str::FromStr;

    /// A rejection has to name the entry the user must fix. Reporting only
    /// "policy rejected" leaves a stopped resolver with no way to tell which of
    /// hundreds of entries is at fault.
    #[test]
    fn every_rejection_identifies_the_offending_entry() {
        let cases = [
            (
                r#"{
                    "overrides": [{"domain":"bad.example","qtype":"A","value":"not-an-ip"}],
                    "forwardZones": []
                }"#,
                "bad.example",
            ),
            (
                r#"{
                    "overrides": [{"domain":"..bad..example","qtype":"A","value":"10.0.0.1"}],
                    "forwardZones": []
                }"#,
                "..bad..example",
            ),
            (
                r#"{
                    "overrides": [
                        {"domain":"alias.example","qtype":"CNAME","value":"target.example"},
                        {"domain":"alias.example","qtype":"A","value":"10.0.0.1"}
                    ],
                    "forwardZones": []
                }"#,
                "alias.example",
            ),
            (
                r#"{
                    "overrides": [
                        {"domain":"a.example","qtype":"A","value":"10.0.0.1"},
                        {"domain":"A.EXAMPLE","qtype":"A","value":"10.0.0.2"}
                    ],
                    "forwardZones": []
                }"#,
                "A.EXAMPLE",
            ),
            (
                r#"{
                    "overrides": [],
                    "forwardZones": [{"domain":"corp.local","forwardIP":"nope"}]
                }"#,
                "corp.local",
            ),
            (
                r#"{
                    "overrides": [],
                    "forwardZones": [{"domain":"..corp..local","forwardIP":"10.0.0.53"}]
                }"#,
                "..corp..local",
            ),
            (
                r#"{
                    "overrides": [],
                    "forwardZones": [
                        {"domain":"corp.local","forwardIP":"10.0.0.53"},
                        {"domain":"CORP.LOCAL","forwardIP":"10.0.0.54"}
                    ]
                }"#,
                "CORP.LOCAL",
            ),
        ];

        for (json, offender) in cases {
            let error = build_snapshot(&dto(json))
                .err()
                .unwrap_or_else(|| panic!("{json} must be rejected"));
            assert!(
                error.contains(offender),
                "rejection {error:?} must name the offending entry {offender:?}"
            );
        }
    }

    #[test]
    fn ephemeral_routes_keep_private_suffixes_and_drop_everything_else() {
        let zones = build_ephemeral_routes(&[
            EphemeralRouteRecord {
                domain: "lan".into(),
                forward_ip: "192.0.2.53".into(),
            },
            EphemeralRouteRecord {
                domain: "office.corp".into(),
                forward_ip: "192.0.2.53".into(),
            },
            EphemeralRouteRecord {
                domain: "example.com".into(),
                forward_ip: "192.0.2.53".into(),
            },
            EphemeralRouteRecord {
                domain: "onion".into(),
                forward_ip: "192.0.2.53".into(),
            },
            EphemeralRouteRecord {
                domain: "broken.lan".into(),
                forward_ip: "0.0.0.0".into(),
            },
        ]);

        assert!(zones.entry_for("nas.lan").is_some());
        assert!(zones.entry_for("printer.office.corp").is_some());
        assert!(zones.entry_for("www.example.com").is_none());
        assert!(zones.entry_for("service.onion").is_none());
        assert!(zones.entry_for("broken.lan").is_some());
        assert_eq!(
            zones
                .entry_for("broken.lan")
                .unwrap()
                .forward_ip
                .to_string(),
            "192.0.2.53",
            "an unusable resolver must not shadow the parent route"
        );
    }

    fn dto(json: &str) -> PolicySnapshotDto {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn builds_complete_policy() {
        let snapshot = build_snapshot(&dto(r#"{
                "overrides": [{"domain":"a.example","qtype":"A","value":"10.0.0.1"}],
                "forwardZones": [{"domain":"corp.local","forwardIP":"10.0.0.53"}]
            }"#))
        .unwrap();

        assert!(snapshot
            .overrides
            .get_exact("a.example", RecordType::A)
            .is_some());
        assert!(snapshot.zones.entry_for("host.corp.local").is_some());
    }

    #[test]
    fn builds_all_ui_supported_override_types() {
        for (qtype, value) in [
            ("A", "192.0.2.1"),
            ("AAAA", "2001:db8::1"),
            ("CNAME", "target.example."),
            ("MX", "10 mail.example."),
            ("TXT", "verification-token"),
            ("PTR", "target.example."),
            ("NS", "ns.example."),
        ] {
            let snapshot = build_snapshot(&PolicySnapshotDto {
                overrides: vec![OverrideRecord {
                    domain: "record.example".into(),
                    qtype: qtype.into(),
                    value: value.into(),
                }],
                forward_zones: vec![],
            })
            .unwrap_or_else(|error| panic!("{qtype} override rejected: {error}"));

            let record_type = RecordType::from_str(qtype).unwrap();
            assert!(snapshot
                .overrides
                .get_exact("record.example", record_type)
                .is_some());
        }
    }

    #[test]
    fn bare_mx_hostname_uses_default_preference() {
        let snapshot = build_snapshot(&PolicySnapshotDto {
            overrides: vec![OverrideRecord {
                domain: "record.example".into(),
                qtype: "MX".into(),
                value: "mail.example.".into(),
            }],
            forward_zones: vec![],
        })
        .unwrap();

        let records = snapshot
            .overrides
            .get_exact("record.example", RecordType::MX)
            .unwrap();
        let RData::MX(mx) = &records[0] else {
            panic!("expected MX RData");
        };
        assert_eq!(mx.preference, 10);
    }

    #[test]
    fn invalid_override_value_rejects_whole_snapshot() {
        let err = build_snapshot(&dto(r#"{
                "overrides": [
                    {"domain":"good.example","qtype":"A","value":"10.0.0.1"},
                    {"domain":"bad.example","qtype":"A","value":"not-an-ip"}
                ],
                "forwardZones": []
            }"#))
        .err()
        .expect("invalid value must reject the snapshot");

        assert!(err.contains("override bad.example A: invalid value"));
    }

    #[test]
    fn single_label_host_is_accepted_only_as_an_exact_override_owner() {
        let snapshot = build_snapshot(&dto(r#"{
                "overrides": [{"domain":"Server","qtype":"A","value":"10.0.0.1"}],
                "forwardZones": []
            }"#))
        .expect("an exact single-label override owner is a host name");
        assert!(snapshot
            .overrides
            .get_exact("server", RecordType::A)
            .is_some());

        assert!(build_snapshot(&dto(r#"{
                "overrides": [{"domain":"*.server","qtype":"A","value":"10.0.0.1"}],
                "forwardZones": []
            }"#))
        .is_err());
        assert!(build_snapshot(&dto(r#"{
                "overrides": [],
                "forwardZones": [{"domain":"server","forwardIP":"10.0.0.53"}]
            }"#))
        .is_err());
    }

    #[test]
    fn invalid_forward_ip_rejects_whole_snapshot() {
        assert!(build_snapshot(&dto(r#"{
                "overrides": [],
                "forwardZones": [{"domain":"corp.local","forwardIP":"nope"}]
            }"#,))
        .err()
        .is_some());
    }

    #[test]
    fn duplicate_override_key_is_rejected() {
        assert!(build_snapshot(&dto(r#"{
                "overrides": [
                    {"domain":"a.example","qtype":"A","value":"10.0.0.1"},
                    {"domain":"A.EXAMPLE","qtype":"A","value":"10.0.0.2"}
                ],
                "forwardZones": []
            }"#,))
        .err()
        .is_some());
    }

    #[test]
    fn duplicate_forward_zone_is_rejected() {
        assert!(build_snapshot(&dto(r#"{
                "overrides": [],
                "forwardZones": [
                    {"domain":"corp.local","forwardIP":"10.0.0.53"},
                    {"domain":"CORP.LOCAL","forwardIP":"10.0.0.54"}
                ]
            }"#,))
        .err()
        .is_some());
    }

    #[test]
    fn canonical_duplicate_names_are_rejected() {
        for json in [
            r#"{
                "overrides": [
                    {"domain":"a.example","qtype":"A","value":"10.0.0.1"},
                    {"domain":"a.example.","qtype":"A","value":"10.0.0.2"}
                ],
                "forwardZones": []
            }"#,
            r#"{
                "overrides": [
                    {"domain":"münchen.de","qtype":"A","value":"10.0.0.1"},
                    {"domain":"xn--mnchen-3ya.de","qtype":"A","value":"10.0.0.2"}
                ],
                "forwardZones": []
            }"#,
            r#"{
                "overrides": [],
                "forwardZones": [
                    {"domain":"corp.local","forwardIP":"10.0.0.53"},
                    {"domain":"corp.local.","forwardIP":"10.0.0.54"}
                ]
            }"#,
            r#"{
                "overrides": [],
                "forwardZones": [
                    {"domain":"münchen.de","forwardIP":"10.0.0.53"},
                    {"domain":"xn--mnchen-3ya.de","forwardIP":"10.0.0.54"}
                ]
            }"#,
        ] {
            assert!(build_snapshot(&dto(json)).is_err(), "accepted {json}");
        }
    }

    #[test]
    fn valid_ascii_ldh_names_are_not_rejected_by_idna_rules() {
        let snapshot = build_snapshot(&dto(r#"{
                "overrides": [
                    {"domain":"cs--poligon.example","qtype":"A","value":"10.0.0.1"}
                ],
                "forwardZones": [
                    {"domain":"tx--gateway.example","forwardIP":"10.0.0.53"}
                ]
            }"#))
        .unwrap();

        assert!(snapshot
            .overrides
            .get_exact("cs--poligon.example", RecordType::A)
            .is_some());
        assert!(snapshot
            .zones
            .entry_for("host.tx--gateway.example")
            .is_some());
    }

    #[test]
    fn txt_override_rejects_payload_over_255_utf8_bytes() {
        let result = build_snapshot(&PolicySnapshotDto {
            overrides: vec![OverrideRecord {
                domain: "txt.example".into(),
                qtype: "TXT".into(),
                value: "😀".repeat(64),
            }],
            forward_zones: vec![],
        });

        assert!(result.is_err());
    }

    #[test]
    fn cname_cannot_coexist_with_other_records_at_same_owner() {
        for overrides in [
            r#"[
                {"domain":"alias.example","qtype":"CNAME","value":"target.example"},
                {"domain":"alias.example","qtype":"A","value":"10.0.0.1"}
            ]"#,
            r#"[
                {"domain":"alias.example","qtype":"A","value":"10.0.0.1"},
                {"domain":"alias.example","qtype":"CNAME","value":"target.example"}
            ]"#,
        ] {
            let json = format!(r#"{{"overrides":{overrides},"forwardZones":[]}}"#);
            assert!(build_snapshot(&dto(&json)).is_err());
        }
    }

    #[test]
    fn unsupported_qtype_is_rejected() {
        assert!(build_snapshot(&dto(r#"{
                "overrides": [{"domain":"a.example","qtype":"NOTAREALTYPE","value":"value"}],
                "forwardZones": []
            }"#,))
        .err()
        .is_some());
    }
}
