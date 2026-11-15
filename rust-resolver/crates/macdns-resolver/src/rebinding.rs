// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue, SVCB};
use hickory_proto::rr::{RData, Record, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns true when the address belongs to a space a legitimate public
/// recursive resolver (Cloudflare/Google/Quad9) should never answer with.
/// Covers:
/// - RFC 1918 (10/8, 172.16/12, 192.168/16)
/// - Loopback (127/8, ::1)
/// - Link-local (169.254/16, fe80::/10)
/// - Unspecified (0.0.0.0, ::)
/// - IPv4 broadcast (255.255.255.255)
/// - Carrier-grade NAT (100.64/10, RFC 6598)
/// - Documentation, benchmarking, and reserved IPv4 ranges that should
///   never arrive from public recursive resolvers
/// - IPv6 unique-local (fc00::/7, RFC 4193)
/// - IPv6 6to4 / NAT64 answers that embed any blocked IPv4 address
///
/// Anything else is treated as public. An unusual public IP in the response,
/// such as multicast, is still legitimate, and blocking it breaks real edge
/// cases.
pub fn ip_is_rebindable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_rebindable(v4),
        IpAddr::V6(v6) => v6_is_rebindable(v6),
    }
}

fn v4_is_rebindable(v4: &Ipv4Addr) -> bool {
    if v4.is_private() || v4.is_loopback() || v4.is_link_local() {
        return true;
    }
    if v4.is_unspecified() || v4.is_broadcast() {
        return true;
    }
    // RFC 6598 shared address space. Carriers hand these to CPE, so a public
    // resolver returning them almost always means a hijacked upstream or a
    // misconfigured CDN.
    let o = v4.octets();
    if o[0] == 100 && (o[1] & 0xC0) == 64 {
        return true;
    }
    // RFC 5737 documentation prefixes, RFC 2544 benchmarking, and
    // 240/4 reserved space are not routable public answers for clients.
    if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] & 0xF0) == 0xF0
    {
        return true;
    }
    false
}

fn v6_is_rebindable(v6: &Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() {
        return true;
    }
    // RFC 4291 §2.5.5.2: IPv4-mapped addresses (::ffff:0:0/96).
    // Strip the wrapper and run the v4 check so a private v4
    // smuggled inside a v6 answer still gets filtered.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return v4_is_rebindable(&v4);
    }
    if let Some(v4) = embedded_6to4_ipv4(v6) {
        return v4_is_rebindable(&v4);
    }
    if let Some(v4) = embedded_nat64_ipv4(v6) {
        return v4_is_rebindable(&v4);
    }
    // fc00::/7 unique-local (RFC 4193) and fe80::/10 link-local (RFC 4291).
    v6.is_unique_local() || v6.is_unicast_link_local()
}

fn embedded_6to4_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = v6.segments();
    if seg[0] != 0x2002 {
        return None;
    }
    Some(Ipv4Addr::new(
        (seg[1] >> 8) as u8,
        seg[1] as u8,
        (seg[2] >> 8) as u8,
        seg[2] as u8,
    ))
}

fn embedded_nat64_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = v6.segments();
    if seg[..6] != [0x0064, 0xff9b, 0, 0, 0, 0] {
        return None;
    }
    Some(Ipv4Addr::new(
        (seg[6] >> 8) as u8,
        seg[6] as u8,
        (seg[7] >> 8) as u8,
        seg[7] as u8,
    ))
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct RebindingFilterResult {
    pub stripped_addresses: usize,
    pub useful_answer_original: usize,
    pub useful_answer_kept: usize,
}

impl RebindingFilterResult {
    pub fn changed(self) -> bool {
        self.stripped_addresses > 0
    }

    pub fn all_useful_answers_stripped(self) -> bool {
        self.changed() && self.useful_answer_original > 0 && self.useful_answer_kept == 0
    }
}

/// Strips every rebindable address from the answer, authority, and additional
/// sections: A/AAAA records are dropped whole, HTTPS/SVCB records lose their
/// rebindable `ipv4hint`/`ipv6hint` values. Records carrying no addressing stay
/// untouched.
/// DNSSEC proof/signature records in the answer section do not count as useful
/// answers for the NODATA decision: once the signed address RRset was modified,
/// the AD bit is cleared and orphan RRSIG/NSEC records must not keep a filtered
/// response cacheable.
pub fn filter_rebindable_records(msg: &mut Message) -> RebindingFilterResult {
    let mut result = RebindingFilterResult::default();
    filter_section(&mut msg.answers, true, &mut result);
    filter_section(&mut msg.authorities, false, &mut result);
    filter_section(&mut msg.additionals, false, &mut result);
    if result.changed() {
        msg.metadata.authentic_data = false;
    }
    result
}

fn filter_section(
    records: &mut Vec<Record>,
    count_useful_answers: bool,
    result: &mut RebindingFilterResult,
) {
    let original = std::mem::take(records);
    for mut rec in original {
        let useful_answer = count_useful_answers && is_useful_answer_record(&rec);
        if useful_answer {
            result.useful_answer_original += 1;
        }
        match filter_record(&mut rec) {
            RebindVerdict::Keep => {}
            RebindVerdict::Rewritten { stripped } => result.stripped_addresses += stripped,
            RebindVerdict::Drop { stripped } => {
                result.stripped_addresses += stripped;
                continue;
            }
        }
        if useful_answer {
            result.useful_answer_kept += 1;
        }
        records.push(rec);
    }
}

enum RebindVerdict {
    /// No rebindable address in this record.
    Keep,
    /// Rebindable addressing was removed in place and the rest of the record
    /// is still valid on its own.
    Rewritten { stripped: usize },
    /// The record cannot be made safe without breaking it, so it is removed.
    Drop { stripped: usize },
}

fn filter_record(rec: &mut Record) -> RebindVerdict {
    match &mut rec.data {
        RData::A(a) if ip_is_rebindable(&IpAddr::V4(a.0)) => RebindVerdict::Drop { stripped: 1 },
        RData::AAAA(aaaa) if ip_is_rebindable(&IpAddr::V6(aaaa.0)) => {
            RebindVerdict::Drop { stripped: 1 }
        }
        RData::HTTPS(https) => filter_svcb(&mut https.0),
        RData::SVCB(svcb) => filter_svcb(svcb),
        _ => RebindVerdict::Keep,
    }
}

/// RFC 9460 §7.3 `ipv4hint`/`ipv6hint` are connection targets, not metadata: a
/// client that trusts them dials the hinted address without ever querying
/// TargetName, so a public name can point browsers at loopback, LAN,
/// link-local, or ULA space while returning no A/AAAA record at all. The hints
/// are filtered exactly like address answers.
///
/// A hint key whose whole list was rebindable is removed. Under RFC 9460 §8
/// every key `mandatory` lists must also be present in the SvcParams, and a
/// client MUST reject the entire RRset when that is broken. Removing a key the
/// record declares mandatory would poison the record's siblings too, so the
/// record is dropped instead of rewritten.
fn filter_svcb(svcb: &mut SVCB) -> RebindVerdict {
    let mut stripped = 0usize;
    let mut removed_keys: Vec<SvcParamKey> = Vec::new();

    let original = std::mem::take(&mut svcb.svc_params);
    for (key, mut value) in original {
        let emptied = match &mut value {
            SvcParamValue::Ipv4Hint(hint) => {
                let before = hint.0.len();
                hint.0.retain(|a| !ip_is_rebindable(&IpAddr::V4(a.0)));
                stripped += before - hint.0.len();
                hint.0.is_empty()
            }
            SvcParamValue::Ipv6Hint(hint) => {
                let before = hint.0.len();
                hint.0.retain(|aaaa| !ip_is_rebindable(&IpAddr::V6(aaaa.0)));
                stripped += before - hint.0.len();
                hint.0.is_empty()
            }
            _ => false,
        };
        if emptied {
            removed_keys.push(key);
            continue;
        }
        svcb.svc_params.push((key, value));
    }

    if stripped == 0 {
        return RebindVerdict::Keep;
    }
    if svcb_mandatory_broken(&svcb.svc_params, &removed_keys) {
        return RebindVerdict::Drop { stripped };
    }
    RebindVerdict::Rewritten { stripped }
}

fn svcb_mandatory_broken(
    params: &[(SvcParamKey, SvcParamValue)],
    removed_keys: &[SvcParamKey],
) -> bool {
    if removed_keys.is_empty() {
        return false;
    }
    params.iter().any(|(_, value)| match value {
        SvcParamValue::Mandatory(mandatory) => mandatory
            .0
            .iter()
            .any(|required| removed_keys.contains(required)),
        _ => false,
    })
}

fn is_useful_answer_record(rec: &Record) -> bool {
    !matches!(
        rec.record_type(),
        RecordType::RRSIG
            | RecordType::NSEC
            | RecordType::NSEC3
            | RecordType::SIG
            | RecordType::OPT
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RData, Record};
    use std::str::FromStr;

    #[test]
    fn ipv4_private_ranges_rebindable() {
        assert!(ip_is_rebindable(&"10.0.0.1".parse().unwrap()));
        assert!(ip_is_rebindable(&"172.20.5.7".parse().unwrap()));
        assert!(ip_is_rebindable(&"192.168.1.1".parse().unwrap()));
        assert!(ip_is_rebindable(&"169.254.10.10".parse().unwrap()));
        assert!(ip_is_rebindable(&"127.0.0.1".parse().unwrap()));
        assert!(ip_is_rebindable(&"0.0.0.0".parse().unwrap()));
        assert!(ip_is_rebindable(&"255.255.255.255".parse().unwrap()));
        assert!(ip_is_rebindable(&"100.64.5.5".parse().unwrap()));
        assert!(ip_is_rebindable(&"100.127.255.254".parse().unwrap()));
    }

    #[test]
    fn ipv4_special_use_ranges_rebindable() {
        assert!(ip_is_rebindable(&"192.0.2.1".parse().unwrap()));
        assert!(ip_is_rebindable(&"198.51.100.1".parse().unwrap()));
        assert!(ip_is_rebindable(&"203.0.113.1".parse().unwrap()));
        assert!(ip_is_rebindable(&"198.18.0.1".parse().unwrap()));
        assert!(ip_is_rebindable(&"198.19.255.254".parse().unwrap()));
        assert!(ip_is_rebindable(&"240.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv4_public_allowed() {
        assert!(!ip_is_rebindable(&"8.8.8.8".parse().unwrap()));
        assert!(!ip_is_rebindable(&"1.1.1.1".parse().unwrap()));
        assert!(!ip_is_rebindable(&"93.184.216.34".parse().unwrap()));
        // Just below CGN space (100.64/10), so public.
        assert!(!ip_is_rebindable(&"100.63.255.254".parse().unwrap()));
    }

    #[test]
    fn ipv6_private_ranges_rebindable() {
        assert!(ip_is_rebindable(&"::1".parse().unwrap()));
        assert!(ip_is_rebindable(&"::".parse().unwrap()));
        assert!(ip_is_rebindable(&"fe80::1".parse().unwrap()));
        assert!(ip_is_rebindable(&"fc00::1".parse().unwrap()));
        assert!(ip_is_rebindable(&"fd12:3456::1".parse().unwrap()));
        assert!(ip_is_rebindable(&"febf:ffff::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_public_allowed() {
        assert!(!ip_is_rebindable(&"2001:db8::1".parse().unwrap()));
        assert!(!ip_is_rebindable(&"2606:4700:4700::1111".parse().unwrap()));
        // Just outside fc00::/7 and fe80::/10.
        assert!(!ip_is_rebindable(&"fbff:ffff::1".parse().unwrap()));
        assert!(!ip_is_rebindable(&"fec0::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_ipv6_private_is_rebindable() {
        assert!(ip_is_rebindable(&"::ffff:10.0.0.1".parse().unwrap()));
        assert!(ip_is_rebindable(&"::ffff:127.0.0.1".parse().unwrap()));
        assert!(ip_is_rebindable(&"::ffff:169.254.1.1".parse().unwrap()));
        assert!(ip_is_rebindable(&"::ffff:100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_ipv6_public_passes_through() {
        assert!(!ip_is_rebindable(&"::ffff:8.8.8.8".parse().unwrap()));
        assert!(!ip_is_rebindable(&"::ffff:93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn ipv6_6to4_private_embedded_ipv4_is_rebindable() {
        assert!(ip_is_rebindable(&"2002:0a00:0001::1".parse().unwrap()));
        assert!(ip_is_rebindable(&"2002:c0a8:0101::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_6to4_public_embedded_ipv4_passes_through() {
        assert!(!ip_is_rebindable(&"2002:0808:0808::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_nat64_private_embedded_ipv4_is_rebindable() {
        assert!(ip_is_rebindable(&"64:ff9b::0a00:0001".parse().unwrap()));
        assert!(ip_is_rebindable(&"64:ff9b::c0a8:0101".parse().unwrap()));
    }

    #[test]
    fn ipv6_nat64_public_embedded_ipv4_passes_through() {
        assert!(!ip_is_rebindable(&"64:ff9b::0808:0808".parse().unwrap()));
    }

    #[test]
    fn filter_strips_private_and_keeps_public() {
        let name = Name::from_str("example.com.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::A(A("10.0.0.1".parse().unwrap())),
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::A(A("93.184.216.34".parse().unwrap())),
        ));
        msg.add_answer(Record::from_rdata(
            name,
            60,
            RData::AAAA(AAAA("::1".parse().unwrap())),
        ));
        let result = filter_rebindable_records(&mut msg);
        assert_eq!(result.useful_answer_original, 3);
        assert_eq!(result.useful_answer_kept, 1);
        assert_eq!(result.stripped_addresses, 2);
        assert_eq!(msg.answers.len(), 1);
    }

    #[test]
    fn filter_keeps_cname_untouched() {
        // CNAME chains are not blocked directly. The downstream resolver
        // re-queries the target and the filter applies there.
        let name = Name::from_str("alias.example.").unwrap();
        let target = Name::from_str("real.example.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(Record::from_rdata(
            name,
            60,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(target)),
        ));
        let result = filter_rebindable_records(&mut msg);
        assert_eq!(result.useful_answer_original, 1);
        assert_eq!(result.useful_answer_kept, 1);
        assert!(!result.all_useful_answers_stripped());
    }

    #[test]
    fn filter_strips_additional_private_addresses_and_clears_ad() {
        let name = Name::from_str("service.example.").unwrap();
        let mut msg = Message::query();
        msg.metadata.authentic_data = true;
        msg.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::MX(hickory_proto::rr::rdata::MX::new(
                10,
                Name::from_str("mail.example.").unwrap(),
            )),
        ));
        msg.add_additional(Record::from_rdata(
            name,
            60,
            RData::A(A("192.168.1.10".parse().unwrap())),
        ));

        let result = filter_rebindable_records(&mut msg);

        assert_eq!(result.stripped_addresses, 1);
        assert_eq!(result.useful_answer_original, 1);
        assert_eq!(result.useful_answer_kept, 1);
        assert_eq!(msg.additionals.len(), 0);
        assert!(!msg.metadata.authentic_data);
    }

    fn svcb_record(name: &Name, params: Vec<(SvcParamKey, SvcParamValue)>) -> Record {
        Record::from_rdata(
            name.clone(),
            60,
            RData::HTTPS(hickory_proto::rr::rdata::HTTPS(SVCB::new(
                1,
                Name::from_str("target.example.").unwrap(),
                params,
            ))),
        )
    }

    fn https_params(msg: &Message) -> &[(SvcParamKey, SvcParamValue)] {
        match &msg.answers[0].data {
            RData::HTTPS(https) => &https.0.svc_params,
            other => panic!("expected HTTPS record, got {other:?}"),
        }
    }

    #[test]
    fn https_hints_lose_only_the_rebindable_addresses() {
        use hickory_proto::rr::rdata::svcb::IpHint;

        let name = Name::from_str("cdn.example.").unwrap();
        let mut msg = Message::query();
        msg.metadata.authentic_data = true;
        msg.add_answer(svcb_record(
            &name,
            vec![
                (SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn),
                (
                    SvcParamKey::Ipv4Hint,
                    SvcParamValue::Ipv4Hint(IpHint(vec![
                        A("192.168.1.5".parse().unwrap()),
                        A("93.184.216.34".parse().unwrap()),
                    ])),
                ),
                (
                    SvcParamKey::Ipv6Hint,
                    SvcParamValue::Ipv6Hint(IpHint(vec![AAAA("::1".parse().unwrap())])),
                ),
            ],
        ));

        let result = filter_rebindable_records(&mut msg);

        assert_eq!(result.stripped_addresses, 2);
        assert_eq!(result.useful_answer_kept, 1);
        assert!(!result.all_useful_answers_stripped());
        assert!(!msg.metadata.authentic_data);
        let params = https_params(&msg);
        assert_eq!(params.len(), 2, "the emptied ipv6hint key must be removed");
        assert!(params.iter().all(|(key, _)| *key != SvcParamKey::Ipv6Hint));
        match &params[1] {
            (SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(hint)) => {
                assert_eq!(hint.0, vec![A("93.184.216.34".parse().unwrap())]);
            }
            other => panic!("expected the surviving ipv4hint, got {other:?}"),
        }
    }

    #[test]
    fn svcb_record_is_dropped_when_mandatory_names_a_removed_hint() {
        use hickory_proto::rr::rdata::svcb::{IpHint, Mandatory};

        let name = Name::from_str("cdn.example.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(svcb_record(
            &name,
            vec![
                (
                    SvcParamKey::Mandatory,
                    SvcParamValue::Mandatory(Mandatory(vec![SvcParamKey::Ipv4Hint])),
                ),
                (
                    SvcParamKey::Ipv4Hint,
                    SvcParamValue::Ipv4Hint(IpHint(vec![A("10.0.0.1".parse().unwrap())])),
                ),
            ],
        ));

        let result = filter_rebindable_records(&mut msg);

        assert_eq!(result.stripped_addresses, 1);
        assert!(result.all_useful_answers_stripped());
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn svcb_record_survives_when_mandatory_names_a_surviving_hint() {
        use hickory_proto::rr::rdata::svcb::{IpHint, Mandatory};

        let name = Name::from_str("cdn.example.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(svcb_record(
            &name,
            vec![
                (
                    SvcParamKey::Mandatory,
                    SvcParamValue::Mandatory(Mandatory(vec![SvcParamKey::Ipv4Hint])),
                ),
                (
                    SvcParamKey::Ipv4Hint,
                    SvcParamValue::Ipv4Hint(IpHint(vec![
                        A("10.0.0.1".parse().unwrap()),
                        A("93.184.216.34".parse().unwrap()),
                    ])),
                ),
            ],
        ));

        let result = filter_rebindable_records(&mut msg);

        assert_eq!(result.stripped_addresses, 1);
        assert_eq!(msg.answers.len(), 1);
        let params = https_params(&msg);
        match &params[1] {
            (SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(hint)) => {
                assert_eq!(hint.0, vec![A("93.184.216.34".parse().unwrap())]);
            }
            other => panic!("expected the surviving ipv4hint, got {other:?}"),
        }
    }

    #[test]
    fn public_only_https_hints_are_untouched() {
        use hickory_proto::rr::rdata::svcb::IpHint;

        let name = Name::from_str("cdn.example.").unwrap();
        let mut msg = Message::query();
        msg.metadata.authentic_data = true;
        msg.add_answer(svcb_record(
            &name,
            vec![(
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A("93.184.216.34".parse().unwrap())])),
            )],
        ));

        let result = filter_rebindable_records(&mut msg);

        assert!(!result.changed());
        assert!(msg.metadata.authentic_data);
        assert_eq!(https_params(&msg).len(), 1);
    }

    #[test]
    fn dnssec_signature_does_not_keep_filtered_address_useful() {
        use hickory_proto::dnssec::rdata::{DNSSECRData, SigInput, RRSIG};
        use hickory_proto::dnssec::Algorithm;
        use hickory_proto::rr::SerialNumber;

        let name = Name::from_str("signed.example.").unwrap();
        let mut msg = Message::query();
        msg.metadata.authentic_data = true;
        msg.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::A(A("10.0.0.1".parse().unwrap())),
        ));
        let sig_input = SigInput {
            type_covered: RecordType::A,
            algorithm: Algorithm::RSASHA256,
            num_labels: 2,
            original_ttl: 60,
            sig_expiration: SerialNumber::from(0),
            sig_inception: SerialNumber::from(0),
            key_tag: 0,
            signer_name: Name::root(),
        };
        msg.add_answer(Record::from_rdata(
            name,
            60,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(sig_input, vec![]))),
        ));

        let result = filter_rebindable_records(&mut msg);

        assert!(result.all_useful_answers_stripped());
        assert_eq!(result.useful_answer_original, 1);
        assert_eq!(result.useful_answer_kept, 0);
        assert_eq!(msg.answers.len(), 1, "RRSIG may remain, but is not useful");
        assert!(!msg.metadata.authentic_data);
    }
}
