// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! DNS64 for networks whose own resolver synthesizes AAAA records.
//!
//! The attached network decides: when its resolver answers `ipv4only.arpa`
//! AAAA with a NAT64 address (RFC 7050), MacDNS synthesizes AAAA records for
//! IPv4-only names the same way (RFC 6147), so applications reach those names
//! through the network's NAT64 path instead of a possibly broken IPv4 path.
//!
//! Synthesis is a per-network view applied when a response is built. Its
//! output never enters the answer cache or the cache dump, so cached data stays
//! valid on every network.

use crate::rebinding::ip_is_rebindable;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::AAAA;
use hickory_proto::rr::{RData, Record, RecordType};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// RFC 6052 §2.2 prefix lengths, in the order RFC 7050 §3 scans them.
const VALID_PREFIX_LENGTHS: [u8; 6] = [96, 64, 56, 48, 40, 32];

/// RFC 6052 §2.2: bits 64 to 71 of every IPv4-embedded address are reserved.
const U_OCTET_INDEX: usize = 8;

/// RFC 7050 §2.2 / RFC 8880: the well-known IPv4-only addresses behind
/// `ipv4only.arpa`.
pub(crate) const IPV4ONLY_ARPA_ADDRS: [Ipv4Addr; 2] =
    [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

pub(crate) const IPV4ONLY_ARPA: &str = "ipv4only.arpa";

/// Upper bound for synthesized record TTLs. Bounds how long a downstream cache
/// (mDNSResponder) can keep a NAT64 address after the host leaves the network.
pub(crate) const SYNTHESIS_MAX_TTL_SECS: u32 = 300;

/// A NAT64 prefix with one of the RFC 6052 lengths. Bits past the prefix
/// length and the reserved u-octet are always zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nat64Prefix {
    octets: [u8; 16],
    len: u8,
}

impl Nat64Prefix {
    /// Returns `None` for a length RFC 6052 does not define, a non-zero
    /// u-octet in a /96, or a prefix inside address space that can never be a
    /// NAT64 translator (unspecified, IPv4-mapped, loopback, link-local,
    /// multicast).
    pub fn new(addr: Ipv6Addr, len: u8) -> Option<Self> {
        if !VALID_PREFIX_LENGTHS.contains(&len) {
            return None;
        }
        let mut octets = addr.octets();
        let prefix_octets = usize::from(len / 8);
        if prefix_octets > U_OCTET_INDEX && octets[U_OCTET_INDEX] != 0 {
            return None;
        }
        for octet in octets.iter_mut().skip(prefix_octets) {
            *octet = 0;
        }
        let network = Ipv6Addr::from(octets);
        if is_reserved_prefix_space(&network) {
            return None;
        }
        Some(Self { octets, len })
    }

    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    pub fn network(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.octets)
    }

    /// RFC 6052 §2.2 IPv4-embedded IPv6 address.
    pub fn synthesize(&self, v4: Ipv4Addr) -> Ipv6Addr {
        let mut out = self.octets;
        for (position, byte) in ipv4_positions(self.len).into_iter().zip(v4.octets()) {
            out[position] = byte;
        }
        Ipv6Addr::from(out)
    }

    /// Inverse of `synthesize`: the embedded IPv4 address when `v6` lies
    /// inside this prefix.
    pub fn extract(&self, v6: &Ipv6Addr) -> Option<Ipv4Addr> {
        let octets = v6.octets();
        let prefix_octets = usize::from(self.len / 8);
        if octets[..prefix_octets] != self.octets[..prefix_octets] {
            return None;
        }
        Some(embedded_ipv4(&octets, self.len))
    }
}

impl fmt::Display for Nat64Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.len)
    }
}

/// Octet positions of the embedded IPv4 address for a prefix length, skipping
/// the reserved u-octet.
fn ipv4_positions(len: u8) -> [usize; 4] {
    let mut positions = [0usize; 4];
    let mut next = usize::from(len / 8);
    for slot in positions.iter_mut() {
        if next == U_OCTET_INDEX {
            next += 1;
        }
        *slot = next;
        next += 1;
    }
    positions
}

fn embedded_ipv4(octets: &[u8; 16], len: u8) -> Ipv4Addr {
    let p = ipv4_positions(len);
    Ipv4Addr::new(octets[p[0]], octets[p[1]], octets[p[2]], octets[p[3]])
}

fn is_reserved_prefix_space(network: &Ipv6Addr) -> bool {
    let octets = network.octets();
    let segments = network.segments();
    // ::/96 (unspecified, loopback, IPv4-compatible) and ::ffff:0:0/96
    // (IPv4-mapped). The rest of ::/8 stays usable: 64:ff9b::/96 lives there.
    let compatible_or_mapped =
        octets[..10].iter().all(|&o| o == 0) && matches!(segments[5], 0 | 0xffff);
    compatible_or_mapped || segments[0] & 0xffc0 == 0xfe80 || segments[0] & 0xff00 == 0xff00
}

/// RFC 7050 §3: the NAT64 prefixes encoded in the network resolver's AAAA
/// answers for `ipv4only.arpa`, deduplicated, in answer order.
pub fn prefixes_from_ipv4only_answers(answers: &[Ipv6Addr]) -> Vec<Nat64Prefix> {
    let mut found: Vec<Nat64Prefix> = Vec::new();
    for answer in answers {
        let octets = answer.octets();
        for len in VALID_PREFIX_LENGTHS {
            if !IPV4ONLY_ARPA_ADDRS.contains(&embedded_ipv4(&octets, len)) {
                continue;
            }
            if let Some(prefix) = Nat64Prefix::new(*answer, len) {
                if !found.contains(&prefix) {
                    found.push(prefix);
                }
                break;
            }
        }
    }
    found
}

/// RFC 6052 §3.1 and RFC 6147 §5.1.4: only globally routable IPv4 addresses
/// are translated. Private and special-purpose space stays IPv4-only, so a
/// synthesized record can never point a client at a LAN address through the
/// translator.
fn is_synthesizable(v4: Ipv4Addr) -> bool {
    !v4.is_multicast() && !ip_is_rebindable(&IpAddr::V4(v4))
}

/// RFC 6147 §5.1.1: synthesis applies only to a successful AAAA response that
/// carries no AAAA record (NODATA, possibly after a CNAME chain). NXDOMAIN and
/// failures pass through unchanged.
pub(crate) fn needs_synthesis(aaaa_response: &Message) -> bool {
    aaaa_response.metadata.response_code == ResponseCode::NoError
        && aaaa_response
            .queries
            .first()
            .is_some_and(|q| q.query_type() == RecordType::AAAA)
        && !aaaa_response
            .answers
            .iter()
            .any(|r| r.record_type() == RecordType::AAAA)
}

/// RFC 6147 §5.1.7: the negative TTL of the AAAA NODATA bounds the synthesized
/// TTL, because the absence of AAAA data is only known for that long.
fn negative_ttl(aaaa_response: &Message) -> Option<u32> {
    aaaa_response
        .authorities
        .iter()
        .find_map(|r| match &r.data {
            RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
            _ => None,
        })
}

/// Builds the DNS64 answer to an AAAA NODATA from the A response for the same
/// name. The CNAME chain comes from the A response. Every globally routable A
/// record becomes one AAAA record per prefix under the same owner name, with a
/// TTL that never exceeds `max_ttl` (the prefixes' remaining validity). An A error
/// (SERVFAIL, NXDOMAIN, ...) becomes the answer to the AAAA question (RFC 6147
/// §5.1.6). Returns `None` when the A response is empty or holds nothing
/// translatable, so the caller keeps the original NODATA.
///
/// The result never sets AD because it is local data the upstream never signed
/// (RFC 6147 §5.5).
pub(crate) fn build_dns64_response(
    aaaa_response: &Message,
    a_response: &Message,
    prefixes: &[Nat64Prefix],
    max_ttl: u32,
) -> Option<Message> {
    if a_response.metadata.response_code != ResponseCode::NoError {
        return Some(error_for_aaaa_question(aaaa_response, a_response));
    }
    let ttl_cap = negative_ttl(aaaa_response)
        .unwrap_or(SYNTHESIS_MAX_TTL_SECS)
        .min(SYNTHESIS_MAX_TTL_SECS)
        .min(max_ttl);

    let mut answers: Vec<Record> = a_response
        .answers
        .iter()
        .filter(|r| matches!(r.data, RData::CNAME(_)))
        .map(|r| {
            let mut cname = r.clone();
            cname.ttl = cname.ttl.min(ttl_cap);
            cname
        })
        .collect();
    let chain_len = answers.len();
    // RFC 7050 §3: every prefix, in the order the network announced them.
    for prefix in prefixes {
        for record in &a_response.answers {
            if let RData::A(a) = &record.data {
                if is_synthesizable(a.0) {
                    answers.push(Record::from_rdata(
                        record.name.clone(),
                        record.ttl.min(ttl_cap),
                        RData::AAAA(AAAA(prefix.synthesize(a.0))),
                    ));
                }
            }
        }
    }
    if answers.len() == chain_len {
        return None;
    }

    let mut response = aaaa_response.clone();
    response.answers = answers;
    response.authorities.clear();
    response.additionals.clear();
    response.metadata.response_code = ResponseCode::NoError;
    response.metadata.authentic_data = false;
    Some(response)
}

/// The A error re-addressed to the client's AAAA question. Its EDNS (and with
/// it any Extended DNS Error) and its negative proof stay. A records cannot
/// answer an AAAA question and are dropped.
fn error_for_aaaa_question(aaaa_response: &Message, a_response: &Message) -> Message {
    let mut response = a_response.clone();
    response.metadata.id = aaaa_response.metadata.id;
    response.metadata.recursion_desired = aaaa_response.metadata.recursion_desired;
    response.metadata.checking_disabled = aaaa_response.metadata.checking_disabled;
    response.metadata.authentic_data = false;
    response.queries = aaaa_response.queries.clone();
    response
        .answers
        .retain(|r| r.record_type() != RecordType::A);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, CNAME, SOA};
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    fn v6(s: &str) -> Ipv6Addr {
        Ipv6Addr::from_str(s).unwrap()
    }

    fn v4(s: &str) -> Ipv4Addr {
        Ipv4Addr::from_str(s).unwrap()
    }

    fn wkp() -> Nat64Prefix {
        Nat64Prefix::new(v6("64:ff9b::"), 96).unwrap()
    }

    /// RFC 6052 §2.4 table: 192.0.2.33 embedded under 2001:db8:122:344::/N.
    #[test]
    fn synthesize_matches_rfc6052_examples_for_every_prefix_length() {
        let base = v6("2001:db8:122:344::");
        let ip = v4("192.0.2.33");
        let cases = [
            (32, "2001:db8:c000:221::"),
            (40, "2001:db8:1c0:2:21::"),
            (48, "2001:db8:122:c000:2:2100::"),
            (56, "2001:db8:122:3c0:0:221::"),
            (64, "2001:db8:122:344:c0:2:2100:0"),
            (96, "2001:db8:122:344::192.0.2.33"),
        ];
        for (len, expected) in cases {
            let prefix = Nat64Prefix::new(base, len).unwrap();
            let synthesized = prefix.synthesize(ip);
            assert_eq!(synthesized, v6(expected), "/{len}");
            assert_eq!(prefix.extract(&synthesized), Some(ip), "/{len} round trip");
        }
    }

    #[test]
    fn well_known_prefix_synthesizes_the_hotspot_answer() {
        assert_eq!(
            wkp().synthesize(v4("35.190.46.17")),
            v6("64:ff9b::23be:2e11")
        );
        assert_eq!(wkp().to_string(), "64:ff9b::/96");
    }

    #[test]
    fn extract_rejects_addresses_outside_the_prefix() {
        assert_eq!(wkp().extract(&v6("2001:db8::23be:2e11")), None);
    }

    #[test]
    fn new_rejects_invalid_lengths_and_reserved_space() {
        assert!(Nat64Prefix::new(v6("64:ff9b::"), 80).is_none());
        assert!(
            Nat64Prefix::new(v6("2001:db8:0:0:ff00::"), 96).is_none(),
            "u-octet set"
        );
        assert!(
            Nat64Prefix::new(v6("::ffff:0:0"), 96).is_none(),
            "IPv4-mapped"
        );
        assert!(Nat64Prefix::new(v6("fe80::"), 96).is_none(), "link-local");
        assert!(Nat64Prefix::new(v6("ff02::"), 96).is_none(), "multicast");
    }

    #[test]
    fn new_zeroes_bits_past_the_prefix_length() {
        let prefix = Nat64Prefix::new(v6("2001:db8:122:344:ff:1:2:3"), 64).unwrap();
        assert_eq!(prefix.network(), v6("2001:db8:122:344::"));
    }

    #[test]
    fn discovery_reads_the_well_known_prefix_from_ipv4only_answers() {
        let prefixes =
            prefixes_from_ipv4only_answers(&[v6("64:ff9b::c000:aa"), v6("64:ff9b::c000:ab")]);
        assert_eq!(prefixes, vec![wkp()]);
    }

    #[test]
    fn discovery_reads_network_specific_prefixes_of_any_length() {
        let nsp = Nat64Prefix::new(v6("2001:db8:122::"), 48).unwrap();
        let answer = nsp.synthesize(IPV4ONLY_ARPA_ADDRS[0]);
        assert_eq!(prefixes_from_ipv4only_answers(&[answer]), vec![nsp]);
    }

    #[test]
    fn discovery_ignores_answers_without_the_well_known_ipv4() {
        assert!(prefixes_from_ipv4only_answers(&[v6("2606:4700::6810:84e5")]).is_empty());
    }

    fn query_message(name: &str, qtype: RecordType) -> Message {
        let mut m = Message::new(0x1234, MessageType::Response, OpCode::Query);
        let mut q = Query::new();
        q.set_name(Name::from_str(name).unwrap())
            .set_query_type(qtype);
        m.add_query(q);
        m
    }

    fn nodata_aaaa(name: &str, soa_ttl: u32, soa_minimum: u32) -> Message {
        let mut m = query_message(name, RecordType::AAAA);
        let soa = SOA::new(
            Name::from_str("example.").unwrap(),
            Name::from_str("hostmaster.example.").unwrap(),
            1,
            3600,
            600,
            86400,
            soa_minimum,
        );
        m.add_authority(Record::from_rdata(
            Name::from_str("example.").unwrap(),
            soa_ttl,
            RData::SOA(soa),
        ));
        m
    }

    fn a_response(name: &str, records: &[(&str, u32, RData)]) -> Message {
        let mut m = query_message(name, RecordType::A);
        for (owner, ttl, data) in records {
            m.add_answer(Record::from_rdata(
                Name::from_str(owner).unwrap(),
                *ttl,
                data.clone(),
            ));
        }
        m
    }

    #[test]
    fn needs_synthesis_only_for_aaaa_nodata() {
        assert!(needs_synthesis(&nodata_aaaa("v4only.example.", 5, 5)));

        let mut nxdomain = nodata_aaaa("missing.example.", 5, 5);
        nxdomain.metadata.response_code = ResponseCode::NXDomain;
        assert!(!needs_synthesis(&nxdomain));

        let mut has_aaaa = query_message("dual.example.", RecordType::AAAA);
        has_aaaa.add_answer(Record::from_rdata(
            Name::from_str("dual.example.").unwrap(),
            60,
            RData::AAAA(AAAA(v6("2001:db8::1"))),
        ));
        assert!(!needs_synthesis(&has_aaaa));

        assert!(!needs_synthesis(&nodata_a_question()));
    }

    fn nodata_a_question() -> Message {
        query_message("v4only.example.", RecordType::A)
    }

    #[test]
    fn synthesis_keeps_the_cname_chain_and_bounds_the_ttl() {
        let aaaa = nodata_aaaa("www.example.", 30, 20);
        let a = a_response(
            "www.example.",
            &[
                (
                    "www.example.",
                    600,
                    RData::CNAME(CNAME(Name::from_str("edge.example.").unwrap())),
                ),
                ("edge.example.", 120, RData::A(A(v4("35.190.46.17")))),
            ],
        );
        let out =
            build_dns64_response(&aaaa, &a, &[wkp()], SYNTHESIS_MAX_TTL_SECS).expect("synthesized");

        assert_eq!(out.metadata.id, 0x1234);
        assert_eq!(out.queries[0].query_type(), RecordType::AAAA);
        assert_eq!(out.answers.len(), 2);
        assert_eq!(out.answers[0].record_type(), RecordType::CNAME);
        assert_eq!(out.answers[0].ttl, 20, "SOA minimum bounds the chain");
        assert_eq!(
            out.answers[1].name,
            Name::from_str("edge.example.").unwrap()
        );
        assert_eq!(
            out.answers[1].data,
            RData::AAAA(AAAA(v6("64:ff9b::23be:2e11")))
        );
        assert_eq!(out.answers[1].ttl, 20);
        assert!(out.authorities.is_empty());
        assert!(!out.metadata.authentic_data);
    }

    #[test]
    fn synthesis_without_soa_caps_the_ttl() {
        let aaaa = query_message("v4only.example.", RecordType::AAAA);
        let a = a_response(
            "v4only.example.",
            &[("v4only.example.", 86_400, RData::A(A(v4("8.8.8.8"))))],
        );
        let out = build_dns64_response(&aaaa, &a, &[wkp()], SYNTHESIS_MAX_TTL_SECS).unwrap();
        assert_eq!(out.answers[0].ttl, SYNTHESIS_MAX_TTL_SECS);
    }

    #[test]
    fn synthesis_uses_every_prefix_in_order() {
        let nsp = Nat64Prefix::new(v6("2001:db8:64::"), 96).unwrap();
        let aaaa = nodata_aaaa("multi.example.", 60, 60);
        let a = a_response(
            "multi.example.",
            &[("multi.example.", 60, RData::A(A(v4("35.190.46.17"))))],
        );
        let out = build_dns64_response(&aaaa, &a, &[nsp, wkp()], SYNTHESIS_MAX_TTL_SECS).unwrap();
        assert_eq!(
            out.answers
                .iter()
                .map(|r| r.data.clone())
                .collect::<Vec<_>>(),
            vec![
                RData::AAAA(AAAA(v6("2001:db8:64::23be:2e11"))),
                RData::AAAA(AAAA(v6("64:ff9b::23be:2e11"))),
            ]
        );
    }

    #[test]
    fn synthesis_never_outlives_the_prefix() {
        let aaaa = nodata_aaaa("v4only.example.", 300, 300);
        let a = a_response(
            "v4only.example.",
            &[("v4only.example.", 300, RData::A(A(v4("8.8.8.8"))))],
        );
        let out = build_dns64_response(&aaaa, &a, &[wkp()], 12).unwrap();
        assert_eq!(out.answers[0].ttl, 12);
    }

    #[test]
    fn synthesis_skips_private_and_special_ipv4() {
        let aaaa = nodata_aaaa("mixed.example.", 60, 60);
        let a = a_response(
            "mixed.example.",
            &[
                ("mixed.example.", 60, RData::A(A(v4("10.0.0.1")))),
                ("mixed.example.", 60, RData::A(A(v4("127.0.0.1")))),
                ("mixed.example.", 60, RData::A(A(v4("224.0.0.1")))),
                ("mixed.example.", 60, RData::A(A(v4("1.1.1.1")))),
            ],
        );
        let out = build_dns64_response(&aaaa, &a, &[wkp()], SYNTHESIS_MAX_TTL_SECS).unwrap();
        assert_eq!(out.answers.len(), 1);
        assert_eq!(
            out.answers[0].data,
            RData::AAAA(AAAA(v6("64:ff9b::101:101")))
        );
    }

    #[test]
    fn synthesis_returns_none_when_nothing_translates() {
        let aaaa = nodata_aaaa("lan.example.", 60, 60);
        let private_only = a_response(
            "lan.example.",
            &[("lan.example.", 60, RData::A(A(v4("192.168.1.10"))))],
        );
        assert!(
            build_dns64_response(&aaaa, &private_only, &[wkp()], SYNTHESIS_MAX_TTL_SECS).is_none()
        );

        let empty = a_response("lan.example.", &[]);
        assert!(build_dns64_response(&aaaa, &empty, &[wkp()], SYNTHESIS_MAX_TTL_SECS).is_none());
    }

    /// RFC 6147 §5.1.6: when the A query fails, that error answers the AAAA
    /// question. The NODATA would hand the client a negative it may cache for a
    /// name whose state is actually unknown.
    #[test]
    fn an_a_query_error_answers_the_aaaa_question() {
        let aaaa = nodata_aaaa("down.example.", 60, 60);
        for rcode in [ResponseCode::ServFail, ResponseCode::NXDomain] {
            let mut failed = a_response("down.example.", &[]);
            failed.metadata.response_code = rcode;
            failed.metadata.authentic_data = true;

            let out = build_dns64_response(&aaaa, &failed, &[wkp()], SYNTHESIS_MAX_TTL_SECS)
                .expect("error passes through");

            assert_eq!(out.metadata.response_code, rcode);
            assert_eq!(out.metadata.id, 0x1234);
            assert_eq!(out.queries.len(), 1);
            assert_eq!(out.queries[0].query_type(), RecordType::AAAA);
            assert!(!out.metadata.authentic_data);
        }
    }
}
