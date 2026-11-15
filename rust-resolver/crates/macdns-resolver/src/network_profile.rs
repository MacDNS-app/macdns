// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! Per-network profile: the facts the host publishes on every network change
//! and the NAT64 status the resolver derives from them.
//!
//! Every snapshot starts a new generation and resets NAT64 to `Unknown`, so a
//! prefix learned on the previous network is never applied on the next one.
//! Discovery (RFC 7050) then asks the network's own resolvers for
//! `ipv4only.arpa` AAAA. Until a generation's discovery answers, and once a
//! discovered prefix outlives its TTL without revalidation, the resolver
//! behaves exactly as it does on a network without NAT64.

use crate::dns64::{prefixes_from_ipv4only_answers, Nat64Prefix, IPV4ONLY_ARPA};
use arc_swap::ArcSwap;
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use serde::Deserialize;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

const DNS_PORT: u16 = 53;
const MAX_RESOLVERS: usize = 8;
const MAX_INTERFACE_NAME_LEN: usize = 32;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Requery bounds (RFC 7050 §3). A positive answer is revalidated
/// `REVALIDATE_AHEAD` before its TTL ends, at most every `MIN_POSITIVE_REQUERY`
/// so a tiny TTL cannot become a query loop, and at least every
/// `MAX_POSITIVE_REQUERY` so a huge TTL cannot hide a silent change. A negative
/// answer is never asked again before its TTL, and not more often than
/// `MIN_NEGATIVE_REQUERY`.
const REVALIDATE_AHEAD: Duration = Duration::from_secs(10);
const MIN_POSITIVE_REQUERY: Duration = Duration::from_secs(5);
const MAX_POSITIVE_REQUERY: Duration = Duration::from_secs(3600);
const MIN_NEGATIVE_REQUERY: Duration = Duration::from_secs(60);
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(30);
/// Upper bound on the prefixes used for synthesis. RFC 7050 §3 asks for all of
/// them. The bound keeps a hostile network from multiplying every answer.
const MAX_PREFIXES: usize = 4;

/// Wire shape of `dns_apply_network_snapshot`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotRecord {
    ipv4: bool,
    ipv6: bool,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    interface_index: u32,
    #[serde(default)]
    resolvers: Vec<String>,
}

/// Validated network facts for one attachment of the primary interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkSnapshot {
    pub ipv4: bool,
    pub ipv6: bool,
    pub interface: String,
    pub resolvers: Vec<SocketAddr>,
}

impl NetworkSnapshot {
    /// Parses and validates the host's JSON. Resolver addresses come from
    /// unauthenticated DHCP/RA data, so anything that cannot be a unicast DNS
    /// server is rejected, and an IPv6 link-local server needs the interface
    /// index to be reachable at all.
    pub fn from_json(raw: &str) -> Result<Self, String> {
        let record: SnapshotRecord =
            serde_json::from_str(raw).map_err(|e| format!("invalid json: {e}"))?;
        if record.interface.len() > MAX_INTERFACE_NAME_LEN
            || !record.interface.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return Err("invalid interface name".into());
        }
        if record.resolvers.len() > MAX_RESOLVERS {
            return Err(format!("more than {MAX_RESOLVERS} resolvers"));
        }
        let mut resolvers: Vec<SocketAddr> = Vec::with_capacity(record.resolvers.len());
        for raw_ip in &record.resolvers {
            let ip: IpAddr = raw_ip
                .parse()
                .map_err(|_| format!("invalid resolver address {raw_ip:?}"))?;
            let addr = resolver_socket_addr(ip, record.interface_index)?;
            if !resolvers.contains(&addr) {
                resolvers.push(addr);
            }
        }
        Ok(Self {
            ipv4: record.ipv4,
            ipv6: record.ipv6,
            interface: record.interface,
            resolvers,
        })
    }
}

fn resolver_socket_addr(ip: IpAddr, interface_index: u32) -> Result<SocketAddr, String> {
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(format!("{ip} cannot be a DNS server"));
    }
    match ip {
        IpAddr::V4(v4) if v4.is_broadcast() => Err(format!("{ip} cannot be a DNS server")),
        IpAddr::V6(v6) if is_link_local(&v6) => {
            if interface_index == 0 {
                return Err(format!("link-local resolver {ip} needs an interface index"));
            }
            Ok(SocketAddr::V6(SocketAddrV6::new(
                v6,
                DNS_PORT,
                0,
                interface_index,
            )))
        }
        _ => Ok(SocketAddr::new(ip, DNS_PORT)),
    }
}

fn is_link_local(v6: &Ipv6Addr) -> bool {
    v6.segments()[0] & 0xffc0 == 0xfe80
}

/// The NAT64 translators confirmed for the current network, in the order the
/// network's DNS64 announced them, valid until the discovery answer's TTL ends
/// (RFC 7050 §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nat64Active {
    pub prefixes: Vec<Nat64Prefix>,
    pub expires_at: Instant,
}

impl Nat64Active {
    /// The longest TTL a record built from these prefixes may carry: it must
    /// never outlive the prefixes themselves.
    pub fn remaining_ttl_secs(&self, now: Instant) -> u32 {
        let remaining = self.expires_at.saturating_duration_since(now).as_secs();
        u32::try_from(remaining).unwrap_or(u32::MAX)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nat64Status {
    /// Discovery for the current generation has not answered yet, or the
    /// prefixes it found lapsed without revalidation.
    Unknown,
    /// The network's resolvers answered without a NAT64 address.
    Absent,
    Present {
        active: Nat64Active,
        resolver: SocketAddr,
    },
}

#[derive(Debug)]
struct ProfileState {
    generation: u64,
    snapshot: Option<NetworkSnapshot>,
    nat64: Nat64Status,
}

pub struct NetworkProfileStore {
    state: ArcSwap<ProfileState>,
    discovery: Mutex<Option<CancellationToken>>,
}

impl Default for NetworkProfileStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkProfileStore {
    pub fn new() -> Self {
        Self {
            state: ArcSwap::from_pointee(ProfileState {
                generation: 0,
                snapshot: None,
                nat64: Nat64Status::Unknown,
            }),
            discovery: Mutex::new(None),
        }
    }

    /// The prefixes to synthesize with at `now`, or `None` when this network
    /// has no confirmed NAT64 or its prefixes lapsed. Hot path: one atomic
    /// load.
    pub fn active_nat64(&self, now: Instant) -> Option<Nat64Active> {
        match &self.state.load().nat64 {
            Nat64Status::Present { active, .. } if now < active.expires_at => Some(active.clone()),
            _ => None,
        }
    }

    pub fn nat64_status(&self) -> Nat64Status {
        self.state.load().nat64.clone()
    }

    /// Ends the current generation without starting discovery, for a snapshot
    /// the resolver refused. NAT64 stays off until the next valid snapshot.
    pub fn invalidate(&self) {
        let (_, token) = self.begin(None);
        token.cancel();
    }

    /// Starts a new generation for `snapshot`: NAT64 drops to `Unknown` at
    /// once, and any discovery still running for an older generation is
    /// cancelled. Returns the generation and the token its discovery must
    /// honour.
    fn begin(&self, snapshot: Option<NetworkSnapshot>) -> (u64, CancellationToken) {
        let mut discovery = self
            .discovery
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(previous) = discovery.take() {
            previous.cancel();
        }
        let token = CancellationToken::new();
        *discovery = Some(token.clone());
        let generation = self.state.load().generation.wrapping_add(1);
        self.state.store(Arc::new(ProfileState {
            generation,
            snapshot,
            nat64: Nat64Status::Unknown,
        }));
        (generation, token)
    }

    /// Publishes `nat64` only while `generation` is still current, so a slow
    /// answer from the previous network can never land on the next one.
    /// Returns the previous status when the publish took effect.
    fn publish_if_current(&self, generation: u64, nat64: Nat64Status) -> Option<Nat64Status> {
        let mut previous = None;
        self.state.rcu(|current| {
            if current.generation != generation {
                previous = None;
                return Arc::clone(current);
            }
            previous = Some(current.nat64.clone());
            Arc::new(ProfileState {
                generation,
                snapshot: current.snapshot.clone(),
                nat64: nat64.clone(),
            })
        });
        previous
    }

    /// Moves a `Present` status whose prefixes already expired back to
    /// `Unknown`. Returns whether it did.
    fn lapse_if_expired(&self, generation: u64, now: Instant) -> bool {
        let expired = matches!(
            &self.state.load().nat64,
            Nat64Status::Present { active, .. } if now >= active.expires_at
        );
        expired
            && self
                .publish_if_current(generation, Nat64Status::Unknown)
                .is_some()
    }

    #[cfg(test)]
    pub(crate) fn set_nat64_for_test(&self, nat64: Nat64Status) {
        let generation = self.state.load().generation;
        self.publish_if_current(generation, nat64);
    }

    fn describe(&self) -> String {
        let state = self.state.load();
        let nat64 = match &state.nat64 {
            Nat64Status::Unknown => "unknown".to_string(),
            Nat64Status::Absent => "absent".to_string(),
            Nat64Status::Present { active, resolver } => format!(
                "{} via {} ttl={}s",
                active
                    .prefixes
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                resolver,
                active.remaining_ttl_secs(Instant::now())
            ),
        };
        match &state.snapshot {
            Some(s) => format!(
                "gen={} interface={} ipv4={} ipv6={} resolvers={} nat64={}",
                state.generation,
                if s.interface.is_empty() {
                    "-"
                } else {
                    &s.interface
                },
                s.ipv4,
                s.ipv6,
                s.resolvers.len(),
                nat64
            ),
            None => format!("gen={} nat64={}", state.generation, nat64),
        }
    }
}

/// Applies a host snapshot and starts NAT64 discovery for it on the resolver
/// runtime.
pub fn apply_snapshot(
    store: &Arc<NetworkProfileStore>,
    snapshot: NetworkSnapshot,
) -> Result<(), String> {
    let resolvers = snapshot.resolvers.clone();
    let (generation, token) = store.begin(Some(snapshot));
    log::info!("network profile {}", store.describe());
    if resolvers.is_empty() {
        store.publish_if_current(generation, Nat64Status::Absent);
        return Ok(());
    }
    let store = Arc::clone(store);
    crate::runtime::spawn(async move {
        tokio::select! {
            _ = token.cancelled() => {}
            _ = run_discovery(&store, generation, &resolvers) => {}
        }
    })
    .map(|_| ())
}

async fn run_discovery(store: &NetworkProfileStore, generation: u64, resolvers: &[SocketAddr]) {
    loop {
        let outcome = discover(resolvers, QUERY_TIMEOUT).await;
        match &outcome {
            DiscoveryOutcome::Present {
                prefixes,
                resolver,
                ttl,
            } => {
                let now = Instant::now();
                let expires_at = now.checked_add(*ttl).unwrap_or(now + MAX_POSITIVE_REQUERY);
                publish_and_log(
                    store,
                    generation,
                    Nat64Status::Present {
                        active: Nat64Active {
                            prefixes: prefixes.clone(),
                            expires_at,
                        },
                        resolver: *resolver,
                    },
                )
            }
            DiscoveryOutcome::Absent { .. } => {
                publish_and_log(store, generation, Nat64Status::Absent)
            }
            // A failed revalidation keeps prefixes only while their TTL lasts.
            // `active_nat64` stops handing them out once it ends, and the
            // status follows here so the log tells the same story.
            DiscoveryOutcome::Failed => {
                log::info!(
                    "NAT64 discovery got no usable answer from {} resolver(s), retrying in {}s",
                    resolvers.len(),
                    RETRY_AFTER_FAILURE.as_secs()
                );
                if store.lapse_if_expired(generation, Instant::now()) {
                    log::info!("network profile {} (NAT64 prefix lapsed)", store.describe());
                }
            }
        }
        tokio::time::sleep(next_discovery_in(&outcome)).await;
    }
}

/// When to ask again (RFC 7050 §3): ten seconds before a positive answer
/// expires, never before a negative answer's TTL has passed, and soon after a
/// failure. See the requery constants for the bounds.
fn next_discovery_in(outcome: &DiscoveryOutcome) -> Duration {
    match outcome {
        DiscoveryOutcome::Present { ttl, .. } => ttl
            .saturating_sub(REVALIDATE_AHEAD)
            .clamp(MIN_POSITIVE_REQUERY, MAX_POSITIVE_REQUERY),
        DiscoveryOutcome::Absent { ttl } => (*ttl).max(MIN_NEGATIVE_REQUERY),
        DiscoveryOutcome::Failed => RETRY_AFTER_FAILURE,
    }
}

fn publish_and_log(store: &NetworkProfileStore, generation: u64, nat64: Nat64Status) {
    if let Some(previous) = store.publish_if_current(generation, nat64.clone()) {
        if previous != nat64 {
            log::info!("network profile {}", store.describe());
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DiscoveryOutcome {
    Present {
        prefixes: Vec<Nat64Prefix>,
        resolver: SocketAddr,
        ttl: Duration,
    },
    /// `ttl` is how long the negative answer stays valid.
    Absent {
        ttl: Duration,
    },
    Failed,
}

/// Asks every resolver in parallel. Any NAT64 answer wins. Otherwise one
/// definite answer without NAT64 (NOERROR or NXDOMAIN) is enough for `Absent`.
/// Silence and error rcodes alone are `Failed`.
async fn discover(resolvers: &[SocketAddr], timeout: Duration) -> DiscoveryOutcome {
    let mut pending: FuturesUnordered<_> = resolvers
        .iter()
        .map(|&resolver| async move { (resolver, query_ipv4only(resolver, timeout).await) })
        .collect();
    // `Some` once any resolver answered definitively: the shortest negative
    // TTL among them, `None` inside when an answer carried no SOA.
    let mut negative: Option<Option<u32>> = None;
    while let Some((resolver, result)) = pending.next().await {
        match result {
            Ok(answer) => {
                let addrs: Vec<Ipv6Addr> = answer.aaaa.iter().map(|(addr, _)| *addr).collect();
                let mut prefixes = prefixes_from_ipv4only_answers(&addrs);
                if !prefixes.is_empty() {
                    if prefixes.len() > MAX_PREFIXES {
                        log::info!(
                            "NAT64 discovery via {resolver}: using the first {MAX_PREFIXES} of {} prefixes",
                            prefixes.len()
                        );
                        prefixes.truncate(MAX_PREFIXES);
                    }
                    let ttl = answer.aaaa.iter().map(|(_, ttl)| *ttl).min().unwrap_or(0);
                    return DiscoveryOutcome::Present {
                        prefixes,
                        resolver,
                        ttl: Duration::from_secs(u64::from(ttl)),
                    };
                }
                negative = Some(match (negative.flatten(), answer.negative_ttl) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                });
            }
            Err(e) => log::debug!("NAT64 discovery via {resolver} failed: {e}"),
        }
    }
    match negative {
        Some(ttl) => DiscoveryOutcome::Absent {
            ttl: ttl.map_or(MIN_NEGATIVE_REQUERY, |secs| {
                Duration::from_secs(u64::from(secs))
            }),
        },
        None => DiscoveryOutcome::Failed,
    }
}

/// A definitive answer to the `ipv4only.arpa` AAAA query.
struct Ipv4onlyAnswer {
    aaaa: Vec<(Ipv6Addr, u32)>,
    /// RFC 2308 negative TTL, when the answer carried an SOA.
    negative_ttl: Option<u32>,
}

/// One RFC 7050 query: `ipv4only.arpa` AAAA over UDP, retried over TCP when the
/// answer is truncated. Only NOERROR and NXDOMAIN count as answers.
async fn query_ipv4only(resolver: SocketAddr, timeout: Duration) -> Result<Ipv4onlyAnswer, String> {
    let id: u16 = rand::random();
    let request = build_query(id)?;
    let response = tokio::time::timeout(timeout, exchange_udp(resolver, &request))
        .await
        .map_err(|_| "udp timeout".to_string())??;
    let response = if response.metadata.truncation {
        tokio::time::timeout(timeout, exchange_tcp(resolver, &request))
            .await
            .map_err(|_| "tcp timeout".to_string())??
    } else {
        response
    };
    validate_response(&response, id)?;
    Ok(Ipv4onlyAnswer {
        aaaa: response
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::AAAA(aaaa) => Some((aaaa.0, r.ttl)),
                _ => None,
            })
            .collect(),
        negative_ttl: response.authorities.iter().find_map(|r| match &r.data {
            RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
            _ => None,
        }),
    })
}

fn ipv4only_name() -> Name {
    Name::from_ascii(format!("{IPV4ONLY_ARPA}.")).expect("static name is valid")
}

fn build_query(id: u16) -> Result<Vec<u8>, String> {
    let mut message = Message::query();
    message.metadata.id = id;
    message.metadata.recursion_desired = true;
    let mut query = Query::new();
    query
        .set_name(ipv4only_name())
        .set_query_type(RecordType::AAAA);
    message.add_query(query);
    message.to_bytes().map_err(|e| e.to_string())
}

fn validate_response(response: &Message, id: u16) -> Result<(), String> {
    if response.metadata.id != id || response.metadata.message_type != MessageType::Response {
        return Err("unexpected response id or type".into());
    }
    let question_matches = response.queries.len() == 1
        && response.queries[0].query_type() == RecordType::AAAA
        && *response.queries[0].name() == ipv4only_name();
    if !question_matches {
        return Err("response question does not match".into());
    }
    match response.metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => Ok(()),
        other => Err(format!("rcode {other:?}")),
    }
}

async fn exchange_udp(resolver: SocketAddr, request: &[u8]) -> Result<Message, String> {
    let bind: SocketAddr = match resolver {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("static address"),
        SocketAddr::V6(_) => "[::]:0".parse().expect("static address"),
    };
    let socket = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    socket.connect(resolver).await.map_err(|e| e.to_string())?;
    socket.send(request).await.map_err(|e| e.to_string())?;
    let mut buf = [0u8; 4096];
    let len = socket.recv(&mut buf).await.map_err(|e| e.to_string())?;
    Message::from_bytes(&buf[..len]).map_err(|e| e.to_string())
}

async fn exchange_tcp(resolver: SocketAddr, request: &[u8]) -> Result<Message, String> {
    let mut stream = TcpStream::connect(resolver)
        .await
        .map_err(|e| e.to_string())?;
    let len = u16::try_from(request.len()).map_err(|_| "request too large".to_string())?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(request).await.map_err(|e| e.to_string())?;
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| e.to_string())?;
    Message::from_bytes(&buf).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::AAAA;
    use hickory_proto::rr::Record;
    use std::str::FromStr;
    use tokio::net::TcpListener;

    fn snapshot(resolvers: &[&str]) -> NetworkSnapshot {
        NetworkSnapshot {
            ipv4: true,
            ipv6: true,
            interface: "en0".into(),
            resolvers: resolvers.iter().map(|r| r.parse().unwrap()).collect(),
        }
    }

    fn wkp() -> Nat64Prefix {
        Nat64Prefix::new(Ipv6Addr::from_str("64:ff9b::").unwrap(), 96).unwrap()
    }

    fn present(prefixes: Vec<Nat64Prefix>, valid_for: Duration) -> Nat64Status {
        Nat64Status::Present {
            active: Nat64Active {
                prefixes,
                expires_at: Instant::now() + valid_for,
            },
            resolver: "172.20.10.1:53".parse().unwrap(),
        }
    }

    fn active_prefixes(store: &NetworkProfileStore) -> Option<Vec<Nat64Prefix>> {
        store.active_nat64(Instant::now()).map(|a| a.prefixes)
    }

    #[test]
    fn snapshot_json_scopes_link_local_resolvers_to_the_interface() {
        let parsed = NetworkSnapshot::from_json(
            r#"{"ipv4":true,"ipv6":true,"interface":"en0","interfaceIndex":11,
                "resolvers":["172.20.10.1","fe80::f004:e1ff:fe89:4364","2001:db8::53"]}"#,
        )
        .unwrap();
        assert_eq!(parsed.interface, "en0");
        assert_eq!(
            parsed.resolvers,
            vec![
                "172.20.10.1:53".parse::<SocketAddr>().unwrap(),
                SocketAddr::V6(SocketAddrV6::new(
                    "fe80::f004:e1ff:fe89:4364".parse().unwrap(),
                    53,
                    0,
                    11
                )),
                "[2001:db8::53]:53".parse::<SocketAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn snapshot_json_rejects_hostile_input() {
        let cases = [
            r#"{"ipv4":true,"ipv6":true,"resolvers":["fe80::1"]}"#,
            r#"{"ipv4":true,"ipv6":true,"resolvers":["0.0.0.0"]}"#,
            r#"{"ipv4":true,"ipv6":true,"resolvers":["255.255.255.255"]}"#,
            r#"{"ipv4":true,"ipv6":true,"resolvers":["ff02::fb"]}"#,
            r#"{"ipv4":true,"ipv6":true,"resolvers":["dns.example"]}"#,
            r#"{"ipv4":true,"ipv6":true,"interface":"en0;rm","resolvers":[]}"#,
            r#"{"ipv4":true,"ipv6":true,"resolvers":[],"extra":1}"#,
            r#"{"ipv4":true,"ipv6":true,"resolvers":["1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4","9.9.9.9","149.112.112.112","2.2.2.2","3.3.3.3","4.4.4.4"]}"#,
        ];
        for case in cases {
            assert!(NetworkSnapshot::from_json(case).is_err(), "{case}");
        }
    }

    #[test]
    fn snapshot_json_deduplicates_resolvers() {
        let parsed = NetworkSnapshot::from_json(
            r#"{"ipv4":true,"ipv6":false,"resolvers":["172.20.10.1","172.20.10.1"]}"#,
        )
        .unwrap();
        assert_eq!(parsed.resolvers.len(), 1);
    }

    #[test]
    fn a_new_generation_drops_the_previous_prefix_and_rejects_its_late_answer() {
        let store = NetworkProfileStore::new();
        let (first, _) = store.begin(Some(snapshot(&["172.20.10.1:53"])));
        let present = present(vec![wkp()], Duration::from_secs(300));
        assert_eq!(
            store.publish_if_current(first, present.clone()),
            Some(Nat64Status::Unknown)
        );
        assert_eq!(active_prefixes(&store), Some(vec![wkp()]));

        let (second, _) = store.begin(Some(snapshot(&["192.168.1.1:53"])));
        assert_eq!(store.nat64_status(), Nat64Status::Unknown);
        assert_eq!(active_prefixes(&store), None);

        assert_eq!(store.publish_if_current(first, present), None);
        assert_eq!(
            active_prefixes(&store),
            None,
            "stale generation must not publish"
        );

        store.publish_if_current(second, Nat64Status::Absent);
        assert_eq!(store.nat64_status(), Nat64Status::Absent);
    }

    /// A snapshot the resolver refuses still means the host moved on. Keeping
    /// the previous network's prefix would synthesize for a translator the
    /// current network may not have.
    #[test]
    fn invalidate_drops_the_prefix_and_stops_discovery() {
        let store = NetworkProfileStore::new();
        let (generation, token) = store.begin(Some(snapshot(&["172.20.10.1:53"])));
        store.publish_if_current(generation, present(vec![wkp()], Duration::from_secs(300)));

        store.invalidate();

        assert_eq!(active_prefixes(&store), None);
        assert!(token.is_cancelled());
        assert_eq!(
            store.publish_if_current(generation, Nat64Status::Absent),
            None,
            "the invalidated generation can no longer publish"
        );
    }

    /// RFC 7050 §3: a discovered prefix is only valid for the TTL of the answer
    /// that carried it. A failed revalidation must not stretch it.
    #[test]
    fn a_prefix_stops_being_active_when_its_ttl_ends() {
        let store = NetworkProfileStore::new();
        let (generation, _) = store.begin(Some(snapshot(&["172.20.10.1:53"])));
        store.publish_if_current(generation, present(vec![wkp()], Duration::from_secs(30)));
        let active = store
            .active_nat64(Instant::now())
            .expect("fresh prefix is active");
        assert!(active.remaining_ttl_secs(Instant::now()) <= 30);

        let later = Instant::now() + Duration::from_secs(31);
        assert_eq!(store.active_nat64(later), None);

        assert!(store.lapse_if_expired(generation, later));
        assert_eq!(store.nat64_status(), Nat64Status::Unknown);
        assert!(
            !store.lapse_if_expired(generation, later),
            "nothing left to lapse"
        );
    }

    #[test]
    fn a_new_generation_cancels_the_previous_discovery() {
        let store = NetworkProfileStore::new();
        let (_, first_token) = store.begin(Some(snapshot(&[])));
        let (_, second_token) = store.begin(Some(snapshot(&[])));
        assert!(first_token.is_cancelled());
        assert!(!second_token.is_cancelled());
    }

    /// Answers every UDP query with `answers` (AAAA addresses) or, when
    /// `truncate` is set, with an empty TC=1 reply.
    async fn fake_udp_resolver(answers: Vec<Ipv6Addr>, truncate: bool) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let mut reply = response_for(&request, if truncate { &[] } else { &answers });
                reply.metadata.truncation = truncate;
                socket
                    .send_to(&reply.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        addr
    }

    fn response_for(request: &Message, answers: &[Ipv6Addr]) -> Message {
        let mut reply = Message::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        reply.add_query(request.queries[0].clone());
        for addr in answers {
            reply.add_answer(Record::from_rdata(
                ipv4only_name(),
                300,
                RData::AAAA(AAAA(*addr)),
            ));
        }
        reply
    }

    /// Answers every UDP query with whatever `reply` builds from it.
    async fn fake_udp_responder<F>(reply: F) -> SocketAddr
    where
        F: Fn(&Message) -> Message + Send + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let wire = reply(&request).to_bytes().unwrap();
                socket.send_to(&wire, peer).await.unwrap();
            }
        });
        addr
    }

    fn nodata_with_soa(request: &Message, soa_ttl: u32, soa_minimum: u32) -> Message {
        let mut reply = response_for(request, &[]);
        let soa = hickory_proto::rr::rdata::SOA::new(
            Name::from_ascii("arpa.").unwrap(),
            Name::from_ascii("hostmaster.arpa.").unwrap(),
            1,
            3600,
            600,
            86400,
            soa_minimum,
        );
        reply.add_authority(Record::from_rdata(
            Name::from_ascii("arpa.").unwrap(),
            soa_ttl,
            RData::SOA(soa),
        ));
        reply
    }

    /// A resolver that fails the query says nothing about DNS64. Treating its
    /// empty SERVFAIL as "no NAT64" would turn synthesis off for the longest
    /// revalidation interval.
    #[tokio::test]
    async fn discovery_treats_an_error_rcode_as_no_answer() {
        for rcode in [ResponseCode::ServFail, ResponseCode::Refused] {
            let resolver = fake_udp_responder(move |request| {
                let mut reply = response_for(request, &[]);
                reply.metadata.response_code = rcode;
                reply
            })
            .await;
            assert_eq!(
                discover(&[resolver], Duration::from_secs(2)).await,
                DiscoveryOutcome::Failed,
                "{rcode:?}"
            );
        }
    }

    /// RFC 7050 §3: a negative answer is valid for its TTL, after which
    /// discovery may run again.
    #[tokio::test]
    async fn discovery_absent_carries_the_negative_ttl() {
        let resolver = fake_udp_responder(|request| nodata_with_soa(request, 30, 120)).await;
        assert_eq!(
            discover(&[resolver], Duration::from_secs(2)).await,
            DiscoveryOutcome::Absent {
                ttl: Duration::from_secs(30)
            }
        );

        let nxdomain = fake_udp_responder(|request| {
            let mut reply = nodata_with_soa(request, 900, 45);
            reply.metadata.response_code = ResponseCode::NXDomain;
            reply
        })
        .await;
        assert_eq!(
            discover(&[nxdomain], Duration::from_secs(2)).await,
            DiscoveryOutcome::Absent {
                ttl: Duration::from_secs(45)
            }
        );
    }

    #[test]
    fn next_discovery_follows_the_answer_ttl_within_bounds() {
        let present = |secs| DiscoveryOutcome::Present {
            prefixes: vec![wkp()],
            resolver: "172.20.10.1:53".parse().unwrap(),
            ttl: Duration::from_secs(secs),
        };
        // RFC 7050 §3: repeat ten seconds before the positive answer expires,
        // so revalidation lands before the prefix lapses.
        assert_eq!(next_discovery_in(&present(300)), Duration::from_secs(290));
        assert_eq!(next_discovery_in(&present(30)), Duration::from_secs(20));
        assert_eq!(next_discovery_in(&present(0)), MIN_POSITIVE_REQUERY);
        assert_eq!(next_discovery_in(&present(86_400)), MAX_POSITIVE_REQUERY);

        // A negative answer is never asked again before its TTL (MUST).
        let absent = |secs| DiscoveryOutcome::Absent {
            ttl: Duration::from_secs(secs),
        };
        assert_eq!(next_discovery_in(&absent(300)), Duration::from_secs(300));
        assert_eq!(next_discovery_in(&absent(30)), MIN_NEGATIVE_REQUERY);
        assert_eq!(
            next_discovery_in(&absent(86_400)),
            Duration::from_secs(86_400)
        );

        assert_eq!(
            next_discovery_in(&DiscoveryOutcome::Failed),
            RETRY_AFTER_FAILURE
        );
    }

    fn hotspot_answers() -> Vec<Ipv6Addr> {
        vec![
            Ipv6Addr::from_str("64:ff9b::c000:aa").unwrap(),
            Ipv6Addr::from_str("64:ff9b::c000:ab").unwrap(),
        ]
    }

    #[tokio::test]
    async fn discovery_finds_the_prefix_of_a_dns64_resolver() {
        let resolver = fake_udp_resolver(hotspot_answers(), false).await;
        assert_eq!(
            discover(&[resolver], Duration::from_secs(2)).await,
            DiscoveryOutcome::Present {
                prefixes: vec![wkp()],
                resolver,
                ttl: Duration::from_secs(300),
            }
        );
    }

    /// RFC 7050 §3: every announced prefix is used, in the order received.
    #[tokio::test]
    async fn discovery_keeps_every_prefix_in_order() {
        let nsp = Nat64Prefix::new(Ipv6Addr::from_str("2001:db8:64::").unwrap(), 96).unwrap();
        let answers = vec![
            nsp.synthesize(crate::dns64::IPV4ONLY_ARPA_ADDRS[0]),
            Ipv6Addr::from_str("64:ff9b::c000:aa").unwrap(),
            nsp.synthesize(crate::dns64::IPV4ONLY_ARPA_ADDRS[1]),
        ];
        let resolver = fake_udp_resolver(answers, false).await;
        assert!(matches!(
            discover(&[resolver], Duration::from_secs(2)).await,
            DiscoveryOutcome::Present { prefixes, .. } if prefixes == vec![nsp, wkp()]
        ));
    }

    #[tokio::test]
    async fn discovery_reports_absent_for_a_resolver_without_dns64() {
        let resolver = fake_udp_resolver(Vec::new(), false).await;
        assert_eq!(
            discover(&[resolver], Duration::from_secs(2)).await,
            DiscoveryOutcome::Absent {
                ttl: MIN_NEGATIVE_REQUERY
            }
        );
    }

    #[tokio::test]
    async fn discovery_reports_failed_when_no_resolver_answers() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = silent.local_addr().unwrap();
        assert_eq!(
            discover(&[resolver], Duration::from_millis(100)).await,
            DiscoveryOutcome::Failed
        );
    }

    #[tokio::test]
    async fn discovery_prefers_any_dns64_answer_over_a_plain_one() {
        let plain = fake_udp_resolver(Vec::new(), false).await;
        let dns64 = fake_udp_resolver(hotspot_answers(), false).await;
        assert!(matches!(
            discover(&[plain, dns64], Duration::from_secs(2)).await,
            DiscoveryOutcome::Present { resolver, .. } if resolver == dns64
        ));
    }

    #[tokio::test]
    async fn discovery_retries_a_truncated_answer_over_tcp() {
        let udp = fake_udp_resolver(Vec::new(), true).await;
        let listener = TcpListener::bind(udp).await.unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.unwrap();
            let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
            stream.read_exact(&mut buf).await.unwrap();
            let request = Message::from_bytes(&buf).unwrap();
            let reply = response_for(&request, &hotspot_answers())
                .to_bytes()
                .unwrap();
            stream
                .write_all(&(reply.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&reply).await.unwrap();
        });
        assert!(matches!(
            discover(&[udp], Duration::from_secs(2)).await,
            DiscoveryOutcome::Present { .. }
        ));
    }
}
