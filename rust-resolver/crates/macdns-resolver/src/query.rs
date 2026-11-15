// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use crate::blocklist::{decide, decide_with_match, BlockDecision};
use crate::cache::{
    cap_message_ttls, clamp_neg_ttl, clamp_ttl, CacheKey, CachedEntry, RefreshSource, RefreshState,
};
use crate::consensus::{evaluate, normalize_ips, Verdict};
use crate::hedge::{dispatch, HedgeError};
use crate::history::{LookupEvent, Route};
use crate::policy::RuntimePolicySnapshot;
use crate::probe;
use crate::state::{get_state, ModuleState};
use crate::stats::{counters, inc};
use dashmap::DashMap;
use hickory_proto::ProtoError;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::{ExtendedErrors, NetError};
use hickory_resolver::proto::op::{
    Edns, Message, MessageType, OpCode, Query as DnsQuery, ResponseCode,
};
use hickory_resolver::proto::rr::rdata::opt::EdnsOption;
use hickory_resolver::proto::rr::rdata::{A, AAAA, NS, SOA};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_resolver::proto::serialize::binary::{BinDecodable, BinEncodable, DecodeError};
use hickory_resolver::TokioResolver;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Semaphore};

/// RFC 8914 Extended DNS Error codes, only the ones MacDNS emits. Hickory has
/// no typed EDE option, so the wire payload (INFO-CODE u16 BE || EXTRA-TEXT
/// utf8) is built by hand into `EdnsOption::Unknown(15, …)`.
const EDE_OTHER: u16 = 0;
const EDE_STALE_ANSWER: u16 = 3;
const EDE_NOT_READY: u16 = 14;
const EDE_FILTERED: u16 = 17;
const EDE_NO_REACHABLE_AUTHORITY: u16 = 22;
const EDE_NETWORK_ERROR: u16 = 23;

/// Per-call wire transport. UDP carries the client's advertised EDNS payload
/// size, or 512 when the query had no OPT (RFC 1035 §4.2.1). TCP has no
/// per-message cap beyond the 64 KiB its 16-bit length prefix allows.
#[derive(Copy, Clone, Debug)]
pub(crate) enum Transport {
    Udp { client_payload_size: u16 },
    Tcp,
}

impl Transport {
    /// Bytes the wire response must fit into. `None` means no per-message cap.
    pub(crate) fn cap(&self) -> Option<usize> {
        match self {
            Transport::Udp {
                client_payload_size,
            } => Some(*client_payload_size as usize),
            Transport::Tcp => None,
        }
    }
}

struct RefreshStateGuard {
    state: Option<Arc<RefreshState>>,
}

impl RefreshStateGuard {
    fn new(state: Arc<RefreshState>) -> Self {
        Self { state: Some(state) }
    }

    fn transfer(&mut self) -> Self {
        Self {
            state: self.state.take(),
        }
    }
}

impl Drop for RefreshStateGuard {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            state.finish();
        }
    }
}

use tokio_util::sync::CancellationToken;

const PROBE_DOMAIN: &str = "_probe.macdns";
const PREFETCH_REMAINING_THRESHOLD_SECS: u64 = 10;
/// Prefetch skips entries unused for 4 hours, so refill traffic stays on names
/// the user still asks for. `cache_clock_secs()` counts from process start, so
/// nothing is pruned in the first 4 hours (`should_prefetch_entry_at` uses
/// `saturating_sub`). Keys in the history's popular set (`history::popular()`)
/// are exempt.
const PREFETCH_MAX_UNUSED_SECS: u64 = 4 * 60 * 60;
const PREFETCH_SCAN_INTERVAL_SECS: u64 = 1;
const PREFETCH_MAX_CONCURRENT: usize = 8;
const PREFETCH_MAX_PER_TICK: usize = 64;
const PREFETCH_MAX_INSPECTED_PER_TICK: usize = 4096;
const FORWARD_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

/// Limit on CNAME override hops. Stops user-made override cycles (alias →
/// alias, alias → alias2 → alias) from recursing forever. Only override-CNAME
/// hops bump `cname_depth`. External names resolved through the hedge do not.
const MAX_CNAME_CHAIN: u8 = 10;

/// How one question was answered: the history route, the DoH provider behind
/// the answer, the blocklist match, and the source `log_replies` prints.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplyOrigin {
    route: Route,
    /// The DoH provider whose answer this is. `None` for local, forwarded and
    /// failed answers.
    provider: Option<String>,
    /// `(matched rule, category tag)` of the blocklist entry that matched.
    block: Option<(String, String)>,
    /// What `log_replies` prints as the source. Separate from `provider`
    /// because the log names local routes and decorates provider names
    /// (`dns64:`, `(stale)`).
    log_source: Option<String>,
}

impl ReplyOrigin {
    fn local(route: Route, log_source: impl Into<String>) -> Self {
        Self {
            route,
            provider: None,
            block: None,
            log_source: Some(log_source.into()),
        }
    }

    fn upstream(route: Route, provider: String) -> Self {
        Self {
            route,
            provider: Some(provider.clone()),
            block: None,
            log_source: Some(provider),
        }
    }
}

/// Captive-portal probes and authenticated control challenges. Neither is a
/// client lookup. DNS names compare without case.
fn is_probe_name(domain_trim: &str) -> bool {
    const SUFFIX: &str = "._probe.macdns";
    domain_trim.eq_ignore_ascii_case(PROBE_DOMAIN)
        || domain_trim
            .len()
            .checked_sub(SUFFIX.len())
            .and_then(|start| domain_trim.get(start..))
            .is_some_and(|tail| tail.eq_ignore_ascii_case(SUFFIX))
}

/// Entry point for client lookups: raw DNS wire in, raw DNS wire out. Only
/// the UDP and TCP listeners call it, so every call is one client lookup and
/// is recorded in the history once.
pub(crate) async fn handle_wire(
    wire: &[u8],
    cancel: CancellationToken,
    transport: Transport,
) -> Vec<u8> {
    let cfg = crate::config::current();
    let started = Instant::now();
    let (resp, origin) = handle_wire_inner(wire, cancel, 0, transport, None).await;
    let latency = started.elapsed();
    if resp.is_empty() {
        return resp;
    }
    let Ok(msg) = Message::from_bytes(&resp) else {
        return resp;
    };
    if cfg.log_replies {
        log_reply(&msg, origin.log_source.as_deref());
    }
    record_lookup(&msg, origin, latency);
    resp
}

fn log_reply(msg: &Message, source: Option<&str>) {
    let Some(q) = msg.queries.first() else {
        return;
    };
    let domain = q.name().to_string();
    let domain_trim = domain.trim_end_matches('.');
    // Captive-portal probes and control challenges stay out of log_replies so
    // real traffic is not drowned.
    if is_probe_name(domain_trim) {
        return;
    }
    let qtype = format!("{:?}", q.query_type());
    let rcode = format!("{:?}", msg.metadata.response_code);
    let answers = msg.answers.len() as u32;
    let data = format_answers(&msg.answers);
    let prov = source.unwrap_or("unknown");
    // emit_reply (os.log `app.macdns.agent:dns`) is the only reply channel.
    // Logging through `:general` as well would duplicate every line.
    crate::log_hooks::emit_reply(&domain, &qtype, &rcode, answers, prov, &data);
}

/// Hands the lookup to the history. A reply without a question (a FORMERR
/// built from a request that never parsed) has no name to record.
fn record_lookup(msg: &Message, origin: ReplyOrigin, latency: Duration) {
    let Some(q) = msg.queries.first() else {
        return;
    };
    let name = q.name().to_lowercase().to_ascii();
    if is_probe_name(name.trim_end_matches('.')) {
        return;
    }
    let (block_rule, block_category) = origin.block.unwrap_or_default();
    crate::history::record(LookupEvent {
        ts: crate::history::unix_now(),
        name,
        qtype: u16::from(q.query_type()),
        rcode: u16::from(msg.metadata.response_code),
        answers: u16::try_from(msg.answers.len()).unwrap_or(u16::MAX),
        route: origin.route,
        provider: origin.provider.unwrap_or_default(),
        latency_us: u32::try_from(latency.as_micros()).unwrap_or(u32::MAX),
        block_rule,
        block_category,
    });
}

/// Best-effort one-line answer summary for logs. Formats
/// A/AAAA/CNAME/MX/TXT/NS/PTR/SOA/SRV and prints any other type in its debug
/// form.
fn format_answers(records: &[Record]) -> String {
    if records.is_empty() {
        return "[]".into();
    }
    let mut parts: Vec<String> = Vec::with_capacity(records.len());
    for rec in records {
        let ttl = rec.ttl;
        let ty = format!("{:?}", rec.record_type());
        let payload = match &rec.data {
            RData::A(v) => v.0.to_string(),
            RData::AAAA(v) => v.0.to_string(),
            RData::CNAME(v) => v.0.to_string(),
            RData::NS(v) => v.0.to_string(),
            RData::PTR(v) => v.0.to_string(),
            RData::MX(mx) => format!("{} {}", mx.preference, mx.exchange),
            RData::TXT(txt) => {
                let joined: Vec<String> = txt
                    .txt_data
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect();
                format!("\"{}\"", joined.join(" "))
            }
            RData::SRV(srv) => format!(
                "{} {} {} {}",
                srv.priority, srv.weight, srv.port, srv.target
            ),
            RData::SOA(soa) => format!("{} {}", soa.mname, soa.rname),
            other => format!("{:?}", other),
        };
        parts.push(format!("{}/{}/{}s", ty, payload, ttl));
    }
    format!("[{}]", parts.join(", "))
}

struct ParsedRequest {
    req: Message,
    tx_id: u16,
    name: Name,
    qtype: RecordType,
    domain_trim: String,
    client_edns: Option<Edns>,
}

enum RequestStart {
    Continue(ParsedRequest),
    Early {
        message: Message,
        client_edns: Option<Edns>,
        route: Route,
        reason: &'static str,
    },
    Empty,
}

enum PrePublicRoute {
    ForwardZone(crate::zones::ZoneEntry),
    CaptiveForward(Arc<crate::forward::ForwardResolver>),
    Localhost(Message),
    BuiltinZone(Message),
    CachedAncestorNxdomain(Message),
    None,
}

/// Resolution precedence before the public path (cache + DoH hedge), highest
/// first:
///
/// 1. Explicit user forward/stub zone (`state.json`).
/// 2. Captive-protected built-ins: `.onion` and the RFC 1918 reverses, names a
///    hotspot resolver can never answer legitimately.
/// 3. Ephemeral route published from the attached network's DHCP search
///    domains.
/// 4. RFC 6761 `localhost` synthesis.
/// 5. RFC 8880 `ipv4only.arpa`, answered from the attached network's NAT64
///    status (see `build_ipv4only_arpa_response`).
/// 6. Blanket captive forwarding.
/// 7. The remaining built-in special-use table (`resolver.arpa`, `.local`, the search-domain
///    suffixes, the other reverse zones), which yields to captive forwarding
///    because portal sign-in depends on the hotspot resolver answering them.
/// 8. RFC 8020 cached-ancestor NXDOMAIN, which is public-cache policy.
///
/// An ephemeral route outranks captive forwarding because it is the more
/// specific route to the same trust domain: both targets come from the very
/// same unauthenticated DHCP data of the attached network, and the private-use
/// suffix guard keeps `.local` and every public namespace out of the ephemeral
/// table. Ordering them the other way costs no portal compatibility and makes
/// the network's own private namespaces unresolvable for the whole duration of
/// captive forwarding.
///
/// `localhost` outranks captive forwarding because RFC 6761 6.3 forbids
/// resolving it against an authoritative server at all. Forwarding it to the
/// hotspot would let the portal answer with a routable address and capture
/// traffic an application assumed was loopback-only.
async fn select_pre_public_route(
    state: &ModuleState,
    policy: &RuntimePolicySnapshot,
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    request: &Message,
    domain_trim: &str,
) -> PrePublicRoute {
    if let Some(entry) = policy.zones.entry_for(domain_trim) {
        return PrePublicRoute::ForwardZone(entry);
    }
    if let Some(apex) = state.local_zones.lookup_built_in_protected(domain_trim) {
        return PrePublicRoute::BuiltinZone(build_builtin_zone_response(
            tx_id,
            name,
            qtype,
            request,
            apex,
            domain_trim,
        ));
    }
    if let Some(entry) = state.ephemeral_zones.load().entry_for(domain_trim) {
        return PrePublicRoute::ForwardZone(entry);
    }
    if let Some(message) = build_localhost_response(tx_id, name, qtype, request, domain_trim) {
        return PrePublicRoute::Localhost(message);
    }
    if let Some(message) = build_ipv4only_arpa_response(
        tx_id,
        name,
        qtype,
        request,
        domain_trim,
        state.network.active_nat64(Instant::now()),
    ) {
        return PrePublicRoute::BuiltinZone(message);
    }
    if let Some(forward) = state.forward.load().as_ref().as_ref().cloned() {
        return PrePublicRoute::CaptiveForward(forward);
    }
    if let Some(apex) = state.local_zones.lookup_built_in(domain_trim) {
        return PrePublicRoute::BuiltinZone(build_builtin_zone_response(
            tx_id,
            name,
            qtype,
            request,
            apex,
            domain_trim,
        ));
    }
    if let Some(message) = resolve_below_nxdomain_or_none(state.cache.as_ref(), name, qtype).await {
        return PrePublicRoute::CachedAncestorNxdomain(message);
    }
    PrePublicRoute::None
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parses `<32hex>.<32hex>.<u|t>._probe.macdns` into (nonce, transport tag).
/// Returns None for anything that is not an authenticated control challenge,
/// or when the name's transport label does not match the transport the query
/// actually arrived on (fail closed, against cross-transport replay).
///
/// `domain_trim` must be the ASCII wire presentation (`Name::to_ascii`), not
/// the `Display` form: hickory decodes `xn--` labels to Unicode when
/// formatting, so a caller-controlled A-label can otherwise hand this
/// function a multi-byte string. Decoding walks raw bytes and rejects every
/// non-hex byte, so a non-ASCII label can never reach an arithmetic slice.
fn parse_control_challenge(domain_trim: &str, transport: Transport) -> Option<([u8; 32], u8)> {
    let rest = domain_trim.strip_suffix("._probe.macdns")?;
    let (hex, label) = rest.rsplit_once('.')?;
    let expected = match transport {
        Transport::Udp { .. } => "u",
        Transport::Tcp => "t",
    };
    if label != expected {
        return None;
    }
    let tag = label.as_bytes()[0];
    // Two 32-byte hex labels joined by one dot: "<32>.<32>" = 65 bytes.
    let (high, low) = hex.split_once('.')?;
    if high.len() != 32 || low.len() != 32 || low.contains('.') {
        return None;
    }
    let mut digits = high.bytes().chain(low.bytes());
    let mut nonce = [0u8; 32];
    for byte in nonce.iter_mut() {
        let hi = hex_digit(digits.next()?)?;
        let lo = hex_digit(digits.next()?)?;
        *byte = (hi << 4) | lo;
    }
    Some((nonce, tag))
}

/// The exact question wire (labels + QTYPE TXT + QCLASS IN) the Swift side
/// hashes, so both sides bind the same bytes. Control challenges are always
/// TXT/IN by contract. Built from the ASCII wire presentation so the label
/// lengths written here are the on-wire lengths, never a punycode-decoded
/// `Display` string.
fn control_question_wire(name: &Name) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in name
        .to_lowercase()
        .to_ascii()
        .trim_end_matches('.')
        .split('.')
    {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0x00);
    wire.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // QTYPE TXT, QCLASS IN
    wire
}

/// Single TXT answer carrying the authenticated control response string.
fn build_txt_answer(
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    txt: &str,
    req: &Message,
) -> Message {
    use hickory_resolver::proto::rr::rdata::TXT;
    let mut m = empty_message();
    question_header(&mut m, tx_id, name, qtype, req);
    m.metadata.response_code = ResponseCode::NoError;
    m.add_answer(Record::from_rdata(
        name.clone(),
        0,
        RData::TXT(TXT::new(vec![txt.to_string()])),
    ));
    m
}

pub(crate) async fn probe_recursive_resolution(state: &ModuleState) -> bool {
    let Ok(name) = Name::from_str("apple.com.") else {
        return false;
    };

    let started = Instant::now();
    let result = dispatch(
        &state.pool,
        &name,
        RecordType::A,
        false,
        CancellationToken::new(),
    )
    .await;

    match result {
        Ok(_) => true,
        Err(error) => {
            let providers = state
                .pool
                .all()
                .iter()
                .map(|provider| provider.name)
                .collect::<Vec<_>>()
                .join(",");
            let duration_ms = started.elapsed().as_millis();
            let failure_class = direct_doh_probe_failure_class(&error);
            if let HedgeError::UpstreamResponse { rcode, .. } = error {
                log::warn!(
                    "health-probe kind=direct-doh providers={} failure={} rcode={:?} duration_ms={}",
                    providers,
                    failure_class,
                    rcode,
                    duration_ms
                );
            } else {
                log::warn!(
                    "health-probe kind=direct-doh providers={} failure={} duration_ms={}",
                    providers,
                    failure_class,
                    duration_ms
                );
            }
            false
        }
    }
}

fn direct_doh_probe_failure_class(error: &HedgeError) -> &'static str {
    match error {
        HedgeError::Timeout => "timeout",
        HedgeError::UpstreamResponse { .. } => "upstream-rcode",
        HedgeError::AllFailed {
            negative: Some(_), ..
        } => "authoritative-negative",
        HedgeError::AllFailed { negative: None, .. } => "all-failed",
        HedgeError::Cancelled => "cancelled",
    }
}

fn parse_request_start(wire: &[u8], transport: Transport) -> RequestStart {
    let req = match Message::from_bytes(wire) {
        Ok(m) => m,
        // RFC 6891 §6.1.1: a request carrying more than one OPT is a format
        // error the responder MUST answer with FORMERR. Nothing else parsed,
        // so the reply is built from the raw header. The transaction ID is
        // the only field the client needs to match it to the query. Every
        // other decode failure stays unanswered.
        Err(DecodeError::DuplicateEdns) if wire.len() >= 2 => {
            let mut m = empty_message();
            m.metadata.id = u16::from_be_bytes([wire[0], wire[1]]);
            m.metadata.response_code = ResponseCode::FormErr;
            return RequestStart::Early {
                message: m,
                client_edns: None,
                route: Route::Invalid,
                reason: "duplicate-opt",
            };
        }
        Err(_) => return RequestStart::Empty,
    };
    if req.metadata.message_type != MessageType::Query {
        return RequestStart::Empty;
    }
    let query = match req.queries.first() {
        Some(q) => q.clone(),
        None => return RequestStart::Empty,
    };
    let tx_id = req.metadata.id;
    let name = query.name().clone();
    let qtype = query.query_type();
    // ASCII wire presentation, not `Display`: hickory decodes `xn--` labels
    // to Unicode when formatting, which both breaks routing keys (zones,
    // overrides and blocklists all canonicalize to punycode) and hands
    // caller-controlled multi-byte strings to downstream byte parsing.
    let domain = name.to_lowercase().to_ascii();
    let domain_trim = domain.trim_end_matches('.').to_string();
    let client_edns = req.edns.clone();

    // RFC 6891: reject unsupported EDNS versions deterministically.
    if client_edns.as_ref().is_some_and(|opt| opt.version() != 0) {
        let mut m = empty_message();
        question_header(&mut m, tx_id, &name, qtype, &req);
        m.metadata.response_code = ResponseCode::BADVERS;
        return RequestStart::Early {
            message: m,
            client_edns,
            route: Route::Invalid,
            reason: "badvers",
        };
    }

    // RFC 1035 §4.1.1: only OpCode::Query is implemented.
    if req.metadata.op_code != OpCode::Query {
        let mut m = empty_message();
        question_header(&mut m, tx_id, &name, qtype, &req);
        m.metadata.response_code = ResponseCode::NotImp;
        return RequestStart::Early {
            message: m,
            client_edns,
            route: Route::Invalid,
            reason: "notimp",
        };
    }

    // Class CH/HS is not implemented. REFUSED keeps those probes off upstream.
    if query.query_class() != DNSClass::IN {
        let mut m = empty_message();
        question_header(&mut m, tx_id, &name, qtype, &req);
        m.metadata.response_code = ResponseCode::Refused;
        return RequestStart::Early {
            message: m,
            client_edns,
            route: Route::Invalid,
            reason: "non-in-class",
        };
    }

    // Multi-question has no sane single-response mapping in modern resolvers.
    if req.queries.len() > 1 {
        let mut m = empty_message();
        question_header(&mut m, tx_id, &name, qtype, &req);
        m.metadata.response_code = ResponseCode::FormErr;
        return RequestStart::Early {
            message: m,
            client_edns,
            route: Route::Invalid,
            reason: "multi-question",
        };
    }

    // Authenticated control-plane challenge `<32hex>.<32hex>.<u|t>._probe.macdns`.
    // There is no unsigned readiness probe. The provider proves the resolver's
    // identity only through this HMAC challenge.
    if let Some((nonce, transport_tag)) = parse_control_challenge(&domain_trim, transport) {
        let question_wire = control_question_wire(&name);
        let ready = crate::proxy_interception_ready();
        let message = match crate::proxy_control::build_response(
            &nonce,
            transport_tag,
            ready,
            &question_wire,
        ) {
            Some(txt) => build_txt_answer(tx_id, &name, qtype, &txt, &req),
            // No session installed → fail closed with REFUSED (never upstream).
            None => build_refused(tx_id, &name, qtype, &req),
        };
        return RequestStart::Early {
            message,
            client_edns,
            route: Route::Local,
            reason: "proxy-control",
        };
    }

    RequestStart::Continue(ParsedRequest {
        req,
        tx_id,
        name,
        qtype,
        domain_trim,
        client_edns,
    })
}

/// Blocklist stage. Never produces SERVFAIL: `decide` fails open, so an
/// unusable filtering database degrades filtering instead of failing queries.
fn resolve_blocklist_or_none(
    domain_trim: &str,
    qtype: RecordType,
    tx_id: u16,
    name: &Name,
    req: &Message,
    transport: Transport,
    client_edns: Option<&Edns>,
) -> Option<(Vec<u8>, ReplyOrigin)> {
    let (decision, block_match) = decide_with_match(domain_trim, qtype);
    let message = match decision {
        BlockDecision::AddressA(ip) => build_answer(tx_id, name, qtype, &[RData::A(A(ip))], 0, req),
        BlockDecision::AddressAAAA(ip) => {
            build_answer(tx_id, name, qtype, &[RData::AAAA(AAAA(ip))], 0, req)
        }
        BlockDecision::Nxdomain => build_nxdomain(tx_id, name, qtype, req),
        BlockDecision::Nodata => build_local_nodata(tx_id, name, qtype, req, name),
        BlockDecision::Allow => return None,
    };
    inc(&counters().blocked);
    let mut origin = ReplyOrigin::local(Route::Blocked, "blocklist");
    origin.block = block_match.map(|m| (m.matched_rule, m.tag));
    Some((finalize_wire(message, transport, client_edns), origin))
}

/// Apex of the override zone that claimed the queried name, if any.
fn matched_override_apex(zone_match: &crate::overrides::ZoneMatch) -> Option<&str> {
    match zone_match {
        crate::overrides::ZoneMatch::StaticApex { apex }
        | crate::overrides::ZoneMatch::StaticSubname { apex }
        | crate::overrides::ZoneMatch::Redirect { apex } => Some(apex.as_str()),
        crate::overrides::ZoneMatch::None => None,
    }
}

/// Label count of a canonicalized apex, the specificity score used when an
/// override zone and a forward/stub zone both claim the queried name.
fn apex_specificity(apex: &str) -> usize {
    apex.split('.').filter(|label| !label.is_empty()).count()
}

/// True when a forward/stub zone claims a strictly longer suffix of the
/// queried name than the matched override zone. Longest suffix wins, so an
/// `example.com` static override does not NXDOMAIN `db.corp.example.com`
/// while a `corp.example.com` forward zone owns that subtree. On equal
/// specificity the override wins, because the operator asked for local data
/// at that exact apex. The zone lookup runs only when an override matched, so
/// unclaimed names pay nothing on the hot path.
fn forward_zone_outranks_override(
    policy: &RuntimePolicySnapshot,
    domain_trim: &str,
    override_apex: &str,
) -> bool {
    match policy.zones.entry_with_apex_for(domain_trim) {
        Some((zone_apex, _)) => apex_specificity(&zone_apex) > apex_specificity(override_apex),
        None => false,
    }
}

#[allow(clippy::too_many_arguments)]
async fn resolve_override_or_none(
    policy: &Arc<RuntimePolicySnapshot>,
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    domain_trim: &str,
    req: &Message,
    cancel: &CancellationToken,
    cname_depth: u8,
    transport: Transport,
    client_edns: Option<&Edns>,
) -> Option<(Vec<u8>, ReplyOrigin)> {
    let zone_match = policy.overrides.resolve_zone(domain_trim);
    if let Some(apex) = matched_override_apex(&zone_match) {
        if forward_zone_outranks_override(policy, domain_trim, apex) {
            return None;
        }
    }
    match zone_match {
        crate::overrides::ZoneMatch::StaticApex { apex } => {
            if let Some(rdata) = policy.overrides.get_exact(&apex, qtype) {
                return Some((
                    finalize_wire(
                        build_answer(tx_id, name, qtype, &rdata, 60, req),
                        transport,
                        client_edns,
                    ),
                    ReplyOrigin::local(Route::Override, "override"),
                ));
            }
            if qtype != RecordType::CNAME {
                if let Some(cname_rdata) = policy.overrides.get_exact(&apex, RecordType::CNAME) {
                    if cname_depth >= MAX_CNAME_CHAIN {
                        log::warn!(
                            "CNAME chain depth cap hit at {} ({} hops)",
                            domain_trim,
                            cname_depth
                        );
                        return Some((
                            finalize_wire(
                                build_servfail_with_ede(
                                    tx_id,
                                    name,
                                    qtype,
                                    EDE_OTHER,
                                    "CNAME chain too long",
                                    req,
                                ),
                                transport,
                                client_edns,
                            ),
                            ReplyOrigin::local(Route::Failed, "override"),
                        ));
                    }
                    return Some(
                        resolve_override_cname_chain(
                            tx_id,
                            name,
                            qtype,
                            cname_rdata,
                            cancel.clone(),
                            cname_depth,
                            transport,
                            client_edns,
                            req,
                            policy.clone(),
                        )
                        .await,
                    );
                }
            }
            let apex_name = Name::from_ascii(format!("{}.", apex.trim_end_matches('.')))
                .unwrap_or_else(|_| name.clone());
            Some((
                finalize_wire(
                    build_local_nodata(tx_id, name, qtype, req, &apex_name),
                    transport,
                    client_edns,
                ),
                ReplyOrigin::local(Route::Override, "override"),
            ))
        }
        crate::overrides::ZoneMatch::StaticSubname { .. } => Some((
            finalize_wire(
                build_nxdomain(tx_id, name, qtype, req),
                transport,
                client_edns,
            ),
            ReplyOrigin::local(Route::Override, "override"),
        )),
        crate::overrides::ZoneMatch::Redirect { apex } => {
            let wild = format!("*.{}", apex);
            if let Some(rdata) = policy.overrides.get_exact(&wild, qtype) {
                return Some((
                    finalize_wire(
                        build_answer(tx_id, name, qtype, &rdata, 60, req),
                        transport,
                        client_edns,
                    ),
                    ReplyOrigin::local(Route::Override, "override"),
                ));
            }
            if qtype != RecordType::CNAME {
                if let Some(cname_rdata) = policy.overrides.get_exact(&wild, RecordType::CNAME) {
                    if cname_depth >= MAX_CNAME_CHAIN {
                        log::warn!(
                            "CNAME chain depth cap hit at {} ({} hops)",
                            domain_trim,
                            cname_depth
                        );
                        return Some((
                            finalize_wire(
                                build_servfail_with_ede(
                                    tx_id,
                                    name,
                                    qtype,
                                    EDE_OTHER,
                                    "CNAME chain too long",
                                    req,
                                ),
                                transport,
                                client_edns,
                            ),
                            ReplyOrigin::local(Route::Failed, "override"),
                        ));
                    }
                    return Some(
                        resolve_override_cname_chain(
                            tx_id,
                            name,
                            qtype,
                            cname_rdata,
                            cancel.clone(),
                            cname_depth,
                            transport,
                            client_edns,
                            req,
                            policy.clone(),
                        )
                        .await,
                    );
                }
            }
            let apex_name = Name::from_ascii(format!("{}.", apex.trim_end_matches('.')))
                .unwrap_or_else(|_| name.clone());
            Some((
                finalize_wire(
                    build_local_nodata(tx_id, name, qtype, req, &apex_name),
                    transport,
                    client_edns,
                ),
                ReplyOrigin::local(Route::Override, "override"),
            ))
        }
        crate::overrides::ZoneMatch::None => None,
    }
}

async fn handle_wire_inner(
    wire: &[u8],
    cancel: CancellationToken,
    cname_depth: u8,
    transport: Transport,
    policy: Option<Arc<RuntimePolicySnapshot>>,
) -> (Vec<u8>, ReplyOrigin) {
    let ParsedRequest {
        req,
        tx_id,
        name,
        qtype,
        domain_trim,
        client_edns,
    } = match parse_request_start(wire, transport) {
        RequestStart::Continue(parsed) => parsed,
        RequestStart::Early {
            message,
            client_edns,
            route,
            reason,
        } => {
            return (
                finalize_wire(message, transport, client_edns.as_ref()),
                ReplyOrigin::local(route, reason),
            );
        }
        RequestStart::Empty => {
            return (
                Vec::new(),
                ReplyOrigin {
                    route: Route::Invalid,
                    provider: None,
                    block: None,
                    log_source: None,
                },
            )
        }
    };
    let domain_trim = domain_trim.as_str();

    let cfg = crate::config::current();
    if cfg.log_queries {
        let qtype_str = format!("{:?}", qtype);
        // As on the reply path, log only through the `:dns` callback. The
        // FfiLogger would log the line twice.
        crate::log_hooks::emit_query(domain_trim, &qtype_str);
    }

    let state = match get_state() {
        Some(s) => s.clone(),
        None => {
            // Shutdown/init race: state was cleared between arrival and
            // dispatch. The distinct SERVFAIL reason separates this lifecycle
            // noise from a real upstream outage.
            report_servfail(&cfg, domain_trim, qtype, "module-not-ready", None);
            return (
                finalize_wire(
                    build_servfail_with_ede(
                        tx_id,
                        &name,
                        qtype,
                        EDE_NOT_READY,
                        "module not ready",
                        &req,
                    ),
                    transport,
                    client_edns.as_ref(),
                ),
                ReplyOrigin::local(Route::Failed, "servfail"),
            );
        }
    };
    let policy = policy.unwrap_or_else(|| state.policy.load_full());

    // `resolve_zone` returns the most specific override zone that claims this
    // name (exact override → static, wildcard base → redirect, or None). Each
    // zone type has its own dispatch, so mismatched qtypes, sub-names inside a
    // static zone and nested zones all deny correctly. Nothing leaks upstream
    // for a name the operator has claimed.
    if let Some(response) = resolve_override_or_none(
        &policy,
        tx_id,
        &name,
        qtype,
        domain_trim,
        &req,
        &cancel,
        cname_depth,
        transport,
        client_edns.as_ref(),
    )
    .await
    {
        return response;
    }

    if let Some(response) = resolve_blocklist_or_none(
        domain_trim,
        qtype,
        tx_id,
        &name,
        &req,
        transport,
        client_edns.as_ref(),
    ) {
        return response;
    }

    match select_pre_public_route(
        state.as_ref(),
        policy.as_ref(),
        tx_id,
        &name,
        qtype,
        &req,
        domain_trim,
    )
    .await
    {
        PrePublicRoute::ForwardZone(entry) => {
            let tag = if entry.is_stub {
                "stub-zone"
            } else {
                "forward-zone"
            };
            return (
                upstream_lookup(
                    tx_id,
                    &name,
                    qtype,
                    ForwardTarget {
                        resolver: &entry.resolver,
                        route: tag,
                    },
                    transport,
                    client_edns.as_ref(),
                    &req,
                )
                .await,
                ReplyOrigin::local(Route::Forward, tag),
            );
        }
        PrePublicRoute::CaptiveForward(fwd) => {
            let resolver = Arc::new(fwd.resolver.clone());
            let target = fwd.servers.join(",");
            return (
                upstream_lookup(
                    tx_id,
                    &name,
                    qtype,
                    ForwardTarget {
                        resolver: &resolver,
                        route: "captive-forward",
                    },
                    transport,
                    client_edns.as_ref(),
                    &req,
                )
                .await,
                ReplyOrigin::local(Route::Captive, format!("captive-forward:{}", target)),
            );
        }
        // Built-in special-use zones (RFC 6303/6761/6762/9462).
        PrePublicRoute::Localhost(local_msg) => {
            return (
                finalize_wire(local_msg, transport, client_edns.as_ref()),
                ReplyOrigin::local(Route::Local, "builtin-localhost"),
            );
        }
        PrePublicRoute::BuiltinZone(zone_msg) => {
            return (
                finalize_wire(zone_msg, transport, client_edns.as_ref()),
                ReplyOrigin::local(Route::Local, "builtin-zone"),
            );
        }
        // RFC 8020 `harden-below-nxdomain` is public-cache policy. It runs
        // only when no private or built-in route claimed the query.
        PrePublicRoute::CachedAncestorNxdomain(mut msg) => {
            inc(&counters().below_nxdomain_hits);
            msg.metadata.id = tx_id;
            echo_request_flags(&mut msg, &req);
            return (
                finalize_wire(msg, transport, client_edns.as_ref()),
                ReplyOrigin::local(Route::Local, "below-nxdomain"),
            );
        }
        PrePublicRoute::None => {}
    }

    let (message, origin) = resolve_public_path(
        &state,
        &cfg,
        &req,
        tx_id,
        &name,
        qtype,
        domain_trim,
        &cancel,
    )
    .await;
    let (message, origin) = synthesize_dns64_if_needed(
        &state,
        &cfg,
        &req,
        tx_id,
        &name,
        qtype,
        domain_trim,
        &cancel,
        message,
        origin,
    )
    .await;
    let mut message = message;
    gate_authentic_data(&mut message, &req);
    (
        finalize_wire(message, transport, client_edns.as_ref()),
        origin,
    )
}

/// Cache, serve-expired, and the hedged public DoH path for one question,
/// after every local and user-directed route declined it. Returns the response
/// before wire finalization so the DNS64 view can still be applied on top.
#[allow(clippy::too_many_arguments)]
async fn resolve_public_path(
    state: &Arc<ModuleState>,
    cfg: &Arc<crate::config::ResolverOptions>,
    req: &Message,
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    domain_trim: &str,
    cancel: &CancellationToken,
) -> (Message, ReplyOrigin) {
    // The cache is consulted only after user-directed routes and built-in
    // special-use zones, so a cached public answer cannot shadow a newly
    // configured forward/stub/captive route or the RFC 6761 localhost and
    // RFC 6303 reverse-space defaults.
    //
    // A hit keeps the provider that won the hedge (or the one
    // background_refine last swapped in) until TTL expiry.
    let key = CacheKey::from(domain_trim, qtype);
    // A client that forced CD gets a private, uncached resolution (see
    // `client_forces_unchecked_data`). Every cache read and write below hangs
    // off this one decision.
    let client_forced_cd = client_forces_unchecked_data(req, cfg.dnssec);
    let cached = if client_forced_cd {
        None
    } else {
        state.cache.get(&key).await
    };
    if let Some(entry) = cached {
        inc(&counters().cache_hits);
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(entry.inserted_at).as_secs() as u32;
        // Prefetch near expiry. The periodic worker handles most refills;
        // this hit-path check covers scheduler lag without waiting on
        // upstream. Shared refresh state still keeps one refill per entry.
        // `get` has just marked the entry used, so the idle cut passes
        // without consulting the popular set.
        if cfg.prefetch
            && prefetch_qtype_allowed(qtype)
            && should_prefetch_entry(&entry, now, false)
        {
            // The runtime's cancel token lets `dns_shutdown` abort in-flight
            // refills before runtime teardown. Inside a query the runtime is
            // alive, so the detached fallback token is only a safety net.
            let prefetch_cancel = crate::runtime::cancel_token().unwrap_or_default();
            try_spawn_prefetch(
                state.clone(),
                key.clone(),
                name.clone(),
                qtype,
                RefreshSource::CacheHitPrefetch,
                entry.refresh_state.clone(),
                prefetch_cancel,
            );
        }
        let rotation = if crate::config::RRSET_ROUNDROBIN {
            Some(
                entry
                    .rotation_counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            )
        } else {
            None
        };
        return (
            rewrite_id_with_decremented_ttl(
                &entry.message,
                tx_id,
                name,
                qtype,
                elapsed,
                rotation,
                req,
            ),
            ReplyOrigin::upstream(Route::Cache, entry.provider),
        );
    }

    // Cache miss on the public path. Zone and forward resolves above bypass
    // the hedge and do not count here.
    inc(&counters().cache_misses);

    // RFC 8767 §6: when a stale answer is on hand and the hedge does not
    // answer within `serve-expired-client-timeout`, return the stale entry
    // (stale TTL + EDE 3) and let the hedge finish in the background to
    // refresh the cache. The stale entry's shared `refresh_state` is the
    // single-flight gate here. Once one query owns the refresh, the others
    // wait for it within the same client budget.
    let client_timeout_ms = crate::config::SERVE_EXPIRED_CLIENT_TIMEOUT_MS;
    let servable_stale = if cfg.serve_expired && client_timeout_ms > 0 && !client_forced_cd {
        state
            .cache
            .get_allow_expired(&key)
            .await
            .filter(|entry| !response_is_negative(&entry.message))
    } else {
        None
    };
    if let Some(stale_entry) = servable_stale {
        if let Some(answer) = resolve_through_stale(
            state,
            cfg,
            req,
            tx_id,
            name,
            qtype,
            domain_trim,
            cancel,
            &key,
            stale_entry,
            client_timeout_ms,
            client_forced_cd,
        )
        .await
        {
            return answer;
        }
        // The stale entry vanished while this request waited on it, after a
        // flush or a network change. Nothing is left to serve from it, so the
        // request resolves cold like any other miss.
    }

    // Single-flight: concurrent cold misses for this key share one dispatch.
    let shared =
        resolve_shared_unless_forced_cd(&key, cfg.dnssec, cancel, client_forced_cd, || async {
            // Captured before the lookup so an answer describing the pre-flush
            // network cannot repopulate the cache after an invalidation.
            let cache_epoch = state.cache.capture_epoch();
            let dispatch_result = dispatch(
                &state.pool,
                name,
                qtype,
                req.metadata.checking_disabled,
                cancel.clone(),
            )
            .await;
            let (message, origin) = process_hedge_outcome(
                dispatch_result,
                tx_id,
                name,
                qtype,
                domain_trim,
                cfg,
                state,
                key.clone(),
                req,
                cache_epoch,
                client_forced_cd,
            )
            .await;
            SharedResolution { message, origin }
        })
        .await;

    // Re-stamp for this request. It is a no-op for the leader and required
    // for a request that joined it, whose question may spell the name in a
    // different case than the leader's.
    let mut message = shared.message;
    message.metadata.id = tx_id;
    set_question(&mut message, name, qtype, req);
    echo_request_flags(&mut message, req);
    (message, shared.origin)
}

/// RFC 8767 serve-expired path for a miss that still has a stale entry. One
/// request owns the refresh and races the upstream hedge against the client
/// budget, answering stale when the budget runs out. Every other request waits
/// on that refresh within the same budget and then serves whatever the cache
/// holds. Returns `None` when the stale entry vanished meanwhile, after a flush
/// or a network change, so the caller resolves cold instead of failing.
#[allow(clippy::too_many_arguments)]
async fn resolve_through_stale(
    state: &Arc<ModuleState>,
    cfg: &Arc<crate::config::ResolverOptions>,
    req: &Message,
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    domain_trim: &str,
    cancel: &CancellationToken,
    key: &CacheKey,
    stale_entry: CachedEntry,
    client_timeout_ms: u32,
    client_forced_cd: bool,
) -> Option<(Message, ReplyOrigin)> {
    let refresh_state = stale_entry.refresh_state.clone();
    if let Err(refresh_source) = refresh_state.try_start(RefreshSource::Demand) {
        let reason = wait_for_shared_refresh(&refresh_state, cancel, client_timeout_ms).await;
        if let Some((msg, origin)) = serve_stale(
            cfg,
            state,
            key,
            name,
            qtype,
            domain_trim,
            reason,
            refresh_source,
            tx_id,
            req,
        )
        .await
        {
            return Some((msg, origin));
        }
        return None;
    }
    let mut refresh_guard = RefreshStateGuard::new(refresh_state);

    let timeout = std::time::Duration::from_millis(client_timeout_ms as u64);
    // Captured before dispatch so a flush or network change during the
    // lookup invalidates the commit, including on the detached path.
    let cache_epoch = state.cache.capture_epoch();
    let state_for_disp = state.clone();
    let name_for_disp = name.clone();
    let cancel_for_disp = cancel.clone();
    let client_cd = req.metadata.checking_disabled;
    // The dispatch owns its captures so it can outlive this request when the
    // timeout wins and the task is left to finish in the background.
    let mut handle = tokio::spawn(async move {
        dispatch(
            &state_for_disp.pool,
            &name_for_disp,
            qtype,
            client_cd,
            cancel_for_disp,
        )
        .await
    });
    tokio::select! {
        joined = &mut handle => {
            let r = joined.unwrap_or(Err(HedgeError::Cancelled));
            let (msg, origin) = process_hedge_outcome(
                r,
                tx_id,
                name,
                qtype,
                domain_trim,
                cfg,
                state,
                key.clone(),
                req,
                cache_epoch,
                client_forced_cd,
            ).await;
            Some((msg, origin))
        }
        _ = tokio::time::sleep(timeout) => {
            // The in-flight dispatch keeps running. Its result fills the
            // cache for the next miss.
            let state_bg = state.clone();
            let key_bg = key.clone();
            let name_bg = name.clone();
            let domain_bg = domain_trim.to_string();
            let cfg_bg = cfg.clone();
            let refresh_guard_bg = refresh_guard.transfer();
            if let Err(e) = crate::runtime::spawn(async move {
                let _refresh_guard = refresh_guard_bg;
                let r = handle.await.unwrap_or(Err(HedgeError::Cancelled));
                // No client sees this response, so the stub's RD/CD/class
                // never matter.
                let req_stub = Message::query();
                let _ = process_hedge_outcome(
                    r,
                    0,
                    &name_bg,
                    qtype,
                    &domain_bg,
                    &cfg_bg,
                    &state_bg,
                    key_bg,
                    &req_stub,
                    cache_epoch,
                    client_forced_cd,
                )
                .await;
            }) {
                log::warn!("serve-expired background refill spawn failed: {}", e);
            }
            if let Some((msg, origin)) = serve_stale(
                cfg,
                state,
                key,
                name,
                qtype,
                domain_trim,
                "client-timeout",
                RefreshSource::Demand,
                tx_id,
                req,
            ).await {
                return Some((msg, origin));
            }
            // The stale entry was evicted between the pre-check and now. The
            // background refill keeps running and the caller resolves cold.
            None
        }
    }
}

/// RFC 6147 DNS64 view over the public path. On a network whose own resolver
/// synthesizes AAAA (see `network_profile`), an AAAA NODATA for a name with
/// public A records becomes NAT64 addresses, so the client reaches IPv4-only
/// names the way the network intends.
///
/// The synthesized message goes only to the client. The cache and the dump keep
/// the upstream answers (A records and the AAAA NODATA), so cached data stays
/// valid across moves between NAT64 and non-NAT64 networks. A client that set CD
/// validates DNSSEC itself and gets the unmodified answer (RFC 6147 §5.5).
#[allow(clippy::too_many_arguments)]
async fn synthesize_dns64_if_needed(
    state: &Arc<ModuleState>,
    cfg: &Arc<crate::config::ResolverOptions>,
    req: &Message,
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    domain_trim: &str,
    cancel: &CancellationToken,
    message: Message,
    origin: ReplyOrigin,
) -> (Message, ReplyOrigin) {
    if qtype != RecordType::AAAA || req.metadata.checking_disabled {
        return (message, origin);
    }
    let Some(asked) = state.network.active_nat64(Instant::now()) else {
        return (message, origin);
    };
    if !crate::dns64::needs_synthesis(&message) {
        return (message, origin);
    }
    let a = resolve_public_path(
        state,
        cfg,
        req,
        tx_id,
        name,
        RecordType::A,
        domain_trim,
        cancel,
    )
    .await;
    finish_dns64(&state.network, &asked.prefixes, message, origin, a)
}

/// Builds the DNS64 answer only if the prefixes the query started with still
/// belong to the attached network when the A lookup returns. A network change
/// or a lapsed TTL drops them at once, and an answer built from them would point
/// the client at a translator the network no longer has. Record TTLs never
/// exceed the prefixes' remaining validity.
fn finish_dns64(
    network: &crate::network_profile::NetworkProfileStore,
    asked: &[crate::dns64::Nat64Prefix],
    message: Message,
    origin: ReplyOrigin,
    (a_message, a_origin): (Message, ReplyOrigin),
) -> (Message, ReplyOrigin) {
    let now = Instant::now();
    let Some(current) = network.active_nat64(now) else {
        return (message, origin);
    };
    if current.prefixes != asked {
        return (message, origin);
    }
    match crate::dns64::build_dns64_response(
        &message,
        &a_message,
        &current.prefixes,
        current.remaining_ttl_secs(now),
    ) {
        // The history files the synthesized answer under the A answer it is
        // built from. The log keeps naming the source of the AAAA it replaces.
        Some(answer) => {
            let source = origin.log_source.as_deref().unwrap_or("unknown");
            let log_source = Some(format!("dns64:{source}"));
            (
                answer,
                ReplyOrigin {
                    route: a_origin.route,
                    provider: a_origin.provider,
                    block: None,
                    log_source,
                },
            )
        }
        None => (message, origin),
    }
}

/// Resolves a CNAME override by emitting the CNAME at the alias and feeding
/// the target back through `handle_wire_inner`, so the target goes through
/// every pipeline step (nested overrides, local zones, blocklist, forward
/// zones, built-ins, cache, hedge). The recursion needs `Box::pin`.
/// `cname_depth` grows by one per hop, and the caller enforces
/// `MAX_CNAME_CHAIN` before calling in.
#[allow(clippy::too_many_arguments)]
async fn resolve_override_cname_chain(
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    cname_rdata: Vec<RData>,
    cancel: CancellationToken,
    cname_depth: u8,
    transport: Transport,
    client_edns: Option<&Edns>,
    request: &Message,
    policy: Arc<RuntimePolicySnapshot>,
) -> (Vec<u8>, ReplyOrigin) {
    let mut m = empty_message();
    question_header(&mut m, tx_id, name, qtype, request);
    m.metadata.response_code = ResponseCode::NoError;

    // `parse_override` accepts one CNAME rdata. The loop tolerates a store
    // that ever holds more.
    for rd in &cname_rdata {
        let rec = Record::from_rdata(name.clone(), 60, rd.clone());
        m.add_answer(rec);
    }

    let Some(target) = cname_rdata.iter().find_map(|rd| {
        if let RData::CNAME(c) = rd {
            Some(c.0.clone())
        } else {
            None
        }
    }) else {
        return (
            finalize_wire(m, transport, client_edns),
            ReplyOrigin::local(Route::Override, "override"),
        );
    };

    // Hickory needs an FQDN for upstream dispatch. Override values typed
    // without a trailing dot (`vps.example.com`) parse as relative.
    let mut target_fqdn = target.clone();
    target_fqdn.set_fqdn(true);

    let sub_wire = build_query_wire(&target_fqdn, qtype, request);
    // Internal CNAME expansion needs the complete tail answer. The client UDP
    // cap applies once, after the alias CNAME and target records are merged.
    // Only `handle_wire` records history, so the whole chain is one event
    // under the override route.
    let (sub_resp, _origin) = Box::pin(handle_wire_inner(
        &sub_wire,
        cancel,
        cname_depth + 1,
        Transport::Tcp,
        Some(policy),
    ))
    .await;

    let route = if let Ok(sub_msg) = Message::from_bytes(&sub_resp) {
        merge_override_cname_tail(&mut m, &sub_msg);
        Route::Override
    } else {
        // The sub-query returned no parseable response. SERVFAIL lets the
        // client retry instead of caching an empty answer for the alias, and
        // `report_servfail` logs and counts it like every other SERVFAIL.
        let cfg = crate::config::current();
        let origin = name.to_string();
        let target_str = target_fqdn.to_string();
        report_servfail(
            &cfg,
            origin.trim_end_matches('.'),
            qtype,
            "override-cname-empty-subresponse",
            Some(&format!("target={}", target_str.trim_end_matches('.'))),
        );
        m.metadata.response_code = ResponseCode::ServFail;
        Route::Failed
    };

    (
        finalize_wire(m, transport, client_edns),
        ReplyOrigin::local(route, "override"),
    )
}

fn merge_override_cname_tail(m: &mut Message, sub_msg: &Message) {
    // Negative tails can carry CNAME answers before the terminal denial.
    m.metadata.response_code = sub_msg.metadata.response_code;
    for rec in &sub_msg.answers {
        m.add_answer(rec.clone());
    }
    // Preserve negative caching and denial proofs without importing positive
    // target-zone delegation data into the alias response.
    let positive_any = sub_msg.metadata.response_code == ResponseCode::NoError
        && !sub_msg.answers.is_empty()
        && sub_msg
            .queries
            .first()
            .is_some_and(|query| query.query_type() == RecordType::ANY);
    if !positive_any && response_is_negative(sub_msg) {
        for rec in &sub_msg.authorities {
            m.add_authority(rec.clone());
        }
    }
}

/// Wire for a single-question query with id 0, fed back into
/// `handle_wire_inner` by `resolve_override_cname_chain`.
fn build_query_wire(name: &Name, qtype: RecordType, request: &Message) -> Vec<u8> {
    let mut q_msg = Message::new(0, MessageType::Query, OpCode::Query);
    q_msg.metadata.recursion_desired = request.metadata.recursion_desired;
    q_msg.metadata.checking_disabled = request.metadata.checking_disabled;
    q_msg.edns = request.edns.clone();
    let mut q = DnsQuery::new();
    q.set_name(name.clone())
        .set_query_type(qtype)
        .set_query_class(
            request
                .queries
                .first()
                .map(|q| q.query_class())
                .unwrap_or(DNSClass::IN),
        );
    q_msg.add_query(q);
    message_to_bytes_or_warn(&q_msg, "build_query_wire")
}

/// RFC 8020 short-circuit. If an ancestor name is in the NXDOMAIN apex
/// tracker, synthesize NXDOMAIN locally instead of going upstream.
///
/// `recursion_desired` is left at the `Message::new` default (false). The
/// caller must apply `echo_request_flags` against the originating request
/// before sending so RD/CD/AD reflect what the client asked for.
///
/// Only the Question is rewritten. The authority section is the one the
/// upstream NXDOMAIN carried (its SOA plus any NSEC/NSEC3/RRSIG), so a
/// `DO=1` client receives the same denial proof it would have received from
/// the upstream, and RFC 2308 negative caching keeps the authority's own
/// owner and `MINIMUM`. Every retained TTL is aged down to what is left of
/// the covering entry so downstream caches cannot pin the answer past our
/// own expiry. `finalize_wire` strips DNSSEC records for non-DO clients.
pub(crate) async fn resolve_below_nxdomain_or_none(
    cache: &crate::cache::DnsCache,
    qname: &Name,
    qtype: RecordType,
) -> Option<Message> {
    let name_str = qname.to_string();
    let coverage = cache.nxdomain_apex_coverage(&name_str).await?;
    let mut q = DnsQuery::new();
    q.set_name(qname.clone()).set_query_type(qtype);
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    msg.add_query(q);
    msg.metadata.response_code = ResponseCode::NXDomain;
    msg.metadata.recursion_available = true;
    for rec in coverage.authorities.iter() {
        let mut aged = rec.clone();
        aged.ttl = aged.ttl.min(coverage.remaining_ttl_secs);
        msg.add_authority(aged);
    }
    Some(msg)
}

/// Request-independent outcome of one upstream resolution. Cloneable so the
/// single-flight leader can hand the same answer to every request that joined
/// its in-flight key. Transaction ID, RD/CD echo and EDNS are left out on
/// purpose. Each waiter applies its own before serializing.
#[derive(Clone)]
struct SharedResolution {
    message: Message,
    origin: ReplyOrigin,
}

/// Identity of one in-flight dispatch. The DNSSEC toggle decides the CD bit a
/// dispatch leaves with, so a request made after the toggle flipped must not
/// join a leader that asked the provider under the previous policy: it would
/// receive data the provider was told not to validate, or be refused data it
/// asked to see. The cache is flushed on a toggle, which clears stored
/// answers but not a dispatch already on the wire. This key does.
#[derive(Clone, Hash, PartialEq, Eq)]
struct InflightKey {
    key: CacheKey,
    dnssec: bool,
}

/// In-flight upstream dispatches, keyed by the cache key they will populate
/// and the policy they were dispatched under. An entry exists only while a
/// leader is resolving. Every way a leader can end removes it, so the map is
/// empty at rest.
fn inflight_registry() -> &'static DashMap<InflightKey, broadcast::Sender<SharedResolution>> {
    static REGISTRY: OnceLock<DashMap<InflightKey, broadcast::Sender<SharedResolution>>> =
        OnceLock::new();
    REGISTRY.get_or_init(DashMap::new)
}

/// Ownership token for one in-flight key. Dropping it (success, error, panic
/// or cancellation) frees the slot and closes the channel, so waiters never
/// block on a leader that will not publish.
struct InflightLeader {
    key: Option<InflightKey>,
    tx: broadcast::Sender<SharedResolution>,
}

impl InflightLeader {
    /// Frees the slot, then publishes to everyone who joined while it was
    /// held. Freeing first keeps the window in which a late arrival can
    /// subscribe to an already-published channel as short as possible. Such an
    /// arrival observes the close and resolves independently.
    fn publish(mut self, resolution: &SharedResolution) {
        self.release();
        let _ = self.tx.send(resolution.clone());
    }

    fn release(&mut self) {
        if let Some(key) = self.key.take() {
            inflight_registry().remove(&key);
        }
    }
}

impl Drop for InflightLeader {
    fn drop(&mut self) {
        self.release();
    }
}

/// Claims the in-flight slot for `key`, or subscribes to the leader that
/// already holds it. Deliberately not `async`: the registry shard guard must
/// be released before any await, or a waiter could hold the shard while the
/// leader tries to remove its own entry from it.
fn claim_or_subscribe(
    key: &InflightKey,
) -> Result<InflightLeader, broadcast::Receiver<SharedResolution>> {
    match inflight_registry().entry(key.clone()) {
        dashmap::mapref::entry::Entry::Occupied(slot) => Err(slot.get().subscribe()),
        dashmap::mapref::entry::Entry::Vacant(slot) => {
            let (tx, _) = broadcast::channel(1);
            slot.insert(tx.clone());
            Ok(InflightLeader {
                key: Some(key.clone()),
                tx,
            })
        }
    }
}

/// Per-key single-flight around an upstream resolution. Without it, N
/// simultaneous cold misses for one name each run a full hedge (three
/// primaries plus stagger and backups), so a local client loop turns into
/// hundreds of upstream requests. The first request to claim `key` resolves
/// and publishes. Requests that join while it is in flight receive a clone of
/// its outcome and never touch the network.
///
/// Failures are published too: making waiters retry after the leader already
/// exhausted every upstream would restore the amplification this prevents,
/// and the leader has already made the negative-cache and serve-stale
/// decisions for the key.
///
/// A waiter that loses its leader (panic, cancellation, or a drop without
/// publish) resolves independently rather than hanging, and claims no slot of
/// its own, because the departing leader may still own it.
async fn single_flight<F, Fut>(
    key: &CacheKey,
    dnssec: bool,
    cancel: &CancellationToken,
    resolve: F,
) -> SharedResolution
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = SharedResolution>,
{
    let key = InflightKey {
        key: key.clone(),
        dnssec,
    };
    let mut joined = match claim_or_subscribe(&key) {
        Ok(leader) => {
            let resolution = resolve().await;
            leader.publish(&resolution);
            return resolution;
        }
        Err(receiver) => receiver,
    };

    tokio::select! {
        biased;
        published = joined.recv() => {
            if let Ok(resolution) = published {
                return resolution;
            }
        }
        _ = cancel.cancelled() => {}
    }

    resolve().await
}

/// True when the client's own CD bit asks for data this resolver's cache must
/// never hold. `CacheKey` is `{name, qtype}` with no CD dimension, and the
/// single-flight registry is keyed the same way, so an answer the provider
/// returned unvalidated would otherwise be stored under the key a `CD=0`
/// client reads, and shared live with a `CD=0` request in flight beside it.
///
/// With the DNSSEC toggle off every query already leaves with `CD=1`, so a
/// client setting the bit asks for nothing extra and keeps the shared cache.
/// Only the toggle-on case is a downgrade. That query resolves as an uncached
/// passthrough and `CD=0` clients are unaffected.
fn client_forces_unchecked_data(request: &Message, dnssec_enabled: bool) -> bool {
    request.metadata.checking_disabled && dnssec_enabled
}

/// `single_flight`, unless the caller must resolve alone. A query that forced
/// CD neither leads an in-flight key nor joins one: leading would publish
/// unvalidated data to every `CD=0` request that joined, and joining would
/// return validated data the client explicitly asked to bypass.
async fn resolve_shared_unless_forced_cd<F, Fut>(
    key: &CacheKey,
    dnssec: bool,
    cancel: &CancellationToken,
    client_forced_cd: bool,
    resolve: F,
) -> SharedResolution
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = SharedResolution>,
{
    if client_forced_cd {
        return resolve().await;
    }
    single_flight(key, dnssec, cancel, resolve).await
}

/// End-of-pipeline handler for a hedge result, shared by the hot path and the
/// RFC 8767 detached refresh (whose client already got a stale answer):
/// cache insertion, refinement and SERVFAIL formatting. `tx_id == 0` marks
/// the background path, whose returned message is never sent.
///
/// Returns the response message rather than wire bytes so the single-flight
/// leader can publish one upstream outcome to every waiting request, each of
/// which then applies its own transaction ID, flags and EDNS through
/// `finalize_wire`.
#[allow(clippy::too_many_arguments)]
async fn process_hedge_outcome(
    dispatch_result: Result<crate::hedge::HedgeResult, HedgeError>,
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    domain_trim: &str,
    cfg: &crate::config::ResolverOptions,
    state: &Arc<crate::state::ModuleState>,
    key: CacheKey,
    request: &Message,
    // Cache epoch captured before the upstream lookup started. A flush or
    // network change since then rejects the cache commit while the waiting
    // client still receives its answer.
    cache_epoch: u64,
    // The client forced CD, so this answer may be one the provider never
    // validated (`client_forces_unchecked_data`). It reaches that client and
    // nothing else: no positive entry, no negative entry, no RFC 8020 cut and
    // no refinement, since all of them are keyed without a CD dimension. The
    // stale fallback below still answers when every provider failed. It holds
    // only entries an earlier query committed, so reading it cannot spread
    // unvalidated data.
    client_forced_cd: bool,
) -> (Message, ReplyOrigin) {
    match dispatch_result {
        Ok(mut result) => {
            // Defence in depth: the hedge already rejects `Ok(empty)`, so an
            // empty lookup here is a hedge regression. SERVFAIL without
            // touching the cache.
            if !lookup_has_payload(&result.first) {
                log::error!(
                    "process_hedge_outcome: first lookup has zero payload for {} {:?} (rcode={:?}) — hedge filter regression",
                    domain_trim, qtype,
                    result.first.message().metadata.response_code,
                );
                report_servfail(cfg, domain_trim, qtype, "empty-upstream-response", None);
                return (
                    build_servfail_with_ede(
                        tx_id,
                        name,
                        qtype,
                        EDE_OTHER,
                        "upstream returned empty response",
                        request,
                    ),
                    ReplyOrigin::local(Route::Failed, "servfail"),
                );
            }
            let mut first_msg = message_from_lookup(tx_id, name, qtype, &result.first);
            echo_request_flags(&mut first_msg, request);
            // DNS-rebinding defense: strip private-space A/AAAA from public
            // answers. Only the hedge path does this, because forward-zone
            // and override answers are operator-configured and may carry
            // private IPs. When every record was private the reply is NODATA.
            let mut cacheable = true;
            if crate::config::BLOCK_REBINDING {
                let filter = crate::rebinding::filter_rebindable_records(&mut first_msg);
                if filter.changed() {
                    crate::stats::add(
                        &counters().rebinding_filtered,
                        filter.stripped_addresses as u64,
                    );
                    log::info!(
                        "rebinding: stripped {} private address records for {} {:?}",
                        filter.stripped_addresses,
                        domain_trim,
                        qtype
                    );
                    // EDE 17 (Filtered) shows the strip to clients.
                    attach_ede(&mut first_msg, EDE_FILTERED, "private-address filter");
                    if filter.all_useful_answers_stripped() {
                        first_msg = build_local_nodata(tx_id, name, qtype, request, name);
                        attach_ede(&mut first_msg, EDE_FILTERED, "private-address filter");
                        cacheable = false;
                    }
                }
            }
            let provider_name = state
                .pool
                .all()
                .get(result.first_idx)
                .map(|p| p.name.to_string())
                .unwrap_or_else(|| format!("provider#{}", result.first_idx));
            let stored = if cacheable && !client_forced_cd {
                let entry = CachedEntry::scaffold(first_msg.clone(), provider_name.clone());
                let ttl = positive_cache_ttl(&first_msg);
                state
                    .cache
                    .insert_if_epoch(cache_epoch, key.clone(), entry, ttl)
                    .await
            } else {
                None
            };

            // A refinement improves the stored entry, so none runs without one.
            if let Some(refresh_state) = stored {
                spawn_refinement(
                    &mut result,
                    state,
                    key.clone(),
                    name,
                    qtype,
                    cache_epoch,
                    refresh_state,
                );
            }

            (
                first_msg,
                ReplyOrigin::upstream(Route::Provider, provider_name),
            )
        }
        Err(e) => match e {
            HedgeError::AllFailed {
                negative: Some(err),
                negative_idx,
            } => {
                let provider =
                    negative_idx.and_then(|i| state.pool.all().get(i).map(|p| p.name.to_string()));
                let provider_name = provider.clone().unwrap_or_else(|| "negative".into());
                let origin = ReplyOrigin {
                    route: Route::Provider,
                    provider,
                    block: None,
                    log_source: Some(provider_name.clone()),
                };
                match classify_negative_err(tx_id, name, qtype, &err, request) {
                    Some(NegativeAnswer::Cacheable {
                        message: neg_msg,
                        ttl_secs,
                    }) => {
                        if !client_forced_cd {
                            let entry =
                                CachedEntry::scaffold(neg_msg.clone(), provider_name.clone());
                            state
                                .cache
                                .insert_neg_if_epoch(cache_epoch, key.clone(), entry, ttl_secs)
                                .await;
                            if neg_msg.metadata.response_code == ResponseCode::NXDomain {
                                // The cut belongs at the name hickory failed on, not
                                // at the QNAME: after a CNAME chase the QNAME still
                                // exists as an alias and only its terminal target is
                                // nonexistent.
                                let terminal = negative_terminal_name(&err).unwrap_or(name);
                                state
                                    .cache
                                    .insert_nxdomain_apex_if_epoch(
                                        cache_epoch,
                                        &nxdomain_apex_from(terminal),
                                        ttl_secs,
                                        &neg_msg.authorities,
                                    )
                                    .await;
                            }
                        }
                        (neg_msg, origin)
                    }
                    Some(NegativeAnswer::Uncacheable { message }) => (message, origin),
                    Some(NegativeAnswer::Unresolvable) => {
                        report_servfail(
                            cfg,
                            domain_trim,
                            qtype,
                            "unresolvable-cname-chain",
                            Some(&err.to_string()),
                        );
                        (
                            build_servfail_with_ede(
                                tx_id,
                                name,
                                qtype,
                                EDE_OTHER,
                                "unresolvable CNAME chain",
                                request,
                            ),
                            ReplyOrigin::local(Route::Failed, "servfail"),
                        )
                    }
                    None => {
                        report_servfail(
                            cfg,
                            domain_trim,
                            qtype,
                            "negative-extraction-failed",
                            Some(&err.to_string()),
                        );
                        (
                            build_servfail_with_ede(
                                tx_id,
                                name,
                                qtype,
                                EDE_OTHER,
                                "negative extraction failed",
                                request,
                            ),
                            ReplyOrigin::local(Route::Failed, "servfail"),
                        )
                    }
                }
            }
            HedgeError::AllFailed { negative: None, .. } => {
                if let Some(stale) = serve_stale(
                    cfg,
                    state,
                    &key,
                    name,
                    qtype,
                    domain_trim,
                    "all-upstream-failed",
                    RefreshSource::Demand,
                    tx_id,
                    request,
                )
                .await
                {
                    stale
                } else {
                    report_servfail(cfg, domain_trim, qtype, "all-upstream-failed", None);
                    (
                        build_servfail_with_ede(
                            tx_id,
                            name,
                            qtype,
                            ede_for_reason("all-upstream-failed"),
                            "all upstream providers failed",
                            request,
                        ),
                        ReplyOrigin::local(Route::Failed, "servfail"),
                    )
                }
            }
            HedgeError::UpstreamResponse {
                rcode,
                extended_errors,
            } => {
                let (reason, ede, text) = servfail_for_upstream_response(rcode);
                if let Some(stale) = serve_stale(
                    cfg,
                    state,
                    &key,
                    name,
                    qtype,
                    domain_trim,
                    reason,
                    RefreshSource::Demand,
                    tx_id,
                    request,
                )
                .await
                {
                    stale
                } else {
                    report_servfail(cfg, domain_trim, qtype, reason, None);
                    let mut servfail =
                        build_servfail_with_ede(tx_id, name, qtype, ede, &text, request);
                    attach_provider_ede(&mut servfail, &extended_errors);
                    (servfail, ReplyOrigin::local(Route::Failed, "servfail"))
                }
            }
            HedgeError::Timeout => {
                if let Some(stale) = serve_stale(
                    cfg,
                    state,
                    &key,
                    name,
                    qtype,
                    domain_trim,
                    "upstream-timeout",
                    RefreshSource::Demand,
                    tx_id,
                    request,
                )
                .await
                {
                    stale
                } else {
                    report_servfail(cfg, domain_trim, qtype, "upstream-timeout", None);
                    (
                        build_servfail_with_ede(
                            tx_id,
                            name,
                            qtype,
                            ede_for_reason("upstream-timeout"),
                            "upstream timeout",
                            request,
                        ),
                        ReplyOrigin::local(Route::Failed, "servfail"),
                    )
                }
            }
            HedgeError::Cancelled => {
                report_servfail(cfg, domain_trim, qtype, "cancelled", None);
                (
                    build_servfail_with_ede(
                        tx_id,
                        name,
                        qtype,
                        EDE_OTHER,
                        "query cancelled",
                        request,
                    ),
                    ReplyOrigin::local(Route::Failed, "servfail"),
                )
            }
        },
    }
}

/// Attaches an RFC 8914 Extended DNS Error option (`INFO-CODE u16 BE ||
/// EXTRA-TEXT utf8`) to the OPT record. `info_code` is one of the EDE_*
/// constants. Keep `extra_text` to a few dozen bytes so the OPT fits the
/// EDNS0 payload size clients advertise.
fn attach_ede(msg: &mut Message, info_code: u16, extra_text: &str) {
    let mut buf = Vec::with_capacity(2 + extra_text.len());
    buf.extend_from_slice(&info_code.to_be_bytes());
    if !extra_text.is_empty() {
        buf.extend_from_slice(extra_text.as_bytes());
    }
    msg.edns
        .get_or_insert_with(Edns::new)
        .options_mut()
        .insert(EdnsOption::Unknown(15, buf));
}

/// Appends the Extended DNS Errors a provider attached to its own response,
/// after any EDE the resolver attached. Only EDE options travel. The bounds
/// on their number and size are applied where they are read
/// (`ExtendedErrors::from_message`).
fn attach_provider_ede(msg: &mut Message, extended_errors: &ExtendedErrors) {
    for payload in extended_errors.payloads() {
        msg.edns
            .get_or_insert_with(Edns::new)
            .options_mut()
            .insert(EdnsOption::Unknown(15, payload.clone()));
    }
}

/// SERVFAIL tagged with an EDE code so clients and `dig` see why the resolver
/// gave up.
fn build_servfail_with_ede(
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    info_code: u16,
    extra_text: &str,
    request: &Message,
) -> Message {
    let mut m = empty_message();
    question_header(&mut m, tx_id, name, qtype, request);
    m.metadata.response_code = ResponseCode::ServFail;
    attach_ede(&mut m, info_code, extra_text);
    m
}

/// Serializes `msg` for `transport`. On UDP, when the wire exceeds the
/// client's payload cap, it drops EDE options and additional records first,
/// and only then trailing answer RRs with TC=1 (RFC 1035 §4.2.1, RFC 2181 §9).
/// TCP gets the full wire.
///
/// With `client_edns` set, every response carries an OPT with the resolver's
/// payload size and the client's DO bit. An existing OPT (for example one
/// carrying EDE from `attach_ede`) keeps its options. With `None` the OPT is
/// stripped, as RFC 6891 §6.1.1 requires, and any EDE is lost.
fn finalize_wire(mut msg: Message, transport: Transport, client_edns: Option<&Edns>) -> Vec<u8> {
    // Last gate before every response leaves the resolver, so it is also the
    // one place that can guarantee RFC 2181 §5.2 for locally built answers and
    // for cache hits whose records were aged individually.
    normalize_rrset_ttls(&mut msg);

    let client_dnssec_ok = client_edns
        .map(|opt| opt.flags().dnssec_ok)
        .unwrap_or(false);

    msg = msg.maybe_strip_dnssec_records(client_dnssec_ok);

    // RFC 6891 §6.1.1: no OPT in a reply to a query that lacked one.
    // `attach_ede` adds an OPT regardless of client EDNS support.
    if client_edns.is_none() {
        msg.edns = None;
    }

    // The OPT advertises this resolver's own receive capacity (RFC 6891
    // §6.2.3), not an echo of the client's. The client's value only bounds
    // the response size below. DO is echoed. EDE options already in the OPT
    // survive.
    if client_edns.is_some() {
        let entry = msg.edns.get_or_insert_with(Edns::new);
        entry.set_max_payload(crate::listener::UDP_PAYLOAD_SIZE);
        entry.set_dnssec_ok(client_dnssec_ok);
    }

    let cap = match transport.cap() {
        Some(c) if c >= 512 => c,
        // RFC 1035's minimum is 512. A smaller advertised cap would force
        // truncation on every reply.
        Some(_) => 512,
        None => return message_to_bytes_or_warn(&msg, "finalize_wire"),
    };

    let bytes = message_to_bytes_or_warn(&msg, "finalize_wire");
    if bytes.len() <= cap {
        return bytes;
    }

    // RFC 8914 §3: omit optional diagnostics before discarding DNS records.
    if let Some(edns) = &mut msg.edns {
        edns.options_mut()
            .remove(hickory_proto::rr::rdata::opt::EdnsCode::Unknown(15));
        let trial = message_to_bytes_or_warn(&msg, "finalize_wire");
        if trial.len() <= cap {
            return trial;
        }
    }

    // RFC 2181 §9: additional data is optional. If its removal is enough,
    // the response is complete and TC stays clear.
    if !msg.additionals.is_empty() {
        msg.additionals.clear();
        let trial = message_to_bytes_or_warn(&msg, "finalize_wire");
        if trial.len() <= cap {
            return trial;
        }
    }

    // Required data does not fit. Trailing answer RRs go one at a time and
    // TC=1 tells the client to retry over TCP. Authority stays because it
    // anchors negative caching and DNSSEC denial proofs.
    msg.metadata.truncation = true;
    while !msg.answers.is_empty() {
        msg.answers.pop();
        let trial = message_to_bytes_or_warn(&msg, "finalize_wire");
        if trial.len() <= cap {
            return trial;
        }
    }
    msg.authorities.clear();
    let trial = message_to_bytes_or_warn(&msg, "finalize_wire");
    if trial.len() <= cap {
        return trial;
    }
    // Oversized options or a pathological question section can exceed even
    // the minimum UDP budget. Keep the OPT metadata, then bound the question
    // section. Every retry removes data, so this fallback always terminates.
    if let Some(edns) = &mut msg.edns {
        *edns.options_mut() = Default::default();
    }
    loop {
        let trial = message_to_bytes_or_warn(&msg, "finalize_wire");
        if trial.len() <= cap {
            return trial;
        }
        if msg.queries.pop().is_none() {
            return Vec::new();
        }
    }
}

/// `msg.to_bytes()` that logs a failure with the call-site `context` and
/// falls back to a header/question-only SERVFAIL, so the client gets an
/// explicit error instead of a timeout. Returns empty bytes only when that
/// fallback also fails.
fn message_to_bytes_or_warn(msg: &Message, context: &str) -> Vec<u8> {
    match msg.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            log::warn!(
                "message serialize failed ({}): {}; returning SERVFAIL",
                context,
                e
            );
            servfail_wire_for_unserializable_message(msg).unwrap_or_else(|fallback_error| {
                log::warn!(
                    "message serialize fallback failed ({}): {}",
                    context,
                    fallback_error
                );
                Vec::new()
            })
        }
    }
}

fn servfail_wire_for_unserializable_message(msg: &Message) -> Result<Vec<u8>, ProtoError> {
    let mut fallback = empty_message();
    fallback.metadata.id = msg.metadata.id;
    fallback.metadata.op_code = msg.metadata.op_code;
    fallback.metadata.recursion_desired = msg.metadata.recursion_desired;
    fallback.metadata.recursion_available = true;
    fallback.metadata.checking_disabled = msg.metadata.checking_disabled;
    fallback.metadata.response_code = ResponseCode::ServFail;
    if let Some(query) = msg.queries.first() {
        fallback.add_query(query.clone());
    }
    fallback.to_bytes()
}

/// Maps a SERVFAIL reason tag (closed set from `report_servfail`) to an
/// RFC 8914 EDE info code, so clients learn the cause without seeing the
/// free-form error.
fn ede_for_reason(reason: &str) -> u16 {
    match reason {
        "all-upstream-failed" => EDE_NO_REACHABLE_AUTHORITY,
        "upstream-timeout" | "forward-upstream-error" => EDE_NETWORK_ERROR,
        "module-not-ready" => EDE_NOT_READY,
        // EDE 0 with explanatory text, deliberately. A bare SERVFAIL says the
        // upstream failed, not why. RFC 8914's specific codes (6 DNSSEC Bogus,
        // 7 Signature Expired, ...) would be a guess. When the provider stated
        // the cause with its own EDE, `attach_provider_ede` forwards it after
        // this one.
        "upstream-response-failure" => EDE_OTHER,
        _ => EDE_OTHER,
    }
}

/// The SERVFAIL reason, EDE info-code and EDE text for a provider that
/// answered with a failure rcode.
///
/// Kept separate so the mapping is testable and the caller's match arm cannot
/// hardcode an EDE that disagrees with what the providers did. Only this case
/// lives here. The other `HedgeError` arms keep their strings inline, so there
/// is one place for each to drift.
fn servfail_for_upstream_response(rcode: ResponseCode) -> (&'static str, u16, String) {
    (
        "upstream-response-failure",
        ede_for_reason("upstream-response-failure"),
        format!("upstream returned {rcode}"),
    )
}

/// Cache lifetime for a positive answer, in seconds. `0` means do not cache,
/// and `DnsCache::insert` refuses it. That happens when the upstream published
/// TTL 0 (RFC 2181 §8) or the response has no answer RRset.
fn positive_cache_ttl(msg: &Message) -> u32 {
    // RFC 2181 §5.2: per-RRset TTLs are independent. RFC 2308 §3 reserves
    // the SOA MINIMUM (and the authority SOA TTL) for negative caching. Using
    // it here would cut the lifetime of an answer that arrives with an SOA
    // alongside (www A 300s + zone SOA 60s).
    let min_ttl = msg
        .answers
        .iter()
        .filter(|r| r.record_type() != RecordType::OPT)
        .map(|r| r.ttl)
        .min()
        .unwrap_or(0);
    clamp_ttl(min_ttl)
}

/// RFC 2181 §5.2 forbids sending an RRset whose records carry different TTLs.
/// Upstream answers routinely violate it, because every record ages on its own
/// in upstream caches, and a downstream resolver that keeps only the
/// longest-lived member of a split RRset serves a partial answer once the
/// shortest expires. Every RRset (owner + class + type) is collapsed to its
/// minimum TTL before the message is cached or written to the wire.
fn normalize_rrset_ttls(msg: &mut Message) {
    normalize_section_rrset_ttls(&mut msg.answers);
    normalize_section_rrset_ttls(&mut msg.authorities);
    normalize_section_rrset_ttls(&mut msg.additionals);
}

fn normalize_section_rrset_ttls(records: &mut [Record]) {
    if records.len() < 2 {
        return;
    }
    let mut normalized = Vec::with_capacity(records.len());
    {
        let mut minimums: std::collections::HashMap<(&Name, DNSClass, RecordType), u32> =
            std::collections::HashMap::new();
        for rec in records.iter() {
            minimums
                .entry((&rec.name, rec.dns_class, rec.record_type()))
                .and_modify(|ttl| *ttl = (*ttl).min(rec.ttl))
                .or_insert(rec.ttl);
        }
        for rec in records.iter() {
            normalized.push(
                minimums
                    .get(&(&rec.name, rec.dns_class, rec.record_type()))
                    .copied()
                    .unwrap_or(rec.ttl),
            );
        }
    }
    for (rec, ttl) in records.iter_mut().zip(normalized) {
        rec.ttl = ttl;
    }
}

fn remaining_ttl_secs(entry: &CachedEntry, now: Instant) -> u64 {
    entry.expires_at.saturating_duration_since(now).as_secs()
}

fn should_prefetch_entry(entry: &CachedEntry, now: Instant, popular: bool) -> bool {
    should_prefetch_entry_at(entry, now, crate::cache::cache_clock_secs(), popular)
}

/// Seconds before expiry in which an entry becomes a prefetch candidate.
/// Capped at a third of the entry's lifetime so short TTLs (the cache honours
/// them down to 1s) do not sit permanently inside the window and turn every
/// hit into an upstream refill. For TTLs of 30s or more this is the flat
/// `PREFETCH_REMAINING_THRESHOLD_SECS`.
fn prefetch_window_secs(entry: &CachedEntry) -> u64 {
    PREFETCH_REMAINING_THRESHOLD_SECS.min(u64::from(entry.original_ttl_secs) / 3)
}

/// `popular` is whether the entry's key is in `history::popular()`. A popular
/// entry skips the idle cut. Every other condition still applies.
fn should_prefetch_entry_at(
    entry: &CachedEntry,
    now: Instant,
    now_usage_secs: u64,
    popular: bool,
) -> bool {
    let remaining = remaining_ttl_secs(entry, now);
    entry.original_ttl_secs > 0
        && !response_is_negative(&entry.message)
        && remaining > 0
        && remaining <= prefetch_window_secs(entry)
        && (popular
            || now_usage_secs.saturating_sub(entry.last_used_secs.load(Ordering::Relaxed))
                <= PREFETCH_MAX_UNUSED_SECS)
}

fn is_prefetch_candidate(entry: &CachedEntry, now: Instant, popular: bool) -> bool {
    !entry.message.answers.is_empty() && should_prefetch_entry(entry, now, popular)
}

pub(crate) fn prefetch_qtype_allowed(qtype: RecordType) -> bool {
    !matches!(
        qtype,
        RecordType::ANY
            | RecordType::AXFR
            | RecordType::IXFR
            | RecordType::OPT
            | RecordType::TSIG
            | RecordType::ZERO
            | RecordType::Unknown(_)
    )
}

pub async fn run_prefetch_loop(
    state: Arc<crate::state::ModuleState>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(PREFETCH_SCAN_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut scan_offset = 0usize;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tick.tick() => scan_prefetch_candidates(&state, &cancel, &mut scan_offset).await,
        }
    }
}

async fn scan_prefetch_candidates(
    state: &Arc<crate::state::ModuleState>,
    cancel: &tokio_util::sync::CancellationToken,
    scan_offset: &mut usize,
) {
    if !crate::config::current().prefetch {
        return;
    }
    let now = Instant::now();
    let popular = crate::history::popular();
    let mut spawned = 0usize;
    let mut inspected = 0usize;
    let mut next_offset = 0usize;
    let mut exhausted = true;
    for (idx, (key_arc, entry)) in state.cache.iter().enumerate().skip(*scan_offset) {
        if spawned >= PREFETCH_MAX_PER_TICK
            || inspected >= PREFETCH_MAX_INSPECTED_PER_TICK
            || cancel.is_cancelled()
        {
            next_offset = idx;
            exhausted = false;
            break;
        }
        inspected += 1;
        let key = (*key_arc).clone();
        if !is_prefetch_candidate(&entry, now, popular.contains(&key)) {
            continue;
        }
        let qtype = RecordType::from(key.qtype);
        if !prefetch_qtype_allowed(qtype) {
            continue;
        }
        let Ok(name) = Name::from_str(&format!("{}.", key.name)) else {
            log::debug!("prefetch skip invalid name: {}", key.name);
            continue;
        };
        match try_spawn_prefetch(
            state.clone(),
            key,
            name,
            qtype,
            RefreshSource::PeriodicPrefetch,
            entry.refresh_state.clone(),
            cancel.clone(),
        ) {
            SpawnOutcome::Spawned => spawned += 1,
            SpawnOutcome::AlreadyInFlight => {}
            // No idle permits or the runtime refuses spawns. Retry this entry
            // on the next tick and stop scanning the rest of the cache.
            SpawnOutcome::PermitExhausted | SpawnOutcome::SpawnFailed => {
                next_offset = idx;
                exhausted = false;
                break;
            }
        }
    }
    *scan_offset = if exhausted || inspected == 0 {
        0
    } else {
        next_offset
    };
}

fn prefetch_semaphore() -> Arc<Semaphore> {
    static SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEMAPHORE
        .get_or_init(|| Arc::new(Semaphore::new(PREFETCH_MAX_CONCURRENT)))
        .clone()
}

pub(crate) enum SpawnOutcome {
    Spawned,
    AlreadyInFlight,
    PermitExhausted,
    SpawnFailed,
}

/// Identity of the routing policy a prefetch was scheduled under.
///
/// A prefetch has no client behind it, so it must never outlive the policy
/// that justified it: an answer pulled from the public pool under the old
/// policy would land in the cache and keep leaking a namespace the user has
/// since made private. Clearing the cache cannot recall a dispatch already on
/// the wire, which is why the generation is checked again immediately before
/// the dispatch and again before the insert.
///
/// The published `Arc`s are held rather than compared by address, so a freed
/// snapshot can never be mistaken for the live one through a reused
/// allocation. Inputs with no published generation (blocklist, local zones,
/// the RFC 8020 tracker) are covered by re-running the route decision itself
/// at both checkpoints.
#[derive(Clone)]
struct PolicyGeneration {
    policy: Arc<RuntimePolicySnapshot>,
    ephemeral_zones: Arc<crate::zones::ForwardZones>,
    /// The captive forward is pinned by published value, not only by its
    /// counter. Reading a counter alone makes coherence depend on the order
    /// its publisher happens to use: a capture landing between the two writes
    /// would pair a generation with a forward that is not the one it names,
    /// and the revalidation would accept it.
    forward: Arc<Option<Arc<crate::forward::ForwardResolver>>>,
    forward_generation: u64,
}

impl PolicyGeneration {
    fn capture(state: &ModuleState) -> Self {
        Self {
            policy: state.policy.load_full(),
            ephemeral_zones: Arc::clone(&state.ephemeral_zones.load()),
            forward: state.forward.load_full(),
            forward_generation: state.forward_generation.load(Ordering::Acquire),
        }
    }

    fn is_current(&self, state: &ModuleState) -> bool {
        Arc::ptr_eq(&self.policy, &state.policy.load_full())
            && Arc::ptr_eq(&self.ephemeral_zones, &state.ephemeral_zones.load())
            && Arc::ptr_eq(&self.forward, &state.forward.load_full())
            && self.forward_generation == state.forward_generation.load(Ordering::Acquire)
    }
}

/// The single decision that says whether a name may still be resolved through
/// the public DoH pool.
///
/// A prefetch never re-enters `handle_wire_inner`, so without this it refills
/// the cache straight from the public pool for names the live policy has since
/// claimed. It walks the same ladder a client query walks before the public
/// path (overrides, blocklist, then `select_pre_public_route` in its fixed
/// order), and any match means the name is privately routed now.
///
/// The prefetch is then abandoned, never redirected. A private answer belongs
/// to its own route's response path, and writing it under the public cache key
/// would hand it to every later public lookup of the same name.
async fn prefetch_public_route_allowed(
    state: &ModuleState,
    policy: &RuntimePolicySnapshot,
    name: &Name,
    qtype: RecordType,
    domain_trim: &str,
) -> bool {
    if !matches!(
        policy.overrides.resolve_zone(domain_trim),
        crate::overrides::ZoneMatch::None
    ) {
        return false;
    }
    if !matches!(decide(domain_trim, qtype), BlockDecision::Allow) {
        return false;
    }
    let request = prefetch_probe_request(name, qtype);
    matches!(
        select_pre_public_route(state, policy, 0, name, qtype, &request, domain_trim).await,
        PrePublicRoute::None
    )
}

/// Minimal request handed to the route ladder on behalf of a prefetch. Routes
/// that answer locally build a response from it. The prefetch discards that
/// response and reads only which route claimed the name.
fn prefetch_probe_request(name: &Name, qtype: RecordType) -> Message {
    let mut request = Message::new(0, MessageType::Query, OpCode::Query);
    let mut query = DnsQuery::new();
    query
        .set_name(name.clone())
        .set_query_type(qtype)
        .set_query_class(DNSClass::IN);
    request.add_query(query);
    request
}

async fn prefetch_may_use_public_pool(
    state: &ModuleState,
    generation: &PolicyGeneration,
    key: &CacheKey,
    name: &Name,
    qtype: RecordType,
) -> bool {
    generation.is_current(state)
        && prefetch_public_route_allowed(state, &generation.policy, name, qtype, &key.name).await
}

fn try_spawn_prefetch(
    state: Arc<crate::state::ModuleState>,
    key: CacheKey,
    name: Name,
    qtype: RecordType,
    source: RefreshSource,
    expected_refresh_state: Arc<RefreshState>,
    cancel: tokio_util::sync::CancellationToken,
) -> SpawnOutcome {
    let Ok(permit) = prefetch_semaphore().try_acquire_owned() else {
        return SpawnOutcome::PermitExhausted;
    };
    if expected_refresh_state.try_start(source).is_err() {
        return SpawnOutcome::AlreadyInFlight;
    }
    let generation = PolicyGeneration::capture(&state);
    let state_for_spawn_error = expected_refresh_state.clone();
    match crate::runtime::spawn(async move {
        let _permit = permit;
        prefetch_refill(
            state,
            key,
            name,
            qtype,
            expected_refresh_state,
            generation,
            cancel,
        )
        .await;
    }) {
        Ok(_) => SpawnOutcome::Spawned,
        Err(e) => {
            state_for_spawn_error.finish();
            log::warn!("{} spawn failed: {}", source.as_str(), e);
            SpawnOutcome::SpawnFailed
        }
    }
}

/// Applies the DNS-rebinding filter to an answer a background task is about
/// to cache: a prefetch refill or a refined winner. Returns `false`
/// when every useful answer was stripped, so the caller abandons the refill
/// and lets the existing entry expire naturally instead of caching a
/// synthetic NODATA. A partially filtered refill keeps its public data and
/// carries EDE 17, so a client served from the prefetched entry sees the same
/// diagnostics the hedge path would have attached.
fn apply_background_rebinding_filter(
    msg: &mut Message,
    name: &Name,
    qtype: RecordType,
    source: &str,
) -> bool {
    let filter = crate::rebinding::filter_rebindable_records(msg);
    if !filter.changed() {
        return true;
    }
    crate::stats::add(
        &counters().rebinding_filtered,
        filter.stripped_addresses as u64,
    );
    if filter.all_useful_answers_stripped() {
        return false;
    }
    log::info!(
        "rebinding: stripped {} private address records on {} for {} {:?}",
        filter.stripped_addresses,
        source,
        name,
        qtype
    );
    attach_ede(msg, EDE_FILTERED, "private-address filter");
    true
}

#[derive(Debug, PartialEq, Eq)]
enum PrefetchOutcome {
    /// The name is no longer eligible for the public pool, or the policy moved
    /// on while the refill was in flight. Nothing was dispatched or cached.
    /// Silent by design: speculative work, no client waiting on it.
    Aborted,
    /// Dispatch failed, was cancelled, or the answer was not cacheable.
    NotRefilled,
    /// A fresh answer, positive or negative, replaced the cached entry.
    Refilled,
    /// A provider proved the name gone without a cacheable negative, so the
    /// positive entry was dropped instead of replaced.
    Withdrawn,
}

/// Fires one hedge dispatch for `(name, qtype)` and writes the winner back
/// into the cache. Runs in a detached task for an entry inside the prefetch
/// window. The caller has already claimed `refresh_state` on that entry, so no
/// other prefetch for the key runs at the same time. On failure the cache
/// keeps serving the existing entry until it expires.
///
/// `cancel` comes from the runtime's global token so `dns_shutdown` aborts
/// the refill. Otherwise the task could outlive the runtime teardown, hold
/// cache or pool references after `clear_state` and race the next `dns_init`.
async fn prefetch_refill(
    state: Arc<crate::state::ModuleState>,
    key: CacheKey,
    name: Name,
    qtype: RecordType,
    expected_refresh_state: Arc<RefreshState>,
    generation: PolicyGeneration,
    cancel: tokio_util::sync::CancellationToken,
) -> PrefetchOutcome {
    let _refresh_guard = RefreshStateGuard::new(expected_refresh_state.clone());
    if !prefetch_may_use_public_pool(&state, &generation, &key, &name, qtype).await {
        return PrefetchOutcome::Aborted;
    }
    #[cfg(test)]
    tests::run_prefetch_pre_dispatch_hook(&state);
    // Last policy read before `dispatch` is entered. It narrows the swap race
    // but does not close it. `dispatch` staggers hedges behind a delay, so for
    // part of the traffic the first packet leaves well after this check.
    if !generation.is_current(&state) {
        return PrefetchOutcome::Aborted;
    }
    inc(&counters().prefetch_refills);
    let cache_epoch = state.cache.capture_epoch();
    let result = tokio::select! {
        _ = cancel.cancelled() => {
            return PrefetchOutcome::NotRefilled;
        },
        r = dispatch(&state.pool, &name, qtype, false, cancel.clone()) => r,
    };
    let mut result = match result {
        Ok(result) => result,
        Err(HedgeError::AllFailed {
            negative: Some(error),
            negative_idx,
        }) => {
            return prefetch_store_negative(
                &state,
                &generation,
                &key,
                &name,
                qtype,
                &error,
                negative_idx,
                &expected_refresh_state,
            )
            .await;
        }
        Err(_) => return PrefetchOutcome::NotRefilled,
    };
    // The dispatch is already off the wire, so the policy it was authorised
    // against may have been replaced meanwhile. Re-check before the answer
    // becomes reachable through the cache.
    if !prefetch_may_use_public_pool(&state, &generation, &key, &name, qtype).await {
        return PrefetchOutcome::Aborted;
    }
    let mut msg = message_from_lookup(0, &name, qtype, &result.first);
    if crate::config::BLOCK_REBINDING
        && !apply_background_rebinding_filter(&mut msg, &name, qtype, "prefetch")
    {
        return PrefetchOutcome::NotRefilled;
    }
    let provider_name = state
        .pool
        .all()
        .get(result.first_idx)
        .map(|p| p.name.to_string())
        .unwrap_or_else(|| format!("provider#{}", result.first_idx));
    let ttl = positive_cache_ttl(&msg);
    let entry = CachedEntry::scaffold(msg, provider_name);
    let Some(refresh_state) = state
        .cache
        .insert_prefetch_returning_state(key.clone(), entry, ttl, &expected_refresh_state)
        .await
    else {
        return PrefetchOutcome::NotRefilled;
    };
    spawn_refinement(
        &mut result,
        &state,
        key,
        &name,
        qtype,
        cache_epoch,
        refresh_state,
    );
    PrefetchOutcome::Refilled
}

/// A provider proved the name gone or empty while the entry still held a
/// positive answer. Keeping that answer until it expires, or serving it stale
/// after that, would hand out an address the authority withdrew. The entry is
/// replaced by the negative when it can be cached and dropped when it cannot,
/// under the same identity guard as a positive refill, and an NXDOMAIN
/// establishes the RFC 8020 cut a demand query would.
#[allow(clippy::too_many_arguments)]
async fn prefetch_store_negative(
    state: &Arc<crate::state::ModuleState>,
    generation: &PolicyGeneration,
    key: &CacheKey,
    name: &Name,
    qtype: RecordType,
    error: &NetError,
    negative_idx: Option<usize>,
    expected_refresh_state: &Arc<RefreshState>,
) -> PrefetchOutcome {
    if !prefetch_may_use_public_pool(state, generation, key, name, qtype).await {
        return PrefetchOutcome::Aborted;
    }
    let request = prefetch_probe_request(name, qtype);
    match classify_negative_err(0, name, qtype, error, &request) {
        Some(NegativeAnswer::Cacheable { message, ttl_secs }) => {
            let provider_name = negative_idx
                .and_then(|i| state.pool.all().get(i).map(|p| p.name.to_string()))
                .unwrap_or_else(|| "negative".into());
            let is_nxdomain = message.metadata.response_code == ResponseCode::NXDomain;
            let authorities = message.authorities.clone();
            let entry = CachedEntry::scaffold(message, provider_name);
            let replaced = state
                .cache
                .insert_prefetch_if_current(key.clone(), entry, ttl_secs, expected_refresh_state)
                .await;
            if !replaced {
                return PrefetchOutcome::NotRefilled;
            }
            if is_nxdomain {
                let terminal = negative_terminal_name(error).unwrap_or(name);
                state
                    .cache
                    .insert_nxdomain_apex_with_ttl(
                        &nxdomain_apex_from(terminal),
                        ttl_secs,
                        &authorities,
                    )
                    .await;
            }
            PrefetchOutcome::Refilled
        }
        Some(NegativeAnswer::Uncacheable { .. }) => {
            if state
                .cache
                .invalidate_if_current(key, expected_refresh_state)
                .await
            {
                PrefetchOutcome::Withdrawn
            } else {
                PrefetchOutcome::NotRefilled
            }
        }
        Some(NegativeAnswer::Unresolvable) | None => PrefetchOutcome::NotRefilled,
    }
}

async fn wait_for_shared_refresh(
    refresh_state: &RefreshState,
    cancel: &CancellationToken,
    client_timeout_ms: u32,
) -> &'static str {
    tokio::select! {
        _ = refresh_state.wait_for_completion() => "refresh-no-fresh-answer",
        _ = tokio::time::sleep(Duration::from_millis(u64::from(client_timeout_ms))) => "refresh-client-timeout",
        _ = cancel.cancelled() => "cancelled",
    }
}

fn serve_stale_log_message(
    domain: &str,
    qtype: RecordType,
    reason: &str,
    provider: &str,
    refresh_source: RefreshSource,
) -> String {
    format!(
        "serve-stale {} {:?}: reason={} cached_provider={} refresh_source={}",
        domain,
        qtype,
        reason,
        provider,
        refresh_source.as_str()
    )
}

/// Rechecks the cache after a refresh wait or upstream failure. Fresh entries
/// retain their TTL and response code. Only expired positive answers use the
/// stale fallback, with the stale TTL, EDE 3 and a single-flight background refill.
#[allow(clippy::too_many_arguments)]
async fn serve_stale(
    cfg: &crate::config::ResolverOptions,
    state: &Arc<crate::state::ModuleState>,
    key: &CacheKey,
    name: &Name,
    qtype: RecordType,
    domain: &str,
    reason: &'static str,
    refresh_source: RefreshSource,
    tx_id: u16,
    request: &Message,
) -> Option<(Message, ReplyOrigin)> {
    if !cfg.serve_expired {
        return None;
    }
    let stale = state.cache.get_allow_expired(key).await?;
    let now = Instant::now();
    if stale.expires_at > now {
        let elapsed = now.saturating_duration_since(stale.inserted_at).as_secs() as u32;
        let rotation = crate::config::RRSET_ROUNDROBIN
            .then(|| stale.rotation_counter.fetch_add(1, Ordering::Relaxed));
        return Some((
            rewrite_id_with_decremented_ttl(
                &stale.message,
                tx_id,
                name,
                qtype,
                elapsed,
                rotation,
                request,
            ),
            ReplyOrigin::upstream(Route::Cache, stale.provider),
        ));
    }
    if response_is_negative(&stale.message) {
        return None;
    }
    inc(&counters().stale_served);
    log::warn!(
        "{}",
        serve_stale_log_message(domain, qtype, reason, &stale.provider, refresh_source)
    );
    // Fire-and-forget refill so the reply never waits. The refresh-state gate
    // stops concurrent hits on the same stale entry from spawning duplicates
    // during an upstream outage.
    if prefetch_qtype_allowed(qtype) {
        let refill_cancel = crate::runtime::cancel_token().unwrap_or_default();
        try_spawn_prefetch(
            state.clone(),
            key.clone(),
            name.clone(),
            qtype,
            RefreshSource::StaleRefill,
            stale.refresh_state.clone(),
            refill_cancel,
        );
    }
    // RFC 8767 §4: a stale answer carries a positive TTL, 30 s recommended,
    // so downstream caches hold it briefly instead of asking again at once.
    // It never exceeds the TTL the entry was cached with, so a short
    // failover TTL is not stretched. EDE 3 (Stale Answer) lets clients and
    // operators tell it apart from a fresh answer.
    let msg = rewrite_stale_for_wire(
        &stale.message,
        tx_id,
        name,
        qtype,
        stale_answer_ttl_secs(stale.original_ttl_secs),
        &format!("stale from {}", stale.provider),
        request,
    );
    let tag = format!("{}(stale)", stale.provider);
    Some((
        msg,
        ReplyOrigin {
            route: Route::Stale,
            provider: Some(stale.provider),
            block: None,
            log_source: Some(tag),
        },
    ))
}

/// Always fires the `ServfailCallback` so Swift logs the line under the `:dns`
/// subsystem. `reason` comes from a closed set (see
/// `log_hooks::emit_servfail`) so dashboards can bucket it.
///
/// `detail` carries the upstream error string ("connection refused", a TLS or
/// parse error), the only thing that tells failures apart. It is logged at
/// `warn!` so it is visible without debug tracing. Without a detail the line
/// goes only to `:dns`, so normal logs carry no duplicate SERVFAIL lines.
fn report_servfail(
    _cfg: &crate::config::ResolverOptions,
    domain: &str,
    qtype: RecordType,
    reason: &'static str,
    detail: Option<&str>,
) {
    inc(&counters().servfail);
    let qtype_str = format!("{:?}", qtype);
    crate::log_hooks::emit_servfail(domain, &qtype_str, reason);
    if let Some(detail) = detail {
        log::warn!("SERVFAIL {} {} ({}): {}", domain, qtype_str, reason, detail);
    }
}

/// Apex used by RFC 8020 `harden-below-nxdomain` is the name that does not
/// exist: "an NXDOMAIN response for QNAME means QNAME and every name below it
/// also do not exist" (RFC 8020 §2). Never the SOA owner from the authority
/// section: that poisons every sibling in the zone, so one transient or forged
/// NXDOMAIN for `g1.globo.com` would deny `*.globo.com` for the negative TTL.
fn nxdomain_apex_from(qname: &Name) -> String {
    qname.to_string()
}

/// The name hickory actually gave up on. It resolves CNAME chains internally
/// and reports the failure against the terminal query, so for `a -> b -> c`
/// this is `c`, the only name the NXDOMAIN says anything about. The client's
/// QNAME still exists as an alias, and cutting RFC 8020 there would deny
/// every descendant of a name that resolves fine.
fn negative_terminal_name(err: &NetError) -> Option<&Name> {
    use hickory_resolver::net::{DnsError, NoRecords};
    let NetError::Dns(DnsError::NoRecordsFound(NoRecords { query, .. })) = err else {
        return None;
    };
    Some(query.name())
}

/// What the resolver is allowed to do with a `NoRecordsFound` upstream error.
///
/// On hickory 0.26 `NetError::Dns(DnsError::NoRecordsFound(NoRecords))`
/// carries the SOA, authorities, response_code, and negative_ttl pulled out
/// of the raw upstream message. The variant is matched directly because the
/// public `into_soa` / `is_no_records_found` helpers return only the SOA and
/// lose the authorities and negative TTL that negative caching needs.
enum NegativeAnswer {
    /// The upstream proved the denial with an SOA and asked for a non-zero
    /// negative TTL. Safe to answer and to cache for `ttl_secs`.
    Cacheable { message: Message, ttl_secs: u32 },
    /// A negative answer that must never be stored: no SOA to bound its
    /// reuse, or an explicit TTL of 0 (RFC 2308 §5: a negative answer may
    /// not be reused once its TTL reaches zero). Answered once and dropped.
    Uncacheable { message: Message },
    /// A CNAME chain that ended in NOERROR with no data and no authority at
    /// all. Hickory reports both a CNAME loop and `MAX_QUERY_DEPTH`
    /// exhaustion in exactly this shape. It abandons the chase and builds a
    /// bare `NoRecords` from the last hop, so the terminal name differs from
    /// the QNAME and neither an SOA nor any other authority record comes with
    /// it. There is no answer to return and no proof to cache, so the query
    /// fails instead of becoming a NOERROR that `response_is_negative` reads
    /// as positive and serve-stale then replays for hours.
    ///
    /// Two shapes deliberately fall through to `Uncacheable` instead, because
    /// they are indistinguishable from an authority that simply answers
    /// NOERROR without an SOA, and failing those would turn a common lame
    /// NODATA into SERVFAIL: a chain that loops directly onto its own owner
    /// (`a CNAME a`, terminal name still the QNAME), and a terminal response
    /// that carried some authority section even though it lacked the SOA.
    Unresolvable,
}

fn classify_negative_err(
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    err: &NetError,
    request: &Message,
) -> Option<NegativeAnswer> {
    use hickory_resolver::net::{DnsError, NoRecords};
    let NetError::Dns(DnsError::NoRecordsFound(NoRecords {
        query,
        response_code,
        soa,
        authorities,
        negative_ttl,
        cname_chain,
        extended_errors,
        ..
    })) = err
    else {
        return None;
    };
    let soa_ref: Option<&Record<hickory_resolver::proto::rr::rdata::SOA>> = soa.as_deref();
    let authorities_slice: Option<&[Record]> = authorities.as_deref();
    let cname_chain: Option<&[Record]> = cname_chain.as_deref();
    if soa_ref.is_none()
        && authorities_slice.is_none_or(|records| records.is_empty())
        && *response_code == ResponseCode::NoError
        && query.name() != name
    {
        return Some(NegativeAnswer::Unresolvable);
    }
    let mut message = build_negative(
        tx_id,
        name,
        qtype,
        *response_code,
        cname_chain,
        soa_ref,
        authorities_slice,
        *negative_ttl,
        request,
    );
    attach_provider_ede(&mut message, extended_errors);
    // Prefer the upstream's explicit negative_ttl, else RFC 2308 §5
    // `min(SOA.TTL, SOA.MINIMUM)`. The SOA TTL alone can outrun MINIMUM when
    // a zone publishes a long TTL but a tight negative cap.
    let ttl_hint = negative_ttl
        .or_else(|| soa_ref.map(|r| r.ttl.min(r.data.minimum)))
        .unwrap_or(0);
    // Without an SOA there is nothing to bound the reuse of this answer, and
    // a hint of 0 is the authority saying "do not reuse at all". Either way,
    // the wire TTLs go to 0 so downstream caches drop the answer too.
    if soa_ref.is_none() || ttl_hint == 0 {
        cap_message_ttls(&mut message, 0);
        return Some(NegativeAnswer::Uncacheable { message });
    }
    let ttl_secs = clamp_neg_ttl(ttl_hint);
    cap_message_ttls(&mut message, ttl_secs);
    Some(NegativeAnswer::Cacheable { message, ttl_secs })
}

/// Hands the hedge's sibling answers, including the ones its collector is
/// still gathering, to `background_refine` for the entry identified by
/// `refresh_state`. The demand path and prefetch both go through here, so a
/// refreshed entry reaches the same consensus a fresh one does.
fn spawn_refinement(
    result: &mut crate::hedge::HedgeResult,
    state: &Arc<crate::state::ModuleState>,
    key: CacheKey,
    name: &Name,
    qtype: RecordType,
    cache_epoch: u64,
    refresh_state: Arc<RefreshState>,
) {
    let refine = result.refine.take();
    if refine.is_none() && result.all.len() <= 1 {
        return;
    }
    let mut all = result.all.clone();
    let first_idx = result.first_idx;
    let name = name.clone();
    let state = state.clone();
    if let Err(e) = crate::runtime::spawn_on_current_or_global(async move {
        if let Some(handle) = refine {
            match handle.await {
                Ok(mut late) => all.append(&mut late),
                Err(e) => log::debug!("background_refine collector join failed: {}", e),
            }
        }
        if all.len() <= 1 {
            return;
        }
        background_refine(
            all,
            first_idx,
            key,
            name,
            qtype,
            state,
            cache_epoch,
            refresh_state,
        )
        .await;
    }) {
        log::warn!("background_refine spawn failed: {}", e);
    }
}

#[allow(clippy::too_many_arguments)]
async fn background_refine(
    all: Vec<(usize, Lookup)>,
    first_idx: usize,
    key: CacheKey,
    name: Name,
    qtype: RecordType,
    state: Arc<crate::state::ModuleState>,
    // Epoch captured before the originating lookup. A refinement that started
    // before a flush must not repopulate the cleared cache.
    cache_epoch: u64,
    // Identity of the entry the originating lookup stored. The refinement
    // replaces that entry only. A newer answer under the same key stays.
    refresh_state: Arc<RefreshState>,
) {
    let candidates = unique_provider_lookups(&all);
    if candidates.len() <= 1 {
        return;
    }
    let ip_sets: Vec<_> = candidates
        .iter()
        .map(|(_, l)| normalize_ips(l.answers()))
        .collect();
    let (winner, verdict_kind): (Option<(usize, Lookup)>, &'static str) = match evaluate(&ip_sets) {
        Verdict::Consensus(set) => (
            candidates
                .iter()
                .find(|(_, l)| normalize_ips(l.answers()) == set)
                .map(|(i, l)| (*i, l.clone())),
            "consensus",
        ),
        Verdict::Probe(positional_candidates) => {
            if !crate::config::current().answer_refinement {
                (None, "first-result")
            } else {
                // These are the raw upstream sets. `probe` drops every address
                // the rebinding policy rejects before it emits a packet, so a
                // hostile answer cannot aim ICMP into private space.
                let provider_candidates =
                    provider_indexed_probe_candidates(&positional_candidates, &candidates);
                let best_idx = probe::pick_best_provider(&provider_candidates).await;
                (
                    candidates
                        .iter()
                        .find(|(i, _)| *i == best_idx)
                        .map(|(i, l)| (*i, l.clone())),
                    "answer-refinement",
                )
            }
        }
    };
    if let Some((winner_idx, lookup)) = winner {
        let winner_ips = normalize_ips(lookup.answers());
        let first_ips = candidates
            .iter()
            .find(|(i, _)| *i == first_idx)
            .map(|(_, l)| normalize_ips(l.answers()))
            .unwrap_or_default();

        // Write only when the refined answer differs from the fast-path one.
        // Trace level, because the reply and SERVFAIL channels carry the
        // user-visible signals.
        if winner_idx != first_idx || winner_ips != first_ips {
            let providers = state.pool.all();
            let first_name = providers.get(first_idx).map(|p| p.name).unwrap_or("?");
            let winner_name = providers.get(winner_idx).map(|p| p.name).unwrap_or("?");
            log::trace!(
                "cache refined ({}) {} {:?}: first={} winner={} ips={:?}",
                verdict_kind,
                name,
                qtype,
                first_name,
                winner_name,
                winner_ips
            );

            let mut msg = message_from_lookup(0, &name, qtype, &lookup);
            // The refine winner can be a different provider whose answer
            // carries private IPs the fast path never saw.
            if crate::config::BLOCK_REBINDING
                && !apply_background_rebinding_filter(&mut msg, &name, qtype, "refinement")
            {
                return;
            }
            let ttl = positive_cache_ttl(&msg);
            state
                .cache
                .replace_refined_if_epoch(
                    cache_epoch,
                    &key,
                    msg,
                    winner_name.to_string(),
                    ttl,
                    &refresh_state,
                )
                .await;
        }
    }
}

fn unique_provider_lookups(all: &[(usize, Lookup)]) -> Vec<(usize, Lookup)> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for (provider_idx, lookup) in all {
        if seen.insert(*provider_idx) {
            out.push((*provider_idx, lookup.clone()));
        }
    }
    out
}

fn provider_indexed_probe_candidates(
    positional_candidates: &[(usize, std::collections::BTreeSet<std::net::IpAddr>)],
    provider_candidates: &[(usize, Lookup)],
) -> Vec<(usize, std::collections::BTreeSet<std::net::IpAddr>)> {
    // `evaluate()` returns positions into `ip_sets`, which is built from
    // `provider_candidates` in the same order, so translate those positions
    // back to stable provider indices before answer-refinement probing.
    debug_assert!(
        positional_candidates
            .iter()
            .all(|(pos, _)| *pos < provider_candidates.len()),
        "probe candidate positions must index provider_candidates"
    );
    positional_candidates
        .iter()
        .filter_map(|(pos, ips)| {
            provider_candidates
                .get(*pos)
                .map(|(idx, _)| (*idx, ips.clone()))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
/// Prefixes a forward failure with the route that selected the resolver.
/// Forward zones and captive forwarding share `upstream_lookup`, so without
/// it a SERVFAIL does not say whether a user zone or the network's resolvers
/// failed.
fn forward_failure_detail(route: &str, error: &str) -> String {
    format!("route={route}: {error}")
}

/// The resolver a pre-public route selected, with the route's label for
/// failure diagnostics.
struct ForwardTarget<'a> {
    resolver: &'a Arc<TokioResolver>,
    route: &'a str,
}

async fn upstream_lookup(
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    target: ForwardTarget<'_>,
    transport: Transport,
    client_edns: Option<&Edns>,
    request: &Message,
) -> Vec<u8> {
    let lookup_result = match tokio::time::timeout(
        FORWARD_LOOKUP_TIMEOUT,
        target.resolver.lookup(name.clone(), qtype),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            let cfg = crate::config::current();
            let domain = name.to_string();
            let domain_trim = domain.trim_end_matches('.');
            report_servfail(
                &cfg,
                domain_trim,
                qtype,
                "upstream-timeout",
                Some(&forward_failure_detail(
                    target.route,
                    "lookup deadline exceeded",
                )),
            );
            return finalize_wire(
                build_servfail_with_ede(
                    tx_id,
                    name,
                    qtype,
                    ede_for_reason("upstream-timeout"),
                    "forward upstream timeout",
                    request,
                ),
                transport,
                client_edns,
            );
        }
    };
    match lookup_result {
        Ok(lookup) => {
            // An `Ok` with no answer or authority RRs is a protocol
            // violation. Serving it would look like a valid NOERROR/NODATA,
            // so it goes through normal error handling instead.
            if !lookup_has_payload(&lookup) {
                let cfg = crate::config::current();
                let domain = name.to_string();
                let domain_trim = domain.trim_end_matches('.');
                log::error!(
                    "upstream_lookup: empty-Ok from forward/stub resolver for {} {:?} (rcode={:?} route={})",
                    domain_trim,
                    qtype,
                    lookup.message().metadata.response_code,
                    target.route,
                );
                report_servfail(&cfg, domain_trim, qtype, "empty-upstream-response", None);
                return finalize_wire(
                    build_servfail_with_ede(
                        tx_id,
                        name,
                        qtype,
                        EDE_OTHER,
                        "upstream returned empty response",
                        request,
                    ),
                    transport,
                    client_edns,
                );
            }
            let mut msg = message_from_lookup(tx_id, name, qtype, &lookup);
            echo_request_flags(&mut msg, request);
            gate_authentic_data(&mut msg, request);
            finalize_wire(msg, transport, client_edns)
        }
        Err(e) => {
            // Forward resolvers produce the same `NoRecordsFound` shape as the
            // public hedge, so negative extraction is shared. Nothing on this
            // path is cached, so cacheable and uncacheable outcomes are
            // answered the same way.
            let cfg = crate::config::current();
            let domain = name.to_string();
            let domain_trim = domain.trim_end_matches('.');
            match classify_negative_err(tx_id, name, qtype, &e, request) {
                Some(NegativeAnswer::Cacheable { message, .. })
                | Some(NegativeAnswer::Uncacheable { message }) => {
                    return finalize_wire(message, transport, client_edns);
                }
                Some(NegativeAnswer::Unresolvable) => {
                    report_servfail(
                        &cfg,
                        domain_trim,
                        qtype,
                        "unresolvable-cname-chain",
                        Some(&forward_failure_detail(target.route, &e.to_string())),
                    );
                    return finalize_wire(
                        build_servfail_with_ede(
                            tx_id,
                            name,
                            qtype,
                            EDE_OTHER,
                            "unresolvable CNAME chain",
                            request,
                        ),
                        transport,
                        client_edns,
                    );
                }
                None => {}
            }
            report_servfail(
                &cfg,
                domain_trim,
                qtype,
                "forward-upstream-error",
                Some(&forward_failure_detail(target.route, &e.to_string())),
            );
            finalize_wire(
                build_servfail_with_ede(
                    tx_id,
                    name,
                    qtype,
                    ede_for_reason("forward-upstream-error"),
                    "forward upstream error",
                    request,
                ),
                transport,
                client_edns,
            )
        }
    }
}

fn question_header(
    msg: &mut Message,
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    request: &Message,
) {
    msg.metadata.id = tx_id;
    msg.metadata.message_type = MessageType::Response;
    msg.metadata.op_code = request.metadata.op_code;
    msg.metadata.recursion_desired = request.metadata.recursion_desired;
    msg.metadata.recursion_available = true;
    msg.metadata.checking_disabled = request.metadata.checking_disabled;
    // AD stays false. Local answers (overrides, blocklist, local zones) are
    // never validated. Only the hedge path propagates the upstream AD.
    set_question(msg, name, qtype, request);
}

/// Makes `name`, `qtype` and the request's class the only question of `msg`.
/// `name` is the request's own spelling. Cached and shared messages need this
/// because their keys are lowercased, so they carry the spelling of whichever
/// request resolved them (RFC 1035 §4.1.2: the question is copied to the reply).
fn set_question(msg: &mut Message, name: &Name, qtype: RecordType, request: &Message) {
    let mut q = DnsQuery::new();
    q.set_name(name.clone())
        .set_query_type(qtype)
        .set_query_class(
            request
                .queries
                .first()
                .map(|q| q.query_class())
                .unwrap_or(DNSClass::IN),
        );
    msg.queries.clear();
    msg.add_query(q);
}

/// RFC 6840 §5.8: a resolver sets AD only in a response to a query that
/// asked for it, with either the AD or the DO bit. The validation status the
/// provider returned stays on cached and shared messages. Only the copy sent
/// to this client is gated, so a later client that asks still sees it.
fn gate_authentic_data(response: &mut Message, request: &Message) {
    let asked = request.metadata.authentic_data
        || request
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags().dnssec_ok);
    response.metadata.authentic_data &= asked;
}

/// Echoes the request's RD (RFC 1035 §4.1.1) and CD (RFC 4035 §3.2.2) onto
/// the response. AD is validation status and is never touched here.
///
/// CD also reaches the wire. `handle_wire_inner` hands it to `dispatch`, and
/// `ProviderUpstream::lookup` picks the `CD=1` client for it, so a client
/// asking to bypass validation gets the provider's unvalidated data instead of
/// SERVFAIL. The `config.dnssec` toggle supplies only the default, for clients
/// that left the bit clear. Such a query is also kept off the shared cache and
/// out of single-flight (see `client_forces_unchecked_data`).
fn echo_request_flags(response: &mut Message, request: &Message) {
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.checking_disabled = request.metadata.checking_disabled;
}

/// A response carries payload when the answer or authority section holds at
/// least one RR. Authority-only is the normal NXDOMAIN/NODATA shape (the SOA
/// anchors negative caching). With both empty the message is not a valid
/// answer, and the hedge, `process_hedge_outcome` and `upstream_lookup`
/// reject it. The additional section (where the OPT lives) does not count.
pub(crate) fn message_has_payload(msg: &Message) -> bool {
    !msg.answers.is_empty() || !msg.authorities.is_empty()
}

/// `message_has_payload` for a hickory `Lookup`.
pub(crate) fn lookup_has_payload(lookup: &Lookup) -> bool {
    message_has_payload(lookup.message())
}

/// Builds a positive `Message` from a hickory `Lookup`. `Lookup::message()`
/// exposes the full upstream response, so the AD bit and the DNSSEC
/// authority/additional records survive. DNSSEC passthrough (`dig +dnssec`
/// AD=1) and negative-cache anchoring on the authority SOA depend on that.
fn message_from_lookup(tx_id: u16, name: &Name, qtype: RecordType, lookup: &Lookup) -> Message {
    message_from_upstream_message(tx_id, name, qtype, lookup.message())
}

fn message_from_upstream_message(
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    upstream: &Message,
) -> Message {
    let mut m = Message::new(tx_id, MessageType::Response, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.metadata.recursion_available = true;
    m.metadata.response_code = upstream.metadata.response_code;
    // RFC 6840 5.7: never claim AD without validation. With the DNSSEC toggle
    // off we send CD=1, which asks the provider *not* to validate, so whatever
    // AD comes back cannot be a validation result. Quad9 returns AD=1 under
    // CD=1 regardless of the DO bit. Cloudflare and Google do not. Forwarding
    // it would claim an authentication nothing performed, and a stub on
    // loopback cannot second-guess it.
    m.metadata.authentic_data = upstream.metadata.authentic_data && crate::config::current().dnssec;
    let mut q = DnsQuery::new();
    q.set_name(name.clone())
        .set_query_type(qtype)
        .set_query_class(DNSClass::IN);
    m.add_query(q);
    for rec in &upstream.answers {
        m.add_answer(rec.clone());
    }
    for rec in &upstream.authorities {
        m.add_authority(rec.clone());
    }
    for rec in &upstream.additionals {
        m.add_additional(rec.clone());
    }
    attach_provider_ede(&mut m, &ExtendedErrors::from_message(upstream));
    // Normalize here rather than only on the wire: this message is what the
    // cache stores, and cache hits age every record by the same elapsed time,
    // so an RRset that enters the cache split stays split on every hit.
    normalize_rrset_ttls(&mut m);
    m
}

fn build_refused(tx_id: u16, name: &Name, qtype: RecordType, request: &Message) -> Message {
    let mut m = empty_message();
    question_header(&mut m, tx_id, name, qtype, request);
    m.metadata.response_code = ResponseCode::Refused;
    m
}

/// Synthetic answer for `localhost.` and every name under it (RFC 6761
/// §6.3.2): A is 127.0.0.1, AAAA is ::1, any other qtype is NODATA (NOERROR +
/// SOA). Returns `None` for other names so the caller falls through.
///
/// macOS usually answers `localhost` from `/etc/hosts` before DNS, but clients
/// that bypass it (raw DNS APIs, custom stacks) would otherwise get NXDOMAIN.
/// The 1h TTL matches the upper end of BIND's built-in localhost zone.
fn build_localhost_response(
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    request: &Message,
    domain_trim: &str,
) -> Option<Message> {
    if !is_localhost_name(domain_trim) {
        return None;
    }
    const LOOPBACK_TTL: u32 = 3600;
    let mut m = empty_message();
    question_header(&mut m, tx_id, name, qtype, request);
    m.metadata.response_code = ResponseCode::NoError;
    match qtype {
        RecordType::A => {
            m.add_answer(Record::from_rdata(
                name.clone(),
                LOOPBACK_TTL,
                RData::A(A(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            ));
        }
        RecordType::AAAA => {
            m.add_answer(Record::from_rdata(
                name.clone(),
                LOOPBACK_TTL,
                RData::AAAA(AAAA(std::net::Ipv6Addr::LOCALHOST)),
            ));
        }
        _ => {
            // The synthetic SOA lets downstream resolvers negative-cache the
            // absence of this RRset under the configured negative bound.
            let neg_ttl = synthetic_negative_ttl_secs();
            let neg_retry = soa_i32_secs(neg_ttl);
            let soa = SOA::new(
                Name::from_ascii("localhost.").unwrap(),
                Name::from_ascii("nobody.invalid.").unwrap(),
                1,
                3600,
                neg_retry,
                604800,
                neg_ttl,
            );
            m.add_authority(Record::from_rdata(
                Name::from_ascii("localhost.").unwrap(),
                neg_ttl,
                RData::SOA(soa),
            ));
        }
    }
    Some(m)
}

/// RFC 8880 §7.1 `ipv4only.arpa`, answered locally. A carries the two
/// well-known addresses. AAAA carries them synthesized with each of the
/// attached network's NAT64 prefixes, so the system's own RFC 7050 discovery
/// sees what the network's DNS64 would answer, and is NODATA on a network
/// without NAT64. Names below it do not exist. DS is the one exception: it
/// resolves the usual way so a validator can prove the delegation insecure.
fn build_ipv4only_arpa_response(
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    request: &Message,
    domain_trim: &str,
    nat64: Option<crate::network_profile::Nat64Active>,
) -> Option<Message> {
    let apex = crate::dns64::IPV4ONLY_ARPA;
    if !domain_trim.eq_ignore_ascii_case(apex) {
        let below = domain_trim
            .to_ascii_lowercase()
            .ends_with(&format!(".{apex}"));
        return below.then(|| build_nxdomain(tx_id, name, qtype, request));
    }
    if qtype == RecordType::DS {
        return None;
    }
    let ttl = crate::dns64::SYNTHESIS_MAX_TTL_SECS;
    let mut m = empty_message();
    question_header(&mut m, tx_id, name, qtype, request);
    m.metadata.response_code = ResponseCode::NoError;
    match (qtype, nat64) {
        (RecordType::A, _) => {
            for v4 in crate::dns64::IPV4ONLY_ARPA_ADDRS {
                m.add_answer(Record::from_rdata(name.clone(), ttl, RData::A(A(v4))));
            }
        }
        (RecordType::AAAA, Some(active)) => {
            let ttl = ttl.min(active.remaining_ttl_secs(Instant::now()));
            for prefix in &active.prefixes {
                for v4 in crate::dns64::IPV4ONLY_ARPA_ADDRS {
                    m.add_answer(Record::from_rdata(
                        name.clone(),
                        ttl,
                        RData::AAAA(AAAA(prefix.synthesize(v4))),
                    ));
                }
            }
        }
        _ => {
            let apex_name = Name::from_ascii(format!("{apex}.")).expect("static name is valid");
            return Some(build_local_nodata(tx_id, name, qtype, request, &apex_name));
        }
    }
    Some(m)
}

fn is_localhost_name(domain_trim: &str) -> bool {
    let lowered = domain_trim.to_ascii_lowercase();
    lowered == "localhost" || lowered.ends_with(".localhost")
}

/// Local answer for a built-in zone. DDR uses NODATA throughout (RFC 9462),
/// while the remaining zones are authoritative empty zones (RFC 6303 §3).
///
/// Empty zones hold nothing but their own SOA and NS, so:
///
/// * the apex answers SOA, NS and ANY positively,
/// * any other type at the apex is NODATA (NOERROR + SOA authority),
/// * every name below the apex is NXDOMAIN.
///
/// Empty-zone responses set `AA=1` and put the zone apex in the SOA owner,
/// which RFC 2308 §3 requires for a downstream resolver to negative-cache the
/// denial against the right name.
///
/// `apex` comes from the table that matched, so it is already normalized the
/// same way as `domain_trim` and the two compare directly.
fn build_builtin_zone_response(
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    request: &Message,
    apex: &str,
    domain_trim: &str,
) -> Message {
    // The tables are protocol invariants that never change at runtime, so the
    // apex records are safe to cache for as long as `localhost.` synthesis.
    const EMPTY_ZONE_TTL: u32 = 3600;

    let apex_name = Name::from_ascii(format!("{apex}.")).unwrap_or_else(|_| name.clone());
    // RFC 9462 §4/6.1: upstream DDR describes the upstream, not this forwarder.
    if apex == "resolver.arpa" {
        return build_local_nodata(tx_id, name, qtype, request, &apex_name);
    }
    let neg_ttl = synthetic_negative_ttl_secs();
    // MINIMUM drives downstream negative caching, so it tracks the internal
    // negative bound even when the SOA itself is served as a positive answer.
    let soa = SOA::new(
        apex_name.clone(),
        Name::from_ascii("nobody.invalid.").unwrap(),
        1,
        3600,
        soa_i32_secs(neg_ttl),
        604800,
        neg_ttl,
    );

    let mut m = empty_message();
    question_header(&mut m, tx_id, name, qtype, request);
    m.metadata.authoritative = true;

    if domain_trim != apex {
        m.metadata.response_code = ResponseCode::NXDomain;
        m.add_authority(Record::from_rdata(apex_name, neg_ttl, RData::SOA(soa)));
        return m;
    }

    m.metadata.response_code = ResponseCode::NoError;
    if matches!(qtype, RecordType::SOA | RecordType::ANY) {
        m.add_answer(Record::from_rdata(
            apex_name.clone(),
            EMPTY_ZONE_TTL,
            RData::SOA(soa.clone()),
        ));
    }
    if matches!(qtype, RecordType::NS | RecordType::ANY) {
        m.add_answer(Record::from_rdata(
            apex_name.clone(),
            EMPTY_ZONE_TTL,
            RData::NS(NS(apex_name.clone())),
        ));
    }
    if m.answers.is_empty() {
        m.add_authority(Record::from_rdata(apex_name, neg_ttl, RData::SOA(soa)));
    }
    m
}

fn build_nxdomain(tx_id: u16, name: &Name, qtype: RecordType, request: &Message) -> Message {
    let mut m = empty_message();
    question_header(&mut m, tx_id, name, qtype, request);
    m.metadata.response_code = ResponseCode::NXDomain;
    // The SOA owner is the queried name because no delegation is tracked.
    // MINIMUM follows the internal negative bound so blocks and unblocks
    // recover downstream on the same short window.
    let neg_ttl = synthetic_negative_ttl_secs();
    let neg_retry = soa_i32_secs(neg_ttl);
    let soa = SOA::new(
        Name::from_ascii("localhost.").unwrap(),
        Name::from_ascii("nobody.invalid.").unwrap(),
        1,
        3600,
        neg_retry,
        604800,
        neg_ttl,
    );
    let rec = Record::from_rdata(name.clone(), neg_ttl, RData::SOA(soa));
    m.add_authority(rec);
    m
}

/// NODATA (NOERROR + empty answer + synthesised SOA) for a locally claimed
/// name with no configured answer, including resolver discovery.
/// The SOA uses the common `localhost.`/`nobody.invalid.` convention.
fn build_local_nodata(
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    request: &Message,
    apex: &Name,
) -> Message {
    let mut m = empty_message();
    question_header(&mut m, tx_id, name, qtype, request);
    m.metadata.response_code = ResponseCode::NoError;
    let neg_ttl = synthetic_negative_ttl_secs();
    let neg_retry = soa_i32_secs(neg_ttl);
    let soa = SOA::new(
        Name::from_ascii("localhost.").unwrap(),
        Name::from_ascii("nobody.invalid.").unwrap(),
        1,
        3600,
        neg_retry,
        604800,
        neg_ttl,
    );
    // RFC 2308 §3: the SOA owner is the claimed zone apex, not the query name.
    let rec = Record::from_rdata(apex.clone(), neg_ttl, RData::SOA(soa));
    m.add_authority(rec);
    m
}

fn synthetic_negative_ttl_secs() -> u32 {
    crate::cache::NEG_MAX_TTL_SECS
}

fn soa_i32_secs(ttl: u32) -> i32 {
    i32::try_from(ttl).unwrap_or(i32::MAX)
}

fn response_is_negative(msg: &Message) -> bool {
    if msg.metadata.response_code == ResponseCode::NXDomain {
        return true;
    }
    if msg.metadata.response_code != ResponseCode::NoError
        || !msg
            .authorities
            .iter()
            .any(|r| matches!(&r.data, RData::SOA(_)))
    {
        return false;
    }
    match msg.queries.first().map(|q| q.query_type()) {
        Some(qtype) => !msg.answers.iter().any(|r| r.record_type() == qtype),
        None => msg.answers.is_empty(),
    }
}

/// Placeholder `Message`. `question_header` overwrites the id, type and opcode
/// that `Message::new` requires.
fn empty_message() -> Message {
    Message::new(0, MessageType::Response, OpCode::Query)
}

/// Builds a negative response preserving the upstream response code (NXDOMAIN
/// vs NODATA), the CNAME chain that led to it, SOA, authorities, and negative
/// TTL, which downstream negative caching and DNSSEC validation need.
/// Returns the `Message` so callers can both serialize it and cache it without
/// a round-trip.
#[allow(clippy::too_many_arguments)]
fn build_negative(
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    response_code: ResponseCode,
    cname_chain: Option<&[Record]>,
    soa: Option<&Record<hickory_proto::rr::rdata::SOA>>,
    authorities: Option<&[Record]>,
    negative_ttl: Option<u32>,
    request: &Message,
) -> Message {
    let mut m = empty_message();
    question_header(&mut m, tx_id, name, qtype, request);
    m.metadata.response_code = response_code;
    // RFC 2308 §2.1 and §2.2: the aliases that led to the negative belong in
    // the answer section, so the client learns the name exists and where it
    // points. `response_is_negative` still reads the message as negative
    // because no record of the queried type is among them.
    for rec in cname_chain.unwrap_or_default() {
        m.add_answer(rec.clone());
    }
    let mut soa_added = false;
    if let Some(soa_rec) = soa {
        let ttl = negative_ttl.unwrap_or(soa_rec.ttl);
        let rec = Record::from_rdata(soa_rec.name.clone(), ttl, RData::SOA(soa_rec.data.clone()));
        m.add_authority(rec);
        soa_added = true;
    }
    if let Some(auths) = authorities {
        for rec in auths {
            // `NoRecords::authorities` is the full wire authority section and
            // usually repeats the SOA already added from the `soa` field.
            // Skip it so clients do not see it twice. NSEC/NSEC3 and other
            // authority records pass through.
            if soa_added && matches!(&rec.data, RData::SOA(_)) {
                continue;
            }
            m.add_authority(rec.clone());
        }
    }
    // The negative authority section is cached and replayed by the RFC 8020
    // path, so it carries the same RFC 2181 §5.2 obligation as an answer.
    normalize_rrset_ttls(&mut m);
    m
}

fn build_answer(
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    rdata: &[RData],
    ttl: u32,
    request: &Message,
) -> Message {
    let mut m = empty_message();
    question_header(&mut m, tx_id, name, qtype, request);
    m.metadata.response_code = ResponseCode::NoError;
    for rd in rdata {
        let rec: Record = Record::from_rdata(name.clone(), ttl, rd.clone());
        m.add_answer(rec);
    }
    m
}

/// Rotates the trailing A/AAAA records of the answer section so repeated
/// lookups see a different order (rrset-roundrobin). Records before them
/// (a CNAME chain is order-sensitive) stay in place.
fn rotate_address_rrset(msg: &mut Message, offset: u32) {
    let mut answers = std::mem::take(&mut msg.answers);
    let first_addr = answers
        .iter()
        .position(|r| matches!(&r.data, RData::A(_) | RData::AAAA(_)));
    if let Some(start) = first_addr {
        let tail_len = answers.len() - start;
        if tail_len > 1 {
            let shift = (offset as usize) % tail_len;
            if shift > 0 {
                answers[start..].rotate_left(shift);
            }
        }
    }
    for r in answers {
        msg.add_answer(r);
    }
}

/// Serializes a cached `Message`, decrementing every record TTL (answers,
/// authority, additionals, including a negative answer's SOA) by the time
/// since insertion. RFC 1035 §3.2.1: downstream caches must see the remaining
/// TTL, or they would re-cache for the full lifetime and outlive this cache.
/// A TTL of 0 tells downstream not to cache. The question becomes the one
/// this request asked.
fn rewrite_id_with_decremented_ttl(
    msg: &Message,
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    elapsed_secs: u32,
    rotation: Option<u32>,
    request: &Message,
) -> Message {
    let mut out = msg.clone();
    out.metadata.id = tx_id;
    set_question(&mut out, name, qtype, request);
    // The cached AD bit stays what the upstream produced.
    echo_request_flags(&mut out, request);
    if elapsed_secs > 0 {
        for rec in &mut out.answers {
            rec.ttl = rec.ttl.saturating_sub(elapsed_secs);
        }
        for rec in &mut out.authorities {
            rec.ttl = rec.ttl.saturating_sub(elapsed_secs);
        }
        for rec in &mut out.additionals {
            rec.ttl = rec.ttl.saturating_sub(elapsed_secs);
        }
    }
    if let Some(offset) = rotation {
        rotate_address_rrset(&mut out, offset);
    }
    out
}

/// RFC 8767 §4 recommends 30 seconds for the TTL of a stale answer.
const STALE_ANSWER_TTL_SECS: u32 = 30;

/// TTL a stale answer is served with: the RFC 8767 recommendation, capped at
/// the TTL the entry was cached with and never 0.
fn stale_answer_ttl_secs(original_ttl_secs: u32) -> u32 {
    STALE_ANSWER_TTL_SECS.min(original_ttl_secs).max(1)
}

/// Serializes a cached `Message` for the serve-expired path with every
/// record TTL set to `ttl_secs` and EDE 3 (Stale Answer) attached, per
/// RFC 8767 §4 and §7. The question becomes the one this request asked.
fn rewrite_stale_for_wire(
    msg: &Message,
    tx_id: u16,
    name: &Name,
    qtype: RecordType,
    ttl_secs: u32,
    ede_text: &str,
    request: &Message,
) -> Message {
    let mut out = msg.clone();
    out.metadata.id = tx_id;
    set_question(&mut out, name, qtype, request);
    // The cached AD bit stays what the upstream produced.
    echo_request_flags(&mut out, request);
    for rec in &mut out.answers {
        rec.ttl = ttl_secs;
    }
    for rec in &mut out.authorities {
        rec.ttl = ttl_secs;
    }
    for rec in &mut out.additionals {
        rec.ttl = ttl_secs;
    }
    attach_ede(&mut out, EDE_STALE_ANSWER, ede_text);
    out
}

#[cfg(test)]
mod tests {
    use super::{
        background_refine, build_local_nodata, build_localhost_response, build_negative,
        build_nxdomain, classify_negative_err, client_forces_unchecked_data,
        direct_doh_probe_failure_class, ede_for_reason, gate_authentic_data, inflight_registry,
        is_localhost_name, lookup_has_payload, message_from_upstream_message, message_has_payload,
        negative_terminal_name, positive_cache_ttl, prefetch_may_use_public_pool,
        prefetch_qtype_allowed, prefetch_refill, process_hedge_outcome,
        provider_indexed_probe_candidates, resolve_below_nxdomain_or_none,
        resolve_override_or_none, resolve_public_path, resolve_shared_unless_forced_cd,
        response_is_negative, rotate_address_rrset, select_pre_public_route,
        serve_stale_log_message, servfail_for_upstream_response, should_prefetch_entry_at,
        single_flight, synthetic_negative_ttl_secs, unique_provider_lookups, CachedEntry,
        InflightKey, NegativeAnswer, PolicyGeneration, PrePublicRoute, PrefetchOutcome,
        ReplyOrigin, SharedResolution, Transport, EDE_NETWORK_ERROR, EDE_NO_REACHABLE_AUTHORITY,
        EDE_OTHER, PREFETCH_MAX_UNUSED_SECS,
    };
    use crate::cache::{CacheKey, DnsCache, RefreshSource, RefreshState};
    use crate::consensus::{evaluate, normalize_ips, Verdict};
    use crate::forward::ForwardResolver;
    use crate::hedge::HedgeError;
    use crate::history::Route;
    use crate::local_zones::LocalZones;
    use crate::overrides::OverrideStore;
    use crate::policy::RuntimePolicySnapshot;
    use crate::providers::ProviderPool;
    use crate::state::ModuleState;
    use crate::zones::ForwardZones;
    use arc_swap::ArcSwap;
    use hickory_proto::dnssec::rdata::{DNSSECRData, DS, NSEC};
    use hickory_proto::dnssec::{Algorithm, DigestType};
    use hickory_proto::op::{Message, MessageType, OpCode, Query as DnsQuery, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use hickory_resolver::lookup::Lookup;
    use hickory_resolver::net::{DnsError, NetError, NoRecords};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio_util::sync::CancellationToken;

    /// No providers, so a lookup that reaches the public path fails the same
    /// way on every machine. The production pool would query the real DoH
    /// providers, which answer on a CI runner but not on a Mac whose Content
    /// Filter blocks DoH.
    fn route_test_state() -> ModuleState {
        route_test_state_with_pool(ProviderPool::for_local_test(Vec::new()))
    }

    fn route_test_state_with_pool(pool: ProviderPool) -> ModuleState {
        ModuleState {
            pool: Arc::new(pool),
            cache: Arc::new(DnsCache::new(1_048_576)),
            policy: ArcSwap::from_pointee(RuntimePolicySnapshot {
                overrides: Arc::new(OverrideStore::new()),
                zones: Arc::new(ForwardZones::new()),
            }),
            ephemeral_zones: ArcSwap::from_pointee(Arc::new(ForwardZones::new())),
            local_zones: Arc::new(LocalZones::new()),
            forward: ArcSwap::from_pointee(None),
            forward_generation: AtomicU64::new(0),
            network: Arc::new(crate::network_profile::NetworkProfileStore::new()),
        }
    }

    #[test]
    fn direct_doh_probe_failure_classes_are_stable() {
        let mut query = DnsQuery::new();
        query
            .set_name(Name::from_ascii("absent.example.").unwrap())
            .set_query_type(RecordType::A)
            .set_query_class(DNSClass::IN);
        let negative = NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            query,
            ResponseCode::NXDomain,
        )));

        assert_eq!(
            direct_doh_probe_failure_class(&HedgeError::Timeout),
            "timeout"
        );
        assert_eq!(
            direct_doh_probe_failure_class(&HedgeError::UpstreamResponse {
                rcode: ResponseCode::Refused,
                extended_errors: Default::default(),
            }),
            "upstream-rcode"
        );
        assert_eq!(
            direct_doh_probe_failure_class(&HedgeError::AllFailed {
                negative: Some(negative),
                negative_idx: Some(0),
            }),
            "authoritative-negative"
        );
        assert_eq!(
            direct_doh_probe_failure_class(&HedgeError::AllFailed {
                negative: None,
                negative_idx: None,
            }),
            "all-failed"
        );
        assert_eq!(
            direct_doh_probe_failure_class(&HedgeError::Cancelled),
            "cancelled"
        );
    }

    fn request_for(name: &Name) -> Message {
        let mut request = Message::query();
        let mut query = DnsQuery::new();
        query
            .set_name(name.clone())
            .set_query_type(RecordType::A)
            .set_query_class(DNSClass::IN);
        request.add_query(query);
        request
    }

    /// The question section as it goes on the wire. `Name` equality ignores
    /// letter case, the wire does not.
    fn question_wire(message: &Message) -> Vec<u8> {
        use hickory_proto::serialize::binary::BinEncodable;
        let mut question = Message::query();
        question.queries = message.queries.clone();
        question.to_bytes().unwrap()[12..].to_vec()
    }

    /// The message the cache holds after `asked_as` was resolved upstream.
    fn stored_answer(asked_as: &Name) -> Message {
        let mut upstream = Message::query();
        upstream.add_answer(Record::from_rdata(
            asked_as.clone(),
            60,
            RData::A(A::new(203, 0, 113, 7)),
        ));
        message_from_upstream_message(0x1111, asked_as, RecordType::A, &upstream)
    }

    /// `CacheKey` is lowercased, so one entry answers every spelling of a name.
    /// The reply must carry the question as this client sent it (RFC 1035
    /// §4.1.2), or a client that compares it byte for byte drops the answer.
    #[tokio::test]
    async fn cache_hit_echoes_the_question_of_the_request_being_answered() {
        let state = Arc::new(route_test_state());
        let first_asker = Name::from_ascii("ExAmPlE.com.").unwrap();
        state
            .cache
            .insert(
                CacheKey::from("example.com", RecordType::A),
                CachedEntry::scaffold(stored_answer(&first_asker), "cached".into()),
                60,
            )
            .await;

        let asked = Name::from_ascii("example.COM.").unwrap();
        assert!(
            !asked.eq_case(&first_asker),
            "the two spellings must differ"
        );
        let request = request_for(&asked);
        let (reply, origin) = resolve_public_path(
            &state,
            &crate::config::current(),
            &request,
            0x2222,
            &asked,
            RecordType::A,
            "example.com",
            &CancellationToken::new(),
        )
        .await;

        assert_eq!(origin.route, Route::Cache);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(question_wire(&reply), question_wire(&request));
    }

    #[tokio::test]
    async fn stale_answer_echoes_the_question_of_the_request_being_answered() {
        let state = Arc::new(route_test_state());
        let first_asker = Name::from_ascii("ExAmPlE.com.").unwrap();
        let key = CacheKey::from("example.com", RecordType::A);
        let mut entry = CachedEntry::scaffold(stored_answer(&first_asker), "cached".into());
        entry.expires_at = Instant::now() - Duration::from_secs(1);
        entry.original_ttl_secs = 60;
        entry
            .refresh_state
            .try_start(RefreshSource::Demand)
            .unwrap();
        state.cache.inner_insert_raw(key.clone(), entry).await;

        let asked = Name::from_ascii("example.COM.").unwrap();
        assert!(
            !asked.eq_case(&first_asker),
            "the two spellings must differ"
        );
        let request = request_for(&asked);
        let (reply, origin) = super::serve_stale(
            &crate::config::ResolverOptions::default(),
            &state,
            &key,
            &asked,
            RecordType::A,
            "example.com",
            "client-timeout",
            RefreshSource::Demand,
            0x2222,
            &request,
        )
        .await
        .unwrap();

        assert_eq!(origin.route, Route::Stale);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(question_wire(&reply), question_wire(&request));
    }

    /// A request that joins an in-flight resolution receives the leader's
    /// message, which carries the leader's spelling of the name.
    #[tokio::test]
    async fn single_flight_joiner_echoes_its_own_question() {
        let state = Arc::new(route_test_state());
        let cfg = crate::config::current();
        let leader_name = Name::from_ascii("JoInEr.example.").unwrap();
        let key = CacheKey::from("joiner.example", RecordType::A);
        let inflight_key = InflightKey {
            key: key.clone(),
            dnssec: cfg.dnssec,
        };
        let Ok(leader) = super::claim_or_subscribe(&inflight_key) else {
            panic!("the test must own the in-flight slot");
        };

        let asked = Name::from_ascii("joiner.EXAMPLE.").unwrap();
        assert!(
            !asked.eq_case(&leader_name),
            "the two spellings must differ"
        );
        let request = request_for(&asked);
        let joiner = tokio::spawn({
            let state = state.clone();
            let cfg = cfg.clone();
            let asked = asked.clone();
            let request = request.clone();
            async move {
                resolve_public_path(
                    &state,
                    &cfg,
                    &request,
                    0x2222,
                    &asked,
                    RecordType::A,
                    "joiner.example",
                    &CancellationToken::new(),
                )
                .await
            }
        });
        wait_until("the joiner to park on the leader", || {
            inflight_registry()
                .get(&inflight_key)
                .is_some_and(|slot| slot.receiver_count() == 1)
        })
        .await;
        leader.publish(&SharedResolution {
            message: stored_answer(&leader_name),
            origin: ReplyOrigin::upstream(Route::Provider, "leader".into()),
        });

        let (reply, origin) = joiner.await.unwrap();
        assert_eq!(
            origin.provider.as_deref(),
            Some("leader"),
            "the request must have joined the leader, not resolved on its own"
        );
        assert_eq!(reply.metadata.id, 0x2222);
        assert_eq!(question_wire(&reply), question_wire(&request));
    }

    #[tokio::test]
    async fn forward_zone_state_wins_over_captive_builtin_and_cached_ancestor() {
        let state = route_test_state();
        state
            .policy
            .load()
            .zones
            .upsert("private.local", "127.0.0.1")
            .unwrap();
        state.forward.store(Arc::new(Some(Arc::new(
            ForwardResolver::new(&["127.0.0.1".into()]).unwrap(),
        ))));
        state.cache.insert_nxdomain_apex("private.local.").await;
        let qname = Name::from_str("host.private.local.").unwrap();
        let request = request_for(&qname);
        assert!(
            resolve_below_nxdomain_or_none(state.cache.as_ref(), &qname, RecordType::A)
                .await
                .is_some(),
            "test setup requires a real cached ancestor NXDOMAIN"
        );
        let policy = state.policy.load_full();

        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "host.private.local",
        )
        .await;

        assert!(matches!(route, PrePublicRoute::ForwardZone(_)));
    }

    #[tokio::test]
    async fn more_specific_forward_zone_wins_over_parent_static_override() {
        let state = route_test_state();
        {
            let policy = state.policy.load();
            policy.overrides.set(
                "example.com",
                RecordType::A,
                vec![RData::A(A("192.0.2.1".parse().unwrap()))],
            );
            policy
                .zones
                .upsert("corp.example.com", "127.0.0.1")
                .unwrap();
        }
        let qname = Name::from_str("db.corp.example.com.").unwrap();
        let request = request_for(&qname);
        let policy = state.policy.load_full();

        let override_response = resolve_override_or_none(
            &policy,
            0xBEEF,
            &qname,
            RecordType::A,
            "db.corp.example.com",
            &request,
            &CancellationToken::new(),
            0,
            Transport::Tcp,
            None,
        )
        .await;
        assert!(
            override_response.is_none(),
            "the parent static override must not NXDOMAIN a name owned by a more specific forward zone"
        );

        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "db.corp.example.com",
        )
        .await;

        assert!(matches!(route, PrePublicRoute::ForwardZone(_)));
    }

    #[tokio::test]
    async fn override_keeps_precedence_at_equal_or_greater_specificity() {
        let state = route_test_state();
        {
            let policy = state.policy.load();
            policy.overrides.set(
                "corp.example.com",
                RecordType::A,
                vec![RData::A(A("192.0.2.1".parse().unwrap()))],
            );
            policy
                .zones
                .upsert("corp.example.com", "127.0.0.1")
                .unwrap();
        }
        let policy = state.policy.load_full();

        // Equal specificity: apex query answered from the override.
        let qname = Name::from_str("corp.example.com.").unwrap();
        let request = request_for(&qname);
        let apex = resolve_override_or_none(
            &policy,
            0xBEEF,
            &qname,
            RecordType::A,
            "corp.example.com",
            &request,
            &CancellationToken::new(),
            0,
            Transport::Tcp,
            None,
        )
        .await;
        assert_eq!(
            apex.and_then(|(_, origin)| origin.log_source).as_deref(),
            Some("override")
        );

        // Equal specificity: sub-name inside the static zone stays NXDOMAIN.
        let qname = Name::from_str("db.corp.example.com.").unwrap();
        let request = request_for(&qname);
        let sub = resolve_override_or_none(
            &policy,
            0xBEEF,
            &qname,
            RecordType::A,
            "db.corp.example.com",
            &request,
            &CancellationToken::new(),
            0,
            Transport::Tcp,
            None,
        )
        .await;
        assert_eq!(
            sub.and_then(|(_, origin)| origin.log_source).as_deref(),
            Some("override")
        );
    }

    /// A single-label override that is also a public TLD answers for the bare
    /// name only. Claiming its subnames would NXDOMAIN the whole TLD.
    #[tokio::test]
    async fn single_label_host_override_leaves_names_under_it_to_the_pipeline() {
        let state = route_test_state();
        state.policy.load().overrides.set(
            "dev",
            RecordType::A,
            vec![RData::A(A("192.0.2.1".parse().unwrap()))],
        );
        let policy = state.policy.load_full();

        let qname = Name::from_str("dev.").unwrap();
        let request = request_for(&qname);
        let apex = resolve_override_or_none(
            &policy,
            0xBEEF,
            &qname,
            RecordType::A,
            "dev",
            &request,
            &CancellationToken::new(),
            0,
            Transport::Tcp,
            None,
        )
        .await;
        assert_eq!(
            apex.and_then(|(_, origin)| origin.log_source).as_deref(),
            Some("override")
        );

        let qname = Name::from_str("web.dev.").unwrap();
        let request = request_for(&qname);
        let sub = resolve_override_or_none(
            &policy,
            0xBEEF,
            &qname,
            RecordType::A,
            "web.dev",
            &request,
            &CancellationToken::new(),
            0,
            Transport::Tcp,
            None,
        )
        .await;
        assert!(
            sub.is_none(),
            "web.dev must not be answered by the dev override"
        );
    }

    #[tokio::test]
    async fn policy_publication_cannot_mix_override_and_forward_zone_generations() {
        let state = route_test_state();
        state
            .policy
            .load()
            .zones
            .upsert("private.local", "127.0.0.1")
            .unwrap();
        let qname = Name::from_str("host.private.local.").unwrap();
        let request = request_for(&qname);
        let policy = state.policy.load_full();

        let override_response = resolve_override_or_none(
            &policy,
            0xBEEF,
            &qname,
            RecordType::A,
            "host.private.local",
            &request,
            &CancellationToken::new(),
            0,
            Transport::Tcp,
            None,
        )
        .await;
        assert!(override_response.is_none());

        let new_overrides = OverrideStore::new();
        new_overrides.set(
            "host.private.local",
            RecordType::A,
            vec![RData::A(A("192.0.2.1".parse().unwrap()))],
        );
        state.policy.store(Arc::new(RuntimePolicySnapshot {
            overrides: Arc::new(new_overrides),
            zones: Arc::new(ForwardZones::new()),
        }));

        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "host.private.local",
        )
        .await;

        assert!(matches!(route, PrePublicRoute::ForwardZone(_)));
    }

    /// Scoped to `.local` on purpose: the captive-yielding built-ins
    /// (`.local`, the DHCP search domain) must keep losing to an active
    /// captive route because portal sign-in depends on the hotspot resolver
    /// answering them. The protected subset is pinned separately by
    /// `captive_forward_does_not_capture_protected_special_use`.
    #[tokio::test]
    async fn captive_state_wins_over_builtin_and_cached_ancestor() {
        let state = route_test_state();
        state.forward.store(Arc::new(Some(Arc::new(
            ForwardResolver::new(&["127.0.0.1".into()]).unwrap(),
        ))));
        state.cache.insert_nxdomain_apex("private.local.").await;
        let qname = Name::from_str("host.private.local.").unwrap();
        let request = request_for(&qname);
        assert!(
            resolve_below_nxdomain_or_none(state.cache.as_ref(), &qname, RecordType::A)
                .await
                .is_some(),
            "test setup requires a real cached ancestor NXDOMAIN"
        );
        let policy = state.policy.load_full();

        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "host.private.local",
        )
        .await;

        assert!(matches!(route, PrePublicRoute::CaptiveForward(_)));
    }

    /// `.onion` (RFC 7686) and the RFC 1918 reverse zones never legitimately
    /// resolve through a hotspot resolver, so they are the captive-protected
    /// built-in subset: blanket captive forwarding must not capture them.
    #[tokio::test]
    async fn captive_forward_does_not_capture_protected_special_use() {
        let state = route_test_state();
        state.forward.store(Arc::new(Some(Arc::new(
            ForwardResolver::new(&["127.0.0.1".into()]).unwrap(),
        ))));
        let policy = state.policy.load_full();

        for domain in [
            "service.onion",
            "1.0.10.in-addr.arpa",
            "1.1.168.192.in-addr.arpa",
            "1.0.20.172.in-addr.arpa",
        ] {
            let qname = Name::from_str(&format!("{domain}.")).unwrap();
            let request = request_for(&qname);

            let route = select_pre_public_route(
                &state,
                policy.as_ref(),
                0xBEEF,
                &qname,
                RecordType::A,
                &request,
                domain,
            )
            .await;

            assert!(
                matches!(route, PrePublicRoute::BuiltinZone(_)),
                "{domain} must not be captured by captive forwarding"
            );
        }
    }

    /// An explicit user forward/stub route still outranks the protected
    /// built-in subset, which sits only ahead of blanket captive forwarding.
    #[tokio::test]
    async fn user_forward_zone_still_wins_over_protected_special_use() {
        let state = route_test_state();
        state
            .policy
            .load()
            .zones
            .upsert("10.in-addr.arpa", "127.0.0.1")
            .unwrap();
        state.forward.store(Arc::new(Some(Arc::new(
            ForwardResolver::new(&["127.0.0.1".into()]).unwrap(),
        ))));
        let qname = Name::from_str("1.0.10.in-addr.arpa.").unwrap();
        let request = request_for(&qname);
        let policy = state.policy.load_full();

        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "1.0.10.in-addr.arpa",
        )
        .await;

        assert!(matches!(route, PrePublicRoute::ForwardZone(_)));
    }

    /// A DHCP-discovered search domain publishes an ephemeral forward route, so
    /// `nas.lan` reaches the network's own resolver instead of the built-in
    /// NXDOMAIN. Private suffixes the network did not hand out stay closed.
    #[tokio::test]
    async fn ephemeral_search_domain_route_beats_builtin_nxdomain() {
        let state = route_test_state();
        let ephemeral = ForwardZones::new();
        ephemeral.upsert("lan", "192.0.2.53").unwrap();
        state.ephemeral_zones.store(Arc::new(Arc::new(ephemeral)));
        let policy = state.policy.load_full();

        let qname = Name::from_str("nas.lan.").unwrap();
        let request = request_for(&qname);
        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "nas.lan",
        )
        .await;
        assert!(matches!(route, PrePublicRoute::ForwardZone(_)));

        let qname = Name::from_str("nas.corp.").unwrap();
        let request = request_for(&qname);
        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "nas.corp",
        )
        .await;
        assert!(
            matches!(route, PrePublicRoute::BuiltinZone(_)),
            "an unprovisioned private suffix must stay NXDOMAIN"
        );
    }

    /// Ephemeral routes are derived from unauthenticated DHCP, so they sit
    /// below every explicit user route and below the captive-protected
    /// built-ins.
    #[tokio::test]
    async fn ephemeral_route_never_outranks_user_route_or_protected_builtin() {
        let state = route_test_state();
        let ephemeral = ForwardZones::new();
        ephemeral.upsert("lan", "192.0.2.53").unwrap();
        ephemeral.upsert("10.in-addr.arpa", "192.0.2.53").unwrap();
        state.ephemeral_zones.store(Arc::new(Arc::new(ephemeral)));
        state
            .policy
            .load()
            .zones
            .upsert("lan", "127.0.0.1")
            .unwrap();
        let policy = state.policy.load_full();

        let qname = Name::from_str("nas.lan.").unwrap();
        let request = request_for(&qname);
        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "nas.lan",
        )
        .await;
        match route {
            PrePublicRoute::ForwardZone(entry) => {
                assert_eq!(
                    entry.forward_ip.to_string(),
                    "127.0.0.1",
                    "the explicit user route must win over the ephemeral one"
                );
            }
            _ => panic!("expected a forward zone route"),
        }

        let qname = Name::from_str("1.0.10.in-addr.arpa.").unwrap();
        let request = request_for(&qname);
        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "1.0.10.in-addr.arpa",
        )
        .await;
        assert!(
            matches!(route, PrePublicRoute::BuiltinZone(_)),
            "an ephemeral route must not capture a captive-protected built-in"
        );
    }

    /// Captive forwarding is blanket. An ephemeral route is the more specific
    /// route to the same DHCP-advertised resolver. Letting the blanket route
    /// win makes the attached network's private namespaces unresolvable for as
    /// long as portal sign-in lasts.
    #[tokio::test]
    async fn ephemeral_route_survives_active_captive_forwarding() {
        let state = route_test_state();
        let ephemeral = ForwardZones::new();
        ephemeral.upsert("corp", "192.0.2.53").unwrap();
        state.ephemeral_zones.store(Arc::new(Arc::new(ephemeral)));
        state.forward.store(Arc::new(Some(Arc::new(
            ForwardResolver::new(&["127.0.0.1".into()]).unwrap(),
        ))));
        let policy = state.policy.load_full();

        let qname = Name::from_str("host.corp.").unwrap();
        let request = request_for(&qname);
        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "host.corp",
        )
        .await;
        match route {
            PrePublicRoute::ForwardZone(entry) => assert_eq!(
                entry.forward_ip.to_string(),
                "192.0.2.53",
                "the discovered private route must survive captive forwarding"
            ),
            _ => panic!("expected the ephemeral forward route"),
        }

        // Everything the network did not hand a route for still reaches the
        // portal resolver, so sign-in keeps working.
        let qname = Name::from_str("captive.example.com.").unwrap();
        let request = request_for(&qname);
        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "captive.example.com",
        )
        .await;
        assert!(
            matches!(route, PrePublicRoute::CaptiveForward(_)),
            "names without an ephemeral route must still reach the portal"
        );
    }

    /// RFC 6761 6.3 forbids resolving `localhost` against an authoritative
    /// server. Forwarding it to the hotspot would let a portal answer with a
    /// routable address and capture traffic an application assumed could only
    /// reach loopback.
    #[tokio::test]
    async fn localhost_is_never_forwarded_to_the_captive_resolver() {
        let state = route_test_state();
        state.forward.store(Arc::new(Some(Arc::new(
            ForwardResolver::new(&["127.0.0.1".into()]).unwrap(),
        ))));
        let policy = state.policy.load_full();

        let qname = Name::from_str("localhost.").unwrap();
        let request = request_for(&qname);
        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "localhost",
        )
        .await;
        assert!(
            matches!(route, PrePublicRoute::Localhost(_)),
            "localhost must be synthesized locally even while captive forwarding is active"
        );
    }

    /// Full precedence under active captive forwarding: explicit user route and
    /// captive-protected built-ins stay above the ephemeral table, the
    /// ephemeral table stays above blanket captive forwarding, and `.local`,
    /// which portals rely on, keeps yielding to the portal resolver.
    #[tokio::test]
    async fn captive_forwarding_precedence_keeps_user_routes_and_protected_builtins_on_top() {
        let state = route_test_state();
        let ephemeral = ForwardZones::new();
        ephemeral.upsert("lan", "192.0.2.53").unwrap();
        ephemeral.upsert("corp", "192.0.2.53").unwrap();
        ephemeral.upsert("10.in-addr.arpa", "192.0.2.53").unwrap();
        state.ephemeral_zones.store(Arc::new(Arc::new(ephemeral)));
        state
            .policy
            .load()
            .zones
            .upsert("corp", "127.0.0.1")
            .unwrap();
        state.forward.store(Arc::new(Some(Arc::new(
            ForwardResolver::new(&["127.0.0.1".into()]).unwrap(),
        ))));
        let policy = state.policy.load_full();

        let qname = Name::from_str("nas.lan.").unwrap();
        let request = request_for(&qname);
        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "nas.lan",
        )
        .await;
        match route {
            PrePublicRoute::ForwardZone(entry) => assert_eq!(
                entry.forward_ip.to_string(),
                "192.0.2.53",
                "the ephemeral route must outrank blanket captive forwarding"
            ),
            _ => panic!("expected the ephemeral forward route"),
        }

        let qname = Name::from_str("host.corp.").unwrap();
        let request = request_for(&qname);
        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "host.corp",
        )
        .await;
        match route {
            PrePublicRoute::ForwardZone(entry) => assert_eq!(
                entry.forward_ip.to_string(),
                "127.0.0.1",
                "the explicit user route must win over the ephemeral one"
            ),
            _ => panic!("expected the user forward route"),
        }

        for domain in ["1.0.10.in-addr.arpa", "service.onion"] {
            let qname = Name::from_str(&format!("{domain}.")).unwrap();
            let request = request_for(&qname);
            let route = select_pre_public_route(
                &state,
                policy.as_ref(),
                0xBEEF,
                &qname,
                RecordType::A,
                &request,
                domain,
            )
            .await;
            assert!(
                matches!(route, PrePublicRoute::BuiltinZone(_)),
                "{domain} must stay protected from both the ephemeral table and captive forwarding"
            );
        }

        let qname = Name::from_str("printer.local.").unwrap();
        let request = request_for(&qname);
        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "printer.local",
        )
        .await;
        assert!(
            matches!(route, PrePublicRoute::CaptiveForward(_)),
            "`.local` must keep yielding to the portal resolver"
        );
    }

    /// Returns the built-in answer, failing when another route claims the name.
    async fn empty_zone_answer(state: &ModuleState, domain: &str, qtype: RecordType) -> Message {
        let qname = Name::from_str(&format!("{domain}.")).unwrap();
        let request = request_for(&qname);
        let policy = state.policy.load_full();
        let route = select_pre_public_route(
            state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            qtype,
            &request,
            domain,
        )
        .await;
        match route {
            PrePublicRoute::BuiltinZone(msg) => msg,
            _ => panic!("{domain} must be claimed by a built-in zone"),
        }
    }

    #[tokio::test]
    async fn resolver_discovery_returns_local_nodata_for_all_names_and_types() {
        let state = route_test_state();
        state.cache.insert_nxdomain_apex("arpa.").await;
        for domain in [
            "resolver.arpa",
            "_dns.resolver.arpa",
            "other._dns.resolver.arpa",
            "_DNS.ReSoLvEr.ArPa",
        ] {
            for qtype in [
                RecordType::SVCB,
                RecordType::HTTPS,
                RecordType::A,
                RecordType::AAAA,
                RecordType::SOA,
                RecordType::NS,
                RecordType::ANY,
            ] {
                let msg = empty_zone_answer(&state, domain, qtype).await;
                assert_eq!(msg.metadata.id, 0xBEEF);
                assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
                assert!(!msg.metadata.authentic_data);
                assert!(
                    msg.answers.is_empty(),
                    "{domain} {qtype} must not advertise upstream resolvers"
                );
                assert!(msg.additionals.is_empty());
                assert_eq!(msg.queries[0].query_type(), qtype);
                assert_eq!(msg.authorities.len(), 1);
                assert_eq!(
                    msg.authorities[0].name,
                    Name::from_str("resolver.arpa.").unwrap()
                );
                assert_eq!(msg.authorities[0].record_type(), RecordType::SOA);
                assert_eq!(msg.authorities[0].ttl, synthetic_negative_ttl_secs());
            }
        }
    }

    #[tokio::test]
    async fn resolver_discovery_excludes_public_prefetch_without_capturing_similar_names() {
        let state = route_test_state();
        let policy = state.policy.load_full();
        for (domain, public) in [
            ("resolver.arpa", false),
            ("_dns.resolver.arpa", false),
            ("_DNS.ReSoLvEr.ArPa.", false),
            ("notresolver.arpa", true),
            ("_dns.resolver.arpa.example.com", true),
            ("example.com", true),
        ] {
            let name = Name::from_str(domain).unwrap();
            assert_eq!(
                super::prefetch_public_route_allowed(
                    &state,
                    &policy,
                    &name,
                    RecordType::SVCB,
                    domain
                )
                .await,
                public,
                "unexpected public route for {domain}"
            );
        }
    }

    #[tokio::test]
    async fn resolver_discovery_preserves_explicit_and_captive_forward_precedence() {
        let state = route_test_state();
        let domain = "_dns.resolver.arpa";
        let name = Name::from_str(domain).unwrap();
        let request = request_for(&name);
        state.forward.store(Arc::new(Some(Arc::new(
            ForwardResolver::new(&["127.0.0.1".into()]).unwrap(),
        ))));
        let policy = state.policy.load_full();
        let route = select_pre_public_route(
            &state,
            &policy,
            1,
            &name,
            RecordType::SVCB,
            &request,
            domain,
        )
        .await;
        assert!(matches!(route, PrePublicRoute::CaptiveForward(_)));

        policy.zones.upsert("resolver.arpa", "192.0.2.53").unwrap();
        let route = select_pre_public_route(
            &state,
            &policy,
            1,
            &name,
            RecordType::SVCB,
            &request,
            domain,
        )
        .await;
        assert!(matches!(route, PrePublicRoute::ForwardZone(_)));
    }

    /// RFC 6303 §3: the empty zone owns an SOA and an NS, so the
    /// apex answers both positively and authoritatively instead of denying
    /// records the zone demonstrably has.
    #[tokio::test]
    async fn built_in_empty_zone_apex_answers_soa_and_ns_authoritatively() {
        let state = route_test_state();
        let apex = Name::from_str("local.").unwrap();

        for qtype in [RecordType::SOA, RecordType::NS] {
            let msg = empty_zone_answer(&state, "local", qtype).await;
            assert!(
                msg.metadata.authoritative,
                "{qtype} at the zone apex must be authoritative"
            );
            assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
            let answer = msg
                .answers
                .iter()
                .find(|rec| rec.record_type() == qtype)
                .unwrap_or_else(|| panic!("the apex must answer {qtype}"));
            assert_eq!(
                answer.name, apex,
                "the apex record must be owned by the zone apex"
            );
        }

        // ANY carries both so an RFC 8482-style client still sees the zone.
        let msg = empty_zone_answer(&state, "local", RecordType::ANY).await;
        assert!(msg
            .answers
            .iter()
            .any(|rec| rec.record_type() == RecordType::SOA));
        assert!(msg
            .answers
            .iter()
            .any(|rec| rec.record_type() == RecordType::NS));
    }

    /// RFC 2308: a type the empty zone does not hold is NODATA at the apex,
    /// never NXDOMAIN, because the apex itself exists.
    #[tokio::test]
    async fn built_in_empty_zone_apex_returns_nodata_for_other_qtypes() {
        let state = route_test_state();
        let apex = Name::from_str("local.").unwrap();

        for qtype in [RecordType::A, RecordType::AAAA, RecordType::TXT] {
            let msg = empty_zone_answer(&state, "local", qtype).await;
            assert!(msg.metadata.authoritative);
            assert_eq!(
                msg.metadata.response_code,
                ResponseCode::NoError,
                "{qtype} at an existing apex must be NODATA, not NXDOMAIN"
            );
            assert!(msg.answers.is_empty(), "NODATA carries no answer records");
            let soa = msg
                .authorities
                .iter()
                .find(|rec| rec.record_type() == RecordType::SOA)
                .expect("NODATA must carry the zone SOA for negative caching");
            assert_eq!(soa.name, apex);
        }
    }

    /// RFC 2308 §3: below the apex the answer stays NXDOMAIN, but it
    /// is authoritative and the SOA owner is the zone apex rather than the
    /// QNAME, so downstream negative caching files it against the right name.
    #[tokio::test]
    async fn built_in_empty_zone_below_apex_is_authoritative_nxdomain_owned_by_the_apex() {
        let state = route_test_state();

        for (domain, apex) in [
            ("printer.local", "local."),
            ("a.b.printer.local", "local."),
            ("1.0.10.in-addr.arpa", "10.in-addr.arpa."),
            ("service.onion", "onion."),
        ] {
            let msg = empty_zone_answer(&state, domain, RecordType::A).await;
            assert!(
                msg.metadata.authoritative,
                "{domain} must be denied authoritatively"
            );
            assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
            let soa = msg
                .authorities
                .iter()
                .find(|rec| rec.record_type() == RecordType::SOA)
                .expect("NXDOMAIN must carry an SOA for negative caching");
            assert_eq!(
                soa.name,
                Name::from_str(apex).unwrap(),
                "{domain} must be denied by the {apex} SOA, not by its own name"
            );
        }
    }

    /// RFC 6303 §4.3: a PTR for the unspecified address `::` is served from
    /// the built-in table and never reaches the public path. The `::1` zone
    /// next to it keeps its own apex.
    #[tokio::test]
    async fn ipv6_unspecified_reverse_zone_is_served_locally() {
        let state = route_test_state();
        let unspecified =
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";
        let loopback = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";

        let msg = empty_zone_answer(&state, unspecified, RecordType::PTR).await;
        assert!(msg.metadata.authoritative);
        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::NoError,
            "the query is the zone apex, so PTR is NODATA"
        );

        let msg = empty_zone_answer(&state, loopback, RecordType::PTR).await;
        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::NoError,
            "the `::1` zone must keep its own apex, not fall into `::`"
        );

        // No ephemeral route can claim it either, because DHCP search domains
        // are restricted to the private-use suffixes.
        assert!(!crate::local_zones::is_publishable_ephemeral_route(
            unspecified
        ));
    }

    /// Walks the documented pre-public ladder in one state: explicit user
    /// route → captive-protected built-in → ephemeral route → `localhost` →
    /// `ipv4only.arpa` → blanket captive forward → remaining built-ins →
    /// cached-ancestor NXDOMAIN.
    #[tokio::test]
    async fn pre_public_precedence_is_unchanged_without_the_user_local_zone_stage() {
        let state = route_test_state();
        let ephemeral = ForwardZones::new();
        ephemeral.upsert("lan", "192.0.2.53").unwrap();
        ephemeral.upsert("10.in-addr.arpa", "192.0.2.53").unwrap();
        state.ephemeral_zones.store(Arc::new(Arc::new(ephemeral)));
        state
            .policy
            .load()
            .zones
            .upsert("corp.example", "127.0.0.1")
            .unwrap();
        state
            .cache
            .insert_nxdomain_apex("private.example.com.")
            .await;
        state.forward.store(Arc::new(Some(Arc::new(
            ForwardResolver::new(&["198.51.100.1".into()]).unwrap(),
        ))));

        async fn route_of(state: &ModuleState, domain: &str) -> PrePublicRoute {
            let qname = Name::from_str(&format!("{domain}.")).unwrap();
            let request = request_for(&qname);
            let policy = state.policy.load_full();
            select_pre_public_route(
                state,
                policy.as_ref(),
                0xBEEF,
                &qname,
                RecordType::A,
                &request,
                domain,
            )
            .await
        }

        // 1. Explicit user forward zone beats everything below it.
        match route_of(&state, "svc.corp.example").await {
            PrePublicRoute::ForwardZone(entry) => {
                assert_eq!(entry.forward_ip.to_string(), "127.0.0.1")
            }
            _ => panic!("the explicit user route must win"),
        }
        // 2. Captive-protected built-ins outrank the ephemeral table and the
        //    blanket captive forward.
        assert!(matches!(
            route_of(&state, "1.0.10.in-addr.arpa").await,
            PrePublicRoute::BuiltinZone(_)
        ));
        // 3. Ephemeral DHCP route.
        match route_of(&state, "nas.lan").await {
            PrePublicRoute::ForwardZone(entry) => {
                assert_eq!(entry.forward_ip.to_string(), "192.0.2.53")
            }
            _ => panic!("the ephemeral route must outrank captive forwarding"),
        }
        // 4. RFC 6761 localhost synthesis.
        assert!(matches!(
            route_of(&state, "localhost").await,
            PrePublicRoute::Localhost(_)
        ));
        // 5. RFC 8880 `ipv4only.arpa` is answered locally, never by the portal.
        match route_of(&state, "ipv4only.arpa").await {
            PrePublicRoute::BuiltinZone(message) => assert_eq!(
                message.answers.len(),
                crate::dns64::IPV4ONLY_ARPA_ADDRS.len(),
                "ipv4only.arpa A must carry the well-known addresses"
            ),
            _ => panic!("ipv4only.arpa must outrank captive forwarding"),
        }
        // 6. Blanket captive forwarding, including the remaining built-ins and
        //    the cached-ancestor NXDOMAIN that both sit below it.
        for domain in [
            "captive.example.com",
            "printer.local",
            "host.private.example.com",
        ] {
            assert!(
                matches!(
                    route_of(&state, domain).await,
                    PrePublicRoute::CaptiveForward(_)
                ),
                "{domain} must reach the portal resolver while captive forwarding is active"
            );
        }
        // 7/8. With the portal gone, the remaining built-ins claim their names
        //      and the cached-ancestor NXDOMAIN is last.
        state.forward.store(Arc::new(None));
        assert!(matches!(
            route_of(&state, "printer.local").await,
            PrePublicRoute::BuiltinZone(_)
        ));
        assert!(matches!(
            route_of(&state, "host.private.example.com").await,
            PrePublicRoute::CachedAncestorNxdomain(_)
        ));
    }

    #[tokio::test]
    async fn cached_ancestor_state_is_selected_without_private_route() {
        let state = route_test_state();
        state
            .cache
            .insert_nxdomain_apex("private.example.com.")
            .await;
        let qname = Name::from_str("host.private.example.com.").unwrap();
        let request = request_for(&qname);
        let policy = state.policy.load_full();

        let route = select_pre_public_route(
            &state,
            policy.as_ref(),
            0xBEEF,
            &qname,
            RecordType::A,
            &request,
            "host.private.example.com",
        )
        .await;

        assert!(matches!(route, PrePublicRoute::CachedAncestorNxdomain(_)));
    }

    #[test]
    fn control_challenge_parses_only_with_matching_transport() {
        let hex32 = "a".repeat(32);
        let name = format!("{hex32}.{hex32}.u._probe.macdns");
        // Matching transport (UDP) parses.
        assert!(super::parse_control_challenge(
            &name,
            Transport::Udp {
                client_payload_size: 512
            }
        )
        .is_some());
        // Mismatched transport (TCP) rejects the u-labelled name.
        assert!(super::parse_control_challenge(&name, Transport::Tcp).is_none());
        // A plain probe name is not a control challenge.
        assert!(super::parse_control_challenge(
            "_probe.macdns",
            Transport::Udp {
                client_payload_size: 512
            }
        )
        .is_none());
    }

    /// `xn--` A-label whose hickory `Display` form is 29 ASCII bytes plus a
    /// 3-byte scalar: exactly 32 UTF-8 bytes with a scalar boundary at an odd
    /// offset, so a two-byte hex slice lands inside a character. Reachable
    /// before authentication over 127.0.0.1:5335.
    const PUNYCODE_32_BYTE_DISPLAY_LABEL: &str = "xn--aaaaaaaaaaaaaaaaaaaaaaaaaaaaa-jp31a";

    #[test]
    fn punycode_label_cannot_panic_control_challenge_parsing() {
        use hickory_proto::serialize::binary::BinEncodable;

        let name = Name::from_ascii(format!(
            "{}.{}.t._probe.macdns.",
            PUNYCODE_32_BYTE_DISPLAY_LABEL,
            "b".repeat(32)
        ))
        .unwrap();

        // Preconditions the regression depends on: the Display form is
        // exactly 32 bytes and byte offset 30 is not a character boundary.
        let display = name.to_lowercase().to_string();
        let display_label = display.split('.').next().unwrap();
        assert_eq!(display_label.len(), 32);
        assert!(!display_label.is_char_boundary(30));

        let mut req = Message::query();
        let mut q = DnsQuery::new();
        q.set_name(name).set_query_type(RecordType::TXT);
        req.add_query(q);
        let wire = req.to_bytes().unwrap();

        let parsed_as_regular_query = std::panic::catch_unwind(|| {
            matches!(
                super::parse_request_start(&wire, Transport::Tcp),
                super::RequestStart::Continue(_)
            )
        });

        assert_eq!(
            parsed_as_regular_query.ok(),
            Some(true),
            "a punycode label must parse as an ordinary query, never panic"
        );
    }

    #[test]
    fn control_challenge_without_session_is_refused() {
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        let _guard = crate::proxy_control::test_lock();
        crate::proxy_control::clear();
        let hex32 = "b".repeat(32);
        let mut req = Message::query();
        let mut q = DnsQuery::new();
        q.set_name(Name::from_str(&format!("{hex32}.{hex32}.u._probe.macdns.")).unwrap())
            .set_query_type(RecordType::TXT);
        req.add_query(q);
        let wire = req.to_bytes().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resp = rt.block_on(super::handle_wire(
            &wire,
            cancel,
            Transport::Udp {
                client_payload_size: 4096,
            },
        ));
        let parsed = Message::from_bytes(&resp).unwrap();
        // No session installed → fail closed with REFUSED, never upstream.
        assert_eq!(parsed.metadata.response_code, ResponseCode::Refused);
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn control_challenge_with_session_answers_txt() {
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        let _guard = crate::proxy_control::test_lock();
        crate::proxy_control::configure([5u8; 16], [9u8; 32]);
        let hex32 = "c".repeat(32);
        let mut req = Message::query();
        let mut q = DnsQuery::new();
        q.set_name(Name::from_str(&format!("{hex32}.{hex32}.u._probe.macdns.")).unwrap())
            .set_query_type(RecordType::TXT);
        req.add_query(q);
        let wire = req.to_bytes().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resp = rt.block_on(super::handle_wire(
            &wire,
            cancel,
            Transport::Udp {
                client_payload_size: 4096,
            },
        ));
        let parsed = Message::from_bytes(&resp).unwrap();
        assert_eq!(parsed.metadata.response_code, ResponseCode::NoError);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].record_type(), RecordType::TXT);

        // Raw-wire guarantees the Swift extension verifier depends on
        // (single-TXT parser expecting ARCOUNT=0 + a 0xC00C name pointer). If
        // hickory ever stopped compressing the answer name or appended an OPT,
        // the provider would fail every challenge and stay in bypass.
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        let nscount = u16::from_be_bytes([resp[8], resp[9]]);
        let arcount = u16::from_be_bytes([resp[10], resp[11]]);
        assert_eq!(ancount, 1, "exactly one answer");
        assert_eq!(nscount, 0, "no authority records");
        assert_eq!(arcount, 0, "no OPT/additional records");
        // Walk the question in the response to find where the answer begins.
        let mut i = 12usize;
        while resp[i] != 0 {
            i += 1 + resp[i] as usize;
        }
        i += 1 + 4; // 0x00 terminator + QTYPE + QCLASS
                    // The answer owner name must be the compression pointer 0xC0 0x0C to
                    // the question at offset 12.
        assert_eq!(
            &resp[i..i + 2],
            &[0xC0, 0x0C],
            "answer name must be a compression pointer to the question"
        );
        crate::proxy_control::clear();
    }

    #[test]
    fn refresh_state_guard_resets_on_drop() {
        let state = Arc::new(RefreshState::new());
        assert_eq!(state.try_start(RefreshSource::Demand), Ok(()));

        {
            let _guard = super::RefreshStateGuard::new(state.clone());
            assert_eq!(
                state.try_start(RefreshSource::PeriodicPrefetch),
                Err(RefreshSource::Demand)
            );
        }

        assert_eq!(state.try_start(RefreshSource::PeriodicPrefetch), Ok(()));
    }

    #[test]
    fn serve_stale_log_identifies_refresh_owner() {
        assert_eq!(
            serve_stale_log_message(
                "my.1password.com",
                RecordType::A,
                "refresh-client-timeout",
                "Quad9",
                RefreshSource::PeriodicPrefetch,
            ),
            "serve-stale my.1password.com A: reason=refresh-client-timeout cached_provider=Quad9 refresh_source=periodic-prefetch"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shared_refresh_waiters_receive_fresh_positive_and_negative_answers() {
        for source in [RefreshSource::Demand, RefreshSource::PeriodicPrefetch] {
            for negative in [false, true] {
                let state = Arc::new(route_test_state());
                let name = Name::from_str("refresh.example.").unwrap();
                let key = CacheKey::from("refresh.example", RecordType::A);
                let refresh = Arc::new(RefreshState::new());
                refresh.try_start(source).unwrap();
                let cancel = CancellationToken::new();
                let mut first = Box::pin(super::wait_for_shared_refresh(&refresh, &cancel, 1_000));
                let mut second = Box::pin(super::wait_for_shared_refresh(&refresh, &cancel, 1_000));
                assert!(futures::poll!(&mut first).is_pending());
                assert!(futures::poll!(&mut second).is_pending());

                let mut message = Message::query();
                message.metadata.message_type = MessageType::Response;
                if negative {
                    message.metadata.response_code = ResponseCode::NXDomain;
                    state
                        .cache
                        .insert_neg(
                            key.clone(),
                            CachedEntry::scaffold(message, "fresh".into()),
                            5,
                        )
                        .await;
                } else {
                    message.add_answer(Record::from_rdata(
                        name.clone(),
                        60,
                        RData::A(A::new(203, 0, 113, 9)),
                    ));
                    state
                        .cache
                        .insert(
                            key.clone(),
                            CachedEntry::scaffold(message, "fresh".into()),
                            60,
                        )
                        .await;
                }
                refresh.finish();
                let completed_at = tokio::time::Instant::now();
                for (tx_id, reason) in [(11, first.await), (12, second.await)] {
                    assert_eq!(reason, "refresh-no-fresh-answer");
                    assert_eq!(completed_at.elapsed(), Duration::ZERO);
                    let mut request = Message::query();
                    request.metadata.recursion_desired = false;
                    request.metadata.checking_disabled = true;
                    let (reply, provider) = super::serve_stale(
                        &crate::config::ResolverOptions::default(),
                        &state,
                        &key,
                        &name,
                        RecordType::A,
                        "refresh.example",
                        reason,
                        source,
                        tx_id,
                        &request,
                    )
                    .await
                    .unwrap();
                    assert_eq!(provider.log_source.as_deref(), Some("fresh"));
                    assert_eq!(provider.route, Route::Cache);
                    assert_eq!(reply.metadata.id, tx_id);
                    assert!(!reply.metadata.recursion_desired);
                    assert!(reply.metadata.checking_disabled);
                    assert!(reply.edns.is_none());
                    if negative {
                        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
                        assert!(reply.answers.is_empty());
                    } else {
                        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
                        assert_eq!(reply.answers[0].ttl, 60);
                    }
                }
            }
        }
    }

    /// The stale entry can vanish while a request waits on another request's
    /// refresh, because a flush or a network change invalidates it. The query
    /// then resolves cold like any other miss instead of failing.
    #[tokio::test]
    async fn stale_entry_evicted_during_the_shared_refresh_resolves_cold() {
        let state = prefetch_state_over_negative_server(ResponseCode::NXDomain, true).await;
        let name = Name::from_str("evicted.example.com.").unwrap();
        let key = CacheKey::from("evicted.example.com", RecordType::A);
        let mut message = Message::query();
        message.metadata.message_type = MessageType::Response;
        message.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::A(A::new(203, 0, 113, 8)),
        ));
        let mut entry = CachedEntry::scaffold(message, "cached".into());
        entry.expires_at = Instant::now() - Duration::from_secs(1);
        let refresh = entry.refresh_state.clone();
        refresh.try_start(RefreshSource::Demand).unwrap();
        state.cache.inner_insert_raw(key.clone(), entry).await;
        let owner = tokio::spawn({
            let state = state.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                state.cache.clear().await;
                refresh.finish();
            }
        });

        let (reply, _provider) = resolve_public_path(
            &state,
            &crate::config::current(),
            &request_for(&name),
            0xBEEF,
            &name,
            RecordType::A,
            "evicted.example.com",
            &CancellationToken::new(),
        )
        .await;
        owner.await.unwrap();

        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NXDomain,
            "a vanished stale entry must fall through to a cold resolution"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shared_refresh_timeout_serves_stale_without_releasing_owner() {
        let state = Arc::new(route_test_state());
        let name = Name::from_str("refresh.example.").unwrap();
        let key = CacheKey::from("refresh.example", RecordType::A);
        let mut message = Message::query();
        message.metadata.message_type = MessageType::Response;
        message.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::A(A::new(203, 0, 113, 8)),
        ));
        let mut entry = CachedEntry::scaffold(message, "cached".into());
        entry.expires_at = Instant::now() - Duration::from_secs(1);
        entry.original_ttl_secs = 60;
        let refresh = entry.refresh_state.clone();
        refresh.try_start(RefreshSource::Demand).unwrap();
        state.cache.inner_insert_raw(key.clone(), entry).await;
        let cancel = CancellationToken::new();
        let start = tokio::time::Instant::now();
        let reason = super::wait_for_shared_refresh(&refresh, &cancel, 1_000).await;
        assert_eq!(reason, "refresh-client-timeout");
        assert_eq!(start.elapsed(), Duration::from_secs(1));
        let (reply, provider) = super::serve_stale(
            &crate::config::ResolverOptions::default(),
            &state,
            &key,
            &name,
            RecordType::A,
            "refresh.example",
            reason,
            RefreshSource::Demand,
            17,
            &Message::query(),
        )
        .await
        .unwrap();
        assert_eq!(provider.log_source.as_deref(), Some("cached(stale)"));
        assert_eq!(provider.route, Route::Stale);
        assert_eq!(provider.provider.as_deref(), Some("cached"));
        assert_eq!(
            reply.answers[0].ttl, 30,
            "RFC 8767 §4: a stale answer carries a positive TTL, 30 s recommended"
        );
        assert!(reply.edns.is_some());
        assert_eq!(
            refresh.try_start(RefreshSource::Demand),
            Err(RefreshSource::Demand)
        );
    }

    #[tokio::test]
    async fn restored_entries_keep_existing_fresh_and_stale_wire_ttls() {
        for (captured_ttl, downtime, expected_ttl) in [
            (120, 10, 110),
            (120, 110, 10),
            (120, 120, 30),
            (120, 200, 30),
            (20, 30, 20),
        ] {
            let state = Arc::new(route_test_state());
            let name = Name::from_ascii("restore-wire.example.").unwrap();
            let key = CacheKey::from("restore-wire.example", RecordType::A);
            let mut message = Message::response(7, OpCode::Query);
            message
                .queries
                .push(DnsQuery::query(name.clone(), RecordType::A));
            message.add_answer(Record::from_rdata(
                name.clone(),
                captured_ttl,
                RData::A(A::new(203, 0, 113, 9)),
            ));
            assert!(
                state
                    .cache
                    .insert_restored_aged(
                        key.clone(),
                        CachedEntry::scaffold(message, "cached".into()),
                        captured_ttl,
                        downtime,
                        Instant::now(),
                    )
                    .await
            );
            let (reply, _) = super::serve_stale(
                &crate::config::ResolverOptions::default(),
                &state,
                &key,
                &name,
                RecordType::A,
                "restore-wire.example",
                "all-upstream-failed",
                RefreshSource::Demand,
                18,
                &Message::query(),
            )
            .await
            .unwrap();
            assert_eq!(
                reply.answers[0].ttl, expected_ttl,
                "capture={captured_ttl} downtime={downtime}"
            );
        }
    }

    /// A record the authority published with a short TTL is a failover
    /// signal. Serving it stale must not stretch that signal past what the
    /// authority granted, even though RFC 8767 recommends 30 s.
    #[tokio::test]
    async fn stale_answer_ttl_never_exceeds_the_original_ttl() {
        let state = Arc::new(route_test_state());
        let name = Name::from_str("failover.example.").unwrap();
        let key = CacheKey::from("failover.example", RecordType::A);
        let mut message = Message::query();
        message.metadata.message_type = MessageType::Response;
        message.add_answer(Record::from_rdata(
            name.clone(),
            5,
            RData::A(A::new(203, 0, 113, 9)),
        ));
        let mut entry = CachedEntry::scaffold(message, "cached".into());
        entry.expires_at = Instant::now() - Duration::from_secs(1);
        entry.original_ttl_secs = 5;
        state.cache.inner_insert_raw(key.clone(), entry).await;

        let (reply, _provider) = super::serve_stale(
            &crate::config::ResolverOptions::default(),
            &state,
            &key,
            &name,
            RecordType::A,
            "failover.example",
            "all-upstream-failed",
            RefreshSource::Demand,
            18,
            &Message::query(),
        )
        .await
        .unwrap();

        assert!(reply.answers.iter().all(|r| r.ttl == 5));
    }

    #[tokio::test(start_paused = true)]
    async fn shared_refresh_completed_before_wait_does_not_wait_for_timeout() {
        let refresh = RefreshState::new();
        refresh.try_start(RefreshSource::Demand).unwrap();
        refresh.finish();
        let start = tokio::time::Instant::now();
        assert_eq!(
            super::wait_for_shared_refresh(&refresh, &CancellationToken::new(), 1_000).await,
            "refresh-no-fresh-answer"
        );
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn shared_refresh_wait_is_cancelled_promptly() {
        let refresh = RefreshState::new();
        refresh.try_start(RefreshSource::Demand).unwrap();
        let cancel = CancellationToken::new();
        let mut waiting = Box::pin(super::wait_for_shared_refresh(&refresh, &cancel, 1_000));
        assert!(futures::poll!(&mut waiting).is_pending());
        cancel.cancel();
        assert_eq!(waiting.await, "cancelled");
        assert_eq!(
            refresh.try_start(RefreshSource::Demand),
            Err(RefreshSource::Demand)
        );
    }

    #[test]
    fn prefetch_zero_original_ttl_never_fires() {
        let mut entry = CachedEntry::scaffold(Message::query(), "test".into());
        entry.original_ttl_secs = 0;
        entry.expires_at = Instant::now() + Duration::from_secs(10);
        assert!(!should_prefetch_entry_at(&entry, Instant::now(), 0, false));
    }

    #[test]
    fn prefetch_fires_at_remaining_threshold() {
        let mut entry = CachedEntry::scaffold(Message::query(), "test".into());
        entry.original_ttl_secs = 60;
        entry.expires_at = Instant::now() + Duration::from_secs(10);
        assert!(should_prefetch_entry_at(&entry, Instant::now(), 0, false));
    }

    #[test]
    fn prefetch_window_scales_down_for_short_ttl_entries() {
        // A 6s entry sits inside the flat 10s window for its whole life. The
        // window must shrink to a third of the TTL so a freshly inserted
        // short-TTL entry is not an immediate refill candidate.
        let mut fresh = CachedEntry::scaffold(Message::query(), "test".into());
        fresh.original_ttl_secs = 6;
        fresh.expires_at = Instant::now() + Duration::from_secs(6);
        assert!(!should_prefetch_entry_at(&fresh, Instant::now(), 0, false));

        let mut near_expiry = CachedEntry::scaffold(Message::query(), "test".into());
        near_expiry.original_ttl_secs = 6;
        near_expiry.expires_at = Instant::now() + Duration::from_secs(2);
        assert!(should_prefetch_entry_at(
            &near_expiry,
            Instant::now(),
            0,
            false
        ));

        // Below 3s there is no window at all. Refilling would cost more
        // upstream traffic than the natural miss on expiry.
        let mut one_second = CachedEntry::scaffold(Message::query(), "test".into());
        one_second.original_ttl_secs = 1;
        one_second.expires_at = Instant::now() + Duration::from_secs(1);
        assert!(!should_prefetch_entry_at(
            &one_second,
            Instant::now(),
            0,
            false
        ));
    }

    #[test]
    fn prefetch_does_not_fire_above_remaining_threshold() {
        let mut entry = CachedEntry::scaffold(Message::query(), "test".into());
        entry.original_ttl_secs = 60;
        entry.expires_at = Instant::now() + Duration::from_secs(12);
        assert!(!should_prefetch_entry_at(&entry, Instant::now(), 0, false));
    }

    #[test]
    fn prefetch_does_not_fire_for_expired_entry() {
        let mut entry = CachedEntry::scaffold(Message::query(), "test".into());
        entry.original_ttl_secs = 60;
        entry.expires_at = Instant::now();
        assert!(!should_prefetch_entry_at(&entry, Instant::now(), 0, false));
    }

    #[test]
    fn prefetch_does_not_fire_when_unused_over_four_hours() {
        let mut entry = CachedEntry::scaffold(Message::query(), "test".into());
        entry.original_ttl_secs = 60;
        entry.expires_at = Instant::now() + Duration::from_secs(10);
        entry
            .last_used_secs
            .store(0, std::sync::atomic::Ordering::Relaxed);
        assert!(!should_prefetch_entry_at(
            &entry,
            Instant::now(),
            PREFETCH_MAX_UNUSED_SECS + 1,
            false,
        ));
    }

    #[test]
    fn prefetch_does_not_fire_for_negative_cache_entries() {
        let qname = Name::from_str("missing.example.").unwrap();
        let apex = Name::from_str("example.").unwrap();
        let req = Message::query();

        let negative_messages = [
            build_nxdomain(0xBEEF, &qname, RecordType::A, &req),
            build_local_nodata(0xBEEF, &qname, RecordType::AAAA, &req, &apex),
            {
                let mut cname_nodata =
                    build_local_nodata(0xBEEF, &qname, RecordType::A, &req, &apex);
                cname_nodata.add_answer(Record::from_rdata(
                    qname.clone(),
                    300,
                    RData::CNAME(CNAME(Name::from_str("target.example.").unwrap())),
                ));
                cname_nodata
            },
        ];

        for msg in negative_messages {
            let mut entry = CachedEntry::scaffold(msg, "test".into());
            entry.original_ttl_secs = 5;
            entry.expires_at = Instant::now() + Duration::from_secs(5);

            assert!(!should_prefetch_entry_at(&entry, Instant::now(), 0, false));
        }
    }

    /// A host in the popular set skips only the idle cut: it stays a
    /// candidate however long ago a client asked for it.
    #[test]
    fn prefetch_fires_for_a_popular_entry_unused_over_four_hours() {
        let mut entry = CachedEntry::scaffold(Message::query(), "test".into());
        entry.original_ttl_secs = 60;
        entry.expires_at = Instant::now() + Duration::from_secs(10);
        entry
            .last_used_secs
            .store(0, std::sync::atomic::Ordering::Relaxed);
        assert!(should_prefetch_entry_at(
            &entry,
            Instant::now(),
            PREFETCH_MAX_UNUSED_SECS + 1,
            true,
        ));
    }

    #[test]
    fn prefetch_keeps_every_other_check_for_popular_entries() {
        let idle = PREFETCH_MAX_UNUSED_SECS + 1;
        let entry_with = |original_ttl_secs: u32, remaining_secs: u64| {
            let mut entry = CachedEntry::scaffold(Message::query(), "test".into());
            entry.original_ttl_secs = original_ttl_secs;
            entry.expires_at = Instant::now() + Duration::from_secs(remaining_secs);
            entry
                .last_used_secs
                .store(0, std::sync::atomic::Ordering::Relaxed);
            entry
        };

        let outside_window = entry_with(60, 12);
        assert!(!should_prefetch_entry_at(
            &outside_window,
            Instant::now(),
            idle,
            true
        ));
        let short_ttl_fresh = entry_with(6, 6);
        assert!(!should_prefetch_entry_at(
            &short_ttl_fresh,
            Instant::now(),
            idle,
            true
        ));
        let zero_ttl = entry_with(0, 10);
        assert!(!should_prefetch_entry_at(
            &zero_ttl,
            Instant::now(),
            idle,
            true
        ));
        let expired = entry_with(60, 0);
        assert!(!should_prefetch_entry_at(
            &expired,
            Instant::now(),
            idle,
            true
        ));

        let qname = Name::from_str("missing.example.").unwrap();
        let mut negative = CachedEntry::scaffold(
            build_nxdomain(0xBEEF, &qname, RecordType::A, &Message::query()),
            "test".into(),
        );
        negative.original_ttl_secs = 60;
        negative.expires_at = Instant::now() + Duration::from_secs(10);
        assert!(!should_prefetch_entry_at(
            &negative,
            Instant::now(),
            idle,
            true
        ));
    }

    #[test]
    fn prefetch_skips_unknown_qtype() {
        assert!(!prefetch_qtype_allowed(RecordType::Unknown(65_000)));
        assert!(prefetch_qtype_allowed(RecordType::A));
    }

    type PrefetchPreDispatchFn = Box<dyn Fn(&ModuleState) + Send + Sync>;

    static PREFETCH_PRE_DISPATCH_HOOK: std::sync::Mutex<Option<PrefetchPreDispatchFn>> =
        std::sync::Mutex::new(None);

    /// Stands in for a policy swap that lands inside the eligibility check's own
    /// awaits: `prefetch_refill` fires it after the check returned and before
    /// the revalidation that guards the dispatch. The installed closure filters
    /// on the state it owns, so a prefetch from a concurrent test is untouched.
    pub(super) fn run_prefetch_pre_dispatch_hook(state: &ModuleState) {
        if let Some(hook) = PREFETCH_PRE_DISPATCH_HOOK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            hook(state);
        }
    }

    /// Holds the hook slot for the test's lifetime. The slot is process-wide,
    /// so installs are exclusive: a concurrent test would otherwise replace
    /// this hook or clear it on drop while this test still depends on it.
    struct PrefetchPreDispatchHook {
        _exclusive: std::sync::MutexGuard<'static, ()>,
    }

    impl PrefetchPreDispatchHook {
        fn install(hook: PrefetchPreDispatchFn) -> Self {
            static EXCLUSIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let exclusive = EXCLUSIVE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *PREFETCH_PRE_DISPATCH_HOOK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
            Self {
                _exclusive: exclusive,
            }
        }
    }

    impl Drop for PrefetchPreDispatchHook {
        fn drop(&mut self) {
            *PREFETCH_PRE_DISPATCH_HOOK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }
    }

    fn claimed_prefetch_state() -> Arc<RefreshState> {
        let state = Arc::new(RefreshState::new());
        assert_eq!(state.try_start(RefreshSource::PeriodicPrefetch), Ok(()));
        state
    }

    /// A name cached while it was public keeps a live prefetch schedule. If the
    /// refill still dispatches to the public pool, the namespace the user has
    /// just made private keeps leaking, and keeps being re-cached, without a
    /// single new client query.
    async fn prefetch_outcome_after<F>(mutate: F) -> (Arc<ModuleState>, CacheKey, PrefetchOutcome)
    where
        F: FnOnce(&Arc<ModuleState>),
    {
        let state = Arc::new(route_test_state());
        let qname = Name::from_str("app.corp.example.com.").unwrap();
        let key = CacheKey::from("app.corp.example.com", RecordType::A);
        let generation = PolicyGeneration::capture(&state);

        assert!(
            prefetch_may_use_public_pool(&state, &generation, &key, &qname, RecordType::A).await,
            "test setup requires a name that starts out publicly routable"
        );

        mutate(&state);

        let outcome = prefetch_refill(
            state.clone(),
            key.clone(),
            qname,
            RecordType::A,
            claimed_prefetch_state(),
            generation,
            CancellationToken::new(),
        )
        .await;
        (state, key, outcome)
    }

    async fn prefetch_state_over_negative_server(
        rcode: ResponseCode,
        with_soa: bool,
    ) -> Arc<ModuleState> {
        let (address, _) = crate::test_dns_server::spawn_negative_server(rcode, with_soa).await;
        let pool = ProviderPool::for_local_test(vec![
            crate::providers::Provider::for_local_test_with_conns(address, 2),
        ]);
        Arc::new(route_test_state_with_pool(pool))
    }

    async fn prefetch_over_cached_positive(
        state: &Arc<ModuleState>,
    ) -> (CacheKey, PrefetchOutcome) {
        let name = Name::from_str("gone.example.com.").unwrap();
        let key = CacheKey::from("gone.example.com", RecordType::A);
        let mut positive = Message::query();
        positive.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ));
        let refresh_state = state
            .cache
            .insert_returning_state(
                key.clone(),
                CachedEntry::scaffold(positive, "first".into()),
                300,
            )
            .await
            .unwrap();
        assert_eq!(refresh_state.try_start(RefreshSource::StaleRefill), Ok(()));
        let generation = PolicyGeneration::capture(state);

        let outcome = prefetch_refill(
            state.clone(),
            key.clone(),
            name,
            RecordType::A,
            refresh_state,
            generation,
            CancellationToken::new(),
        )
        .await;
        (key, outcome)
    }

    /// A refill that learns the name is gone must not keep the positive entry:
    /// the next hit would serve the withdrawn address until the entry expired,
    /// and a stale refill would keep serving it for hours.
    #[tokio::test]
    async fn prefetch_replaces_the_positive_entry_with_an_authoritative_negative() {
        let state = prefetch_state_over_negative_server(ResponseCode::NXDomain, true).await;

        let (key, outcome) = prefetch_over_cached_positive(&state).await;

        assert_eq!(outcome, PrefetchOutcome::Refilled);
        let entry = state
            .cache
            .get(&key)
            .await
            .expect("the negative must replace the positive entry");
        assert_eq!(entry.message.metadata.response_code, ResponseCode::NXDomain);
        assert!(response_is_negative(&entry.message));
        assert!(
            state
                .cache
                .nxdomain_apex_covers("below.gone.example.com")
                .await,
            "the refill establishes the same RFC 8020 cut a demand query would"
        );
    }

    /// Without an SOA the negative cannot be cached, but it still proves the
    /// positive answer stale.
    #[tokio::test]
    async fn prefetch_withdraws_the_positive_entry_on_an_uncacheable_negative() {
        let state = prefetch_state_over_negative_server(ResponseCode::NXDomain, false).await;

        let (key, outcome) = prefetch_over_cached_positive(&state).await;

        assert_eq!(outcome, PrefetchOutcome::Withdrawn);
        assert!(state.cache.get_allow_expired(&key).await.is_none());
    }

    #[tokio::test]
    async fn prefetch_aborts_when_a_forward_zone_claims_the_name() {
        let (state, key, outcome) = prefetch_outcome_after(|state| {
            state
                .policy
                .load()
                .zones
                .upsert("corp.example.com", "127.0.0.1")
                .unwrap();
        })
        .await;

        assert_eq!(outcome, PrefetchOutcome::Aborted);
        assert!(state.cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn prefetch_aborts_when_an_override_claims_the_name() {
        let (state, key, outcome) = prefetch_outcome_after(|state| {
            state.policy.load().overrides.set(
                "corp.example.com",
                RecordType::A,
                vec![RData::A(A("10.0.0.7".parse().unwrap()))],
            );
        })
        .await;

        assert_eq!(outcome, PrefetchOutcome::Aborted);
        assert!(state.cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn prefetch_aborts_when_captive_forwarding_takes_over() {
        let (state, key, outcome) = prefetch_outcome_after(|state| {
            state.forward.store(Arc::new(Some(Arc::new(
                ForwardResolver::new(&["127.0.0.1".into()]).unwrap(),
            ))));
            state.forward_generation.fetch_add(1, Ordering::AcqRel);
        })
        .await;

        assert_eq!(outcome, PrefetchOutcome::Aborted);
        assert!(state.cache.get(&key).await.is_none());
    }

    /// Republishing the policy is enough on its own: the prefetch was
    /// authorised against a snapshot that no longer runs, and the answer it
    /// would write cannot be attributed to the live one.
    #[tokio::test]
    async fn prefetch_aborts_when_the_policy_snapshot_was_replaced() {
        let (state, key, outcome) = prefetch_outcome_after(|state| {
            state.policy.store(Arc::new(RuntimePolicySnapshot {
                overrides: Arc::new(OverrideStore::new()),
                zones: Arc::new(ForwardZones::new()),
            }));
        })
        .await;

        assert_eq!(outcome, PrefetchOutcome::Aborted);
        assert!(state.cache.get(&key).await.is_none());
    }

    /// The eligibility check awaits, so the policy can be replaced after the
    /// generation was validated and before anything reaches the public pool.
    /// Validating the generation once at the top is not enough: the dispatch
    /// must be gated on a policy read taken after the check returned.
    #[tokio::test]
    async fn prefetch_aborts_when_the_policy_changes_during_the_eligibility_check() {
        let state = Arc::new(route_test_state());
        let qname = Name::from_str("app.corp.example.com.").unwrap();
        let key = CacheKey::from("app.corp.example.com", RecordType::A);
        let generation = PolicyGeneration::capture(&state);

        assert!(
            prefetch_may_use_public_pool(&state, &generation, &key, &qname, RecordType::A).await,
            "test setup requires a name that starts out publicly routable"
        );

        let racing = state.clone();
        let _hook = PrefetchPreDispatchHook::install(Box::new(move |observed| {
            if !std::ptr::eq(observed, Arc::as_ptr(&racing)) {
                return;
            }
            racing.policy.store(Arc::new(RuntimePolicySnapshot {
                overrides: Arc::new(OverrideStore::new()),
                zones: Arc::new(ForwardZones::new()),
            }));
        }));

        let outcome = prefetch_refill(
            state.clone(),
            key.clone(),
            qname,
            RecordType::A,
            claimed_prefetch_state(),
            generation,
            CancellationToken::new(),
        )
        .await;

        assert_eq!(outcome, PrefetchOutcome::Aborted);
        assert!(state.cache.get(&key).await.is_none());
    }

    /// Enabling a captive forward publishes a counter and a value, and a
    /// prefetch samples both without the lifecycle lock. A capture taken
    /// between the two writes (counter already advanced, forward still empty)
    /// passes the eligibility check, and a revalidation that only compares
    /// counters accepts it after the forward went live. Reaching the dispatch
    /// shows up as `NotRefilled`: the empty test pool fails the public lookup
    /// that should never have been issued.
    #[tokio::test]
    async fn prefetch_aborts_when_the_forward_lands_after_its_generation() {
        let state = Arc::new(route_test_state());
        let qname = Name::from_str("app.corp.example.com.").unwrap();
        let key = CacheKey::from("app.corp.example.com", RecordType::A);

        state.forward_generation.fetch_add(1, Ordering::AcqRel);
        let generation = PolicyGeneration::capture(&state);

        assert!(
            prefetch_may_use_public_pool(&state, &generation, &key, &qname, RecordType::A).await,
            "test setup requires a name that starts out publicly routable"
        );

        let racing = state.clone();
        let _hook = PrefetchPreDispatchHook::install(Box::new(move |observed| {
            if !std::ptr::eq(observed, Arc::as_ptr(&racing)) {
                return;
            }
            racing.forward.store(Arc::new(Some(Arc::new(
                ForwardResolver::new(&["127.0.0.1".into()]).unwrap(),
            ))));
        }));

        let outcome = prefetch_refill(
            state.clone(),
            key.clone(),
            qname,
            RecordType::A,
            claimed_prefetch_state(),
            generation,
            CancellationToken::new(),
        )
        .await;

        assert_eq!(outcome, PrefetchOutcome::Aborted);
        assert!(state.cache.get(&key).await.is_none());
    }

    #[test]
    fn positive_cache_ttl_uses_lowest_answer_ttl() {
        let alias = Name::from_str("www.example.").unwrap();
        let target = Name::from_str("edge.example.").unwrap();
        let zone = Name::from_str("example.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(Record::from_rdata(
            alias,
            3600,
            RData::CNAME(CNAME(target.clone())),
        ));
        msg.add_answer(Record::from_rdata(
            target,
            30,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ));
        msg.add_authority(Record::from_rdata(
            zone,
            60,
            RData::SOA(SOA::new(
                Name::from_str("ns.example.").unwrap(),
                Name::from_str("hostmaster.example.").unwrap(),
                1,
                3600,
                600,
                86400,
                300,
            )),
        ));

        assert_eq!(positive_cache_ttl(&msg), 30);
    }

    #[test]
    fn positive_cache_ttl_preserves_short_and_zero_ttls() {
        let qname = Name::from_str("failover.example.").unwrap();
        let ttl_for = |ttl: u32| {
            let mut msg = Message::query();
            msg.add_answer(Record::from_rdata(
                qname.clone(),
                ttl,
                RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
            ));
            positive_cache_ttl(&msg)
        };

        // A short authoritative TTL is a failover signal, not noise.
        assert_eq!(ttl_for(5), 5);
        assert_eq!(ttl_for(1), 1);
        // RFC 2181 §8: TTL 0 means "do not cache".
        assert_eq!(ttl_for(0), 0);
        // No answer RRset, so nothing positive to cache.
        assert_eq!(positive_cache_ttl(&Message::query()), 0);
    }

    #[test]
    fn positive_cache_ttl_excludes_authority_ttl() {
        // RFC 2181 §5.2: the answer TTL stands on its own. RFC 2308 reserves
        // the SOA TTL for negative caching, so an authority SOA on a positive
        // answer must not cut the answer's cached lifetime.
        let qname = Name::from_str("example.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ));
        msg.add_authority(Record::from_rdata(
            qname,
            60,
            RData::SOA(SOA::new(
                Name::from_str("ns.example.").unwrap(),
                Name::from_str("hostmaster.example.").unwrap(),
                1,
                3600,
                600,
                86400,
                300,
            )),
        ));

        assert_eq!(positive_cache_ttl(&msg), 300);
    }

    fn a_record(name: &Name, last: u8) -> Record {
        Record::from_rdata(
            name.clone(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, last))),
        )
    }

    fn lookup_with_a(name: &Name, last: u8) -> Lookup {
        Lookup::new_with_deadline(
            DnsQuery::new()
                .set_name(name.clone())
                .set_query_type(RecordType::A)
                .set_query_class(DNSClass::IN)
                .clone(),
            vec![a_record(name, last)],
            Instant::now() + Duration::from_secs(60),
        )
    }

    /// `a_record` uses the RFC 5737 documentation prefix, which the rebinding
    /// policy rejects. Refinement tests that must reach the cache write need a
    /// publicly-routable answer instead.
    fn public_lookup_with_a(name: &Name, last: u8) -> Lookup {
        Lookup::new_with_deadline(
            DnsQuery::new()
                .set_name(name.clone())
                .set_query_type(RecordType::A)
                .set_query_class(DNSClass::IN)
                .clone(),
            vec![Record::from_rdata(
                name.clone(),
                60,
                RData::A(A(std::net::Ipv4Addr::new(9, 9, 9, last))),
            )],
            Instant::now() + Duration::from_secs(60),
        )
    }

    fn has_ede_filtered(msg: &Message) -> bool {
        msg.edns.as_ref().is_some_and(|edns| {
            edns.options().as_ref().iter().any(|(_, opt)| {
                matches!(opt, hickory_resolver::proto::rr::rdata::opt::EdnsOption::Unknown(15, payload)
                    if payload.starts_with(&super::EDE_FILTERED.to_be_bytes()))
            })
        })
    }

    /// The refined winner can come from a provider whose answer the fast
    /// path never saw. When the rebinding filter strips part of it, the
    /// cached answer must say so with EDE 17, as the fast path does.
    #[tokio::test]
    async fn refined_answer_with_stripped_private_addresses_carries_ede_17() {
        let name = Name::from_str("refine-filter.example.").unwrap();
        let key = CacheKey::from("refine-filter.example", RecordType::A);
        let state = Arc::new(route_test_state());
        let refresh_state = state
            .cache
            .insert_returning_state(
                key.clone(),
                CachedEntry::scaffold(
                    super::message_from_lookup(
                        0,
                        &name,
                        RecordType::A,
                        &public_lookup_with_a(&name, 1),
                    ),
                    "first".into(),
                ),
                60,
            )
            .await
            .unwrap();
        let mixed = || {
            Lookup::new_with_deadline(
                DnsQuery::new()
                    .set_name(name.clone())
                    .set_query_type(RecordType::A)
                    .set_query_class(DNSClass::IN)
                    .clone(),
                vec![
                    Record::from_rdata(name.clone(), 60, RData::A(A::new(9, 9, 9, 2))),
                    Record::from_rdata(name.clone(), 60, RData::A(A::new(10, 0, 0, 7))),
                ],
                Instant::now() + Duration::from_secs(60),
            )
        };

        background_refine(
            vec![
                (0, public_lookup_with_a(&name, 1)),
                (1, mixed()),
                (2, mixed()),
            ],
            0,
            key.clone(),
            name.clone(),
            RecordType::A,
            state.clone(),
            state.cache.capture_epoch(),
            refresh_state,
        )
        .await;

        let entry = state.cache.get(&key).await.unwrap();
        assert_eq!(
            entry.message.answers.len(),
            1,
            "the private address is stripped"
        );
        assert!(has_ede_filtered(&entry.message));
    }

    /// A prefetch refill must reach the answer a demand query would: its
    /// first result is subject to the same consensus as the demand path, or
    /// every refresh reverts a refined entry to whichever provider was fastest.
    #[tokio::test]
    async fn prefetch_refill_applies_consensus_to_the_first_answer() {
        let fast = crate::test_dns_server::spawn_a_server(
            std::net::Ipv4Addr::new(9, 9, 9, 1),
            Duration::ZERO,
        )
        .await;
        let mut slow = Vec::new();
        for _ in 0..2 {
            slow.push(
                crate::test_dns_server::spawn_a_server(
                    std::net::Ipv4Addr::new(9, 9, 9, 2),
                    Duration::from_millis(40),
                )
                .await,
            );
        }
        let pool = ProviderPool::for_local_test(vec![
            crate::providers::Provider::for_local_test_with_conns(fast, 2),
            crate::providers::Provider::for_local_test_with_conns(slow[0], 2),
            crate::providers::Provider::for_local_test_with_conns(slow[1], 2),
        ]);
        let state = Arc::new(route_test_state_with_pool(pool));
        let name = Name::from_str("consensus.example.com.").unwrap();
        let key = CacheKey::from("consensus.example.com", RecordType::A);
        let refresh_state = state
            .cache
            .insert_returning_state(
                key.clone(),
                CachedEntry::scaffold(
                    super::message_from_lookup(
                        0,
                        &name,
                        RecordType::A,
                        &public_lookup_with_a(&name, 3),
                    ),
                    "old".into(),
                ),
                300,
            )
            .await
            .unwrap();
        assert_eq!(
            refresh_state.try_start(RefreshSource::PeriodicPrefetch),
            Ok(())
        );
        let generation = PolicyGeneration::capture(&state);

        let outcome = prefetch_refill(
            state.clone(),
            key.clone(),
            name,
            RecordType::A,
            refresh_state,
            generation,
            CancellationToken::new(),
        )
        .await;
        assert_eq!(outcome, PrefetchOutcome::Refilled);

        let consensus = [std::net::IpAddr::V4(std::net::Ipv4Addr::new(9, 9, 9, 2))]
            .into_iter()
            .collect();
        for _ in 0..200 {
            let entry = state.cache.get(&key).await.unwrap();
            if normalize_ips(&entry.message.answers) == consensus {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the prefetched entry never reached the consensus answer");
    }

    /// A refinement can land seconds after the answer it improves (probing
    /// alone is budgeted at 3s). Committing it through `insert` would restamp
    /// `inserted_at` / `expires_at` and give the entry a new full TTL, keeping
    /// a name alive past what its authority published. The refined payload
    /// must replace the old one inside the original expiry window.
    #[tokio::test]
    async fn late_refined_winner_cannot_extend_the_original_expiry() {
        let name = Name::from_str("refine-expiry.example.").unwrap();
        let key = CacheKey::from("refine-expiry.example", RecordType::A);
        let state = Arc::new(route_test_state());

        let mut original = Message::query();
        original.add_answer(Record::from_rdata(
            name.clone(),
            30,
            RData::A(A(std::net::Ipv4Addr::new(9, 9, 9, 1))),
        ));
        assert!(
            state
                .cache
                .insert(
                    key.clone(),
                    CachedEntry::scaffold(original, "first".into()),
                    30,
                )
                .await
        );
        let before = state.cache.get(&key).await.unwrap();

        // Two providers agree on an answer the fast path did not return, so the
        // consensus branch picks a new winner without any ICMP probing.
        tokio::time::sleep(Duration::from_millis(20)).await;
        background_refine(
            vec![
                (0, public_lookup_with_a(&name, 1)),
                (1, public_lookup_with_a(&name, 2)),
                (2, public_lookup_with_a(&name, 2)),
            ],
            0,
            key.clone(),
            name.clone(),
            RecordType::A,
            state.clone(),
            state.cache.capture_epoch(),
            before.refresh_state.clone(),
        )
        .await;

        let after = state.cache.get(&key).await.unwrap();
        assert_eq!(
            normalize_ips(&after.message.answers),
            [std::net::IpAddr::V4(std::net::Ipv4Addr::new(9, 9, 9, 2))]
                .into_iter()
                .collect(),
            "the refined winner must actually have replaced the payload"
        );
        assert_eq!(
            after.expires_at, before.expires_at,
            "a refinement must not move the entry's expiry"
        );
        assert_eq!(
            after.inserted_at, before.inserted_at,
            "a refinement must not restamp the entry's insertion time"
        );
        assert_eq!(
            after.original_ttl_secs, 30,
            "the entry keeps the TTL it was cached with"
        );
        assert!(
            after.message.answers.iter().all(|rec| rec.ttl <= 30),
            "refined record TTLs must not exceed the entry's own lifetime"
        );
    }

    #[test]
    fn refine_candidates_dedupe_provider_keep_first_answer() {
        let n = Name::from_str("example.com.").unwrap();
        let all = vec![
            (1, lookup_with_a(&n, 1)),
            (1, lookup_with_a(&n, 2)),
            (2, lookup_with_a(&n, 3)),
        ];

        let unique = unique_provider_lookups(&all);
        let first_ips = normalize_ips(unique[0].1.answers());

        assert_eq!(unique.len(), 2);
        assert_eq!(unique[0].0, 1);
        assert_eq!(unique[1].0, 2);
        assert!(first_ips.contains(&"192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn refine_probe_candidates_keep_provider_indices_not_positions() {
        let n = Name::from_str("example.com.").unwrap();
        let unique = vec![(1, lookup_with_a(&n, 1)), (2, lookup_with_a(&n, 2))];
        let ip_sets: Vec<_> = unique
            .iter()
            .map(|(_, lookup)| normalize_ips(lookup.answers()))
            .collect();
        let Verdict::Probe(positional) = evaluate(&ip_sets) else {
            panic!("distinct answers should require probe")
        };

        let provider_candidates = provider_indexed_probe_candidates(&positional, &unique);

        assert_eq!(provider_candidates[0].0, 1);
        assert_eq!(provider_candidates[1].0, 2);
    }

    #[test]
    fn rotate_rotates_tail_a_records() {
        let n = Name::from_str("example.com.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(a_record(&n, 1));
        msg.add_answer(a_record(&n, 2));
        msg.add_answer(a_record(&n, 3));
        rotate_address_rrset(&mut msg, 1);
        // Shift-left by 1 ⇒ order becomes 2,3,1.
        let ips: Vec<u8> = msg
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0.octets()[3]),
                _ => None,
            })
            .collect();
        assert_eq!(ips, vec![2, 3, 1]);
    }

    #[test]
    fn rotate_preserves_leading_cname() {
        let alias = Name::from_str("alias.example.").unwrap();
        let target = Name::from_str("real.example.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(Record::from_rdata(
            alias,
            60,
            RData::CNAME(CNAME(target.clone())),
        ));
        msg.add_answer(a_record(&target, 1));
        msg.add_answer(a_record(&target, 2));
        rotate_address_rrset(&mut msg, 1);
        // CNAME stays first and the A rrset rotates.
        assert!(matches!(&msg.answers[0].data, RData::CNAME(_)));
        let a_octets: Vec<u8> = msg
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0.octets()[3]),
                _ => None,
            })
            .collect();
        assert_eq!(a_octets, vec![2, 1]);
    }

    /// Upstream conversion must preserve the AD bit and the authority and
    /// additional sections (NXDOMAIN SOA + NSEC chain).
    #[test]
    fn message_from_upstream_preserves_ad_bit_and_authorities() {
        // Explicit: the AD passthrough is only valid while the toggle is on,
        // because that is what sends CD=0 and asks the provider to validate.
        let _guard = crate::config::ConfigGuard::new(crate::config::ResolverOptions {
            dnssec: true,
            ..Default::default()
        });
        let qname = Name::from_str("signed.example.").unwrap();
        let qtype = RecordType::A;

        let mut upstream = Message::new(0, MessageType::Response, OpCode::Query);
        upstream.metadata.authentic_data = true;
        let mut q = DnsQuery::new();
        q.set_name(qname.clone())
            .set_query_type(qtype)
            .set_query_class(DNSClass::IN);
        upstream.add_query(q);
        upstream.add_answer(Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(93, 184, 216, 34))),
        ));
        upstream.add_authority(Record::from_rdata(
            Name::from_str("example.").unwrap(),
            3600,
            RData::SOA(SOA::new(
                Name::from_str("ns.example.").unwrap(),
                Name::from_str("hostmaster.example.").unwrap(),
                1,
                3600,
                600,
                86400,
                300,
            )),
        ));
        let out = message_from_upstream_message(0xBEEF, &qname, qtype, &upstream);
        assert_eq!(out.metadata.id, 0xBEEF);
        assert!(
            out.metadata.authentic_data,
            "AD bit must propagate from upstream Lookup",
        );
        assert_eq!(out.answers.len(), 1, "answer must round-trip");
        assert_eq!(
            out.authorities.len(),
            1,
            "SOA in authority section must round-trip for negative caching",
        );
    }

    /// With the toggle off, `dig +dnssec` through MacDNS came back with AD set.
    /// Quad9 sets AD under CD=1 regardless of the DO bit (Cloudflare and Google
    /// do not), so the bit depended on which provider won the hedge race.
    ///
    /// Passing it on tells the client the answer was authenticated when
    /// MacDNS's own request asked the provider not to authenticate it. The
    /// records still flow. Only the claim about them is withheld.
    #[test]
    fn message_from_upstream_drops_the_ad_bit_when_the_toggle_is_off() {
        let _guard = crate::config::ConfigGuard::new(crate::config::ResolverOptions {
            dnssec: false,
            ..Default::default()
        });
        let qname = Name::from_str("signed.example.").unwrap();
        let qtype = RecordType::A;

        let mut upstream = Message::new(0, MessageType::Response, OpCode::Query);
        upstream.metadata.authentic_data = true;
        let mut q = DnsQuery::new();
        q.set_name(qname.clone())
            .set_query_type(qtype)
            .set_query_class(DNSClass::IN);
        upstream.add_query(q);
        upstream.add_answer(Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(93, 184, 216, 34))),
        ));

        let out = message_from_upstream_message(0xBEEF, &qname, qtype, &upstream);

        assert!(
            !out.metadata.authentic_data,
            "we sent CD=1, so nothing validated this answer and AD must not be \
             forwarded no matter what the provider claimed"
        );
        assert_eq!(
            out.answers.len(),
            1,
            "withholding the claim must not withhold the data"
        );
    }

    #[test]
    fn rotate_is_noop_for_single_record() {
        let n = Name::from_str("example.com.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(a_record(&n, 42));
        rotate_address_rrset(&mut msg, 7);
        assert_eq!(msg.answers.len(), 1);
        match &msg.answers[0].data {
            RData::A(a) => assert_eq!(a.0.octets()[3], 42),
            _ => panic!("expected A"),
        }
    }

    /// NODATA shape for override-owned names: NOERROR, zero answers, one
    /// synthesised SOA in authority, id echoed from the request. Guards the
    /// contract consumed by the query pipeline when `overrides.has_any` is
    /// true but the exact qtype is missing.
    #[test]
    fn build_local_nodata_returns_noerror_with_single_soa() {
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        let qname = Name::from_str("private.internal.").unwrap();
        let apex = Name::from_str("internal.").unwrap();
        let req = Message::query();
        let m = build_local_nodata(0xBEEF, &qname, RecordType::AAAA, &req, &apex);
        let bytes = m.to_bytes().unwrap();
        let parsed = Message::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.metadata.id, 0xBEEF);
        assert_eq!(parsed.metadata.response_code, ResponseCode::NoError);
        assert!(parsed.answers.is_empty(), "NODATA must carry no answer RRs");
        assert_eq!(
            parsed.authorities.len(),
            1,
            "expected exactly one authority"
        );
        assert!(
            matches!(&parsed.authorities[0].data, RData::SOA(_)),
            "authority must be SOA",
        );
        assert_eq!(
            parsed.authorities[0].name, apex,
            "SOA owner must be the zone apex (RFC 2308 §3)",
        );
        assert_eq!(parsed.authorities[0].ttl, synthetic_negative_ttl_secs());
        match &parsed.authorities[0].data {
            RData::SOA(soa) => assert_eq!(soa.minimum, synthetic_negative_ttl_secs()),
            other => panic!("expected SOA, got {:?}", other),
        }
    }

    #[test]
    fn build_nxdomain_includes_synth_soa_for_negative_caching() {
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        let qname = Name::from_str("blocked.example.").unwrap();
        let req = Message::query();
        let m = build_nxdomain(0xBEEF, &qname, RecordType::A, &req);
        let bytes = m.to_bytes().unwrap();
        let parsed = Message::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(parsed.authorities.len(), 1, "NXDOMAIN must carry an SOA");
        assert_eq!(parsed.authorities[0].ttl, synthetic_negative_ttl_secs());
        match &parsed.authorities[0].data {
            RData::SOA(soa) => assert_eq!(soa.minimum, synthetic_negative_ttl_secs()),
            other => panic!("expected SOA, got {:?}", other),
        }
    }

    #[test]
    fn is_localhost_name_matches_apex_and_subnames_case_insensitively() {
        assert!(is_localhost_name("localhost"));
        assert!(is_localhost_name("LocalHost"));
        assert!(is_localhost_name("api.localhost"));
        assert!(is_localhost_name("a.b.LOCALHOST"));
        assert!(!is_localhost_name("localhost.com"));
        assert!(!is_localhost_name("notlocalhost"));
        assert!(!is_localhost_name("example.com"));
    }

    #[test]
    fn build_localhost_response_returns_loopback_for_a_query() {
        let qname = Name::from_str("localhost.").unwrap();
        let msg = build_localhost_response(
            0xBEEF,
            &qname,
            RecordType::A,
            &Message::query(),
            "localhost",
        )
        .expect("localhost A must yield a synthetic answer");
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert_eq!(msg.answers.len(), 1, "A query must answer with 127.0.0.1");
        match &msg.answers[0].data {
            RData::A(a) => assert_eq!(a.0, std::net::Ipv4Addr::new(127, 0, 0, 1)),
            other => panic!("expected A, got {:?}", other),
        }
    }

    #[test]
    fn build_localhost_response_returns_ipv6_loopback_for_aaaa_query() {
        let qname = Name::from_str("localhost.").unwrap();
        let msg = build_localhost_response(
            0xBEEF,
            &qname,
            RecordType::AAAA,
            &Message::query(),
            "localhost",
        )
        .expect("localhost AAAA must yield a synthetic answer");
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert_eq!(msg.answers.len(), 1);
        match &msg.answers[0].data {
            RData::AAAA(a) => assert_eq!(a.0, std::net::Ipv6Addr::LOCALHOST),
            other => panic!("expected AAAA, got {:?}", other),
        }
    }

    #[test]
    fn build_localhost_response_returns_nodata_for_other_qtypes() {
        let qname = Name::from_str("api.localhost.").unwrap();
        let msg = build_localhost_response(
            0xBEEF,
            &qname,
            RecordType::TXT,
            &Message::query(),
            "api.localhost",
        )
        .expect("localhost TXT must yield a NODATA shape");
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert!(msg.answers.is_empty(), "NODATA must carry no answers");
        assert_eq!(
            msg.authorities.len(),
            1,
            "NODATA must carry an SOA for negative caching"
        );
        assert!(matches!(msg.authorities[0].data, RData::SOA(_)));
        assert_eq!(
            msg.authorities[0].name,
            Name::from_str("localhost.").unwrap(),
            "localhost NODATA authority owner must be the special-use apex"
        );
        assert_eq!(msg.authorities[0].ttl, synthetic_negative_ttl_secs());
        match &msg.authorities[0].data {
            RData::SOA(soa) => assert_eq!(soa.minimum, synthetic_negative_ttl_secs()),
            other => panic!("expected SOA, got {:?}", other),
        }
    }

    #[test]
    fn build_localhost_response_passes_through_non_localhost_names() {
        let qname = Name::from_str("example.com.").unwrap();
        let msg = build_localhost_response(
            0xBEEF,
            &qname,
            RecordType::A,
            &Message::query(),
            "example.com",
        );
        assert!(msg.is_none(), "non-localhost names must fall through");
    }

    /// Hickory's `NoRecords` exposes the zone SOA through both the `soa` field
    /// and the wire `authorities` section. `build_negative` must emit the SOA
    /// once (`dig` showed `AUTHORITY: 2` with matching serials) and keep every
    /// non-SOA authority record (NSEC/NSEC3 chains on validated negatives).
    #[test]
    fn build_negative_deduplicates_soa_across_soa_field_and_authorities() {
        let qname = Name::from_str("missing.example.").unwrap();
        let zone = Name::from_str("example.").unwrap();
        let soa_data = SOA::new(
            Name::from_str("ns.example.").unwrap(),
            Name::from_str("hostmaster.example.").unwrap(),
            2026042000,
            3600,
            600,
            86400,
            300,
        );
        let soa_typed: Record<SOA> = Record::from_rdata(zone.clone(), 300, soa_data.clone());
        let soa_in_auth = Record::from_rdata(zone, 300, RData::SOA(soa_data));
        let authorities = vec![soa_in_auth];

        let msg = build_negative(
            0xBEEF,
            &qname,
            RecordType::A,
            ResponseCode::NoError,
            None,
            Some(&soa_typed),
            Some(&authorities),
            Some(60),
            &Message::query(),
        );

        let soas = msg
            .authorities
            .iter()
            .filter(|r| matches!(&r.data, RData::SOA(_)))
            .count();
        assert_eq!(
            soas, 1,
            "SOA must appear exactly once even when present in both `soa` and `authorities`",
        );
    }

    /// The other half of `build_negative`'s authority handling. The dedup test
    /// above supplies only an SOA, so it cannot catch a build that stops
    /// copying the other authority records.
    ///
    /// This is the NSEC chain that proves a negative answer. Dropping it leaves
    /// a client that asked for DNSSEC with an NXDOMAIN it cannot verify.
    #[test]
    fn build_negative_preserves_non_soa_dnssec_authorities() {
        let qname = Name::from_str("missing.example.").unwrap();
        let zone = Name::from_str("example.").unwrap();
        let soa_data = SOA::new(
            Name::from_str("ns.example.").unwrap(),
            Name::from_str("hostmaster.example.").unwrap(),
            2026042000,
            3600,
            600,
            86400,
            300,
        );
        let soa_typed: Record<SOA> = Record::from_rdata(zone.clone(), 300, soa_data.clone());
        let soa_in_auth = Record::from_rdata(zone, 300, RData::SOA(soa_data));
        let nsec = Record::from_rdata(
            qname.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                Name::from_str("next.example.").unwrap(),
                [RecordType::A, RecordType::RRSIG],
            ))),
        );
        // The NSEC alone would not catch a copy that skipped only RRSIG, and an
        // NSEC without its signature proves nothing to a validator.
        let rrsig = Record::update0(qname.clone(), 300, RecordType::RRSIG);
        let authorities = vec![soa_in_auth, nsec, rrsig];

        let msg = build_negative(
            0xBEEF,
            &qname,
            RecordType::A,
            ResponseCode::NXDomain,
            None,
            Some(&soa_typed),
            Some(&authorities),
            Some(60),
            &Message::query(),
        );

        assert_eq!(
            msg.authorities
                .iter()
                .filter(|r| r.record_type() == RecordType::RRSIG)
                .count(),
            1,
            "the RRSIG signing the NSEC must survive too - an unsigned denial \
             proof is not a proof"
        );

        assert_eq!(
            msg.authorities
                .iter()
                .filter(|r| matches!(&r.data, RData::DNSSEC(DNSSECRData::NSEC(_))))
                .count(),
            1,
            "the NSEC proving the negative must reach the client - without it a \
             signed NXDOMAIN cannot be verified"
        );
        assert_eq!(
            msg.authorities
                .iter()
                .filter(|r| matches!(&r.data, RData::SOA(_)))
                .count(),
            1,
            "the SOA must still be emitted exactly once alongside the NSEC"
        );
    }

    /// Builds the `NoRecordsFound` error a provider surfaces for a negative
    /// answer. `terminal` is the name hickory reports the failure against: the
    /// QNAME for a direct negative, the end of the chain after a CNAME chase.
    fn no_records_err(
        terminal: &Name,
        qtype: RecordType,
        response_code: ResponseCode,
        soa: Option<(Name, u32, u32)>,
        negative_ttl: Option<u32>,
    ) -> NetError {
        let mut q = DnsQuery::new();
        q.set_name(terminal.clone())
            .set_query_type(qtype)
            .set_query_class(DNSClass::IN);
        let mut no_records = NoRecords::new(q, response_code);
        if let Some((zone, ttl, minimum)) = soa {
            let soa_data = SOA::new(
                Name::from_str("ns.example.").unwrap(),
                Name::from_str("hostmaster.example.").unwrap(),
                2026042000,
                3600,
                600,
                86400,
                minimum,
            );
            no_records.soa = Some(Box::new(Record::from_rdata(zone, ttl, soa_data)));
        }
        no_records.negative_ttl = negative_ttl;
        NetError::Dns(DnsError::NoRecordsFound(no_records))
    }

    /// Drives the real negative branch of `process_hedge_outcome`, the only
    /// place that decides what a `NoRecordsFound` puts in the cache, with a
    /// provider error instead of a network dispatch.
    async fn negative_hedge_outcome_with_state(
        state: &Arc<ModuleState>,
        name: &Name,
        qtype: RecordType,
        err: NetError,
    ) -> (Message, ReplyOrigin) {
        negative_hedge_outcome_with_cd(state, name, qtype, err, false).await
    }

    /// Same, with the caller's forced-CD decision exposed so the containment
    /// path can be driven through the real negative branch.
    async fn negative_hedge_outcome_with_cd(
        state: &Arc<ModuleState>,
        name: &Name,
        qtype: RecordType,
        err: NetError,
        client_forced_cd: bool,
    ) -> (Message, ReplyOrigin) {
        let cfg = crate::config::current();
        let domain = name.to_string();
        let domain_trim = domain.trim_end_matches('.').to_string();
        let key = CacheKey::from(&domain_trim, qtype);
        let cache_epoch = state.cache.capture_epoch();
        process_hedge_outcome(
            Err(crate::hedge::HedgeError::AllFailed {
                negative: Some(err),
                negative_idx: None,
            }),
            0xBEEF,
            name,
            qtype,
            &domain_trim,
            &cfg,
            state,
            key,
            &request_for(name),
            cache_epoch,
            client_forced_cd,
        )
        .await
    }

    async fn negative_hedge_outcome(
        name: &Name,
        qtype: RecordType,
        err: NetError,
    ) -> (Message, ReplyOrigin) {
        let state = Arc::new(route_test_state());
        negative_hedge_outcome_with_state(&state, name, qtype, err).await
    }

    fn cacheable_negative(answer: Option<NegativeAnswer>) -> (Message, u32) {
        match answer {
            Some(NegativeAnswer::Cacheable { message, ttl_secs }) => (message, ttl_secs),
            Some(NegativeAnswer::Uncacheable { .. }) => {
                panic!("expected a cacheable negative answer, got an uncacheable one")
            }
            Some(NegativeAnswer::Unresolvable) => {
                panic!("expected a cacheable negative answer, got an unresolvable chain")
            }
            None => panic!("expected a NoRecordsFound error"),
        }
    }

    fn ad_request(ad: bool, dnssec_ok: Option<bool>) -> Message {
        let mut request = Message::query();
        request.metadata.authentic_data = ad;
        if let Some(dnssec_ok) = dnssec_ok {
            let mut edns = hickory_resolver::proto::op::Edns::new();
            edns.set_dnssec_ok(dnssec_ok);
            request.edns = Some(edns);
        }
        request
    }

    /// RFC 6840 §5.8: AD goes only to a client that asked for it with AD or
    /// DO. mDNSResponder sets neither, so its answers must not claim
    /// authentication it never requested.
    #[test]
    fn authentic_data_reaches_only_clients_that_asked_for_it() {
        for (request, expected) in [
            (ad_request(false, None), false),
            (ad_request(false, Some(false)), false),
            (ad_request(true, None), true),
            (ad_request(false, Some(true)), true),
        ] {
            let mut response = Message::query();
            response.metadata.authentic_data = true;

            gate_authentic_data(&mut response, &request);

            assert_eq!(response.metadata.authentic_data, expected);
        }
    }

    #[test]
    fn gate_never_raises_authentic_data() {
        let mut response = Message::query();
        gate_authentic_data(&mut response, &ad_request(true, Some(true)));
        assert!(!response.metadata.authentic_data);
    }

    fn ede_payload(info_code: u16, text: &str) -> Vec<u8> {
        let mut payload = info_code.to_be_bytes().to_vec();
        payload.extend_from_slice(text.as_bytes());
        payload
    }

    fn ede_payloads(msg: &Message) -> Vec<Vec<u8>> {
        msg.edns
            .as_ref()
            .map(|edns| {
                edns.options()
                    .as_ref()
                    .iter()
                    .filter_map(|(_, opt)| match opt {
                        hickory_resolver::proto::rr::rdata::opt::EdnsOption::Unknown(15, p) => {
                            Some(p.clone())
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// RFC 8914: the provider's own Extended DNS Errors explain its answer.
    /// Only those reach the client. The rest of the provider's OPT describes
    /// the DoH hop.
    #[test]
    fn positive_answer_keeps_the_provider_extended_dns_errors_only() {
        let qname = Name::from_str("ede.example.com.").unwrap();
        let mut upstream = Message::query();
        upstream.add_answer(Record::from_rdata(
            qname.clone(),
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        let mut edns = hickory_resolver::proto::op::Edns::new();
        edns.options_mut().insert(
            hickory_resolver::proto::rr::rdata::opt::EdnsOption::Unknown(
                15,
                ede_payload(3, "Stale Answer"),
            ),
        );
        edns.options_mut()
            .insert(hickory_resolver::proto::rr::rdata::opt::EdnsOption::Unknown(10, vec![1; 8]));
        upstream.edns = Some(edns);

        let out = message_from_upstream_message(0xBEEF, &qname, RecordType::A, &upstream);

        assert_eq!(ede_payloads(&out), vec![ede_payload(3, "Stale Answer")]);
        let options = out.edns.as_ref().unwrap().options().as_ref().len();
        assert_eq!(options, 1, "no other provider option may be copied");
    }

    #[test]
    fn negative_answer_keeps_the_provider_extended_dns_errors() {
        let qname = Name::from_str("blocked.example.com.").unwrap();
        let mut err = no_records_err(
            &qname,
            RecordType::A,
            ResponseCode::NXDomain,
            Some((Name::from_str("example.com.").unwrap(), 60, 60)),
            Some(60),
        );
        let NetError::Dns(DnsError::NoRecordsFound(no_records)) = &mut err else {
            panic!("helper must build a NoRecordsFound error");
        };
        let mut response = Message::query();
        let mut edns = hickory_resolver::proto::op::Edns::new();
        edns.options_mut().insert(
            hickory_resolver::proto::rr::rdata::opt::EdnsOption::Unknown(
                15,
                ede_payload(15, "Blocked"),
            ),
        );
        response.edns = Some(edns);
        no_records.extended_errors = hickory_resolver::net::ExtendedErrors::from_message(&response);

        let (msg, _ttl) = cacheable_negative(classify_negative_err(
            0xBEEF,
            &qname,
            RecordType::A,
            &err,
            &Message::query(),
        ));

        assert_eq!(ede_payloads(&msg), vec![ede_payload(15, "Blocked")]);
    }

    /// A provider's SERVFAIL usually says why (DNSSEC bogus, no reachable
    /// authority). The resolver's own EDE stays first and the provider's follow.
    #[tokio::test]
    async fn upstream_servfail_carries_the_provider_extended_dns_errors() {
        let state = Arc::new(route_test_state());
        let name = Name::from_str("bogus.example.com.").unwrap();
        let mut response = Message::query();
        let mut edns = hickory_resolver::proto::op::Edns::new();
        edns.options_mut().insert(
            hickory_resolver::proto::rr::rdata::opt::EdnsOption::Unknown(
                15,
                ede_payload(6, "DNSSEC Bogus"),
            ),
        );
        response.edns = Some(edns);

        let (msg, _provider) = process_hedge_outcome(
            Err(HedgeError::UpstreamResponse {
                rcode: ResponseCode::ServFail,
                extended_errors: hickory_resolver::net::ExtendedErrors::from_message(&response),
            }),
            0xBEEF,
            &name,
            RecordType::A,
            "bogus.example.com",
            &crate::config::current(),
            &state,
            CacheKey::from("bogus.example.com", RecordType::A),
            &request_for(&name),
            state.cache.capture_epoch(),
            false,
        )
        .await;

        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
        let payloads = ede_payloads(&msg);
        assert_eq!(payloads.len(), 2);
        assert_eq!(&payloads[0][..2], &EDE_OTHER.to_be_bytes());
        assert_eq!(payloads[1], ede_payload(6, "DNSSEC Bogus"));
    }

    /// RFC 2308 §2.1 and §2.2: when the negative was reached through aliases,
    /// the chain belongs in the answer section so the client learns the name
    /// exists and where it points.
    #[test]
    fn classify_negative_err_puts_the_cname_chain_in_the_answer_section() {
        let alias = Name::from_str("www.example.com.").unwrap();
        let terminal = Name::from_str("target.cdn.example.").unwrap();
        let cname = Record::from_rdata(alias.clone(), 300, RData::CNAME(CNAME(terminal.clone())));
        let mut err = no_records_err(
            &terminal,
            RecordType::AAAA,
            ResponseCode::NoError,
            Some((Name::from_str("cdn.example.").unwrap(), 60, 60)),
            Some(60),
        );
        let NetError::Dns(DnsError::NoRecordsFound(no_records)) = &mut err else {
            panic!("helper must build a NoRecordsFound error");
        };
        no_records.cname_chain = Some(std::sync::Arc::from(vec![cname.clone()]));

        let (msg, _ttl) = cacheable_negative(classify_negative_err(
            0xBEEF,
            &alias,
            RecordType::AAAA,
            &err,
            &Message::query(),
        ));

        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            msg.answers.len(),
            1,
            "the chain must reach the answer section"
        );
        assert_eq!(msg.answers[0].name, alias);
        assert!(matches!(&msg.answers[0].data, RData::CNAME(CNAME(target)) if target == &terminal));
        assert!(
            msg.authorities
                .iter()
                .any(|r| matches!(&r.data, RData::SOA(_))),
            "the SOA proof still bounds the negative"
        );
        assert!(response_is_negative(&msg));
    }

    /// `classify_negative_err` pulls the authority records out of Hickory's
    /// `NoRecords` before calling `build_negative`. Dropping that field would
    /// strip every denial proof and leave the direct `build_negative` tests green.
    #[test]
    fn classify_negative_err_carries_the_denial_proof_through() {
        let qname = Name::from_str("missing.example.").unwrap();
        let zone = Name::from_str("example.").unwrap();
        let nsec = Record::from_rdata(
            qname.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                Name::from_str("next.example.").unwrap(),
                [RecordType::A, RecordType::RRSIG],
            ))),
        );
        let rrsig = Record::update0(qname.clone(), 300, RecordType::RRSIG);

        let mut err = no_records_err(
            &qname,
            RecordType::A,
            ResponseCode::NXDomain,
            Some((zone, 300, 300)),
            Some(60),
        );
        let NetError::Dns(DnsError::NoRecordsFound(no_records)) = &mut err else {
            panic!("helper must build a NoRecordsFound error");
        };
        no_records.authorities = Some(std::sync::Arc::from(vec![nsec, rrsig]));

        let (msg, _ttl) = cacheable_negative(classify_negative_err(
            0xBEEF,
            &qname,
            RecordType::A,
            &err,
            &Message::query(),
        ));

        assert_eq!(
            msg.authorities
                .iter()
                .filter(|r| matches!(&r.data, RData::DNSSEC(DNSSECRData::NSEC(_))))
                .count(),
            1,
            "the NSEC from NoRecords::authorities must reach the response"
        );
        assert_eq!(
            msg.authorities
                .iter()
                .filter(|r| r.record_type() == RecordType::RRSIG)
                .count(),
            1,
            "the RRSIG from NoRecords::authorities must reach the response"
        );
    }

    #[test]
    fn classify_negative_err_caps_wire_ttl_without_mutating_soa_minimum() {
        let qname = Name::from_str("missing.example.").unwrap();
        let zone = Name::from_str("example.").unwrap();
        let soa_data = SOA::new(
            Name::from_str("ns.example.").unwrap(),
            Name::from_str("hostmaster.example.").unwrap(),
            2026042000,
            3600,
            600,
            86400,
            3600,
        );
        let soa_wire = Record::from_rdata(zone.clone(), 3600, RData::SOA(soa_data));
        let mut err = no_records_err(
            &qname,
            RecordType::A,
            ResponseCode::NXDomain,
            Some((zone, 3600, 3600)),
            Some(900),
        );
        let NetError::Dns(DnsError::NoRecordsFound(no_records)) = &mut err else {
            panic!("helper must build a NoRecordsFound error");
        };
        no_records.authorities = Some(Arc::from(vec![soa_wire].into_boxed_slice()));

        let (msg, neg_ttl) = cacheable_negative(classify_negative_err(
            0xBEEF,
            &qname,
            RecordType::A,
            &err,
            &Message::query(),
        ));

        assert_eq!(neg_ttl, synthetic_negative_ttl_secs());
        assert_eq!(msg.authorities.len(), 1);
        assert_eq!(msg.authorities[0].ttl, synthetic_negative_ttl_secs());
        match &msg.authorities[0].data {
            RData::SOA(soa) => assert_eq!(
                soa.minimum, 3600,
                "signed upstream SOA RDATA must not be rewritten"
            ),
            other => panic!("expected SOA, got {:?}", other),
        }
    }

    #[test]
    fn response_is_negative_detects_nxdomain_nodata_and_cname_nodata() {
        let qname = Name::from_str("missing.example.").unwrap();
        let apex = Name::from_str("example.").unwrap();
        let req = Message::query();
        assert!(response_is_negative(&build_nxdomain(
            0xBEEF,
            &qname,
            RecordType::A,
            &req
        )));
        assert!(response_is_negative(&build_local_nodata(
            0xBEEF,
            &qname,
            RecordType::AAAA,
            &req,
            &apex,
        )));

        let mut cname_nodata = build_local_nodata(0xBEEF, &qname, RecordType::A, &req, &apex);
        cname_nodata.add_answer(Record::from_rdata(
            qname.clone(),
            300,
            RData::CNAME(CNAME(Name::from_str("target.example.").unwrap())),
        ));
        assert!(response_is_negative(&cname_nodata));

        let mut positive = Message::query();
        let mut q = DnsQuery::new();
        q.set_name(qname.clone())
            .set_query_type(RecordType::A)
            .set_query_class(DNSClass::IN);
        positive.add_query(q);
        positive.add_answer(a_record(&qname, 42));
        positive.add_authority(Record::from_rdata(
            apex,
            300,
            RData::SOA(SOA::new(
                Name::from_str("ns.example.").unwrap(),
                Name::from_str("hostmaster.example.").unwrap(),
                1,
                3600,
                600,
                86400,
                300,
            )),
        ));
        assert!(!response_is_negative(&positive));
    }

    #[tokio::test]
    async fn below_nxdomain_short_circuits_upstream() {
        use crate::cache::DnsCache;
        let cache = Arc::new(DnsCache::new(1_048_576));
        cache.insert_nxdomain_apex("vanished.test.").await;

        let qname = Name::from_str("x.y.vanished.test.").unwrap();
        let out = resolve_below_nxdomain_or_none(&cache, &qname, RecordType::A).await;
        let msg = out.expect("cached NXDOMAIN apex must short-circuit");
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(msg.answers.len(), 0);
        assert_eq!(msg.authorities.len(), 1);
        assert_eq!(
            msg.authorities[0].name,
            Name::from_str("vanished.test.").unwrap(),
            "RFC 2308 authority SOA owner must be the covering NXDOMAIN apex"
        );
    }

    #[tokio::test]
    async fn below_nxdomain_passes_through_when_no_apex() {
        use crate::cache::DnsCache;
        let cache = Arc::new(DnsCache::new(1_048_576));
        let qname = Name::from_str("live.example.").unwrap();
        let out = resolve_below_nxdomain_or_none(&cache, &qname, RecordType::A).await;
        assert!(out.is_none());
    }

    #[test]
    fn nxdomain_apex_is_the_denied_name_per_rfc8020() {
        use crate::query::nxdomain_apex_from;
        let denied = Name::from_str("g1.globo.com.").unwrap();
        assert_eq!(
            nxdomain_apex_from(&denied),
            "g1.globo.com.",
            "RFC 8020 apex is the name that does not exist, never the SOA owner — \
             using the SOA owner would let one transient NXDOMAIN poison the whole \
             authoritative zone"
        );
    }

    #[tokio::test]
    async fn nxdomain_for_subdomain_does_not_poison_zone_apex() {
        // A transient NXDOMAIN for `g1.globo.com` must not make
        // `www.globo.com` short-circuit to NXDOMAIN. The RFC 8020 apex is the
        // QNAME, so siblings under the parent zone are unaffected.
        use crate::cache::DnsCache;
        let cache = Arc::new(DnsCache::new(1_048_576));
        cache.insert_nxdomain_apex("g1.globo.com.").await;

        let sibling = Name::from_str("www.globo.com.").unwrap();
        assert!(
            resolve_below_nxdomain_or_none(&cache, &sibling, RecordType::A)
                .await
                .is_none(),
            "siblings under parent zone must not be poisoned by a leaf NXDOMAIN"
        );

        let descendant = Name::from_str("sub.g1.globo.com.").unwrap();
        assert!(
            resolve_below_nxdomain_or_none(&cache, &descendant, RecordType::A)
                .await
                .is_some(),
            "descendants of the NXDOMAIN qname must still short-circuit (RFC 8020)"
        );
    }

    #[test]
    fn message_has_payload_true_when_answer_present() {
        let qname = Name::from_str("example.com.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(a_record(&qname, 1));
        assert!(message_has_payload(&msg));
    }

    /// Negative answers (NXDOMAIN / NODATA) arrive with zero answer RRs but
    /// a SOA in the authority section. That SOA is the payload, and stripping
    /// it would break negative caching downstream.
    #[test]
    fn message_has_payload_true_when_only_authority_present() {
        let zone = Name::from_str("example.").unwrap();
        let soa = SOA::new(
            Name::from_str("ns.example.").unwrap(),
            Name::from_str("hostmaster.example.").unwrap(),
            1,
            3600,
            600,
            86400,
            300,
        );
        let mut msg = Message::query();
        msg.add_authority(Record::from_rdata(zone, 300, RData::SOA(soa)));
        assert!(message_has_payload(&msg));
    }

    /// A response with zero answers and zero authorities is not a valid DNS
    /// payload, whatever its rcode. The pipeline must neither cache nor serve it.
    #[test]
    fn message_has_payload_false_when_answer_and_authority_empty() {
        let msg = Message::query();
        assert!(!message_has_payload(&msg));
    }

    #[test]
    fn lookup_has_payload_true_when_answer_present() {
        let qname = Name::from_str("example.com.").unwrap();
        let lookup = Lookup::new_with_deadline(
            DnsQuery::new()
                .set_name(qname.clone())
                .set_query_type(RecordType::A)
                .set_query_class(DNSClass::IN)
                .clone(),
            vec![a_record(&qname, 1)],
            Instant::now() + Duration::from_secs(60),
        );
        assert!(lookup_has_payload(&lookup));
    }

    /// Authority-only upstream response (the shape every legitimate
    /// NXDOMAIN/NODATA carries on the wire) must still count as payload.
    #[test]
    fn lookup_has_payload_true_when_only_authority_present() {
        let qname = Name::from_str("missing.example.").unwrap();
        let zone = Name::from_str("example.").unwrap();
        let soa = SOA::new(
            Name::from_str("ns.example.").unwrap(),
            Name::from_str("hostmaster.example.").unwrap(),
            1,
            3600,
            600,
            86400,
            300,
        );
        let mut lookup = Lookup::new_with_deadline(
            DnsQuery::new()
                .set_name(qname.clone())
                .set_query_type(RecordType::A)
                .set_query_class(DNSClass::IN)
                .clone(),
            vec![],
            Instant::now() + Duration::from_secs(60),
        );
        lookup.extend_authorities(std::iter::once(Record::from_rdata(
            zone,
            300,
            RData::SOA(soa),
        )));
        assert!(lookup_has_payload(&lookup));
    }

    /// The intermittent empty `dig . NS`: hickory surfaced `Ok(Lookup)` with
    /// zero answers and zero authorities (provider misbehavior or an H2 edge
    /// case). The predicate reports no payload so the hedge rejects it instead
    /// of caching a 17-byte header.
    #[test]
    fn lookup_has_payload_false_when_answer_and_authority_empty() {
        let qname = Name::from_str(".").unwrap();
        let lookup = Lookup::new_with_deadline(
            DnsQuery::new()
                .set_name(qname)
                .set_query_type(RecordType::NS)
                .set_query_class(DNSClass::IN)
                .clone(),
            vec![],
            Instant::now() + Duration::from_secs(60),
        );
        assert!(!lookup_has_payload(&lookup));
    }

    #[test]
    fn finalize_wire_does_not_truncate_when_under_cap() {
        use hickory_proto::serialize::binary::BinDecodable;
        let qname = Name::from_str("example.com.").unwrap();
        let mut msg = Message::query();
        msg.metadata.id = 0xDEAD;
        msg.add_answer(Record::from_rdata(
            qname,
            60,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let bytes = super::finalize_wire(
            msg,
            super::Transport::Udp {
                client_payload_size: 4096,
            },
            None,
        );
        let parsed = Message::from_bytes(&bytes).unwrap();
        assert!(!parsed.metadata.truncation, "must not set TC under cap");
        assert_eq!(parsed.answers.len(), 1);
    }

    #[test]
    fn finalize_wire_sets_tc_and_drops_answers_when_over_cap() {
        use hickory_proto::serialize::binary::BinDecodable;
        let qname = Name::from_str("example.com.").unwrap();
        let mut msg = Message::query();
        for _ in 0..10 {
            msg.add_answer(Record::from_rdata(
                qname.clone(),
                60,
                RData::TXT(hickory_proto::rr::rdata::TXT::new(vec!["x".repeat(200)])),
            ));
        }
        let bytes = super::finalize_wire(
            msg,
            super::Transport::Udp {
                client_payload_size: 512,
            },
            None,
        );
        assert!(bytes.len() <= 512, "wire must fit cap");
        let parsed = Message::from_bytes(&bytes).unwrap();
        assert!(parsed.metadata.truncation, "TC must be set when truncated");
    }

    /// RFC 2181 §9: additional data is optional, so it goes first, and a
    /// response that fits once it is gone is complete, not truncated. Popping
    /// answers first would lose a small required answer to large optional glue
    /// and force the client to retry over TCP.
    #[test]
    fn finalize_wire_drops_optional_additionals_before_answers() {
        use hickory_proto::serialize::binary::BinDecodable;
        let qname = Name::from_str("example.com.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(Record::from_rdata(
            qname.clone(),
            60,
            RData::MX(hickory_proto::rr::rdata::MX::new(
                10,
                Name::from_str("mail.example.com.").unwrap(),
            )),
        ));
        for i in 0..40 {
            msg.add_additional(Record::from_rdata(
                Name::from_str("mail.example.com.").unwrap(),
                60,
                RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, i))),
            ));
        }
        let bytes = super::finalize_wire(
            msg,
            super::Transport::Udp {
                client_payload_size: 512,
            },
            None,
        );
        let parsed = Message::from_bytes(&bytes).unwrap();

        assert!(bytes.len() <= 512);
        assert_eq!(parsed.answers.len(), 1, "the required answer must survive");
        assert!(parsed.additionals.is_empty());
        assert!(
            !parsed.metadata.truncation,
            "omitting optional additional data does not truncate the answer"
        );
    }

    #[test]
    fn finalize_wire_tcp_path_does_not_truncate() {
        use hickory_proto::serialize::binary::BinDecodable;
        let qname = Name::from_str("example.com.").unwrap();
        let mut msg = Message::query();
        for _ in 0..10 {
            msg.add_answer(Record::from_rdata(
                qname.clone(),
                60,
                RData::TXT(hickory_proto::rr::rdata::TXT::new(vec!["x".repeat(200)])),
            ));
        }
        let bytes = super::finalize_wire(msg, super::Transport::Tcp, None);
        let parsed = Message::from_bytes(&bytes).unwrap();
        assert!(!parsed.metadata.truncation);
        assert_eq!(parsed.answers.len(), 10, "TCP keeps full answer set");
    }

    /// RFC 2181 §5.2: a server must not send an RRset whose members
    /// carry different TTLs. Upstreams routinely do, and a downstream cache
    /// that keeps only the longest-lived member serves a partial RRset once
    /// the shortest expires. Both transports share `finalize_wire`, so both
    /// are asserted here rather than trusting one to cover the other.
    #[test]
    fn finalize_wire_normalizes_unequal_rrset_ttls_on_both_transports() {
        use hickory_proto::serialize::binary::BinDecodable;
        let qname = Name::from_str("example.com.").unwrap();
        let sibling = Name::from_str("other.example.com.").unwrap();

        for transport in [
            super::Transport::Tcp,
            super::Transport::Udp {
                client_payload_size: 4096,
            },
        ] {
            let mut msg = Message::query();
            msg.add_answer(Record::from_rdata(
                qname.clone(),
                300,
                RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
            ));
            msg.add_answer(Record::from_rdata(
                qname.clone(),
                60,
                RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 2))),
            ));
            msg.add_answer(Record::from_rdata(
                qname.clone(),
                900,
                RData::AAAA(AAAA(std::net::Ipv6Addr::LOCALHOST)),
            ));
            msg.add_answer(Record::from_rdata(
                sibling.clone(),
                1200,
                RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 3))),
            ));

            let bytes = super::finalize_wire(msg, transport, None);
            let parsed = Message::from_bytes(&bytes).unwrap();

            let a_ttls: Vec<u32> = parsed
                .answers
                .iter()
                .filter(|r| r.name == qname && r.record_type() == RecordType::A)
                .map(|r| r.ttl)
                .collect();
            assert_eq!(
                a_ttls,
                vec![60, 60],
                "every member of one RRset leaves with the RRset minimum",
            );
            let other_ttls: Vec<u32> = parsed
                .answers
                .iter()
                .filter(|r| r.name != qname || r.record_type() != RecordType::A)
                .map(|r| r.ttl)
                .collect();
            assert_eq!(
                other_ttls,
                vec![900, 1200],
                "a different owner or type is a different RRset and keeps its own TTL",
            );
        }
    }

    /// The cache stores what `message_from_upstream_message` produced and ages
    /// every record by the same elapsed time on a hit, so an RRset that enters
    /// the cache split stays split for the whole entry lifetime.
    #[test]
    fn message_from_upstream_normalizes_rrset_ttls_before_caching() {
        let qname = Name::from_str("example.com.").unwrap();
        let mut upstream = Message::query();
        upstream.add_answer(Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ));
        upstream.add_answer(Record::from_rdata(
            qname.clone(),
            45,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 2))),
        ));

        let out = message_from_upstream_message(0xBEEF, &qname, RecordType::A, &upstream);

        assert!(
            out.answers.iter().all(|r| r.ttl == 45),
            "the cached copy must already satisfy RFC 2181 §5.2",
        );
        assert_eq!(positive_cache_ttl(&out), 45);
    }

    #[test]
    fn finalize_wire_answers_an_edns_client_with_opt_and_do() {
        use hickory_proto::serialize::binary::BinDecodable;
        let qname = Name::from_str("example.com.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(Record::from_rdata(
            qname,
            60,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let mut client_opt = hickory_proto::op::Edns::new();
        client_opt.set_max_payload(1232);
        client_opt.set_dnssec_ok(true);
        let bytes = super::finalize_wire(
            msg,
            super::Transport::Udp {
                client_payload_size: 1232,
            },
            Some(&client_opt),
        );
        let parsed = Message::from_bytes(&bytes).unwrap();
        let opt = parsed.edns.expect("response must echo OPT");
        assert_eq!(opt.max_payload(), crate::listener::UDP_PAYLOAD_SIZE);
        assert!(opt.flags().dnssec_ok);
    }

    /// RFC 6891 §6.2.3: the OPT in a response carries the responder's own
    /// receive capacity, not the requester's. Echoing the client's value would
    /// claim this listener can read 8 KiB messages over UDP.
    #[test]
    fn response_opt_advertises_the_listener_capacity() {
        use hickory_proto::serialize::binary::BinDecodable;

        for client_payload in [512u16, 1232, 8192] {
            let mut client_opt = hickory_proto::op::Edns::new();
            client_opt.set_max_payload(client_payload);
            let bytes = super::finalize_wire(
                Message::query(),
                super::Transport::Udp {
                    client_payload_size: client_payload.clamp(512, 4096),
                },
                Some(&client_opt),
            );
            let opt = Message::from_bytes(&bytes).unwrap().edns.unwrap();
            assert_eq!(
                opt.max_payload(),
                crate::listener::UDP_PAYLOAD_SIZE,
                "client advertised {client_payload}"
            );
        }
    }

    #[test]
    fn cname_reentry_query_preserves_request_flags_class_and_edns() {
        use hickory_proto::serialize::binary::BinDecodable;

        let mut request = Message::query();
        request.metadata.recursion_desired = false;
        request.metadata.checking_disabled = true;
        let mut opt = hickory_proto::op::Edns::new();
        opt.set_max_payload(1232);
        opt.set_dnssec_ok(true);
        request.edns = Some(opt);
        let mut original_query = DnsQuery::new();
        original_query
            .set_name(Name::from_str("alias.example.").unwrap())
            .set_query_type(RecordType::TXT)
            .set_query_class(DNSClass::CH);
        request.add_query(original_query);

        let wire = super::build_query_wire(
            &Name::from_str("target.example.").unwrap(),
            RecordType::A,
            &request,
        );
        let parsed = Message::from_bytes(&wire).unwrap();

        assert!(!parsed.metadata.recursion_desired);
        assert!(parsed.metadata.checking_disabled);
        assert_eq!(parsed.queries[0].query_class(), DNSClass::CH);
        let opt = parsed.edns.expect("sub-query must preserve OPT");
        assert_eq!(opt.max_payload(), 1232);
        assert!(opt.flags().dnssec_ok);
    }

    /// The sibling test below passes `client_edns = None`, a client with no
    /// EDNS at all. This covers the ordinary case: EDNS present with DO clear,
    /// which most clients send. A gate on `client_edns.is_some()` would pass
    /// every other test in this file while shipping authentication records to
    /// every EDNS client that never asked for them.
    ///
    /// Both toggle positions run because only the client's bit decides. A
    /// regression that brought the toggle back would make the two rows
    /// disagree.
    #[test]
    fn finalize_wire_strips_dnssec_records_for_an_edns_client_without_do() {
        use hickory_proto::serialize::binary::BinDecodable;

        for dnssec in [true, false] {
            let _guard = crate::config::ConfigGuard::new(crate::config::ResolverOptions {
                dnssec,
                ..Default::default()
            });

            let qname = Name::from_str("example.com.").unwrap();
            let mut msg = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
            let mut q = DnsQuery::new();
            q.set_name(qname.clone())
                .set_query_type(RecordType::A)
                .set_query_class(DNSClass::IN);
            msg.add_query(q);
            msg.add_answer(Record::from_rdata(
                qname.clone(),
                60,
                RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
            ));
            msg.add_answer(Record::from_rdata(
                qname,
                60,
                RData::DNSSEC(DNSSECRData::DS(DS::new(
                    1,
                    Algorithm::RSASHA256,
                    DigestType::SHA256,
                    vec![0; 32],
                ))),
            ));

            // EDNS advertised, DO clear (`Edns::new()` defaults dnssec_ok to false).
            let client_opt = hickory_proto::op::Edns::new();

            let bytes = super::finalize_wire(
                msg,
                super::Transport::Udp {
                    client_payload_size: 4096,
                },
                Some(&client_opt),
            );
            let parsed = Message::from_bytes(&bytes).unwrap();

            assert_eq!(
                parsed.answers.len(),
                1,
                "dnssec={dnssec}: an EDNS client with DO clear must not receive \
                 accompanying authentication records"
            );
            assert_eq!(parsed.answers[0].record_type(), RecordType::A);
            assert!(
                !parsed
                    .edns
                    .expect("response echoes the client's OPT")
                    .flags()
                    .dnssec_ok,
                "dnssec={dnssec}: the response DO bit must echo the client's"
            );
        }
    }

    #[test]
    fn finalize_wire_strips_dnssec_records_without_client_do() {
        use hickory_proto::serialize::binary::BinDecodable;
        let qname = Name::from_str("example.com.").unwrap();
        let mut msg = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
        let mut q = DnsQuery::new();
        q.set_name(qname.clone())
            .set_query_type(RecordType::A)
            .set_query_class(DNSClass::IN);
        msg.add_query(q);
        msg.add_answer(Record::from_rdata(
            qname.clone(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        ));
        msg.add_answer(Record::from_rdata(
            qname,
            60,
            RData::DNSSEC(DNSSECRData::DS(DS::new(
                1,
                Algorithm::RSASHA256,
                DigestType::SHA256,
                vec![0; 32],
            ))),
        ));

        let bytes = super::finalize_wire(
            msg,
            super::Transport::Udp {
                client_payload_size: 4096,
            },
            None,
        );
        let parsed = Message::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].record_type(), RecordType::A);
    }

    #[test]
    fn finalize_wire_keeps_dnssec_records_with_client_do() {
        use hickory_proto::serialize::binary::BinDecodable;
        let qname = Name::from_str("example.com.").unwrap();
        let mut msg = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
        let mut q = DnsQuery::new();
        q.set_name(qname.clone())
            .set_query_type(RecordType::A)
            .set_query_class(DNSClass::IN);
        msg.add_query(q);
        msg.add_answer(Record::from_rdata(
            qname.clone(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        ));
        msg.add_answer(Record::from_rdata(
            qname,
            60,
            RData::DNSSEC(DNSSECRData::DS(DS::new(
                1,
                Algorithm::RSASHA256,
                DigestType::SHA256,
                vec![0; 32],
            ))),
        ));
        let mut client_opt = hickory_proto::op::Edns::new();
        client_opt.set_dnssec_ok(true);

        let bytes = super::finalize_wire(
            msg,
            super::Transport::Udp {
                client_payload_size: 4096,
            },
            Some(&client_opt),
        );
        let parsed = Message::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.answers.len(), 2);
        assert!(parsed
            .answers
            .iter()
            .any(|rec| rec.record_type() == RecordType::DS));
    }

    /// The toggle governs whether the provider validates, not whether this
    /// client gets the records it asked for. RFC 4035 3.2.1 ties the strip to
    /// the initiating query's DO bit and to nothing else. Otherwise a client
    /// sending `+dnssec` with the toggle off gets a signed zone stripped of its
    /// signatures and can only conclude "unsigned", a downgrade it cannot
    /// detect.
    #[test]
    fn finalize_wire_keeps_dnssec_records_with_client_do_and_the_toggle_off() {
        use hickory_proto::serialize::binary::BinDecodable;
        let _guard = crate::config::ConfigGuard::new(crate::config::ResolverOptions {
            dnssec: false,
            ..Default::default()
        });

        let qname = Name::from_str("example.com.").unwrap();
        let mut msg = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
        let mut q = DnsQuery::new();
        q.set_name(qname.clone())
            .set_query_type(RecordType::A)
            .set_query_class(DNSClass::IN);
        msg.add_query(q);
        msg.add_answer(Record::from_rdata(
            qname.clone(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        ));
        msg.add_answer(Record::from_rdata(
            qname,
            60,
            RData::DNSSEC(DNSSECRData::DS(DS::new(
                1,
                Algorithm::RSASHA256,
                DigestType::SHA256,
                vec![0; 32],
            ))),
        ));

        let mut client_opt = hickory_proto::op::Edns::new();
        client_opt.set_dnssec_ok(true);

        let bytes = super::finalize_wire(
            msg,
            super::Transport::Udp {
                client_payload_size: 4096,
            },
            Some(&client_opt),
        );
        let parsed = Message::from_bytes(&bytes).unwrap();

        assert_eq!(
            parsed.answers.len(),
            2,
            "a client that asked for DNSSEC records must get them even with the \
             toggle off - the toggle decides validation, not visibility"
        );
        assert!(
            parsed.edns.expect("response carries OPT").flags().dnssec_ok,
            "the response DO bit must echo the client's, not the toggle"
        );
    }

    #[test]
    fn negative_terminal_name_is_the_end_of_the_chain() {
        let original = Name::from_str("a.slack-edge.com.").unwrap();
        let target = Name::from_str("first.cdn.example.net.").unwrap();
        let err = no_records_err(
            &target,
            RecordType::AAAA,
            ResponseCode::NoError,
            Some((Name::from_str("cdn.example.net.").unwrap(), 60, 60)),
            Some(60),
        );

        assert_eq!(negative_terminal_name(&err), Some(&target));
        assert_ne!(negative_terminal_name(&err), Some(&original));
    }

    /// Hickory drops the intermediate CNAMEs on its error path, so the real
    /// `a -> b -> c` chain is not available here. Fabricating `a CNAME c` would
    /// publish an RR no authority served, with a TTL taken from the negative
    /// answer. The terminal negative is returned as is.
    #[tokio::test]
    async fn multi_hop_cname_nodata_does_not_invent_a_direct_alias() {
        let alias = Name::from_str("configuration.apple.com.").unwrap();
        let terminal = Name::from_str("configuration.v.aaplimg.com.").unwrap();
        let err = no_records_err(
            &terminal,
            RecordType::HTTPS,
            ResponseCode::NoError,
            Some((Name::from_str("v.aaplimg.com.").unwrap(), 300, 300)),
            Some(60),
        );

        let (msg, _provider) = negative_hedge_outcome(&alias, RecordType::HTTPS, err).await;

        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert!(
            msg.answers.is_empty(),
            "a CNAME the upstream never published must not be synthesized",
        );
        assert!(
            msg.authorities
                .iter()
                .any(|r| matches!(&r.data, RData::SOA(_))),
            "the terminal NODATA proof must still reach the client",
        );
    }

    /// Hickory reports CNAME depth exhaustion as `NoRecordsFound` with
    /// NOERROR, a terminal name that is not the QNAME, and no SOA. Caching it
    /// would produce an entry `response_is_negative` reads as positive, which
    /// serve-stale then replays for up to `SERVE_EXPIRED_TTL_SECS`.
    #[tokio::test]
    async fn cname_loop_is_servfail_and_never_reaches_the_cache() {
        let qname = Name::from_str("loop-a.example.").unwrap();
        let terminal = Name::from_str("loop-b.example.").unwrap();
        let err = no_records_err(&terminal, RecordType::A, ResponseCode::NoError, None, None);
        let state = Arc::new(route_test_state());

        let (msg, _provider) =
            negative_hedge_outcome_with_state(&state, &qname, RecordType::A, err).await;

        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
        assert!(
            state
                .cache
                .get_allow_expired(&CacheKey::from("loop-a.example", RecordType::A))
                .await
                .is_none(),
            "an unresolvable chain must leave nothing behind to serve stale",
        );
    }

    /// The deliberate carve-out around the rule above. Hickory's depth
    /// exhaustion builds a bare `NoRecords` with no authority section at all,
    /// so a chained NODATA that did carry one is a real answer from a lame
    /// authority, not a loop, and must not become SERVFAIL.
    #[tokio::test]
    async fn chained_nodata_with_an_authority_section_is_still_answered() {
        let alias = Name::from_str("alias.example.").unwrap();
        let terminal = Name::from_str("target.example.").unwrap();
        let mut err = no_records_err(&terminal, RecordType::A, ResponseCode::NoError, None, None);
        let NetError::Dns(DnsError::NoRecordsFound(no_records)) = &mut err else {
            panic!("helper must build a NoRecordsFound error");
        };
        no_records.authorities = Some(Arc::from(vec![Record::from_rdata(
            Name::from_str("example.").unwrap(),
            300,
            RData::NS(hickory_proto::rr::rdata::NS(
                Name::from_str("ns.example.").unwrap(),
            )),
        )]));

        let (msg, _provider) = negative_hedge_outcome(&alias, RecordType::A, err).await;

        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    }

    /// Pairs with the depth-exhaustion test: a direct negative without an SOA
    /// is a real answer for the client but has no bound on how long it may be
    /// reused, so it is forwarded once and never stored.
    ///
    /// The same shape is what Hickory reports for a CNAME that points at its own
    /// owner (`a CNAME a`), so that loop also answers NOERROR. Turning it into
    /// SERVFAIL would fail every lame NODATA with it.
    #[tokio::test]
    async fn negative_without_soa_is_answered_but_never_cached() {
        let qname = Name::from_str("lame.example.").unwrap();
        let err = no_records_err(&qname, RecordType::HTTPS, ResponseCode::NoError, None, None);
        let state = Arc::new(route_test_state());

        let (msg, _provider) =
            negative_hedge_outcome_with_state(&state, &qname, RecordType::HTTPS, err).await;

        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::NoError,
            "a lame NODATA is still the answer the client asked for",
        );
        assert!(
            state
                .cache
                .get_allow_expired(&CacheKey::from("lame.example", RecordType::HTTPS))
                .await
                .is_none(),
            "a negative answer with no SOA has no TTL bound and must not be cached",
        );
    }

    /// RFC 2308 §5: a negative TTL of 0 means no reuse at all, so it must not
    /// be floored to one second and cached.
    #[tokio::test]
    async fn zero_negative_ttl_answer_is_never_cached() {
        let qname = Name::from_str("dynamic.example.").unwrap();
        let err = no_records_err(
            &qname,
            RecordType::A,
            ResponseCode::NXDomain,
            Some((Name::from_str("example.").unwrap(), 0, 0)),
            Some(0),
        );
        let state = Arc::new(route_test_state());

        let (msg, _provider) =
            negative_hedge_outcome_with_state(&state, &qname, RecordType::A, err).await;

        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(
            msg.authorities[0].ttl, 0,
            "the wire SOA keeps the zero TTL the authority published",
        );
        assert!(
            state
                .cache
                .get_allow_expired(&CacheKey::from("dynamic.example", RecordType::A))
                .await
                .is_none(),
            "a zero-TTL negative answer must not be reusable",
        );
        assert!(
            !state
                .cache
                .nxdomain_apex_covers("sub.dynamic.example.")
                .await,
            "a zero-TTL NXDOMAIN must not install an RFC 8020 cut either",
        );
    }

    /// Hickory reports the failure against the terminal name of the chain.
    /// Cutting at the QNAME would deny every descendant of an alias that
    /// resolves fine, without ever asking upstream.
    #[tokio::test]
    async fn nxdomain_after_cname_cuts_only_the_terminal_name() {
        let alias = Name::from_str("www.example.").unwrap();
        let terminal = Name::from_str("gone.cdn.invalid.").unwrap();
        let err = no_records_err(
            &terminal,
            RecordType::A,
            ResponseCode::NXDomain,
            Some((Name::from_str("cdn.invalid.").unwrap(), 300, 300)),
            Some(300),
        );
        let state = Arc::new(route_test_state());

        let (msg, _provider) =
            negative_hedge_outcome_with_state(&state, &alias, RecordType::A, err).await;
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);

        assert!(
            !state.cache.nxdomain_apex_covers("api.www.example.").await,
            "the alias exists - only its terminal target is nonexistent",
        );
        assert!(
            state
                .cache
                .nxdomain_apex_covers("x.gone.cdn.invalid.")
                .await,
            "the cut belongs at the name that does not exist",
        );
    }

    /// The synthesized descendant answer carries the upstream authority, not a
    /// fabricated `localhost.` / `nobody.invalid.` SOA without denial proof,
    /// which no DO=1 client could verify and which misstates the negative-cache
    /// bound.
    #[tokio::test]
    async fn below_nxdomain_replays_the_upstream_denial_proof() {
        let zone = Name::from_str("cdn.invalid.").unwrap();
        let terminal = Name::from_str("gone.cdn.invalid.").unwrap();
        let nsec = Record::from_rdata(
            terminal.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                Name::from_str("next.cdn.invalid.").unwrap(),
                [RecordType::A, RecordType::RRSIG],
            ))),
        );
        let rrsig = Record::update0(terminal.clone(), 300, RecordType::RRSIG);
        let mut err = no_records_err(
            &terminal,
            RecordType::A,
            ResponseCode::NXDomain,
            Some((zone.clone(), 300, 300)),
            Some(300),
        );
        let NetError::Dns(DnsError::NoRecordsFound(no_records)) = &mut err else {
            panic!("helper must build a NoRecordsFound error");
        };
        no_records.authorities = Some(Arc::from(vec![nsec, rrsig]));
        let state = Arc::new(route_test_state());

        negative_hedge_outcome_with_state(&state, &terminal, RecordType::A, err).await;

        let descendant = Name::from_str("x.gone.cdn.invalid.").unwrap();
        let synthesized = resolve_below_nxdomain_or_none(&state.cache, &descendant, RecordType::A)
            .await
            .expect("the cut must cover the descendant");

        assert_eq!(synthesized.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(
            synthesized.queries[0].name(),
            &descendant,
            "only the Question is rewritten",
        );
        let soa = synthesized
            .authorities
            .iter()
            .find(|r| matches!(&r.data, RData::SOA(_)))
            .expect("the upstream SOA must be replayed");
        assert_eq!(
            soa.name, zone,
            "the SOA owner is the authority's zone, never a fabricated localhost.",
        );
        assert!(
            synthesized
                .authorities
                .iter()
                .any(|r| matches!(&r.data, RData::DNSSEC(DNSSECRData::NSEC(_)))),
            "the NSEC proving the denial must survive into the synthesized answer",
        );
        assert!(
            synthesized
                .authorities
                .iter()
                .any(|r| r.record_type() == RecordType::RRSIG),
            "an unsigned denial proof is not a proof",
        );
        assert!(
            synthesized
                .authorities
                .iter()
                .all(|r| r.ttl <= synthetic_negative_ttl_secs()),
            "replayed TTLs must be aged down to what is left of the cut",
        );
    }

    #[test]
    fn forward_failure_detail_names_the_route_that_failed() {
        assert_eq!(
            crate::query::forward_failure_detail("captive-forward", "request timed out"),
            "route=captive-forward: request timed out"
        );
        assert_eq!(
            crate::query::forward_failure_detail("forward-zone", "connection refused"),
            "route=forward-zone: connection refused"
        );
    }

    #[test]
    fn forward_lookup_timeout_is_bounded_below_hickory_retry_budget() {
        assert_eq!(super::FORWARD_LOOKUP_TIMEOUT, Duration::from_secs(3));
    }

    #[test]
    fn null_blocking_answers_addresses_and_nodata_on_the_wire() {
        use crate::lmdb::{BlockAction, BlocklistDb, BlocklistEntry, DomainName, MultiCategoryDb};
        use hickory_proto::serialize::binary::BinDecodable;

        let _guard = crate::blocklist::test_lock();
        let action: BlockAction = serde_json::from_str("\"null\"").unwrap();
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("blocked.db");
        let db = Arc::new(BlocklistDb::open_for_write(&path).unwrap());
        let domain = "blocked.null-mode.test";
        db.insert(&DomainName::new(domain).unwrap()).unwrap();
        crate::blocklist::install_snapshot_for_tests(MultiCategoryDb::from_databases(vec![(
            db,
            BlocklistEntry {
                name: "Null blocking".into(),
                tag: "test".into(),
                db_path: path,
                action,
            },
        )]));

        let name = Name::from_ascii(format!("{domain}.")).unwrap();
        for transport in [
            Transport::Tcp,
            Transport::Udp {
                client_payload_size: 512,
            },
        ] {
            for qtype in [
                RecordType::A,
                RecordType::AAAA,
                RecordType::HTTPS,
                RecordType::SVCB,
                RecordType::TXT,
                RecordType::MX,
            ] {
                let mut req = Message::query();
                req.add_query(DnsQuery::query(name.clone(), qtype));
                let (wire, provider) = super::resolve_blocklist_or_none(
                    domain, qtype, 0x1234, &name, &req, transport, None,
                )
                .expect("a blocked query must finish locally");
                let response = Message::from_bytes(&wire).unwrap();
                assert_eq!(provider.log_source.as_deref(), Some("blocklist"));
                assert_eq!(response.metadata.id, 0x1234);
                assert_eq!(response.metadata.response_code, ResponseCode::NoError);
                assert!(!response.metadata.authentic_data);
                assert_eq!(response.queries[0].query_type(), qtype);
                match qtype {
                    RecordType::A | RecordType::AAAA => {
                        assert_eq!(response.answers.len(), 1);
                        let answer = &response.answers[0];
                        assert_eq!(answer.name, name);
                        assert_eq!(answer.ttl, 0);
                        match &answer.data {
                            RData::A(ip) if qtype == RecordType::A => {
                                assert!(ip.0.is_unspecified())
                            }
                            RData::AAAA(ip) if qtype == RecordType::AAAA => {
                                assert!(ip.0.is_unspecified())
                            }
                            other => panic!("unexpected {qtype} answer: {other:?}"),
                        }
                        assert!(response.authorities.is_empty());
                    }
                    _ => {
                        assert!(response.answers.is_empty());
                        assert_eq!(response.authorities.len(), 1);
                        let soa = &response.authorities[0];
                        assert_eq!(soa.name, name);
                        assert_eq!(soa.ttl, synthetic_negative_ttl_secs());
                        assert!(matches!(&soa.data, RData::SOA(data)
                            if data.minimum == synthetic_negative_ttl_secs()));
                    }
                }
            }
        }
        for domain in ["safe.null-mode.test", "nas"] {
            let name = Name::from_ascii(format!("{domain}.")).unwrap();
            for qtype in [
                RecordType::A,
                RecordType::AAAA,
                RecordType::HTTPS,
                RecordType::SVCB,
            ] {
                let mut req = Message::query();
                req.add_query(DnsQuery::query(name.clone(), qtype));
                assert!(
                    super::resolve_blocklist_or_none(
                        domain,
                        qtype,
                        0x1234,
                        &name,
                        &req,
                        Transport::Tcp,
                        None,
                    )
                    .is_none(),
                    "unlisted {domain} {qtype} must follow normal resolution"
                );
            }
        }

        crate::blocklist::install_snapshot_for_tests(MultiCategoryDb::new());
    }

    /// One unusable blocklist category must not take DNS down: the healthy
    /// categories keep filtering and every other name resolves normally.
    /// Filtering is a policy layer, not a security boundary. Unlike the
    /// licensing and proxy-control planes it fails open.
    #[test]
    fn corrupt_category_does_not_servfail_healthy_queries() {
        use crate::lmdb::{BlockAction, BlocklistDb, BlocklistEntry, DomainName, MultiCategoryDb};
        let _guard = crate::blocklist::test_lock();
        let temp = tempfile::TempDir::new().unwrap();
        let broken_dir = temp.path().join("broken.db");
        let healthy_dir = temp.path().join("healthy.db");

        let broken = Arc::new(BlocklistDb::open_for_write(&broken_dir).unwrap());
        let healthy = Arc::new(BlocklistDb::open_for_write(&healthy_dir).unwrap());
        healthy
            .insert(&DomainName::new("ads.example").unwrap())
            .unwrap();

        let entry = |tag: &str, path: &std::path::Path| BlocklistEntry {
            name: tag.into(),
            tag: tag.into(),
            db_path: path.to_path_buf(),
            action: BlockAction::Nxdomain,
        };
        // The broken category is listed first, so a fallible lookup aborts
        // the whole check before the healthy category is ever consulted.
        let held = broken.hold_reader().unwrap();
        crate::blocklist::install_snapshot_for_tests(MultiCategoryDb::from_databases(vec![
            (broken.clone(), entry("broken", &broken_dir)),
            (healthy.clone(), entry("healthy", &healthy_dir)),
        ]));

        let transport = Transport::Udp {
            client_payload_size: 4096,
        };
        let blocked_name = Name::from_str("ads.example.").unwrap();
        let mut req = Message::query();
        let mut q = DnsQuery::new();
        q.set_name(blocked_name.clone())
            .set_query_type(RecordType::A);
        req.add_query(q);

        let blocked = super::resolve_blocklist_or_none(
            "ads.example",
            RecordType::A,
            0x1234,
            &blocked_name,
            &req,
            transport,
            None,
        );
        assert_eq!(
            blocked
                .as_ref()
                .and_then(|(_, origin)| origin.log_source.as_deref()),
            Some("blocklist"),
            "a healthy category must keep filtering while another is quarantined"
        );

        let clean_name = Name::from_str("safe.example.").unwrap();
        let clean = super::resolve_blocklist_or_none(
            "safe.example",
            RecordType::A,
            0x1235,
            &clean_name,
            &req,
            transport,
            None,
        );
        assert!(
            clean.is_none(),
            "an unrelated name must resolve normally, not SERVFAIL"
        );

        drop(held);
        crate::blocklist::install_snapshot_for_tests(MultiCategoryDb::new());
    }

    /// A prefetch refill that loses only some of its answers to the
    /// rebinding filter must still be cached, and must carry the same EDE 17
    /// a live (non-prefetch) response would. Otherwise diagnostics depend on
    /// which path happened to populate the entry.
    #[test]
    fn prefetch_partial_filtering_keeps_public_data_and_adds_ede_17() {
        use hickory_resolver::proto::rr::rdata::opt::EdnsOption;
        let qname = Name::from_str("mixed.example.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(Record::from_rdata(
            qname.clone(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(93, 184, 216, 34))),
        ));
        msg.add_answer(Record::from_rdata(
            qname.clone(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(192, 168, 1, 1))),
        ));

        assert!(
            super::apply_background_rebinding_filter(&mut msg, &qname, RecordType::A, "prefetch"),
            "a partially filtered refill must stay cacheable"
        );
        assert_eq!(msg.answers.len(), 1, "public answer must be retained");
        let has_ede = msg
            .edns
            .as_ref()
            .expect("filtered prefetch answer must carry OPT")
            .options()
            .as_ref()
            .iter()
            .any(|(_, opt)| matches!(opt, EdnsOption::Unknown(15, payload) if payload.starts_with(&super::EDE_FILTERED.to_be_bytes())));
        assert!(has_ede, "filtered prefetch answer must carry EDE 17");
    }

    /// RFC 9460 address hints are connection targets a client dials before it
    /// ever queries TargetName, so the prefetch path has to strip them for the
    /// same reason it strips A/AAAA. Otherwise a refill re-caches a loopback
    /// hint the hedge path would have removed.
    #[test]
    fn prefetch_strips_private_https_hints() {
        let qname = Name::from_str("hints.example.com.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(https_record_with_ipv4_hints(
            &qname,
            &["127.0.0.1", "93.184.216.34"],
        ));

        assert!(
            super::apply_background_rebinding_filter(
                &mut msg,
                &qname,
                RecordType::HTTPS,
                "prefetch"
            ),
            "an HTTPS record with one surviving public hint stays cacheable"
        );
        assert_eq!(
            surviving_ipv4_hints(&msg),
            vec![A("93.184.216.34".parse().unwrap())],
            "the loopback hint must not survive a prefetch refill"
        );
    }

    #[test]
    fn prefetch_fully_filtered_answer_is_abandoned() {
        let qname = Name::from_str("private.example.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(Record::from_rdata(
            qname.clone(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(192, 168, 1, 1))),
        ));

        assert!(
            !super::apply_background_rebinding_filter(&mut msg, &qname, RecordType::A, "prefetch"),
            "a refill whose every useful answer was stripped must be dropped"
        );
    }

    /// A provider answering SERVFAIL is not a network error. EDE 23 would send
    /// an operator after connectivity and EDE 22 after the authority.
    #[test]
    fn ede_for_upstream_response_failure_is_not_a_network_error() {
        let ede = ede_for_reason("upstream-response-failure");
        assert_eq!(ede, EDE_OTHER);
        assert_ne!(ede, EDE_NETWORK_ERROR);
        assert_ne!(ede, EDE_NO_REACHABLE_AUTHORITY);
    }

    /// Pins the decision not to guess a DNSSEC verdict (EDE 6) from a bare
    /// SERVFAIL.
    #[test]
    fn ede_for_upstream_response_failure_does_not_claim_dnssec_bogus() {
        const EDE_DNSSEC_BOGUS: u16 = 6;
        assert_ne!(
            ede_for_reason("upstream-response-failure"),
            EDE_DNSSEC_BOGUS
        );
    }

    /// Gates the arm itself, not just the mapping table. Without this, the
    /// handler could hardcode EDE 23 and both tests above would still pass.
    #[test]
    fn ede_and_reason_for_an_upstream_refusal_name_the_rcode() {
        let (reason, ede, text) = servfail_for_upstream_response(ResponseCode::ServFail);
        assert_eq!(reason, "upstream-response-failure");
        assert_eq!(ede, EDE_OTHER);
        assert_eq!(text, "upstream returned Server Failure");
    }

    #[test]
    fn finalize_wire_merges_client_opt_into_existing_ede() {
        use hickory_proto::serialize::binary::BinDecodable;
        use hickory_resolver::proto::rr::rdata::opt::EdnsOption;
        let qname = Name::from_str("filtered.example.").unwrap();
        let mut msg = Message::query();
        msg.metadata.id = 0xBEEF;
        msg.add_answer(Record::from_rdata(
            qname,
            60,
            RData::A(A(std::net::Ipv4Addr::new(10, 0, 0, 1))),
        ));
        // Pre-populate msg.edns with an EDE option, mirroring the rebinding /
        // SERVFAIL builders that call attach_ede before finalize_wire runs.
        super::attach_ede(&mut msg, super::EDE_FILTERED, "test-ede");

        let mut client_opt = hickory_proto::op::Edns::new();
        client_opt.set_max_payload(1232);
        client_opt.set_dnssec_ok(true);

        let bytes = super::finalize_wire(
            msg,
            super::Transport::Udp {
                client_payload_size: 1232,
            },
            Some(&client_opt),
        );
        let parsed = Message::from_bytes(&bytes).unwrap();
        let opt = parsed.edns.expect("response must carry OPT");
        assert_eq!(
            opt.max_payload(),
            crate::listener::UDP_PAYLOAD_SIZE,
            "the EDE-bearing OPT must advertise the resolver's own payload size"
        );
        assert!(
            opt.flags().dnssec_ok,
            "client DO bit must be echoed onto the EDE-bearing OPT"
        );
        // The EDE option (code 15) survives the merge. set_max_payload and
        // set_dnssec_ok must not clobber the options collection.
        let has_ede = opt
            .options()
            .as_ref()
            .iter()
            .any(|(_, opt)| matches!(opt, EdnsOption::Unknown(15, _)));
        assert!(has_ede, "EDE option must survive client-OPT echo");
    }

    #[test]
    fn non_query_opcode_yields_notimp() {
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        let mut req = Message::new(0x42, MessageType::Query, OpCode::Update);
        let mut q = DnsQuery::new();
        q.set_name(Name::from_str("example.com.").unwrap())
            .set_query_type(RecordType::A)
            .set_query_class(DNSClass::IN);
        req.add_query(q);
        let wire = req.to_bytes().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resp = rt.block_on(super::handle_wire(
            &wire,
            cancel,
            super::Transport::Udp {
                client_payload_size: 4096,
            },
        ));
        let parsed = Message::from_bytes(&resp).unwrap();
        assert_eq!(parsed.metadata.response_code, ResponseCode::NotImp);
    }

    #[test]
    fn chaos_class_yields_refused() {
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        let mut req = Message::query();
        let mut q = DnsQuery::new();
        q.set_name(Name::from_str("version.bind.").unwrap())
            .set_query_type(RecordType::TXT)
            .set_query_class(DNSClass::CH);
        req.add_query(q);
        let wire = req.to_bytes().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resp = rt.block_on(super::handle_wire(
            &wire,
            cancel,
            super::Transport::Udp {
                client_payload_size: 4096,
            },
        ));
        let parsed = Message::from_bytes(&resp).unwrap();
        assert_eq!(parsed.metadata.response_code, ResponseCode::Refused);
    }

    #[test]
    fn cd_bit_is_echoed_on_local_responses() {
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        // CH-class queries short-circuit to REFUSED without going upstream,
        // and the CD bit must echo on locally synthesised answers.
        let mut req = Message::query();
        req.metadata.checking_disabled = true;
        let mut q = DnsQuery::new();
        q.set_name(Name::from_str("version.bind.").unwrap())
            .set_query_type(RecordType::TXT)
            .set_query_class(DNSClass::CH);
        req.add_query(q);
        let wire = req.to_bytes().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resp = rt.block_on(super::handle_wire(
            &wire,
            cancel,
            super::Transport::Udp {
                client_payload_size: 4096,
            },
        ));
        let parsed = Message::from_bytes(&resp).unwrap();
        assert!(parsed.metadata.checking_disabled);
    }

    #[test]
    fn rd_bit_is_echoed() {
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        // Client sends RD=0, and the local REFUSED must echo it.
        let mut req = Message::query();
        req.metadata.recursion_desired = false;
        let mut q = DnsQuery::new();
        q.set_name(Name::from_str("version.bind.").unwrap())
            .set_query_type(RecordType::TXT)
            .set_query_class(DNSClass::CH);
        req.add_query(q);
        let wire = req.to_bytes().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resp = rt.block_on(super::handle_wire(
            &wire,
            cancel,
            super::Transport::Udp {
                client_payload_size: 4096,
            },
        ));
        let parsed = Message::from_bytes(&resp).unwrap();
        assert!(!parsed.metadata.recursion_desired);
    }

    #[test]
    fn multi_question_yields_formerr() {
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        let mut req = Message::query();
        let mut q1 = DnsQuery::new();
        q1.set_name(Name::from_str("a.example.").unwrap())
            .set_query_type(RecordType::A);
        let mut q2 = DnsQuery::new();
        q2.set_name(Name::from_str("b.example.").unwrap())
            .set_query_type(RecordType::AAAA);
        req.add_query(q1);
        req.add_query(q2);
        let wire = req.to_bytes().unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resp = rt.block_on(super::handle_wire(
            &wire,
            cancel,
            super::Transport::Udp {
                client_payload_size: 4096,
            },
        ));
        let parsed = Message::from_bytes(&resp).unwrap();
        assert_eq!(parsed.metadata.response_code, ResponseCode::FormErr);
    }

    /// One question plus two OPT records. Built by hand because hickory's
    /// encoder emits at most one OPT, so there is no way to round-trip the
    /// shape RFC 6891 §6.1.1 is about.
    fn duplicate_opt_query_wire(tx_id: u16) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(&tx_id.to_be_bytes());
        wire.extend_from_slice(&[0x01, 0x00]); // QR=0, OpCode=QUERY, RD=1
        wire.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        wire.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        wire.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        wire.extend_from_slice(&2u16.to_be_bytes()); // ARCOUNT
        wire.extend_from_slice(b"\x07example\x03com\x00");
        wire.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        wire.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        for _ in 0..2 {
            wire.push(0x00); // root owner name
            wire.extend_from_slice(&41u16.to_be_bytes()); // TYPE OPT
            wire.extend_from_slice(&4096u16.to_be_bytes()); // requestor payload size
            wire.extend_from_slice(&0u32.to_be_bytes()); // extended rcode + flags
            wire.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
        }
        wire
    }

    #[tokio::test]
    async fn duplicate_opt_query_yields_formerr_on_both_transports() {
        use hickory_proto::serialize::binary::BinDecodable;
        let wire = duplicate_opt_query_wire(0xABCD);
        assert!(
            Message::from_bytes(&wire).is_err(),
            "test setup requires a query hickory rejects at parse time"
        );

        for transport in [
            Transport::Udp {
                client_payload_size: 4096,
            },
            Transport::Tcp,
        ] {
            let (resp, reason) =
                super::handle_wire_inner(&wire, CancellationToken::new(), 0, transport, None).await;

            assert!(
                !resp.is_empty(),
                "a duplicate-OPT query must be answered, not dropped ({transport:?})"
            );
            let parsed = Message::from_bytes(&resp).unwrap();
            assert_eq!(parsed.metadata.id, 0xABCD);
            assert_eq!(parsed.metadata.response_code, ResponseCode::FormErr);
            assert_eq!(reason.log_source.as_deref(), Some("duplicate-opt"));
            assert_eq!(reason.route, Route::Invalid);
        }
    }

    /// Injected dispatcher result. A distinct address and provider tag per
    /// dispatch makes a waiter that silently resolved on its own visible in the
    /// answer itself, not just in the dispatch counter.
    fn injected_resolution(serial: u32) -> SharedResolution {
        let mut message = Message::query();
        message.add_answer(Record::from_rdata(
            Name::from_str("injected.example.").unwrap(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(
                10,
                0,
                (serial >> 8) as u8,
                serial as u8,
            ))),
        ));
        SharedResolution {
            message,
            origin: ReplyOrigin::upstream(Route::Provider, format!("provider-{}", serial)),
        }
    }

    /// The registry key the single-flight tests dispatch under.
    fn inflight(key: &CacheKey) -> InflightKey {
        InflightKey {
            key: key.clone(),
            dnssec: true,
        }
    }

    fn inflight_subscribers(key: &CacheKey) -> Option<usize> {
        inflight_registry()
            .get(&inflight(key))
            .map(|slot| slot.receiver_count())
    }

    /// Spins the runtime until `ready` holds so tests observe the in-flight
    /// registry without sleeping, and panics rather than hanging if the
    /// condition never becomes true.
    async fn wait_until(label: &str, mut ready: impl FnMut() -> bool) {
        for _ in 0..100_000 {
            if ready() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("timed out waiting for {}", label);
    }

    /// 200 simultaneous cold misses for one key must produce exactly one
    /// upstream dispatch. Without the in-flight registry each one runs its own
    /// hedge (three primaries plus stagger and backups), so a single local
    /// client loop amplifies into hundreds of upstream requests.
    #[tokio::test]
    async fn single_flight_collapses_identical_cold_misses() {
        const WAITERS: usize = 200;
        let key = CacheKey::from("collapse.example", RecordType::A);
        let cancel = tokio_util::sync::CancellationToken::new();
        let dispatches = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));

        let mut handles = Vec::with_capacity(WAITERS);
        for _ in 0..WAITERS {
            let key = key.clone();
            let cancel = cancel.clone();
            let dispatches = dispatches.clone();
            let gate = gate.clone();
            handles.push(tokio::spawn(async move {
                single_flight(&key, true, &cancel, || async {
                    let serial = dispatches.fetch_add(1, Ordering::AcqRel) as u32;
                    // Hold the slot open until every waiter has parked on it.
                    let _permit = gate.acquire().await.unwrap();
                    injected_resolution(serial)
                })
                .await
            }));
        }

        // Release once every waiter has parked, or early if more than one
        // dispatch got through, so the amplification is reported as a dispatch
        // count rather than as a stalled test.
        wait_until("every waiter to park on the leader", || {
            inflight_subscribers(&key) == Some(WAITERS - 1)
                || dispatches.load(Ordering::Acquire) > 1
        })
        .await;
        gate.add_permits(WAITERS);

        let mut answers = Vec::with_capacity(WAITERS);
        for handle in handles {
            answers.push(handle.await.unwrap());
        }
        assert_eq!(
            dispatches.load(Ordering::Acquire),
            1,
            "one dispatch must serve every identical cold miss"
        );
        assert_eq!(answers.len(), WAITERS);
        for answer in &answers {
            assert_eq!(answer.origin.provider.as_deref(), Some("provider-0"));
            assert_eq!(answer.message.answers.len(), 1);
        }
        assert!(
            inflight_registry().get(&inflight(&key)).is_none(),
            "slot must be freed after a successful dispatch"
        );
    }

    /// The DNSSEC toggle changes what a dispatch asks the provider (CD). A
    /// request under the new policy must not join a leader that started under
    /// the old one, or it receives data the provider was told not to validate.
    #[tokio::test]
    async fn single_flight_keeps_dnssec_policies_apart() {
        let key = CacheKey::from("policy.example", RecordType::A);
        let cancel = tokio_util::sync::CancellationToken::new();
        let dispatches = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));

        let unchecked_leader = tokio::spawn({
            let key = key.clone();
            let cancel = cancel.clone();
            let dispatches = dispatches.clone();
            let gate = gate.clone();
            async move {
                single_flight(&key, false, &cancel, || async {
                    dispatches.fetch_add(1, Ordering::AcqRel);
                    let _permit = gate.acquire().await.unwrap();
                    injected_resolution(0)
                })
                .await
            }
        });
        wait_until("the unchecked leader to start resolving", || {
            dispatches.load(Ordering::Acquire) == 1
        })
        .await;

        let validating = tokio::spawn({
            let key = key.clone();
            let cancel = cancel.clone();
            let dispatches = dispatches.clone();
            async move {
                single_flight(&key, true, &cancel, || async {
                    let serial = dispatches.fetch_add(1, Ordering::AcqRel) as u32;
                    injected_resolution(serial)
                })
                .await
            }
        });
        let answer = tokio::time::timeout(Duration::from_secs(1), validating)
            .await
            .expect("a validating request must not wait on an unchecked leader")
            .unwrap();

        assert_eq!(answer.origin.provider.as_deref(), Some("provider-1"));
        assert_eq!(dispatches.load(Ordering::Acquire), 2);
        gate.add_permits(1);
        unchecked_leader.await.unwrap();
    }

    /// The gate is per cache key. A different name or a different qtype must
    /// dispatch on its own and must not block behind an unrelated leader.
    #[tokio::test]
    async fn single_flight_keeps_distinct_keys_independent() {
        let keys = [
            CacheKey::from("independent-a.example", RecordType::A),
            CacheKey::from("independent-b.example", RecordType::A),
            CacheKey::from("independent-a.example", RecordType::AAAA),
        ];
        let cancel = tokio_util::sync::CancellationToken::new();
        let dispatches = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));

        let mut handles = Vec::new();
        for (serial, key) in keys.iter().enumerate() {
            let key = key.clone();
            let cancel = cancel.clone();
            let dispatches = dispatches.clone();
            let gate = gate.clone();
            handles.push(tokio::spawn(async move {
                single_flight(&key, true, &cancel, || async {
                    dispatches.fetch_add(1, Ordering::AcqRel);
                    let _permit = gate.acquire().await.unwrap();
                    injected_resolution(serial as u32)
                })
                .await
            }));
        }

        wait_until("all three keys to hold their own slot", || {
            keys.iter()
                .all(|key| inflight_registry().contains_key(&inflight(key)))
        })
        .await;
        gate.add_permits(keys.len());

        let mut answers = Vec::new();
        for handle in handles {
            answers.push(handle.await.unwrap());
        }
        assert_eq!(
            dispatches.load(Ordering::Acquire),
            keys.len(),
            "each distinct key must dispatch for itself"
        );
        for (serial, answer) in answers.iter().enumerate() {
            assert_eq!(
                answer.origin.provider.as_deref(),
                Some(format!("provider-{}", serial).as_str()),
                "key {} must keep its own answer",
                serial
            );
        }
    }

    /// A leader that panics mid-dispatch must free its slot and close its
    /// channel, so the waiter resolves for itself instead of hanging forever on
    /// an answer that will never be published.
    #[tokio::test]
    async fn single_flight_leader_panic_releases_waiters() {
        let key = CacheKey::from("panic-leader.example", RecordType::A);
        let cancel = tokio_util::sync::CancellationToken::new();
        let dispatches = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));

        let leader = tokio::spawn({
            let key = key.clone();
            let cancel = cancel.clone();
            let dispatches = dispatches.clone();
            let gate = gate.clone();
            async move {
                single_flight(&key, true, &cancel, || async {
                    dispatches.fetch_add(1, Ordering::AcqRel);
                    let _permit = gate.acquire().await.unwrap();
                    panic!("upstream dispatch panicked");
                })
                .await
            }
        });
        wait_until("the leader to claim the slot", || {
            inflight_registry().contains_key(&inflight(&key))
        })
        .await;

        let waiter = tokio::spawn({
            let key = key.clone();
            let cancel = cancel.clone();
            let dispatches = dispatches.clone();
            async move {
                single_flight(&key, true, &cancel, || async {
                    let serial = dispatches.fetch_add(1, Ordering::AcqRel) as u32;
                    injected_resolution(serial)
                })
                .await
            }
        });
        wait_until("the waiter to park on the leader", || {
            inflight_subscribers(&key) == Some(1)
        })
        .await;

        gate.add_permits(1);
        assert!(leader.await.is_err(), "leader must have panicked");
        let answer = waiter.await.unwrap();
        assert_eq!(
            dispatches.load(Ordering::Acquire),
            2,
            "the released waiter must resolve for itself"
        );
        assert_eq!(answer.origin.provider.as_deref(), Some("provider-1"));
        assert!(
            inflight_registry().get(&inflight(&key)).is_none(),
            "a panicking leader must free its slot"
        );
    }

    /// A leader whose future is dropped mid-dispatch (client gone, shutdown,
    /// `select!` losing the race) must release its slot too, so the waiter
    /// falls back to its own dispatch instead of blocking on a dead leader.
    #[tokio::test]
    async fn single_flight_leader_cancellation_releases_waiters() {
        let key = CacheKey::from("cancelled-leader.example", RecordType::A);
        let cancel = tokio_util::sync::CancellationToken::new();
        let dispatches = Arc::new(AtomicUsize::new(0));
        let never = Arc::new(tokio::sync::Semaphore::new(0));

        let leader = tokio::spawn({
            let key = key.clone();
            let cancel = cancel.clone();
            let dispatches = dispatches.clone();
            let never = never.clone();
            async move {
                single_flight(&key, true, &cancel, || async {
                    dispatches.fetch_add(1, Ordering::AcqRel);
                    let _permit = never.acquire().await.unwrap();
                    injected_resolution(u32::MAX)
                })
                .await
            }
        });
        wait_until("the leader to claim the slot", || {
            inflight_registry().contains_key(&inflight(&key))
        })
        .await;

        let waiter = tokio::spawn({
            let key = key.clone();
            let cancel = cancel.clone();
            let dispatches = dispatches.clone();
            async move {
                single_flight(&key, true, &cancel, || async {
                    let serial = dispatches.fetch_add(1, Ordering::AcqRel) as u32;
                    injected_resolution(serial)
                })
                .await
            }
        });
        wait_until("the waiter to park on the leader", || {
            inflight_subscribers(&key) == Some(1)
        })
        .await;

        leader.abort();
        match leader.await {
            Err(e) => assert!(e.is_cancelled(), "leader must have been cancelled"),
            Ok(_) => panic!("leader must not have completed"),
        }
        let answer = waiter.await.unwrap();
        assert_eq!(
            dispatches.load(Ordering::Acquire),
            2,
            "the released waiter must resolve for itself"
        );
        assert_eq!(answer.origin.provider.as_deref(), Some("provider-1"));
        assert!(
            inflight_registry().get(&inflight(&key)).is_none(),
            "a cancelled leader must free its slot"
        );
    }

    /// A waiter whose own request is cancelled while parked must stop waiting
    /// on the leader's channel. It then resolves independently, where the
    /// cancellation surfaces through the normal dispatch path.
    #[tokio::test]
    async fn single_flight_waiter_stops_waiting_when_its_own_request_is_cancelled() {
        let key = CacheKey::from("cancelled-waiter.example", RecordType::A);
        let leader_cancel = tokio_util::sync::CancellationToken::new();
        let waiter_cancel = tokio_util::sync::CancellationToken::new();
        let never = Arc::new(tokio::sync::Semaphore::new(0));

        let leader = tokio::spawn({
            let key = key.clone();
            let cancel = leader_cancel.clone();
            let never = never.clone();
            async move {
                single_flight(&key, true, &cancel, || async {
                    let _permit = never.acquire().await.unwrap();
                    injected_resolution(u32::MAX)
                })
                .await
            }
        });
        wait_until("the leader to claim the slot", || {
            inflight_registry().contains_key(&inflight(&key))
        })
        .await;

        let waiter = tokio::spawn({
            let key = key.clone();
            let cancel = waiter_cancel.clone();
            async move { single_flight(&key, true, &cancel, || async { injected_resolution(7) }).await }
        });
        wait_until("the waiter to park on the leader", || {
            inflight_subscribers(&key) == Some(1)
        })
        .await;

        waiter_cancel.cancel();
        let answer = waiter.await.unwrap();
        assert_eq!(
            answer.origin.provider.as_deref(),
            Some("provider-7"),
            "a cancelled waiter must stop waiting and resolve independently"
        );
        assert!(
            inflight_registry().contains_key(&inflight(&key)),
            "a departing waiter must not steal the live leader's slot"
        );
        leader.abort();
        let _ = leader.await;
    }

    /// The toggle decides whether a client's CD bit is a downgrade at all.
    /// With DNSSEC off every query already leaves with `CD=1`, so the client
    /// asked for nothing extra and must keep the shared cache. Only the
    /// toggle-on case bypasses it.
    #[test]
    fn only_a_cd_client_under_an_enabled_toggle_is_forced_off_the_cache() {
        let name = Name::from_str("cd-toggle.example.").unwrap();
        let plain = request_for(&name);
        let mut with_cd = request_for(&name);
        with_cd.metadata.checking_disabled = true;

        assert!(client_forces_unchecked_data(&with_cd, true));
        assert!(!client_forces_unchecked_data(&with_cd, false));
        assert!(!client_forces_unchecked_data(&plain, true));
        assert!(!client_forces_unchecked_data(&plain, false));
    }

    /// Forced-CD containment, sharing half. `CacheKey`, and with it the
    /// in-flight registry, has no CD dimension, so a query the client forced
    /// to `CD=1` must resolve alone. Joining a `CD=0` leader would return
    /// validated data the client asked to bypass. Leading one would publish
    /// unvalidated data to every `CD=0` request parked on the key.
    #[tokio::test]
    async fn a_forced_cd_query_neither_joins_nor_leads_a_single_flight() {
        let key = CacheKey::from("forced-cd-flight.example", RecordType::A);
        let cancel = tokio_util::sync::CancellationToken::new();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));

        let leader = tokio::spawn({
            let key = key.clone();
            let cancel = cancel.clone();
            let gate = gate.clone();
            async move {
                resolve_shared_unless_forced_cd(&key, true, &cancel, false, || async {
                    let _permit = gate.acquire().await.unwrap();
                    injected_resolution(0)
                })
                .await
            }
        });
        wait_until("the CD=0 leader to claim the slot", || {
            inflight_registry().contains_key(&inflight(&key))
        })
        .await;

        // The leader is parked on the gate. A forced-CD query that joined it
        // would never return, so the timeout reports the regression instead of
        // hanging the suite.
        let forced = tokio::time::timeout(
            Duration::from_secs(5),
            resolve_shared_unless_forced_cd(&key, true, &cancel, true, || async {
                assert_eq!(
                    inflight_subscribers(&key),
                    Some(0),
                    "a forced-CD query must not subscribe to the leader"
                );
                injected_resolution(1)
            }),
        )
        .await
        .expect("a forced-CD query must not park on a CD=0 leader");
        assert_eq!(
            forced.origin.provider.as_deref(),
            Some("provider-1"),
            "the forced-CD query must return its own resolution, not the leader's"
        );

        gate.add_permits(1);
        assert_eq!(
            leader.await.unwrap().origin.provider.as_deref(),
            Some("provider-0"),
            "the CD=0 leader must keep its own answer"
        );

        let solo = resolve_shared_unless_forced_cd(&key, true, &cancel, true, || async {
            assert!(
                inflight_registry().get(&inflight(&key)).is_none(),
                "a forced-CD query must not claim the in-flight key"
            );
            injected_resolution(2)
        })
        .await;
        assert_eq!(solo.origin.provider.as_deref(), Some("provider-2"));
    }

    /// Forced-CD containment, storage half. A positive answer fetched for a
    /// forced-CD client may be one the provider never validated, and the cache
    /// would hand it to `CD=0` clients afterwards. The client still gets it.
    #[tokio::test]
    async fn a_forced_cd_answer_reaches_the_client_without_reaching_the_cache() {
        let name = Name::from_str("forced-cd-store.example.").unwrap();
        let key = CacheKey::from("forced-cd-store.example", RecordType::A);
        let state = Arc::new(route_test_state());

        let (msg, _provider) = positive_hedge_outcome_with_cd(&state, &name, &key, true).await;

        assert_eq!(
            msg.answers.len(),
            1,
            "the forced-CD client must still receive its answer"
        );
        assert!(
            state.cache.get_allow_expired(&key).await.is_none(),
            "an answer fetched under a forced CD must not be cached"
        );
    }

    /// The inverse of the test above: the gate must not have turned into a
    /// blanket "never cache the hedge result".
    #[tokio::test]
    async fn a_normal_answer_is_still_cached() {
        let name = Name::from_str("normal-store.example.").unwrap();
        let key = CacheKey::from("normal-store.example", RecordType::A);
        let state = Arc::new(route_test_state());

        let (_msg, _provider) = positive_hedge_outcome_with_cd(&state, &name, &key, false).await;

        assert!(
            state.cache.get(&key).await.is_some(),
            "a CD=0 answer must still populate the cache"
        );
    }

    /// Negatives take a different branch and carry a second write with them:
    /// the RFC 8020 cut. Both must stay out of the cache for a forced-CD query.
    #[tokio::test]
    async fn a_forced_cd_negative_is_neither_cached_nor_cut() {
        let qname = Name::from_str("absent.forced-cd.example.").unwrap();
        let key = CacheKey::from("absent.forced-cd.example", RecordType::A);
        let nxdomain_err = || {
            no_records_err(
                &qname,
                RecordType::A,
                ResponseCode::NXDomain,
                Some((Name::from_str("forced-cd.example.").unwrap(), 300, 300)),
                Some(300),
            )
        };

        // The cut is installed at the nonexistent name, and coverage is only
        // ever asked about a descendant of it.
        let covered = format!("sub.{}", qname);

        // Same error, CD=0: both writes must happen, or the assertions below
        // would hold for a negative that was never cacheable in the first place.
        let baseline = Arc::new(route_test_state());
        negative_hedge_outcome_with_cd(&baseline, &qname, RecordType::A, nxdomain_err(), false)
            .await;
        assert!(baseline.cache.get_allow_expired(&key).await.is_some());
        assert!(baseline.cache.nxdomain_apex_covers(&covered).await);

        let state = Arc::new(route_test_state());
        let (msg, _provider) =
            negative_hedge_outcome_with_cd(&state, &qname, RecordType::A, nxdomain_err(), true)
                .await;

        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::NXDomain,
            "the forced-CD client must still receive the negative answer"
        );
        assert!(
            state.cache.get_allow_expired(&key).await.is_none(),
            "a negative fetched under a forced CD must not be cached"
        );
        assert!(
            !state.cache.nxdomain_apex_covers(&covered).await,
            "a forced-CD NXDOMAIN must not install an RFC 8020 cut"
        );
    }

    fn https_record_with_ipv4_hints(name: &Name, hints: &[&str]) -> Record {
        use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey, SvcParamValue};
        use hickory_proto::rr::rdata::{HTTPS, SVCB};
        Record::from_rdata(
            name.clone(),
            60,
            RData::HTTPS(HTTPS(SVCB::new(
                1,
                Name::from_str("target.example.com.").unwrap(),
                vec![(
                    SvcParamKey::Ipv4Hint,
                    SvcParamValue::Ipv4Hint(IpHint(
                        hints.iter().map(|ip| A(ip.parse().unwrap())).collect(),
                    )),
                )],
            ))),
        )
    }

    fn surviving_ipv4_hints(msg: &Message) -> Vec<A> {
        use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
        match &msg.answers.first().expect("HTTPS answer must survive").data {
            RData::HTTPS(https) => match https.0.svc_params.first() {
                Some((SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(hint))) => hint.0.clone(),
                _ => Vec::new(),
            },
            other => panic!("expected an HTTPS answer, got {other:?}"),
        }
    }

    /// The rebinding filter has to cover HTTPS/SVCB hints on the hedge path as
    /// well. This answer reaches the client directly, so a private hint that
    /// survives here is dialled by the browser without any further lookup.
    #[tokio::test]
    async fn hedge_strips_private_https_hints_before_the_client_sees_them() {
        let state = Arc::new(route_test_state());
        let name = Name::from_str("hints.example.com.").unwrap();
        let key = CacheKey::from("hints.example.com", RecordType::HTTPS);
        let lookup = Lookup::new_with_deadline(
            DnsQuery::new()
                .set_name(name.clone())
                .set_query_type(RecordType::HTTPS)
                .set_query_class(DNSClass::IN)
                .clone(),
            vec![https_record_with_ipv4_hints(
                &name,
                &["127.0.0.1", "93.184.216.34"],
            )],
            Instant::now() + Duration::from_secs(60),
        );
        let cfg = crate::config::current();
        let cache_epoch = state.cache.capture_epoch();

        let (msg, _provider) = process_hedge_outcome(
            Ok(crate::hedge::HedgeResult {
                first: lookup.clone(),
                first_idx: 0,
                all: vec![(0, lookup)],
                refine: None,
            }),
            0xBEEF,
            &name,
            RecordType::HTTPS,
            "hints.example.com",
            &cfg,
            &state,
            key,
            &request_for(&name),
            cache_epoch,
            false,
        )
        .await;

        assert_eq!(
            surviving_ipv4_hints(&msg),
            vec![A("93.184.216.34".parse().unwrap())],
            "the loopback hint must not reach the client"
        );
    }

    /// Drives the positive branch of `process_hedge_outcome` with an injected
    /// hedge win instead of a network dispatch.
    async fn positive_hedge_outcome_with_cd(
        state: &Arc<ModuleState>,
        name: &Name,
        key: &CacheKey,
        client_forced_cd: bool,
    ) -> (Message, ReplyOrigin) {
        let cfg = crate::config::current();
        let domain = name.to_string();
        let domain_trim = domain.trim_end_matches('.').to_string();
        let cache_epoch = state.cache.capture_epoch();
        process_hedge_outcome(
            Ok(crate::hedge::HedgeResult {
                first: public_lookup_with_a(name, 1),
                first_idx: 0,
                all: vec![(0, public_lookup_with_a(name, 1))],
                refine: None,
            }),
            0xBEEF,
            name,
            RecordType::A,
            &domain_trim,
            &cfg,
            state,
            key.clone(),
            &request_for(name),
            cache_epoch,
            client_forced_cd,
        )
        .await
    }

    mod dns64_view {
        use super::super::ReplyOrigin;
        use super::route_test_state;
        use crate::cache::{CacheKey, CachedEntry};
        use crate::dns64::Nat64Prefix;
        use crate::history::Route;
        use crate::network_profile::{Nat64Active, Nat64Status};
        use crate::state::ModuleState;
        use hickory_proto::op::{Message, MessageType, Query as DnsQuery, ResponseCode};
        use hickory_proto::rr::rdata::{A, AAAA, SOA};
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        use std::net::Ipv6Addr;
        use std::str::FromStr;
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        use tokio_util::sync::CancellationToken;

        fn wkp() -> Nat64Prefix {
            Nat64Prefix::new(Ipv6Addr::from_str("64:ff9b::").unwrap(), 96).unwrap()
        }

        fn nsp() -> Nat64Prefix {
            Nat64Prefix::new(Ipv6Addr::from_str("2001:db8:64::").unwrap(), 96).unwrap()
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

        fn nat64_state() -> Arc<ModuleState> {
            let state = Arc::new(route_test_state());
            state
                .network
                .set_nat64_for_test(present(vec![wkp()], Duration::from_secs(300)));
            state
        }

        fn request(name: &Name, qtype: RecordType, checking_disabled: bool) -> Message {
            let mut req = Message::query();
            req.metadata.id = 0x4242;
            req.metadata.recursion_desired = true;
            req.metadata.checking_disabled = checking_disabled;
            let mut q = DnsQuery::new();
            q.set_name(name.clone()).set_query_type(qtype);
            req.add_query(q);
            req
        }

        fn aaaa_nodata(name: &Name) -> Message {
            let mut m = Message::new(
                0x4242,
                MessageType::Response,
                hickory_proto::op::OpCode::Query,
            );
            let mut q = DnsQuery::new();
            q.set_name(name.clone()).set_query_type(RecordType::AAAA);
            m.add_query(q);
            let soa = SOA::new(
                Name::from_str("example.").unwrap(),
                Name::from_str("hostmaster.example.").unwrap(),
                1,
                3600,
                600,
                86400,
                5,
            );
            m.add_authority(Record::from_rdata(
                Name::from_str("example.").unwrap(),
                5,
                RData::SOA(soa),
            ));
            m
        }

        async fn cache_a(state: &ModuleState, name: &Name, domain: &str, ip: [u8; 4]) {
            let mut m = Message::query();
            m.metadata.message_type = MessageType::Response;
            m.add_answer(Record::from_rdata(
                name.clone(),
                120,
                RData::A(A::new(ip[0], ip[1], ip[2], ip[3])),
            ));
            assert!(
                state
                    .cache
                    .insert(
                        CacheKey::from(domain, RecordType::A),
                        CachedEntry::scaffold(m, "Quad9".into()),
                        120
                    )
                    .await
            );
        }

        async fn view(
            state: &Arc<ModuleState>,
            name: &Name,
            domain: &str,
            checking_disabled: bool,
        ) -> (Message, ReplyOrigin) {
            let req = request(name, RecordType::AAAA, checking_disabled);
            super::super::synthesize_dns64_if_needed(
                state,
                &crate::config::current(),
                &req,
                0x4242,
                name,
                RecordType::AAAA,
                domain,
                &CancellationToken::new(),
                aaaa_nodata(name),
                ReplyOrigin::upstream(Route::Provider, "Quad9".into()),
            )
            .await
        }

        #[tokio::test]
        async fn aaaa_nodata_becomes_nat64_addresses_without_touching_the_cache() {
            let state = nat64_state();
            let name = Name::from_str("downloads.example.").unwrap();
            cache_a(&state, &name, "downloads.example", [35, 190, 46, 17]).await;

            let (msg, provider) = view(&state, &name, "downloads.example", false).await;

            assert_eq!(msg.metadata.id, 0x4242);
            assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
            assert_eq!(
                msg.answers
                    .iter()
                    .map(|r| r.data.clone())
                    .collect::<Vec<_>>(),
                vec![RData::AAAA(AAAA(
                    Ipv6Addr::from_str("64:ff9b::23be:2e11").unwrap()
                ))]
            );
            assert_eq!(provider.log_source.as_deref(), Some("dns64:Quad9"));
            assert_eq!(provider.provider.as_deref(), Some("Quad9"));
            assert_eq!(
                provider.route,
                Route::Cache,
                "the A answer came from the cache"
            );
            assert!(
                state
                    .cache
                    .get_allow_expired(&CacheKey::from("downloads.example", RecordType::AAAA))
                    .await
                    .is_none(),
                "a synthesized answer must never be cached"
            );
        }

        #[tokio::test]
        async fn no_nat64_prefix_leaves_the_nodata_untouched() {
            let state = Arc::new(route_test_state());
            let name = Name::from_str("downloads.example.").unwrap();
            cache_a(&state, &name, "downloads.example", [35, 190, 46, 17]).await;

            let (msg, provider) = view(&state, &name, "downloads.example", false).await;

            assert!(msg.answers.is_empty());
            assert_eq!(provider.log_source.as_deref(), Some("Quad9"));
        }

        #[tokio::test]
        async fn a_client_that_set_cd_gets_the_unmodified_answer() {
            let state = nat64_state();
            let name = Name::from_str("downloads.example.").unwrap();
            cache_a(&state, &name, "downloads.example", [35, 190, 46, 17]).await;

            let (msg, _) = view(&state, &name, "downloads.example", true).await;

            assert!(msg.answers.is_empty());
        }

        #[tokio::test]
        async fn private_ipv4_is_never_translated() {
            let state = nat64_state();
            let name = Name::from_str("nas.example.").unwrap();
            cache_a(&state, &name, "nas.example", [192, 168, 1, 10]).await;

            let (msg, _) = view(&state, &name, "nas.example", false).await;

            assert!(msg.answers.is_empty());
            assert!(
                msg.authorities
                    .iter()
                    .any(|r| matches!(&r.data, RData::SOA(_))),
                "the original NODATA proof must reach the client"
            );
        }

        /// The A lookup can span a network change. The answer must follow the
        /// network the client is on when it is sent, not the one it asked on.
        #[test]
        fn a_prefix_dropped_during_the_a_lookup_is_not_used() {
            let state = nat64_state();
            let asked = vec![wkp()];
            let name = Name::from_str("downloads.example.").unwrap();
            let mut a = Message::query();
            a.metadata.message_type = MessageType::Response;
            a.add_answer(Record::from_rdata(
                name.clone(),
                60,
                RData::A(A::new(35, 190, 46, 17)),
            ));

            state.network.set_nat64_for_test(Nat64Status::Unknown);
            let (msg, provider) = super::super::finish_dns64(
                &state.network,
                &asked,
                aaaa_nodata(&name),
                ReplyOrigin::upstream(Route::Provider, "Quad9".into()),
                (
                    a.clone(),
                    ReplyOrigin::upstream(Route::Provider, "Quad9".into()),
                ),
            );
            assert!(msg.answers.is_empty(), "stale prefix must not synthesize");
            assert_eq!(provider.log_source.as_deref(), Some("Quad9"));

            state
                .network
                .set_nat64_for_test(present(vec![nsp()], Duration::from_secs(300)));
            let (msg, _) = super::super::finish_dns64(
                &state.network,
                &asked,
                aaaa_nodata(&name),
                ReplyOrigin::upstream(Route::Provider, "Quad9".into()),
                (a, ReplyOrigin::upstream(Route::Provider, "Quad9".into())),
            );
            assert!(
                msg.answers.is_empty(),
                "a different network's prefix must not be mixed in"
            );
        }

        /// RFC 7050 §3: the prefix is only valid for the TTL its discovery
        /// answer carried. Past it, the network may have moved the translator.
        #[test]
        fn a_lapsed_prefix_is_not_used() {
            let state = Arc::new(route_test_state());
            state.network.set_nat64_for_test(Nat64Status::Present {
                active: Nat64Active {
                    prefixes: vec![wkp()],
                    expires_at: Instant::now() - Duration::from_secs(1),
                },
                resolver: "172.20.10.1:53".parse().unwrap(),
            });
            let name = Name::from_str("downloads.example.").unwrap();
            let mut a = Message::query();
            a.metadata.message_type = MessageType::Response;
            a.add_answer(Record::from_rdata(
                name.clone(),
                60,
                RData::A(A::new(35, 190, 46, 17)),
            ));

            let (msg, _) = super::super::finish_dns64(
                &state.network,
                &[wkp()],
                aaaa_nodata(&name),
                ReplyOrigin::upstream(Route::Provider, "Quad9".into()),
                (a, ReplyOrigin::upstream(Route::Provider, "Quad9".into())),
            );

            assert!(msg.answers.is_empty());
        }

        /// The history files a synthesized answer under the A answer it was
        /// built from, while the log line keeps naming the AAAA's source.
        #[test]
        fn a_synthesized_answer_takes_the_route_of_its_a_answer() {
            let state = nat64_state();
            let name = Name::from_str("downloads.example.").unwrap();
            let mut a = Message::query();
            a.metadata.message_type = MessageType::Response;
            a.add_answer(Record::from_rdata(
                name.clone(),
                60,
                RData::A(A::new(35, 190, 46, 17)),
            ));

            let (msg, origin) = super::super::finish_dns64(
                &state.network,
                &[wkp()],
                aaaa_nodata(&name),
                ReplyOrigin::upstream(Route::Cache, "Quad9".into()),
                (
                    a,
                    ReplyOrigin::upstream(Route::Provider, "Cloudflare".into()),
                ),
            );

            assert_eq!(msg.answers.len(), 1, "test setup must synthesize");
            assert_eq!(origin.route, Route::Provider);
            assert_eq!(origin.provider.as_deref(), Some("Cloudflare"));
            assert_eq!(origin.log_source.as_deref(), Some("dns64:Quad9"));
        }

        #[tokio::test]
        async fn every_prefix_is_used_and_no_record_outlives_it() {
            let state = Arc::new(route_test_state());
            state
                .network
                .set_nat64_for_test(present(vec![nsp(), wkp()], Duration::from_secs(3)));
            let name = Name::from_str("downloads.example.").unwrap();
            cache_a(&state, &name, "downloads.example", [35, 190, 46, 17]).await;

            let (msg, _) = view(&state, &name, "downloads.example", false).await;

            assert_eq!(
                msg.answers
                    .iter()
                    .map(|r| r.data.clone())
                    .collect::<Vec<_>>(),
                vec![
                    RData::AAAA(AAAA(Ipv6Addr::from_str("2001:db8:64::23be:2e11").unwrap())),
                    RData::AAAA(AAAA(Ipv6Addr::from_str("64:ff9b::23be:2e11").unwrap())),
                ]
            );
            assert!(msg.answers.iter().all(|r| r.ttl <= 3));

            let arpa = ipv4only_route(&state, RecordType::AAAA, "ipv4only.arpa.").await;
            assert_eq!(arpa.answers.len(), 4, "two well-known addresses per prefix");
            assert!(arpa.answers.iter().all(|r| r.ttl <= 3));
        }

        /// RFC 8880 §7.1: DS for `ipv4only.arpa` resolves the usual way so a
        /// validator can prove the delegation insecure.
        #[tokio::test]
        async fn ipv4only_arpa_ds_is_not_answered_locally() {
            let state = nat64_state();
            let name = Name::from_str("ipv4only.arpa.").unwrap();
            let req = request(&name, RecordType::DS, false);
            let policy = state.policy.load_full();
            let route = super::super::select_pre_public_route(
                &state,
                policy.as_ref(),
                0x4242,
                &name,
                RecordType::DS,
                &req,
                "ipv4only.arpa",
            )
            .await;
            assert!(matches!(route, super::super::PrePublicRoute::None));
        }

        async fn ipv4only_route(state: &ModuleState, qtype: RecordType, qname: &str) -> Message {
            let name = Name::from_str(qname).unwrap();
            let req = request(&name, qtype, false);
            let policy = state.policy.load_full();
            let domain = qname.trim_end_matches('.').to_ascii_lowercase();
            match super::super::select_pre_public_route(
                state,
                policy.as_ref(),
                0x4242,
                &name,
                qtype,
                &req,
                &domain,
            )
            .await
            {
                super::super::PrePublicRoute::BuiltinZone(m) => m,
                _ => panic!("ipv4only.arpa must be answered locally"),
            }
        }

        #[tokio::test]
        async fn ipv4only_arpa_is_answered_from_the_network_nat64_status() {
            let state = nat64_state();
            let a = ipv4only_route(&state, RecordType::A, "ipv4only.arpa.").await;
            assert_eq!(a.answers.len(), 2);

            let aaaa = ipv4only_route(&state, RecordType::AAAA, "IPv4only.ARPA.").await;
            assert_eq!(
                aaaa.answers
                    .iter()
                    .map(|r| r.data.clone())
                    .collect::<Vec<_>>(),
                vec![
                    RData::AAAA(AAAA(Ipv6Addr::from_str("64:ff9b::c000:aa").unwrap())),
                    RData::AAAA(AAAA(Ipv6Addr::from_str("64:ff9b::c000:ab").unwrap())),
                ]
            );

            let plain = route_test_state();
            let nodata = ipv4only_route(&plain, RecordType::AAAA, "ipv4only.arpa.").await;
            assert_eq!(nodata.metadata.response_code, ResponseCode::NoError);
            assert!(nodata.answers.is_empty());

            let below = ipv4only_route(&state, RecordType::A, "x.ipv4only.arpa.").await;
            assert_eq!(below.metadata.response_code, ResponseCode::NXDomain);
        }
    }
    #[test]
    fn audit_udp_large_ede_drops_before_records_and_fits() {
        use hickory_proto::op::Edns;
        use hickory_proto::serialize::binary::BinDecodable;
        let name = Name::from_ascii("audit.example.").unwrap();
        for text_len in [8, 256] {
            let mut message = Message::response(7, OpCode::Query);
            message
                .queries
                .push(DnsQuery::query(name.clone(), RecordType::A));
            message.add_answer(a_record(&name, 1));
            for _ in 0..4 {
                super::attach_ede(&mut message, super::EDE_OTHER, &"x".repeat(text_len));
            }
            let wire = super::finalize_wire(
                message,
                Transport::Udp {
                    client_payload_size: 512,
                },
                Some(&Edns::new()),
            );
            assert!(wire.len() <= 512, "final UDP wire is {} bytes", wire.len());
            let parsed = Message::from_bytes(&wire).unwrap();
            assert_eq!(
                parsed.answers.len(),
                1,
                "EDE must be dropped before answers"
            );
            assert!(
                !parsed.metadata.truncation,
                "optional EDE removal is not truncation"
            );
            let has_ede = parsed
                .edns
                .unwrap()
                .options()
                .as_ref()
                .iter()
                .any(|(_, option)| {
                    matches!(
                        option,
                        hickory_proto::rr::rdata::opt::EdnsOption::Unknown(15, _)
                    )
                });
            assert_eq!(has_ede, text_len == 8);
        }
    }

    #[test]
    fn audit_udp_oversized_options_and_questions_terminate_within_cap() {
        use hickory_proto::op::Edns;
        use hickory_proto::rr::rdata::opt::EdnsOption;
        use hickory_proto::serialize::binary::BinDecodable;
        let mut message = Message::response(7, OpCode::Query);
        for i in 0..20 {
            message.queries.push(DnsQuery::query(
                Name::from_ascii(format!("{i}.{}.example.", "x".repeat(60))).unwrap(),
                RecordType::A,
            ));
        }
        message.edns = Some(Edns::new());
        message
            .edns
            .as_mut()
            .unwrap()
            .options_mut()
            .insert(EdnsOption::Unknown(65001, vec![1; 800]));
        let wire = super::finalize_wire(
            message,
            Transport::Udp {
                client_payload_size: 1,
            },
            Some(&Edns::new()),
        );
        assert!(wire.len() <= 512, "final UDP wire is {} bytes", wire.len());
        assert!(Message::from_bytes(&wire).unwrap().metadata.truncation);
    }

    #[tokio::test]
    async fn audit_http_age_preserves_soa_rdata_and_negative_lifetime() {
        let cases = [
            (3600, 2, 1, 1),
            (3600, 2, 2, 0),
            (2, 2, 1, 1),
            (3600, 3600, 120, 5),
        ];
        for (code, qtype) in [
            (ResponseCode::NXDomain, RecordType::A),
            (ResponseCode::NoError, RecordType::SOA),
            (ResponseCode::NoError, RecordType::ANY),
        ] {
            for (record_ttl, minimum, age, expected_ttl) in cases {
                let original = SOA::new(
                    Name::from_ascii("ns.audit.example.").unwrap(),
                    Name::from_ascii("hostmaster.audit.example.").unwrap(),
                    1,
                    3600,
                    600,
                    86400,
                    minimum,
                );
                let served = original.clone();
                let server = crate::doh_test_server::DohServer::start(
                    Arc::new(move |query| {
                        let mut message = Message::response(query.metadata.id, OpCode::Query);
                        message.metadata.response_code = code;
                        message.queries = query.queries;
                        message.add_authority(Record::from_rdata(
                            Name::from_ascii("audit.example.").unwrap(),
                            record_ttl,
                            RData::SOA(served.clone()),
                        ));
                        crate::doh_test_server::Reply {
                            headers: vec![("age", age.to_string())],
                            message,
                        }
                    }),
                    None,
                )
                .await;
                let name = Name::from_ascii("missing.audit.example.").unwrap();
                let error = server
                    .upstream()
                    .lookup(
                        DnsQuery::query(name.clone(), qtype),
                        crate::provider_transport::request_options(),
                        false,
                    )
                    .await
                    .expect_err("SOA-bearing negative reply");
                let negative =
                    classify_negative_err(7, &name, qtype, &error, &Message::query()).unwrap();
                let (message, ttl) = match negative {
                    NegativeAnswer::Cacheable { message, ttl_secs } => (message, ttl_secs),
                    NegativeAnswer::Uncacheable { message } => (message, 0),
                    NegativeAnswer::Unresolvable => panic!("expected SOA-bearing negative"),
                };
                assert_eq!(ttl, expected_ttl, "{code:?} {qtype:?} Age={age}");
                let record = message
                    .authorities
                    .iter()
                    .find(|r| matches!(r.data, RData::SOA(_)))
                    .unwrap();
                assert_eq!(record.ttl, expected_ttl);
                assert_eq!(
                    hickory_proto::serialize::binary::BinEncodable::to_bytes(&record.data).unwrap(),
                    hickory_proto::serialize::binary::BinEncodable::to_bytes(&RData::SOA(
                        original.clone()
                    ))
                    .unwrap(),
                    "SOA RDATA encoding must remain byte-identical"
                );
                assert_eq!(
                    record.data,
                    RData::SOA(original),
                    "HTTP Age must preserve signed SOA RDATA"
                );
            }
        }
    }

    #[tokio::test]
    async fn audit_http_age_cname_nodata_preserves_soa_rdata_and_lifetime() {
        let cases = [
            (3600, 2, 1, 1),
            (3600, 2, 2, 0),
            (2, 2, 1, 1),
            (3600, 3600, 120, 5),
        ];
        for (record_ttl, minimum, age, expected_ttl) in cases {
            let original = SOA::new(
                Name::from_ascii("ns.audit.example.").unwrap(),
                Name::from_ascii("hostmaster.audit.example.").unwrap(),
                1,
                3600,
                600,
                86400,
                minimum,
            );
            let served = original.clone();
            let server = crate::doh_test_server::DohServer::start(
                Arc::new(move |query| {
                    let mut message = Message::response(query.metadata.id, OpCode::Query);
                    message.metadata.response_code = ResponseCode::NoError;
                    message.add_answer(Record::from_rdata(
                        query.queries[0].name().clone(),
                        60,
                        RData::CNAME(CNAME(Name::from_ascii("terminal.audit.example.").unwrap())),
                    ));
                    message.queries = query.queries;
                    message.add_authority(Record::from_rdata(
                        Name::from_ascii("audit.example.").unwrap(),
                        record_ttl,
                        RData::SOA(served.clone()),
                    ));
                    crate::doh_test_server::Reply {
                        headers: vec![("age", age.to_string())],
                        message,
                    }
                }),
                None,
            )
            .await;
            let name = Name::from_ascii("missing.audit.example.").unwrap();
            let error = server
                .upstream()
                .lookup(
                    DnsQuery::query(name.clone(), RecordType::A),
                    crate::provider_transport::request_options(),
                    false,
                )
                .await
                .expect_err("NXDOMAIN reply");
            let negative =
                classify_negative_err(7, &name, RecordType::A, &error, &Message::query()).unwrap();
            let (message, ttl) = match negative {
                NegativeAnswer::Cacheable { message, ttl_secs } => (message, ttl_secs),
                NegativeAnswer::Uncacheable { message } => (message, 0),
                NegativeAnswer::Unresolvable => panic!("expected SOA-bearing negative"),
            };
            assert_eq!(ttl, expected_ttl);
            let record = message
                .authorities
                .iter()
                .find(|r| matches!(r.data, RData::SOA(_)))
                .unwrap();
            assert_eq!(record.ttl, expected_ttl);
            assert_eq!(
                hickory_proto::serialize::binary::BinEncodable::to_bytes(&record.data).unwrap(),
                hickory_proto::serialize::binary::BinEncodable::to_bytes(&RData::SOA(
                    original.clone()
                ))
                .unwrap(),
                "SOA RDATA encoding must remain byte-identical"
            );
            assert_eq!(
                record.data,
                RData::SOA(original),
                "HTTP Age must preserve signed SOA RDATA"
            );
        }
    }

    #[tokio::test]
    async fn audit_http_age_positive_soa_keeps_record_ttl() {
        let original = SOA::new(
            Name::from_ascii("ns.audit.example.").unwrap(),
            Name::from_ascii("hostmaster.audit.example.").unwrap(),
            1,
            3600,
            600,
            86400,
            2,
        );
        let served = original.clone();
        let server = crate::doh_test_server::DohServer::start(
            Arc::new(move |query| {
                let mut message = Message::response(query.metadata.id, OpCode::Query);
                message.add_answer(Record::from_rdata(
                    query.queries[0].name().clone(),
                    3600,
                    RData::SOA(served.clone()),
                ));
                message.queries = query.queries;
                crate::doh_test_server::Reply {
                    headers: vec![("age", "1".into())],
                    message,
                }
            }),
            None,
        )
        .await;
        let lookup = server
            .upstream()
            .lookup(
                DnsQuery::query(Name::from_ascii("audit.example.").unwrap(), RecordType::SOA),
                crate::provider_transport::request_options(),
                false,
            )
            .await
            .unwrap();
        let record = lookup
            .answers()
            .iter()
            .find(|r| matches!(r.data, RData::SOA(_)))
            .unwrap();
        assert_eq!(record.ttl, 3599);
        assert_eq!(record.data, RData::SOA(original));
    }

    #[test]
    fn audit_override_cname_negative_tail_preserves_soa_and_proof() {
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        let alias = Name::from_ascii("alias.audit.example.").unwrap();
        let middle = Name::from_ascii("middle.audit.example.").unwrap();
        let terminal = Name::from_ascii("terminal.audit.example.").unwrap();
        for code in [ResponseCode::NoError, ResponseCode::NXDomain] {
            let mut error = no_records_err(
                &middle,
                RecordType::A,
                code,
                Some((Name::from_ascii("audit.example.").unwrap(), 300, 300)),
                Some(60),
            );
            let NetError::Dns(DnsError::NoRecordsFound(records)) = &mut error else {
                unreachable!()
            };
            records.cname_chain = Some(Arc::from(vec![Record::from_rdata(
                middle.clone(),
                60,
                RData::CNAME(CNAME(terminal.clone())),
            )]));
            records.authorities = Some(Arc::from(vec![Record::from_rdata(
                terminal.clone(),
                300,
                RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                    Name::from_ascii("next.audit.example.").unwrap(),
                    [RecordType::AAAA, RecordType::RRSIG],
                ))),
            )]));
            let (tail, _) = cacheable_negative(classify_negative_err(
                7,
                &middle,
                RecordType::A,
                &error,
                &Message::query(),
            ));
            let tail = Message::from_bytes(&tail.to_bytes().unwrap()).unwrap();
            let mut result = Message::response(7, OpCode::Query);
            result
                .queries
                .push(DnsQuery::query(alias.clone(), RecordType::A));
            result.add_answer(Record::from_rdata(
                alias.clone(),
                60,
                RData::CNAME(CNAME(middle.clone())),
            ));
            super::merge_override_cname_tail(&mut result, &tail);
            let mut client = hickory_proto::op::Edns::new();
            client.set_dnssec_ok(true);
            let result =
                Message::from_bytes(&super::finalize_wire(result, Transport::Tcp, Some(&client)))
                    .unwrap();
            assert_eq!(result.answers.len(), 2);
            assert_eq!(result.metadata.response_code, code);
            assert_eq!(
                result.authorities, tail.authorities,
                "negative CNAME tail must preserve SOA and proof"
            );
            assert!(result.authorities.iter().all(|record| record.ttl <= 5));
        }
    }

    #[test]
    fn audit_override_cname_positive_tail_omits_authority() {
        for qtype in [RecordType::A, RecordType::ANY] {
            let mut result = Message::response(7, OpCode::Query);
            let mut tail = Message::response(7, OpCode::Query);
            let name = Name::from_ascii("audit.example.").unwrap();
            tail.queries.push(DnsQuery::query(name.clone(), qtype));
            tail.add_answer(a_record(&name, 1));
            tail.add_authority(Record::from_rdata(
                name.clone(),
                60,
                RData::SOA(SOA::new(name.clone(), name, 1, 2, 3, 4, 5)),
            ));
            super::merge_override_cname_tail(&mut result, &tail);
            assert_eq!(result.answers, tail.answers);
            assert!(result.authorities.is_empty(), "positive {qtype:?}");
        }
    }
    #[tokio::test]
    async fn audit_http_age_positive_authority_soa_keeps_record_ttl() {
        let original = SOA::new(
            Name::from_ascii("ns.audit.example.").unwrap(),
            Name::from_ascii("hostmaster.audit.example.").unwrap(),
            1,
            3600,
            600,
            86400,
            2,
        );
        let served = original.clone();
        let server = crate::doh_test_server::DohServer::start(
            Arc::new(move |query| {
                let mut message = Message::response(query.metadata.id, OpCode::Query);
                message.add_answer(Record::from_rdata(
                    query.queries[0].name().clone(),
                    3600,
                    RData::A(A("192.0.2.1".parse().unwrap())),
                ));
                message.add_authority(Record::from_rdata(
                    Name::from_ascii("audit.example.").unwrap(),
                    3600,
                    RData::SOA(served.clone()),
                ));
                message.queries = query.queries;
                crate::doh_test_server::Reply {
                    headers: vec![("age", "1".into())],
                    message,
                }
            }),
            None,
        )
        .await;
        let lookup = server
            .upstream()
            .lookup(
                DnsQuery::query(
                    Name::from_ascii("www.audit.example.").unwrap(),
                    RecordType::A,
                ),
                crate::provider_transport::request_options(),
                false,
            )
            .await
            .unwrap();
        let record = lookup
            .authorities()
            .iter()
            .find(|r| matches!(r.data, RData::SOA(_)))
            .unwrap();
        assert_eq!(record.ttl, 3599);
        assert_eq!(record.data, RData::SOA(original));
    }

    /// Every client lookup through `handle_wire` becomes exactly one history
    /// event that says how it was answered. Names end in `history-tests.com`
    /// because `.test` and `.example` are built-in zones that answer locally.
    mod history_recording {
        use super::super::{
            handle_wire, prefetch_refill, PolicyGeneration, PrefetchOutcome, Transport,
        };
        use super::{route_test_state, route_test_state_with_pool};
        use crate::cache::{CacheKey, CachedEntry, RefreshSource};
        use crate::forward::ForwardResolver;
        use crate::history::{capture, LookupEvent, Route};
        use crate::providers::{Provider, ProviderPool};
        use crate::state::ModuleState;
        use hickory_proto::op::{
            Edns, Message, MessageType, OpCode, Query as DnsQuery, ResponseCode,
        };
        use hickory_proto::rr::rdata::{A, CNAME, SOA};
        use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        use std::str::FromStr;
        use std::sync::{Arc, MutexGuard};
        use std::time::{Duration, Instant};
        use tokio_util::sync::CancellationToken;

        /// Keeps `state` installed as the module state `handle_wire` reads and
        /// clears it on drop.
        struct InstalledState {
            _lock: MutexGuard<'static, ()>,
        }

        impl Drop for InstalledState {
            fn drop(&mut self) {
                crate::state::clear_state();
            }
        }

        fn install(state: ModuleState) -> (InstalledState, Arc<ModuleState>) {
            let lock = crate::state::test_lock();
            let state = crate::state::init_state(state);
            (InstalledState { _lock: lock }, state)
        }

        fn runtime() -> tokio::runtime::Runtime {
            tokio::runtime::Runtime::new().unwrap()
        }

        fn query(name: &str, qtype: RecordType) -> Message {
            let mut req = Message::query();
            req.metadata.id = 0x5151;
            req.add_query(DnsQuery::query(Name::from_str(name).unwrap(), qtype));
            req
        }

        async fn lookup_wire(wire: &[u8]) -> Vec<u8> {
            handle_wire(
                wire,
                CancellationToken::new(),
                Transport::Udp {
                    client_payload_size: 4096,
                },
            )
            .await
        }

        async fn lookup(req: &Message) -> Message {
            Message::from_bytes(&lookup_wire(&req.to_bytes().unwrap()).await).unwrap()
        }

        fn only_event(capture: &capture::Capture, name: &str) -> LookupEvent {
            let events = capture.events_for(name);
            assert_eq!(events.len(), 1, "one lookup of {name} records one event");
            events.into_iter().next().unwrap()
        }

        /// Route, provider and response code, plus the fields every event
        /// that was not blocked shares.
        fn assert_event(event: &LookupEvent, route: Route, provider: &str, rcode: ResponseCode) {
            assert_eq!(event.route, route, "{event:?}");
            assert_eq!(event.provider, provider, "{event:?}");
            assert_eq!(event.rcode, u16::from(rcode), "{event:?}");
            assert_eq!(event.block_rule, "", "{event:?}");
            assert_eq!(event.block_category, "", "{event:?}");
            assert!(
                (event.ts - crate::history::unix_now()).abs() <= 5,
                "{event:?}"
            );
        }

        fn positive(name: &str, ttl: u32) -> Message {
            let mut message = Message::response(0, OpCode::Query);
            message.queries.push(DnsQuery::query(
                Name::from_str(name).unwrap(),
                RecordType::A,
            ));
            message.add_answer(Record::from_rdata(
                Name::from_str(name).unwrap(),
                ttl,
                RData::A(A::new(35, 190, 46, 17)),
            ));
            message
        }

        #[test]
        fn history_tells_a_provider_answer_from_the_cache_hit_after_it() {
            let rt = runtime();
            let upstream = rt.block_on(crate::test_dns_server::spawn_a_server(
                std::net::Ipv4Addr::new(9, 9, 9, 1),
                Duration::ZERO,
            ));
            let (_state, _) = install(route_test_state_with_pool(ProviderPool::for_local_test(
                vec![Provider::for_local_test_with_conns(upstream, 2)],
            )));
            let capture = capture::start();
            let name = "popular.history-tests.com.";

            rt.block_on(async {
                lookup(&query(name, RecordType::A)).await;
                lookup(&query(name, RecordType::A)).await;
            });

            let events = capture.events_for(name);
            assert_eq!(events.len(), 2, "{events:?}");
            assert_event(&events[0], Route::Provider, "Test", ResponseCode::NoError);
            assert_event(&events[1], Route::Cache, "Test", ResponseCode::NoError);
            for event in &events {
                assert_eq!(event.qtype, u16::from(RecordType::A));
                assert_eq!(event.answers, 1);
            }
        }

        #[test]
        fn history_records_a_stale_answer_with_the_provider_that_cached_it() {
            let rt = runtime();
            let (_state, state) = install(route_test_state());
            let name = "stale.history-tests.com.";
            let mut entry = CachedEntry::scaffold(positive(name, 60), "Quad9".into());
            entry.expires_at = Instant::now() - Duration::from_secs(1);
            entry.original_ttl_secs = 60;
            rt.block_on(state.cache.inner_insert_raw(
                CacheKey::from("stale.history-tests.com", RecordType::A),
                entry,
            ));
            let capture = capture::start();

            let reply = rt.block_on(lookup(&query(name, RecordType::A)));

            assert_eq!(reply.answers.len(), 1, "the stale answer must be served");
            let event = only_event(&capture, name);
            assert_event(&event, Route::Stale, "Quad9", ResponseCode::NoError);
            assert_eq!(event.answers, 1);
        }

        #[test]
        fn history_records_the_blocklist_rule_and_category() {
            use crate::lmdb::{
                BlockAction, BlocklistDb, BlocklistEntry, DomainName, MultiCategoryDb,
            };
            let rt = runtime();
            let (_state, _) = install(route_test_state());
            let _blocklist = crate::blocklist::test_lock();
            let temp = tempfile::TempDir::new().unwrap();
            let path = temp.path().join("trackers.db");
            let db = Arc::new(BlocklistDb::open_for_write(&path).unwrap());
            db.insert(&DomainName::new("tracker.history-tests.com").unwrap())
                .unwrap();
            crate::blocklist::install_snapshot_for_tests(MultiCategoryDb::from_databases(vec![(
                db,
                BlocklistEntry {
                    name: "Trackers".into(),
                    tag: "ads_tracking".into(),
                    db_path: path,
                    action: BlockAction::Nxdomain,
                },
            )]));
            let capture = capture::start();
            let name = "pixel.tracker.history-tests.com.";

            rt.block_on(lookup(&query(name, RecordType::A)));
            crate::blocklist::install_snapshot_for_tests(MultiCategoryDb::new());

            let event = only_event(&capture, name);
            assert_eq!(event.route, Route::Blocked);
            assert_eq!(event.provider, "");
            assert_eq!(event.rcode, u16::from(ResponseCode::NXDomain));
            assert_eq!(event.block_rule, "tracker.history-tests.com");
            assert_eq!(event.block_category, "ads_tracking");
        }

        #[test]
        fn history_records_an_override_and_its_cname_chain_once() {
            let rt = runtime();
            let (_state, state) = install(route_test_state());
            {
                let policy = state.policy.load();
                policy.overrides.set(
                    "alias.history-tests.com",
                    RecordType::CNAME,
                    vec![RData::CNAME(CNAME(
                        Name::from_str("target.history-tests.com.").unwrap(),
                    ))],
                );
                policy.overrides.set(
                    "target.history-tests.com",
                    RecordType::A,
                    vec![RData::A(A::new(192, 0, 2, 7))],
                );
            }
            let capture = capture::start();
            let alias = "alias.history-tests.com.";
            let target = "target.history-tests.com.";

            let reply = rt.block_on(lookup(&query(alias, RecordType::A)));

            assert_eq!(reply.answers.len(), 2, "test setup must resolve the chain");
            let event = only_event(&capture, alias);
            assert_event(&event, Route::Override, "", ResponseCode::NoError);
            assert_eq!(event.answers, 2);
            assert!(
                capture.events_for(target).is_empty(),
                "the chain's internal sub-query is part of the alias lookup"
            );

            rt.block_on(lookup(&query(target, RecordType::A)));
            assert_event(
                &only_event(&capture, target),
                Route::Override,
                "",
                ResponseCode::NoError,
            );
        }

        #[test]
        fn history_records_a_forward_zone_answer_as_forward() {
            let rt = runtime();
            let server = rt.block_on(crate::test_dns_server::spawn_udp_a_server(
                std::net::Ipv4Addr::new(192, 0, 2, 9),
            ));
            let (_state, state) = install(route_test_state());
            state.policy.load().zones.upsert_for_test(
                "corp.history-tests.com",
                ForwardResolver::for_local_test(server.port()).resolver,
            );
            let capture = capture::start();
            let name = "db.corp.history-tests.com.";

            rt.block_on(lookup(&query(name, RecordType::A)));

            let event = only_event(&capture, name);
            assert_event(&event, Route::Forward, "", ResponseCode::NoError);
            assert_eq!(event.answers, 1, "test setup must reach the zone's server");
        }

        #[test]
        fn history_records_a_captive_portal_answer_as_captive() {
            let rt = runtime();
            let server = rt.block_on(crate::test_dns_server::spawn_udp_a_server(
                std::net::Ipv4Addr::new(192, 0, 2, 10),
            ));
            let (_state, state) = install(route_test_state());
            state
                .forward
                .store(Arc::new(Some(Arc::new(ForwardResolver::for_local_test(
                    server.port(),
                )))));
            let capture = capture::start();
            let name = "portal.history-tests.com.";

            rt.block_on(lookup(&query(name, RecordType::A)));

            let event = only_event(&capture, name);
            assert_event(&event, Route::Captive, "", ResponseCode::NoError);
            assert_eq!(event.answers, 1, "test setup must reach the hotspot server");
        }

        #[test]
        fn history_records_built_in_answers_as_local() {
            let rt = runtime();
            let (_state, state) = install(route_test_state());
            rt.block_on(state.cache.insert_nxdomain_apex("gone.history-tests.com."));
            let capture = capture::start();
            let cases = [
                ("history-local.localhost.", ResponseCode::NoError),
                ("printer.history-local.test.", ResponseCode::NXDomain),
                ("ipv4only.arpa.", ResponseCode::NoError),
                ("www.gone.history-tests.com.", ResponseCode::NXDomain),
            ];

            for (name, rcode) in cases {
                rt.block_on(lookup(&query(name, RecordType::A)));
                assert_event(&only_event(&capture, name), Route::Local, "", rcode);
            }
        }

        #[test]
        fn history_records_servfails_macdns_produced_as_failed() {
            let rt = runtime();
            let (state_guard, _) = install(route_test_state());
            let capture = capture::start();
            let no_provider = "down.history-tests.com.";

            rt.block_on(lookup(&query(no_provider, RecordType::A)));
            assert_event(
                &only_event(&capture, no_provider),
                Route::Failed,
                "",
                ResponseCode::ServFail,
            );

            crate::state::clear_state();
            let not_ready = "starting.history-tests.com.";
            rt.block_on(lookup(&query(not_ready, RecordType::A)));
            assert_event(
                &only_event(&capture, not_ready),
                Route::Failed,
                "",
                ResponseCode::ServFail,
            );
            drop(capture);
            drop(state_guard);
        }

        #[test]
        fn history_records_refused_and_malformed_requests_as_invalid() {
            let rt = runtime();
            let capture = capture::start();

            let mut update = query("update.history-tests.com.", RecordType::A);
            update.metadata.op_code = OpCode::Update;

            let mut chaos = Message::query();
            let mut q = DnsQuery::new();
            q.set_name(Name::from_str("chaos.history-tests.com.").unwrap())
                .set_query_type(RecordType::TXT)
                .set_query_class(DNSClass::CH);
            chaos.add_query(q);

            let mut edns_v1 = query("edns1.history-tests.com.", RecordType::A);
            let mut edns = Edns::new();
            edns.set_version(1);
            edns_v1.edns = Some(edns);

            let mut two_questions = query("first.history-tests.com.", RecordType::A);
            two_questions.add_query(DnsQuery::query(
                Name::from_str("second.history-tests.com.").unwrap(),
                RecordType::A,
            ));

            for (req, name, rcode) in [
                (update, "update.history-tests.com.", ResponseCode::NotImp),
                (chaos, "chaos.history-tests.com.", ResponseCode::Refused),
                (edns_v1, "edns1.history-tests.com.", ResponseCode::BADVERS),
                (
                    two_questions,
                    "first.history-tests.com.",
                    ResponseCode::FormErr,
                ),
            ] {
                rt.block_on(lookup(&req));
                assert_event(&only_event(&capture, name), Route::Invalid, "", rcode);
            }
        }

        #[test]
        fn history_skips_probes_control_challenges_and_unanswered_input() {
            let rt = runtime();
            let _session = crate::proxy_control::test_lock();
            crate::proxy_control::clear();
            let capture = capture::start();
            let hex32 = "d".repeat(32);
            let challenge = format!("{hex32}.{hex32}.u._probe.macdns.");

            let refused = rt.block_on(lookup(&query(&challenge, RecordType::TXT)));
            assert_eq!(
                refused.metadata.response_code,
                ResponseCode::Refused,
                "test setup must answer the challenge"
            );
            for name in ["_probe.macdns.", "history.x._probe.macdns."] {
                rt.block_on(lookup(&query(name, RecordType::A)));
            }
            let mut response = query("response.history-tests.com.", RecordType::A);
            response.metadata.message_type = MessageType::Response;
            let unanswered = rt.block_on(lookup_wire(&response.to_bytes().unwrap()));
            assert!(
                unanswered.is_empty(),
                "test setup must send unanswerable input"
            );

            for name in [
                challenge.as_str(),
                "_probe.macdns.",
                "history.x._probe.macdns.",
                "response.history-tests.com.",
            ] {
                assert!(
                    capture.events_for(name).is_empty(),
                    "{name} is not a client lookup"
                );
            }
        }

        /// RFC 6147: a synthesized AAAA takes the route and provider of the A
        /// answer it was built from, per the spec's Routes table. The AAAA
        /// NODATA it replaces came from another provider, so the test tells
        /// the two apart.
        #[test]
        fn history_records_a_dns64_synthesis_under_the_route_of_its_a_answer() {
            use crate::dns64::Nat64Prefix;
            use crate::network_profile::{Nat64Active, Nat64Status};
            let rt = runtime();
            let (_state, state) = install(route_test_state());
            state.network.set_nat64_for_test(Nat64Status::Present {
                active: Nat64Active {
                    prefixes: vec![Nat64Prefix::new(
                        std::net::Ipv6Addr::from_str("64:ff9b::").unwrap(),
                        96,
                    )
                    .unwrap()],
                    expires_at: Instant::now() + Duration::from_secs(300),
                },
                resolver: "172.20.10.1:53".parse().unwrap(),
            });
            let cases = [
                ("v4only.history-tests.com", false, Route::Cache),
                ("v4only-stale.history-tests.com", true, Route::Stale),
            ];
            for (domain, expired, _) in cases {
                let name = format!("{domain}.");
                let mut nodata = Message::response(0, OpCode::Query);
                nodata.queries.push(DnsQuery::query(
                    Name::from_str(&name).unwrap(),
                    RecordType::AAAA,
                ));
                nodata.add_authority(Record::from_rdata(
                    Name::from_str("history-tests.com.").unwrap(),
                    60,
                    RData::SOA(SOA::new(
                        Name::from_str("ns.history-tests.com.").unwrap(),
                        Name::from_str("hostmaster.history-tests.com.").unwrap(),
                        1,
                        3600,
                        600,
                        86400,
                        60,
                    )),
                ));
                let mut a = CachedEntry::scaffold(positive(&name, 300), "Cloudflare".into());
                a.original_ttl_secs = 300;
                a.expires_at = if expired {
                    Instant::now() - Duration::from_secs(1)
                } else {
                    Instant::now() + Duration::from_secs(300)
                };
                rt.block_on(async {
                    state
                        .cache
                        .inner_insert_raw(CacheKey::from(domain, RecordType::A), a)
                        .await;
                    state
                        .cache
                        .insert_neg(
                            CacheKey::from(domain, RecordType::AAAA),
                            CachedEntry::scaffold(nodata, "Quad9".into()),
                            60,
                        )
                        .await;
                });
            }
            let capture = capture::start();

            for (domain, _, route) in cases {
                let reply = rt.block_on(lookup(&query(&format!("{domain}."), RecordType::AAAA)));

                assert_eq!(
                    reply.answers.len(),
                    1,
                    "test setup must synthesize {domain}"
                );
                let event = only_event(&capture, domain);
                assert_event(&event, route, "Cloudflare", ResponseCode::NoError);
                assert_eq!(event.qtype, u16::from(RecordType::AAAA));
            }
        }

        /// DNS names compare without case, so a probe in any case is still a
        /// probe for the reply log, as it is for the history.
        #[test]
        fn reply_log_skips_probe_names_in_any_case() {
            use std::cell::RefCell;
            use std::ffi::{c_char, CStr};

            thread_local! {
                static LOGGED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
            }
            extern "C" fn capture_reply(
                domain: *const c_char,
                _: *const c_char,
                _: *const c_char,
                _: u32,
                _: *const c_char,
                _: *const c_char,
            ) {
                // SAFETY: the reply callback owns a valid C string for this call.
                let domain = unsafe { CStr::from_ptr(domain) }.to_string_lossy();
                LOGGED.with(|logged| logged.borrow_mut().push(domain.into_owned()));
            }
            crate::log_hooks::set_reply_callback(capture_reply);

            for name in [
                "_PROBE.macdns.",
                "History.X._Probe.MacDNS.",
                "logged.history-tests.com.",
            ] {
                let mut reply = query(name, RecordType::A);
                reply.metadata.message_type = MessageType::Response;
                super::super::log_reply(&reply, Some("Test"));
            }

            let logged = LOGGED.with(|logged| logged.borrow().clone());
            assert_eq!(logged, ["logged.history-tests.com."]);
        }

        #[test]
        fn prefetch_refill_records_nothing() {
            let rt = runtime();
            let upstream = rt.block_on(crate::test_dns_server::spawn_a_server(
                std::net::Ipv4Addr::new(9, 9, 9, 3),
                Duration::ZERO,
            ));
            let state = Arc::new(route_test_state_with_pool(ProviderPool::for_local_test(
                vec![Provider::for_local_test_with_conns(upstream, 2)],
            )));
            let name = "refill.history-tests.com.";
            let key = CacheKey::from("refill.history-tests.com", RecordType::A);
            let refresh_state = rt
                .block_on(state.cache.insert_returning_state(
                    key.clone(),
                    CachedEntry::scaffold(positive(name, 300), "Test".into()),
                    300,
                ))
                .unwrap();
            refresh_state
                .try_start(RefreshSource::PeriodicPrefetch)
                .unwrap();
            let generation = PolicyGeneration::capture(&state);
            let capture = capture::start();

            let outcome = rt.block_on(prefetch_refill(
                state.clone(),
                key,
                Name::from_str(name).unwrap(),
                RecordType::A,
                refresh_state,
                generation,
                CancellationToken::new(),
            ));

            assert_eq!(outcome, PrefetchOutcome::Refilled, "test setup must refill");
            assert!(capture.events_for(name).is_empty());
        }
    }
}
