// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! Transport adapter that stamps the CD (Checking Disabled) header bit on
//! every upstream query, plus the upstream stack the provider connection
//! slots are built from.
//!
//! hickory 0.26 exposes DO through `DnsRequestOptions` but not CD, and the
//! only CD writer is `DnssecDnsHandle`, which hardcodes `CD=0` because it
//! assumes it is the validator. The provider validates, not MacDNS, so CD
//! needs an owner of its own. `CD=0` asks the provider to validate and refuse
//! bogus answers. `CD=1` asks it to hand the data over regardless.
//!
//! CD is per-query (RFC 4035 3.2.2). The client's own bit decides, and the
//! DNSSEC toggle only supplies the value for clients that left it clear.
//! `DnsRequestOptions` carries no CD field, so a single `CachingClient` cannot
//! serve both values. `ProviderUpstream` therefore holds one `CachingClient`
//! per CD value over a single shared `NameServerPool` (both variants reuse
//! the same connections and the same in-flight table), and
//! `ProviderUpstream::lookup` picks between them per query.
//!
//! The adapter sits between `CachingClient` and the pool rather than below the
//! connection, and that placement is load-bearing. `NameServerPool::send`
//! memoises in-flight requests under a key that includes `checking_disabled`
//! (`CacheKey` in `name_server_pool.rs`). Stamping CD below that point would
//! leave every key reading `CD=0`, so a `CD=1` and a `CD=0` query for the same
//! name in flight together would share one upstream request, handing
//! unvalidated data to a client that asked for validation.
//!
//! Overriding `send` rather than `lookup` means `NameServerPool::lookup` is
//! bypassed, and with it the one thing it does beyond the default: copying
//! `PoolContext::options.case_randomization` into the per-request options.
//! Both `opts()` and `request_options()` keep that flag off, so the two paths
//! are equivalent today. `case_randomization_stays_off_on_both_sides` fails if
//! that stops being true.
//!
//! DO is not set here. `request_options` owns it and sets it unconditionally.
//! A second DO writer can stamp it correctly on the wire and still lose every
//! RRSIG record, because `CachingClient` filters on the request options.
//!
//! `DnsHandle` is documented by hickory as an extension point, so this needs
//! no patch or fork. Nothing below the adapter writes CD again, so its value
//! is final. Re-enabling `ResolverOpts::validate` would not restore `CD=0` on
//! its own.
use hickory_proto::op::{DnsRequest, DnsRequestOptions, Query};
use hickory_resolver::caching_client::CachingClient;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::DnsHandle;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::NameServerPool;

/// The upstream every provider connection slot holds: hickory's
/// `CachingClient` over a `NameServerPool`, assembled here instead of via
/// `Resolver`, once per CD value.
///
/// `Resolver` is the only layer that couples the DO bit to local validation:
/// it derives `DnsRequestOptions::edns_set_dnssec_ok` from
/// `ResolverOpts::validate` (`resolver.rs:360`), and `CachingClient` then
/// strips every DNSSEC record from the response when that flag is false
/// (`maybe_strip_dnssec_records` in `caching_client.rs`). Both
/// `request_options` and `inner_lookup` are `pub(crate)`, so the two cannot be
/// separated through that API. Assembling the stack here gives the options per
/// call and drops `DnssecDnsHandle`, which is what removes local validation,
/// while keeping `CachingClient`'s CNAME chasing, record filtering, and TTL
/// clamping, and keeping `Lookup` as the result type so nothing downstream
/// changes.
pub(crate) struct ProviderUpstream<H: DnsHandle = NameServerPool<TokioRuntimeProvider>> {
    /// `CD=0`: the provider validates and refuses bogus answers.
    validating: CachingClient<CheckingDisabled<H>>,
    /// `CD=1`: the provider hands the data over unvalidated.
    unchecked: CachingClient<CheckingDisabled<H>>,
    /// What a client that left CD clear gets. This is the inverse of the
    /// user-facing DNSSEC toggle: toggle on means "provider, validate for me"
    /// (`CD=0`), toggle off means "hand me the data even if it fails
    /// validation" (`CD=1`).
    default_checking_disabled: bool,
}

impl<H: DnsHandle> ProviderUpstream<H> {
    /// `handle` is cloned once per CD variant. For a `NameServerPool` that
    /// clone shares the pool state, so the two variants are two views of one
    /// set of connections, not two sets.
    pub(crate) fn new(
        handle: H,
        cache_size: u64,
        preserve_intermediates: bool,
        dnssec_enabled: bool,
    ) -> Self {
        Self {
            validating: CachingClient::new(
                cache_size,
                CheckingDisabled::new(handle.clone(), false),
                preserve_intermediates,
            ),
            unchecked: CachingClient::new(
                cache_size,
                CheckingDisabled::new(handle, true),
                preserve_intermediates,
            ),
            default_checking_disabled: !dnssec_enabled,
        }
    }

    /// `client_checking_disabled` is the CD bit the client set on its own
    /// query. A client that set it always reaches the provider with `CD=1`. A
    /// client that left it clear reaches the provider with whatever the DNSSEC
    /// toggle asks for. Internal callers with no client behind them (warm-up,
    /// keepalive probes) pass `false` and so follow the toggle.
    ///
    /// The bit selects the client, never the connection. Both clients share
    /// one pool, so honouring CD costs no extra sockets or handshakes.
    pub(crate) async fn lookup(
        &self,
        query: Query,
        options: DnsRequestOptions,
        client_checking_disabled: bool,
    ) -> Result<Lookup, NetError> {
        if client_checking_disabled || self.default_checking_disabled {
            self.unchecked.lookup(query, options).await
        } else {
            self.validating.lookup(query, options).await
        }
    }
}

/// Per-request options for an upstream query. `edns_set_dnssec_ok` is the DO
/// bit and it is unconditionally true.
///
/// RFC 4035 3.2.1 requires the resolver side of a recursive server to set DO
/// "regardless of the state of the DO bit in the initiating request", and the
/// reason is the cache. `CachingClient` strips DNSSEC records before returning
/// the `Lookup` when this flag is false (`maybe_strip_dnssec_records` in
/// `caching_client.rs`), and the reduced message is what MacDNS's own
/// name/type-keyed cache then stores. One client without `+dnssec` would
/// decide what every later client can see.
///
/// Whether a given client sees those records is decided on the way out, in
/// `finalize_wire`. CD is not here either. It is per-query and belongs to
/// `ProviderUpstream::lookup` above.
pub(crate) fn request_options() -> DnsRequestOptions {
    let mut options = DnsRequestOptions::default();
    options.use_edns = true;
    options.edns_payload_len = 1232;
    options.edns_set_dnssec_ok = true;
    options.recursion_desired = true;
    options.case_randomization = false;
    options
}

pub(crate) type LookupResult = Result<Result<Lookup, NetError>, tokio::time::error::Elapsed>;

/// Reports transport evidence without treating local capacity or cancellation as a DNS answer.
pub(crate) fn lookup_diagnostics(result: &LookupResult) -> String {
    let error = match result {
        Ok(Ok(lookup)) => {
            return format!(
                "outcome=response rcode={:?} answers={} authority={}",
                lookup.message().metadata.response_code,
                lookup.message().answers.len(),
                lookup.message().authorities.len(),
            )
        }
        Ok(Err(error)) => error,
        Err(_) => return "outcome=timeout source=deadline".into(),
    };
    let fields = match error {
        NetError::Timeout => return "outcome=timeout source=resolver".into(),
        NetError::Busy => return "outcome=busy".into(),
        NetError::NoConnections => return "outcome=no_connections".into(),
        NetError::Dns(DnsError::NoRecordsFound(negative)) => return format!(
            "outcome=dns_negative rcode={:?}", negative.response_code,
        ),
        NetError::Dns(DnsError::ResponseCode(rcode, _)) => return format!(
            "outcome=dns_error rcode={rcode:?}",
        ),
        NetError::Dns(_) => return "outcome=dns_error".into(),
        NetError::HttpStatus { status } => return format!("outcome=http http_status={status}"),
        NetError::ForeignClassRecord { .. } | NetError::Proto(_) => {
            return format!("outcome={}", error.as_metrics_label());
        }
        NetError::H2(h2) => format!(
            "outcome=h2 h2_reason={:?} h2_goaway={} h2_reset={} h2_remote={} h2_library={} io_kind={:?} os_error={:?}",
            h2.reason(), h2.is_go_away(), h2.is_reset(), h2.is_remote(), h2.is_library(),
            h2.get_io().map(std::io::Error::kind), h2.get_io().and_then(std::io::Error::raw_os_error),
        ),
        NetError::Io(io) => format!(
            "outcome=io io_kind={:?} os_error={:?}", io.kind(), io.raw_os_error(),
        ),
        NetError::RustlsError(_) => "outcome=tls".into(),
        _ => "outcome=error".into(),
    };
    // Upstream error text is untrusted and may contain control characters.
    let detail = error.to_string();
    if detail.contains("DNSSEC Negative Record Response") {
        return "outcome=dns_error kind=dnssec_negative_record_response".into();
    }
    // Budget escaped UTF-8 bytes, leaving room for correlation and typed fields in host logs.
    let mut escaped = String::new();
    let mut truncated = false;
    for ch in detail.chars() {
        let next = ch.escape_debug().to_string();
        if escaped.len() + next.len() > 256 {
            truncated = true;
            break;
        }
        escaped.push_str(&next);
    }
    format!("{fields} error_truncated={truncated} error=\"{escaped}\"")
}

/// Writes CD on every request travelling from a `CachingClient` down to the
/// pool. One instance carries one value, and `ProviderUpstream` owns both.
#[derive(Clone)]
pub(crate) struct CheckingDisabled<H> {
    inner: H,
    checking_disabled: bool,
}

impl<H> CheckingDisabled<H> {
    fn new(inner: H, checking_disabled: bool) -> Self {
        Self {
            inner,
            checking_disabled,
        }
    }
}

impl<H: DnsHandle> DnsHandle for CheckingDisabled<H> {
    type Response = H::Response;
    type Runtime = H::Runtime;

    fn is_verifying_dnssec(&self) -> bool {
        self.inner.is_verifying_dnssec()
    }

    fn is_using_edns(&self) -> bool {
        self.inner.is_using_edns()
    }

    fn send(&self, mut request: DnsRequest) -> Self::Response {
        request.metadata.checking_disabled = self.checking_disabled;
        self.inner.send(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{ns_cfg, opts};
    use hickory_proto::op::{DnsResponse, Message, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use hickory_resolver::config::ConnectionConfig;
    use hickory_resolver::net::DnsError;
    use hickory_resolver::{ConnectionProvider, PoolContext, TlsConfig};
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    #[test]
    fn diagnostics_preserve_transport_evidence() {
        let io = NetError::from(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        let diagnostic = lookup_diagnostics(&Ok(Err(io)));
        assert!(diagnostic.contains("outcome=io io_kind=ConnectionReset"));
        let h2 = NetError::from(h2::Error::from(h2::Reason::REFUSED_STREAM));
        let diagnostic = lookup_diagnostics(&Ok(Err(h2)));
        assert!(diagnostic.contains("outcome=h2 h2_reason=Some(REFUSED_STREAM)"));
        assert!(
            diagnostic.contains("h2_remote=false"),
            "a reason alone is not evidence of a remote frame"
        );
        assert_eq!(lookup_diagnostics(&Ok(Err(NetError::Busy))), "outcome=busy");
        assert_eq!(
            lookup_diagnostics(&Ok(Err(NetError::NoConnections))),
            "outcome=no_connections"
        );
        assert_eq!(
            lookup_diagnostics(&Ok(Err(NetError::Timeout))),
            "outcome=timeout source=resolver"
        );
    }

    #[tokio::test]
    async fn diagnostics_recognize_remote_h2_reset_and_goaway_frames() {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            for reset in [true, false] {
                let (client_io, server_io) = tokio::io::duplex(4096);
                let server = tokio::spawn(async move {
                    let mut connection = h2::server::handshake(server_io).await.unwrap();
                    if reset {
                        let (_, mut response) = connection.accept().await.unwrap().unwrap();
                        response.send_reset(h2::Reason::REFUSED_STREAM);
                    } else {
                        connection.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM);
                    }
                    while let Some(result) = connection.accept().await {
                        if result.is_err() {
                            break;
                        }
                    }
                });
                let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
                let driver = tokio::spawn(connection);
                let request = http::Request::builder()
                    .uri("https://example.invalid/dns-query")
                    .body(())
                    .unwrap();
                let (response, _) = client.send_request(request, true).unwrap();
                let error = NetError::from(response.await.unwrap_err());
                driver.abort();
                server.abort();
                let diagnostic = lookup_diagnostics(&Ok(Err(error)));
                assert!(
                    diagnostic.contains("h2_remote=true"),
                    "reset={reset} {diagnostic}"
                );
                assert!(
                    diagnostic.contains(&format!("h2_reset={reset}")),
                    "{diagnostic}"
                );
                assert!(
                    diagnostic.contains(&format!("h2_goaway={}", !reset)),
                    "{diagnostic}"
                );
                let reason = if reset {
                    "REFUSED_STREAM"
                } else {
                    "ENHANCE_YOUR_CALM"
                };
                assert!(
                    diagnostic.contains(&format!("h2_reason=Some({reason})")),
                    "{diagnostic}"
                );
            }
        })
        .await
        .expect("local H2 frames must complete without network access");
    }

    #[test]
    fn diagnostics_bound_and_escape_errors_before_the_host_callback() {
        let error = NetError::from(format!("broken\n\0\t\"{}", "α\u{1}".repeat(600)));
        let lines = crate::log_hooks::capture_logs(|| {
            log::info!("{}", lookup_diagnostics(&Ok(Err(error))));
        });
        assert_eq!(
            lines.len(),
            1,
            "embedded NUL must not discard the whole log at FFI"
        );
        let message = &lines[0].1;
        assert!(message.contains("error_truncated=true"));
        assert!(message.contains("\\n\\0\\t\\\""));
        assert!(!message.contains(['\n', '\0', '\t']));
        assert!(message.len() <= 512, "{} UTF-8 bytes", message.len());
        assert!(message.ends_with('"'));
    }

    #[test]
    fn dns_diagnostics_do_not_log_query_names_or_answers() {
        let name = Name::from_ascii("private.example.").unwrap();
        let lookup = Lookup::from_rdata(
            Query::query(name, RecordType::A),
            RData::A(A::new(192, 0, 2, 1)),
        );
        let diagnostic = lookup_diagnostics(&Ok(Ok(lookup)));
        assert_eq!(
            diagnostic,
            "outcome=response rcode=NoError answers=1 authority=0"
        );
        let error = NetError::from(
            "DNS error: DNSSEC Negative Record Response for private.example. IN A, Bogus",
        );
        assert_eq!(
            lookup_diagnostics(&Ok(Err(error))),
            "outcome=dns_error kind=dnssec_negative_record_response"
        );
        let error = NetError::ForeignClassRecord {
            record_name: Name::from_ascii("private.example.").unwrap(),
            record_class: hickory_proto::rr::DNSClass::CH,
            record_type: RecordType::A,
        };
        assert_eq!(
            lookup_diagnostics(&Ok(Err(error))),
            "outcome=foreign_class_record"
        );
        let error = NetError::HttpStatus { status: 429 };
        assert_eq!(
            lookup_diagnostics(&Ok(Err(error))),
            "outcome=http http_status=429"
        );
    }

    #[derive(Clone)]
    struct SpyHandle {
        seen: Arc<Mutex<Vec<bool>>>,
    }

    impl DnsHandle for SpyHandle {
        type Response = futures::stream::Empty<Result<DnsResponse, NetError>>;
        type Runtime = TokioRuntimeProvider;

        fn send(&self, request: DnsRequest) -> Self::Response {
            self.seen
                .lock()
                .unwrap()
                .push(request.metadata.checking_disabled);
            futures::stream::empty()
        }
    }

    fn query_request() -> DnsRequest {
        let mut message = Message::query();
        message.queries.push(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        DnsRequest::from(message)
    }

    #[test]
    fn handle_sets_checking_disabled() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut request = query_request();
        request.metadata.checking_disabled = false;
        let handle = CheckingDisabled::new(SpyHandle { seen: seen.clone() }, true);
        let _ = handle.send(request);
        assert_eq!(*seen.lock().unwrap(), vec![true]);
    }

    /// The adapter decides CD for the client it belongs to. Whatever a layer
    /// above set must be overwritten, not merged.
    #[test]
    fn handle_clears_checking_disabled_set_upstack() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut request = query_request();
        request.metadata.checking_disabled = true;
        let handle = CheckingDisabled::new(SpyHandle { seen: seen.clone() }, false);
        let _ = handle.send(request);
        assert_eq!(*seen.lock().unwrap(), vec![false]);
    }

    /// Overriding `send` skips `NameServerPool::lookup`, whose only extra step
    /// is copying `case_randomization` from the pool options into the request
    /// options. Both sides keep it off, so the skip is a no-op. This test is
    /// the tripwire for either one turning it on.
    #[test]
    fn case_randomization_stays_off_on_both_sides() {
        assert!(!opts().case_randomization);
        assert!(!request_options().case_randomization);
    }

    /// Answers every query with one A record plus one RRSIG-typed record, and
    /// records the DO and CD bits it was asked with. One mock covers both
    /// halves of the contract: that the bits reached the wire, and that the
    /// DNSSEC record survived the response path back to the caller.
    #[derive(Clone)]
    struct SignedAnswerProvider {
        runtime: TokioRuntimeProvider,
        seen_bits: Arc<Mutex<Vec<(bool, bool)>>>,
    }

    fn signed_response(query: &Query) -> DnsResponse {
        let mut message = Message::response(0, OpCode::Query);
        message.queries.push(query.clone());
        message.add_answer(Record::from_rdata(
            query.name().clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        // A record whose type is a DNSSEC type other than the query type,
        // exactly what `maybe_strip_dnssec_records` removes when DO is unset.
        // `update0` is the public constructor that sets a record's type without
        // requiring matching RData. `Record::record_type()` derives from RData,
        // so `from_rdata` could not produce an RRSIG-typed record here.
        message.add_answer(Record::update0(
            query.name().clone(),
            300,
            RecordType::RRSIG,
        ));
        DnsResponse::from_message(message).expect("build signed response")
    }

    impl ConnectionProvider for SignedAnswerProvider {
        type Conn = SignedAnswerHandle;
        type FutureConn =
            Pin<Box<dyn Future<Output = Result<Self::Conn, NetError>> + Send + 'static>>;
        type RuntimeProvider = TokioRuntimeProvider;

        fn new_connection(
            &self,
            _ip: IpAddr,
            _config: &ConnectionConfig,
            _cx: &PoolContext,
        ) -> Result<Self::FutureConn, NetError> {
            let seen_bits = self.seen_bits.clone();
            Ok(Box::pin(
                async move { Ok(SignedAnswerHandle { seen_bits }) },
            ))
        }

        fn runtime_provider(&self) -> &Self::RuntimeProvider {
            &self.runtime
        }
    }

    #[derive(Clone)]
    struct SignedAnswerHandle {
        seen_bits: Arc<Mutex<Vec<(bool, bool)>>>,
    }

    impl DnsHandle for SignedAnswerHandle {
        type Response =
            futures::stream::Once<futures::future::Ready<Result<DnsResponse, NetError>>>;
        type Runtime = TokioRuntimeProvider;

        fn send(&self, request: DnsRequest) -> Self::Response {
            self.seen_bits.lock().unwrap().push((
                request
                    .edns
                    .as_ref()
                    .map(|e| e.flags().dnssec_ok)
                    .unwrap_or(false),
                request.metadata.checking_disabled,
            ));
            let query = request
                .queries
                .first()
                .cloned()
                .expect("request has a query");
            futures::stream::once(futures::future::ready(Ok(signed_response(&query))))
        }
    }

    fn mock_upstream(
        dnssec_enabled: bool,
        seen_bits: Arc<Mutex<Vec<(bool, bool)>>>,
    ) -> ProviderUpstream<NameServerPool<SignedAnswerProvider>> {
        let options = opts();
        let preserve_intermediates = options.preserve_intermediates;
        let cache_size = options.cache_size;
        let cx = Arc::new(PoolContext::new(
            options,
            TlsConfig::new().expect("build TLS config"),
        ));
        let pool = NameServerPool::from_config(
            [ns_cfg(
                "127.0.0.1".parse().unwrap(),
                "example.invalid",
                "/dns-query",
            )],
            cx,
            SignedAnswerProvider {
                runtime: TokioRuntimeProvider::default(),
                seen_bits,
            },
        );
        ProviderUpstream::new(pool, cache_size, preserve_intermediates, dnssec_enabled)
    }

    /// Returns (DO seen on the wire, CD seen on the wire, RRSIG records
    /// reaching the caller).
    async fn wire_bits_and_delivered_rrsigs(
        dnssec_enabled: bool,
        client_checking_disabled: bool,
    ) -> (bool, bool, usize) {
        let seen_bits = Arc::new(Mutex::new(Vec::new()));
        let upstream = mock_upstream(dnssec_enabled, seen_bits.clone());
        let lookup = upstream
            .lookup(
                Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A),
                request_options(),
                client_checking_disabled,
            )
            .await
            .expect("mock upstream answers");
        let rrsigs = lookup
            .message()
            .all_sections()
            .filter(|r| r.record_type() == RecordType::RRSIG)
            .count();
        let (wire_do, wire_cd) = *seen_bits
            .lock()
            .unwrap()
            .first()
            .expect("no request reached the wire");
        (wire_do, wire_cd, rrsigs)
    }

    /// Two halves, one test. DO must reach the wire, and the RRSIG the
    /// provider sent must survive back to the caller. Asserting only the first
    /// misses the regression where `CachingClient` drops the record because the
    /// request options do not say DO, whatever the transport stamped.
    #[tokio::test]
    async fn toggle_on_sets_wire_do_and_delivers_dnssec_records() {
        assert_eq!(
            wire_bits_and_delivered_rrsigs(true, false).await,
            (true, false, 1)
        );
    }

    /// RFC 4035 3.2.1: the resolver side MUST set DO "regardless of the state
    /// of the DO bit in the initiating request". The toggle governs the default
    /// CD, and only CD. Asking for fewer records upstream would make the shared
    /// cache depend on whichever client queried first. Whether a given client
    /// sees them is decided later, in `finalize_wire`.
    #[tokio::test]
    async fn toggle_off_still_sets_wire_do_and_delivers_dnssec_records() {
        assert_eq!(
            wire_bits_and_delivered_rrsigs(false, false).await,
            (true, true, 1)
        );
    }

    /// RFC 4035 3.2.2: CD belongs to the query, not to the resolver's own
    /// policy. A client asking for unvalidated data must reach the provider
    /// with `CD=1` even while the toggle would have asked the provider to
    /// validate. Otherwise the client gets the provider's SERVFAIL for bogus
    /// zones instead of the data it asked for.
    #[tokio::test]
    async fn toggle_on_forwards_the_client_checking_disabled_bit() {
        assert_eq!(
            wire_bits_and_delivered_rrsigs(true, true).await,
            (true, true, 1)
        );
    }

    /// Answers every query the way a recursive provider answers an alias
    /// with no record of the asked type: the CNAME in the answer section and
    /// the target zone's SOA in the authority section, in one response.
    #[derive(Clone)]
    struct CnameNodataProvider {
        runtime: TokioRuntimeProvider,
        sends: Arc<std::sync::atomic::AtomicUsize>,
    }

    fn cname_nodata_response(query: &Query) -> DnsResponse {
        let mut message = Message::response(0, OpCode::Query);
        message.queries.push(query.clone());
        message.add_answer(Record::from_rdata(
            query.name().clone(),
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(
                Name::from_ascii("target.cdn.example.").unwrap(),
            )),
        ));
        message.add_authority(Record::from_rdata(
            Name::from_ascii("cdn.example.").unwrap(),
            60,
            RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::from_ascii("ns.cdn.example.").unwrap(),
                Name::from_ascii("hostmaster.cdn.example.").unwrap(),
                1,
                3600,
                600,
                604800,
                60,
            )),
        ));
        DnsResponse::from_message(message).expect("build CNAME NODATA response")
    }

    impl ConnectionProvider for CnameNodataProvider {
        type Conn = CnameNodataHandle;
        type FutureConn =
            Pin<Box<dyn Future<Output = Result<Self::Conn, NetError>> + Send + 'static>>;
        type RuntimeProvider = TokioRuntimeProvider;

        fn new_connection(
            &self,
            _ip: IpAddr,
            _config: &ConnectionConfig,
            _cx: &PoolContext,
        ) -> Result<Self::FutureConn, NetError> {
            let sends = self.sends.clone();
            Ok(Box::pin(async move { Ok(CnameNodataHandle { sends }) }))
        }

        fn runtime_provider(&self) -> &Self::RuntimeProvider {
            &self.runtime
        }
    }

    #[derive(Clone)]
    struct CnameNodataHandle {
        sends: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl DnsHandle for CnameNodataHandle {
        type Response =
            futures::stream::Once<futures::future::Ready<Result<DnsResponse, NetError>>>;
        type Runtime = TokioRuntimeProvider;

        fn send(&self, request: DnsRequest) -> Self::Response {
            self.sends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let query = request
                .queries
                .first()
                .cloned()
                .expect("request has a query");
            futures::stream::once(futures::future::ready(Ok(cname_nodata_response(&query))))
        }
    }

    /// RFC 2308 §2.2: a response carrying the alias chain and the target
    /// zone's SOA has already proved the target empty. Chasing the target with
    /// a second query would cost two round trips per provider, and reporting
    /// the negative without the chain shows NODATA for a name that exists as
    /// an alias.
    #[tokio::test]
    async fn cname_chain_with_a_terminal_soa_is_a_negative_in_one_query() {
        let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let options = opts();
        let cx = Arc::new(PoolContext::new(
            options.clone(),
            TlsConfig::new().expect("build TLS config"),
        ));
        let pool = NameServerPool::from_config(
            [ns_cfg(
                "127.0.0.1".parse().unwrap(),
                "example.invalid",
                "/dns-query",
            )],
            cx,
            CnameNodataProvider {
                runtime: TokioRuntimeProvider::default(),
                sends: sends.clone(),
            },
        );
        let upstream = ProviderUpstream::new(
            pool,
            options.cache_size,
            options.preserve_intermediates,
            true,
        );
        let alias = Name::from_ascii("www.example.com.").unwrap();

        let error = upstream
            .lookup(
                Query::query(alias.clone(), RecordType::AAAA),
                request_options(),
                false,
            )
            .await
            .expect_err("an alias with no AAAA is a negative answer");

        let NetError::Dns(hickory_resolver::net::DnsError::NoRecordsFound(no_records)) = &error
        else {
            panic!("expected NoRecordsFound, got {error:?}");
        };
        assert_eq!(
            no_records.query.name(),
            &Name::from_ascii("target.cdn.example.").unwrap(),
            "the negative is about the chain's target"
        );
        assert_eq!(no_records.response_code, ResponseCode::NoError);
        assert!(
            no_records.soa.is_some(),
            "the SOA proof must travel with it"
        );
        let chain = no_records
            .cname_chain
            .as_deref()
            .expect("the CNAME chain must travel with the negative");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].name, alias);
        assert_eq!(
            sends.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the response already proved the target empty"
        );
    }

    fn a_reply(query: Message, ttl: u32) -> Message {
        let mut message = Message::response(query.metadata.id, OpCode::Query);
        let question = query.queries[0].clone();
        message.add_answer(Record::from_rdata(
            question.name().clone(),
            ttl,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
        ));
        message.queries.push(question);
        message
    }

    /// RFC 8484 §5.1: a DoH response that sat in an HTTP cache already aged by
    /// the `Age` header's value. Its DNS TTLs must be reduced by that much, or
    /// the answer outlives what the authority granted.
    #[tokio::test]
    async fn http_age_reduces_the_dns_ttls() {
        let server = crate::doh_test_server::DohServer::start(
            Arc::new(|query| crate::doh_test_server::Reply {
                headers: vec![("age", "120".into())],
                message: a_reply(query, 300),
            }),
            None,
        )
        .await;

        let lookup = server
            .upstream()
            .lookup(
                Query::query(
                    Name::from_ascii("aged.example.com.").unwrap(),
                    RecordType::A,
                ),
                request_options(),
                false,
            )
            .await
            .expect("local DoH server answers");

        assert_eq!(lookup.answers()[0].ttl, 180);
    }

    #[tokio::test]
    async fn http_age_beyond_the_ttl_leaves_a_zero_ttl() {
        let server = crate::doh_test_server::DohServer::start(
            Arc::new(|query| crate::doh_test_server::Reply {
                headers: vec![("age", "900".into())],
                message: a_reply(query, 300),
            }),
            None,
        )
        .await;

        let lookup = server
            .upstream()
            .lookup(
                Query::query(
                    Name::from_ascii("expired.example.com.").unwrap(),
                    RecordType::A,
                ),
                request_options(),
                false,
            )
            .await
            .expect("local DoH server answers");

        assert_eq!(lookup.answers()[0].ttl, 0);
    }

    const LARGE_TXT_RECORDS: usize = 220;

    /// About 59 KiB of TXT records. Half of two of these nearly fills the
    /// 64 KiB HTTP/2 connection window, so neither second half fits after.
    fn large_txt_reply(query: Message) -> Message {
        let mut message = Message::response(query.metadata.id, OpCode::Query);
        let question = query.queries[0].clone();
        for _ in 0..LARGE_TXT_RECORDS {
            message.add_answer(Record::from_rdata(
                question.name().clone(),
                300,
                RData::TXT(hickory_proto::rr::rdata::TXT::new(vec!["x".repeat(255)])),
            ));
        }
        message.queries.push(question);
        message
    }

    /// RFC 9113 §6.9: a receiver returns flow-control credit as it consumes
    /// DATA. Releasing it only when a stream ends lets two large answers,
    /// whose first halves arrive before either second half, exhaust the
    /// 64 KiB connection window and stall until their deadline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn interleaved_large_responses_share_one_connection_without_stalling() {
        let halfway = Arc::new(tokio::sync::Barrier::new(2));
        let send_body: crate::doh_test_server::SendBody = Arc::new(move |mut stream, wire| {
            let halfway = halfway.clone();
            Box::pin(async move {
                let (first, second) = wire.split_at(wire.len() / 2);
                let (first, second) = (first.to_vec(), second.to_vec());
                let _ = stream.send_data(bytes::Bytes::from(first), false);
                halfway.wait().await;
                let _ = stream.send_data(bytes::Bytes::from(second), true);
                std::future::poll_fn(|cx| stream.poll_reset(cx)).await.ok();
            })
        });
        let server = crate::doh_test_server::DohServer::start(
            Arc::new(|query| crate::doh_test_server::Reply {
                headers: Vec::new(),
                message: large_txt_reply(query),
            }),
            Some(send_body),
        )
        .await;
        let upstream = server.upstream();
        let lookup = |name: &'static str| {
            upstream.lookup(
                Query::query(Name::from_ascii(name).unwrap(), RecordType::TXT),
                request_options(),
                false,
            )
        };

        let (first, second) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(lookup("one.example.com."), lookup("two.example.com."))
        })
        .await
        .expect("interleaved responses must not stall the connection");

        assert_eq!(
            first.expect("first answer").answers().len(),
            LARGE_TXT_RECORDS
        );
        assert_eq!(
            second.expect("second answer").answers().len(),
            LARGE_TXT_RECORDS
        );
        assert_eq!(
            server.connections(),
            1,
            "both answers must share one connection"
        );
    }

    type AnswerByName = Arc<dyn Fn(&Query) -> Message + Send + Sync>;

    /// Answers each query from a script keyed by the queried name, so a test
    /// can serve a CNAME chain one hop per response.
    #[derive(Clone)]
    struct ByNameProvider {
        runtime: TokioRuntimeProvider,
        respond: AnswerByName,
    }

    #[derive(Clone)]
    struct ByNameHandle {
        respond: AnswerByName,
    }

    impl ConnectionProvider for ByNameProvider {
        type Conn = ByNameHandle;
        type FutureConn =
            Pin<Box<dyn Future<Output = Result<Self::Conn, NetError>> + Send + 'static>>;
        type RuntimeProvider = TokioRuntimeProvider;

        fn new_connection(
            &self,
            _ip: IpAddr,
            _config: &ConnectionConfig,
            _cx: &PoolContext,
        ) -> Result<Self::FutureConn, NetError> {
            let respond = self.respond.clone();
            Ok(Box::pin(async move { Ok(ByNameHandle { respond }) }))
        }

        fn runtime_provider(&self) -> &Self::RuntimeProvider {
            &self.runtime
        }
    }

    impl DnsHandle for ByNameHandle {
        type Response =
            futures::stream::Once<futures::future::Ready<Result<DnsResponse, NetError>>>;
        type Runtime = TokioRuntimeProvider;

        fn send(&self, request: DnsRequest) -> Self::Response {
            let query = request
                .queries
                .first()
                .cloned()
                .expect("request has a query");
            let mut message = (self.respond)(&query);
            message.queries = vec![query];
            futures::stream::once(futures::future::ready(Ok(DnsResponse::from_message(
                message,
            )
            .expect("build scripted response"))))
        }
    }

    fn by_name_upstream(respond: AnswerByName) -> ProviderUpstream<NameServerPool<ByNameProvider>> {
        let options = opts();
        let cx = Arc::new(PoolContext::new(
            options.clone(),
            TlsConfig::new().expect("build TLS config"),
        ));
        let pool = NameServerPool::from_config(
            [ns_cfg(
                "127.0.0.1".parse().unwrap(),
                "example.invalid",
                "/dns-query",
            )],
            cx,
            ByNameProvider {
                runtime: TokioRuntimeProvider::default(),
                respond,
            },
        );
        ProviderUpstream::new(
            pool,
            options.cache_size,
            options.preserve_intermediates,
            true,
        )
    }

    fn rrsig_over(owner: &Name, covered: RecordType) -> Record {
        use hickory_proto::dnssec::rdata::{DNSSECRData, SigInput, RRSIG};
        use hickory_proto::dnssec::Algorithm;
        use hickory_proto::rr::SerialNumber;

        let input = SigInput {
            type_covered: covered,
            algorithm: Algorithm::ECDSAP256SHA256,
            num_labels: owner.num_labels(),
            original_ttl: 300,
            sig_expiration: SerialNumber::from(0),
            sig_inception: SerialNumber::from(0),
            key_tag: 1,
            signer_name: Name::root(),
        };
        Record::from_rdata(
            owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![]))),
        )
    }

    fn covered_by(record: &Record) -> Option<RecordType> {
        match &record.data {
            RData::DNSSEC(hickory_proto::dnssec::rdata::DNSSECRData::RRSIG(sig)) => {
                Some(sig.input().type_covered)
            }
            _ => None,
        }
    }

    /// `alias.example.com CNAME target.example.com` in one response and the
    /// target's A record in another, each with its RRSIG, the alias hop
    /// carrying `alias_ad` and the target hop `target_ad`.
    fn split_chain(alias_ad: bool, target_ad: bool) -> AnswerByName {
        Arc::new(move |query: &Query| {
            let alias = Name::from_ascii("alias.example.com.").unwrap();
            let target = Name::from_ascii("target.example.com.").unwrap();
            let mut message = Message::response(0, OpCode::Query);
            if query.name() == &alias {
                message.metadata.authentic_data = alias_ad;
                message.add_answer(Record::from_rdata(
                    alias.clone(),
                    300,
                    RData::CNAME(hickory_proto::rr::rdata::CNAME(target.clone())),
                ));
                message.add_answer(rrsig_over(&alias, RecordType::CNAME));
            } else {
                message.metadata.authentic_data = target_ad;
                message.add_answer(Record::from_rdata(
                    target.clone(),
                    300,
                    RData::A(A(Ipv4Addr::new(192, 0, 2, 9))),
                ));
                message.add_answer(rrsig_over(&target, RecordType::A));
            }
            message
        })
    }

    async fn resolve_alias(upstream: &ProviderUpstream<NameServerPool<ByNameProvider>>) -> Lookup {
        upstream
            .lookup(
                Query::query(
                    Name::from_ascii("alias.example.com.").unwrap(),
                    RecordType::A,
                ),
                request_options(),
                false,
            )
            .await
            .expect("the chain resolves")
    }

    /// RFC 4035 §3.2.3: AD may be set only when every RRset in the answer is
    /// authentic. A chain assembled from several responses must combine the AD
    /// of every hop, not take the last one, and keep every signature.
    #[tokio::test]
    async fn chain_from_several_responses_keeps_its_signatures_and_combines_ad() {
        let lookup = resolve_alias(&by_name_upstream(split_chain(false, true))).await;

        let answers = &lookup.message().answers;
        let covered: Vec<_> = answers.iter().filter_map(covered_by).collect();
        assert!(answers.iter().any(|r| r.record_type() == RecordType::CNAME));
        assert!(answers.iter().any(|r| r.record_type() == RecordType::A));
        assert!(
            covered.contains(&RecordType::CNAME) && covered.contains(&RecordType::A),
            "each RRset's signature must travel with it, got {covered:?}"
        );
        assert!(
            !lookup.message().metadata.authentic_data,
            "an unauthenticated alias hop makes the whole answer unauthenticated"
        );
    }

    #[tokio::test]
    async fn chain_authenticated_on_every_hop_keeps_ad() {
        let lookup = resolve_alias(&by_name_upstream(split_chain(true, true))).await;

        assert!(lookup.message().metadata.authentic_data);
    }

    /// RFC 2308 §2: a negative reached through aliases carries the chain,
    /// whether the provider sent the chain and the SOA together or the
    /// target's negative arrived in its own response.
    #[tokio::test]
    async fn chain_ending_in_a_separate_negative_response_keeps_the_chain() {
        let upstream = by_name_upstream(Arc::new(|query: &Query| {
            let alias = Name::from_ascii("alias.example.com.").unwrap();
            let target = Name::from_ascii("gone.example.net.").unwrap();
            let mut message = Message::response(0, OpCode::Query);
            if query.name() == &alias {
                message.add_answer(Record::from_rdata(
                    alias.clone(),
                    300,
                    RData::CNAME(hickory_proto::rr::rdata::CNAME(target)),
                ));
            } else {
                message.metadata.response_code = ResponseCode::NXDomain;
                message.add_authority(Record::from_rdata(
                    Name::from_ascii("example.net.").unwrap(),
                    60,
                    RData::SOA(hickory_proto::rr::rdata::SOA::new(
                        Name::from_ascii("ns.example.net.").unwrap(),
                        Name::from_ascii("hostmaster.example.net.").unwrap(),
                        1,
                        3600,
                        600,
                        604800,
                        60,
                    )),
                ));
            }
            message
        }));

        let error = upstream
            .lookup(
                Query::query(
                    Name::from_ascii("alias.example.com.").unwrap(),
                    RecordType::A,
                ),
                request_options(),
                false,
            )
            .await
            .expect_err("the target does not exist");

        let NetError::Dns(hickory_resolver::net::DnsError::NoRecordsFound(no_records)) = &error
        else {
            panic!("expected NoRecordsFound, got {error:?}");
        };
        assert_eq!(no_records.response_code, ResponseCode::NXDomain);
        let chain = no_records
            .cname_chain
            .as_deref()
            .expect("the chain must travel");
        assert!(chain.iter().any(
            |r| r.name == Name::from_ascii("alias.example.com.").unwrap()
                && r.record_type() == RecordType::CNAME
        ));
    }

    const SIGNED: &str = "cloudflare.com.";
    const BOGUS: &str = "www.dnssec-failed.org.";
    const PROVIDERS: [(&str, &str, &str); 3] = [
        ("Quad9", "9.9.9.9", "dns.quad9.net"),
        ("Cloudflare", "1.1.1.1", "cloudflare-dns.com"),
        ("Google", "8.8.8.8", "dns.google"),
    ];

    /// Always built with the DNSSEC toggle on, because that is the only
    /// setting under which the client's CD bit can still change the outcome.
    fn live_upstream(ip: IpAddr, tls: &str) -> ProviderUpstream {
        let options = opts();
        let preserve_intermediates = options.preserve_intermediates;
        let cache_size = options.cache_size;
        let cx = Arc::new(PoolContext::new(
            options,
            TlsConfig::new().expect("build TLS config"),
        ));
        let pool = NameServerPool::from_config(
            [ns_cfg(ip, tls, "/dns-query")],
            cx,
            TokioRuntimeProvider::default(),
        );
        ProviderUpstream::new(pool, cache_size, preserve_intermediates, true)
    }

    fn rrsig_count(lookup: &Lookup) -> usize {
        lookup
            .message()
            .all_sections()
            .filter(|r| r.record_type() == RecordType::RRSIG)
            .count()
    }

    /// `cloudflare.com` is DNSSEC-signed. `www.dnssec-failed.org` is Comcast's
    /// permanently bogus test zone.
    #[tokio::test]
    #[ignore = "requires public internet and reaches all three providers"]
    async fn providers_honour_the_do_and_cd_bits() {
        for (label, ip, tls) in PROVIDERS {
            let ip: IpAddr = ip.parse().expect("provider IP literal");

            // One upstream, toggle on, three queries. The CD variation below
            // is per-query, so it must not need a second upstream.
            let on = live_upstream(ip, tls);

            // DO=1: the signed zone's RRSIGs must come back.
            let signed = on
                .lookup(
                    Query::query(Name::from_ascii(SIGNED).unwrap(), RecordType::A),
                    request_options(),
                    false,
                )
                .await
                .unwrap_or_else(|e| panic!("{label}: signed lookup failed: {e}"));
            assert!(
                rrsig_count(&signed) > 0,
                "{label}: DO=1 must deliver RRSIG records, got none"
            );

            // CD=0: the provider refuses the bogus zone. A provider SERVFAIL
            // arrives as Dns(ResponseCode(ServFail)), never as NoRecordsFound.
            // Asserting the concrete shape stops a TLS or timeout failure from
            // passing for a DNSSEC rejection, and keeps rejections out of the
            // negative cache.
            let err = on
                .lookup(
                    Query::query(Name::from_ascii(BOGUS).unwrap(), RecordType::A),
                    request_options(),
                    false,
                )
                .await
                .expect_err("CD=0 must not resolve a bogus zone");
            assert!(
                matches!(
                    &err,
                    NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail, _))
                ),
                "{label}: expected the provider's SERVFAIL, got {err:?}"
            );
            assert!(
                !err.is_no_records_found(),
                "{label}: a DNSSEC rejection must not classify as a cacheable negative"
            );

            // CD=1 from the client, same upstream and same toggle: the bogus
            // answer comes back with its signatures. The provider skipped
            // validation because CD was set, and the client gets the material
            // to reach its own verdict.
            let bogus = on
                .lookup(
                    Query::query(Name::from_ascii(BOGUS).unwrap(), RecordType::A),
                    request_options(),
                    true,
                )
                .await
                .unwrap_or_else(|e| panic!("{label}: CD=1 must return data, got {e}"));
            assert!(
                !bogus.message().answers.is_empty(),
                "{label}: CD=1 must carry answer records"
            );
            assert!(
                rrsig_count(&bogus) > 0,
                "{label}: DO=1 must carry DNSSEC records even with CD=1"
            );
        }
    }
}
