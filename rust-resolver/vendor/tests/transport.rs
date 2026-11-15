// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use futures::Stream;
use hickory_proto::op::{DnsRequest, DnsRequestOptions, DnsResponse, Message, Query};
use hickory_proto::rr::{rdata::A, Name, RData, Record, RecordType};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::{
    DnsExchange, DnsHandle, DnsRequestSender, DnsResponseStream, FirstAnswer, Protocol,
};
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::{ConnectionProvider, NameServer, NameServerPool, PoolContext, TlsConfig};
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::task::{Context, Poll};

fn request(label: &str) -> DnsRequest {
    DnsRequest::from_query(
        Query::query(
            Name::from_ascii(format!("{label}.example.com.")).unwrap(),
            RecordType::A,
        ),
        DnsRequestOptions::default(),
    )
}

fn answer(request: DnsRequest) -> DnsResponse {
    let mut response = Message::response(request.metadata.id, request.op_code);
    response.add_queries(request.queries.clone());
    response.add_answer(Record::from_rdata(
        request.queries[0].name.clone(),
        0,
        RData::A(A::new(192, 0, 2, 1)),
    ));
    DnsResponse::from_message(response).unwrap()
}

fn closed() -> NetError {
    io::Error::from(io::ErrorKind::ConnectionReset).into()
}

struct ExchangeStream {
    error: Option<NetError>,
    shutdown: bool,
}

impl Stream for ExchangeStream {
    type Item = Result<(), NetError>;
    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.shutdown {
            Poll::Ready(None)
        } else if let Some(error) = self.error.take() {
            Poll::Ready(Some(Err(error)))
        } else {
            Poll::Pending
        }
    }
}

impl DnsRequestSender for ExchangeStream {
    fn send_message(&mut self, request: DnsRequest) -> DnsResponseStream {
        let response = answer(request);
        Box::pin(async move { Ok(response) }).into()
    }
    fn shutdown(&mut self) {
        self.shutdown = true;
    }
    fn is_shutdown(&self) -> bool {
        self.shutdown
    }
}

#[tokio::test]
async fn exchange_preserves_shutdown_reason_for_queued_requests() {
    let (exchange, background) = DnsExchange::<TokioRuntimeProvider>::from_stream(ExchangeStream {
        error: Some(closed()),
        shutdown: false,
    });
    let queued = exchange.send(request("queued"));
    background.await;
    let error = queued.first_answer().await.unwrap_err();
    assert!(
        matches!(error, NetError::Io(ref io) if io.kind() == io::ErrorKind::ConnectionReset),
        "{error:?}"
    );
    let error = exchange
        .send(request("later"))
        .first_answer()
        .await
        .unwrap_err();
    assert!(
        error.is_connection_closed(),
        "closed queue was reported as {error:?}"
    );
}

#[tokio::test]
async fn exchange_background_abort_reports_closed_instead_of_caller_cancellation() {
    let (exchange, background) = DnsExchange::<TokioRuntimeProvider>::from_stream(ExchangeStream {
        error: None,
        shutdown: false,
    });
    let queued = exchange.send(request("queued"));
    drop(background);
    let error = queued.first_answer().await.unwrap_err();
    assert!(error.is_connection_closed(), "{error:?}");
}

#[tokio::test]
async fn exchange_caller_cancellation_keeps_other_requests_alive() {
    let (exchange, background) = DnsExchange::<TokioRuntimeProvider>::from_stream(ExchangeStream {
        error: None,
        shutdown: false,
    });
    drop(exchange.send(request("cancelled")));
    let pending = exchange.send(request("live"));
    let driver = tokio::spawn(background);
    assert!(pending.first_answer().await.is_ok());
    drop(exchange);
    driver.await.unwrap();
}

#[derive(Clone)]
struct ScriptedProvider {
    runtime: TokioRuntimeProvider,
    protocol: Protocol,
    connects: Arc<AtomicUsize>,
    sends: Arc<AtomicUsize>,
    outcomes: Arc<Mutex<VecDeque<Option<NetError>>>>,
    release_success: Arc<tokio::sync::Semaphore>,
}

impl ConnectionProvider for ScriptedProvider {
    type Conn = Self;
    type FutureConn = Pin<Box<dyn Future<Output = Result<Self, NetError>> + Send>>;
    type RuntimeProvider = TokioRuntimeProvider;

    fn new_connection(
        &self,
        _: IpAddr,
        config: &ConnectionConfig,
        _: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        let mut provider = self.clone();
        provider.protocol = config.protocol.to_protocol();
        Ok(Box::pin(async move {
            provider.connects.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok(provider)
        }))
    }
    fn runtime_provider(&self) -> &TokioRuntimeProvider {
        &self.runtime
    }
}

impl DnsHandle for ScriptedProvider {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = TokioRuntimeProvider;
    fn send(&self, request: DnsRequest) -> Self::Response {
        self.sends.fetch_add(1, Ordering::SeqCst);
        let outcome = self.outcomes.lock().unwrap().pop_front().flatten();
        let gate = self.release_success.clone();
        let truncated = self.protocol == Protocol::Udp
            && request.queries[0].name.to_ascii().starts_with("fallback.");
        Box::pin(futures::stream::once(async move {
            if request.queries[0].name.to_ascii().starts_with("held.") {
                gate.acquire().await.unwrap().forget();
            }
            match outcome {
                Some(error) => Err(error),
                None => {
                    let mut response = answer(request).into_message();
                    response.metadata.truncation = truncated;
                    Ok(DnsResponse::from_message(response).unwrap())
                }
            }
        }))
    }
}

fn pool(outcomes: Vec<Option<NetError>>) -> (NameServerPool<ScriptedProvider>, ScriptedProvider) {
    let provider = ScriptedProvider {
        runtime: TokioRuntimeProvider::default(),
        protocol: Protocol::Udp,
        connects: Arc::new(AtomicUsize::new(0)),
        sends: Arc::new(AtomicUsize::new(0)),
        outcomes: Arc::new(Mutex::new(outcomes.into())),
        release_success: Arc::new(tokio::sync::Semaphore::new(0)),
    };
    let mut options = ResolverOpts::default();
    options.attempts = 0;
    options.num_concurrent_reqs = 1;
    let cx = Arc::new(PoolContext::new(options, TlsConfig::new().unwrap()));
    (
        NameServerPool::from_config(
            [NameServerConfig::udp(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            cx,
            provider.clone(),
        ),
        provider,
    )
}

#[tokio::test]
async fn cold_queries_share_one_establishment() {
    let (pool, provider) = pool(vec![]);
    let (first, second) = tokio::join!(
        pool.send(request("first")).first_answer(),
        pool.send(request("second")).first_answer(),
    );
    assert!(first.is_ok() && second.is_ok());
    assert_eq!(provider.connects.load(Ordering::SeqCst), 1);
    assert_eq!(provider.sends.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn fresh_closure_recovers_once_and_exhaustion_stops() {
    let (recovering, provider) = pool(vec![Some(closed()), None]);
    assert!(recovering
        .send(request("recover"))
        .first_answer()
        .await
        .is_ok());
    assert_eq!(provider.connects.load(Ordering::SeqCst), 2);
    assert_eq!(provider.sends.load(Ordering::SeqCst), 2);

    let (failing, provider) = pool(vec![Some(closed()), Some(closed()), None]);
    let error = failing
        .send(request("fail"))
        .first_answer()
        .await
        .unwrap_err();
    assert!(error.is_connection_closed(), "{error:?}");
    assert_eq!(provider.connects.load(Ordering::SeqCst), 2);
    assert_eq!(provider.sends.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn timeout_dns_http_and_certificate_errors_do_not_trigger_connection_retries() {
    for error in [
        NetError::Timeout,
        NetError::Dns(DnsError::ResponseCode(
            hickory_proto::op::ResponseCode::Refused,
            Default::default(),
        )),
        NetError::HttpStatus { status: 403 },
        NetError::RustlsError(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        )),
    ] {
        let (pool, provider) = pool(vec![Some(error)]);
        assert!(pool.send(request("fail")).first_answer().await.is_err());
        assert_eq!(provider.connects.load(Ordering::SeqCst), 1);
        assert_eq!(provider.sends.load(Ordering::SeqCst), 1);
    }
}

/// A non-2xx status is the server's answer over a healthy exchange. Marking
/// the connection failed would spend a handshake on the next query for
/// nothing, and under rate limiting it turns every refusal into a reconnect.
#[tokio::test]
async fn http_status_error_keeps_the_connection_established() {
    let (pool, provider) = pool(vec![Some(NetError::HttpStatus { status: 429 }), None]);
    let error = pool
        .send(request("limited"))
        .first_answer()
        .await
        .unwrap_err();
    assert!(
        matches!(error, NetError::HttpStatus { status: 429 }),
        "{error:?}"
    );
    pool.send(request("next")).first_answer().await.unwrap();
    assert_eq!(provider.connects.load(Ordering::SeqCst), 1);
    assert_eq!(provider.sends.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn late_success_does_not_resurrect_a_failed_connection() {
    let (pool, provider) = pool(vec![
        None,
        None,
        Some(NetError::from("terminal transport failure")),
    ]);
    pool.send(request("warmup")).first_answer().await.unwrap();
    let mut held = pool.send(request("held")).first_answer();
    assert!(futures::poll!(&mut held).is_pending());
    assert!(pool.send(request("failure")).first_answer().await.is_err());
    provider.release_success.add_permits(1);
    held.await.unwrap();
    pool.send(request("next")).first_answer().await.unwrap();
    assert_eq!(provider.connects.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn cancelled_establishment_releases_the_guard() {
    let (pool, provider) = pool(vec![]);
    let mut first = pool.send(request("cancelled")).first_answer();
    assert!(futures::poll!(&mut first).is_pending());
    let mut waiter = pool.send(request("waiter")).first_answer();
    assert!(futures::poll!(&mut waiter).is_pending());
    drop(waiter);
    drop(first);
    pool.send(request("next")).first_answer().await.unwrap();
    assert_eq!(provider.connects.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn recovery_uses_a_healthy_sibling_without_establishing_again() {
    let (unused, provider) = pool(vec![]);
    let context = unused.context().clone();
    let mut failed = provider.clone();
    failed.outcomes = Arc::new(Mutex::new(VecDeque::from([Some(closed())])));
    let server = NameServer::new(
        [(Protocol::Udp, failed), (Protocol::Tcp, provider.clone())],
        NameServerConfig::udp_and_tcp(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        &context.options,
        provider.clone(),
    );
    let pool = NameServerPool::from_nameservers(vec![Arc::new(server)], context);
    pool.send(request("recover")).first_answer().await.unwrap();
    assert_eq!(provider.connects.load(Ordering::SeqCst), 0);
    assert_eq!(provider.sends.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn tcp_establishment_does_not_block_a_healthy_udp_connection() {
    let (unused, provider) = pool(vec![]);
    let context = unused.context().clone();
    let server = NameServer::new(
        [(Protocol::Udp, provider.clone())],
        NameServerConfig::udp_and_tcp(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        &context.options,
        provider.clone(),
    );
    let pool = NameServerPool::from_nameservers(vec![Arc::new(server)], context);
    let mut tcp = pool.send(request("fallback")).first_answer();
    assert!(futures::poll!(&mut tcp).is_pending());
    assert_eq!(provider.connects.load(Ordering::SeqCst), 1);
    let mut udp = pool.send(request("hot")).first_answer();
    assert!(matches!(futures::poll!(&mut udp), Poll::Ready(Ok(_))));
    tcp.await.unwrap();
}

fn response_with_options(
    rcode: hickory_proto::op::ResponseCode,
    options: Vec<hickory_proto::rr::rdata::opt::EdnsOption>,
) -> DnsResponse {
    let mut response = Message::response(0, hickory_proto::op::OpCode::Query);
    response.add_query(Query::query(
        Name::from_ascii("ede.example.com.").unwrap(),
        RecordType::A,
    ));
    response.metadata.response_code = rcode;
    let mut edns = hickory_proto::op::Edns::new();
    for option in options {
        edns.options_mut().insert(option);
    }
    response.edns = Some(edns);
    DnsResponse::from_message(response).unwrap()
}

fn ede(info_code: u16, text: &str) -> hickory_proto::rr::rdata::opt::EdnsOption {
    let mut payload = info_code.to_be_bytes().to_vec();
    payload.extend_from_slice(text.as_bytes());
    hickory_proto::rr::rdata::opt::EdnsOption::Unknown(15, payload)
}

/// RFC 8914: a provider explains a failure with Extended DNS Errors. They
/// must survive the conversion to an error, and nothing else from the OPT
/// record may come along: a cookie or padding describes the hop, not the answer.
#[test]
fn error_responses_keep_only_their_extended_dns_errors() {
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::rdata::opt::EdnsOption;

    let servfail = response_with_options(
        ResponseCode::ServFail,
        vec![
            ede(6, "DNSSEC Bogus"),
            EdnsOption::Unknown(10, vec![1; 8]),
            EdnsOption::Unknown(12, vec![0; 32]),
        ],
    );
    let Err(DnsError::ResponseCode(ResponseCode::ServFail, errors)) =
        DnsError::from_response(servfail)
    else {
        panic!("SERVFAIL must become a ResponseCode error");
    };
    assert_eq!(errors.payloads(), &[ede(6, "DNSSEC Bogus").into_payload()]);

    let nxdomain = response_with_options(ResponseCode::NXDomain, vec![ede(15, "Blocked")]);
    let Err(DnsError::NoRecordsFound(no_records)) = DnsError::from_response(nxdomain) else {
        panic!("NXDOMAIN without answers must become NoRecordsFound");
    };
    assert_eq!(
        no_records.extended_errors.payloads(),
        &[ede(15, "Blocked").into_payload()]
    );
}

/// The options come from an untrusted server: their number and size are
/// bounded before they reach a client.
#[test]
fn extended_dns_errors_are_bounded() {
    use hickory_proto::op::ResponseCode;

    let mut options: Vec<_> = (0..10).map(|code| ede(code, "x")).collect();
    options.push(ede(0, &"y".repeat(4096)));
    options.push(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(
        15,
        vec![7],
    ));
    let Err(DnsError::ResponseCode(_, errors)) =
        DnsError::from_response(response_with_options(ResponseCode::ServFail, options))
    else {
        panic!("SERVFAIL must become a ResponseCode error");
    };
    assert_eq!(
        errors.payloads().len(),
        hickory_resolver::net::MAX_EXTENDED_ERRORS
    );
    assert!(errors
        .payloads()
        .iter()
        .all(|p| p.len() >= 2 && p.len() <= hickory_resolver::net::MAX_EXTENDED_ERROR_LEN));
}

trait IntoPayload {
    fn into_payload(self) -> Vec<u8>;
}

impl IntoPayload for hickory_proto::rr::rdata::opt::EdnsOption {
    fn into_payload(self) -> Vec<u8> {
        match self {
            hickory_proto::rr::rdata::opt::EdnsOption::Unknown(15, payload) => payload,
            other => panic!("not an EDE option: {other:?}"),
        }
    }
}
