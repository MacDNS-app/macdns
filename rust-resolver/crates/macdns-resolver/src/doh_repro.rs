// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! Wire regression for connection recovery using the production upstream and options.
use crate::provider_transport::{
    lookup_diagnostics, request_options, LookupResult, ProviderUpstream,
};
use crate::provider_transport_trace::lookup_span;
use crate::providers::{ns_cfg, opts};
use bytes::Bytes;
use hickory_proto::op::{Message, OpCode, Query};
use hickory_proto::rr::rdata::{A, NS};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{NameServerPool, PoolContext, TlsConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::ffi::{c_char, CStr};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;

static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());
const DEADLINE: Duration = Duration::from_secs(3);

extern "C" fn capture(_: i32, _: *const c_char, message: *const c_char) {
    // SAFETY: the FFI logger owns a valid C string for the callback duration.
    let line = unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned();
    let _ = writeln!(std::io::stdout().lock(), "{line}");
    LINES.lock().unwrap_or_else(|e| e.into_inner()).push(line);
}

#[derive(Clone, Copy, Debug)]
enum Close {
    TlsEof,
    TcpDrop,
    Goaway,
}

struct Accepted {
    id: usize,
    close: mpsc::UnboundedSender<Close>,
}

struct Received {
    id: usize,
    checking_disabled: bool,
    reply: oneshot::Sender<()>,
}

struct Peer {
    address: SocketAddr,
    client: rustls::ClientConfig,
    permits: Arc<Semaphore>,
    accepted: mpsc::UnboundedReceiver<Accepted>,
    received: mpsc::UnboundedReceiver<Received>,
    count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Peer {
    async fn start(client: rustls::ClientConfig, server: Arc<rustls::ServerConfig>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let permits = Arc::new(Semaphore::new(0));
        let count = Arc::new(AtomicUsize::new(0));
        let (accepted_tx, accepted) = mpsc::unbounded_channel();
        let (received_tx, received) = mpsc::unbounded_channel();
        let gate = permits.clone();
        let total = count.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (socket, _) = result.unwrap();
                        let id = total.fetch_add(1, Ordering::SeqCst) + 1;
                        let (close, mut commands) = mpsc::unbounded_channel();
                        accepted_tx.send(Accepted { id, close }).unwrap();
                        log::info!("event=server_accept tcp_id={id}");
                        let gate = gate.clone();
                        let received_tx = received_tx.clone();
                        let acceptor = TlsAcceptor::from(server.clone());
                        tasks.spawn(async move {
                            gate.acquire().await.unwrap().forget();
                            // A caller deadline can cancel a connection during its TLS handshake.
                            let Ok(mut tls) = acceptor.accept(socket).await else {
                                return;
                            };
                            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                            let (http_io, mut bridge) = tokio::io::duplex(65536);
                            let (goaway, goaway_rx) = mpsc::unbounded_channel();
                            let http_task = tokio::spawn(serve_h2(http_io, id, goaway_rx, received_tx));
                            // Keep TLS separately owned so the peer can send close_notify
                            // without GOAWAY. The client uses real TCP, TLS and h2 throughout.
                            let close = {
                                let pump = copy_bidirectional(&mut tls, &mut bridge);
                                tokio::pin!(pump);
                                loop {
                                    tokio::select! {
                                        result = &mut pump => {
                                            log::info!("event=server_transport_finished tcp_id={id} io_kind={:?}", result.as_ref().err().map(|e| e.kind()));
                                            break None;
                                        }
                                        Some(command) = commands.recv() => {
                                            log::info!("event=server_close tcp_id={id} kind={command:?}");
                                            match command {
                                                Close::Goaway => goaway.send(()).unwrap(),
                                                _ => break Some(command),
                                            }
                                        }
                                    }
                                }
                            };
                            if matches!(close, Some(Close::TlsEof)) {
                                tls.shutdown().await.unwrap();
                            }
                            if close.is_some() {
                                http_task.abort();
                            } else {
                                http_task.await.unwrap();
                            }
                        });
                    }
                    Some(result) = tasks.join_next(), if !tasks.is_empty() => result.unwrap(),
                }
            }
        });
        Self {
            address,
            client,
            permits,
            accepted,
            received,
            count,
            task,
        }
    }

    fn upstream(&self) -> ProviderUpstream {
        let mut cfg = ns_cfg(self.address.ip(), "localhost", "/dns-query");
        cfg.connections[0].port = self.address.port();
        let options = opts();
        let cache_size = options.cache_size;
        let intermediates = options.preserve_intermediates;
        let cx = Arc::new(PoolContext::new(
            options,
            TlsConfig {
                config: self.client.clone(),
            },
        ));
        let pool = NameServerPool::from_config([cfg], cx, TokioRuntimeProvider::default());
        ProviderUpstream::new(pool, cache_size, intermediates, true)
    }

    async fn answer(&mut self, count: usize, id: usize) {
        let mut pending = Vec::new();
        for _ in 0..count {
            let request = self.received.recv().await.unwrap();
            assert_eq!(
                request.id, id,
                "concurrent queries must share one connection"
            );
            assert!(!request.checking_disabled);
            pending.push(request);
        }
        for request in pending {
            request.reply.send(()).unwrap();
        }
    }
}

async fn serve_h2(
    io: DuplexStream,
    id: usize,
    mut goaway: mpsc::UnboundedReceiver<()>,
    received: mpsc::UnboundedSender<Received>,
) {
    let mut connection = h2::server::handshake(io).await.unwrap();
    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            request = connection.accept() => {
                let Some(request) = request else { break };
                let (request, response) = request.expect("local HTTP/2 request failed");
                requests.spawn(answer(request, response, id, received.clone()));
            }
            Some(()) = goaway.recv() => connection.abrupt_shutdown(h2::Reason::NO_ERROR),
            Some(result) = requests.join_next(), if !requests.is_empty() => result.unwrap(),
        }
    }
}

async fn answer(
    request: http::Request<h2::RecvStream>,
    mut response: h2::server::SendResponse<Bytes>,
    id: usize,
    received: mpsc::UnboundedSender<Received>,
) {
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(request.uri().path(), "/dns-query");
    let mut body = request.into_body();
    let mut wire = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        assert!(wire.len() + chunk.len() <= 4096);
        wire.extend_from_slice(&chunk);
        body.flow_control().release_capacity(chunk.len()).unwrap();
    }
    let query = Message::from_vec(&wire).unwrap();
    assert!(query.edns.as_ref().unwrap().flags().dnssec_ok);
    let question = query.queries[0].clone();
    log::info!(
        "event=server_query tcp_id={id} name={} type={:?} do=true cd={}",
        question.name(),
        question.query_type(),
        query.metadata.checking_disabled,
    );
    let (reply, release) = oneshot::channel();
    received
        .send(Received {
            id,
            checking_disabled: query.metadata.checking_disabled,
            reply,
        })
        .unwrap();
    if release.await.is_err() {
        return;
    }
    let mut message = Message::response(query.metadata.id, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.recursion_available = true;
    message.edns = query.edns;
    let data = match question.query_type() {
        RecordType::NS => RData::NS(NS(Name::from_ascii("ns.repro.example.com.").unwrap())),
        RecordType::A => RData::A(A(Ipv4Addr::new(192, 0, 2, id.try_into().unwrap()))),
        other => panic!("unexpected test query {other:?}"),
    };
    message.add_answer(Record::from_rdata(question.name().clone(), 0, data));
    message.queries.push(question);
    let wire = message.to_vec().unwrap();
    let headers = http::Response::builder()
        .header("content-type", "application/dns-message")
        .header("content-length", wire.len())
        .body(())
        .unwrap();
    // Caller cancellation may reset the stream before its controlled reply.
    if let Ok(mut stream) = response.send_response(headers, false) {
        let _ = stream.send_data(Bytes::from(wire), true);
    }
}

async fn lookup(upstream: &ProviderUpstream, name: &str, generation: u64) -> LookupResult {
    lookup_cd(upstream, name, generation, false).await
}

async fn lookup_cd(
    upstream: &ProviderUpstream,
    name: &str,
    generation: u64,
    checking_disabled: bool,
) -> LookupResult {
    let qtype = if name == "." {
        RecordType::NS
    } else {
        RecordType::A
    };
    let result = tokio::time::timeout(
        DEADLINE,
        upstream
            .lookup(
                Query::query(Name::from_ascii(name).unwrap(), qtype),
                request_options(),
                checking_disabled,
            )
            .instrument(lookup_span(0, Ipv4Addr::LOCALHOST.into(), generation)),
    )
    .await;
    log::info!(
        "event=client_lookup name={name} gen={generation} {}",
        lookup_diagnostics(&result)
    );
    result
}

async fn concurrent_shutdown(
    client: rustls::ClientConfig,
    server: Arc<rustls::ServerConfig>,
    close: Close,
) {
    let generation = match close {
        Close::TlsEof => 10,
        Close::TcpDrop => 11,
        Close::Goaway => 12,
    };
    let mut peer = Peer::start(client, server).await;
    let upstream = peer.upstream();
    let control = concurrent_open(&mut peer, &upstream, generation).await;
    let recover = async {
        let first = peer.received.recv().await.unwrap();
        let second = peer.received.recv().await.unwrap();
        assert_eq!((first.id, second.id), (1, 1));
        let before = LINES.lock().unwrap().len();
        control.close.send(close).unwrap();
        wait_trace(before, generation, "action=connection_dropped").await;
        drop((first, second));
        peer.answer(2, 2).await;
    };
    let (first, second, ()) = tokio::join!(
        lookup(&upstream, "inflight-a.repro.example.com.", generation),
        lookup(&upstream, "inflight-b.repro.example.com.", generation),
        recover,
    );
    assert_eq!((answered_by(&first), answered_by(&second)), (2, 2));
    assert_eq!(peer.count.load(Ordering::SeqCst), 2);
    log::info!("event=inflight_summary kind={close:?} recovered_queries=2 total_connections=2");
}

async fn caller_cancellation(client: rustls::ClientConfig, server: Arc<rustls::ServerConfig>) {
    let mut peer = Peer::start(client, server).await;
    peer.permits.add_permits(4);
    let upstream = peer.upstream();
    let mut pending = Box::pin(lookup(&upstream, "cancel.repro.example.com.", 20));
    let canceled = tokio::select! {
        request = peer.received.recv() => request.unwrap(),
        result = &mut pending => panic!("query completed before cancellation: {result:?}"),
    };
    assert_eq!(canceled.id, 1);
    drop(pending);
    let _ = canceled.reply.send(());
    let (next, ()) = tokio::join!(
        lookup(&upstream, "after-cancel.repro.example.com.", 20),
        peer.answer(1, 1),
    );
    assert_eq!(answered_by(&next), 1);
    assert_eq!(peer.count.load(Ordering::SeqCst), 1);
    log::info!("event=cancellation_summary total_connections=1");
}

async fn delayed_reply_revalidation(
    client: rustls::ClientConfig,
    server: Arc<rustls::ServerConfig>,
) {
    let mut peer = Peer::start(client, server).await;
    peer.permits.add_permits(1);
    let upstream = peer.upstream();
    let (warmup, ()) = tokio::join!(
        lookup(&upstream, "before-delay.repro.example.com.", 25),
        peer.answer(1, 1),
    );
    assert_eq!(answered_by(&warmup), 1);

    // Withhold the application reply on an established HTTP/2 connection, without packet loss.
    let mut pending = Box::pin(tokio::time::timeout(
        Duration::from_millis(250),
        lookup(&upstream, "delayed.repro.example.com.", 25),
    ));
    let delayed = tokio::select! {
        request = peer.received.recv() => request.unwrap(),
        result = &mut pending => panic!("query completed before the peer withheld its reply: {result:?}"),
    };
    assert_eq!(delayed.id, 1);
    assert!(
        pending.await.is_err(),
        "the stalled reply must expire at the caller deadline"
    );
    delayed.reply.send(()).unwrap();

    let (probe, ()) = tokio::join!(lookup(&upstream, ".", 25), peer.answer(1, 1));
    let probe = probe
        .expect("revalidation must finish within its deadline")
        .expect("revalidation must receive a DNS response");
    assert_eq!(probe.message().queries[0].name(), &Name::root());
    assert!(matches!(probe.message().answers[0].data, RData::NS(_)));
    assert_eq!(
        peer.count.load(Ordering::SeqCst),
        1,
        "a delayed application reply must not require a replacement TCP connection"
    );
    log::info!(
        "event=delayed_reply_summary caller_budget_ms=250 revalidation=root_ns total_connections=1"
    );
}

async fn complete_failure(client: rustls::ClientConfig, server: Arc<rustls::ServerConfig>) {
    let mut peer = Peer::start(client, server).await;
    peer.permits.add_permits(4);
    let upstream = peer.upstream();
    let mut pending = Box::pin(lookup(&upstream, "unavailable.repro.example.com.", 30));
    let failure = loop {
        tokio::select! {
            result = &mut pending => break result,
            request = peer.received.recv() => {
                let request = request.unwrap();
                assert!(request.id <= 2, "recovery exceeded one reconnect attempt");
                let control = peer.accepted.recv().await.unwrap();
                assert_eq!(control.id, request.id);
                let before = LINES.lock().unwrap().len();
                control.close.send(Close::TlsEof).unwrap();
                wait_trace(before, 30, "action=connection_dropped").await;
            }
        }
    };
    let error = failure
        .expect("recovery must stop before the outer deadline")
        .unwrap_err();
    assert!(
        error.is_connection_closed(),
        "closure lost its type: {error:?}"
    );
    assert_eq!(peer.count.load(Ordering::SeqCst), 2);
    log::info!("event=unavailable_summary total_connections=2 error={error}");
}

async fn reconnect_deadline_releases_guard(
    client: rustls::ClientConfig,
    server: Arc<rustls::ServerConfig>,
) {
    let mut peer = Peer::start(client, server).await;
    peer.permits.add_permits(1);
    let upstream = peer.upstream();
    let (warmup, ()) = tokio::join!(lookup(&upstream, ".", 35), peer.answer(1, 1));
    assert!(warmup.unwrap().is_ok());
    let control = peer.accepted.recv().await.unwrap();
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_millis(250);
    let interrupt = async {
        let request = peer.received.recv().await.unwrap();
        assert_eq!(request.id, 1);
        tokio::time::sleep_until(started + Duration::from_millis(50)).await;
        let before = LINES.lock().unwrap().len();
        control.close.send(Close::TlsEof).unwrap();
        wait_trace(before, 35, "action=connection_dropped").await;
        let replacement = peer.accepted.recv().await.unwrap();
        assert_eq!(replacement.id, 2);
        assert!(tokio::time::Instant::now() < deadline);
    };
    let (expired, ()) = tokio::join!(
        tokio::time::timeout_at(
            deadline,
            lookup(&upstream, "deadline.repro.example.com.", 35),
        ),
        interrupt,
    );
    assert!(
        expired.is_err(),
        "the caller deadline must cancel the stalled handshake"
    );
    assert_eq!(peer.count.load(Ordering::SeqCst), 2);

    // The canceled handshake and a new caller must both leave the establishment gate usable.
    peer.permits.add_permits(2);
    let (next, ()) = tokio::join!(
        lookup(&upstream, "after-deadline.repro.example.com.", 35),
        peer.answer(1, 3),
    );
    assert_eq!(answered_by(&next), 3);
    assert_eq!(peer.count.load(Ordering::SeqCst), 3);
    log::info!(
        "event=deadline_summary caller_budget_ms=250 total_connections=3 guard_released=true"
    );
}

async fn dnssec_recovery(client: rustls::ClientConfig, server: Arc<rustls::ServerConfig>) {
    let mut peer = Peer::start(client, server).await;
    let upstream = peer.upstream();
    let control = concurrent_open(&mut peer, &upstream, 40).await;
    let before = LINES.lock().unwrap().len();
    control.close.send(Close::TlsEof).unwrap();
    wait_trace(before, 40, "action=connection_dropped").await;
    let reply = async {
        let first = peer.received.recv().await.unwrap();
        let second = peer.received.recv().await.unwrap();
        assert_eq!((first.id, second.id), (2, 2));
        assert_ne!(first.checking_disabled, second.checking_disabled);
        first.reply.send(()).unwrap();
        second.reply.send(()).unwrap();
    };
    let (validating, unchecked, ()) = tokio::join!(
        lookup_cd(&upstream, "dnssec.repro.example.com.", 40, false),
        lookup_cd(&upstream, "dnssec.repro.example.com.", 40, true),
        reply,
    );
    assert_eq!((answered_by(&validating), answered_by(&unchecked)), (2, 2));
    assert_eq!(peer.count.load(Ordering::SeqCst), 2);
    log::info!("event=dnssec_summary total_connections=2 do=true cd_variants=2");
}

fn answered_by(result: &LookupResult) -> usize {
    let lookup = result.as_ref().unwrap().as_ref().unwrap();
    match lookup.message().answers[0].data {
        RData::A(A(ip)) => usize::from(ip.octets()[3]),
        ref other => panic!("unexpected answer {other:?}"),
    }
}

fn transport_lines(after: usize, generation: u64) -> Vec<String> {
    let prefix = format!("ip[127.0.0.1] gen={generation} phase=h2");
    LINES.lock().unwrap()[after..]
        .iter()
        .filter(|line| line.contains(&prefix))
        .cloned()
        .collect()
}

async fn wait_trace(after: usize, generation: u64, text: &str) {
    tokio::time::timeout(DEADLINE, async {
        loop {
            if transport_lines(after, generation)
                .iter()
                .any(|line| line.contains(text))
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("missing transport event {text}"));
}

async fn concurrent_open(
    peer: &mut Peer,
    upstream: &ProviderUpstream,
    generation: u64,
) -> Accepted {
    let connections = async {
        let first = peer.accepted.recv().await.unwrap();
        peer.permits.add_permits(8);
        peer.answer(2, first.id).await;
        first
    };
    let (warmup, retry, connection) = tokio::join!(
        lookup(upstream, ".", generation),
        lookup(upstream, "retry.repro.example.com.", generation),
        connections,
    );
    assert!(warmup.unwrap().is_ok());
    assert_eq!(answered_by(&retry), 1);
    assert_eq!(peer.count.load(Ordering::SeqCst), 1);
    connection
}

async fn scenario(client: rustls::ClientConfig, server: Arc<rustls::ServerConfig>, close: Close) {
    let generation = match close {
        Close::TlsEof => 1,
        Close::TcpDrop => 3,
        Close::Goaway => 5,
    };
    log::info!("event=scenario_start kind={close:?}");
    let mut peer = Peer::start(client, server).await;
    let upstream = peer.upstream();
    let control = concurrent_open(&mut peer, &upstream, generation).await;
    let before = LINES.lock().unwrap().len();
    control.close.send(close).unwrap();
    wait_trace(before, generation, "action=connection_dropped").await;
    let evidence = transport_lines(before, generation).join("\n");
    match close {
        Close::TlsEof => {
            assert!(evidence.contains("eof=true"), "{evidence}");
            assert!(!evidence.contains("goaway_reason=") && !evidence.contains("io_kind="));
        }
        Close::TcpDrop => {
            assert!(evidence.contains("io_kind=UnexpectedEof"), "{evidence}");
            assert!(!evidence.contains("eof=true") && !evidence.contains("goaway_reason="));
        }
        Close::Goaway => {
            assert!(evidence.contains("goaway_reason=NO_ERROR"), "{evidence}");
        }
    }
    let (recovered, ()) = tokio::join!(
        lookup(&upstream, "after.repro.example.com.", generation),
        peer.answer(1, 2),
    );
    assert_eq!(answered_by(&recovered), 2);
    assert_eq!(
        peer.count.load(Ordering::SeqCst),
        2,
        "the original pool must recover with one replacement connection"
    );
    log::info!(
        "event=scenario_summary kind={close:?} initial_connections=1 total_after_recovery=2"
    );
}

/// Ephemeral localhost TLS identity for local DoH servers: a client config
/// that trusts it and a server config that presents it with ALPN `h2`.
pub(crate) fn tls_identity() -> (rustls::ClientConfig, Arc<rustls::ServerConfig>) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("openssl.cnf"), "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n").unwrap();
    for args in [
        vec![
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-config",
            "openssl.cnf",
            "-keyout",
            "key.pem",
            "-out",
            "cert.der",
            "-outform",
            "DER",
        ],
        vec![
            "pkcs8", "-topk8", "-nocrypt", "-in", "key.pem", "-out", "key.der", "-outform", "DER",
        ],
    ] {
        let output = Command::new("openssl")
            .args(args)
            .current_dir(directory.path())
            .output()
            .expect("openssl is required to create the ephemeral localhost TLS identity");
        assert!(
            output.status.success(),
            "openssl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let certificate =
        CertificateDer::from(std::fs::read(directory.path().join("cert.der")).unwrap());
    let key = PrivatePkcs8KeyDer::from(std::fs::read(directory.path().join("key.der")).unwrap());
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(crypto.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut server = rustls::ServerConfig::builder_with_provider(crypto)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key.into())
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    (client, Arc::new(server))
}

#[test]
fn provider_connection_recovery() {
    let (client, server) = tls_identity();
    let _callback = crate::log_hooks::install_test_log_callback(capture);
    LINES.lock().unwrap().clear();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus::get_physical().clamp(2, 8))
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(20), async {
                let mut baseline = Peer::start(client.clone(), server.clone()).await;
                baseline.permits.add_permits(1);
                let upstream = baseline.upstream();
                let (warmup, ()) = tokio::join!(lookup(&upstream, ".", 0), baseline.answer(1, 1));
                assert!(warmup.unwrap().is_ok());
                let (sequential, ()) = tokio::join!(
                    lookup(&upstream, "sequential.repro.example.com.", 0),
                    baseline.answer(1, 1),
                );
                assert_eq!(answered_by(&sequential), 1);
                assert_eq!(baseline.count.load(Ordering::SeqCst), 1);
                log::info!("event=baseline_summary sequential_connections=1");
                let _control = baseline.accepted.recv().await.unwrap();
                drop(upstream);
                drop(baseline);
                for close in [Close::TlsEof, Close::TcpDrop, Close::Goaway] {
                    scenario(client.clone(), server.clone(), close).await;
                    concurrent_shutdown(client.clone(), server.clone(), close).await;
                }
                caller_cancellation(client.clone(), server.clone()).await;
                delayed_reply_revalidation(client.clone(), server.clone()).await;
                complete_failure(client.clone(), server.clone()).await;
                reconnect_deadline_releases_guard(client.clone(), server.clone()).await;
                dnssec_recovery(client.clone(), server.clone()).await;
            })
            .await
            .expect("local regression must complete within its deadline");
        });
}
