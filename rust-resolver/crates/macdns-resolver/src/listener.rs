// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use crate::query::handle_wire;
use crate::stats::{counters, inc};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Per-stream budget for a single TCP DNS exchange. RFC 7766 recommends an
/// idle timeout in the order of seconds. Without it, a half-open
/// captive-portal client (stuck mid-handshake, never sending the length
/// prefix) would pin a spawned task forever. Five seconds is loose enough for
/// any legitimate client on a slow network and tight enough that a thousand
/// stuck connections are reaped within seconds.
const TCP_STREAM_TIMEOUT: Duration = Duration::from_secs(5);
const LISTENER_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(30);
/// Above what the DNS Proxy can have pending (`ResolverSocketPool`), so a
/// burst the proxy accepted is never dropped here, and neither is the
/// proxy-control challenge that travels with it.
const UDP_MAX_IN_FLIGHT: usize = 4096;
/// Largest UDP DNS message this listener reads, and so the payload size the
/// resolver advertises in its own OPT record (RFC 6891 §6.2.3). It also caps
/// how large a UDP response is sent, whatever the client advertised.
pub(crate) const UDP_PAYLOAD_SIZE: u16 = 4096;
const TCP_MAX_CONNECTIONS: usize = 256;
const TCP_ACCEPT_BACKOFF_INITIAL: Duration = Duration::from_millis(5);
const TCP_ACCEPT_BACKOFF_MAX: Duration = Duration::from_millis(500);

pub async fn run_udp(socket: UdpSocket, cancel: CancellationToken) {
    let socket = Arc::new(socket);
    let permits = Arc::new(Semaphore::new(UDP_MAX_IN_FLIGHT));
    let mut next_recv_error_log = Instant::now();
    let mut next_drop_log = Instant::now();

    loop {
        let mut buf = vec![0u8; usize::from(UDP_PAYLOAD_SIZE)];
        tokio::select! {
            _ = cancel.cancelled() => break,
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((len, addr)) => {
                        inc(&counters().queries_total);
                        let query = buf[..len].to_vec();
                        let sock = socket.clone();
                        let c = cancel.clone();
                        let Ok(permit) = permits.clone().try_acquire_owned() else {
                            inc(&counters().udp_overload_drops);
                            let now = Instant::now();
                            if now >= next_drop_log {
                                log::warn!(
                                    "UDP query dropped from {}: in-flight limit {} reached",
                                    addr,
                                    UDP_MAX_IN_FLIGHT
                                );
                                next_drop_log = now + LISTENER_ERROR_LOG_INTERVAL;
                            }
                            continue;
                        };
                        tokio::spawn(async move {
                            let _permit = permit;
                            let payload_size = parse_client_udp_payload_size(&query);
                            let resp = handle_wire(
                                &query,
                                c,
                                crate::query::Transport::Udp { client_payload_size: payload_size },
                            ).await;
                            if !resp.is_empty() {
                                if let Err(e) = sock.send_to(&resp, addr).await {
                                    log::warn!(
                                        "UDP send_to {} failed: resp_len={} payload_size={}: {}",
                                        addr,
                                        resp.len(),
                                        payload_size,
                                        e
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        let now = Instant::now();
                        if now >= next_recv_error_log {
                            log::warn!("UDP recv_from failed: {}", e);
                            next_recv_error_log = now + LISTENER_ERROR_LOG_INTERVAL;
                        }
                        continue;
                    }
                }
            }
        }
    }
    log::info!("resolver UDP listener stopped");
}

/// Bounded exponential delay applied only after a failed `accept()`. A
/// sustained `EMFILE` (the soft `maxfiles` limit is 256) otherwise leaves the
/// accept task continuously runnable, burning CPU without ever making
/// progress. Tokio's cooperative budget still yields, so the worker is shared
/// rather than monopolised, but the spin is pure waste. Any successful accept
/// resets the delay.
struct AcceptBackoff {
    delay: Option<Duration>,
}

impl AcceptBackoff {
    fn new() -> Self {
        Self { delay: None }
    }

    fn reset(&mut self) {
        self.delay = None;
    }

    fn next_delay(&mut self) -> Duration {
        let delay = match self.delay {
            None => TCP_ACCEPT_BACKOFF_INITIAL,
            Some(previous) => (previous * 2).min(TCP_ACCEPT_BACKOFF_MAX),
        };
        self.delay = Some(delay);
        delay
    }

    /// Waits out the next delay. Returns `false` when the listener was
    /// cancelled while waiting so the caller stops without a further accept.
    async fn wait(&mut self, cancel: &CancellationToken) -> bool {
        let delay = self.next_delay();
        tokio::select! {
            _ = cancel.cancelled() => false,
            _ = tokio::time::sleep(delay) => true,
        }
    }
}

pub async fn run_tcp(listener: TcpListener, cancel: CancellationToken) {
    let permits = Arc::new(Semaphore::new(TCP_MAX_CONNECTIONS));
    let mut next_accept_error_log = Instant::now();
    let mut next_drop_log = Instant::now();
    let mut accept_backoff = AcceptBackoff::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            res = listener.accept() => {
                let (mut stream, peer) = match res {
                    Ok(accepted) => {
                        accept_backoff.reset();
                        accepted
                    }
                    Err(e) => {
                        let now = Instant::now();
                        if now >= next_accept_error_log {
                            log::warn!("TCP accept failed: {}", e);
                            next_accept_error_log = now + LISTENER_ERROR_LOG_INTERVAL;
                        }
                        if !accept_backoff.wait(&cancel).await {
                            break;
                        }
                        continue;
                    }
                };
                let c = cancel.clone();
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    inc(&counters().tcp_overload_drops);
                    let now = Instant::now();
                    if now >= next_drop_log {
                        log::warn!(
                            "TCP connection dropped from {}: connection limit {} reached",
                            peer,
                            TCP_MAX_CONNECTIONS
                        );
                        next_drop_log = now + LISTENER_ERROR_LOG_INTERVAL;
                    }
                    continue;
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    // RFC 7766: serve as many queries as the client sends.
                    // The timeout is idle/per-operation, not whole-connection,
                    // so active persistent clients are not disconnected after
                    // a fixed wall-clock budget.
                    loop {
                        let mut len_buf = [0u8; 2];
                        tokio::select! {
                            _ = c.cancelled() => return,
                            res = timeout(TCP_STREAM_TIMEOUT, stream.read_exact(&mut len_buf)) => {
                                match res {
                                    Ok(Ok(_)) => {}
                                    Ok(Err(e)) => {
                                        // A clean EOF while waiting for the next query's
                                        // length prefix is a normal RFC 7766 connection
                                        // close (e.g. a one-shot client such as the
                                        // control-plane probe), not a failure.
                                        if e.kind() != std::io::ErrorKind::UnexpectedEof {
                                            log::debug!("TCP read length failed from {}: {}", peer, e);
                                        }
                                        return;
                                    }
                                    // Idle timeout between queries on a persistent connection.
                                    Err(_) => return,
                                }
                            }
                        }
                        let len = u16::from_be_bytes(len_buf) as usize;
                        if len == 0 {
                            return;
                        }
                        let mut query = vec![0u8; len];
                        tokio::select! {
                            _ = c.cancelled() => return,
                            res = timeout(TCP_STREAM_TIMEOUT, stream.read_exact(&mut query)) => {
                                match res {
                                    Ok(Ok(_)) => {}
                                    Ok(Err(e)) => {
                                        log::warn!("TCP read body failed from {}: len={}: {}", peer, len, e);
                                        return;
                                    }
                                    Err(_) => {
                                        log::debug!("TCP read body timed out from {}: len={}", peer, len);
                                        return;
                                    }
                                }
                            }
                        }
                        inc(&counters().queries_total);
                        let resp = handle_wire(&query, c.clone(), crate::query::Transport::Tcp).await;
                        if !resp.is_empty() {
                            let Some(rlen) = tcp_response_len_prefix(resp.len()) else {
                                log::warn!(
                                    "TCP response too large for {}: resp_len={} max={}",
                                    peer,
                                    resp.len(),
                                    u16::MAX,
                                );
                                return;
                            };
                            match timeout(TCP_STREAM_TIMEOUT, stream.write_all(&rlen)).await {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    log::warn!("TCP write length failed to {}: resp_len={}: {}", peer, resp.len(), e);
                                    return;
                                }
                                Err(_) => {
                                    log::debug!("TCP write length timed out to {}: resp_len={}", peer, resp.len());
                                    return;
                                }
                            }
                            match timeout(TCP_STREAM_TIMEOUT, stream.write_all(&resp)).await {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    log::warn!("TCP write body failed to {}: resp_len={}: {}", peer, resp.len(), e);
                                    return;
                                }
                                Err(_) => {
                                    log::debug!("TCP write body timed out to {}: resp_len={}", peer, resp.len());
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        }
    }
    log::info!("resolver TCP listener stopped");
}

fn tcp_response_len_prefix(resp_len: usize) -> Option<[u8; 2]> {
    u16::try_from(resp_len).ok().map(u16::to_be_bytes)
}

/// Parses the EDNS OPT pseudo-RR out of a raw query and returns
/// the advertised UDP payload size. Falls back to 512 (RFC 1035
/// §4.2.1) when the message is malformed or carries no OPT.
/// The `UDP_PAYLOAD_SIZE` cap matches the listener's read buffer.
fn parse_client_udp_payload_size(wire: &[u8]) -> u16 {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::BinDecodable;
    let Ok(msg) = Message::from_bytes(wire) else {
        return 512;
    };
    let advertised = msg.edns.as_ref().map(|e| e.max_payload()).unwrap_or(512);
    advertised.clamp(512, UDP_PAYLOAD_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Instant;
    use tokio::net::TcpStream;

    /// A half-open client (connects but never sends the length prefix)
    /// must not pin the spawned handler beyond TCP_STREAM_TIMEOUT.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn half_open_tcp_client_is_dropped_within_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let cancel_for_listener = cancel.clone();
        tokio::spawn(async move {
            run_tcp(listener, cancel_for_listener).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let started = Instant::now();
        // Read returns Ok(0) when the server closes, which must happen
        // within TCP_STREAM_TIMEOUT plus a small slack for task scheduling.
        let mut sink = [0u8; 1];
        let _ = timeout(
            TCP_STREAM_TIMEOUT + Duration::from_secs(2),
            client.read(&mut sink),
        )
        .await
        .expect("server did not drop the half-open client in time");
        let elapsed = started.elapsed();
        assert!(
            elapsed <= TCP_STREAM_TIMEOUT + Duration::from_secs(1),
            "server took too long to drop half-open client: {:?}",
            elapsed,
        );
        cancel.cancel();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_handles_multiple_queries_on_same_connection() {
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
        use std::str::FromStr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let cancel_for_listener = cancel.clone();
        tokio::spawn(async move { run_tcp(listener, cancel_for_listener).await });

        // _probe.macdns short-circuits to REFUSED, so the test stays offline
        // and deterministic.
        let mut probe1 = Message::query();
        let mut q1 = Query::new();
        q1.set_name(Name::from_str("_probe.macdns.").unwrap())
            .set_query_type(RecordType::A);
        probe1.add_query(q1);
        probe1.metadata.id = 1;
        let probe1_wire = probe1.to_bytes().unwrap();

        let mut probe2 = probe1.clone();
        probe2.metadata.id = 2;
        let probe2_wire = probe2.to_bytes().unwrap();

        let mut sock = TcpStream::connect(addr).await.unwrap();

        for (i, wire) in [&probe1_wire, &probe2_wire].iter().enumerate() {
            let len = (wire.len() as u16).to_be_bytes();
            sock.write_all(&len).await.unwrap();
            sock.write_all(wire).await.unwrap();

            let mut len_buf = [0u8; 2];
            sock.read_exact(&mut len_buf).await.unwrap();
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            let mut resp = vec![0u8; resp_len];
            sock.read_exact(&mut resp).await.unwrap();
            let parsed = Message::from_bytes(&resp).unwrap();
            assert_eq!(parsed.metadata.id, (i + 1) as u16);
        }
        cancel.cancel();
    }

    fn emfile() -> std::io::Error {
        std::io::Error::from_raw_os_error(24)
    }

    /// Mirrors `run_tcp`'s accept-error path against an injected accept
    /// source, so the production backoff drives the loop. Returns the number
    /// of accept attempts made inside `budget` and the delay actually waited
    /// after each failure.
    async fn drive_accepts(
        cancel: &CancellationToken,
        mut accept: impl FnMut(usize) -> std::io::Result<()>,
        budget: Duration,
    ) -> (usize, Vec<Duration>) {
        let mut backoff = AcceptBackoff::new();
        let deadline = tokio::time::Instant::now() + budget;
        let mut attempts = 0usize;
        let mut delays = Vec::new();
        while tokio::time::Instant::now() < deadline {
            let outcome = accept(attempts);
            attempts += 1;
            match outcome {
                Ok(()) => backoff.reset(),
                Err(_) => {
                    let started = tokio::time::Instant::now();
                    if !backoff.wait(cancel).await {
                        break;
                    }
                    delays.push(started.elapsed());
                }
            }
        }
        (attempts, delays)
    }

    /// Sustained EMFILE must not spin: the attempt count inside a fixed
    /// simulated window stays small and the delay grows to the cap.
    #[tokio::test(start_paused = true)]
    async fn repeated_tcp_accept_errors_are_bounded_by_growing_delay() {
        let cancel = CancellationToken::new();
        let (attempts, delays) =
            drive_accepts(&cancel, |_| Err(emfile()), Duration::from_secs(1)).await;

        assert!(
            (2..=12).contains(&attempts),
            "sustained EMFILE must be bounded, got {attempts} attempts"
        );
        assert_eq!(delays[0], TCP_ACCEPT_BACKOFF_INITIAL);
        for pair in delays.windows(2) {
            assert!(pair[1] >= pair[0], "delay must never shrink while failing");
            assert!(pair[1] <= TCP_ACCEPT_BACKOFF_MAX, "delay must stay bounded");
        }
        assert_eq!(*delays.last().unwrap(), TCP_ACCEPT_BACKOFF_MAX);
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_accept_backoff_resets_after_a_successful_accept() {
        let cancel = CancellationToken::new();
        let (_, delays) = drive_accepts(
            &cancel,
            |attempt| if attempt == 2 { Ok(()) } else { Err(emfile()) },
            Duration::from_millis(60),
        )
        .await;

        assert!(delays.len() >= 4, "expected more failures, got {delays:?}");
        assert_eq!(delays[0], TCP_ACCEPT_BACKOFF_INITIAL);
        assert_eq!(delays[1], TCP_ACCEPT_BACKOFF_INITIAL * 2);
        assert_eq!(
            delays[2], TCP_ACCEPT_BACKOFF_INITIAL,
            "a successful accept must reset the delay"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_accept_backoff_returns_immediately_when_cancelled() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let started = tokio::time::Instant::now();

        let (attempts, delays) =
            drive_accepts(&cancel, |_| Err(emfile()), Duration::from_secs(1)).await;

        assert_eq!(attempts, 1);
        assert!(delays.is_empty());
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[test]
    fn tcp_response_len_prefix_rejects_oversized_payload() {
        assert_eq!(tcp_response_len_prefix(0), Some([0, 0]));
        assert_eq!(tcp_response_len_prefix(65_535), Some([0xff, 0xff]));
        assert_eq!(tcp_response_len_prefix(65_536), None);
    }

    #[test]
    fn parse_payload_size_falls_back_to_512_without_opt() {
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        use hickory_proto::serialize::binary::BinEncodable;
        use std::str::FromStr;
        let mut q = Message::query();
        let mut query = Query::new();
        query
            .set_name(Name::from_str("example.com.").unwrap())
            .set_query_type(RecordType::A);
        q.add_query(query);
        let wire = q.to_bytes().unwrap();
        assert_eq!(parse_client_udp_payload_size(&wire), 512);
    }

    #[test]
    fn parse_payload_size_clamps_advertised_above_4096() {
        use hickory_proto::op::{Edns, Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        use hickory_proto::serialize::binary::BinEncodable;
        use std::str::FromStr;
        let mut q = Message::query();
        let mut query = Query::new();
        query
            .set_name(Name::from_str("example.com.").unwrap())
            .set_query_type(RecordType::A);
        q.add_query(query);
        let mut opt = Edns::new();
        opt.set_max_payload(8192);
        q.edns = Some(opt);
        let wire = q.to_bytes().unwrap();
        assert_eq!(parse_client_udp_payload_size(&wire), 4096);
    }
}
