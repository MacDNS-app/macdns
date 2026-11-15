// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! One bounded h2 shutdown summary per provider connection, sent through FFI at debug.
//! A connection the resolver closed itself without error gets none.
use std::fmt::{self, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use std::time::Instant;
use tracing::span::{Attributes, Id};
use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

const H2_TARGET: &str = "h2::proto::connection";
const LOCAL_CLEAN_CLOSE: &str = "Closed(NO_ERROR, Library)";
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::registry().with(TransportEvents);
        if tracing::subscriber::set_global_default(subscriber).is_err() {
            log::warn!(
                "phase=h2 action=diagnostics_unavailable reason=subscriber_already_installed"
            );
        }
    });
}

pub(crate) fn lookup_span(conn: usize, ip: IpAddr, generation: u64) -> tracing::Span {
    tracing::debug_span!("provider_lookup", conn, %ip, gen = generation)
}

struct LookupContext(String);

struct ConnectionContext {
    prefix: String,
    id: u64,
    started: Instant,
    eof: bool,
    goaway: String,
    reset_count: u64,
    reset: String,
    io_kind: String,
    connection_error: bool,
    stream_errors: u64,
    state: String,
}

impl ConnectionContext {
    /// The resolver closed the connection itself and h2 saw nothing from the
    /// peer and no error. h2 still reports its own GOAWAY NO_ERROR as a
    /// connection error, so `connection_error` does not count here.
    fn closed_locally_without_error(&self) -> bool {
        self.state == LOCAL_CLEAN_CLOSE
            && !self.eof
            && self.goaway.is_empty()
            && self.reset_count == 0
            && self.io_kind.is_empty()
            && self.stream_errors == 0
    }

    fn emit(&self) {
        if self.closed_locally_without_error() || !log::log_enabled!(log::Level::Debug) {
            return;
        }
        let mut details = String::new();
        if self.eof {
            details.push_str(" eof=true");
        }
        details.push_str(&self.goaway);
        if self.reset_count > 0 {
            let _ = write!(details, " reset_count={}{}", self.reset_count, self.reset);
        }
        if !self.io_kind.is_empty() {
            let _ = write!(details, " io_kind={}", self.io_kind);
        }
        if self.connection_error {
            details.push_str(" connection_error=true");
        }
        if self.stream_errors > 0 {
            let _ = write!(details, " stream_errors={}", self.stream_errors);
        }
        if !self.state.is_empty() {
            let _ = write!(details, " state={:?}", self.state);
        }
        log::debug!(
            "{} phase=h2 h2_conn={} action=connection_dropped h2_age_ms={}{}",
            self.prefix,
            self.id,
            self.started.elapsed().as_millis(),
            details,
        );
    }
}

struct TransportEvents;

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for TransportEvents {
    fn enabled(&self, metadata: &Metadata<'_>, _: Context<'_, S>) -> bool {
        (metadata.target() == module_path!() && metadata.name() == "provider_lookup")
            || (metadata.target() == H2_TARGET
                && (metadata.is_event() || metadata.name() == "Connection"))
    }

    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if attrs.metadata().target() != module_path!() {
            return;
        }
        let mut conn = String::new();
        let mut ip = String::new();
        let mut generation = String::new();
        attrs.record(
            &mut |field: &tracing::field::Field, value: &dyn fmt::Debug| match field.name() {
                "conn" => conn = format!("{value:?}"),
                "ip" => ip = format!("{value:?}"),
                "gen" => generation = format!("{value:?}"),
                _ => {}
            },
        );
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(LookupContext(format!(
                "conn[{conn}] ip[{ip}] gen={generation}"
            )));
        }
    }

    fn on_follows_from(&self, id: &Id, follows: &Id, ctx: Context<'_, S>) {
        let (Some(span), Some(parent)) = (ctx.span(id), ctx.span(follows)) else {
            return;
        };
        if span.metadata().target() != H2_TARGET {
            return;
        }
        // h2's root Connection span follows the handshake's current span. Its
        // driver keeps this link after Hickory spawns it outside the lookup.
        let parent_extensions = parent.extensions();
        let Some(lookup) = parent_extensions.get::<LookupContext>() else {
            return;
        };
        let connection = ConnectionContext {
            prefix: lookup.0.clone(),
            id: NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
            started: Instant::now(),
            eof: false,
            goaway: String::new(),
            reset_count: 0,
            reset: String::new(),
            io_kind: String::new(),
            connection_error: false,
            stream_errors: 0,
            state: String::new(),
        };
        span.extensions_mut().insert(connection);
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let Some(scope) = ctx.event_scope(event) else {
            return;
        };
        for span in scope {
            let mut extensions = span.extensions_mut();
            let Some(connection) = extensions.get_mut::<ConnectionContext>() else {
                continue;
            };
            // Select the static message before formatting any field. HEADERS,
            // DATA and arbitrary connection errors can contain private payloads.
            let message = event_field(event, "message");
            match message.as_str() {
                "recv GOAWAY" => {
                    connection.goaway =
                        frame_details(event, "last_stream_id", "goaway_reason", "last_stream_id");
                }
                "recv RST_STREAM" => {
                    connection.reset_count = connection.reset_count.saturating_add(1);
                    connection.reset =
                        frame_details(event, "stream_id", "reset_reason", "reset_stream_id");
                }
                "codec closed" => connection.eof = true,
                "Connection::poll; IO error" => connection.io_kind = event_field(event, "error"),
                "Connection::poll; connection error" => connection.connection_error = true,
                "stream reset" | "stream error" => {
                    connection.stream_errors = connection.stream_errors.saturating_add(1);
                }
                "" => {
                    let state = event_field(event, "connection.state");
                    if !state.starts_with("Closed(") {
                        return;
                    }
                    connection.state = state;
                }
                _ => return,
            }
            return;
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(&id) {
            if let Some(connection) = span.extensions().get::<ConnectionContext>() {
                // Dropping a span does not distinguish completion from task cancellation.
                connection.emit();
            }
        }
    }
}

fn event_field(event: &Event<'_>, name: &str) -> String {
    let mut output = BoundedField(String::new());
    event.record(
        &mut |field: &tracing::field::Field, value: &dyn fmt::Debug| {
            if field.name() == name {
                let _ = write!(output, "{value:?}");
            }
        },
    );
    output.0
}

struct BoundedField(String);

impl fmt::Write for BoundedField {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.0.len() + value.len() > 256 {
            return Err(fmt::Error);
        }
        self.0.push_str(value);
        Ok(())
    }
}

fn frame_details(
    event: &Event<'_>,
    stream_field: &str,
    reason_key: &str,
    stream_key: &str,
) -> String {
    let frame = event_field(event, "frame");
    // Only h2's reason and numeric stream ID cross FFI. Never forward GOAWAY
    // debug_data, even if its contents resemble another diagnostic field.
    let safe = frame.split(", debug_data:").next().unwrap_or_default();
    let reason = safe
        .split_once("error_code: ")
        .map(|(_, tail)| tail.split([',', '}']).next().unwrap_or_default().trim());
    let stream = safe
        .split_once(&format!("{stream_field}: StreamId("))
        .and_then(|(_, tail)| {
            tail.split_once(')')
                .and_then(|(id, _)| id.parse::<u32>().ok())
        });
    match (reason, stream) {
        (Some(reason), Some(stream))
            if reason
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'(' | b')')) =>
        {
            format!(" {reason_key}={reason} {stream_key}={stream}")
        }
        _ => format!(" {reason_key}=unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing::Instrument;

    #[test]
    fn summarizes_graceful_and_error_goaway_once_at_debug_without_peer_data() {
        for reason in [0u32, 11, 42] {
            let lines = crate::log_hooks::capture_logs(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        tokio::time::timeout(Duration::from_secs(2), async {
                            let (client_io, mut server_io) = tokio::io::duplex(4096);
                            let server = tokio::spawn(async move {
                                let mut preface = [0; 24];
                                server_io.read_exact(&mut preface).await.unwrap();
                                // SETTINGS followed by GOAWAY with opaque peer-controlled data.
                                server_io
                                    .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
                                    .await
                                    .unwrap();
                                let secret = b"private.example\0\nAuthorization: secret";
                                let length = 8 + secret.len();
                                let mut frame = vec![0, 0, length as u8, 7, 0, 0, 0, 0, 0];
                                frame.extend_from_slice(&0u32.to_be_bytes());
                                frame.extend_from_slice(&reason.to_be_bytes());
                                frame.extend_from_slice(secret);
                                server_io.write_all(&frame).await.unwrap();
                                let mut drain = Vec::new();
                                server_io.read_to_end(&mut drain).await.unwrap();
                            });
                            let (client, driver) = h2::client::handshake(client_io)
                                .instrument(lookup_span(3, "9.9.9.9".parse().unwrap(), 7))
                                .await
                                .unwrap();
                            // Hickory polls the driver on a separate task without the lookup span.
                            let result = tokio::spawn(driver).await.unwrap();
                            assert_eq!(result.is_ok(), reason == 0);
                            drop(client);
                            server.await.unwrap();
                        })
                        .await
                        .expect("local H2 shutdown must complete");
                    });
            });
            assert_eq!(lines.len(), 1, "one summary per connection: {lines:?}");
            let diagnostic = &lines[0];
            assert_eq!(
                diagnostic.0, 3,
                "driver diagnostics must reach FFI at debug"
            );
            let expected = match reason {
                0 => "NO_ERROR",
                11 => "ENHANCE_YOUR_CALM",
                _ => "Reason(2a)",
            };
            assert!(
                diagnostic
                    .1
                    .contains(&format!("goaway_reason={expected} last_stream_id=0")),
                "{diagnostic:?}"
            );
            assert!(diagnostic.1.contains("conn[3] ip[9.9.9.9] gen=7"));
            assert!(diagnostic.1.contains("h2_conn="));
            assert!(diagnostic.1.contains("action=connection_dropped"));
            for (_, line) in &lines {
                assert!(!line.contains("private.example") && !line.contains("Authorization"));
                assert!(!line.contains("secret") && !line.contains(['\0', '\n']));
            }
        }
    }

    #[test]
    fn combines_remote_stream_reset_and_eof_in_one_debug_summary() {
        let lines = crate::log_hooks::capture_logs(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    tokio::time::timeout(Duration::from_secs(2), async {
                        let (client_io, server_io) = tokio::io::duplex(4096);
                        let (close, closed) = tokio::sync::oneshot::channel();
                        let server = tokio::spawn(async move {
                            let mut connection = h2::server::handshake(server_io).await.unwrap();
                            let (_, mut response) = connection.accept().await.unwrap().unwrap();
                            response.send_reset(h2::Reason::REFUSED_STREAM);
                            tokio::select! {
                                _ = connection.accept() => {},
                                _ = closed => {},
                            }
                        });
                        let (mut client, driver) = h2::client::handshake(client_io)
                            .instrument(lookup_span(5, "2620:fe::fe".parse().unwrap(), 2))
                            .await
                            .unwrap();
                        let driver = tokio::spawn(driver);
                        let request = http::Request::builder()
                            .uri("https://private.example/dns-query")
                            .header("authorization", "secret")
                            .body(())
                            .unwrap();
                        let (response, _) = client.send_request(request, true).unwrap();
                        assert!(response.await.unwrap_err().is_reset());
                        close.send(()).unwrap();
                        let _ = driver.await.unwrap();
                        server.await.unwrap();
                    })
                    .await
                    .expect("local H2 reset and EOF must complete");
                });
        });
        assert_eq!(lines.len(), 1, "one summary per connection: {lines:?}");
        let (level, summary) = &lines[0];
        assert_eq!(*level, 3);
        assert!(summary.contains("conn[5] ip[2620:fe::fe] gen=2"));
        assert!(summary.contains("h2_conn="));
        assert!(summary.contains("action=connection_dropped"));
        assert!(summary.contains("reset_count=1 reset_reason=REFUSED_STREAM reset_stream_id=1"));
        assert!(summary.contains("eof=true"));
        assert!(lines
            .iter()
            .all(|(_, line)| !line.contains("private.example") && !line.contains("secret")));
    }

    /// A connection the resolver closes itself, as rotation does, ends with a
    /// local GOAWAY NO_ERROR. h2 reports that as a connection error, and the
    /// summary read like a failure. Nothing went wrong, so nothing is logged.
    #[test]
    fn omits_the_summary_of_a_connection_closed_locally_without_error() {
        let lines = crate::log_hooks::capture_logs(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    tokio::time::timeout(Duration::from_secs(2), async {
                        let (client_io, server_io) = tokio::io::duplex(4096);
                        let server = tokio::spawn(async move {
                            let mut connection = h2::server::handshake(server_io).await.unwrap();
                            while let Some(request) = connection.accept().await {
                                let (_, mut response) = request.unwrap();
                                let reply = http::Response::builder().status(200).body(()).unwrap();
                                response.send_response(reply, true).unwrap();
                            }
                        });
                        let (mut client, driver) = h2::client::handshake(client_io)
                            .instrument(lookup_span(2, "9.9.9.9".parse().unwrap(), 4))
                            .await
                            .unwrap();
                        let driver = tokio::spawn(driver);
                        let request = http::Request::builder()
                            .uri("https://dns.example/dns-query")
                            .body(())
                            .unwrap();
                        let (response, _) = client.send_request(request, true).unwrap();
                        assert_eq!(response.await.unwrap().status(), 200);
                        drop(client);
                        driver.await.unwrap().unwrap();
                        server.await.unwrap();
                    })
                    .await
                    .expect("local H2 shutdown must complete");
                });
        });
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn ignores_payload_fields_and_connections_without_provider_context() {
        struct PrivatePayload;
        impl fmt::Debug for PrivatePayload {
            fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
                panic!("private payload must not even be formatted");
            }
        }
        let lines = crate::log_hooks::capture_logs(|| {
            let lookup = lookup_span(1, "1.1.1.1".parse().unwrap(), 0);
            let _lookup = lookup.enter();
            let connection = tracing::debug_span!(target: H2_TARGET, parent: None, "Connection");
            connection.follows_from(lookup.id());
            let _connection = connection.enter();
            tracing::trace!(target: H2_TARGET, frame = ?PrivatePayload, "recv HEADERS");
            tracing::trace!(target: H2_TARGET, frame = ?PrivatePayload, "recv DATA");
            tracing::debug!(target: H2_TARGET, error = ?PrivatePayload, "Connection::poll; connection error");
        });
        assert_eq!(lines.len(), 1, "one summary per connection: {lines:?}");
        assert_eq!(lines[0].0, 3);
        assert!(lines[0].1.contains("connection_error=true"));
        assert!(!lines[0].1.contains("eof=true"));
        assert!(!lines[0].1.contains("state="));
        let unrelated = crate::log_hooks::capture_logs(|| {
            let connection = tracing::debug_span!(target: H2_TARGET, parent: None, "Connection");
            let _connection = connection.enter();
            tracing::trace!(target: H2_TARGET, frame = ?PrivatePayload, "recv GOAWAY");
        });
        assert!(unrelated.is_empty());
    }
}
