// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! Local DoH server over real TCP, TLS and HTTP/2 for transport tests. Each
//! test decides the DNS reply, the HTTP headers and how the body is sent.
use crate::provider_transport::ProviderUpstream;
use crate::providers::{ns_cfg, opts};
use bytes::Bytes;
use hickory_proto::op::Message;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{NameServerPool, PoolContext, TlsConfig};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// How one request is answered.
pub(crate) struct Reply {
    /// Extra HTTP response headers, besides content type and length.
    pub headers: Vec<(&'static str, String)>,
    pub message: Message,
}

/// Sends a response body. The default sends it in one DATA frame. A test can
/// split it and pace the frames.
pub(crate) type SendBody = Arc<
    dyn Fn(h2::SendStream<Bytes>, Vec<u8>) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

pub(crate) type Respond = Arc<dyn Fn(Message) -> Reply + Send + Sync>;

pub(crate) struct DohServer {
    address: SocketAddr,
    client: rustls::ClientConfig,
    connections: Arc<std::sync::atomic::AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for DohServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl DohServer {
    pub(crate) async fn start(respond: Respond, send_body: Option<SendBody>) -> Self {
        let (client, server) = crate::doh_repro::tls_identity();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(server);
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accepted = connections.clone();
        let task = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let respond = respond.clone();
                let send_body = send_body.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(socket).await else {
                        return;
                    };
                    let mut connection = h2::server::handshake(tls).await.unwrap();
                    while let Some(request) = connection.accept().await {
                        let Ok((request, response)) = request else {
                            return;
                        };
                        let respond = respond.clone();
                        let send_body = send_body.clone();
                        tokio::spawn(answer(request, response, respond, send_body));
                    }
                });
            }
        });
        Self {
            address,
            client,
            connections,
            task,
        }
    }

    /// TCP connections accepted so far.
    pub(crate) fn connections(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The production upstream stack pointed at this server.
    pub(crate) fn upstream(&self) -> ProviderUpstream {
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
}

async fn answer(
    request: http::Request<h2::RecvStream>,
    mut response: h2::server::SendResponse<Bytes>,
    respond: Respond,
    send_body: Option<SendBody>,
) {
    let mut body = request.into_body();
    let mut wire = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        wire.extend_from_slice(&chunk);
        body.flow_control().release_capacity(chunk.len()).unwrap();
    }
    let query = Message::from_vec(&wire).unwrap();
    let reply = respond(query);
    let wire = reply.message.to_vec().unwrap();
    let mut builder = http::Response::builder()
        .header("content-type", "application/dns-message")
        .header("content-length", wire.len());
    for (name, value) in reply.headers {
        builder = builder.header(name, value);
    }
    let Ok(stream) = response.send_response(builder.body(()).unwrap(), false) else {
        return;
    };
    match send_body {
        Some(send_body) => send_body(stream, wire).await,
        None => {
            let mut stream = stream;
            let _ = stream.send_data(Bytes::from(wire), true);
        }
    }
}
