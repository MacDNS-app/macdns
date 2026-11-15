// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! Local TCP DNS servers for tests that drive the hedge end to end.
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{
    rdata::{A, SOA},
    Name, RData, Record,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Answers every query with `rcode` and an empty answer section. With
/// `with_soa` the authority section carries the SOA that makes the negative
/// cacheable. Returns the listening address and the count of queries received.
pub(crate) async fn spawn_negative_server(
    rcode: ResponseCode,
    with_soa: bool,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = queries.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let counter = counter.clone();
            tokio::spawn(async move {
                while let Ok(size) = stream.read_u16().await {
                    let mut wire = vec![0; usize::from(size)];
                    stream.read_exact(&mut wire).await.unwrap();
                    counter.fetch_add(1, Ordering::SeqCst);
                    let mut message = Message::from_vec(&wire).unwrap();
                    message.metadata.message_type = MessageType::Response;
                    message.metadata.response_code = rcode;
                    if with_soa {
                        let soa = SOA::new(
                            Name::from_ascii("ns.example.").unwrap(),
                            Name::from_ascii("hostmaster.example.").unwrap(),
                            1,
                            3600,
                            600,
                            604800,
                            60,
                        );
                        message.add_authority(Record::from_rdata(
                            Name::from_ascii("example.").unwrap(),
                            60,
                            RData::SOA(soa),
                        ));
                    }
                    let wire = message.to_vec().unwrap();
                    stream.write_u16(wire.len() as u16).await.unwrap();
                    stream.write_all(&wire).await.unwrap();
                }
            });
        }
    });
    (address, queries)
}

/// Answers every query with one A record `address` (TTL 300) after `delay`.
pub(crate) async fn spawn_a_server(address: Ipv4Addr, delay: Duration) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                while let Ok(size) = stream.read_u16().await {
                    let mut wire = vec![0; usize::from(size)];
                    stream.read_exact(&mut wire).await.unwrap();
                    tokio::time::sleep(delay).await;
                    let mut message = Message::from_vec(&wire).unwrap();
                    message.metadata.message_type = MessageType::Response;
                    let name = message.queries[0].name().clone();
                    message.add_answer(Record::from_rdata(name, 300, RData::A(A(address))));
                    let wire = message.to_vec().unwrap();
                    stream.write_u16(wire.len() as u16).await.unwrap();
                    stream.write_all(&wire).await.unwrap();
                }
            });
        }
    });
    local
}

/// Answers every UDP query with one A record `address` (TTL 300).
pub(crate) async fn spawn_udp_a_server(address: Ipv4Addr) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let mut message = Message::from_vec(&buf[..len]).unwrap();
            message.metadata.message_type = MessageType::Response;
            let name = message.queries[0].name().clone();
            message.add_answer(Record::from_rdata(name, 300, RData::A(A(address))));
            let wire = message.to_vec().unwrap();
            socket.send_to(&wire, peer).await.unwrap();
        }
    });
    local
}
