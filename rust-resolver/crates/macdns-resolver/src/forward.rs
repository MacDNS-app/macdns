// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError, NoRecords};
use hickory_resolver::TokioResolver;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use crate::zones::validate_forward_target;

pub struct ForwardResolver {
    pub resolver: TokioResolver,
    pub servers: Vec<String>,
}

impl ForwardResolver {
    /// Captive and global forwarding get the same target rule as forward
    /// zones. A hotspot advertising `0.0.0.0` or a multicast group would
    /// otherwise be configured and black-hole every query, so unusable
    /// addresses are dropped and the usable ones still serve. Only when
    /// nothing usable is left does this fail, which leaves the caller on its
    /// existing no-servers path (bypass) instead of a silent black hole.
    pub fn new(servers: &[String]) -> Result<Self, String> {
        Self::build(servers, 53)
    }

    #[cfg(test)]
    pub(crate) fn for_local_test(port: u16) -> Self {
        Self::build(&["127.0.0.1".into()], port).unwrap()
    }

    fn build(servers: &[String], port: u16) -> Result<Self, String> {
        if servers.is_empty() {
            return Err("no forwarding servers".into());
        }
        let mut name_servers = Vec::with_capacity(servers.len());
        let mut usable = Vec::with_capacity(servers.len());
        for s in servers {
            let ip = IpAddr::from_str(s).map_err(|e| format!("{}: {}", s, e))?;
            if let Err(e) = validate_forward_target(ip) {
                log::warn!("forwarding: skipping {}", e);
                continue;
            }
            let mut name_server = NameServerConfig::udp_and_tcp(ip);
            for connection in &mut name_server.connections {
                connection.port = port;
            }
            name_servers.push(name_server);
            usable.push(s.clone());
        }
        if name_servers.is_empty() {
            return Err("no usable forwarding servers".into());
        }
        let cfg = ResolverConfig::from_parts(None, vec![], name_servers);
        let resolver = TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default())
            .with_options(build_forward_opts())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            resolver,
            servers: usable,
        })
    }
}

/// Upper bound for the whole network-DNS probe. The forward options already
/// cap one lookup at 2s x 2 attempts. This only guards against a transport
/// that never settles.
const NETWORK_DNS_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Proves that the network's own resolvers answer before captive detection
/// moves public DNS onto them. Any NOERROR or NXDOMAIN reply counts, because
/// both show a working resolver. Timeouts, SERVFAIL and REFUSED do not, so a
/// WAN outage keeps the public DoH path and its serve-stale answers.
/// It uses the same transport and options as live forwarding and bypasses
/// every resolver cache.
pub async fn probe_network_dns(servers: &[String]) -> Result<(), String> {
    probe_network_dns_at(servers, 53, NETWORK_DNS_PROBE_TIMEOUT).await
}

async fn probe_network_dns_at(
    servers: &[String],
    port: u16,
    bound: Duration,
) -> Result<(), String> {
    let forward = ForwardResolver::build(servers, port)?;
    let name = Name::from_str("apple.com.").map_err(|e| e.to_string())?;
    match tokio::time::timeout(bound, forward.resolver.lookup(name, RecordType::A)).await {
        Err(_) => Err("timeout".into()),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => network_dns_answer(&error),
    }
}

fn network_dns_answer(error: &NetError) -> Result<(), String> {
    match error {
        NetError::Dns(DnsError::NoRecordsFound(NoRecords {
            response_code: ResponseCode::NoError | ResponseCode::NXDomain,
            ..
        })) => Ok(()),
        NetError::Dns(DnsError::NoRecordsFound(NoRecords { response_code, .. })) => {
            Err(format!("rcode={response_code:?}"))
        }
        NetError::Timeout => Err("timeout".into()),
        other => Err(other.to_string()),
    }
}

fn build_forward_opts() -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    // Forwarding targets are private/split-DNS resolvers (DHCP, VPN,
    // Tailscale). Public DNSSEC validation here turns legitimate unsigned
    // negative answers into SERVFAIL, so only the public DoH path validates.
    opts.validate = false;
    // The resolver owns the DNS cache, so hickory's internal one stays off.
    opts.cache_size = 0;
    // Bound forward latency. hickory's defaults (5s × 2 attempts = 10s) let
    // a flapping VPN/Tailscale resolver block the calling task for a full
    // ten seconds before SERVFAIL. 2s × 2 keeps one UDP retry for packet
    // loss while capping the worst case at four seconds.
    opts.timeout = std::time::Duration::from_secs(2);
    opts.attempts = 2;
    opts.case_randomization = false;
    opts
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use tokio::net::UdpSocket;

    #[test]
    fn empty_is_err() {
        assert!(ForwardResolver::new(&[]).is_err());
    }

    #[test]
    fn invalid_ip_is_err() {
        assert!(ForwardResolver::new(&["bad".into()]).is_err());
    }

    #[test]
    fn valid_ip_is_ok() {
        assert!(ForwardResolver::new(&["192.168.1.1".into()]).is_ok());
    }

    #[test]
    fn unusable_targets_are_dropped_and_usable_ones_kept() {
        let resolver =
            ForwardResolver::new(&["0.0.0.0".into(), "192.168.1.1".into(), "ff02::fb".into()])
                .expect("a usable server must still build a resolver");

        assert_eq!(resolver.servers, vec!["192.168.1.1".to_string()]);
    }

    #[test]
    fn only_unusable_targets_is_err() {
        for ip in [
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.251",
            "::",
            "ff02::fb",
        ] {
            assert!(
                ForwardResolver::new(&[ip.into()]).is_err(),
                "{ip} must not be accepted as a forwarding server"
            );
        }
    }

    #[test]
    fn forward_resolver_does_not_validate_split_dns() {
        let opts = crate::config::ResolverOptions {
            dnssec: true,
            ..Default::default()
        };
        crate::config::set(opts);
        assert!(!build_forward_opts().validate);
        crate::config::set(crate::config::ResolverOptions::default());
    }

    /// Answers every UDP query with `rcode` and an empty answer section.
    async fn fake_resolver(rcode: ResponseCode) -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let request = Message::from_bytes(&buf[..len]).unwrap();
                let mut reply = Message::new(
                    request.metadata.id,
                    MessageType::Response,
                    request.metadata.op_code,
                );
                reply.metadata.response_code = rcode;
                reply.add_query(request.queries[0].clone());
                socket
                    .send_to(&reply.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        port
    }

    fn loopback() -> Vec<String> {
        vec!["127.0.0.1".into()]
    }

    #[tokio::test]
    async fn network_dns_probe_accepts_a_positive_or_negative_answer() {
        for rcode in [ResponseCode::NoError, ResponseCode::NXDomain] {
            let port = fake_resolver(rcode).await;
            assert_eq!(
                probe_network_dns_at(&loopback(), port, Duration::from_secs(2)).await,
                Ok(()),
                "{rcode:?} proves the network resolver answers"
            );
        }
    }

    #[tokio::test]
    async fn network_dns_probe_rejects_a_resolver_that_cannot_resolve() {
        for rcode in [ResponseCode::ServFail, ResponseCode::Refused] {
            let port = fake_resolver(rcode).await;
            assert!(
                probe_network_dns_at(&loopback(), port, Duration::from_secs(2))
                    .await
                    .is_err(),
                "{rcode:?} must not count as a usable resolver"
            );
        }
    }

    #[tokio::test]
    async fn network_dns_probe_rejects_a_silent_resolver_within_its_bound() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = silent.local_addr().unwrap().port();
        let started = std::time::Instant::now();

        let outcome = probe_network_dns_at(&loopback(), port, Duration::from_millis(200)).await;

        assert_eq!(outcome, Err("timeout".to_string()));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn network_dns_probe_rejects_an_empty_or_unusable_server_list() {
        for servers in [vec![], vec!["0.0.0.0".to_string()]] {
            assert!(probe_network_dns(&servers).await.is_err());
        }
    }

    #[test]
    fn forward_resolver_bounds_latency_but_keeps_one_retry() {
        let opts = build_forward_opts();

        assert_eq!(opts.timeout, std::time::Duration::from_secs(2));
        assert_eq!(opts.attempts, 2);
    }
}
