// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use futures::future::BoxFuture;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};
use tokio::sync::Semaphore;

const PING_TIMEOUT: Duration = Duration::from_secs(2);
const PINGS_PER_IP: u16 = 2;

/// Process-wide ceiling on concurrent probe pings. `PROBE_BUDGET` bounds how
/// long a single refinement probes, not how many packets it emits or how many
/// refinements probe at once. Without this cap, a burst of distinct names all
/// reaching `Verdict::Probe` could put hundreds of ICMP sockets in flight.
const PROBE_MAX_CONCURRENT_PINGS: usize = 8;

/// Ceiling on concurrent pings from one refinement, so a single query cannot
/// take every process-wide permit and stall the others until their budget
/// expires.
const PROBE_MAX_CONCURRENT_PINGS_PER_REFINEMENT: usize = 4;

/// Candidate ceilings. Without them a provider answering with a large CDN
/// RRset contributes one ping per address, and the number of provider sets is
/// bounded only by the pool size. Latency ranking needs a representative
/// sample, not the whole RRset.
const PROBE_MAX_PROVIDERS: usize = 4;
const PROBE_MAX_IPS_PER_PROVIDER: usize = 4;

/// ICMP probe clients, owned by the resolver session that built them.
///
/// `surge_ping::Client::new()` spawns its receiver task on whichever Tokio
/// runtime is current at construction time, and a resolver stop tears that
/// runtime down. A client held across the stop still sends packets, but no
/// receiver task ever completes a waiter again: every candidate burns
/// `PING_TIMEOUT`, and refinement degrades to "first candidate wins" for the
/// rest of the agent's lifetime. So the clients live in a slot the session can
/// empty. `reset_clients()` drops them while their runtime is still alive, and
/// the next session builds its own inside the new runtime.
#[derive(Default)]
struct ProbeClients {
    v4: Option<Arc<Client>>,
    v6: Option<Arc<Client>>,
}

fn clients() -> MutexGuard<'static, ProbeClients> {
    static CLIENTS: OnceLock<Mutex<ProbeClients>> = OnceLock::new();
    CLIENTS
        .get_or_init(|| Mutex::new(ProbeClients::default()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Initialize answer refinement probe clients for the current session. Must run
/// inside that session's Tokio runtime. On macOS, unprivileged SOCK_DGRAM ICMP
/// is available by default, but sandboxed or restricted environments can still
/// fail. A failure here must not abort the agent. Answer refinement degrades
/// to "first candidate wins" through `client_for` returning None.
pub fn init_clients() {
    let mut guard = clients();
    if guard.v4.is_none() {
        match Client::new(&Config::default()) {
            Ok(c) => guard.v4 = Some(Arc::new(c)),
            Err(e) => log::warn!(
                "answer refinement v4 probe unavailable, falling back: {}",
                e
            ),
        }
    }
    if guard.v6.is_none() {
        match Client::new(&Config::builder().kind(ICMP::V6).build()) {
            Ok(c) => guard.v6 = Some(Arc::new(c)),
            Err(e) => log::warn!(
                "answer refinement v6 probe unavailable, falling back: {}",
                e
            ),
        }
    }
}

/// Release the session's probe clients. Must run before the runtime that
/// created them is stopped, so the sockets and receiver tasks go away with the
/// session that owns them instead of surviving as orphans the next
/// `init_clients()` would leave in place.
pub fn reset_clients() {
    *clients() = ProbeClients::default();
}

fn client_for(ip: IpAddr) -> Option<Arc<Client>> {
    let guard = clients();
    match ip {
        IpAddr::V4(_) => guard.v4.clone(),
        IpAddr::V6(_) => guard.v6.clone(),
    }
}

fn probe_semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(PROBE_MAX_CONCURRENT_PINGS))
}

pub fn avg_duration(samples: &[Option<Duration>]) -> Duration {
    let valid: Vec<Duration> = samples.iter().filter_map(|d| *d).collect();
    if valid.is_empty() {
        return Duration::MAX;
    }
    valid.iter().sum::<Duration>() / valid.len() as u32
}

async fn ping_ip(ip: IpAddr, count: u16) -> Option<Duration> {
    let client = client_for(ip)?;
    let mut pinger = client.pinger(ip, PingIdentifier(rand::random())).await;
    pinger.timeout(PING_TIMEOUT);
    let mut results = Vec::with_capacity(count as usize);
    for seq in 0..count {
        results.push(
            pinger
                .ping(PingSequence(seq), &[])
                .await
                .ok()
                .map(|(_, rtt)| rtt),
        );
    }
    let avg = avg_duration(&results);
    if avg == Duration::MAX {
        None
    } else {
        Some(avg)
    }
}

/// Latency probe for one candidate address. Behind a trait so tests can assert
/// which addresses are probed, and how many probes run at once, without
/// emitting a single ICMP packet.
trait Pinger: Send + Sync {
    fn ping(&self, ip: IpAddr) -> BoxFuture<'_, Option<Duration>>;
}

struct IcmpPinger;

impl Pinger for IcmpPinger {
    fn ping(&self, ip: IpAddr) -> BoxFuture<'_, Option<Duration>> {
        Box::pin(ping_ip(ip, PINGS_PER_IP))
    }
}

/// Bounds and sanitizes the probe set. Two independent jobs:
///
/// 1. Drops every address the DNS-rebinding policy would strip from the answer
///    anyway. `background_refine` filters the *winning* answer only after
///    probing has finished, so without this an attacker-controlled domain can
///    aim ICMP at loopback, RFC 1918, link-local (169.254.169.254) and CGNAT
///    hosts inside the user's own network simply by being resolved. The filter
///    is unconditional: it governs which packets this process emits, which is
///    a separate question from which records the answer is allowed to carry.
/// 2. Caps how many providers and how many addresses per provider are probed.
fn probe_targets(candidates: &[(usize, BTreeSet<IpAddr>)]) -> Vec<(usize, Vec<IpAddr>)> {
    candidates
        .iter()
        .take(PROBE_MAX_PROVIDERS)
        .filter_map(|(provider_idx, ips)| {
            let probeable: Vec<IpAddr> = ips
                .iter()
                .filter(|ip| !crate::rebinding::ip_is_rebindable(ip))
                .take(PROBE_MAX_IPS_PER_PROVIDER)
                .copied()
                .collect();
            if probeable.is_empty() {
                None
            } else {
                Some((*provider_idx, probeable))
            }
        })
        .collect()
}

/// Pings one candidate address under both concurrency limits. Per-refinement
/// permit first, then the process-wide one: every probe takes them in this
/// order, so the two can never deadlock against each other.
async fn probe_address(
    ip: IpAddr,
    pinger: &dyn Pinger,
    refinement: &Semaphore,
) -> Option<Duration> {
    let _local = refinement.acquire().await.ok()?;
    let _global = probe_semaphore().acquire().await.ok()?;
    pinger.ping(ip).await
}

/// Hard ceiling on the total time `pick_best_provider` can spend probing.
/// Without this, a sandboxed environment that silently swallows ICMP
/// (NetworkExtension entitlements, MDM) makes every ping reach
/// `PING_TIMEOUT` × `PINGS_PER_IP` per IP, multiplied by the number of
/// candidate IPs. With a few CDN responses that turns into 8s+ of
/// background_refine work per query that hits `Verdict::Probe`. The budget
/// ends the probing, not the result: the best measurement completed by then
/// still wins, and the first candidate is used only when none completed.
const PROBE_BUDGET: Duration = Duration::from_secs(3);

pub async fn pick_best_provider(candidates: &[(usize, BTreeSet<IpAddr>)]) -> usize {
    let fallback = candidates.first().map(|(i, _)| *i).unwrap_or(0);
    if !crate::config::current().answer_refinement {
        return fallback;
    }
    init_clients();
    pick_best_provider_with(candidates, &IcmpPinger, PROBE_BUDGET).await
}

/// Probes every candidate address and returns the provider with the lowest
/// measured RTT. Results are folded in as each address answers, so an address
/// that never replies, or a provider whose addresses all swallow ICMP, cannot
/// hide a measurement another address already produced.
async fn pick_best_provider_with(
    candidates: &[(usize, BTreeSet<IpAddr>)],
    pinger: &dyn Pinger,
    budget: Duration,
) -> usize {
    let fallback = candidates.first().map(|(i, _)| *i).unwrap_or(0);
    let targets = probe_targets(candidates);
    if targets.is_empty() {
        return fallback;
    }
    let refinement = Semaphore::new(PROBE_MAX_CONCURRENT_PINGS_PER_REFINEMENT);
    let mut futs: FuturesUnordered<_> = targets
        .iter()
        .flat_map(|(provider_idx, ips)| ips.iter().map(move |&ip| (*provider_idx, ip)))
        .map(|(provider_idx, ip)| {
            let refinement = &refinement;
            async move { (provider_idx, probe_address(ip, pinger, refinement).await) }
        })
        .collect();
    let mut best: Option<(usize, Duration)> = None;
    let deadline = tokio::time::sleep(budget);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => break,
            next = futs.next() => {
                let Some((provider_idx, rtt)) = next else { break };
                if let Some(rtt) = rtt {
                    if best.is_none_or(|(_, current)| rtt < current) {
                        best = Some((provider_idx, rtt));
                    }
                }
            }
        }
    }
    best.map(|(provider_idx, _)| provider_idx)
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;

    #[test]
    fn avg_includes_only_successful() {
        let s = vec![
            Some(Duration::from_millis(20)),
            Some(Duration::from_millis(30)),
            None,
        ];
        assert_eq!(avg_duration(&s), Duration::from_millis(25));
    }
    #[test]
    fn all_lost_is_max() {
        assert_eq!(avg_duration(&[None, None]), Duration::MAX);
    }

    /// `probe_semaphore()` is process-wide, so probe tests running in parallel
    /// compete for its permits and can throttle each other below the
    /// per-refinement cap. Every test that emits probes takes this lock, which
    /// keeps the observed concurrency a property of the code under test rather
    /// than of the test harness's scheduling.
    fn probe_test_serial() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// Injected pinger: records every probed address and the highest number of
    /// probes that were ever admitted past the semaphores at the same time.
    #[derive(Default)]
    struct RecordingPinger {
        probed: Mutex<Vec<IpAddr>>,
        in_flight: AtomicUsize,
        peak: AtomicUsize,
    }

    impl RecordingPinger {
        fn probed(&self) -> Vec<IpAddr> {
            self.probed.lock().unwrap().clone()
        }

        fn peak(&self) -> usize {
            self.peak.load(Ordering::Acquire)
        }
    }

    impl Pinger for RecordingPinger {
        fn ping(&self, ip: IpAddr) -> BoxFuture<'_, Option<Duration>> {
            Box::pin(async move {
                self.probed.lock().unwrap().push(ip);
                let live = self.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
                self.peak.fetch_max(live, Ordering::AcqRel);
                // Park so every probe the semaphores admitted overlaps with
                // the others: without this the peak would read 1 even for a
                // completely unbounded implementation.
                tokio::task::yield_now().await;
                tokio::task::yield_now().await;
                self.in_flight.fetch_sub(1, Ordering::AcqRel);
                Some(Duration::from_millis(10))
            })
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// Every address the rebinding policy rejects must be dropped before any
    /// packet is emitted. `background_refine` filters the winning answer only
    /// after probing, so a hostile domain would otherwise get this process to
    /// ICMP-scan the user's own network, including the cloud metadata address.
    #[tokio::test]
    async fn probe_skips_private_and_reserved_addresses() {
        let _serial = probe_test_serial().lock().await;
        let private: BTreeSet<IpAddr> = [
            v4(127, 0, 0, 1),
            v4(10, 1, 2, 3),
            v4(192, 168, 1, 1),
            v4(172, 16, 5, 5),
            v4(169, 254, 169, 254),
            v4(100, 64, 0, 1),
            v4(0, 0, 0, 0),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fc00::1".parse::<Ipv6Addr>().unwrap()),
        ]
        .into_iter()
        .collect();
        let mut mixed = private.clone();
        mixed.insert(v4(9, 9, 9, 9));

        let pinger = RecordingPinger::default();
        let best =
            pick_best_provider_with(&[(3, mixed), (7, private.clone())], &pinger, PROBE_BUDGET)
                .await;

        let probed = pinger.probed();
        assert_eq!(
            probed,
            vec![v4(9, 9, 9, 9)],
            "only the public address may be probed"
        );
        for ip in &private {
            assert!(
                !probed.contains(ip),
                "{} must never be probed by answer refinement",
                ip
            );
        }
        assert_eq!(best, 3, "the provider with a reachable address must win");
    }

    /// A candidate set with nothing publicly routable must emit no packets at
    /// all and fall back to the first candidate.
    #[tokio::test]
    async fn probe_emits_nothing_when_every_candidate_is_private() {
        let _serial = probe_test_serial().lock().await;
        let only_private: BTreeSet<IpAddr> =
            [v4(10, 0, 0, 1), v4(192, 168, 0, 2)].into_iter().collect();
        let pinger = RecordingPinger::default();
        let best = pick_best_provider_with(
            &[(5, only_private.clone()), (6, only_private)],
            &pinger,
            PROBE_BUDGET,
        )
        .await;
        assert!(pinger.probed().is_empty(), "no probe may be emitted");
        assert_eq!(best, 5, "must fall back to the first candidate");
    }

    /// Concurrency is capped, not just duration. The probe budget bounds how
    /// long refinement runs, not how many pings are in flight at once.
    #[tokio::test]
    async fn probe_concurrency_never_exceeds_the_cap() {
        let _serial = probe_test_serial().lock().await;
        let candidates: Vec<(usize, BTreeSet<IpAddr>)> = (0..PROBE_MAX_PROVIDERS)
            .map(|p| {
                let ips: BTreeSet<IpAddr> = (0..PROBE_MAX_IPS_PER_PROVIDER)
                    .map(|i| v4(9, 9, p as u8, i as u8))
                    .collect();
                (p, ips)
            })
            .collect();
        let pinger = RecordingPinger::default();
        let _ = pick_best_provider_with(&candidates, &pinger, PROBE_BUDGET).await;

        assert_eq!(
            pinger.probed().len(),
            PROBE_MAX_PROVIDERS * PROBE_MAX_IPS_PER_PROVIDER,
            "every admitted candidate should still be probed"
        );
        assert!(
            pinger.peak() > 1,
            "probes must genuinely overlap, otherwise the cap assertion is vacuous"
        );
        assert!(
            pinger.peak() <= PROBE_MAX_CONCURRENT_PINGS_PER_REFINEMENT,
            "peak concurrency {} exceeded the per-refinement cap {}",
            pinger.peak(),
            PROBE_MAX_CONCURRENT_PINGS_PER_REFINEMENT
        );
        assert!(
            pinger.peak() <= PROBE_MAX_CONCURRENT_PINGS,
            "peak concurrency {} exceeded the process-wide cap {}",
            pinger.peak(),
            PROBE_MAX_CONCURRENT_PINGS
        );
    }

    /// Fan-out is bounded by candidate count too: a large CDN RRset, or a pool
    /// that grows, must not turn into one ping per address per provider.
    #[tokio::test]
    async fn probe_caps_providers_and_addresses_per_provider() {
        let _serial = probe_test_serial().lock().await;
        let oversized = PROBE_MAX_IPS_PER_PROVIDER + 6;
        let candidates: Vec<(usize, BTreeSet<IpAddr>)> = (0..PROBE_MAX_PROVIDERS + 3)
            .map(|p| {
                let ips: BTreeSet<IpAddr> =
                    (0..oversized).map(|i| v4(9, 9, p as u8, i as u8)).collect();
                (p, ips)
            })
            .collect();
        let pinger = RecordingPinger::default();
        let _ = pick_best_provider_with(&candidates, &pinger, PROBE_BUDGET).await;

        let probed = pinger.probed();
        assert_eq!(
            probed.len(),
            PROBE_MAX_PROVIDERS * PROBE_MAX_IPS_PER_PROVIDER,
            "probe fan-out must be capped by provider and address limits"
        );
        for ip in &probed {
            let IpAddr::V4(v4) = ip else {
                panic!("unexpected address family");
            };
            let provider = v4.octets()[2] as usize;
            let address = v4.octets()[3] as usize;
            assert!(
                provider < PROBE_MAX_PROVIDERS,
                "provider {} is past the provider cap",
                provider
            );
            assert!(
                address < PROBE_MAX_IPS_PER_PROVIDER,
                "address {} is past the per-provider cap",
                address
            );
        }
    }

    fn probe_session() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap()
    }

    /// A probe client belongs to the session that built it: `Client::new`
    /// spawns its receiver task on the runtime that is current at construction
    /// time. A client that outlives its runtime still sends, but nothing ever
    /// completes a waiter again, so refinement burns the whole probe budget and
    /// falls back to the first provider on every query until the agent process
    /// restarts. Process-wide `OnceLock`s made that state terminal, because
    /// nothing could clear or rebuild them.
    #[test]
    fn reset_rebuilds_probe_clients_in_the_next_session() {
        let first_session = probe_session();
        let first = first_session.block_on(async {
            init_clients();
            client_for(v4(9, 9, 9, 9))
        });
        // The weak handle keeps the `Arc` allocation reserved without keeping
        // the client alive, so the allocator cannot hand the second session the
        // same address and satisfy the identity check by accident.
        let orphan = first.as_ref().map(Arc::downgrade);
        let first_ptr = first.as_ref().map(Arc::as_ptr);
        drop(first);

        // The shutdown ordering under test: release the clients while the
        // runtime owning their receiver tasks is still alive.
        reset_clients();
        first_session.shutdown_timeout(Duration::from_secs(2));

        {
            let guard = clients();
            assert!(
                guard.v4.is_none() && guard.v6.is_none(),
                "reset must leave no client behind for the next session"
            );
        }
        if let Some(orphan) = &orphan {
            assert!(
                orphan.upgrade().is_none(),
                "the previous session's client must be dropped, not merely unreferenced"
            );
        }

        let second_session = probe_session();
        let second = second_session.block_on(async {
            init_clients();
            client_for(v4(9, 9, 9, 9))
        });
        let second_ptr = second.as_ref().map(Arc::as_ptr);
        drop(second);
        reset_clients();
        second_session.shutdown_timeout(Duration::from_secs(2));

        // `Client::new` needs an unprivileged ICMP socket, which macOS grants to
        // every user. A sandbox that denies it exercises the documented "first
        // candidate wins" fallback instead, and both sessions must agree on it.
        assert_eq!(
            first_ptr.is_some(),
            second_ptr.is_some(),
            "ICMP availability must not differ between sessions"
        );
        if let (Some(first_ptr), Some(second_ptr)) = (first_ptr, second_ptr) {
            assert_ne!(
                first_ptr, second_ptr,
                "the new session must build its own client instead of reusing the orphan"
            );
        }
    }

    /// Answers each address after a fixed delay, or never.
    struct ScriptedPinger(Vec<(IpAddr, Option<Duration>)>);

    impl Pinger for ScriptedPinger {
        fn ping(&self, ip: IpAddr) -> BoxFuture<'_, Option<Duration>> {
            let delay = self
                .0
                .iter()
                .find(|(addr, _)| *addr == ip)
                .and_then(|(_, delay)| *delay);
            Box::pin(async move {
                match delay {
                    Some(delay) => {
                        tokio::time::sleep(delay).await;
                        Some(delay)
                    }
                    None => std::future::pending().await,
                }
            })
        }
    }

    /// A provider whose addresses swallow ICMP must not cost the measurements
    /// the others already produced, and one silent address must not hide its
    /// sibling's fast reply.
    #[tokio::test(start_paused = true)]
    async fn budget_keeps_the_best_completed_measurement() {
        let _serial = probe_test_serial().lock().await;
        let silent = v4(1, 1, 1, 1);
        let fast = v4(8, 8, 8, 8);
        let fast_sibling_silent = v4(8, 8, 4, 4);
        let slow = v4(9, 9, 9, 9);
        let pinger = ScriptedPinger(vec![
            (silent, None),
            (fast, Some(Duration::from_millis(10))),
            (fast_sibling_silent, None),
            (slow, Some(Duration::from_millis(400))),
        ]);
        let candidates = vec![
            (0, BTreeSet::from([silent])),
            (1, BTreeSet::from([fast, fast_sibling_silent])),
            (2, BTreeSet::from([slow])),
        ];

        let started = tokio::time::Instant::now();
        let best = pick_best_provider_with(&candidates, &pinger, Duration::from_secs(3)).await;

        assert_eq!(best, 1, "the fastest completed measurement must win");
        assert!(started.elapsed() <= Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn budget_falls_back_when_nothing_answered() {
        let _serial = probe_test_serial().lock().await;
        let pinger = ScriptedPinger(vec![]);
        let candidates = vec![
            (4, BTreeSet::from([v4(1, 1, 1, 1)])),
            (5, BTreeSet::from([v4(8, 8, 8, 8)])),
        ];

        let best = pick_best_provider_with(&candidates, &pinger, Duration::from_secs(3)).await;

        assert_eq!(best, 4);
    }
}
