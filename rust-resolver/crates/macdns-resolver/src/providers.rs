// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use crate::config::DoHProviderId;
use crate::provider_transport::{
    lookup_diagnostics, request_options, LookupResult, ProviderUpstream,
};
use arc_swap::ArcSwap;
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::{DnsRequestOptions, Query};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::{Name, RecordType};
use hickory_resolver::{NameServerPool, PoolContext, TlsConfig};
use rand::{rng, RngExt};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

pub const PROVIDER_TIMEOUT: Duration = Duration::from_secs(3);
/// Number of most-recent successful lookup samples kept per provider conn.
pub const LATENCY_WINDOW_SIZE: usize = 30;

/// Slots per upstream IP. Each provider has 2 v4 + 2 v6 IPs, so its pool
/// holds `CONNS_PER_ENDPOINT * 4` connections. The pool is fixed at
/// construction and never resized: there is no resize race, no pressure
/// heuristic to mistune, and upstream rate limiters see the same connection
/// count for the agent's lifetime instead of reconnect bursts.
pub const CONNS_PER_ENDPOINT: usize = 4;

/// Timeout for the warm-up lookup that flips a conn from `Warming` to
/// `Ready`. Generous on purpose: a cold TLS handshake can take a second on
/// slow links, and a failed warm-up only costs one maintenance tick to retry.
const WARMUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Each maintenance tick re-warms `Degraded` conns and keepalive-probes idle
/// `Ready` conns.
const MAINTENANCE_TICK: Duration = Duration::from_secs(30);

/// Idle time after which a `Ready` conn gets a keepalive probe. Well below
/// typical NAT timeouts (300s), so the probe lands before the conntrack entry
/// expires and the next real query pays a silent reconnect.
const KEEPALIVE_IDLE_THRESHOLD: Duration = Duration::from_secs(60);

/// Keepalive probe budget. Tight enough to detect a wedged conn within one
/// tick, loose enough to ride out a briefly loaded upstream without churn.
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(2);

/// Generation age from which maintenance replaces a `Ready` slot, at the
/// first tick that finds it this old. Quad9 closes a connection about 600 s
/// after it opened, without a GOAWAY, and the next query on that slot then
/// pays the reconnect. Replacing the slot first keeps the reconnect out of
/// the query path. The same age applies to every provider.
const CONN_ROTATION_AGE: Duration = Duration::from_secs(500);

/// Delay before the first maintenance tick, so it does not race the initial
/// warm-ups.
const MAINTENANCE_WARMUP_DELAY: Duration = Duration::from_secs(5);

/// Deadline for leaving `Warming`. A slot still `Warming` after this is stuck:
/// its warm-up timed out without exiting cleanly or never started. The
/// generation-fenced timer from `arm_stuck_warming_watchdog` starts recovery
/// at this deadline, not up to one `MAINTENANCE_TICK` later. `maintenance_tick`
/// still samples stuck slots as a backstop for the entries it drives itself.
/// Kept well above `WARMUP_TIMEOUT` so a slow handshake is not interrupted.
const STUCK_WARMING_THRESHOLD: Duration = Duration::from_secs(15);

/// Maximum random delay before a warm-up starts. Without it the
/// `CONNS_PER_ENDPOINT` conns to each upstream IP would hit it with that many
/// simultaneous TLS handshakes. The jitter spreads them across this window.
const WARMUP_JITTER_MAX: Duration = Duration::from_millis(150);

/// Consecutive primary-hedge timeouts on one slot before it is demoted to
/// `Degraded`. Low enough that a wedged slot stops winning picks within
/// seconds instead of waiting up to 60s for keepalive, high enough that a
/// brief burst does not flap a healthy slot. The demote never rebuilds.
/// Rebuilding under load causes a reconnect death spiral, so maintenance
/// rebuilds on its own clock.
pub(crate) const CONSECUTIVE_TIMEOUTS_THRESHOLD: u32 = 3;

/// In-flight queries on one connection before `pick_conn` prefers a sibling,
/// which spreads hedge bursts across the pool. When every slot in the tier is
/// at the cap, `pick_conn` still returns one of them. The cap is a routing
/// preference, never a throttle that stalls queries.
const MAX_INFLIGHT_PER_CONN: usize = 4;

/// Per-slot quarantine after a transport failure, so a fresh replacement does
/// not win picks while siblings can absorb traffic. Only a preference: if no
/// sibling is available the slot is still used, so provider-local churn never
/// becomes a no-pick error.
const TRANSPORT_ERROR_COOLDOWN_MS: u64 = 500;

/// Latency ceiling under which an alternate address family is considered
/// healthy enough to be preferred for the backup pick.
const BACKUP_FAMILY_HEALTHY_US: u64 = 500_000;

/// A whole address family is suppressed only after every selected provider IP
/// has produced failures for this long while the opposite family has proven
/// alive. Network-change events or this retry interval close the gate.
const FAMILY_GATE_FAILURE_WINDOW: Duration = Duration::from_secs(2 * 60);
const FAMILY_GATE_RETRY_AFTER: Duration = Duration::from_secs(2 * 60 * 60);

/// Origin of the monotonic `now_secs` / `now_millis` clocks shared by every
/// `ProviderConn`.
static EPOCH: OnceLock<Instant> = OnceLock::new();

fn now_secs() -> u64 {
    let start = *EPOCH.get_or_init(Instant::now);
    Instant::now().saturating_duration_since(start).as_secs()
}

fn now_millis() -> u64 {
    let start = *EPOCH.get_or_init(Instant::now);
    Instant::now().saturating_duration_since(start).as_millis() as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnState {
    /// No successful warm-up yet, typically right after startup or a rebuild.
    /// Picked only when no `Ready` slot is available.
    Warming,
    /// A warm-up or real query succeeded. Preferred pick target.
    Ready,
    /// A warm-up, probe or rebuild failed, or timeouts reached
    /// `CONSECUTIVE_TIMEOUTS_THRESHOLD`. Last-resort pick. The maintenance
    /// tick reprobes it and rebuilds it if the probe fails.
    Degraded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    fn opposite(self) -> Self {
        match self {
            Self::V4 => Self::V6,
            Self::V6 => Self::V4,
        }
    }
}

#[derive(Default)]
struct FamilyGateState {
    failed_targets: Vec<FamilyGateFailure>,
    last_success_secs: Option<u64>,
}

impl FamilyGateState {
    fn reset(&mut self) {
        self.failed_targets.clear();
        self.last_success_secs = None;
    }

    fn remember_failure(&mut self, target: FamilyGateEndpoint, now_secs: u64) {
        if !self
            .failed_targets
            .iter()
            .any(|failure| failure.target == target)
        {
            self.failed_targets.push(FamilyGateFailure {
                target,
                first_failed_secs: now_secs,
            });
        }
    }

    fn clear_failures_after_success(&mut self, now_secs: u64) {
        self.last_success_secs = Some(now_secs);
        self.failed_targets.clear();
    }

    fn all_targets_failed_since(
        &self,
        targets: &[FamilyGateEndpoint],
        now_secs: u64,
    ) -> Option<u64> {
        if targets.is_empty() {
            return None;
        }
        let mut newest_first_failure = 0;
        for target in targets {
            let first_failed_secs = self
                .failed_targets
                .iter()
                .find(|failure| failure.target == *target)?
                .first_failed_secs;
            newest_first_failure = newest_first_failure.max(first_failed_secs);
        }
        (now_secs.saturating_sub(newest_first_failure) >= FAMILY_GATE_FAILURE_WINDOW.as_secs())
            .then_some(newest_first_failure)
    }
}

#[derive(Default)]
struct FamilyGateInner {
    v4: FamilyGateState,
    v6: FamilyGateState,
}

impl FamilyGateInner {
    fn states_mut(&mut self, family: AddressFamily) -> (&mut FamilyGateState, &FamilyGateState) {
        match family {
            AddressFamily::V4 => (&mut self.v4, &self.v6),
            AddressFamily::V6 => (&mut self.v6, &self.v4),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FamilyGateEndpoint {
    provider_id: DoHProviderId,
    ip: IpAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FamilyGateFailure {
    target: FamilyGateEndpoint,
    first_failed_secs: u64,
}

pub(crate) struct FamilyGateSet {
    v4_targets: Vec<FamilyGateEndpoint>,
    v6_targets: Vec<FamilyGateEndpoint>,
    v4_open_until_secs: AtomicU64,
    v6_open_until_secs: AtomicU64,
    inner: Mutex<FamilyGateInner>,
}

impl FamilyGateSet {
    fn for_provider_ids(provider_ids: Vec<DoHProviderId>) -> Arc<Self> {
        let mut v4_targets = Vec::with_capacity(provider_ids.len() * 2);
        let mut v6_targets = Vec::with_capacity(provider_ids.len() * 2);
        for provider_id in provider_ids {
            let spec = provider_spec_for_id(provider_id);
            v4_targets.extend(
                spec.v4_endpoints
                    .into_iter()
                    .map(|ip| FamilyGateEndpoint { provider_id, ip }),
            );
            v6_targets.extend(
                spec.v6_endpoints
                    .into_iter()
                    .map(|ip| FamilyGateEndpoint { provider_id, ip }),
            );
        }
        Arc::new(Self {
            v4_targets,
            v6_targets,
            v4_open_until_secs: AtomicU64::new(0),
            v6_open_until_secs: AtomicU64::new(0),
            inner: Mutex::new(FamilyGateInner::default()),
        })
    }

    fn open_until_for(&self, family: AddressFamily) -> &AtomicU64 {
        match family {
            AddressFamily::V4 => &self.v4_open_until_secs,
            AddressFamily::V6 => &self.v6_open_until_secs,
        }
    }

    fn targets_for(&self, family: AddressFamily) -> &[FamilyGateEndpoint] {
        match family {
            AddressFamily::V4 => &self.v4_targets,
            AddressFamily::V6 => &self.v6_targets,
        }
    }

    fn target_for(
        &self,
        provider_id: DoHProviderId,
        family: AddressFamily,
        ip: IpAddr,
    ) -> Option<FamilyGateEndpoint> {
        let target = FamilyGateEndpoint { provider_id, ip };
        self.targets_for(family).contains(&target).then_some(target)
    }

    fn is_open_for(&self, family: AddressFamily) -> bool {
        self.is_open_for_at(family, now_secs())
    }

    fn is_open_for_at(&self, family: AddressFamily, now_secs: u64) -> bool {
        let open_until = self.open_until_for(family).load(Ordering::Acquire);
        if gate_open_at(open_until, now_secs) {
            return true;
        }
        if open_until == 0 {
            return false;
        }
        match self.open_until_for(family).compare_exchange(
            open_until,
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => false,
            Err(current) => gate_open_at(current, now_secs),
        }
    }

    fn is_allowed(&self, family: AddressFamily) -> bool {
        !self.is_open_for(family)
    }

    fn record_success_for_ip(&self, provider_id: DoHProviderId, family: AddressFamily, ip: IpAddr) {
        self.record_success_at(provider_id, family, ip, now_secs());
    }

    fn record_success_at(
        &self,
        provider_id: DoHProviderId,
        family: AddressFamily,
        ip: IpAddr,
        now_secs: u64,
    ) {
        if self.target_for(provider_id, family, ip).is_none() {
            return;
        }
        if self.is_open_for_at(family, now_secs) {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if self.is_open_now(family, now_secs) {
            return;
        }
        let (state, _) = inner.states_mut(family);
        state.clear_failures_after_success(now_secs);
    }

    fn record_failure_for_ip(&self, provider_id: DoHProviderId, family: AddressFamily, ip: IpAddr) {
        self.record_failure_at(provider_id, family, ip, now_secs());
    }

    fn record_failure_at(
        &self,
        provider_id: DoHProviderId,
        family: AddressFamily,
        ip: IpAddr,
        now_secs: u64,
    ) {
        let Some(target) = self.target_for(provider_id, family, ip) else {
            return;
        };
        if self.is_open_for_at(family, now_secs) || self.is_open_for_at(family.opposite(), now_secs)
        {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if self.is_open_now(family, now_secs) || self.is_open_now(family.opposite(), now_secs) {
            return;
        }
        let (state, other) = inner.states_mut(family);

        state.remember_failure(target, now_secs);
        let Some(all_failed_since) =
            state.all_targets_failed_since(self.targets_for(family), now_secs)
        else {
            return;
        };
        let opposite_family_alive = other
            .last_success_secs
            .is_some_and(|last| last >= all_failed_since);
        if opposite_family_alive {
            state.reset();
            self.open_until_for(family).store(
                now_secs.saturating_add(FAMILY_GATE_RETRY_AFTER.as_secs()),
                Ordering::Release,
            );
            log::warn!(
                "{:?} family gate opened after all selected provider IPs failed for {:?}",
                family,
                FAMILY_GATE_FAILURE_WINDOW
            );
        }
    }

    fn close_all_for_network_change(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.v4.reset();
        inner.v6.reset();
        self.v4_open_until_secs.store(0, Ordering::Release);
        self.v6_open_until_secs.store(0, Ordering::Release);
        log::info!("address-family gates closed after network change");
    }

    fn is_open_now(&self, family: AddressFamily, now_secs: u64) -> bool {
        gate_open_at(
            self.open_until_for(family).load(Ordering::Acquire),
            now_secs,
        )
    }
}

fn gate_open_at(open_until_secs: u64, now_secs: u64) -> bool {
    open_until_secs != 0 && now_secs < open_until_secs
}

/// Result of a rebuild attempt. A build failure is distinct so the slot never
/// looks healthy while the old resolver is still active.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RebuildOutcome {
    /// Fresh resolver published in `Warming` under a new generation. The
    /// caller spawns its warm-up.
    Rebuilt,
    /// A concurrent path rebuilt after the caller's snapshot and owns the
    /// state transition. The caller does nothing.
    StaleGen,
    /// `try_build_resolver` failed, for example a TLS config rejected during
    /// network churn. The old resolver stays as a `Degraded` fallback. The
    /// generation still advances so pre-rebuild events cannot mark it healthy.
    BuildFailed(String),
}

/// Fields that must be read as one consistent snapshot. Published through one
/// `ArcSwap`, so a reader never sees a new generation with the old upstream or
/// the reverse. Every mutation holds the conn's `write_lock`.
#[derive(Clone)]
pub(crate) struct InnerState {
    pub(crate) gen: u64,
    pub(crate) state: ConnState,
    pub(crate) resolver: Arc<ProviderUpstream>,
    /// Built with this slot's transport. DO is always set. Never rebuild these
    /// from global config at query time.
    pub(crate) request_options: DnsRequestOptions,
    /// The DNSSEC setting this snapshot was built for. It is the upstream's
    /// default CD for clients that left the bit clear, so it identifies the
    /// policy the slot serves. `matches_configured_policy` uses it to keep a
    /// slot that failed to rebuild from answering under the wrong policy.
    ///
    /// Mirrors `needs_provider_rebuild` (`lib.rs`), which keys on `dnssec`
    /// alone. A knob added there must be added here too, or slots get gated
    /// out with no rebuild to clear them.
    pub(crate) built_for_dnssec: bool,
}

/// One encrypted upstream connection slot in a provider's fixed-size pool. A
/// slot's index, family and endpoint IP are stable for the agent's lifetime.
/// In-flight lookups keep the `Arc<ProviderUpstream>` captured at pick time
/// until they complete, while new picks already see a replacement.
pub struct ProviderConn {
    inner: ArcSwap<InnerState>,
    cfg: NameServerConfig,
    target_ip: IpAddr,
    family: AddressFamily,
    inflight: AtomicUsize,
    last_used_secs: AtomicU64,
    /// Hedge-side timeouts since the last success or rebuild. Reaching
    /// `CONSECUTIVE_TIMEOUTS_THRESHOLD` demotes the slot to `Degraded`
    /// without a rebuild. Maintenance retries it on its own clock.
    consecutive_timeouts: AtomicU32,
    transport_cooldown_until_ms: AtomicU64,
    /// Resolver generation start. Hickory can reconnect within one generation,
    /// so this is not the physical TCP connection's age.
    generation_started_ms: AtomicU64,
    /// Leases acquired since rebuild, approximate when acquisition races a rebuild.
    requests_served: AtomicU64,
    /// Serializes every read-modify-write of `inner`: rebuilds and the
    /// gen-gated transitions behind `record_*`. Reads stay lock-free.
    write_lock: Mutex<()>,
    /// Cancels the stuck-Warming watchdog armed for the current generation.
    /// Replaced on every arming and cancelled by every mutation of `inner`.
    warming_watchdog: Mutex<Option<CancellationToken>>,
    pub latency: LatencyWindow,
}

impl ProviderConn {
    fn new(cfg: NameServerConfig, target_ip: IpAddr, family: AddressFamily) -> Arc<Self> {
        // Startup panics on build failure because there is no previous
        // resolver to fall back to. Background rebuilds keep the previous one.
        let (upstream, options, dnssec) =
            try_build_resolver(cfg.clone()).expect("DoH provider build failed at init");
        let inner = InnerState {
            gen: 0,
            state: ConnState::Warming,
            resolver: Arc::new(upstream),
            request_options: options,
            built_for_dnssec: dnssec,
        };
        Arc::new(Self {
            inner: ArcSwap::from_pointee(inner),
            cfg,
            target_ip,
            family,
            inflight: AtomicUsize::new(0),
            last_used_secs: AtomicU64::new(now_secs()),
            consecutive_timeouts: AtomicU32::new(0),
            transport_cooldown_until_ms: AtomicU64::new(0),
            generation_started_ms: AtomicU64::new(now_millis()),
            requests_served: AtomicU64::new(0),
            write_lock: Mutex::new(()),
            warming_watchdog: Mutex::new(None),
            latency: LatencyWindow::new(),
        })
    }

    /// Publishes a new snapshot and cancels any armed stuck-Warming watchdog.
    /// The slot either left `Warming` or entered a new generation whose own
    /// warm-up arms a fresh watchdog. Callers hold `write_lock`.
    fn store_inner_locked(&self, next: InnerState) {
        self.inner.store(Arc::new(next));
        self.cancel_warming_watchdog();
    }

    /// Replaces the armed watchdog, cancelling the previous one, and returns
    /// the token the new watchdog must wait on.
    fn arm_warming_watchdog(&self) -> CancellationToken {
        let token = CancellationToken::new();
        let mut slot = self
            .warming_watchdog
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(previous) = slot.replace(token.clone()) {
            previous.cancel();
        }
        token
    }

    fn cancel_warming_watchdog(&self) {
        let previous = self
            .warming_watchdog
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(token) = previous {
            token.cancel();
        }
    }

    /// Callers that need more than one `InnerState` field read them from one
    /// snapshot so they cannot tear.
    pub(crate) fn snapshot(&self) -> Arc<InnerState> {
        self.inner.load_full()
    }

    /// Fail-closed policy gate. A slot built for a different DNSSEC setting
    /// carries a CD default that contradicts the configured policy, so it must
    /// not answer. `rebuild_all_conns` clears this for every slot within
    /// milliseconds of a toggle. A slot that stays stale had its build fail or
    /// lost a rebuild race.
    ///
    /// The configured setting is only a staleness gate, never a source of
    /// header bits. CD comes from the `InnerState` snapshot so it cannot split
    /// from the generation it was built for. Do not "simplify" this into
    /// reading CD from config at query time.
    ///
    /// The setting is an argument so callers read the global config once per
    /// pick instead of once per slot. `crate::config::current()` clones an
    /// `Arc` and this runs on the query hot path.
    pub(crate) fn matches_configured_policy(&self, want_dnssec: bool) -> bool {
        self.inner.load().built_for_dnssec == want_dnssec
    }

    pub fn generation(&self) -> u64 {
        self.inner.load().gen
    }

    pub(crate) fn family(&self) -> AddressFamily {
        self.family
    }

    pub(crate) fn target_ip(&self) -> IpAddr {
        self.target_ip
    }

    pub(crate) fn state(&self) -> ConnState {
        self.inner.load().state
    }

    /// Sets the state without gen gating, so tests can seed states without
    /// the warm-up network path. Production must use `try_set_state_if_gen`
    /// so a stale event cannot stamp the current generation.
    #[cfg(test)]
    fn force_state(&self, new_state: ConnState) {
        let _guard = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.inner.load_full();
        if current.state == new_state {
            return;
        }
        let mut next = (*current).clone();
        next.state = new_state;
        self.store_inner_locked(next);
    }

    /// Gen-gated state transition. Returns `true` when `expected_gen` is
    /// still current. Check and swap happen under `write_lock`, so a
    /// concurrent rebuild cannot leave a stale `Ready` on a fresh resolver.
    fn try_set_state_if_gen(&self, expected_gen: u64, new_state: ConnState) -> bool {
        let _guard = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.inner.load_full();
        if current.gen != expected_gen {
            return false;
        }
        // A `Ready` target means the caller just saw the slot healthy, even
        // when it is already `Ready`. Reset the timeout counter before the
        // early return, or a keepalive success leaves old timeouts that let
        // the next one demote a slot that just proved healthy.
        if new_state == ConnState::Ready {
            self.consecutive_timeouts.store(0, Ordering::Release);
        }
        if current.state == new_state {
            return true;
        }
        let mut next = (*current).clone();
        next.state = new_state;
        self.store_inner_locked(next);
        true
    }

    /// A build failure is still a rebuild boundary. The old resolver stays as
    /// a degraded fallback, but the generation advances under `write_lock` so
    /// in-flight events from before the failure cannot record success or
    /// latency on the demoted fallback.
    fn store_build_failed_state_locked(&self, current: &Arc<InnerState>) {
        // Carry the upstream, its options and `built_for_dnssec` over
        // together, so `matches_configured_policy` sees a consistent snapshot
        // and can recognize it as stale.
        self.store_inner_locked(InnerState {
            gen: current.gen + 1,
            state: ConnState::Degraded,
            resolver: current.resolver.clone(),
            request_options: current.request_options,
            built_for_dnssec: current.built_for_dnssec,
        });
        self.consecutive_timeouts.store(0, Ordering::Release);
        self.last_used_secs.store(now_secs(), Ordering::Relaxed);
        self.generation_started_ms
            .store(now_millis(), Ordering::Relaxed);
        self.requests_served.store(0, Ordering::Relaxed);
        self.transport_cooldown_until_ms.store(
            now_millis().saturating_add(TRANSPORT_ERROR_COOLDOWN_MS),
            Ordering::Release,
        );
    }

    /// Records a hedge-side success only if `expected_gen` is still current.
    /// The latency push, `mark_used`, counter reset and `Ready` transition all
    /// run under `write_lock`, so a stale success cannot promote a freshly
    /// rebuilt resolver. Lock order: no path takes `write_lock` while holding
    /// the latency window's mutex.
    pub(crate) fn try_record_success_if_gen(&self, expected_gen: u64, sample_us: u64) -> bool {
        let _guard = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.inner.load_full();
        if current.gen != expected_gen {
            return false;
        }
        self.latency.push(sample_us);
        self.last_used_secs.store(now_secs(), Ordering::Relaxed);
        self.consecutive_timeouts.store(0, Ordering::Release);
        if current.state != ConnState::Ready {
            let mut next = (*current).clone();
            next.state = ConnState::Ready;
            self.store_inner_locked(next);
        }
        true
    }

    /// Records a hedge-side timeout only if `expected_gen` is still current.
    /// The gen check, increment and demote run under `write_lock`, so a
    /// timeout from before a rebuild cannot bump the new generation's counter.
    /// Returns `true` if this call demoted the slot to `Degraded`.
    pub(crate) fn try_record_timeout_if_gen(&self, expected_gen: u64) -> bool {
        let _guard = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.inner.load_full();
        if current.gen != expected_gen {
            return false;
        }
        // A `Degraded` slot has nowhere lower to go. Counting further would
        // only grow the counter without bound.
        if current.state == ConnState::Degraded {
            return false;
        }
        let prev = self.consecutive_timeouts.fetch_add(1, Ordering::AcqRel);
        if prev.saturating_add(1) < CONSECUTIVE_TIMEOUTS_THRESHOLD {
            return false;
        }
        let mut next = (*current).clone();
        next.state = ConnState::Degraded;
        self.store_inner_locked(next);
        true
    }

    pub(crate) fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Acquire)
    }

    pub fn mark_used(&self) {
        self.last_used_secs.store(now_secs(), Ordering::Relaxed);
    }

    fn idle_secs(&self) -> u64 {
        let last = self.last_used_secs.load(Ordering::Relaxed);
        now_secs().saturating_sub(last)
    }

    fn generation_age_ms(&self) -> u64 {
        now_millis().wrapping_sub(self.generation_started_ms.load(Ordering::Relaxed))
    }

    /// Makes the current generation look `by` older. The start may wrap below
    /// the clock's origin, which `generation_age_ms` undoes.
    #[cfg(test)]
    fn backdate_generation(&self, by: Duration) {
        let started = self.generation_started_ms.load(Ordering::Relaxed);
        self.generation_started_ms.store(
            started.wrapping_sub(by.as_millis() as u64),
            Ordering::Relaxed,
        );
    }

    /// Includes cancelled dispatches and is approximate across rebuilds.
    fn requests_served(&self) -> u64 {
        self.requests_served.load(Ordering::Relaxed)
    }

    fn diagnostic_context(&self, expected_gen: u64) -> String {
        let _guard = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.inner.load_full();
        if current.gen != expected_gen {
            return format!("context=stale current_gen={}", current.gen);
        }
        format!(
            "slot_inflight={} generation_age_ms={} idle_s={} leased_requests_approx={}",
            self.inflight(),
            self.generation_age_ms(),
            self.idle_secs(),
            self.requests_served(),
        )
    }

    fn log_probe_result(
        &self,
        prefix: &str,
        gen: u64,
        phase: &str,
        elapsed: Duration,
        result: &LookupResult,
        accepted: bool,
    ) {
        log::debug!(
            "{} gen={} phase={} elapsed_us={} accepted={} {} {}",
            prefix,
            gen,
            phase,
            elapsed.as_micros(),
            accepted,
            self.diagnostic_context(gen),
            lookup_diagnostics(result),
        );
    }

    async fn probe(&self, idx: usize, snapshot: &InnerState, budget: Duration) -> LookupResult {
        tokio::time::timeout(
            budget,
            snapshot
                .resolver
                .lookup(
                    Query::query(Name::root(), RecordType::NS),
                    snapshot.request_options,
                    false,
                )
                .instrument(crate::provider_transport_trace::lookup_span(
                    idx,
                    self.target_ip(),
                    snapshot.gen,
                )),
        )
        .await
    }

    fn is_in_transport_cooldown(&self, now_ms: u64) -> bool {
        self.transport_cooldown_until_ms.load(Ordering::Acquire) > now_ms
    }

    fn start_transport_cooldown_if_gen(&self, expected_gen: u64) -> bool {
        let _guard = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.inner.load_full();
        if current.gen != expected_gen {
            return false;
        }
        self.transport_cooldown_until_ms.store(
            now_millis().saturating_add(TRANSPORT_ERROR_COOLDOWN_MS),
            Ordering::Release,
        );
        true
    }

    /// Rebuilds only if the generation is still `expected`. Check, build and
    /// swap run under `write_lock`, so `BuildFailed` always refers to the
    /// caller's own generation, never one another caller just rebuilt.
    pub(crate) fn rebuild_if(&self, expected: u64) -> RebuildOutcome {
        let _guard = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let current = self.inner.load_full();
        if current.gen != expected {
            return RebuildOutcome::StaleGen;
        }
        self.rebuild_locked(&current)
    }

    // Caller holds write_lock so validation and replacement share one transaction.
    fn rebuild_locked(&self, current: &Arc<InnerState>) -> RebuildOutcome {
        let (upstream, options, dnssec) = match try_build_resolver(self.cfg.clone()) {
            Ok(built) => built,
            Err(e) => {
                self.store_build_failed_state_locked(current);
                return RebuildOutcome::BuildFailed(e.to_string());
            }
        };
        self.publish_generation_locked(InnerState {
            gen: current.gen + 1,
            state: ConnState::Warming,
            resolver: Arc::new(upstream),
            request_options: options,
            built_for_dnssec: dnssec,
        });
        RebuildOutcome::Rebuilt
    }

    /// Publishes a newly built generation. Callers hold `write_lock`.
    fn publish_generation_locked(&self, next: InnerState) {
        self.store_inner_locked(next);
        // Reset under the lock that bumped gen, so a stale timeout cannot
        // land between the swap and the reset.
        self.consecutive_timeouts.store(0, Ordering::Release);
        self.last_used_secs.store(now_secs(), Ordering::Relaxed);
        // Reset logical generation diagnostics even before the first connection opens.
        self.generation_started_ms
            .store(now_millis(), Ordering::Relaxed);
        self.requests_served.store(0, Ordering::Relaxed);
    }

    /// Publishes `next`, which the caller built and probed, in place of
    /// generation `expected`. Returns `false` when the slot was rebuilt
    /// meanwhile, and `next` is then discarded.
    fn replace_if_gen(&self, expected: u64, next: InnerState) -> bool {
        let _guard = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        if self.inner.load().gen != expected {
            return false;
        }
        self.publish_generation_locked(next);
        true
    }
}

/// RAII inflight counter that pins the `(gen, resolver)` snapshot taken at
/// pick time. The hedge holds it across `lookup().await`, so the resolver it
/// queried and the generation it reports to `record_*` come from the same
/// snapshot even if a rebuild lands mid-query. `Drop` releases `inflight`,
/// including when the outer `FuturesUnordered` is cancelled.
pub(crate) struct ProviderConnLease {
    conn: Arc<ProviderConn>,
    snapshot: Arc<InnerState>,
}

impl ProviderConnLease {
    fn new(conn: Arc<ProviderConn>) -> Self {
        conn.inflight.fetch_add(1, Ordering::AcqRel);
        conn.requests_served.fetch_add(1, Ordering::Relaxed);
        let snapshot = conn.snapshot();
        Self { conn, snapshot }
    }

    /// The upstream current at pick time. Kept alive even if a rebuild swaps
    /// in a new one.
    pub(crate) fn resolver(&self) -> Arc<ProviderUpstream> {
        self.snapshot.resolver.clone()
    }

    /// Options from the same snapshot as `resolver()`. They do not vary with
    /// the DNSSEC toggle: DO is always set, and CD is chosen per query inside
    /// `ProviderUpstream::lookup` with the toggle as the default.
    pub(crate) fn request_options(&self) -> DnsRequestOptions {
        self.snapshot.request_options
    }

    /// Generation of `resolver()`, so reports reach the right slot version.
    pub(crate) fn generation(&self) -> u64 {
        self.snapshot.gen
    }
}

impl std::ops::Deref for ProviderConnLease {
    type Target = ProviderConn;
    fn deref(&self) -> &ProviderConn {
        &self.conn
    }
}

impl Drop for ProviderConnLease {
    fn drop(&mut self) {
        self.conn.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Sliding window of recent successful-lookup latencies in microseconds. Only
/// successes and authoritative no-records answers feed it. Timeouts and
/// transport errors act through state transitions instead of latency
/// penalties, so a transient burst cannot skew the ranking after recovery.
pub struct LatencyWindow {
    samples: Mutex<VecDeque<u64>>,
}

impl LatencyWindow {
    fn new() -> Self {
        Self {
            samples: Mutex::new(VecDeque::with_capacity(LATENCY_WINDOW_SIZE)),
        }
    }

    pub fn push(&self, sample_us: u64) {
        let mut s = self.samples.lock().unwrap_or_else(|p| p.into_inner());
        if s.len() >= LATENCY_WINDOW_SIZE {
            s.pop_front();
        }
        s.push_back(sample_us);
    }

    pub fn mean_or_zero(&self) -> u64 {
        let s = self.samples.lock().unwrap_or_else(|p| p.into_inner());
        if s.is_empty() {
            return 0;
        }
        let sum: u128 = s.iter().map(|v| *v as u128).sum();
        (sum / s.len() as u128) as u64
    }

    pub fn len(&self) -> usize {
        self.samples.lock().map(|s| s.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.samples.lock().map(|s| s.is_empty()).unwrap_or(true)
    }
}

pub struct Provider {
    pub id: DoHProviderId,
    pub name: &'static str,
    pub(crate) conns: Vec<Arc<ProviderConn>>,
    family_gates: Arc<FamilyGateSet>,
}

impl Provider {
    #[cfg(test)]
    pub(crate) fn for_local_test(address: std::net::SocketAddr) -> Arc<Self> {
        Self::for_local_test_with_conns(address, 1)
    }

    /// Every slot speaks plain TCP to one local test server. The hedge backup
    /// tests need two or more slots so `pick_backup_conn` finds a sibling.
    #[cfg(test)]
    pub(crate) fn for_local_test_with_conns(
        address: std::net::SocketAddr,
        conns: usize,
    ) -> Arc<Self> {
        let mut cfg = NameServerConfig::tcp(address.ip());
        cfg.connections[0].port = address.port();
        Arc::new(Self {
            id: DoHProviderId::Cloudflare,
            name: "Test",
            conns: (0..conns)
                .map(|_| ProviderConn::new(cfg.clone(), address.ip(), AddressFamily::V4))
                .collect(),
            family_gates: FamilyGateSet::for_provider_ids(vec![DoHProviderId::Cloudflare]),
        })
    }

    /// Lowest mean across allowed, non-`Degraded` conns with samples. `0`
    /// means no data, and the hedge then fires every provider in parallel.
    /// That way a cold provider is not penalized, and a provider whose conns
    /// all went bad does not keep a low ranking from pre-failure samples.
    pub fn latency_us(&self) -> u64 {
        self.conns
            .iter()
            .filter(|c| self.family_gates.is_allowed(c.family()))
            .filter(|c| c.state() != ConnState::Degraded && !c.latency.is_empty())
            .map(|c| c.latency.mean_or_zero())
            .min()
            .unwrap_or(0)
    }

    pub fn latency_sample_count(&self) -> usize {
        self.conns.iter().map(|c| c.latency.len()).sum()
    }

    /// Records a success only if the slot is still at the generation the
    /// caller captured at pick time. See `try_record_success_if_gen`.
    pub fn record_success(&self, idx: usize, sample_us: u64, expected_gen: u64) {
        if let Some(c) = self.conns.get(idx) {
            if c.try_record_success_if_gen(expected_gen, sample_us) {
                self.family_gates
                    .record_success_for_ip(self.id, c.family(), c.target_ip());
            }
        }
    }

    /// Records a hedge-side timeout. A timeout often means local congestion,
    /// not a wedged upstream, so it never triggers a rebuild: rebuilding under
    /// load causes a reconnect storm. It still counts toward the address-family
    /// gate, and `CONSECUTIVE_TIMEOUTS_THRESHOLD` timeouts in a row demote the
    /// slot to `Degraded`. Maintenance rebuilds on its own clock.
    ///
    /// `expected_gen` drops timeouts from lookups started before a rebuild,
    /// which could otherwise demote the fresh slot.
    pub fn record_timeout(&self, idx: usize, expected_gen: u64) {
        let Some(c) = self.conns.get(idx) else { return };
        if c.try_record_timeout_if_gen(expected_gen) {
            self.family_gates
                .record_failure_for_ip(self.id, c.family(), c.target_ip());
            log::debug!(
                "{} gen={} action=degraded reason=consecutive_timeouts count={} {}",
                provider_conn_log_prefix(self.name, idx, c.target_ip()),
                expected_gen,
                CONSECUTIVE_TIMEOUTS_THRESHOLD,
                c.diagnostic_context(expected_gen),
            );
        } else if c.generation() == expected_gen {
            self.family_gates
                .record_failure_for_ip(self.id, c.family(), c.target_ip());
        }
    }

    /// Called after Hickory returns a terminal transport error (TLS error,
    /// broken pipe, h2 RST/GOAWAY). The resolver is presumed broken and is
    /// rebuilt if `gen` is still current. On `Rebuilt` the fresh slot gets a
    /// transport cooldown and a warm-up. On `BuildFailed` the old resolver
    /// stays as a degraded fallback. On `StaleGen` another caller owns the
    /// transition.
    ///
    /// Returns whether the current generation is usable for further lookups.
    pub fn record_transport_error(&self, idx: usize, gen: u64) -> bool {
        let Some(c) = self.conns.get(idx) else {
            return false;
        };
        match c.rebuild_if(gen) {
            RebuildOutcome::Rebuilt => {
                self.family_gates
                    .record_failure_for_ip(self.id, c.family(), c.target_ip());
                let _ = c.start_transport_cooldown_if_gen(gen.saturating_add(1));
                if self.family_gates.is_allowed(c.family()) {
                    spawn_warmup(
                        c.clone(),
                        self.id,
                        self.name,
                        idx,
                        self.family_gates.clone(),
                    );
                }
                true
            }
            RebuildOutcome::BuildFailed(error) => {
                self.family_gates
                    .record_failure_for_ip(self.id, c.family(), c.target_ip());
                log::warn!(
                    "{} rebuild failed, keeping previous resolver; demoted to Degraded for maintenance retry: {}",
                    provider_conn_log_prefix(self.name, idx, c.target_ip()),
                    error
                );
                false
            }
            RebuildOutcome::StaleGen => {
                // A concurrent caller owns the transition. A failed build
                // keeps the previous resolver as a degraded fallback.
                c.state() != ConnState::Degraded
            }
        }
    }

    pub(crate) fn conn_diagnostics(&self, idx: usize, gen: u64) -> String {
        self.conns
            .get(idx)
            .map(|c| c.diagnostic_context(gen))
            .unwrap_or_else(|| "context=unavailable".into())
    }

    /// Picks a slot by state tier: `Ready`, then `Warming` so rebuilt slots
    /// get traffic while their connection establishes, then `Degraded`.
    /// Inside a tier the least-loaded slot wins, then the lowest latency mean,
    /// then a random choice so a tie does not send every concurrent pick to
    /// the same slot. The lease bumps `inflight` at once, so later picks in
    /// the same burst see the load.
    ///
    /// Each tier prefers slots outside transport-error cooldown, then slots
    /// below `MAX_INFLIGHT_PER_CONN`. Both are preferences, so a saturated or
    /// fully cooling tier still returns a slot.
    pub(crate) fn pick_conn(&self) -> Option<(usize, ProviderConnLease)> {
        if self.conns.is_empty() {
            log::error!("provider[{}] has no connection slots", self.name);
            return None;
        }
        let now_ms = now_millis();
        let want_dnssec = crate::config::current().dnssec;
        for desired in [ConnState::Ready, ConnState::Warming, ConnState::Degraded] {
            let tier: Vec<usize> = self
                .conns
                .iter()
                .enumerate()
                .filter_map(|(i, c)| {
                    if c.state() == desired
                        && self.family_gates.is_allowed(c.family())
                        && c.matches_configured_policy(want_dnssec)
                    {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect();
            let candidates = self.preferred_pick_candidates(&tier, now_ms);
            if let Some(pick) = self.pick_among(&candidates) {
                return Some(pick);
            }
        }
        None
    }

    /// Picks a second slot after the primary missed its fast budget. Prefers
    /// the opposite address family so a broken v4 or v6 path does not cost
    /// both attempts. Uses the same tiers and preferences as `pick_conn` and
    /// chooses between families with `should_prefer_opposite_family`.
    pub(crate) fn pick_backup_conn(
        &self,
        primary_idx: usize,
    ) -> Option<(usize, ProviderConnLease)> {
        if self.conns.len() <= 1 || primary_idx >= self.conns.len() {
            return None;
        }
        let now_ms = now_millis();
        let want_dnssec = crate::config::current().dnssec;
        let primary_family = self.conns[primary_idx].family();
        for desired in [ConnState::Ready, ConnState::Warming, ConnState::Degraded] {
            let all_tier: Vec<usize> = self
                .conns
                .iter()
                .enumerate()
                .filter_map(|(i, c)| {
                    if i != primary_idx
                        && c.state() == desired
                        && self.family_gates.is_allowed(c.family())
                        && c.matches_configured_policy(want_dnssec)
                    {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect();
            if all_tier.is_empty() {
                continue;
            }
            let all = self.preferred_pick_candidates(&all_tier, now_ms);
            let opposite: Vec<usize> = all
                .iter()
                .copied()
                .filter(|i| self.conns[*i].family() != primary_family)
                .collect();
            let (best_idx, best_us, _) = match self.snapshot_best(&all) {
                Some(t) => t,
                None => continue,
            };
            let chosen = match self.snapshot_best(&opposite) {
                Some((opp_idx, opp_us, _)) if should_prefer_opposite_family(opp_us, best_us) => {
                    opp_idx
                }
                _ => best_idx,
            };
            return Some((chosen, ProviderConnLease::new(self.conns[chosen].clone())));
        }
        None
    }

    fn preferred_pick_candidates(&self, candidates: &[usize], now_ms: u64) -> Vec<usize> {
        let not_cooling: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|i| !self.conns[*i].is_in_transport_cooldown(now_ms))
            .collect();
        let base = if not_cooling.is_empty() {
            candidates.to_vec()
        } else {
            not_cooling
        };
        let under_cap: Vec<usize> = base
            .iter()
            .copied()
            .filter(|i| self.conns[*i].inflight() < MAX_INFLIGHT_PER_CONN)
            .collect();
        if under_cap.is_empty() {
            base
        } else {
            under_cap
        }
    }

    /// Lowest inflight, then lowest latency, then random. Returns `None` only
    /// when `candidates` is empty.
    fn pick_among(&self, candidates: &[usize]) -> Option<(usize, ProviderConnLease)> {
        let (idx, _, _) = self.snapshot_best(candidates)?;
        Some((idx, ProviderConnLease::new(self.conns[idx].clone())))
    }

    fn snapshot_best(&self, candidates: &[usize]) -> Option<(usize, u64, usize)> {
        if candidates.is_empty() {
            return None;
        }
        let snapshot: Vec<(usize, usize, u64)> = candidates
            .iter()
            .copied()
            .map(|i| {
                (
                    i,
                    self.conns[i].inflight(),
                    self.conns[i].latency.mean_or_zero(),
                )
            })
            .collect();
        let min_inflight = snapshot.iter().map(|(_, inf, _)| *inf).min()?;
        let best_us = snapshot
            .iter()
            .filter(|(_, inf, _)| *inf == min_inflight)
            .map(|(_, _, m)| *m)
            .min()?;
        let best: Vec<usize> = snapshot
            .iter()
            .filter(|(_, inf, m)| *inf == min_inflight && *m == best_us)
            .map(|(i, _, _)| *i)
            .collect();
        let idx = match best.as_slice() {
            [one] => *one,
            many => many[rng().random_range(0..many.len())],
        };
        Some((idx, best_us, min_inflight))
    }

    pub fn conn_count(&self) -> usize {
        self.conns.len()
    }

    /// One loop per provider, started by `ProviderPool::spawn_keepalive` and
    /// stopped by `cancel`.
    async fn run_maintenance_loop(self: Arc<Self>, cancel: CancellationToken) {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(MAINTENANCE_WARMUP_DELAY) => {}
        }
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(MAINTENANCE_TICK) => {
                    self.maintenance_tick().await;
                }
            }
        }
    }

    async fn maintenance_tick(self: &Arc<Self>) {
        let idle_threshold = KEEPALIVE_IDLE_THRESHOLD.as_secs();
        let stuck_warming_threshold = STUCK_WARMING_THRESHOLD.as_secs();
        let want_dnssec = crate::config::current().dnssec;
        let mut futs: FuturesUnordered<_> = FuturesUnordered::new();
        for (idx, c) in self.conns.iter().enumerate() {
            if !self.family_gates.is_allowed(c.family()) {
                // Suppressed family: no probe or warm-up over a path judged
                // dead. Still refresh a stale policy so the slot is routable
                // the moment the gate reopens.
                if !c.matches_configured_policy(want_dnssec) {
                    let _ = c.rebuild_if(c.generation());
                }
                continue;
            }
            let state = c.state();
            // Backstop for stuck `Warming`. The watchdog misses two cases: a
            // slot this tick rebuilt whose inline probe was dropped, and a
            // slot armed while no runtime could host the timer. Without this
            // the slot would stay a last-resort `Warming` pick forever,
            // because keepalive only probes `Ready` and recovery only
            // `Degraded`.
            let stuck_warming =
                state == ConnState::Warming && c.idle_secs() >= stuck_warming_threshold;
            let needs_recovery = maintenance_needs_recovery(c, state, want_dnssec, stuck_warming);
            let needs_keepalive = state == ConnState::Ready && c.idle_secs() >= idle_threshold;
            if !needs_recovery && !needs_keepalive {
                continue;
            }
            let conn = c.clone();
            let provider_name = self.name;
            futs.push(async move {
                let kind = if needs_recovery {
                    "recovery"
                } else {
                    "keepalive"
                };
                if needs_recovery {
                    let snapshot = conn.snapshot();
                    let current_policy =
                        snapshot.built_for_dnssec == crate::config::current().dnssec;
                    if snapshot.state == ConnState::Ready && current_policy {
                        return;
                    }
                    let outcome = if snapshot.state == ConnState::Degraded && current_policy {
                        let started = Instant::now();
                        let res = conn.probe(idx, &snapshot, KEEPALIVE_TIMEOUT).await;
                        let elapsed = started.elapsed();
                        // Only a successful DNS lookup proves a degraded slot recovered.
                        let accepted = matches!(&res, Ok(Ok(_)));
                        let outcome = {
                            let _guard = conn.write_lock.lock().unwrap_or_else(|p| p.into_inner());
                            if !Arc::ptr_eq(&snapshot, &conn.snapshot())
                                || snapshot.built_for_dnssec != crate::config::current().dnssec
                            {
                                return;
                            }
                            if accepted {
                                let mut next = (*snapshot).clone();
                                next.state = ConnState::Ready;
                                conn.consecutive_timeouts.store(0, Ordering::Release);
                                conn.mark_used();
                                conn.store_inner_locked(next);
                                None
                            } else {
                                Some(conn.rebuild_locked(&snapshot))
                            }
                        };
                        conn.log_probe_result(
                            &provider_conn_log_prefix(provider_name, idx, conn.target_ip()),
                            snapshot.gen,
                            "reprobe",
                            elapsed,
                            &res,
                            accepted,
                        );
                        let Some(outcome) = outcome else {
                            self.family_gates.record_success_for_ip(
                                self.id,
                                conn.family(),
                                conn.target_ip(),
                            );
                            return;
                        };
                        outcome
                    } else {
                        conn.rebuild_if(snapshot.gen)
                    };
                    drop(snapshot);
                    match outcome {
                        RebuildOutcome::Rebuilt => {
                            // Fall through and probe the fresh resolver.
                        }
                        RebuildOutcome::BuildFailed(error) => {
                            // The old resolver stays as a degraded fallback.
                            // Probing it would hit the same wedge, so the
                            // next tick retries the build instead.
                            self.family_gates.record_failure_for_ip(
                                self.id,
                                conn.family(),
                                conn.target_ip(),
                            );
                            log::warn!(
                                "{} {} rebuild failed, keeping previous resolver: {}",
                                provider_conn_log_prefix(provider_name, idx, conn.target_ip()),
                                kind,
                                error
                            );
                            return;
                        }
                        RebuildOutcome::StaleGen => {
                            // Concurrent caller rebuilt and owns the transition.
                            return;
                        }
                    }
                }
                // One snapshot gives the probe its resolver and generation.
                // Two separate loads would let a rebuild slip between them
                // and void a successful recovery or keepalive.
                let snapshot = conn.snapshot();
                let probe_gen = snapshot.gen;
                let started = Instant::now();
                let res = conn.probe(idx, &snapshot, KEEPALIVE_TIMEOUT).await;
                if probe_indicates_alive(&res) {
                    // Probe latency stays out of the window: on the recovery
                    // path it includes the TLS handshake and would bias the
                    // ranking high.
                    if conn.try_set_state_if_gen(probe_gen, ConnState::Ready) {
                        self.family_gates.record_success_for_ip(
                            self.id,
                            conn.family(),
                            conn.target_ip(),
                        );
                        if needs_recovery || matches!(&res, Ok(Err(NetError::Busy))) {
                            conn.log_probe_result(
                                &provider_conn_log_prefix(provider_name, idx, conn.target_ip()),
                                probe_gen,
                                kind,
                                started.elapsed(),
                                &res,
                                true,
                            );
                        }
                        conn.mark_used();
                    }
                } else if conn.try_set_state_if_gen(probe_gen, ConnState::Degraded) {
                    self.family_gates.record_failure_for_ip(
                        self.id,
                        conn.family(),
                        conn.target_ip(),
                    );
                    conn.log_probe_result(
                        &provider_conn_log_prefix(provider_name, idx, conn.target_ip()),
                        probe_gen,
                        kind,
                        started.elapsed(),
                        &res,
                        false,
                    );
                }
            });
        }
        while futs.next().await.is_some() {}
        self.rotate_aged_conns().await;
    }

    /// Replaces `Ready` slots that reached the rotation age, so a connection
    /// is renewed here instead of being closed by the upstream under a query.
    /// One slot at a time: the next starts only after the previous replacement
    /// was published, and a replacement that fails ends the round.
    async fn rotate_aged_conns(&self) {
        for (idx, conn) in self.conns.iter().enumerate() {
            if !self.family_gates.is_allowed(conn.family()) {
                continue;
            }
            let current = conn.snapshot();
            let age = Duration::from_millis(conn.generation_age_ms());
            if current.state != ConnState::Ready || age < CONN_ROTATION_AGE {
                continue;
            }
            if !self.replace_conn(conn, idx, &current).await {
                return;
            }
        }
    }

    /// Builds a replacement for `current` and publishes it only after it
    /// answered a probe, so the slot never leaves `Ready` and a failed
    /// replacement costs nothing: the slot keeps the connection it has.
    /// Queries in flight finish on the connection they were leased on.
    /// Returns `false` when the replacement could not be built or did not
    /// answer.
    async fn replace_conn(&self, conn: &ProviderConn, idx: usize, current: &InnerState) -> bool {
        let prefix = provider_conn_log_prefix(self.name, idx, conn.target_ip());
        let (upstream, request_options, built_for_dnssec) =
            match try_build_resolver(conn.cfg.clone()) {
                Ok(built) => built,
                Err(error) => {
                    log::warn!(
                        "{prefix} rotation build failed, keeping the current connection: {error}"
                    );
                    return false;
                }
            };
        let replacement = InnerState {
            gen: current.gen + 1,
            state: ConnState::Ready,
            resolver: Arc::new(upstream),
            request_options,
            built_for_dnssec,
        };
        let started = Instant::now();
        let res = conn.probe(idx, &replacement, KEEPALIVE_TIMEOUT).await;
        let alive = probe_indicates_alive(&res);
        // Probe latency stays out of the window: it includes the TLS
        // handshake and would bias the ranking high.
        let published = alive && conn.replace_if_gen(current.gen, replacement);
        if published {
            self.family_gates
                .record_success_for_ip(self.id, conn.family(), conn.target_ip());
        } else if !alive {
            self.family_gates
                .record_failure_for_ip(self.id, conn.family(), conn.target_ip());
            log::warn!(
                "{prefix} rotation failed, keeping the current connection: elapsed_us={} {} {}",
                started.elapsed().as_micros(),
                conn.diagnostic_context(current.gen),
                lookup_diagnostics(&res),
            );
        }
        alive
    }
}

fn should_prefer_opposite_family(opposite_us: u64, best_us: u64) -> bool {
    opposite_us == 0 || opposite_us <= BACKUP_FAMILY_HEALTHY_US || opposite_us <= best_us
}

/// Slots needing recovery. A degraded slot is reprobed before rebuilding.
/// `stuck_warming` is a warm-up that never landed. A policy-stale slot is one
/// the selection gate refuses to route. It must be rebuilt here, or it stays
/// gated out forever because a `Ready` slot only ever gets keepalive probes.
///
/// As a reconcile loop this bounds a gated-out slot in an allowed family to
/// one maintenance interval, whatever left it stale: a `StaleGen` rebuild that
/// raced a toggle, a `BuildFailed` slot a probe later promoted, or anything
/// else. `maintenance_tick` refreshes suppressed-family slots in place before
/// skipping them.
///
/// `state` is the value the tick already captured. Re-reading it here would
/// let a concurrent transition classify the slot differently from the rest of
/// the loop body.
fn maintenance_needs_recovery(
    c: &ProviderConn,
    state: ConnState,
    want_dnssec: bool,
    stuck_warming: bool,
) -> bool {
    state == ConnState::Degraded || stuck_warming || !c.matches_configured_policy(want_dnssec)
}

/// Alive when the probe got a DNS response, including an authoritative
/// NoRecordsFound, which proves the transport works. DNS-layer and local
/// resolver errors also count as alive so they do not cause rebuild churn.
/// Transport errors, TLS failures and timeouts mean the slot needs recovery.
fn probe_indicates_alive(res: &LookupResult) -> bool {
    match res {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => e.is_no_records_found() || probe_error_is_non_transport(e),
        Err(_) => false,
    }
}

fn probe_error_is_non_transport(error: &NetError) -> bool {
    match error {
        NetError::Busy
        | NetError::Dns(_)
        | NetError::HttpStatus { .. }
        | NetError::Proto(_)
        | NetError::ForeignClassRecord { .. } => true,
        NetError::Message(msg) => msg.contains("DNSSEC Negative Record Response"),
        NetError::Msg(msg) => msg.contains("DNSSEC Negative Record Response"),
        _ => false,
    }
}

fn provider_conn_log_prefix(provider_name: &str, idx: usize, target_ip: IpAddr) -> String {
    format!("provider[{provider_name}] conn[{idx}] ip[{target_ip}]")
}

/// Spawns the warm-up that promotes a slot from `Warming` to `Ready`, after
/// the initial pool fill and after every rebuild. A random delay of up to
/// `WARMUP_JITTER_MAX` keeps the conns to one upstream IP from handshaking at
/// the same instant.
///
/// Without a running runtime, as in unit tests that never call
/// `start_runtime`, the spawn is skipped silently and tests drive state
/// directly. A spawn failure on a running runtime is logged, so the
/// stuck-Warming recovery that follows has a visible cause.
fn spawn_warmup(
    conn: Arc<ProviderConn>,
    provider_id: DoHProviderId,
    provider_name: &'static str,
    idx: usize,
    family_gates: Arc<FamilyGateSet>,
) {
    // Armed before the spawn so the watchdog also covers a warm-up task that
    // never starts.
    arm_stuck_warming_watchdog(
        conn.clone(),
        provider_id,
        provider_name,
        idx,
        family_gates.clone(),
    );
    if !crate::runtime::is_running() {
        return;
    }
    let target_ip = conn.target_ip();
    let family = conn.family();
    let result = crate::runtime::spawn(async move {
        // Pin the generation being warmed. If a rebuild lands first, the
        // rebuilder warms the new generation and this result is dropped.
        let snapshot = conn.snapshot();
        let warmup_gen = snapshot.gen;
        let jitter_us = rng().random_range(0u64..WARMUP_JITTER_MAX.as_micros() as u64);
        tokio::time::sleep(Duration::from_micros(jitter_us)).await;
        let start = Instant::now();
        let res = conn.probe(idx, &snapshot, WARMUP_TIMEOUT).await;
        if probe_indicates_alive(&res) {
            // Warm-up latency stays out of the window: it includes the
            // one-time TLS handshake, not steady-state query latency.
            if conn.try_set_state_if_gen(warmup_gen, ConnState::Ready) {
                family_gates.record_success_for_ip(provider_id, family, target_ip);
                if warmup_gen > 0 || matches!(&res, Ok(Err(NetError::Busy))) {
                    conn.log_probe_result(
                        &provider_conn_log_prefix(provider_name, idx, target_ip),
                        warmup_gen,
                        "warmup",
                        start.elapsed(),
                        &res,
                        true,
                    );
                }
                conn.mark_used();
            }
        } else if conn.try_set_state_if_gen(warmup_gen, ConnState::Degraded) {
            family_gates.record_failure_for_ip(provider_id, family, target_ip);
            conn.log_probe_result(
                &provider_conn_log_prefix(provider_name, idx, target_ip),
                warmup_gen,
                "warmup",
                start.elapsed(),
                &res,
                false,
            );
        }
    });
    if let Err(e) = result {
        log::warn!(
            "{} warm-up spawn failed: {} — stuck-Warming rescue will retry",
            provider_conn_log_prefix(provider_name, idx, target_ip),
            e
        );
    }
}

/// Enforces `STUCK_WARMING_THRESHOLD` as a deadline. Armed by `spawn_warmup`
/// and cancelled by any change to the slot's snapshot, so a slot that warmed
/// up, failed warm-up or was rebuilt elsewhere never triggers recovery.
///
/// The timer does nothing unless the slot is still `Warming` in the generation
/// seen at arming. Recovery goes through `rebuild_if(armed_gen)`, so when a
/// maintenance tick recovers the same slot concurrently only one rebuild
/// happens.
fn arm_stuck_warming_watchdog(
    conn: Arc<ProviderConn>,
    provider_id: DoHProviderId,
    provider_name: &'static str,
    idx: usize,
    family_gates: Arc<FamilyGateSet>,
) {
    let snapshot = conn.snapshot();
    if snapshot.state != ConnState::Warming {
        return;
    }
    let armed_gen = snapshot.gen;
    let token = conn.arm_warming_watchdog();
    let watchdog_conn = conn.clone();
    let spawned = spawn_detached(async move {
        tokio::select! {
            _ = token.cancelled() => return,
            _ = tokio::time::sleep(STUCK_WARMING_THRESHOLD) => {}
        }
        let current = watchdog_conn.snapshot();
        if current.gen != armed_gen || current.state != ConnState::Warming {
            return;
        }
        log::warn!(
            "{} stuck in Warming for {:?}, rebuilding now",
            provider_conn_log_prefix(provider_name, idx, watchdog_conn.target_ip()),
            STUCK_WARMING_THRESHOLD
        );
        recover_stuck_warming(
            watchdog_conn,
            armed_gen,
            provider_id,
            provider_name,
            idx,
            family_gates,
        );
    });
    if !spawned {
        // No runtime to host the timer, as with `dns_init` before
        // `start_runtime`. Leave nothing armed so the next arming is not
        // treated as a replacement. `maintenance_tick` is the backstop.
        conn.cancel_warming_watchdog();
    }
}

/// Rebuilds and rewarms a slot the watchdog found stuck, like the
/// transport-error path. The fresh generation gets its own warm-up and
/// watchdog.
fn recover_stuck_warming(
    conn: Arc<ProviderConn>,
    armed_gen: u64,
    provider_id: DoHProviderId,
    provider_name: &'static str,
    idx: usize,
    family_gates: Arc<FamilyGateSet>,
) {
    match conn.rebuild_if(armed_gen) {
        RebuildOutcome::Rebuilt => {
            if family_gates.is_allowed(conn.family()) {
                spawn_warmup(conn, provider_id, provider_name, idx, family_gates);
            }
        }
        RebuildOutcome::BuildFailed(error) => {
            family_gates.record_failure_for_ip(provider_id, conn.family(), conn.target_ip());
            log::warn!(
                "{} stuck-Warming rebuild failed, keeping previous resolver: {}",
                provider_conn_log_prefix(provider_name, idx, conn.target_ip()),
                error
            );
        }
        RebuildOutcome::StaleGen => {
            // A maintenance tick or transport error already rebuilt it.
        }
    }
}

/// Spawns a detached task on the runtime the caller already runs on, falling
/// back to the resolver's global runtime for off-runtime callers (`dns_init`,
/// FFI threads). Returns `false` when neither is available.
fn spawn_detached<F>(future: F) -> bool
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(future);
            true
        }
        Err(_) => crate::runtime::spawn(future).is_ok(),
    }
}

pub struct ProviderPool {
    providers: Vec<Arc<Provider>>,
    family_gates: Arc<FamilyGateSet>,
}

pub(crate) fn ns_cfg(ip: IpAddr, tls: &str, path: &str) -> NameServerConfig {
    NameServerConfig::new(
        ip,
        true,
        vec![ConnectionConfig::https(
            std::sync::Arc::from(tls),
            Some(std::sync::Arc::from(path)),
        )],
    )
}

/// Options every provider slot's `PoolContext` is built from.
///
/// `use_hosts_file` stays at its default and never reaches a hosts lookup: the
/// provider path assembles `CachingClient` directly, and only
/// `Resolver::build()` loads `/etc/hosts`. Clients are unaffected because
/// macOS applies `/etc/hosts` in `mDNSResponder`, upstream of MacDNS.
/// `state.json` overrides are the supported way to pin a name.
pub(crate) fn opts() -> ResolverOpts {
    let mut o = ResolverOpts::default();
    // No positive floor: hickory's `clamp_positive_ttls` rewrites the record
    // TTLs of the `Lookup` it returns, so a minimum here would raise a
    // 5-second authoritative TTL before the agent's cache sees it and defeat
    // DNS-level failover.
    //
    // The other three bounds do not reach the record clamp.
    // `CachingClient::with_cache`, the constructor that takes a `TtlConfig`,
    // is `pub(crate)`, so `CachingClient::new()` uses `TtlConfig::default()`:
    // the positive ceiling is `MAX_TTL` (1 day, not 4) and the negative bounds
    // are hickory's defaults, not 5 seconds. They still feed `PoolContext`.
    o.positive_min_ttl = None;
    o.positive_max_ttl = Some(Duration::from_secs(4 * 24 * 3600));
    o.negative_min_ttl = Some(Duration::from_secs(5));
    o.negative_max_ttl = Some(Duration::from_secs(5));
    // EDNS stays on regardless of DNSSEC. Without it the response cap drops
    // to 512 bytes (RFC 1035) and ECS, NSID, EDE and padding are lost.
    o.edns0 = true;
    o.edns_payload_len = 1232;
    // The provider is the only validator. Local validation would refetch the
    // whole DS/DNSKEY chain on every cache miss: hickory's answer cache sits
    // above `DnssecDnsHandle`, so with `cache_size = 0` nothing would amortize
    // it, and the validation cache would be per slot and lost on each rebuild.
    //
    // Only `Resolver` reads this field and the provider path does not use
    // `Resolver`, so it is inert. It stays `false` so reintroducing that
    // layer cannot silently turn local validation back on.
    o.validate = false;
    // DNS 0x20 protects UDP. Over encrypted transports it only triggers
    // hickory's QueryCaseMismatch handling.
    o.case_randomization = false;
    // Disable generic lookup retries. Hickory owns one connection-closure
    // retry inside the caller's deadline, with hedging across providers.
    o.attempts = 0;
    o.num_concurrent_reqs = 1;
    o.max_active_requests = 128;
    // The agent owns the DNS cache, so hickory's internal one is off.
    o.cache_size = 0;
    o.timeout = PROVIDER_TIMEOUT;
    o
}

/// Builds one slot's upstream.
///
/// The DNSSEC toggle read here becomes the upstream's default CD for clients
/// that left the bit clear. A client that set CD reaches the provider with
/// `CD=1` either way. DO is always set. Both travel with the resolver, so a
/// slot never serves under a policy it was not built for.
fn try_build_resolver(
    cfg: NameServerConfig,
) -> Result<(ProviderUpstream, DnsRequestOptions, bool), String> {
    let dnssec = crate::config::current().dnssec;
    let tls = TlsConfig::new().map_err(|e| e.to_string())?;
    let options = opts();
    let preserve_intermediates = options.preserve_intermediates;
    let cache_size = options.cache_size;
    let cx = std::sync::Arc::new(PoolContext::new(options, tls));
    let pool = NameServerPool::from_config([cfg], cx, TokioRuntimeProvider::default());
    Ok((
        ProviderUpstream::new(pool, cache_size, preserve_intermediates, dnssec),
        request_options(),
        dnssec,
    ))
}

struct ProviderSpec {
    v4_endpoints: [IpAddr; 2],
    v6_endpoints: [IpAddr; 2],
    tls: &'static str,
    path: &'static str,
}

fn provider_spec_for_id(id: DoHProviderId) -> ProviderSpec {
    match id {
        DoHProviderId::Cloudflare => ProviderSpec {
            v4_endpoints: [
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            ],
            v6_endpoints: [
                IpAddr::V6("2606:4700:4700::1111".parse().unwrap()),
                IpAddr::V6("2606:4700:4700::1001".parse().unwrap()),
            ],
            tls: "cloudflare-dns.com",
            path: "/dns-query",
        },
        DoHProviderId::Google => ProviderSpec {
            v4_endpoints: [
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            ],
            v6_endpoints: [
                IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
                IpAddr::V6("2001:4860:4860::8844".parse().unwrap()),
            ],
            tls: "dns.google",
            path: "/dns-query",
        },
        DoHProviderId::Quad9 => ProviderSpec {
            v4_endpoints: [
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
            ],
            v6_endpoints: [
                IpAddr::V6("2620:fe::fe".parse().unwrap()),
                IpAddr::V6("2620:fe::9".parse().unwrap()),
            ],
            tls: "dns.quad9.net",
            path: "/dns-query",
        },
    }
}

fn build_provider(
    id: DoHProviderId,
    v4_endpoints: [IpAddr; 2],
    v6_endpoints: [IpAddr; 2],
    tls: &str,
    path: &str,
    family_gates: Arc<FamilyGateSet>,
) -> Arc<Provider> {
    let mut conns: Vec<Arc<ProviderConn>> = Vec::with_capacity(CONNS_PER_ENDPOINT * 4);
    for ip in v4_endpoints {
        let cfg = ns_cfg(ip, tls, path);
        for _ in 0..CONNS_PER_ENDPOINT {
            conns.push(ProviderConn::new(cfg.clone(), ip, AddressFamily::V4));
        }
    }
    for ip in v6_endpoints {
        let cfg = ns_cfg(ip, tls, path);
        for _ in 0..CONNS_PER_ENDPOINT {
            conns.push(ProviderConn::new(cfg.clone(), ip, AddressFamily::V6));
        }
    }
    Arc::new(Provider {
        id,
        name: id.display_name(),
        conns,
        family_gates,
    })
}

fn build_provider_for_id(id: DoHProviderId, family_gates: Arc<FamilyGateSet>) -> Arc<Provider> {
    let spec = provider_spec_for_id(id);
    build_provider(
        id,
        spec.v4_endpoints,
        spec.v6_endpoints,
        spec.tls,
        spec.path,
        family_gates,
    )
}

impl ProviderPool {
    /// Builds the pool with every slot in `Warming` without spawning warm-up
    /// or maintenance tasks, so tests that observe initial state do not depend
    /// on whether a parallel test left the global runtime running.
    /// `dns_init` follows it with `spawn_keepalive()`.
    pub fn new() -> Self {
        let provider_ids = crate::config::current().selected_providers_in_canonical_order();
        let family_gates = FamilyGateSet::for_provider_ids(provider_ids.clone());
        let providers: Vec<_> = provider_ids
            .into_iter()
            .map(|id| build_provider_for_id(id, family_gates.clone()))
            .collect();
        let total: usize = providers.iter().map(|p| p.conns.len()).sum();
        log::info!(
            "provider pool built with {} provider(s), {} conn(s) total ({} per endpoint × 4 endpoints)",
            providers.len(),
            total,
            CONNS_PER_ENDPOINT
        );
        Self {
            providers,
            family_gates,
        }
    }

    /// The family gates come from the first provider so every slot shares one
    /// gate set, as in production.
    #[cfg(test)]
    pub(crate) fn for_local_test(providers: Vec<Arc<Provider>>) -> Self {
        let family_gates = providers
            .first()
            .map(|p| p.family_gates.clone())
            .unwrap_or_else(|| FamilyGateSet::for_provider_ids(Vec::new()));
        Self {
            providers,
            family_gates,
        }
    }

    pub fn all(&self) -> &[Arc<Provider>] {
        &self.providers
    }

    pub fn sorted_by_latency(&self) -> Vec<Arc<Provider>> {
        let mut v = self.providers.clone();
        v.sort_by_key(|p| p.latency_us());
        v
    }

    pub fn provider_ids_canonical_order(&self) -> Vec<DoHProviderId> {
        self.providers.iter().map(|p| p.id).collect()
    }

    /// Starts one warm-up per conn, so the first user queries land on slots
    /// that already completed their handshake, and one maintenance loop per
    /// provider that stops on `cancel`. Called once from `dns_init`.
    pub fn spawn_keepalive(&self, cancel: CancellationToken) {
        for p in &self.providers {
            for (idx, c) in p.conns.iter().enumerate() {
                spawn_warmup(c.clone(), p.id, p.name, idx, self.family_gates.clone());
            }
        }
        for p in self.providers.iter().cloned() {
            let c = cancel.clone();
            let _ = crate::runtime::spawn(async move {
                p.run_maintenance_loop(c).await;
            });
        }
    }

    /// Rebuilds every conn slot, after a change to a setting that
    /// `try_build_resolver` captures or when a network change or the App's
    /// manual flush asks for a clean slate. The only captured setting is the
    /// DNSSEC toggle, frozen into each slot's `InnerState` as the default CD,
    /// which is why a toggle needs a rebuild to take effect.
    ///
    /// Successful rebuilds enter `Warming` and get a warm-up. Slots whose
    /// build fails are demoted to `Degraded` and the maintenance tick retries
    /// them.
    ///
    /// Returns the number of slots still built for a different DNSSEC setting,
    /// which `matches_configured_policy` keeps out of routing. It is not summed
    /// with `build_failed` because the two overlap: a failed build on a
    /// pre-toggle snapshot is both, while a failed build on a slot a racing
    /// caller already moved to the new policy is degraded but not gated out.
    /// `build_failed` stays in the summary log.
    pub fn rebuild_all_conns(&self, reason: &str) -> usize {
        let want_dnssec = crate::config::current().dnssec;
        let mut total = 0usize;
        let mut rebuilt = 0usize;
        let mut build_failed = 0usize;
        let mut warmup_skipped = 0usize;
        let mut policy_stale = 0usize;
        for p in &self.providers {
            for (idx, c) in p.conns.iter().enumerate() {
                // Two attempts at most: the second runs against the generation
                // a racing caller just published. Looping without a bound could
                // livelock under `write_lock` contention. The maintenance tick
                // catches anything still stale.
                for _ in 0..2 {
                    let pre_rebuild_gen = c.generation();
                    match c.rebuild_if(pre_rebuild_gen) {
                        RebuildOutcome::Rebuilt => {
                            if self.family_gates.is_allowed(c.family()) {
                                spawn_warmup(
                                    c.clone(),
                                    p.id,
                                    p.name,
                                    idx,
                                    self.family_gates.clone(),
                                );
                            } else {
                                warmup_skipped += 1;
                            }
                            rebuilt += 1;
                            break;
                        }
                        RebuildOutcome::BuildFailed(error) => {
                            log::warn!(
                                "{} rebuild failed ({}), keeping previous resolver: {}",
                                provider_conn_log_prefix(p.name, idx, c.target_ip()),
                                reason,
                                error
                            );
                            build_failed += 1;
                            break;
                        }
                        // A racing caller may have built from the pre-toggle
                        // config. Accept its snapshot only if it matches the
                        // policy being rebuilt for. Otherwise retry against the
                        // generation it published.
                        RebuildOutcome::StaleGen => {
                            if c.matches_configured_policy(want_dnssec) {
                                break;
                            }
                        }
                    }
                }
                if !c.matches_configured_policy(want_dnssec) {
                    policy_stale += 1;
                }
                total += 1;
            }
        }
        log::info!(
            "provider pool rebuilt {} of {} conns ({} build-failed, {} warmup-skipped, {} policy-stale) across {} providers: {}",
            rebuilt,
            total,
            build_failed,
            warmup_skipped,
            policy_stale,
            self.providers.len(),
            reason
        );
        policy_stale
    }

    pub fn close_family_gates_for_network_change(&self) {
        self.family_gates.close_all_for_network_change();
    }
}

impl Default for ProviderPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigGuard;
    use crate::config::DoHProviderId;

    /// Lets pick logic be tested without the network warm-up.
    fn force_all_ready(p: &Provider) {
        for c in &p.conns {
            c.force_state(ConnState::Ready);
        }
    }

    /// Record events against the slot's current generation. Production
    /// passes the gen captured at pick time. Macros instead of functions
    /// avoid `&Arc<Provider>` vs `&Provider` clippy friction.
    macro_rules! record_success_now {
        ($p:expr, $idx:expr, $us:expr) => {{
            let gen = $p.conns[$idx].generation();
            $p.record_success($idx, $us, gen);
        }};
    }
    macro_rules! record_timeout_now {
        ($p:expr, $idx:expr) => {{
            let gen = $p.conns[$idx].generation();
            $p.record_timeout($idx, gen);
        }};
    }

    #[test]
    fn cold_start_has_no_latency_bias() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        for p in pool.all() {
            assert_eq!(p.latency_us(), 0);
            assert_eq!(p.latency_sample_count(), 0);
        }
        let sorted = pool.sorted_by_latency();
        assert_eq!(sorted[0].name, "Cloudflare");
        assert_eq!(sorted[1].name, "Google");
        assert_eq!(sorted[2].name, "Quad9");
    }

    #[test]
    fn pool_starts_with_every_conn_warming() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        for p in pool.all() {
            for c in &p.conns {
                assert_eq!(c.state(), ConnState::Warming);
            }
        }
    }

    #[test]
    fn provider_pool_builds_selected_provider_only() {
        let _guard = ConfigGuard::new(crate::config::ResolverOptions {
            doh_providers: vec![DoHProviderId::Cloudflare],
            ..Default::default()
        });
        let pool = ProviderPool::new();
        assert_eq!(pool.all().len(), 1);
        assert_eq!(
            pool.provider_ids_canonical_order(),
            vec![DoHProviderId::Cloudflare]
        );
    }

    #[test]
    fn provider_pool_keeps_canonical_order_for_selected_pair() {
        let _guard = ConfigGuard::new(crate::config::ResolverOptions {
            doh_providers: vec![DoHProviderId::Quad9, DoHProviderId::Google],
            ..Default::default()
        });
        let pool = ProviderPool::new();
        assert_eq!(
            pool.provider_ids_canonical_order(),
            vec![DoHProviderId::Google, DoHProviderId::Quad9]
        );
    }

    #[test]
    fn ranking_follows_sliding_window_after_samples() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        for p in pool.all() {
            let us = match p.name {
                "Cloudflare" => 25_000,
                "Google" => 40_000,
                "Quad9" => 10_000,
                _ => 0,
            };
            for _ in 0..10 {
                record_success_now!(p, 0, us);
            }
        }
        let sorted = pool.sorted_by_latency();
        assert_eq!(sorted[0].name, "Quad9");
        assert_eq!(sorted[1].name, "Cloudflare");
        assert_eq!(sorted[2].name, "Google");
    }

    #[test]
    fn latency_window_rolls_off_oldest() {
        let w = LatencyWindow::new();
        for i in 0..(LATENCY_WINDOW_SIZE + 5) {
            w.push(i as u64 * 1_000);
        }
        assert_eq!(w.len(), LATENCY_WINDOW_SIZE);
        let baseline_sum: u64 = (0..LATENCY_WINDOW_SIZE as u64).map(|v| v * 1_000).sum();
        let baseline_mean = baseline_sum / LATENCY_WINDOW_SIZE as u64;
        assert!(
            w.mean_or_zero() > baseline_mean,
            "window did not roll off the oldest samples",
        );
    }

    #[test]
    fn empty_window_reports_zero() {
        let w = LatencyWindow::new();
        assert_eq!(w.mean_or_zero(), 0);
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn generation_bumps_on_rebuild() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let conn = pool.all()[0].conns[0].clone();
        let gen0 = conn.generation();
        assert_eq!(conn.rebuild_if(gen0), RebuildOutcome::Rebuilt);
        assert_eq!(conn.generation(), gen0 + 1);
    }

    #[test]
    fn rebuild_if_dedupes_parallel_attempts() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let conn = pool.all()[0].conns[0].clone();
        let gen = conn.generation();
        assert_eq!(conn.rebuild_if(gen), RebuildOutcome::Rebuilt);
        assert_eq!(conn.rebuild_if(gen), RebuildOutcome::StaleGen);
        assert_eq!(conn.generation(), gen + 1);
    }

    #[test]
    fn rebuild_outcome_distinguishes_stale_from_build_failed() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let conn = pool.all()[0].conns[0].clone();
        let gen = conn.generation();
        assert_eq!(conn.rebuild_if(gen), RebuildOutcome::Rebuilt);
        // Same captured gen, already bumped. Must be StaleGen so callers
        // cannot mistake it for BuildFailed.
        assert_eq!(conn.rebuild_if(gen), RebuildOutcome::StaleGen);
    }

    #[test]
    fn provider_budget_is_single_shot_and_bounded() {
        let opts = opts();
        assert_eq!(opts.attempts, 0);
        assert_eq!(opts.timeout, PROVIDER_TIMEOUT);
        assert_eq!(opts.negative_min_ttl, Some(Duration::from_secs(5)));
        assert_eq!(opts.negative_max_ttl, Some(Duration::from_secs(5)));
        assert_eq!(opts.max_active_requests, 128);
        assert_eq!(opts.cache_size, 0);
    }

    #[test]
    fn edns0_always_on_after_fix() {
        let opts = opts();
        assert!(opts.edns0);
        assert_eq!(opts.edns_payload_len, 1232);
    }

    #[test]
    fn edns0_stays_on_independent_of_dnssec() {
        let _guard = ConfigGuard::new(crate::config::ResolverOptions {
            dnssec: false,
            ..Default::default()
        });
        let o = opts();
        assert!(o.edns0);
        assert_eq!(o.edns_payload_len, 1232);
    }

    /// The provider is the only validator. Local validation would bring back
    /// the per-query DNSKEY/DS chain fetch that dominated cache-miss latency.
    #[test]
    fn local_validation_is_off_regardless_of_toggle() {
        let _guard = ConfigGuard::new(crate::config::ResolverOptions {
            dnssec: true,
            ..Default::default()
        });
        assert!(!opts().validate);
    }

    #[test]
    fn provider_timeout_matches_backup_wave_budget() {
        assert_eq!(PROVIDER_TIMEOUT, Duration::from_secs(3));
    }

    #[test]
    fn each_provider_ships_conns_per_endpoint_times_four() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        for p in pool.all() {
            assert_eq!(
                p.conn_count(),
                CONNS_PER_ENDPOINT * 4,
                "provider {} must ship {} × 4 conns",
                p.name,
                CONNS_PER_ENDPOINT
            );
            let v4 = p
                .conns
                .iter()
                .filter(|c| c.family() == AddressFamily::V4)
                .count();
            let v6 = p
                .conns
                .iter()
                .filter(|c| c.family() == AddressFamily::V6)
                .count();
            assert_eq!(v4, CONNS_PER_ENDPOINT * 2);
            assert_eq!(v6, CONNS_PER_ENDPOINT * 2);
        }
    }

    #[test]
    fn all_providers_use_doh() {
        use hickory_resolver::config::ProtocolConfig;

        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        for provider in pool.all() {
            for conn in &provider.conns {
                let connection = conn.cfg.connections.first().unwrap();
                assert_eq!(connection.port, 443, "{} must use DoH", provider.name);
                assert!(
                    matches!(connection.protocol, ProtocolConfig::Https { .. }),
                    "{} must use the same DoH transport as every other provider",
                    provider.name
                );
            }
        }
    }

    #[test]
    fn pick_conn_returns_none_for_empty_provider() {
        let p = Provider {
            id: DoHProviderId::Cloudflare,
            name: "Empty",
            conns: Vec::new(),
            family_gates: FamilyGateSet::for_provider_ids(vec![DoHProviderId::Cloudflare]),
        };
        assert!(p.pick_conn().is_none());
    }

    fn open_family_gate_for_test(pool: &ProviderPool, family: AddressFamily) -> u64 {
        open_gate_for_test(&pool.family_gates, family)
    }

    fn open_gate_for_test(gates: &FamilyGateSet, family: AddressFamily) -> u64 {
        let other = family.opposite();
        let start = now_secs();
        let opened_at = start + FAMILY_GATE_FAILURE_WINDOW.as_secs();
        let other_targets = gates.targets_for(other).to_vec();
        let targets = gates.targets_for(family).to_vec();
        for target in other_targets {
            gates.record_success_at(target.provider_id, other, target.ip, start);
        }
        for target in &targets {
            gates.record_failure_at(target.provider_id, family, target.ip, start);
        }
        let first = targets[0];
        gates.record_failure_at(first.provider_id, family, first.ip, opened_at);
        assert!(gates.is_open_for_at(family, opened_at));
        opened_at
    }

    #[test]
    fn family_gate_empty_target_set_never_counts_as_all_failed() {
        let state = FamilyGateState::default();

        assert_eq!(
            state.all_targets_failed_since(&[], now_secs() + FAMILY_GATE_FAILURE_WINDOW.as_secs()),
            None
        );
    }

    #[test]
    fn family_gate_opens_v6_after_all_selected_providers_fail_for_two_minutes() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let start = now_secs();

        let v4_targets = pool.family_gates.targets_for(AddressFamily::V4).to_vec();
        let v6_targets = pool.family_gates.targets_for(AddressFamily::V6).to_vec();
        for target in v4_targets {
            pool.family_gates.record_success_at(
                target.provider_id,
                AddressFamily::V4,
                target.ip,
                start,
            );
        }
        for target in &v6_targets {
            pool.family_gates.record_failure_at(
                target.provider_id,
                AddressFamily::V6,
                target.ip,
                start,
            );
        }

        assert!(
            !pool.family_gates.is_open_for_at(
                AddressFamily::V6,
                start + FAMILY_GATE_FAILURE_WINDOW.as_secs() - 1
            ),
            "gate must stay closed before the two-minute failure window elapses"
        );

        let first = v6_targets[0];
        pool.family_gates.record_failure_at(
            first.provider_id,
            AddressFamily::V6,
            first.ip,
            start + FAMILY_GATE_FAILURE_WINDOW.as_secs(),
        );

        assert!(
            pool.family_gates.is_open_for_at(
                AddressFamily::V6,
                start + FAMILY_GATE_FAILURE_WINDOW.as_secs()
            ),
            "all selected IPv6 endpoints failing for two minutes must suppress IPv6"
        );
        assert!(!pool.family_gates.is_open_for_at(
            AddressFamily::V4,
            start + FAMILY_GATE_FAILURE_WINDOW.as_secs()
        ));
    }

    #[test]
    fn family_gate_waits_for_every_selected_ip_to_fail() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let start = now_secs();
        let v4_targets = pool.family_gates.targets_for(AddressFamily::V4).to_vec();
        let v6_targets = pool.family_gates.targets_for(AddressFamily::V6).to_vec();
        assert!(v6_targets.len() > 1);

        for target in v4_targets {
            pool.family_gates.record_success_at(
                target.provider_id,
                AddressFamily::V4,
                target.ip,
                start,
            );
        }
        for target in v6_targets.iter().take(v6_targets.len() - 1) {
            pool.family_gates.record_failure_at(
                target.provider_id,
                AddressFamily::V6,
                target.ip,
                start,
            );
        }

        let first = v6_targets[0];
        pool.family_gates.record_failure_at(
            first.provider_id,
            AddressFamily::V6,
            first.ip,
            start + FAMILY_GATE_FAILURE_WINDOW.as_secs(),
        );

        assert!(
            !pool.family_gates.is_open_for_at(
                AddressFamily::V6,
                start + FAMILY_GATE_FAILURE_WINDOW.as_secs()
            ),
            "one unfailed selected IPv6 endpoint must keep the IPv6 gate closed"
        );
    }

    #[test]
    fn family_gate_requires_every_selected_ip_to_fail_for_full_window() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let start = now_secs();
        let last_target_failed_at = start + FAMILY_GATE_FAILURE_WINDOW.as_secs();
        let opened_at = last_target_failed_at + FAMILY_GATE_FAILURE_WINDOW.as_secs();
        let v4_targets = pool.family_gates.targets_for(AddressFamily::V4).to_vec();
        let v6_targets = pool.family_gates.targets_for(AddressFamily::V6).to_vec();
        assert!(v6_targets.len() > 1);

        for target in &v4_targets {
            pool.family_gates.record_success_at(
                target.provider_id,
                AddressFamily::V4,
                target.ip,
                last_target_failed_at,
            );
        }
        for target in v6_targets.iter().take(v6_targets.len() - 1) {
            pool.family_gates.record_failure_at(
                target.provider_id,
                AddressFamily::V6,
                target.ip,
                start,
            );
        }

        let last = *v6_targets.last().unwrap();
        pool.family_gates.record_failure_at(
            last.provider_id,
            AddressFamily::V6,
            last.ip,
            last_target_failed_at,
        );
        assert!(
            !pool
                .family_gates
                .is_open_for_at(AddressFamily::V6, last_target_failed_at),
            "the last IPv6 endpoint's first failure must not open the gate immediately"
        );

        let first = v6_targets[0];
        pool.family_gates.record_failure_at(
            first.provider_id,
            AddressFamily::V6,
            first.ip,
            opened_at,
        );
        assert!(
            pool.family_gates
                .is_open_for_at(AddressFamily::V6, opened_at),
            "gate opens only after every selected IPv6 endpoint has been failing for two minutes"
        );
    }

    #[test]
    fn family_gate_opens_v4_when_ipv6_is_the_working_family() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();

        open_family_gate_for_test(&pool, AddressFamily::V4);

        assert!(pool.family_gates.is_open_for(AddressFamily::V4));
        assert!(!pool.family_gates.is_open_for(AddressFamily::V6));
    }

    #[test]
    fn family_gate_does_not_open_when_other_family_has_no_success() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let start = now_secs();

        let v6_targets = pool.family_gates.targets_for(AddressFamily::V6).to_vec();
        for target in &v6_targets {
            pool.family_gates.record_failure_at(
                target.provider_id,
                AddressFamily::V6,
                target.ip,
                start,
            );
        }
        let first = v6_targets[0];
        pool.family_gates.record_failure_at(
            first.provider_id,
            AddressFamily::V6,
            first.ip,
            start + FAMILY_GATE_FAILURE_WINDOW.as_secs(),
        );

        assert!(
            !pool.family_gates.is_open_for_at(
                AddressFamily::V6,
                start + FAMILY_GATE_FAILURE_WINDOW.as_secs()
            ),
            "must not suppress a family unless the opposite family has proven alive"
        );
    }

    #[test]
    fn family_gate_network_change_discards_partial_failure_window() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let start = now_secs();
        let v4_targets = pool.family_gates.targets_for(AddressFamily::V4).to_vec();
        let v6_targets = pool.family_gates.targets_for(AddressFamily::V6).to_vec();
        assert!(v6_targets.len() > 1);

        for target in v4_targets {
            pool.family_gates.record_success_at(
                target.provider_id,
                AddressFamily::V4,
                target.ip,
                start,
            );
        }
        for target in v6_targets.iter().take(v6_targets.len() - 1) {
            pool.family_gates.record_failure_at(
                target.provider_id,
                AddressFamily::V6,
                target.ip,
                start,
            );
        }

        pool.family_gates.close_all_for_network_change();

        let first = v6_targets[0];
        pool.family_gates.record_failure_at(
            first.provider_id,
            AddressFamily::V6,
            first.ip,
            start + FAMILY_GATE_FAILURE_WINDOW.as_secs(),
        );

        assert!(
            !pool.family_gates.is_open_for_at(
                AddressFamily::V6,
                start + FAMILY_GATE_FAILURE_WINDOW.as_secs()
            ),
            "network change must discard pre-change partial failures"
        );
    }

    #[test]
    fn family_gate_closes_on_network_change_or_two_hour_retry() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();

        open_family_gate_for_test(&pool, AddressFamily::V6);
        assert!(pool.family_gates.is_open_for(AddressFamily::V6));

        pool.family_gates.close_all_for_network_change();
        assert!(!pool.family_gates.is_open_for(AddressFamily::V6));

        let opened_at = open_family_gate_for_test(&pool, AddressFamily::V6);
        assert!(pool.family_gates.is_open_for_at(
            AddressFamily::V6,
            opened_at + FAMILY_GATE_RETRY_AFTER.as_secs() - 1
        ));
        assert!(!pool.family_gates.is_open_for_at(
            AddressFamily::V6,
            opened_at + FAMILY_GATE_RETRY_AFTER.as_secs()
        ));
    }

    #[test]
    fn family_gate_retry_starts_with_fresh_failure_window() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();

        let opened_at = open_family_gate_for_test(&pool, AddressFamily::V6);
        let retry_at = opened_at + FAMILY_GATE_RETRY_AFTER.as_secs();
        assert!(!pool
            .family_gates
            .is_open_for_at(AddressFamily::V6, retry_at));

        let v4_targets = pool.family_gates.targets_for(AddressFamily::V4).to_vec();
        let v6_targets = pool.family_gates.targets_for(AddressFamily::V6).to_vec();
        for target in v4_targets {
            pool.family_gates.record_success_at(
                target.provider_id,
                AddressFamily::V4,
                target.ip,
                retry_at,
            );
        }

        let first = v6_targets[0];
        pool.family_gates.record_failure_at(
            first.provider_id,
            AddressFamily::V6,
            first.ip,
            retry_at,
        );
        assert!(
            !pool
                .family_gates
                .is_open_for_at(AddressFamily::V6, retry_at),
            "first post-retry failure must not reuse stale failures from the previous gate"
        );

        for target in v6_targets.iter().skip(1) {
            pool.family_gates.record_failure_at(
                target.provider_id,
                AddressFamily::V6,
                target.ip,
                retry_at,
            );
        }
        pool.family_gates.record_failure_at(
            first.provider_id,
            AddressFamily::V6,
            first.ip,
            retry_at + FAMILY_GATE_FAILURE_WINDOW.as_secs(),
        );
        assert!(pool.family_gates.is_open_for_at(
            AddressFamily::V6,
            retry_at + FAMILY_GATE_FAILURE_WINDOW.as_secs()
        ));
    }

    #[test]
    fn pick_conn_skips_family_with_open_gate() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        force_all_ready(&p);

        open_family_gate_for_test(&pool, AddressFamily::V6);

        for _ in 0..100 {
            let (_, lease) = p.pick_conn().unwrap();
            assert_eq!(lease.family(), AddressFamily::V4);
        }
    }

    #[test]
    fn rebuild_all_conns_refreshes_open_gate_family_but_keeps_gate_closed_for_picks() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        open_family_gate_for_test(&pool, AddressFamily::V6);

        let before: Vec<(AddressFamily, usize)> = pool
            .all()
            .iter()
            .flat_map(|p| {
                p.conns
                    .iter()
                    .map(|c| (c.family(), Arc::as_ptr(&c.snapshot().resolver) as usize))
                    .collect::<Vec<_>>()
            })
            .collect();

        pool.rebuild_all_conns("test");

        let after: Vec<(AddressFamily, usize)> = pool
            .all()
            .iter()
            .flat_map(|p| {
                p.conns
                    .iter()
                    .map(|c| (c.family(), Arc::as_ptr(&c.snapshot().resolver) as usize))
                    .collect::<Vec<_>>()
            })
            .collect();

        for ((family, before_ptr), (_, after_ptr)) in before.iter().zip(after.iter()) {
            assert_ne!(
                before_ptr, after_ptr,
                "{family:?} resolver must be refreshed so config toggles do not leave stale options behind"
            );
        }

        assert!(pool.family_gates.is_open_for(AddressFamily::V6));
        let p = pool.all()[0].clone();
        force_all_ready(&p);
        for _ in 0..20 {
            let (_, lease) = p.pick_conn().unwrap();
            assert_eq!(lease.family(), AddressFamily::V4);
        }
    }

    #[test]
    fn pick_conn_prefers_ready_tier() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        p.conns[0].force_state(ConnState::Ready);
        for _ in 0..50 {
            let (idx, _lease) = p.pick_conn().unwrap();
            assert_eq!(idx, 0, "Ready conn must outrank all Warming siblings");
        }
    }

    #[test]
    fn pick_conn_falls_back_to_warming_then_degraded() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        for c in &p.conns {
            c.force_state(ConnState::Degraded);
        }
        p.conns[1].force_state(ConnState::Warming);
        for _ in 0..50 {
            let (idx, _) = p.pick_conn().unwrap();
            assert_eq!(idx, 1, "Warming must be preferred over Degraded");
        }
        // With every slot Degraded, pick must still return one.
        p.conns[1].force_state(ConnState::Degraded);
        assert!(p.pick_conn().is_some(), "Degraded must still be pickable");
    }

    #[test]
    fn pick_conn_skips_slots_over_inflight_cap() {
        // Slot 0 at the cap, slot 1 below it. Every pick must land on slot 1
        // so one connection does not carry a whole burst.
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        for c in &p.conns {
            c.force_state(ConnState::Degraded);
        }
        p.conns[0].force_state(ConnState::Ready);
        p.conns[1].force_state(ConnState::Ready);
        let _saturate: Vec<_> = (0..MAX_INFLIGHT_PER_CONN)
            .map(|_| ProviderConnLease::new(p.conns[0].clone()))
            .collect();
        assert_eq!(p.conns[0].inflight(), MAX_INFLIGHT_PER_CONN);
        for _ in 0..100 {
            let (idx, _lease) = p.pick_conn().unwrap();
            assert_eq!(
                idx, 1,
                "saturated slot must be skipped while a sibling is under cap"
            );
        }
    }

    #[test]
    fn pick_conn_falls_back_when_every_slot_at_cap() {
        // The cap is a routing preference, not a throttle: with every Ready
        // slot at the cap, pick_conn must still return one.
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        force_all_ready(&p);
        let mut leases = Vec::new();
        for c in &p.conns {
            for _ in 0..MAX_INFLIGHT_PER_CONN {
                leases.push(ProviderConnLease::new(c.clone()));
            }
        }
        for c in &p.conns {
            assert_eq!(c.inflight(), MAX_INFLIGHT_PER_CONN);
        }
        assert!(
            p.pick_conn().is_some(),
            "saturated pool must still pick a slot under the fallback path"
        );
    }

    #[test]
    fn pick_conn_balances_load_inside_tier() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        force_all_ready(&p);
        // No latency samples, so only inflight separates the conns.
        let _busy: Vec<_> = (0..3)
            .map(|i| ProviderConnLease::new(p.conns[i].clone()))
            .collect();
        for _ in 0..200 {
            let (idx, _lease) = p.pick_conn().unwrap();
            assert!(idx >= 3, "pick must avoid busier conns; got {}", idx);
        }
    }

    #[test]
    fn pick_conn_breaks_inflight_tie_by_latency() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        force_all_ready(&p);
        // Equal inflight, so the fastest sample (conn 5) decides.
        for _ in 0..5 {
            for i in 0..p.conn_count() {
                let us = if i == 5 { 5_000 } else { 50_000 };
                record_success_now!(p, i, us);
            }
        }
        let mut hit5 = 0;
        for _ in 0..200 {
            let (idx, _) = p.pick_conn().unwrap();
            if idx == 5 {
                hit5 += 1;
            }
        }
        assert_eq!(hit5, 200, "fastest conn must dominate under inflight tie");
    }

    #[test]
    fn record_success_promotes_warming_to_ready() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        assert_eq!(p.conns[0].state(), ConnState::Warming);
        record_success_now!(p, 0, 12_345);
        assert_eq!(p.conns[0].state(), ConnState::Ready);
        assert_eq!(p.conns[0].latency.len(), 1);
    }

    #[test]
    fn record_success_ignores_stale_generation() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        let stale_gen = p.conns[0].generation();
        let family = p.conns[0].family();
        let target = FamilyGateEndpoint {
            provider_id: p.id,
            ip: p.conns[0].target_ip(),
        };
        // A rebuild lands between the pick and the lookup completing.
        assert_eq!(p.conns[0].rebuild_if(stale_gen), RebuildOutcome::Rebuilt);
        pool.family_gates
            .record_failure_at(target.provider_id, family, target.ip, now_secs());
        let len_before = p.conns[0].latency.len();
        p.record_success(0, 12_345, stale_gen);
        assert!(
            p.conns[0].latency.is_empty() && p.conns[0].latency.len() == len_before,
            "stale-gen success must NOT push latency",
        );
        assert_eq!(
            p.conns[0].state(),
            ConnState::Warming,
            "stale-gen success must NOT promote the freshly rebuilt slot to Ready",
        );
        let inner = pool
            .family_gates
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let failures = match family {
            AddressFamily::V4 => &inner.v4.failed_targets,
            AddressFamily::V6 => &inner.v6.failed_targets,
        };
        assert!(
            failures.iter().any(|failure| failure.target == target),
            "stale-gen success must NOT clear the family-gate failure window"
        );
    }

    #[test]
    fn record_timeout_demotes_after_threshold() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        p.conns[0].force_state(ConnState::Ready);
        let gen_before = p.conns[0].generation();
        for _ in 0..(CONSECUTIVE_TIMEOUTS_THRESHOLD - 1) {
            record_timeout_now!(p, 0);
            assert_eq!(
                p.conns[0].state(),
                ConnState::Ready,
                "below threshold must stay Ready"
            );
        }
        record_timeout_now!(p, 0);
        assert_eq!(
            p.conns[0].state(),
            ConnState::Degraded,
            "reaching threshold must demote (without rebuild)"
        );
        assert_eq!(
            p.conns[0].generation(),
            gen_before,
            "demote must NOT rebuild — that was the death spiral the rewrite removed"
        );
        assert!(
            p.conns[0].latency.is_empty(),
            "timeouts must NOT pollute the latency window"
        );
    }

    #[test]
    fn record_timeout_ignores_stale_generation() {
        // Three overlapping lookups from the previous generation timing out
        // after a rebuild must not demote the fresh slot.
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        let stale_gen = p.conns[0].generation();
        let family = p.conns[0].family();
        let target = FamilyGateEndpoint {
            provider_id: p.id,
            ip: p.conns[0].target_ip(),
        };
        assert_eq!(p.conns[0].rebuild_if(stale_gen), RebuildOutcome::Rebuilt);
        p.conns[0].force_state(ConnState::Ready);
        for _ in 0..(CONSECUTIVE_TIMEOUTS_THRESHOLD + 2) {
            p.record_timeout(0, stale_gen);
        }
        assert_eq!(
            p.conns[0].state(),
            ConnState::Ready,
            "stale-gen timeouts must NOT demote the new generation"
        );
        assert_eq!(
            p.conns[0]
                .consecutive_timeouts
                .load(std::sync::atomic::Ordering::Acquire),
            0,
            "stale-gen timeouts must NOT bump the counter"
        );
        let inner = pool
            .family_gates
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let failures = match family {
            AddressFamily::V4 => &inner.v4.failed_targets,
            AddressFamily::V6 => &inner.v6.failed_targets,
        };
        assert!(
            !failures.iter().any(|failure| failure.target == target),
            "stale-gen timeouts must NOT seed the family-gate failure window"
        );
    }

    #[test]
    fn lease_captures_consistent_gen_and_resolver() {
        // The lookup still runs on the picked resolver after a rebuild, so
        // the lease must keep reporting the pick-time generation for the
        // gen check to reject its signals as stale.
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        p.conns[0].force_state(ConnState::Ready);
        let (idx, lease) = p.pick_conn().unwrap();
        assert_eq!(idx, 0);
        let captured_gen = lease.generation();
        let captured_resolver = lease.resolver();
        assert_eq!(p.conns[0].rebuild_if(captured_gen), RebuildOutcome::Rebuilt);
        assert_eq!(lease.generation(), captured_gen);
        assert!(Arc::ptr_eq(&lease.resolver(), &captured_resolver));
        assert_ne!(captured_gen, p.conns[0].generation());
    }

    #[test]
    fn rebuild_if_holds_lock_across_gen_check_and_build() {
        // Once another caller advanced the gen, `rebuild_if` must return
        // `StaleGen` without building, so a spurious `BuildFailed` cannot
        // demote the fresh generation.
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let conn = pool.all()[0].conns[0].clone();
        let stale_gen = conn.generation();
        assert_eq!(conn.rebuild_if(stale_gen), RebuildOutcome::Rebuilt);
        assert_eq!(conn.rebuild_if(stale_gen), RebuildOutcome::StaleGen);
    }

    #[test]
    fn rebuild_resets_consecutive_timeouts_atomically() {
        // The reset happens under the write_lock that advances gen, so any
        // `try_record_timeout_if_gen` that sees the new gen also sees a zero
        // counter. Otherwise a stale timeout could leave the new generation
        // with a phantom count.
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let conn = pool.all()[0].conns[0].clone();
        conn.force_state(ConnState::Ready);
        for _ in 0..(CONSECUTIVE_TIMEOUTS_THRESHOLD - 1) {
            let gen = conn.generation();
            conn.try_record_timeout_if_gen(gen);
        }
        assert!(
            conn.consecutive_timeouts.load(Ordering::Acquire) > 0,
            "test precondition: counter must be primed"
        );
        let gen = conn.generation();
        assert_eq!(conn.rebuild_if(gen), RebuildOutcome::Rebuilt);
        assert_eq!(
            conn.consecutive_timeouts.load(Ordering::Acquire),
            0,
            "rebuild must reset the counter under its own lock"
        );
    }

    #[test]
    fn try_record_timeout_skips_already_degraded() {
        // Timeouts on an already-Degraded slot must not grow the counter
        // without bound.
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let conn = pool.all()[0].conns[0].clone();
        conn.force_state(ConnState::Degraded);
        let gen = conn.generation();
        assert!(!conn.try_record_timeout_if_gen(gen));
        assert_eq!(
            conn.consecutive_timeouts.load(Ordering::Acquire),
            0,
            "Degraded slots must not bump the counter"
        );
    }

    #[test]
    fn record_timeout_counts_degraded_slot_for_family_gate() {
        // Degraded slots are still last-resort picks, so their timeouts feed
        // the address-family gate even though the per-slot counter stays put.
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let target = pool.family_gates.targets_for(AddressFamily::V6)[0];
        let provider = pool
            .all()
            .iter()
            .find(|p| p.id == target.provider_id)
            .unwrap()
            .clone();
        let idx = provider
            .conns
            .iter()
            .position(|c| c.family() == AddressFamily::V6 && c.target_ip() == target.ip)
            .unwrap();

        provider.conns[idx].force_state(ConnState::Degraded);
        let gen = provider.conns[idx].generation();
        provider.record_timeout(idx, gen);

        let inner = pool
            .family_gates
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        assert!(
            inner
                .v6
                .failed_targets
                .iter()
                .any(|failure| failure.target == target),
            "timeout from a last-resort Degraded IPv6 slot must count as family-gate failure"
        );
        assert_eq!(
            provider.conns[idx]
                .consecutive_timeouts
                .load(Ordering::Acquire),
            0,
            "Degraded timeout must not grow the per-slot counter"
        );
    }

    #[test]
    fn try_set_state_ready_resets_counter_even_when_already_ready() {
        // A keepalive success on an already-Ready slot takes the early
        // return in `try_set_state_if_gen` and must still reset the counter,
        // or the next timeout demotes a slot that just proved healthy.
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let conn = pool.all()[0].conns[0].clone();
        conn.force_state(ConnState::Ready);
        let gen = conn.generation();
        for _ in 0..(CONSECUTIVE_TIMEOUTS_THRESHOLD - 1) {
            conn.try_record_timeout_if_gen(gen);
        }
        assert!(conn.consecutive_timeouts.load(Ordering::Acquire) > 0);
        assert!(conn.try_set_state_if_gen(gen, ConnState::Ready));
        assert_eq!(
            conn.consecutive_timeouts.load(Ordering::Acquire),
            0,
            "`Ready` target must reset the counter on the early-return path too"
        );
    }

    fn simulate_build_failed(conn: &ProviderConn) {
        let _guard = conn.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let current = conn.inner.load_full();
        conn.store_build_failed_state_locked(&current);
    }

    #[test]
    fn build_failed_generation_bump_invalidates_stale_events() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        let conn = p.conns[0].clone();
        conn.force_state(ConnState::Ready);
        let stale_gen = conn.generation();
        let lease = ProviderConnLease::new(conn.clone());
        let previous_started = conn.generation_started_ms.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(2));

        simulate_build_failed(&conn);
        assert_eq!(conn.generation(), stale_gen + 1);
        assert_eq!(conn.state(), ConnState::Degraded);
        assert!(conn.generation_started_ms.load(Ordering::Relaxed) > previous_started);
        let context = conn.diagnostic_context(conn.generation());
        assert!(context.contains("leased_requests_approx=0"), "{context}");
        assert!(context.contains("slot_inflight=1"), "{context}");
        drop(lease);

        p.record_success(0, 12_345, stale_gen);
        assert_eq!(
            conn.state(),
            ConnState::Degraded,
            "stale success must not promote a slot after failed rebuild bumped generation"
        );
        assert!(
            conn.latency.is_empty(),
            "stale success must not contaminate latency after failed rebuild"
        );
        p.record_timeout(0, stale_gen);
        assert_eq!(
            conn.consecutive_timeouts.load(Ordering::Acquire),
            0,
            "stale timeout must not increment counter after failed rebuild"
        );
    }

    #[test]
    fn build_failed_transport_path_sets_cooldown_under_generation_lock() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let conn = pool.all()[0].conns[0].clone();
        conn.force_state(ConnState::Ready);
        let gen = conn.generation();

        simulate_build_failed(&conn);
        assert_eq!(conn.generation(), gen + 1);
        assert!(conn.is_in_transport_cooldown(now_millis()));
    }

    #[test]
    fn record_success_resets_consecutive_timeouts() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        for _ in 0..(CONSECUTIVE_TIMEOUTS_THRESHOLD - 1) {
            record_timeout_now!(p, 0);
        }
        // A success clears the counter, so the next timeout must not demote.
        record_success_now!(p, 0, 12_345);
        record_timeout_now!(p, 0);
        assert_eq!(p.conns[0].state(), ConnState::Ready);
    }

    #[test]
    fn timeout_degradation_reaches_host_log_once_with_generation_context() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let provider = &pool.all()[0];
        let conn = &provider.conns[0];
        conn.force_state(ConnState::Ready);
        let generation = conn.generation();
        let lines = crate::log_hooks::capture_logs(|| {
            for _ in 0..CONSECUTIVE_TIMEOUTS_THRESHOLD + 1 {
                provider.record_timeout(0, generation);
            }
        });
        let visible: Vec<_> = lines.iter().filter(|(level, _)| *level == 3).collect();
        assert_eq!(
            visible.len(),
            1,
            "degradation must produce one debug diagnostic"
        );
        let message = &visible[0].1;
        assert!(message.contains("gen=0"));
        assert!(message.contains("reason=consecutive_timeouts"));
        assert!(message.contains("generation_age_ms="));
        assert!(message.contains("idle_s="));
    }

    #[test]
    fn record_transport_error_rebuilds_and_marks_warming() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        p.conns[0].force_state(ConnState::Ready);
        for _ in 0..(CONSECUTIVE_TIMEOUTS_THRESHOLD - 1) {
            record_timeout_now!(p, 0);
        }
        let gen = p.conns[0].generation();
        p.record_transport_error(0, gen);
        assert_eq!(p.conns[0].generation(), gen + 1);
        assert_eq!(p.conns[0].state(), ConnState::Warming);
        assert_eq!(
            p.conns[0]
                .consecutive_timeouts
                .load(std::sync::atomic::Ordering::Acquire),
            0,
            "Rebuilt outcome must reset the consecutive_timeouts counter"
        );
    }

    #[test]
    fn conn_diagnostics_counts_leases_and_fences_rebuilt_generations() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        for _ in 0..5 {
            drop(ProviderConnLease::new(p.conns[0].clone()));
        }
        let gen = p.conns[0].generation();
        assert!(p
            .conn_diagnostics(0, gen)
            .contains("leased_requests_approx=5"));
        p.record_transport_error(0, gen);
        assert!(p
            .conn_diagnostics(0, gen + 1)
            .contains("leased_requests_approx=0"));
        assert_eq!(p.conn_diagnostics(0, gen), "context=stale current_gen=1");
    }

    #[test]
    fn pick_conn_skips_recent_transport_error_when_sibling_is_ready() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        force_all_ready(&p);

        for i in 0..p.conn_count() {
            let us = if i == 0 { 1_000 } else { 50_000 };
            record_success_now!(p, i, us);
        }

        let gen = p.conns[0].generation();
        p.record_transport_error(0, gen);
        p.conns[0].force_state(ConnState::Ready);

        for _ in 0..50 {
            let (idx, _) = p.pick_conn().unwrap();
            assert_ne!(
                idx, 0,
                "transport-error slot must cool down even after warm-up marks it Ready"
            );
        }
    }

    #[test]
    fn pick_conn_still_returns_when_every_ready_conn_is_cooling() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        force_all_ready(&p);

        for c in &p.conns {
            assert!(c.start_transport_cooldown_if_gen(c.generation()));
        }

        assert!(
            p.pick_conn().is_some(),
            "cooldown is a routing preference, not a hard throttle"
        );
    }

    #[test]
    fn record_transport_error_noops_on_stale_generation() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        let gen = p.conns[0].generation();
        // A concurrent caller already rebuilt.
        assert_eq!(p.conns[0].rebuild_if(gen), RebuildOutcome::Rebuilt);
        let new_gen = p.conns[0].generation();
        assert_eq!(new_gen, gen + 1);
        assert!(
            p.record_transport_error(0, gen),
            "a successful concurrent rebuild leaves the pool usable"
        );
        assert_eq!(
            p.conns[0].generation(),
            new_gen,
            "stale gen must not trigger another rebuild"
        );
    }

    #[test]
    fn record_transport_error_reports_unusable_pool_after_concurrent_build_failure() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        let conn = p.conns[0].clone();
        conn.force_state(ConnState::Ready);
        let stale_gen = conn.generation();

        simulate_build_failed(&conn);
        assert_eq!(conn.generation(), stale_gen + 1);
        assert_eq!(conn.state(), ConnState::Degraded);

        assert!(
            !p.record_transport_error(0, stale_gen),
            "a failed concurrent rebuild leaves the pool unusable"
        );
    }

    #[test]
    fn conn_lease_tracks_inflight_until_drop() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        let conn = p.conns[0].clone();
        assert_eq!(conn.inflight(), 0);
        let lease = ProviderConnLease::new(conn.clone());
        assert_eq!(conn.inflight(), 1);
        let lease2 = ProviderConnLease::new(conn.clone());
        assert_eq!(conn.inflight(), 2);
        drop(lease);
        assert_eq!(conn.inflight(), 1);
        drop(lease2);
        assert_eq!(conn.inflight(), 0);
    }

    #[test]
    fn backup_pick_prefers_opposite_address_family() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        force_all_ready(&p);
        // Primary is conn 0 (v4). A cheap v6 conn must win the backup pick.
        let v6_idx = p
            .conns
            .iter()
            .position(|c| c.family() == AddressFamily::V6)
            .unwrap();
        for _ in 0..5 {
            for i in 0..p.conn_count() {
                let us = if i == v6_idx { 5_000 } else { 50_000 };
                record_success_now!(p, i, us);
            }
        }
        let (idx, lease) = p.pick_backup_conn(0).unwrap();
        assert_eq!(idx, v6_idx);
        assert_eq!(lease.family(), AddressFamily::V6);
    }

    #[test]
    fn backup_pick_skips_recent_transport_error_when_sibling_is_ready() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        force_all_ready(&p);

        let primary_idx = p
            .conns
            .iter()
            .position(|c| c.family() == AddressFamily::V4)
            .unwrap();
        let cooling_idx = p
            .conns
            .iter()
            .position(|c| c.family() != p.conns[primary_idx].family())
            .unwrap();

        for i in 0..p.conn_count() {
            let us = if i == cooling_idx { 1_000 } else { 50_000 };
            record_success_now!(p, i, us);
        }

        let gen = p.conns[cooling_idx].generation();
        p.record_transport_error(cooling_idx, gen);
        p.conns[cooling_idx].force_state(ConnState::Ready);

        for _ in 0..50 {
            let (idx, _) = p.pick_backup_conn(primary_idx).unwrap();
            assert_ne!(
                idx, cooling_idx,
                "backup pick must avoid transport-error slot during cooldown"
            );
        }
    }

    #[test]
    fn backup_pick_avoids_penalized_opposite_family() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        force_all_ready(&p);
        let penalty_us = PROVIDER_TIMEOUT.as_micros() as u64;
        // Every v6 conn slow, every v4 conn except primary 0 fast.
        for _ in 0..LATENCY_WINDOW_SIZE {
            for i in 0..p.conn_count() {
                let us = match p.conns[i].family() {
                    AddressFamily::V4 if i == 0 => 5_000,
                    AddressFamily::V4 => 10_000,
                    AddressFamily::V6 => penalty_us,
                };
                record_success_now!(p, i, us);
            }
        }
        let (idx, lease) = p.pick_backup_conn(0).unwrap();
        assert_eq!(lease.family(), AddressFamily::V4);
        assert_ne!(idx, 0);
    }

    #[test]
    fn rebuild_conn_swaps_resolver_pointer() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        let conn = p.conns[0].clone();
        let before = Arc::as_ptr(&conn.snapshot().resolver) as usize;
        let gen = conn.generation();
        assert_eq!(conn.rebuild_if(gen), RebuildOutcome::Rebuilt);
        let after = Arc::as_ptr(&conn.snapshot().resolver) as usize;
        assert_ne!(before, after);
    }

    #[test]
    fn mark_used_resets_idle_secs() {
        let _ = now_secs();
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let conn = pool.all()[0].conns[0].clone();
        conn.mark_used();
        assert_eq!(conn.idle_secs(), 0);
    }

    #[test]
    fn rebuild_all_conns_swaps_every_resolver_and_resets_state() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        for p in pool.all() {
            for (i, c) in p.conns.iter().enumerate() {
                let s = match i % 3 {
                    0 => ConnState::Ready,
                    1 => ConnState::Warming,
                    _ => ConnState::Degraded,
                };
                c.force_state(s);
            }
        }
        let before: Vec<usize> = pool
            .all()
            .iter()
            .flat_map(|p| {
                p.conns
                    .iter()
                    .map(|c| Arc::as_ptr(&c.snapshot().resolver) as usize)
                    .collect::<Vec<_>>()
            })
            .collect();
        pool.rebuild_all_conns("test");
        let after: Vec<usize> = pool
            .all()
            .iter()
            .flat_map(|p| {
                p.conns
                    .iter()
                    .map(|c| Arc::as_ptr(&c.snapshot().resolver) as usize)
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(before.len(), after.len());
        for (b, a) in before.iter().zip(after.iter()) {
            assert_ne!(b, a, "every conn must have a fresh resolver after rebuild");
        }
        for p in pool.all() {
            for c in &p.conns {
                assert_eq!(c.state(), ConnState::Warming);
            }
        }
    }

    /// Fail-closed DNSSEC transition. A slot whose build failed during a toggle
    /// keeps a consistent but obsolete CD default and must become unroutable
    /// rather than answer under the old policy. The test forces the snapshot a
    /// `BuildFailed` rebuild leaves behind, so it never depends on a race.
    #[test]
    fn stale_dnssec_policy_makes_a_slot_unroutable() {
        let _guard = ConfigGuard::new(crate::config::ResolverOptions {
            dnssec: false,
            ..Default::default()
        });

        // Slots are built here, so every snapshot carries `built_for_dnssec = false`.
        let pool = ProviderPool::new();
        let provider = &pool.all()[0];
        force_all_ready(provider);
        assert!(
            provider.pick_conn().is_some(),
            "baseline: a slot matching the configured policy must be routable"
        );

        // Flip the toggle without rebuilding: the window between `config::set`
        // and a `rebuild_if` that failed to build.
        let mut flipped = (*crate::config::current()).clone();
        flipped.dnssec = true;
        crate::config::set(flipped);

        assert!(
            provider.pick_conn().is_none(),
            "stale-policy slot must not be picked"
        );
        assert!(
            provider.pick_backup_conn(0).is_none(),
            "stale-policy slot must not be chosen as a hedge backup"
        );
    }

    /// Liveness half of the gate: a gated slot must come back. A stale-policy
    /// slot in `Ready` serves nothing because the gate rejects it, and the
    /// tick treats `Ready` as keepalive-only. Without the policy-stale
    /// condition it would never be rebuilt and the provider would stay
    /// stranded.
    #[test]
    fn stale_policy_ready_slot_is_classified_for_recovery() {
        let _guard = ConfigGuard::new(crate::config::ResolverOptions {
            dnssec: false,
            ..Default::default()
        });

        let pool = ProviderPool::new();
        let provider = &pool.all()[0];
        force_all_ready(provider);

        let mut flipped = (*crate::config::current()).clone();
        flipped.dnssec = true;
        crate::config::set(flipped);

        let conn = &provider.conns[0];
        assert_eq!(
            conn.state(),
            ConnState::Ready,
            "precondition: slot is Ready"
        );
        assert!(
            !conn.matches_configured_policy(true),
            "precondition: slot is stale for the new policy"
        );

        // `Ready` and not stuck-warming, so only the policy-stale condition can
        // select this slot.
        assert!(
            maintenance_needs_recovery(conn, ConnState::Ready, true, false),
            "a stale-policy Ready slot must be classified for recovery, not keepalive"
        );
        // Under its own policy the same slot stays keepalive-only.
        assert!(
            !maintenance_needs_recovery(conn, ConnState::Ready, false, false),
            "a matching-policy Ready slot must not be forced into a rebuild"
        );
    }

    #[test]
    fn each_conn_has_independent_latency_window() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        record_success_now!(p, 0, 25_000);
        record_success_now!(p, 0, 35_000);
        assert_eq!(p.conns[0].latency.len(), 2);
        for conn in p.conns.iter().skip(1) {
            assert!(conn.latency.is_empty());
        }
    }

    #[test]
    fn latency_us_ignores_cold_conns() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        // Only conn 0 has samples, so the min mean is its single sample.
        record_success_now!(p, 0, 12_345);
        assert_eq!(p.latency_us(), 12_345);
    }

    #[test]
    fn latency_us_excludes_degraded_conn_with_stale_samples() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        // Conn 0 was fast but is now degraded. Conn 1 is healthy and slow.
        // `latency_us` must reflect conn 1, not the stale fast samples.
        for _ in 0..LATENCY_WINDOW_SIZE {
            record_success_now!(p, 0, 1_000);
        }
        p.conns[0].force_state(ConnState::Degraded);
        for _ in 0..LATENCY_WINDOW_SIZE {
            record_success_now!(p, 1, 50_000);
        }
        assert_eq!(
            p.latency_us(),
            50_000,
            "Degraded conn's pre-failure samples must not pull the provider ranking down"
        );
    }

    /// Recovery must start when `STUCK_WARMING_THRESHOLD` elapses, not up to
    /// one `MAINTENANCE_TICK` later when the tick samples the slot.
    #[tokio::test(start_paused = true)]
    async fn stuck_warming_recovery_runs_at_threshold() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        let conn = p.conns[0].clone();
        let gen0 = conn.generation();
        assert_eq!(conn.state(), ConnState::Warming);

        // Arms the watchdog. No warm-up ever completes here, which is the
        // stuck case.
        spawn_warmup(conn.clone(), p.id, p.name, 0, p.family_gates.clone());
        // Let the watchdog reach its sleep before the clock moves, or the
        // timer registers against an already advanced clock.
        tokio::task::yield_now().await;

        tokio::time::advance(STUCK_WARMING_THRESHOLD - Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            conn.generation(),
            gen0,
            "recovery must not fire before the threshold"
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            conn.generation(),
            gen0 + 1,
            "a slot stuck in Warming must be rebuilt at the threshold, not on the next maintenance tick"
        );
        assert_eq!(conn.state(), ConnState::Warming);
    }

    /// Once anything else has rebuilt the slot, the armed watchdog must do
    /// nothing, so it never fights the other recovery paths.
    #[tokio::test(start_paused = true)]
    async fn stale_generation_watchdog_does_not_rebuild() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        let conn = p.conns[0].clone();
        let stale_gen = conn.generation();

        arm_stuck_warming_watchdog(conn.clone(), p.id, p.name, 0, p.family_gates.clone());
        tokio::task::yield_now().await;

        // A transport error or maintenance tick rebuilt the slot first.
        assert_eq!(conn.rebuild_if(stale_gen), RebuildOutcome::Rebuilt);
        let current_gen = conn.generation();

        tokio::time::advance(STUCK_WARMING_THRESHOLD * 2).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            conn.generation(),
            current_gen,
            "a watchdog armed for a superseded generation must never rebuild"
        );

        // Same fence at the recovery entry point, for the race where the
        // timer elapsed before the cancellation was observed.
        recover_stuck_warming(
            conn.clone(),
            stale_gen,
            p.id,
            p.name,
            0,
            p.family_gates.clone(),
        );
        assert_eq!(
            conn.generation(),
            current_gen,
            "stale-generation recovery must not rebuild"
        );
    }

    /// The watchdog and the maintenance tick both recover through
    /// `rebuild_if`, so the loser sees `StaleGen` and the slot is rebuilt
    /// exactly once, with no reconnect storm from double recovery.
    #[tokio::test(start_paused = true)]
    async fn watchdog_and_maintenance_recovery_rebuild_only_once() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let p = pool.all()[0].clone();
        let conn = p.conns[0].clone();
        let gen0 = conn.generation();

        arm_stuck_warming_watchdog(conn.clone(), p.id, p.name, 0, p.family_gates.clone());
        tokio::task::yield_now().await;
        tokio::time::advance(STUCK_WARMING_THRESHOLD).await;

        // A maintenance tick recovers the same slot at the same generation.
        recover_stuck_warming(conn.clone(), gen0, p.id, p.name, 0, p.family_gates.clone());
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            conn.generation(),
            gen0 + 1,
            "watchdog and maintenance recovery must produce exactly one rebuild"
        );
    }

    #[test]
    fn stuck_warming_constant_exceeds_warmup_timeout() {
        // A warm-up that uses its full `WARMUP_TIMEOUT` must never be treated
        // as stuck.
        assert!(STUCK_WARMING_THRESHOLD > WARMUP_TIMEOUT);
    }

    #[test]
    fn probe_treats_no_connections_as_recovery_needed() {
        let res: Result<
            Result<hickory_resolver::lookup::Lookup, NetError>,
            tokio::time::error::Elapsed,
        > = Ok(Err(NetError::NoConnections));

        assert!(
            !probe_indicates_alive(&res),
            "NoConnections means hickory could not use any upstream connection"
        );
    }

    #[test]
    fn probe_treats_no_connections_message_as_recovery_needed() {
        let res: Result<
            Result<hickory_resolver::lookup::Lookup, NetError>,
            tokio::time::error::Elapsed,
        > = Ok(Err(NetError::from("no connections available".to_string())));

        assert!(
            !probe_indicates_alive(&res),
            "no connections available means hickory could not use any upstream connection"
        );
    }

    #[test]
    fn probe_treats_dnssec_negative_bogus_as_alive_for_rebuild_avoidance() {
        let res: Result<
            Result<hickory_resolver::lookup::Lookup, NetError>,
            tokio::time::error::Elapsed,
        > = Ok(Err(NetError::from(
            "DNS error: DNSSEC Negative Record Response for missing.example.com. IN A, Bogus"
                .to_string(),
        )));

        assert!(
            probe_indicates_alive(&res),
            "DNSSEC negative bogus is DNS-layer failure, not transport death"
        );
    }

    /// The exchange completed and the server answered, so the slot is alive.
    /// Degrading it would rebuild a working connection against the same
    /// provider that just refused.
    #[test]
    fn probe_treats_http_status_as_alive() {
        let res: Result<
            Result<hickory_resolver::lookup::Lookup, NetError>,
            tokio::time::error::Elapsed,
        > = Ok(Err(NetError::HttpStatus { status: 503 }));

        assert!(
            probe_indicates_alive(&res),
            "an HTTP status is the provider's answer over a live connection"
        );
    }

    #[test]
    fn probe_timeout_still_indicates_recovery_needed() {
        let res: Result<
            Result<hickory_resolver::lookup::Lookup, NetError>,
            tokio::time::error::Elapsed,
        > = Ok(Err(NetError::Timeout));

        assert!(
            !probe_indicates_alive(&res),
            "probe timeout means this slot still needs recovery"
        );
    }

    #[test]
    fn maintenance_revalidates_after_probe_timeout() {
        use hickory_proto::op::{Message, MessageType};
        use hickory_proto::rr::{rdata::NS, RData, Record};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[derive(Clone, Copy, Debug)]
        enum Scenario {
            Recovered,
            StillWedged,
            DnsFailure,
            ConcurrentSuccess,
            ConcurrentRebuild,
            PolicyChanged,
        }

        let _guard = ConfigGuard::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let lines = crate::log_hooks::capture_logs(|| {
            runtime.block_on(async {
                for scenario in [
                    Scenario::Recovered,
                    Scenario::StillWedged,
                    Scenario::DnsFailure,
                    Scenario::ConcurrentSuccess,
                    Scenario::ConcurrentRebuild,
                    Scenario::PolicyChanged,
                ] {
                    tokio::time::timeout(Duration::from_secs(10), async {
                        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                        let provider = Provider::for_local_test(listener.local_addr().unwrap());
                        let connections = Arc::new(AtomicUsize::new(0));
                        let original_requests = Arc::new(AtomicUsize::new(0));
                        let peer_provider = provider.clone();
                        let peer_connections = connections.clone();
                        let peer_requests = original_requests.clone();
                        let peer = tokio::spawn(async move {
                            let mut streams = tokio::task::JoinSet::new();
                            loop {
                                let (mut stream, _) = listener.accept().await.unwrap();
                                let id = peer_connections.fetch_add(1, Ordering::SeqCst);
                                let provider = peer_provider.clone();
                                let requests = peer_requests.clone();
                                streams.spawn(async move {
                                    while let Ok(size) = stream.read_u16().await {
                                        let mut wire = vec![0; usize::from(size)];
                                        stream.read_exact(&mut wire).await.unwrap();
                                        let mut message = Message::from_vec(&wire).unwrap();
                                        assert_eq!(
                                            message.queries[0],
                                            Query::query(Name::root(), RecordType::NS)
                                        );
                                        let request = if id == 0 {
                                            requests.fetch_add(1, Ordering::SeqCst)
                                        } else {
                                            0
                                        };
                                        if id == 0 && request > 0 {
                                            if request == 1 {
                                                continue;
                                            }
                                            match scenario {
                                                Scenario::Recovered => {}
                                                Scenario::StillWedged => continue,
                                                Scenario::DnsFailure => {
                                                    message.metadata.response_code =
                                                        hickory_proto::op::ResponseCode::ServFail;
                                                }
                                                Scenario::ConcurrentSuccess => {
                                                    provider.record_success(0, 123, 0);
                                                    continue;
                                                }
                                                Scenario::ConcurrentRebuild => {
                                                    assert_eq!(
                                                        provider.conns[0].rebuild_if(0),
                                                        RebuildOutcome::Rebuilt
                                                    );
                                                    continue;
                                                }
                                                Scenario::PolicyChanged => {
                                                    let mut config =
                                                        (*crate::config::current()).clone();
                                                    config.dnssec = !config.dnssec;
                                                    crate::config::set(config);
                                                }
                                            }
                                        }
                                        message.metadata.message_type = MessageType::Response;
                                        if message.metadata.response_code
                                            == hickory_proto::op::ResponseCode::NoError
                                        {
                                            message.add_answer(Record::from_rdata(
                                                Name::root(),
                                                0,
                                                RData::NS(NS(
                                                    Name::from_ascii("ns.example.").unwrap()
                                                )),
                                            ));
                                        }
                                        let wire = message.to_vec().unwrap();
                                        stream.write_u16(wire.len() as u16).await.unwrap();
                                        stream.write_all(&wire).await.unwrap();
                                    }
                                });
                            }
                        });
                        let conn = &provider.conns[0];
                        let snapshot = conn.snapshot();
                        snapshot
                            .resolver
                            .lookup(
                                Query::query(Name::root(), RecordType::NS),
                                snapshot.request_options,
                                false,
                            )
                            .await
                            .unwrap();
                        tokio::task::yield_now().await;
                        let timeout = tokio::time::timeout(
                            KEEPALIVE_TIMEOUT,
                            snapshot.resolver.lookup(
                                Query::query(Name::root(), RecordType::NS),
                                snapshot.request_options,
                                false,
                            ),
                        )
                        .await;
                        assert!(timeout.is_err(), "the established peer must stop answering");
                        assert!(conn.try_set_state_if_gen(0, ConnState::Degraded));
                        assert_eq!(conn.generation(), 0);
                        conn.consecutive_timeouts.store(2, Ordering::Release);

                        // Let Hickory retire the cancelled lookup before the next maintenance cycle.
                        tokio::time::sleep(
                            PROVIDER_TIMEOUT - KEEPALIVE_TIMEOUT + Duration::from_millis(50),
                        )
                        .await;
                        provider.maintenance_tick().await;
                        match scenario {
                            Scenario::Recovered | Scenario::ConcurrentSuccess => {
                                assert_eq!(
                                    conn.generation(),
                                    0,
                                    "{scenario:?}: preserve recovered pool"
                                );
                                assert_eq!(conn.state(), ConnState::Ready);
                                assert_eq!(conn.consecutive_timeouts.load(Ordering::Acquire), 0);
                                assert_eq!(connections.load(Ordering::SeqCst), 1);
                            }
                            Scenario::StillWedged | Scenario::DnsFailure => {
                                assert_eq!(conn.generation(), 1);
                                assert_eq!(conn.state(), ConnState::Ready);
                                assert_eq!(connections.load(Ordering::SeqCst), 2);
                            }
                            Scenario::ConcurrentRebuild => {
                                assert_eq!(
                                    conn.generation(),
                                    1,
                                    "stale probe must not rebuild twice"
                                );
                                assert_eq!(conn.state(), ConnState::Warming);
                                assert_eq!(connections.load(Ordering::SeqCst), 1);
                            }
                            Scenario::PolicyChanged => {
                                assert_eq!(conn.generation(), 0);
                                assert_eq!(conn.state(), ConnState::Degraded);
                                assert!(
                                    provider.pick_conn().is_none(),
                                    "obsolete policy must stay gated"
                                );
                                assert_eq!(connections.load(Ordering::SeqCst), 1);
                            }
                        }
                        assert_eq!(original_requests.load(Ordering::SeqCst), 3);
                        peer.abort();
                        let _ = peer.await;
                    })
                    .await
                    .expect("maintenance must remain bounded");
                }
            });
        });
        let reprobes: Vec<_> = lines
            .iter()
            .filter(|(_, line)| line.contains("phase=reprobe"))
            .collect();
        assert_eq!(
            reprobes.len(),
            3,
            "only applied reprobe outcomes are logged"
        );
        assert!(reprobes
            .iter()
            .all(|(level, line)| *level == 3 && line.contains("gen=0")));
        assert!(reprobes[0].1.contains("accepted=true"));
        assert!(reprobes[1].1.contains("accepted=false"));
        assert!(reprobes[2].1.contains("accepted=false"));
    }

    #[test]
    fn maintenance_logs_the_actual_recovery_probe_result() {
        use hickory_proto::op::{Message, MessageType};
        use hickory_proto::rr::{rdata::NS, RData, Record};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _guard = ConfigGuard::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let lines = crate::log_hooks::capture_logs(|| {
            runtime.block_on(async {
                for respond in [true, false] {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let provider = Provider::for_local_test(listener.local_addr().unwrap());
                    let conn = &provider.conns[0];
                    conn.force_state(ConnState::Degraded);
                    let mut config = (*crate::config::current()).clone();
                    config.dnssec = !config.dnssec;
                    crate::config::set(config);
                    let peer = async {
                        let (mut stream, _) = listener.accept().await.unwrap();
                        let size = stream.read_u16().await.unwrap();
                        let mut wire = vec![0; usize::from(size)];
                        stream.read_exact(&mut wire).await.unwrap();
                        let mut message = Message::from_vec(&wire).unwrap();
                        assert_eq!(
                            message.queries[0],
                            Query::query(Name::root(), RecordType::NS)
                        );
                        if respond {
                            message.metadata.message_type = MessageType::Response;
                            message.add_answer(Record::from_rdata(
                                Name::root(),
                                0,
                                RData::NS(NS(Name::from_ascii("ns.example.").unwrap())),
                            ));
                            let wire = message.to_vec().unwrap();
                            stream.write_u16(wire.len() as u16).await.unwrap();
                            stream.write_all(&wire).await.unwrap();
                        }
                        std::future::pending::<()>().await;
                    };
                    tokio::time::timeout(KEEPALIVE_TIMEOUT + Duration::from_secs(1), async {
                        tokio::select! {
                            () = provider.maintenance_tick() => {},
                            () = peer => unreachable!(),
                        }
                    })
                    .await
                    .unwrap();
                    assert_eq!(conn.generation(), 1);
                    assert_eq!(
                        conn.state(),
                        if respond {
                            ConnState::Ready
                        } else {
                            ConnState::Degraded
                        }
                    );
                }
            });
        });
        assert!(
            !lines.iter().any(|(_, line)| line.contains("phase=reprobe")),
            "obsolete policy must rebuild without revalidation"
        );
        let lines: Vec<_> = lines
            .iter()
            .filter(|(_, line)| line.contains("phase=recovery"))
            .collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            assert_eq!(line.0, 3);
            assert!(line.1.contains("gen=1"));
            assert!(line.1.contains("elapsed_us="));
        }
        assert!(lines[0].1.contains("accepted=true"));
        assert!(lines[0]
            .1
            .contains("outcome=response rcode=NoError answers=1"));
        assert!(lines[1].1.contains("accepted=false"));
        assert!(lines[1].1.contains("outcome=timeout source=deadline"));
    }

    /// Local TCP peer for the rotation tests. Every slot of `provider` is
    /// already connected to it and `Ready`.
    struct RotationPeer {
        provider: Arc<Provider>,
        connections: Arc<AtomicUsize>,
        /// Replacement connections that opened out of turn: while a slot was
        /// outside `Ready`, or before the previous replacement was published.
        out_of_turn: Arc<AtomicUsize>,
    }

    /// Answers root NS probes on the first `answering` connections and leaves
    /// later ones unanswered.
    async fn rotation_peer(slots: usize, answering: usize) -> RotationPeer {
        use hickory_proto::op::{Message, MessageType};
        use hickory_proto::rr::{rdata::NS, RData, Record};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = Provider::for_local_test_with_conns(listener.local_addr().unwrap(), slots);
        let connections = Arc::new(AtomicUsize::new(0));
        let out_of_turn = Arc::new(AtomicUsize::new(0));
        tokio::spawn({
            let provider = provider.clone();
            let connections = connections.clone();
            let out_of_turn = out_of_turn.clone();
            async move {
                let mut streams = tokio::task::JoinSet::new();
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let id = connections.fetch_add(1, Ordering::SeqCst);
                    if id >= slots {
                        let all_ready =
                            provider.conns.iter().all(|c| c.state() == ConnState::Ready);
                        let replaced = provider.conns.iter().filter(|c| c.generation() > 0).count();
                        if !all_ready || replaced != id - slots {
                            out_of_turn.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    streams.spawn(async move {
                        while let Ok(size) = stream.read_u16().await {
                            let mut wire = vec![0; usize::from(size)];
                            stream.read_exact(&mut wire).await.unwrap();
                            if id >= answering {
                                continue;
                            }
                            let mut message = Message::from_vec(&wire).unwrap();
                            message.metadata.message_type = MessageType::Response;
                            message.add_answer(Record::from_rdata(
                                Name::root(),
                                0,
                                RData::NS(NS(Name::from_ascii("ns.example.").unwrap())),
                            ));
                            let wire = message.to_vec().unwrap();
                            stream.write_u16(wire.len() as u16).await.unwrap();
                            stream.write_all(&wire).await.unwrap();
                        }
                    });
                }
            }
        });
        for conn in &provider.conns {
            let snapshot = conn.snapshot();
            snapshot
                .resolver
                .lookup(
                    Query::query(Name::root(), RecordType::NS),
                    snapshot.request_options,
                    false,
                )
                .await
                .unwrap();
            conn.force_state(ConnState::Ready);
        }
        RotationPeer {
            provider,
            connections,
            out_of_turn,
        }
    }

    fn backdate_all(provider: &Provider, by: Duration) {
        for conn in &provider.conns {
            conn.backdate_generation(by);
        }
    }

    fn generations(provider: &Provider) -> Vec<u64> {
        provider.conns.iter().map(|c| c.generation()).collect()
    }

    /// A slot must be replaced before the upstream's lifetime limit closes its
    /// connection. The replacement is published only after it answered, and
    /// the next slot starts only then, so no slot leaves `Ready` to rotate.
    #[test]
    fn maintenance_rotates_aged_conns_one_at_a_time() {
        let _guard = ConfigGuard::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let lines = crate::log_hooks::capture_logs(|| {
            runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(10), async {
                    let peer = rotation_peer(3, usize::MAX).await;
                    backdate_all(&peer.provider, CONN_ROTATION_AGE);

                    peer.provider.maintenance_tick().await;

                    assert_eq!(generations(&peer.provider), [1, 1, 1]);
                    for conn in &peer.provider.conns {
                        assert_eq!(conn.state(), ConnState::Ready);
                        assert!(conn.generation_age_ms() < 60_000);
                    }
                    assert_eq!(peer.connections.load(Ordering::SeqCst), 6);
                    assert_eq!(
                        peer.out_of_turn.load(Ordering::SeqCst),
                        0,
                        "replacements must open one at a time while every slot stays Ready"
                    );
                })
                .await
                .expect("rotation must remain bounded");
            });
        });
        assert!(
            lines
                .iter()
                .all(|(_, line)| !line.contains("phase=rotation")),
            "a replacement that answered must not be logged: {lines:?}"
        );
    }

    #[tokio::test]
    async fn maintenance_keeps_conns_below_the_rotation_age() {
        let _guard = ConfigGuard::default();
        let peer = rotation_peer(2, usize::MAX).await;
        backdate_all(&peer.provider, CONN_ROTATION_AGE - Duration::from_secs(1));

        peer.provider.maintenance_tick().await;

        assert_eq!(generations(&peer.provider), [0, 0]);
        assert_eq!(peer.connections.load(Ordering::SeqCst), 2);
    }

    /// Rotation goes by age alone. A query in flight does not delay it and
    /// keeps the connection it was leased on.
    #[tokio::test]
    async fn rotation_does_not_wait_for_a_quiet_provider() {
        let _guard = ConfigGuard::default();
        let peer = rotation_peer(2, usize::MAX).await;
        backdate_all(&peer.provider, CONN_ROTATION_AGE);
        let (_, lease) = peer.provider.pick_conn().unwrap();

        peer.provider.maintenance_tick().await;

        assert_eq!(generations(&peer.provider), [1, 1]);
        assert_eq!(lease.generation(), 0);
        lease
            .resolver()
            .lookup(
                Query::query(Name::root(), RecordType::NS),
                lease.request_options(),
                false,
            )
            .await
            .expect("a leased query must finish on the replaced connection");
        assert_eq!(peer.connections.load(Ordering::SeqCst), 4);
    }

    /// A replacement that does not answer is discarded and ends the round.
    /// Every slot keeps the connection it has, which still answers.
    #[test]
    fn failed_replacement_ends_the_rotation_round() {
        let _guard = ConfigGuard::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let lines = crate::log_hooks::capture_logs(|| {
            runtime.block_on(async {
                let peer = rotation_peer(3, 3).await;
                backdate_all(&peer.provider, CONN_ROTATION_AGE);

                tokio::time::timeout(
                    KEEPALIVE_TIMEOUT + Duration::from_secs(1),
                    peer.provider.maintenance_tick(),
                )
                .await
                .expect("one failed replacement must cost one probe timeout");

                assert_eq!(generations(&peer.provider), [0, 0, 0]);
                for conn in &peer.provider.conns {
                    assert_eq!(conn.state(), ConnState::Ready);
                    let snapshot = conn.snapshot();
                    snapshot
                        .resolver
                        .lookup(
                            Query::query(Name::root(), RecordType::NS),
                            snapshot.request_options,
                            false,
                        )
                        .await
                        .expect("the kept connection must still answer");
                }
                assert_eq!(peer.connections.load(Ordering::SeqCst), 4);
            });
        });
        let failures: Vec<_> = lines
            .iter()
            .filter(|(_, line)| line.contains("rotation failed"))
            .collect();
        assert_eq!(failures.len(), 1, "{lines:?}");
        let (level, line) = failures[0];
        assert_eq!(
            *level, 1,
            "a failed rotation must reach the log as a warning"
        );
        assert!(
            line.contains("conn[0]") && line.contains("outcome=timeout"),
            "{line}"
        );
    }

    /// A replacement probed for a generation that was rebuilt meanwhile must
    /// be discarded, or it would overwrite the rebuild that owns the slot.
    #[test]
    fn replacement_for_a_superseded_generation_is_discarded() {
        let _guard = ConfigGuard::default();
        let pool = ProviderPool::new();
        let conn = pool.all()[0].conns[0].clone();
        let replacement = |gen| {
            let mut next = (*conn.snapshot()).clone();
            next.gen = gen;
            next.state = ConnState::Ready;
            next
        };
        assert_eq!(conn.rebuild_if(0), RebuildOutcome::Rebuilt);

        assert!(!conn.replace_if_gen(0, replacement(1)));
        assert_eq!(conn.generation(), 1);
        assert_eq!(conn.state(), ConnState::Warming);

        conn.backdate_generation(CONN_ROTATION_AGE);
        assert!(conn.replace_if_gen(1, replacement(2)));
        assert_eq!(conn.generation(), 2);
        assert_eq!(conn.state(), ConnState::Ready);
        assert!(conn.generation_age_ms() < 60_000);
    }

    #[tokio::test]
    async fn rotation_skips_a_suppressed_family() {
        let _guard = ConfigGuard::default();
        let peer = rotation_peer(2, usize::MAX).await;
        open_gate_for_test(&peer.provider.family_gates, AddressFamily::V4);
        backdate_all(&peer.provider, CONN_ROTATION_AGE);

        peer.provider.maintenance_tick().await;

        assert_eq!(generations(&peer.provider), [0, 0]);
        assert_eq!(peer.connections.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn provider_conn_log_prefix_uses_canonical_format() {
        let target_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));

        let prefix = provider_conn_log_prefix("Quad9", 1, target_ip);

        assert_eq!(prefix, "provider[Quad9] conn[1] ip[9.9.9.9]");
    }

    #[test]
    fn pick_backup_returns_none_when_only_one_conn_exists() {
        let target_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let p = Provider {
            id: DoHProviderId::Cloudflare,
            name: "OneConn",
            conns: vec![ProviderConn::new(
                ns_cfg(target_ip, "cloudflare-dns.com", "/dns-query"),
                target_ip,
                AddressFamily::V4,
            )],
            family_gates: FamilyGateSet::for_provider_ids(vec![DoHProviderId::Cloudflare]),
        };
        assert!(p.pick_backup_conn(0).is_none());
    }

    /// Covers the production path `try_build_resolver` -> `InnerState` ->
    /// `lease.request_options()`. The mock tests in `provider_transport.rs`
    /// call `request_options()` directly, so without this the build site could
    /// derive DO from the toggle again and the suite would stay green.
    #[test]
    fn slots_request_dnssec_records_even_with_the_toggle_off() {
        let _guard = ConfigGuard::new(crate::config::ResolverOptions {
            dnssec: false,
            ..Default::default()
        });

        let pool = ProviderPool::new();
        let provider = &pool.all()[0];
        force_all_ready(provider);
        let (_idx, lease) = provider
            .pick_conn()
            .expect("a ready slot built for the current policy must be pickable");

        assert!(
            lease.request_options().edns_set_dnssec_ok,
            "RFC 4035 3.2.1: DO must be set upstream regardless of the toggle - \
             the toggle governs CD only"
        );
        assert!(
            !lease.matches_configured_policy(true),
            "the slot must still be recognised as built for the DNSSEC-off policy"
        );
    }
}
