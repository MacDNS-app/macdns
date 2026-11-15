// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use crate::config::DispatchMode;
use crate::provider_transport::{lookup_diagnostics, LookupResult};
use crate::providers::{Provider, ProviderConnLease, ProviderPool};
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::{Query, ResponseCode};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::{DnsError, ExtendedErrors, NetError};
use hickory_resolver::proto::rr::{Name, RecordType};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

const PRIMARY_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const BACKUP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(5);
const COLLECT_AFTER_FIRST: Duration = Duration::from_millis(500);

/// Multiplier applied to the fastest provider's sliding-window mean latency
/// per additional rank. Rank N fires after `fastest_mean * FACTOR * N`,
/// clamped to `[MIN, MAX]`. 0.5 means "give the faster provider about half
/// of its typical response time before the next sibling enters the race",
/// tight enough that a dead rank 0 only adds tens of ms of recovery latency.
///
/// The stagger orders the race; it does not reduce traffic. Delays top out at
/// `HEDGE_STAGGER_MAX` while `spawn_collector` keeps the remaining siblings
/// running for `COLLECT_AFTER_FIRST` after the first answer, so in the
/// parallel modes every eligible primary normally reaches the wire. Their
/// answers feed consensus and latency samples, which run whether or not ICMP
/// answer refinement is enabled.
const HEDGE_STAGGER_FACTOR: f64 = 0.5;
const HEDGE_STAGGER_MIN: Duration = Duration::from_millis(10);
const HEDGE_STAGGER_MAX: Duration = Duration::from_millis(150);

pub struct HedgeResult {
    pub first: Lookup,
    pub first_idx: usize,
    pub all: Vec<(usize, Lookup)>,
    pub refine: Option<JoinHandle<Vec<(usize, Lookup)>>>,
}

pub enum HedgeError {
    /// No provider produced a positive answer. If `negative` is `Some`, at
    /// least one provider returned an authoritative NXDOMAIN/NODATA (surfaced
    /// by hickory as `Err(NoRecordsFound)` rather than `Ok(empty_lookup)`).
    /// Callers should prefer that response over a blind SERVFAIL so negative
    /// caching and downstream validators keep working.
    AllFailed {
        negative: Option<NetError>,
        negative_idx: Option<usize>,
    },
    /// Every provider that answered returned a failure rcode. Distinct from
    /// `Timeout` because the name was reachable and the answer was a refusal.
    /// Reporting a network error for it sends an operator, and any EDE-aware
    /// client, after the wrong problem.
    UpstreamResponse {
        rcode: ResponseCode,
        /// Extended DNS Errors the provider attached to that rcode.
        extended_errors: ExtendedErrors,
    },
    Cancelled,
    Timeout,
}

/// Staggered parallel dispatch. Providers are ranked by their sliding-window
/// mean latency (fastest first) and each primary rank fires with an additional
/// delay proportional to that mean. The first positive answer returns to the
/// caller immediately, while pending siblings continue in a short background
/// collector so their latencies and divergent answers can refine the cache.
/// If no primary answers inside the fast budget, a backup slot per provider is
/// launched, preferring the opposite address family from the primary pick.
/// Providers whose primary already answered an authoritative negative are
/// skipped: a backup there repeats the same answer at the cost of a query.
/// Cold start (any provider with an empty window) short-circuits the stagger
/// to zero so nobody is penalised before real latency data exists.
///
/// `checking_disabled` is the client's own CD bit, carried to every attempt
/// this dispatch makes (primaries, backups and transport retries alike), so
/// the whole race asks the providers the same question. Callers with no client
/// behind them pass `false` and follow the DNSSEC toggle's default.
pub async fn dispatch(
    pool: &ProviderPool,
    name: &Name,
    qtype: RecordType,
    checking_disabled: bool,
    cancel: CancellationToken,
) -> Result<HedgeResult, HedgeError> {
    match crate::config::current().dispatch_mode {
        DispatchMode::Parallel | DispatchMode::StaggeredParallel => {
            dispatch_parallelish(pool, name, qtype, checking_disabled, cancel).await
        }
        DispatchMode::SequentialTimeout => {
            dispatch_sequential(pool, name, qtype, checking_disabled, cancel).await
        }
    }
}

async fn dispatch_parallelish(
    pool: &ProviderPool,
    name: &Name,
    qtype: RecordType,
    checking_disabled: bool,
    cancel: CancellationToken,
) -> Result<HedgeResult, HedgeError> {
    let mode = crate::config::current().dispatch_mode;
    let providers = pool.all().to_vec();
    let started = Instant::now();
    let backup_at = started + PRIMARY_LOOKUP_TIMEOUT;
    let deadline = started + GLOBAL_TIMEOUT;

    // Rank providers by their current sliding-window mean latency but keep
    // their stable pool index so sample updates, rebuild calls, and result
    // attribution all target the right provider regardless of the shuffle.
    let mut ranked: Vec<(usize, std::sync::Arc<crate::providers::Provider>)> =
        providers.iter().cloned().enumerate().collect();
    ranked.sort_by_key(|(_, p)| p.latency_us());
    // If any provider in the ranking is still cold (no samples yet), force
    // the stagger to zero for the whole pool. Otherwise an early-warmed
    // provider would keep deferring its cold siblings, which then never fill
    // their windows, and the first-warm bias perpetuates itself.
    let any_cold = ranked.iter().any(|(_, p)| p.latency_us() == 0);
    let fastest_us = if any_cold {
        0
    } else {
        ranked.first().map(|(_, p)| p.latency_us()).unwrap_or(0)
    };

    // Pre-pick a connection per provider so the (provider_idx, conn_idx, gen)
    // attribution survives across the await boundary. A targeted, race-free
    // transport-error rebuild needs it when this exact slot wedges.
    // The lease holds an `Arc<ProviderConn>` and increments `inflight` on
    // construction so subsequent picks within the same burst see real load
    // and balance away from busy slots. Dropping the lease decrements
    // `inflight`, including on the cancellation path where the outer
    // `FuturesUnordered` is dropped at the current await point.
    let mut futs: FuturesUnordered<DispatchFuture> = FuturesUnordered::new();
    let mut primary_picks = Vec::new();
    for (rank, (pool_idx, p)) in ranked.into_iter().enumerate() {
        let Some((conn_idx, lease)) = p.pick_conn() else {
            continue;
        };
        primary_picks.push((pool_idx, conn_idx));
        let gen = lease.generation();
        futs.push(lookup_future(DispatchPlan {
            pool_idx,
            conn_idx,
            gen,
            lease,
            name: name.clone(),
            qtype,
            checking_disabled,
            delay: delay_for_rank(mode, fastest_us, rank),
            timeout: PRIMARY_LOOKUP_TIMEOUT,
        }));
    }

    let mut all = Vec::new();
    let mut negative: Option<(usize, NetError)> = None;
    let mut upstream_rcode: Option<(ResponseCode, ExtendedErrors)> = None;
    let mut saw_timeout = false;
    let mut hit_global_timeout = false;
    let mut backups_started = false;
    // Providers whose primary answered an authoritative negative. They get no
    // backup: the answer is about the name, not about the slot that carried it.
    let mut concluded: Vec<usize> = Vec::new();

    loop {
        if futs.is_empty() {
            if !backups_started {
                enqueue_backups(
                    &mut futs,
                    &providers,
                    &primary_picks,
                    &concluded,
                    name,
                    qtype,
                    checking_disabled,
                );
                backups_started = true;
                if !futs.is_empty() {
                    continue;
                }
            }
            break;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            hit_global_timeout = true;
            break;
        }

        tokio::select! {
            _ = cancel.cancelled() => return Err(HedgeError::Cancelled),
            next = futs.next() => {
                let Some(event) = next else { break; };
                match record_event(event, &providers, name, qtype) {
                    EventOutcome::Positive { provider_idx, lookup } => {
                        all.push((provider_idx, lookup.clone()));
                        let refine = spawn_collector(futs, providers, name.clone(), qtype, cancel.clone());
                        return Ok(HedgeResult { first: lookup, first_idx: provider_idx, all, refine });
                    }
                    EventOutcome::Negative { provider_idx, error } => {
                        concluded.push(provider_idx);
                        if negative.is_none() {
                            negative = Some((provider_idx, error));
                        }
                    }
                    EventOutcome::DnsResponse { rcode, extended_errors } => {
                        // First rcode wins, mirroring how `negative` keeps the
                        // first authoritative answer rather than the last.
                        if upstream_rcode.is_none() {
                            upstream_rcode = Some((rcode, extended_errors));
                        }
                    }
                    EventOutcome::Timeout => saw_timeout = true,
                    EventOutcome::Failure => {}
                }
            }
            _ = tokio::time::sleep(backup_at.saturating_duration_since(Instant::now())), if !backups_started => {
                enqueue_backups(
                    &mut futs,
                    &providers,
                    &primary_picks,
                    &concluded,
                    name,
                    qtype,
                    checking_disabled,
                );
                backups_started = true;
            }
            _ = tokio::time::sleep(remaining) => {
                hit_global_timeout = true;
                break;
            }
        }
    }

    let (negative_idx, neg_err) = match negative {
        Some((i, e)) => (Some(i), Some(e)),
        None => (None, None),
    };
    Err(select_hedge_error(
        neg_err,
        negative_idx,
        upstream_rcode,
        saw_timeout || hit_global_timeout,
    ))
}

async fn dispatch_sequential(
    pool: &ProviderPool,
    name: &Name,
    qtype: RecordType,
    checking_disabled: bool,
    cancel: CancellationToken,
) -> Result<HedgeResult, HedgeError> {
    let providers = pool.all().to_vec();
    let deadline = Instant::now() + GLOBAL_TIMEOUT;
    let mut negative: Option<(usize, NetError)> = None;
    let mut upstream_rcode: Option<(ResponseCode, ExtendedErrors)> = None;
    let mut saw_timeout = false;

    for (pool_idx, provider) in providers.iter().enumerate() {
        let Some((conn_idx, lease)) = provider.pick_conn() else {
            continue;
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            // Fall through to the selector rather than returning: a provider
            // earlier in the loop may already have produced an authoritative
            // negative, and answering SERVFAIL would discard it.
            saw_timeout = true;
            break;
        }

        let gen = lease.generation();
        let event = tokio::select! {
            _ = cancel.cancelled() => return Err(HedgeError::Cancelled),
            event = lookup_future(DispatchPlan {
                pool_idx,
                conn_idx,
                gen,
                lease,
                name: name.clone(),
                qtype,
                checking_disabled,
                delay: Duration::ZERO,
                timeout: PRIMARY_LOOKUP_TIMEOUT.min(remaining),
            }) => event,
        };

        match record_event(event, &providers, name, qtype) {
            EventOutcome::Positive {
                provider_idx,
                lookup,
            } => {
                return Ok(HedgeResult {
                    first: lookup.clone(),
                    first_idx: provider_idx,
                    all: vec![(provider_idx, lookup)],
                    refine: None,
                });
            }
            EventOutcome::Negative {
                provider_idx,
                error,
            } => {
                if negative.is_none() {
                    negative = Some((provider_idx, error));
                }
                continue;
            }
            EventOutcome::DnsResponse {
                rcode,
                extended_errors,
            } => {
                if upstream_rcode.is_none() {
                    upstream_rcode = Some((rcode, extended_errors));
                }
            }
            EventOutcome::Timeout => saw_timeout = true,
            EventOutcome::Failure => {}
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            saw_timeout = true;
            break;
        }
        let Some((backup_idx, backup_lease)) = provider.pick_backup_conn(conn_idx) else {
            continue;
        };
        let backup_gen = backup_lease.generation();
        let event = tokio::select! {
            _ = cancel.cancelled() => return Err(HedgeError::Cancelled),
            event = lookup_future(DispatchPlan {
                pool_idx,
                conn_idx: backup_idx,
                gen: backup_gen,
                lease: backup_lease,
                name: name.clone(),
                qtype,
                checking_disabled,
                delay: Duration::ZERO,
                timeout: BACKUP_LOOKUP_TIMEOUT.min(remaining),
            }) => event,
        };
        match record_event(event, &providers, name, qtype) {
            EventOutcome::Positive {
                provider_idx,
                lookup,
            } => {
                return Ok(HedgeResult {
                    first: lookup.clone(),
                    first_idx: provider_idx,
                    all: vec![(provider_idx, lookup)],
                    refine: None,
                });
            }
            EventOutcome::Negative {
                provider_idx,
                error,
            } => {
                if negative.is_none() {
                    negative = Some((provider_idx, error));
                }
            }
            EventOutcome::DnsResponse {
                rcode,
                extended_errors,
            } => {
                if upstream_rcode.is_none() {
                    upstream_rcode = Some((rcode, extended_errors));
                }
            }
            EventOutcome::Timeout => saw_timeout = true,
            EventOutcome::Failure => {}
        }
    }

    let (negative_idx, neg_err) = match negative {
        Some((i, e)) => (Some(i), Some(e)),
        None => (None, None),
    };
    Err(select_hedge_error(
        neg_err,
        negative_idx,
        upstream_rcode,
        saw_timeout,
    ))
}

struct DispatchPlan {
    pool_idx: usize,
    conn_idx: usize,
    gen: u64,
    lease: ProviderConnLease,
    name: Name,
    qtype: RecordType,
    /// The client's CD bit, handed to `ProviderUpstream::lookup` so this
    /// attempt asks the provider exactly what the client asked for.
    checking_disabled: bool,
    delay: Duration,
    timeout: Duration,
}

struct DispatchEvent {
    pool_idx: usize,
    conn_idx: usize,
    target_ip: IpAddr,
    gen: u64,
    timeout: Duration,
    res: LookupResult,
    elapsed_us: u64,
}

type DispatchFuture = Pin<Box<dyn Future<Output = DispatchEvent> + Send>>;

enum EventOutcome {
    Positive {
        provider_idx: usize,
        lookup: Lookup,
    },
    Negative {
        provider_idx: usize,
        error: NetError,
    },
    DnsResponse {
        rcode: ResponseCode,
        extended_errors: ExtendedErrors,
    },
    Timeout,
    Failure,
}

#[derive(Debug, PartialEq, Eq)]
enum UpstreamErrorSignal {
    NegativeResponse,
    Timeout,
    /// The provider answered, with a failure rcode. Distinct from
    /// `NonTransportFailure` because it is evidence about the name. Every
    /// provider agreeing on SERVFAIL means something about the zone, whereas a
    /// busy pool or a dead socket says nothing about it.
    DnsResponseFailure,
    NonTransportFailure,
    TransportFailure,
}

fn lookup_future(plan: DispatchPlan) -> DispatchFuture {
    Box::pin(async move {
        if !plan.delay.is_zero() {
            tokio::time::sleep(plan.delay).await;
        }
        let target_ip = plan.lease.target_ip();
        let resolver = plan.lease.resolver();
        let options = plan.lease.request_options();
        let start = Instant::now();
        let res = tokio::time::timeout(
            plan.timeout,
            resolver
                .lookup(
                    Query::query(plan.name, plan.qtype),
                    options,
                    plan.checking_disabled,
                )
                .instrument(crate::provider_transport_trace::lookup_span(
                    plan.conn_idx,
                    target_ip,
                    plan.gen,
                )),
        )
        .await;
        let elapsed_us = start.elapsed().as_micros() as u64;
        // Dropping `lease` at the end of the future decrements `inflight`.
        // Only `record_success` calls `mark_used`, so a wedged conn that only
        // ever times out eventually crosses the idle threshold and earns a
        // keepalive probe.
        DispatchEvent {
            pool_idx: plan.pool_idx,
            conn_idx: plan.conn_idx,
            target_ip,
            gen: plan.gen,
            timeout: plan.timeout,
            res,
            elapsed_us,
        }
    })
}

/// Primary picks whose provider still deserves a backup attempt. A provider
/// that answered an authoritative negative has concluded: asking it again on
/// another slot costs a query and cannot change the answer, so only providers
/// that timed out or failed get a backup.
fn backup_targets<'a>(
    primary_picks: &'a [(usize, usize)],
    concluded: &'a [usize],
) -> impl Iterator<Item = &'a (usize, usize)> {
    primary_picks
        .iter()
        .filter(move |(pool_idx, _)| !concluded.contains(pool_idx))
}

fn enqueue_backups(
    futs: &mut FuturesUnordered<DispatchFuture>,
    providers: &[Arc<Provider>],
    primary_picks: &[(usize, usize)],
    concluded: &[usize],
    name: &Name,
    qtype: RecordType,
    checking_disabled: bool,
) {
    for (pool_idx, primary_conn_idx) in backup_targets(primary_picks, concluded) {
        let Some(provider) = providers.get(*pool_idx) else {
            continue;
        };
        let Some((conn_idx, lease)) = provider.pick_backup_conn(*primary_conn_idx) else {
            continue;
        };
        let gen = lease.generation();
        futs.push(lookup_future(DispatchPlan {
            pool_idx: *pool_idx,
            conn_idx,
            gen,
            lease,
            name: name.clone(),
            qtype,
            checking_disabled,
            delay: Duration::ZERO,
            timeout: BACKUP_LOOKUP_TIMEOUT,
        }));
    }
}

fn spawn_collector(
    mut futs: FuturesUnordered<DispatchFuture>,
    providers: Vec<Arc<Provider>>,
    name: Name,
    qtype: RecordType,
    cancel: CancellationToken,
) -> Option<JoinHandle<Vec<(usize, Lookup)>>> {
    if futs.is_empty() {
        return None;
    }
    match crate::runtime::spawn_on_current_or_global(async move {
        let deadline = Instant::now() + COLLECT_AFTER_FIRST;
        let mut all = Vec::new();
        loop {
            if futs.is_empty() {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            tokio::select! {
                _ = cancel.cancelled() => break,
                next = futs.next() => {
                    let Some(event) = next else { break; };
                    match record_event(event, &providers, &name, qtype) {
                        EventOutcome::Positive { provider_idx, lookup } => {
                            all.push((provider_idx, lookup));
                        }
                        EventOutcome::Negative { .. }
                        | EventOutcome::DnsResponse { .. }
                        | EventOutcome::Timeout
                        | EventOutcome::Failure => {}
                    }
                }
                _ = tokio::time::sleep(remaining) => break,
            }
        }
        all
    }) {
        Ok(handle) => Some(handle),
        Err(e) => {
            log::warn!("collector spawn failed: {}", e);
            None
        }
    }
}

fn record_event(
    event: DispatchEvent,
    providers: &[Arc<Provider>],
    name: &Name,
    qtype: RecordType,
) -> EventOutcome {
    let Some(provider) = providers.get(event.pool_idx) else {
        return EventOutcome::Failure;
    };
    match event.res {
        Ok(Ok(lookup)) => {
            // Validate the payload before recording success. An empty-Ok
            // response (NOERROR with no answers and no SOA) is a Failure
            // outcome below, so its latency must not enter the window, flip
            // the slot to `Ready` or reset `consecutive_timeouts`. That would
            // contaminate the ranking and self-healing signals with a
            // non-answer.
            if !crate::query::lookup_has_payload(&lookup) {
                log::warn!(
                    "{} {} {:?} returned empty-Ok (rcode={:?}) — ignoring",
                    hedge_conn_log_prefix(
                        event.pool_idx,
                        provider.name,
                        event.conn_idx,
                        event.target_ip
                    ),
                    name,
                    qtype,
                    lookup.message().metadata.response_code,
                );
                return EventOutcome::Failure;
            }
            provider.record_success(event.conn_idx, event.elapsed_us, event.gen);
            EventOutcome::Positive {
                provider_idx: event.pool_idx,
                lookup,
            }
        }
        Ok(Err(error)) => {
            match classify_upstream_error(&error) {
                UpstreamErrorSignal::NegativeResponse => {
                    // Authoritative NXDOMAIN/NODATA is a successful response.
                    // The H2 path proved alive even though the payload is empty.
                    provider.record_success(event.conn_idx, event.elapsed_us, event.gen);
                    EventOutcome::Negative {
                        provider_idx: event.pool_idx,
                        error,
                    }
                }
                UpstreamErrorSignal::Timeout => {
                    log::trace!(
                        "{} {} {:?} timed out after {:?}: {}",
                        hedge_conn_log_prefix(
                            event.pool_idx,
                            provider.name,
                            event.conn_idx,
                            event.target_ip
                        ),
                        name,
                        qtype,
                        event.timeout,
                        error
                    );
                    provider.record_timeout(event.conn_idx, event.gen);
                    EventOutcome::Timeout
                }
                UpstreamErrorSignal::DnsResponseFailure => {
                    log::debug!(
                        "{} {} {:?} non-transport failure: {}",
                        hedge_conn_log_prefix(
                            event.pool_idx,
                            provider.name,
                            event.conn_idx,
                            event.target_ip
                        ),
                        name,
                        qtype,
                        error
                    );
                    match response_code_of(&error) {
                        Some((rcode, extended_errors)) => EventOutcome::DnsResponse {
                            rcode,
                            extended_errors,
                        },
                        // A `DnsError` with no rcode is a protocol problem, not
                        // an answer about the name.
                        None => EventOutcome::Failure,
                    }
                }
                UpstreamErrorSignal::NonTransportFailure => {
                    log::debug!(
                        "{} gen={} phase=query action=failed elapsed_us={} {} {}",
                        hedge_conn_log_prefix(
                            event.pool_idx,
                            provider.name,
                            event.conn_idx,
                            event.target_ip
                        ),
                        event.gen,
                        event.elapsed_us,
                        provider.conn_diagnostics(event.conn_idx, event.gen),
                        lookup_diagnostics(&Ok(Err(error))),
                    );
                    EventOutcome::Failure
                }
                UpstreamErrorSignal::TransportFailure => {
                    // Rebuild resets generation counters, so capture the failed generation first.
                    let context = provider.conn_diagnostics(event.conn_idx, event.gen);
                    let details = lookup_diagnostics(&Ok(Err(error)));
                    // Hickory owns the bounded reconnect within this attempt's deadline.
                    let pool_usable = provider.record_transport_error(event.conn_idx, event.gen);
                    log::debug!(
                        "{} gen={} action=recovery_failed elapsed_us={} timeout_ms={} pool_usable={} {} {}",
                        hedge_conn_log_prefix(
                            event.pool_idx,
                            provider.name,
                            event.conn_idx,
                            event.target_ip
                        ),
                        event.gen,
                        event.elapsed_us,
                        event.timeout.as_millis(),
                        pool_usable,
                        context,
                        details,
                    );
                    EventOutcome::Failure
                }
            }
        }
        Err(_) => {
            // Timeout is a load signal, not a transport-failure signal, so
            // there is deliberately no rebuild here. Rebuilding a wedged
            // conn under load just throws away an H2 connection that
            // queued queries might still drain successfully, and
            // restarts the TLS handshake clock for every subsequent
            // pick that lands on this slot. A truly broken transport
            // surfaces through `Ok(Err(...))` (Io / broken pipe / TLS
            // errors), and a silently wedged conn that returns nothing
            // but timeouts eventually crosses the keepalive idle
            // threshold and gets probed there.
            log::trace!(
                "{} {} {:?} timed out after {:?}",
                hedge_conn_log_prefix(
                    event.pool_idx,
                    provider.name,
                    event.conn_idx,
                    event.target_ip
                ),
                name,
                qtype,
                event.timeout
            );
            provider.record_timeout(event.conn_idx, event.gen);
            EventOutcome::Timeout
        }
    }
}

fn classify_upstream_error(error: &NetError) -> UpstreamErrorSignal {
    if error.is_no_records_found() {
        return UpstreamErrorSignal::NegativeResponse;
    }

    match error {
        NetError::Timeout => UpstreamErrorSignal::Timeout,
        NetError::Dns(_) => UpstreamErrorSignal::DnsResponseFailure,
        // The exchange completed and the provider answered, with an HTTP
        // status or with a message the resolver could not accept. The slot
        // that carried it is intact.
        NetError::Busy
        | NetError::HttpStatus { .. }
        | NetError::Proto(_)
        | NetError::ForeignClassRecord { .. } => UpstreamErrorSignal::NonTransportFailure,
        NetError::Message(msg) if is_known_non_transport_error_text(msg) => {
            UpstreamErrorSignal::NonTransportFailure
        }
        NetError::Msg(msg) if is_known_non_transport_error_text(msg) => {
            UpstreamErrorSignal::NonTransportFailure
        }
        _ => UpstreamErrorSignal::TransportFailure,
    }
}

/// Chooses which failure to report when no provider produced an answer.
///
/// Precedence: authoritative negative, DNS response failure, timeout, generic
/// failure. A single timed-out sibling must not report `Timeout` for a query
/// every other provider answered with an rcode, because that reason reaches
/// the client as an EDE claiming a network error.
fn select_hedge_error(
    negative: Option<NetError>,
    negative_idx: Option<usize>,
    upstream_rcode: Option<(ResponseCode, ExtendedErrors)>,
    saw_timeout: bool,
) -> HedgeError {
    if negative.is_some() {
        HedgeError::AllFailed {
            negative,
            negative_idx,
        }
    } else if let Some((rcode, extended_errors)) = upstream_rcode {
        HedgeError::UpstreamResponse {
            rcode,
            extended_errors,
        }
    } else if saw_timeout {
        HedgeError::Timeout
    } else {
        HedgeError::AllFailed {
            negative: None,
            negative_idx: None,
        }
    }
}

/// The rcode a provider actually answered with, and the Extended DNS Errors
/// it attached, when the error carries one. Only `DnsError::ResponseCode`
/// does. Every other `DnsError` shape is a protocol or decoding problem with
/// no rcode to report.
fn response_code_of(error: &NetError) -> Option<(ResponseCode, ExtendedErrors)> {
    match error {
        NetError::Dns(DnsError::ResponseCode(rcode, extended_errors)) => {
            Some((*rcode, extended_errors.clone()))
        }
        _ => None,
    }
}

fn is_known_non_transport_error_text(msg: &str) -> bool {
    msg.contains("DNSSEC Negative Record Response")
}

fn hedge_conn_log_prefix(
    _pool_idx: usize,
    provider_name: &str,
    conn_idx: usize,
    target_ip: IpAddr,
) -> String {
    format!("provider[{provider_name}] conn[{conn_idx}] ip[{target_ip}]")
}

/// Compute per-rank dispatch delay from the fastest provider's sliding-window
/// mean latency. Rank 0 never waits. Higher ranks wait
/// `fastest_us * FACTOR * rank` clamped to `[MIN, MAX]` so the rank-0
/// provider starts first. Remaining siblings continue in the collector after
/// the first answer, so eligible primaries normally still reach the wire.
///
/// `fastest_us == 0` means the rank-0 provider has no samples yet (empty
/// window, cold start). Staggering on an unknown baseline would penalise
/// whoever happens to sort first by insertion order, so this short-circuits
/// to zero and let every provider race in parallel until the windows fill.
fn stagger_for_rank(fastest_us: u64, rank: usize) -> Duration {
    if rank == 0 || fastest_us == 0 {
        return Duration::ZERO;
    }
    let scaled = (fastest_us as f64 * HEDGE_STAGGER_FACTOR * rank as f64) as u64;
    Duration::from_micros(scaled).clamp(HEDGE_STAGGER_MIN, HEDGE_STAGGER_MAX)
}

fn delay_for_rank(mode: DispatchMode, fastest_us: u64, rank: usize) -> Duration {
    match mode {
        DispatchMode::Parallel => Duration::ZERO,
        DispatchMode::StaggeredParallel => stagger_for_rank(fastest_us, rank),
        DispatchMode::SequentialTimeout => Duration::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Query as DnsQuery, ResponseCode};
    use hickory_proto::rr::DNSClass;
    use hickory_resolver::net::{DnsError, NoRecords};

    #[test]
    fn lookup_budgets_preserve_full_primary_and_backup_windows() {
        assert_eq!(PRIMARY_LOOKUP_TIMEOUT, Duration::from_secs(2));
        assert_eq!(BACKUP_LOOKUP_TIMEOUT, Duration::from_secs(3));
        assert_eq!(
            GLOBAL_TIMEOUT,
            PRIMARY_LOOKUP_TIMEOUT + BACKUP_LOOKUP_TIMEOUT
        );
    }

    #[test]
    fn stagger_zero_for_rank_zero() {
        assert_eq!(stagger_for_rank(20_000, 0), Duration::ZERO);
        assert_eq!(stagger_for_rank(0, 0), Duration::ZERO);
    }

    #[test]
    fn parallel_delay_is_always_zero() {
        assert_eq!(
            delay_for_rank(DispatchMode::Parallel, 20_000, 2),
            Duration::ZERO
        );
    }

    #[test]
    fn staggered_delay_uses_stagger_policy() {
        assert_eq!(
            delay_for_rank(DispatchMode::StaggeredParallel, 20_000, 1),
            stagger_for_rank(20_000, 1)
        );
    }

    #[test]
    fn sequential_delay_is_zero() {
        assert_eq!(
            delay_for_rank(DispatchMode::SequentialTimeout, 20_000, 2),
            Duration::ZERO
        );
    }

    #[test]
    fn stagger_zero_on_cold_start() {
        // fastest_us == 0 signals an empty sliding window. All providers
        // must fire in parallel so no one pays a boot-time penalty.
        assert_eq!(stagger_for_rank(0, 1), Duration::ZERO);
        assert_eq!(stagger_for_rank(0, 2), Duration::ZERO);
    }

    #[test]
    fn stagger_scales_with_latency_and_rank() {
        // fastest = 40ms, factor 0.5 → rank 1 expects 20ms, rank 2 expects 40ms.
        // Both inside [10ms, 150ms] so no clamp kicks in.
        assert_eq!(stagger_for_rank(40_000, 1), Duration::from_millis(20));
        assert_eq!(stagger_for_rank(40_000, 2), Duration::from_millis(40));
    }

    #[test]
    fn stagger_clamps_floor() {
        // fastest = 1ms → 0.5ms scaled, bumped up to the 10ms floor so a
        // near-zero sliding-window seed on cold start does not collapse into
        // a synchronous fan-out.
        assert_eq!(stagger_for_rank(1_000, 1), HEDGE_STAGGER_MIN);
    }

    #[test]
    fn stagger_clamps_ceiling() {
        // fastest = 500ms × 0.5 × rank 2 = 500ms scaled, clamped to 150ms.
        assert_eq!(stagger_for_rank(500_000, 2), HEDGE_STAGGER_MAX);
    }

    #[test]
    fn classifies_no_connections_as_transport_failure() {
        assert_eq!(
            classify_upstream_error(&NetError::NoConnections),
            UpstreamErrorSignal::TransportFailure
        );
    }

    #[test]
    fn classifies_no_connections_message_as_transport_failure() {
        let err = NetError::from("no connections available".to_string());

        assert_eq!(
            classify_upstream_error(&err),
            UpstreamErrorSignal::TransportFailure
        );
    }

    #[test]
    fn classifies_dnssec_nsec_bogus_as_non_transport_failure() {
        let err = NetError::from(
            "DNS error: DNSSEC Negative Record Response for missing.example.com. IN A, Bogus"
                .to_string(),
        );

        assert_eq!(
            classify_upstream_error(&err),
            UpstreamErrorSignal::NonTransportFailure
        );
    }

    #[test]
    fn classifies_resolver_timeout_as_timeout() {
        assert_eq!(
            classify_upstream_error(&NetError::Timeout),
            UpstreamErrorSignal::Timeout
        );
    }

    #[test]
    fn record_event_counts_resolver_timeout_as_provider_timeout() {
        let pool = ProviderPool::new();
        let providers = pool.all().to_vec();
        let provider = providers[0].clone();
        let conn = provider.conns[0].clone();
        let name = Name::root();
        let qtype = RecordType::NS;

        for _ in 0..crate::providers::CONSECUTIVE_TIMEOUTS_THRESHOLD {
            let outcome = record_event(
                DispatchEvent {
                    pool_idx: 0,
                    conn_idx: 0,
                    target_ip: conn.target_ip(),
                    gen: conn.generation(),
                    timeout: Duration::from_millis(1),
                    res: Ok(Err(NetError::Timeout)),
                    elapsed_us: 0,
                },
                &providers,
                &name,
                qtype,
            );
            assert!(matches!(outcome, EventOutcome::Timeout));
        }

        assert_eq!(conn.state(), crate::providers::ConnState::Degraded);
    }

    #[test]
    fn exhausted_transport_recovery_rebuilds_without_another_retry() {
        let _guard = crate::config::ConfigGuard::default();
        let pool = ProviderPool::new();
        let providers = pool.all().to_vec();
        let provider = providers[0].clone();
        let conn = provider.conns[0].clone();
        let old_gen = conn.generation();
        let name = Name::root();
        let qtype = RecordType::NS;

        let mut outcome = None;
        let lines = crate::log_hooks::capture_logs(|| {
            outcome = Some(record_event(
                DispatchEvent {
                    pool_idx: 0,
                    conn_idx: 0,
                    target_ip: conn.target_ip(),
                    gen: old_gen,
                    timeout: Duration::from_millis(1),
                    res: Ok(Err(NetError::from(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "α\n\0".repeat(600),
                    )))),
                    elapsed_us: 0,
                },
                &providers,
                &name,
                qtype,
            ));
        });

        assert!(matches!(outcome.unwrap(), EventOutcome::Failure));
        assert_ne!(conn.generation(), old_gen);
        let message = lines
            .iter()
            .find(|(level, message)| *level == 3 && message.contains("action=recovery_failed"))
            .expect("exhausted recovery must produce a debug diagnostic");
        assert!(message.1.contains("gen=0"));
        assert!(message.1.contains("io_kind=BrokenPipe"));
        assert!(!message.1.contains("recovered"));
        let host_message = format!("[macdns_resolver::hedge] {}", message.1);
        assert!(
            host_message.len() <= 1024,
            "{} UTF-8 bytes",
            host_message.len()
        );
        assert!(host_message.find("action=recovery_failed").unwrap() + 22 <= 256);
    }

    /// Gates the middle of the chain. The selector tests below use
    /// `select_hedge_error` directly, so nothing else proves that a real
    /// SERVFAIL from a provider actually reaches it as `DnsResponse`.
    #[test]
    fn record_event_preserves_the_upstream_response_code() {
        let pool = ProviderPool::new();
        let providers = pool.all().to_vec();
        let provider = providers[0].clone();
        let conn = provider.conns[0].clone();
        let name = Name::from_ascii("example.com.").unwrap();
        let qtype = RecordType::A;

        let outcome = record_event(
            DispatchEvent {
                pool_idx: 0,
                conn_idx: 0,
                target_ip: conn.target_ip(),
                gen: conn.generation(),
                timeout: Duration::from_millis(1),
                res: Ok(Err(NetError::Dns(DnsError::ResponseCode(
                    ResponseCode::ServFail,
                    Default::default(),
                )))),
                elapsed_us: 0,
            },
            &providers,
            &name,
            qtype,
        );

        assert!(
            matches!(
                outcome,
                EventOutcome::DnsResponse {
                    rcode: ResponseCode::ServFail,
                    ..
                }
            ),
            "a provider's SERVFAIL must reach the selector as DnsResponse, not Failure"
        );
    }

    /// RFC 8484 §4.2.1: a non-2xx status is an HTTP outcome carried by a live
    /// exchange. Rebuilding the slot for it costs a handshake and a warm-up
    /// and, under rate limiting, turns every refusal into a reconnect.
    #[test]
    fn classifies_http_status_as_non_transport_failure() {
        assert_eq!(
            classify_upstream_error(&NetError::HttpStatus { status: 429 }),
            UpstreamErrorSignal::NonTransportFailure
        );
    }

    /// A response the resolver could not accept is evidence about the
    /// message, not about the socket that carried it.
    #[test]
    fn classifies_undecodable_responses_as_non_transport_failure() {
        let proto =
            NetError::from(hickory_proto::serialize::binary::DecodeError::InsufficientBytes);
        let foreign = NetError::ForeignClassRecord {
            record_name: Name::from_ascii("example.com.").unwrap(),
            record_class: DNSClass::CH,
            record_type: RecordType::A,
        };

        assert_eq!(
            classify_upstream_error(&proto),
            UpstreamErrorSignal::NonTransportFailure
        );
        assert_eq!(
            classify_upstream_error(&foreign),
            UpstreamErrorSignal::NonTransportFailure
        );
    }

    #[test]
    fn classifies_broken_pipe_as_transport_failure() {
        let err = broken_pipe_error();

        assert_eq!(
            classify_upstream_error(&err),
            UpstreamErrorSignal::TransportFailure
        );
    }

    #[test]
    fn classifies_dns_response_code_as_its_own_signal() {
        let err = NetError::Dns(DnsError::ResponseCode(
            ResponseCode::ServFail,
            Default::default(),
        ));
        assert_eq!(
            classify_upstream_error(&err),
            UpstreamErrorSignal::DnsResponseFailure,
            "a provider that answered with an rcode is evidence about the name, \
             not about the connection"
        );
    }

    /// `Busy` is local pool capacity, never a provider's answer. Keeping it in
    /// `NonTransportFailure` is what stops it from outranking a real timeout.
    #[test]
    fn classifies_busy_as_non_transport_not_a_dns_response() {
        assert_eq!(
            classify_upstream_error(&NetError::Busy),
            UpstreamErrorSignal::NonTransportFailure
        );
    }

    /// The critical ordering. An NXDOMAIN also arrives as `NetError::Dns`, so
    /// the `is_no_records_found()` early return must keep winning. If the
    /// `Dns(_)` arm ever captured it, every negative answer would become a
    /// SERVFAIL and negative caching would stop working.
    #[test]
    fn classifies_nxdomain_as_negative_not_a_dns_response() {
        let mut q = DnsQuery::new();
        q.set_name(Name::from_ascii("absent.example.").unwrap())
            .set_query_type(RecordType::A)
            .set_query_class(DNSClass::IN);
        let err = NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            q,
            ResponseCode::NXDomain,
        )));
        assert_eq!(
            classify_upstream_error(&err),
            UpstreamErrorSignal::NegativeResponse
        );
    }

    /// NODATA takes the same path with rcode NoError, and must also stay negative.
    #[test]
    fn classifies_nodata_as_negative_not_a_dns_response() {
        let mut q = DnsQuery::new();
        q.set_name(Name::from_ascii("present.example.").unwrap())
            .set_query_type(RecordType::AAAA)
            .set_query_class(DNSClass::IN);
        let err = NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            q,
            ResponseCode::NoError,
        )));
        assert_eq!(
            classify_upstream_error(&err),
            UpstreamErrorSignal::NegativeResponse
        );
    }

    /// One timed-out attempt must not mask every provider that answered by
    /// reporting `Timeout` for a name that was fully reachable.
    #[test]
    fn selects_a_dns_response_over_a_sibling_timeout() {
        let selected = select_hedge_error(
            None,
            None,
            Some((ResponseCode::ServFail, ExtendedErrors::default())),
            /* saw_timeout */ true,
        );
        assert!(
            matches!(
                selected,
                HedgeError::UpstreamResponse {
                    rcode: ResponseCode::ServFail,
                    ..
                }
            ),
            "a provider's rcode must outrank a sibling's timeout"
        );
    }

    /// An authoritative negative still outranks everything, so negative caching
    /// and downstream validators keep working.
    #[test]
    fn selects_an_authoritative_negative_over_a_dns_response() {
        let mut q = DnsQuery::new();
        q.set_name(Name::from_ascii("absent.example.").unwrap())
            .set_query_type(RecordType::A)
            .set_query_class(DNSClass::IN);
        let negative = NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            q,
            ResponseCode::NXDomain,
        )));
        let selected = select_hedge_error(
            Some(negative),
            Some(0),
            Some((ResponseCode::ServFail, ExtendedErrors::default())),
            true,
        );
        assert!(matches!(
            selected,
            HedgeError::AllFailed {
                negative: Some(_),
                ..
            }
        ));
    }

    /// With no rcode anywhere, a timeout is still the honest answer.
    #[test]
    fn selects_timeout_when_no_provider_answered() {
        let selected = select_hedge_error(None, None, None, true);
        assert!(matches!(selected, HedgeError::Timeout));
    }

    #[test]
    fn selects_all_upstream_failed_for_plain_failures() {
        let selected = select_hedge_error(None, None, None, false);
        assert!(matches!(
            selected,
            HedgeError::AllFailed { negative: None, .. }
        ));
    }

    #[test]
    fn hedge_conn_log_prefix_uses_canonical_format() {
        let target_ip = "149.112.112.112".parse().unwrap();

        let prefix = hedge_conn_log_prefix(2, "Quad9", 6, target_ip);

        assert_eq!(prefix, "provider[Quad9] conn[6] ip[149.112.112.112]");
    }

    fn broken_pipe_error() -> NetError {
        NetError::from(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken pipe",
        ))
    }

    /// An authoritative negative concludes a provider. Asking it again on a
    /// backup slot costs a query and cannot change the answer, and would make
    /// every NXDOMAIN and NODATA miss pay two queries per provider.
    #[test]
    fn negative_primary_does_not_get_a_backup() {
        use std::sync::atomic::Ordering;

        let _guard = crate::config::ConfigGuard::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (address, queries) =
                crate::test_dns_server::spawn_negative_server(ResponseCode::NXDomain, true).await;
            let provider = Provider::for_local_test_with_conns(address, 2);
            let pool = ProviderPool::for_local_test(vec![provider]);

            let result = tokio::time::timeout(
                Duration::from_secs(5),
                dispatch(
                    &pool,
                    &Name::from_ascii("absent.example.").unwrap(),
                    RecordType::A,
                    false,
                    CancellationToken::new(),
                ),
            )
            .await
            .expect("a negative answer must end the hedge well inside the global budget");
            assert!(
                matches!(
                    result,
                    Err(HedgeError::AllFailed {
                        negative: Some(_),
                        ..
                    })
                ),
                "the provider's NXDOMAIN must reach the caller"
            );
            // A stray backup would land within the stagger window.
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                queries.load(Ordering::SeqCst),
                1,
                "one authoritative negative must cost exactly one upstream query"
            );
        });
    }

    #[test]
    fn backups_skip_concluded_providers_and_keep_the_rest() {
        let picks = [(0usize, 3usize), (1, 4), (2, 5)];

        let targets: Vec<_> = backup_targets(&picks, &[0, 2]).collect();

        assert_eq!(targets, vec![&(1, 4)]);
    }
}
