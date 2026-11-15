// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide resolver counters: the query, answer and cache volumes the
/// MacDNS UI shows, plus prefetch, stale-served and rebinding-filtered counts.
///
/// Counters only increase and live in memory only, so a process restart resets
/// them to zero. Long-window aggregates must be accumulated by whoever polls
/// them. The persisted per-lookup record is the lookup history in `history`, a
/// separate store with its own schema.
pub struct Counters {
    pub queries_total: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub blocked: AtomicU64,
    pub servfail: AtomicU64,
    pub prefetch_refills: AtomicU64,
    pub stale_served: AtomicU64,
    pub rebinding_filtered: AtomicU64,
    pub below_nxdomain_hits: AtomicU64,
    pub udp_overload_drops: AtomicU64,
    pub tcp_overload_drops: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            servfail: AtomicU64::new(0),
            prefetch_refills: AtomicU64::new(0),
            stale_served: AtomicU64::new(0),
            rebinding_filtered: AtomicU64::new(0),
            below_nxdomain_hits: AtomicU64::new(0),
            udp_overload_drops: AtomicU64::new(0),
            tcp_overload_drops: AtomicU64::new(0),
        }
    }
}

static COUNTERS: Counters = Counters::new();

pub fn counters() -> &'static Counters {
    &COUNTERS
}

/// `Relaxed` everywhere. Counters order no other memory access, and a few
/// hundred nanoseconds of skew across cores is fine for stats. Each `inc`
/// compiles to a single `lock add` on x86_64 or `ldadd` on aarch64, the
/// cheapest atomic available.
#[inline]
pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn add(c: &AtomicU64, n: u64) {
    c.fetch_add(n, Ordering::Relaxed);
}

/// Wire-stable struct exposed across the FFI boundary. `#[repr(C)]` + `u64`
/// fields keep the layout identical between Swift and Rust: the agent passes
/// `dns_stats_snapshot` a pointer to its own eleven-`UInt64` mirror
/// (`RawResolverStats` in `ResolverModule.swift`) and reads the fields back in
/// declaration order, so adding, removing or reordering a field here is an ABI
/// change that must land on both sides together.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct StatsSnapshot {
    pub queries_total: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub blocked: u64,
    pub servfail: u64,
    pub prefetch_refills: u64,
    pub stale_served: u64,
    pub rebinding_filtered: u64,
    pub below_nxdomain_hits: u64,
    pub udp_overload_drops: u64,
    pub tcp_overload_drops: u64,
}

pub fn snapshot() -> StatsSnapshot {
    let c = counters();
    StatsSnapshot {
        queries_total: c.queries_total.load(Ordering::Relaxed),
        cache_hits: c.cache_hits.load(Ordering::Relaxed),
        cache_misses: c.cache_misses.load(Ordering::Relaxed),
        blocked: c.blocked.load(Ordering::Relaxed),
        servfail: c.servfail.load(Ordering::Relaxed),
        prefetch_refills: c.prefetch_refills.load(Ordering::Relaxed),
        stale_served: c.stale_served.load(Ordering::Relaxed),
        rebinding_filtered: c.rebinding_filtered.load(Ordering::Relaxed),
        below_nxdomain_hits: c.below_nxdomain_hits.load(Ordering::Relaxed),
        udp_overload_drops: c.udp_overload_drops.load(Ordering::Relaxed),
        tcp_overload_drops: c.tcp_overload_drops.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_returns_relaxed_loads_of_all_fields() {
        // Asserts only that each snapshot field reads the right counter.
        // Distinct deltas make a wiring mistake (loading the wrong counter)
        // show up as a number mismatch.
        let c = counters();
        let before = snapshot();
        add(&c.queries_total, 5);
        add(&c.cache_hits, 3);
        add(&c.cache_misses, 2);
        add(&c.blocked, 7);
        add(&c.servfail, 1);
        add(&c.prefetch_refills, 4);
        add(&c.stale_served, 6);
        add(&c.rebinding_filtered, 8);
        add(&c.below_nxdomain_hits, 9);
        add(&c.udp_overload_drops, 10);
        add(&c.tcp_overload_drops, 11);
        let after = snapshot();
        assert_eq!(after.queries_total - before.queries_total, 5);
        assert_eq!(after.cache_hits - before.cache_hits, 3);
        assert_eq!(after.cache_misses - before.cache_misses, 2);
        assert_eq!(after.blocked - before.blocked, 7);
        assert_eq!(after.servfail - before.servfail, 1);
        assert_eq!(after.prefetch_refills - before.prefetch_refills, 4);
        assert_eq!(after.stale_served - before.stale_served, 6);
        assert_eq!(after.rebinding_filtered - before.rebinding_filtered, 8);
        assert_eq!(after.below_nxdomain_hits - before.below_nxdomain_hits, 9);
        assert_eq!(after.udp_overload_drops - before.udp_overload_drops, 10);
        assert_eq!(after.tcp_overload_drops - before.tcp_overload_drops, 11);
    }

    #[test]
    fn struct_layout_is_eleven_u64_fields() {
        // FFI ABI gate. `dns_stats_snapshot` writes this struct into the
        // agent's mirror, which reads it as contiguous UInt64s. A field added
        // or removed in `StatsSnapshot` without updating the Swift wrapper
        // fails here before a misaligned reader ships.
        // `ResolverModule.statsSnapshot()` guards the Swift side the same way.
        assert_eq!(std::mem::size_of::<StatsSnapshot>(), 11 * 8);
    }
}
