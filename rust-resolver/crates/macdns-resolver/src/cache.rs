// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use moka::future::Cache;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify, RwLock};

/// Fixed-size pool of write locks, hashed by `CacheKey`. Bounded so the
/// resolver does not accumulate per-key mutexes over time. Collisions
/// serialize unrelated keys in the same stripe but cost only contention,
/// never correctness.
const WRITE_LOCK_STRIPES: usize = 256;

/// Fixed TTL bounds. Positive answers have a ceiling only (86400s, one day)
/// and no floor. A short authoritative TTL is a deliberate failover signal,
/// so extending 1–29s records to a local minimum would keep serving a dead
/// address long after the operator moved it. TTL 0 means "do not cache" (RFC
/// 2181 §8) and is refused by `insert`. Negative answers keep their own
/// [1s, 5s] curve so transient NXDOMAIN/NODATA and operator blocklist
/// changes recover quickly.
pub const MAX_TTL_SECS: u32 = 86_400;
pub const NEG_MIN_TTL_SECS: u32 = 1;
pub const NEG_MAX_TTL_SECS: u32 = 5;

/// Maximum staleness (seconds past original expiry) for the RFC 8767
/// serve-expired fallback. Default is 21800s (~6 hours).
pub const SERVE_EXPIRED_TTL_SECS: u64 = 21_800;

/// Upper bound on the denial-proof records retained per NXDOMAIN apex entry.
/// A canonical NSEC3 NXDOMAIN denial is four RRsets (the SOA plus the closest
/// encloser, next closer and wildcard NSEC3 records), and an RRset carries two
/// signatures whenever the zone is mid-key-rollover or signs with two
/// algorithms, so 4 × 3 = 12 covers a complete proof from a zone in either
/// state. Anything beyond that is an authority padding the response. Retaining
/// it unbounded would let a flood of NXDOMAIN names with oversized authority
/// sections grow the tracker far past its entry count. At the budget the
/// tracker holds at most 12 records × 4096 entries, each record well under 1
/// KiB even with an RSA-2048 signature, and every entry expires within
/// `NEG_MAX_TTL_SECS`.
const NXDOMAIN_APEX_MAX_PROOF_RECORDS: usize = 12;

/// Authority records worth replaying under RFC 8020: the SOA that bounds the
/// denial plus the DNSSEC records that prove it. NS referrals and glue
/// describe the upstream's delegation, not the denial, so they are dropped.
fn is_denial_proof(rec: &Record) -> bool {
    matches!(
        rec.record_type(),
        RecordType::SOA | RecordType::NSEC | RecordType::NSEC3 | RecordType::RRSIG
    )
}

/// Records that prove a name does not exist. An `RRSIG` on its own asserts
/// nothing about nonexistence, so it does not qualify: it is only meaningful
/// next to the RRset it covers.
fn is_negation_record(rec: &Record) -> bool {
    matches!(rec.record_type(), RecordType::NSEC | RecordType::NSEC3)
}

/// The type an `RRSIG` covers, or `None` when the rdata does not carry it.
fn rrsig_type_covered(rec: &Record) -> Option<RecordType> {
    match &rec.data {
        RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some(sig.input().type_covered),
        _ => None,
    }
}

/// Identifies one retained proof unit: the owner name plus the RRset type the
/// unit covers. `None` marks an owner-wide unit, used when a signature's
/// covered type cannot be read.
type ProofSetKey<'a> = (&'a Name, Option<RecordType>);

/// Splits the denial-proof records of `authorities` into the units a validator
/// checks: one RRset plus every `RRSIG` covering it. Owners carrying a
/// signature whose covered type cannot be read from the rdata degrade to a
/// single group per owner. That is coarser than an RRset, but it never
/// separates a signature from what it signs. Groups keep wire order.
fn group_proof_rrsets(authorities: &[Record]) -> Vec<Vec<&Record>> {
    let opaque_owners: Vec<&Name> = authorities
        .iter()
        .filter(|rec| rec.record_type() == RecordType::RRSIG && rrsig_type_covered(rec).is_none())
        .map(|rec| &rec.name)
        .collect();
    let mut sets: Vec<(ProofSetKey<'_>, Vec<&Record>)> = Vec::new();
    for rec in authorities.iter().filter(|rec| is_denial_proof(rec)) {
        let covered = if opaque_owners.contains(&&rec.name) {
            None
        } else {
            Some(rrsig_type_covered(rec).unwrap_or(rec.record_type()))
        };
        let key = (&rec.name, covered);
        match sets.iter().position(|(existing, _)| *existing == key) {
            Some(i) => sets[i].1.push(rec),
            None => sets.push((key, vec![rec])),
        }
    }
    sets.into_iter().map(|(_, records)| records).collect()
}

/// Picks the denial proof retained for one apex entry, bounded by
/// `NXDOMAIN_APEX_MAX_PROOF_RECORDS`. Authority sections carry no guaranteed
/// order, so keeping the first qualifying records can drop the SOA or cut an
/// NSEC/NSEC3 away from its signatures, and either one leaves a synthesized
/// denial no client can accept. Records are grouped into RRsets by
/// `group_proof_rrsets`, the RRset carrying the SOA is retained first, then
/// whole RRsets fill the remaining budget in wire order. A set that does not
/// fit is dropped entirely instead of cut in half.
///
/// Retaining the SOA's own RRset first is what keeps the SOA and the `RRSIG`
/// covering it together. A `DO=1` client handed an SOA whose signature the cap
/// discarded cannot verify the denial. If that RRset alone exceeds the budget,
/// the retained set degrades to the bare SOA that RFC 2308 §2.1 requires, so
/// the cap holds no matter what the authority sent.
///
/// Returns `None` when the retained set cannot carry a coherent denial:
/// when the section has no SOA at all (RFC 2308 §2.1 makes it mandatory, and a
/// denial nothing bounds must not be replayed), or when any NSEC/NSEC3 RRset
/// the response used to prove the denial did not fit the budget. An NSEC3
/// NXDOMAIN proves nonexistence only as a whole (closest encloser, next closer
/// and wildcard denial together), so replaying two of the three would deny
/// every descendant of a name with a proof no validator accepts. Refusing
/// leaves the resolver asking upstream, which is the correct answer. A response
/// carrying no DNSSEC at all is still a valid cut.
fn retain_denial_proof(authorities: &[Record]) -> Option<Arc<[Record]>> {
    let sets = group_proof_rrsets(authorities);
    let soa_idx = sets
        .iter()
        .position(|records| records.iter().any(|r| r.record_type() == RecordType::SOA))?;
    let soa_set = &sets[soa_idx];
    let mut retained = vec![false; sets.len()];
    let mut proof: Vec<&Record> = if soa_set.len() <= NXDOMAIN_APEX_MAX_PROOF_RECORDS {
        retained[soa_idx] = true;
        soa_set.clone()
    } else {
        vec![*soa_set
            .iter()
            .find(|r| r.record_type() == RecordType::SOA)?]
    };
    for (idx, records) in sets.iter().enumerate() {
        if idx == soa_idx {
            continue;
        }
        if proof.len() + records.len() <= NXDOMAIN_APEX_MAX_PROOF_RECORDS {
            proof.extend(records.iter().copied());
            retained[idx] = true;
        }
    }
    let denial_proof_is_whole = sets
        .iter()
        .zip(&retained)
        .all(|(records, kept)| *kept || !records.iter().any(|r| is_negation_record(r)));
    if !denial_proof_is_whole {
        return None;
    }
    Some(proof.into_iter().cloned().collect())
}

static CACHE_CLOCK_START: OnceLock<Instant> = OnceLock::new();

pub(crate) fn cache_clock_secs() -> u64 {
    CACHE_CLOCK_START
        .get_or_init(Instant::now)
        .elapsed()
        .as_secs()
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
}

impl CacheKey {
    pub fn from(domain: &str, qtype: RecordType) -> Self {
        Self {
            name: domain.trim_end_matches('.').to_lowercase(),
            qtype: u16::from(qtype),
        }
    }
}

/// Cached DNS answer. `expires_at` enforces per-entry TTL on top of moka's
/// hard MAX_TTL_SECS upper bound. `get()` returns `None` for stale entries
/// and leaves them in place so `get_allow_expired` (serve-expired fallback)
/// can still find them. `provider` preserves which upstream produced the
/// answer so reply logs can attribute cache hits to the DoH provider that
/// originally won the hedge race. It is refreshed when background_refine swaps
/// the winner. `inserted_at` is set by `insert()` and used by callers to
/// decrement record TTLs on the wire so downstream resolvers see the
/// remaining lifetime, not the original value. `original_ttl_secs` is
/// captured at insert time so prefetch can judge "close to expiry" without
/// having to store the whole history, since `remaining / original` gives a
/// stable ratio. `refresh_state` is shared behind an `Arc`. moka clones
/// `CachedEntry` on every `get`, but every clone still observes the same owner
/// and its source, so repeated hits run only one refill per entry and can
/// attribute collisions.
#[derive(Clone)]
pub struct CachedEntry {
    pub message: Message,
    pub inserted_at: Instant,
    pub expires_at: Instant,
    pub provider: String,
    pub original_ttl_secs: u32,
    pub(crate) refresh_state: Arc<RefreshState>,
    pub last_used_secs: Arc<AtomicU64>,
    /// Per-entry counter for `rrset-roundrobin` rotation. Shared across
    /// moka clones via `Arc` so consecutive cache hits for the same name
    /// deal out different orderings without having to re-insert the
    /// entry. Starts at 0 on insert and increments on every hit.
    pub rotation_counter: Arc<AtomicU32>,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RefreshSource {
    Demand = 1,
    CacheHitPrefetch = 2,
    PeriodicPrefetch = 3,
    StaleRefill = 4,
    Unknown = u8::MAX,
}

impl RefreshSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Demand => "demand",
            Self::CacheHitPrefetch => "cache-hit-prefetch",
            Self::PeriodicPrefetch => "periodic-prefetch",
            Self::StaleRefill => "stale-refill",
            Self::Unknown => "unknown",
        }
    }

    fn from_raw(raw: u8) -> Self {
        match raw {
            value if value == Self::Demand as u8 => Self::Demand,
            value if value == Self::CacheHitPrefetch as u8 => Self::CacheHitPrefetch,
            value if value == Self::PeriodicPrefetch as u8 => Self::PeriodicPrefetch,
            value if value == Self::StaleRefill as u8 => Self::StaleRefill,
            _ => Self::Unknown,
        }
    }
}

pub(crate) struct RefreshState {
    source: AtomicU8,
    completed: Notify,
}

impl RefreshState {
    const IDLE: u8 = 0;

    pub(crate) fn new() -> Self {
        Self {
            source: AtomicU8::new(Self::IDLE),
            completed: Notify::new(),
        }
    }

    pub(crate) fn try_start(&self, source: RefreshSource) -> Result<(), RefreshSource> {
        debug_assert_ne!(source, RefreshSource::Unknown);
        self.source
            .compare_exchange(
                Self::IDLE,
                source as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(RefreshSource::from_raw)
    }

    pub(crate) fn finish(&self) {
        self.source.store(Self::IDLE, Ordering::Release);
        self.completed.notify_waiters();
    }

    pub(crate) async fn wait_for_completion(&self) {
        // Subscribe before checking ownership so completion cannot be missed.
        let completed = self.completed.notified();
        if self.source.load(Ordering::Acquire) != Self::IDLE {
            completed.await;
        }
    }

    #[cfg(test)]
    fn active_source(&self) -> Option<RefreshSource> {
        match self.source.load(Ordering::Acquire) {
            Self::IDLE => None,
            raw => Some(RefreshSource::from_raw(raw)),
        }
    }
}

impl CachedEntry {
    /// Builds an entry with placeholder `inserted_at`, `expires_at`,
    /// `original_ttl_secs` and `refresh_state`. The cache owns those four
    /// fields and `DnsCache::insert` / `insert_neg` overwrite them when the
    /// entry lands in the cache.
    pub fn scaffold(message: Message, provider: String) -> Self {
        let now = Instant::now();
        Self {
            message,
            inserted_at: now,
            expires_at: now,
            provider,
            original_ttl_secs: 0,
            refresh_state: Arc::new(RefreshState::new()),
            last_used_secs: Arc::new(AtomicU64::new(cache_clock_secs())),
            rotation_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn mark_used(&self) {
        self.last_used_secs
            .store(cache_clock_secs(), Ordering::Relaxed);
    }

    pub fn last_used_age_secs(&self) -> u64 {
        cache_clock_secs().saturating_sub(self.last_used_secs.load(Ordering::Relaxed))
    }

    pub fn preserve_usage_from(&mut self, old: &CachedEntry) {
        self.last_used_secs = old.last_used_secs.clone();
    }
}

pub struct DnsCache {
    inner: Cache<CacheKey, CachedEntry>,
    nxdomain_apex: Cache<String, NxdomainApexEntry>,
    write_locks: Box<[Mutex<()>]>,
    /// Monotonic counter bumped by every full invalidation (`clear`).
    ///
    /// An upstream lookup captures this before it starts and presents it back
    /// at commit time. A flush or network change that happened meanwhile
    /// advances the counter, so the in-flight answer, which describes the
    /// pre-flush network, is dropped instead of repopulating the cache.
    cache_epoch: AtomicU64,
    /// Orders conditional commits against full invalidation. Epoch checks alone
    /// cannot protect the awaited moka insertion that follows the check.
    commit_gate: RwLock<()>,
}

#[derive(Clone)]
struct NxdomainApexEntry {
    expires_at: Instant,
    /// Authority section captured from the upstream NXDOMAIN: the SOA that
    /// bounds the denial plus any NSEC/NSEC3/RRSIG proving it. Replayed
    /// verbatim by the RFC 8020 synthesis so a descendant answer carries the
    /// same proof the original response did instead of a fabricated SOA.
    authorities: Arc<[Record]>,
}

/// What a covering NXDOMAIN apex entry can prove about a descendant name.
pub struct NxdomainApexCoverage {
    pub remaining_ttl_secs: u32,
    pub authorities: Arc<[Record]>,
}

impl DnsCache {
    pub fn new(max_capacity: u64) -> Self {
        // moka's time_to_live is fixed at builder time and is decoupled
        // from per-entry `expires_at`. It serves only as a final
        // memory-safety bound.
        Self {
            inner: Cache::builder()
                .max_capacity(max_capacity)
                .weigher(|_k: &CacheKey, v: &CachedEntry| {
                    // `to_bytes()` runs once per insert/update, amortized by
                    // moka's write queue.
                    v.message.to_bytes().map(|b| b.len() as u32).unwrap_or(512)
                })
                // 7-day ceiling: per-entry `expires_at` enforces the effective
                // TTL, so this is just a memory-safety bound.
                .time_to_live(Duration::from_secs(7 * 24 * 3600))
                .build(),
            // NXDOMAIN-apex tracker stays entry-count-bounded (4096)
            // instead of byte-weighted like `inner`. Each entry is a
            // short lowercase owner name, an `Instant` and at most
            // NXDOMAIN_APEX_MAX_PROOF_RECORDS denial-proof records, and
            // every entry expires within NEG_MAX_TTL_SECS. The record
            // cap is what keeps the total bounded, so running each
            // insert through a weigher would add a hash + allocation
            // for no practical cap gain.
            nxdomain_apex: Cache::builder()
                .max_capacity(4096)
                .time_to_live(Duration::from_secs(NEG_MAX_TTL_SECS as u64))
                .build(),
            write_locks: (0..WRITE_LOCK_STRIPES)
                .map(|_| Mutex::new(()))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            cache_epoch: AtomicU64::new(0),
            commit_gate: RwLock::new(()),
        }
    }

    pub fn capture_epoch(&self) -> u64 {
        self.cache_epoch.load(Ordering::Acquire)
    }

    fn epoch_is_current(&self, expected: u64) -> bool {
        self.capture_epoch() == expected
    }

    /// Commits a positive answer only if no full invalidation happened since
    /// `expected` was captured. Returns the stored entry's refresh state,
    /// which identifies that entry for a later `replace_refined_if_epoch`,
    /// or `None` when nothing was stored.
    pub(crate) async fn insert_if_epoch(
        &self,
        expected: u64,
        key: CacheKey,
        entry: CachedEntry,
        ttl_secs: u32,
    ) -> Option<Arc<RefreshState>> {
        let _commit_guard = self.commit_gate.read().await;
        if !self.epoch_is_current(expected) {
            return None;
        }
        self.insert_returning_state(key, entry, ttl_secs).await
    }

    /// Replaces the payload of a live entry with a refined answer without
    /// extending that entry's expiry. `background_refine` can land well after
    /// the answer it improves (ICMP probing alone is budgeted at 3s), so going
    /// through `insert` would restamp `inserted_at` / `expires_at` and silently
    /// extend the cached lifetime past the TTL the authority published.
    ///
    /// The expiry can only move earlier: providers hand out whatever remains
    /// of their own cached copy, so a refined winner may carry a shorter TTL
    /// than the first answer. When it does, the entry's clock restarts now
    /// with that TTL, so the decremented wire TTLs and the entry's lifetime
    /// stay consistent. Otherwise the original stamps are kept and the refined
    /// record TTLs are capped to the entry's original TTL so the decremented
    /// wire TTLs handed to clients cannot outlive the entry either.
    ///
    /// Does nothing when the entry is gone, already expired, replaced by a
    /// later insert (its refresh state no longer matches the one the
    /// originating lookup stored), or when a full invalidation happened since
    /// `expected` was captured. A refinement must improve the live entry it
    /// came from, never resurrect one or overwrite a newer answer. A refined
    /// answer whose own TTL is 0 is refused outright (RFC 2181 §8) rather
    /// than cached under the old expiry.
    pub(crate) async fn replace_refined_if_epoch(
        &self,
        expected: u64,
        key: &CacheKey,
        message: Message,
        provider: String,
        refined_ttl_secs: u32,
        expected_refresh_state: &Arc<RefreshState>,
    ) -> bool {
        let refined_ttl_secs = clamp_ttl(refined_ttl_secs);
        if refined_ttl_secs == 0 {
            return false;
        }
        let _commit_guard = self.commit_gate.read().await;
        if !self.epoch_is_current(expected) {
            return false;
        }
        let _guard = self.stripe_for(key).lock().await;
        let Some(old) = self.inner.get(key).await else {
            return false;
        };
        if !Arc::ptr_eq(&old.refresh_state, expected_refresh_state) {
            return false;
        }
        let now = Instant::now();
        if old.expires_at <= now {
            return false;
        }
        let mut entry = old.clone();
        entry.message = message;
        entry.provider = provider;
        let remaining_secs = old.expires_at.saturating_duration_since(now).as_secs();
        if u64::from(refined_ttl_secs) < remaining_secs {
            entry.inserted_at = now;
            entry.expires_at = now + Duration::from_secs(u64::from(refined_ttl_secs));
            entry.original_ttl_secs = refined_ttl_secs;
            cap_message_ttls(&mut entry.message, refined_ttl_secs);
        } else {
            cap_message_ttls(&mut entry.message, old.original_ttl_secs);
        }
        self.inner.insert(key.clone(), entry).await;
        true
    }

    /// Negative-answer counterpart of `insert_if_epoch`.
    pub async fn insert_neg_if_epoch(
        &self,
        expected: u64,
        key: CacheKey,
        entry: CachedEntry,
        ttl_secs: u32,
    ) -> bool {
        let _commit_guard = self.commit_gate.read().await;
        if !self.epoch_is_current(expected) {
            return false;
        }
        self.insert_neg(key, entry, ttl_secs).await
    }

    /// RFC 8020 apex counterpart of `insert_if_epoch`.
    pub async fn insert_nxdomain_apex_if_epoch(
        &self,
        expected: u64,
        apex: &str,
        ttl_secs: u32,
        authorities: &[Record],
    ) -> bool {
        let _commit_guard = self.commit_gate.read().await;
        if !self.epoch_is_current(expected) {
            return false;
        }
        self.insert_nxdomain_apex_with_ttl(apex, ttl_secs, authorities)
            .await
    }

    fn stripe_for(&self, key: &CacheKey) -> &Mutex<()> {
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        &self.write_locks[(h.finish() as usize) % WRITE_LOCK_STRIPES]
    }

    pub async fn get(&self, key: &CacheKey) -> Option<CachedEntry> {
        let entry = self.inner.get(key).await?;
        if entry.expires_at <= Instant::now() {
            // Keep the entry in moka. `get_allow_expired` may still want to
            // serve it under RFC 8767. Moka's own `time_to_live` ceiling and
            // `get_allow_expired`'s grace-window check together bound how
            // long a stale entry can linger.
            return None;
        }
        entry.mark_used();
        Some(entry)
    }

    /// RFC 8767 serve-expired fallback. Returns the entry even if it is
    /// past `expires_at`, as long as it is within `SERVE_EXPIRED_TTL_SECS`
    /// of that expiry. The caller is responsible for (a) zeroing TTL on
    /// the response so downstream resolvers do not extend the staleness
    /// window, and (b) scheduling a background refill. Entries beyond the
    /// grace window are evicted synchronously so the next call sees a
    /// clean miss instead of an ever-older stale answer.
    pub async fn get_allow_expired(&self, key: &CacheKey) -> Option<CachedEntry> {
        let entry = self.inner.get(key).await?;
        let now = Instant::now();
        if entry.expires_at > now {
            entry.mark_used();
            return Some(entry);
        }
        let stale_for = now.saturating_duration_since(entry.expires_at);
        if stale_for.as_secs() > SERVE_EXPIRED_TTL_SECS {
            self.inner.invalidate(key).await;
            return None;
        }
        entry.mark_used();
        Some(entry)
    }

    /// Stores a positive answer for `min(ttl_secs, MAX_TTL_SECS)` seconds.
    /// Returns `false` without touching the cache when the effective TTL is
    /// 0. RFC 2181 §8 makes a zero TTL "use once, never cache", and an
    /// answer-less positive response has no RRset worth keeping.
    pub async fn insert(&self, key: CacheKey, entry: CachedEntry, ttl_secs: u32) -> bool {
        self.insert_returning_state(key, entry, ttl_secs)
            .await
            .is_some()
    }

    /// `insert` that also hands back the refresh state installed on the
    /// stored entry. Every insert installs a fresh one, so it identifies this
    /// exact entry. A later refinement presents it to prove it is still
    /// improving the answer it came from.
    pub(crate) async fn insert_returning_state(
        &self,
        key: CacheKey,
        mut entry: CachedEntry,
        ttl_secs: u32,
    ) -> Option<Arc<RefreshState>> {
        let clamped = clamp_ttl(ttl_secs);
        if clamped == 0 {
            return None;
        }
        let _guard = self.stripe_for(&key).lock().await;
        let ttl = Duration::from_secs(clamped as u64);
        let now = Instant::now();
        entry.inserted_at = now;
        entry.expires_at = now + ttl;
        entry.original_ttl_secs = clamped;
        // Fresh state per insert. A prefetch that might have been in flight
        // is irrelevant because this overwrote the entry. Reusing an active
        // state would make the next near-expiry hit skip refill. A new one
        // resets ownership and source together.
        let refresh_state = Arc::new(RefreshState::new());
        entry.refresh_state = refresh_state.clone();
        self.inner.insert(key, entry).await;
        Some(refresh_state)
    }

    /// Restore a snapshot entry without extending its fresh or stale lifetime.
    #[cfg(test)]
    pub async fn insert_restored(&self, key: CacheKey, entry: CachedEntry, ttl_secs: u32) {
        self.insert_restored_aged(key, entry, ttl_secs, 0, Instant::now())
            .await;
    }

    pub(crate) async fn insert_restored_aged(
        &self,
        key: CacheKey,
        mut entry: CachedEntry,
        ttl_secs: u32,
        elapsed_secs: u64,
        observed_at: Instant,
    ) -> bool {
        if ttl_secs == 0 {
            return false;
        }
        let ttl_secs = ttl_secs.min(MAX_TTL_SECS);
        let stale_secs = elapsed_secs.saturating_sub(u64::from(ttl_secs));
        if stale_secs > SERVE_EXPIRED_TTL_SECS {
            return false;
        }
        let Some(inserted_at) = observed_at.checked_sub(Duration::from_secs(elapsed_secs)) else {
            return false;
        };
        let Some(expires_at) = inserted_at.checked_add(Duration::from_secs(u64::from(ttl_secs)))
        else {
            return false;
        };
        let _guard = self.stripe_for(&key).lock().await;
        cap_message_ttls(&mut entry.message, ttl_secs);
        entry.inserted_at = inserted_at;
        entry.expires_at = expires_at;
        entry.original_ttl_secs = ttl_secs;
        entry.refresh_state = Arc::new(RefreshState::new());
        self.inner.insert(key, entry).await;
        true
    }

    pub(crate) async fn insert_prefetch_if_current(
        &self,
        key: CacheKey,
        entry: CachedEntry,
        ttl_secs: u32,
        expected_refresh_state: &Arc<RefreshState>,
    ) -> bool {
        self.insert_prefetch_returning_state(key, entry, ttl_secs, expected_refresh_state)
            .await
            .is_some()
    }

    /// `insert_prefetch_if_current` that hands back the refresh state
    /// installed on the new entry, which identifies it for a later
    /// refinement, or `None` when nothing was stored.
    pub(crate) async fn insert_prefetch_returning_state(
        &self,
        key: CacheKey,
        mut entry: CachedEntry,
        ttl_secs: u32,
        expected_refresh_state: &Arc<RefreshState>,
    ) -> Option<Arc<RefreshState>> {
        let _commit_guard = self.commit_gate.read().await;
        let _guard = self.stripe_for(&key).lock().await;
        let old = self.inner.get(&key).await?;
        // An `Arc::ptr_eq` mismatch means the entry was replaced by a full
        // `insert` since prefetch started (every insert path installs a
        // fresh `refresh_state` cell), so writing now would overwrite
        // fresher data.
        if !Arc::ptr_eq(&old.refresh_state, expected_refresh_state) {
            return None;
        }
        entry.preserve_usage_from(&old);
        let clamped = clamp_ttl(ttl_secs);
        // A refill that came back with TTL 0 must not be cached; leave the
        // existing entry to expire on its own schedule.
        if clamped == 0 {
            return None;
        }
        let ttl = Duration::from_secs(clamped as u64);
        let now = Instant::now();
        entry.inserted_at = now;
        entry.expires_at = now + ttl;
        entry.original_ttl_secs = clamped;
        let refresh_state = Arc::new(RefreshState::new());
        entry.refresh_state = refresh_state.clone();
        self.inner.insert(key, entry).await;
        Some(refresh_state)
    }

    /// Drops the entry under `key` only while it is still the one identified
    /// by `expected_refresh_state`. A refill that learned the name is gone but
    /// has no cacheable negative to store uses this so the withdrawn answer is
    /// not served until it expires, or served stale after that.
    pub(crate) async fn invalidate_if_current(
        &self,
        key: &CacheKey,
        expected_refresh_state: &Arc<RefreshState>,
    ) -> bool {
        let _guard = self.stripe_for(key).lock().await;
        let Some(old) = self.inner.get(key).await else {
            return false;
        };
        if !Arc::ptr_eq(&old.refresh_state, expected_refresh_state) {
            return false;
        }
        self.inner.invalidate(key).await;
        true
    }

    /// Negative-response variant of `insert`. Clamps to `[NEG_MIN_TTL_SECS,
    /// NEG_MAX_TTL_SECS]` instead of the positive bounds so NXDOMAIN / NODATA
    /// answers expire on a separate curve.
    ///
    /// Returns `false` without touching the cache when the effective negative
    /// TTL is 0, mirroring `insert`. RFC 2308 §5 forbids reusing a negative
    /// answer once its TTL reaches zero, and clamping such an answer up to
    /// `NEG_MIN_TTL_SECS` would keep a dynamic name negative for a second the
    /// authority explicitly refused to grant.
    pub async fn insert_neg(&self, key: CacheKey, mut entry: CachedEntry, ttl_secs: u32) -> bool {
        if ttl_secs == 0 {
            return false;
        }
        let _guard = self.stripe_for(&key).lock().await;
        let clamped = clamp_neg_ttl(ttl_secs);
        let ttl = Duration::from_secs(clamped as u64);
        let now = Instant::now();
        entry.inserted_at = now;
        entry.expires_at = now + ttl;
        entry.original_ttl_secs = clamped;
        entry.refresh_state = Arc::new(RefreshState::new());
        self.inner.insert(key, entry).await;
        true
    }

    /// RFC 8020 `harden-below-nxdomain` support: tracks zone apexes known
    /// to be NXDOMAIN so sub-names can be answered without hitting
    /// upstream. Keyed on the lower-cased apex with trailing dot stripped
    /// to match `CacheKey::from` normalization.
    ///
    /// `authorities` is the negative authority section of the response that
    /// established the cut. `retain_denial_proof` keeps the bounded, whole-set
    /// part of it. Returns `false` without touching the tracker when the TTL
    /// is 0 (RFC 2308 §5, same rule as `insert_neg`) or when
    /// `retain_denial_proof` cannot keep a coherent proof: no SOA to bound the
    /// denial, or a DNSSEC denial whose NSEC/NSEC3 records did not fit the
    /// record budget whole. A cut nothing can justify must not deny names on
    /// its own.
    ///
    /// TTL is stored verbatim. The ceiling is enforced by moka's builder
    /// `time_to_live(NEG_MAX_TTL_SECS)`, and skipping `clamp_neg_ttl` keeps
    /// the tracker honest for short-SOA-minimum answers.
    pub async fn insert_nxdomain_apex_with_ttl(
        &self,
        apex: &str,
        ttl_secs: u32,
        authorities: &[Record],
    ) -> bool {
        if ttl_secs == 0 {
            return false;
        }
        let Some(proof) = retain_denial_proof(authorities) else {
            return false;
        };
        let key = apex.trim_end_matches('.').to_lowercase();
        let entry = NxdomainApexEntry {
            expires_at: Instant::now() + Duration::from_secs(u64::from(ttl_secs)),
            authorities: proof,
        };
        self.nxdomain_apex.insert(key, entry).await;
        true
    }

    /// Returns true when a cached NXDOMAIN apex strictly covers `name`.
    /// Matching is label-aligned: `b.c.example.` is covered by
    /// `example.` only if the trailing labels line up exactly. Reverse-
    /// zone or confusingly-suffixed names never match by accident.
    pub async fn nxdomain_apex_covers(&self, name: &str) -> bool {
        self.nxdomain_apex_coverage(name).await.is_some()
    }

    /// Mirror of `nxdomain_apex_covers` that also surfaces the remaining TTL
    /// and the retained denial proof of the covering apex entry. Used by the
    /// RFC 8020 synthesis path so a descendant answer carries the original
    /// authority section aged down to what is left of it, instead of a
    /// fabricated SOA that no validator can check.
    pub async fn nxdomain_apex_coverage(&self, name: &str) -> Option<NxdomainApexCoverage> {
        let n = name.trim_end_matches('.').to_lowercase();
        let now = Instant::now();
        let dot = n.find('.')?;
        let mut cur = &n[dot + 1..];
        loop {
            if let Some(entry) = self.nxdomain_apex.get(cur).await {
                if entry.expires_at > now {
                    let remaining = entry
                        .expires_at
                        .saturating_duration_since(now)
                        .as_secs()
                        .max(1);
                    return Some(NxdomainApexCoverage {
                        remaining_ttl_secs: remaining.min(u32::MAX as u64) as u32,
                        authorities: entry.authorities.clone(),
                    });
                }
                self.nxdomain_apex.invalidate(cur).await;
            }
            match cur.find('.') {
                Some(i) => cur = &cur[i + 1..],
                None => return None,
            }
        }
    }

    pub async fn clear(&self) {
        {
            let _commit_guard = self.commit_gate.write().await;
            // Advance first: any upstream lookup already in flight captured the
            // previous epoch and must be refused at commit time, otherwise it
            // would repopulate the cache we are clearing.
            self.cache_epoch.fetch_add(1, Ordering::AcqRel);
            self.inner.invalidate_all();
            self.nxdomain_apex.invalidate_all();
        }
        // Draining moka's queues needs no exclusivity. The epoch bump above
        // already fences every in-flight commit, so a concurrent insert can
        // only be one that captured the new epoch and belongs in the cache.
        self.inner.run_pending_tasks().await;
        self.nxdomain_apex.run_pending_tasks().await;
    }

    /// Drain moka's pending write queue so a subsequent `iter()` reflects
    /// the logical cache state. Snapshot callers must flush first because
    /// `iter()` reads the main hash table directly, so entries inserted or
    /// invalidated moments earlier can otherwise be missing from (or
    /// resurrected into) the dump.
    pub async fn flush_pending(&self) {
        self.inner.run_pending_tasks().await;
    }

    /// Used by `cache_persist` at snapshot time. moka's future variant
    /// exposes a non-consuming iterator that is cheap to call and does not
    /// block concurrent lookups.
    pub fn iter(&self) -> moka::future::Iter<'_, CacheKey, CachedEntry> {
        self.inner.iter()
    }

    /// Insert an entry without re-clamping or overwriting `expires_at`.
    /// Tests use this to install deliberately-expired entries; production
    /// code must go through `insert` / `insert_neg` so TTL bounds are
    /// always enforced.
    #[cfg(test)]
    pub async fn inner_insert_raw(&self, key: CacheKey, entry: CachedEntry) {
        self.inner.insert(key, entry).await;
    }

    /// Installs an RFC 8020 cut at `apex` with a minimal SOA as its proof.
    /// Test-only. Production callers must hand over the authority section of
    /// the response that actually denied the name, so a cut can never outlive
    /// the proof that justified it.
    #[cfg(test)]
    pub async fn insert_nxdomain_apex(&self, apex: &str) {
        use hickory_proto::rr::rdata::SOA;
        use hickory_proto::rr::{Name, RData};

        let owner = Name::from_ascii(apex).expect("test apex must parse as a name");
        let soa = SOA::new(
            Name::from_ascii("ns.invalid.").unwrap(),
            Name::from_ascii("nobody.invalid.").unwrap(),
            1,
            3600,
            600,
            604800,
            NEG_MAX_TTL_SECS,
        );
        let proof = [Record::from_rdata(owner, NEG_MAX_TTL_SECS, RData::SOA(soa))];
        assert!(
            self.insert_nxdomain_apex_with_ttl(apex, NEG_MAX_TTL_SECS, &proof)
                .await
        );
    }
}

pub fn clamp_ttl(ttl: u32) -> u32 {
    ttl.min(MAX_TTL_SECS)
}

pub fn clamp_neg_ttl(ttl: u32) -> u32 {
    ttl.clamp(NEG_MIN_TTL_SECS, NEG_MAX_TTL_SECS)
}

pub(crate) fn cap_message_ttls(msg: &mut Message, max_ttl_secs: u32) {
    for rec in &mut msg.answers {
        rec.ttl = rec.ttl.min(max_ttl_secs);
    }
    for rec in &mut msg.authorities {
        rec.ttl = rec.ttl.min(max_ttl_secs);
    }
    for rec in &mut msg.additionals {
        rec.ttl = rec.ttl.min(max_ttl_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn restore_processing_gap_does_not_extend_lifetime() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("restore-gap.example", RecordType::A);
        let observed_at = Instant::now() - Duration::from_secs(10);
        assert!(
            cache
                .insert_restored_aged(
                    key.clone(),
                    CachedEntry::scaffold(Message::query(), "test".into()),
                    1,
                    0,
                    observed_at,
                )
                .await
        );
        assert!(cache.get(&key).await.is_none());
        let stale = cache.get_allow_expired(&key).await.unwrap();
        assert_eq!(stale.expires_at, observed_at + Duration::from_secs(1));
        assert!(Instant::now().duration_since(stale.expires_at) >= Duration::from_secs(9));
    }
    use hickory_proto::rr::rdata::SOA;
    use hickory_proto::rr::{Name, RData};

    /// Minimal negative authority section: one SOA owned by `zone`, the shape
    /// every cacheable negative answer must carry.
    fn soa_proof(zone: &str, ttl: u32) -> Vec<Record> {
        let soa = SOA::new(
            Name::from_ascii("ns.invalid.").unwrap(),
            Name::from_ascii("nobody.invalid.").unwrap(),
            1,
            3600,
            600,
            604800,
            ttl,
        );
        vec![Record::from_rdata(
            Name::from_ascii(zone).unwrap(),
            ttl,
            RData::SOA(soa),
        )]
    }

    /// A wire-shaped `RRSIG` whose `type_covered` is readable, so proof
    /// grouping can pair it with the RRset it signs. `key_tag` only keeps
    /// sibling signatures distinguishable.
    fn rrsig_over(owner: &Name, covered: RecordType, key_tag: u16) -> Record {
        use hickory_proto::dnssec::rdata::{SigInput, RRSIG};
        use hickory_proto::dnssec::Algorithm;
        use hickory_proto::rr::SerialNumber;

        let input = SigInput {
            type_covered: covered,
            algorithm: Algorithm::ECDSAP256SHA256,
            num_labels: owner.num_labels(),
            original_ttl: NEG_MAX_TTL_SECS,
            sig_expiration: SerialNumber::from(0),
            sig_inception: SerialNumber::from(0),
            key_tag,
            signer_name: Name::root(),
        };
        Record::from_rdata(
            owner.clone(),
            NEG_MAX_TTL_SECS,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![]))),
        )
    }

    fn covers_soa(rec: &Record) -> bool {
        rrsig_type_covered(rec) == Some(RecordType::SOA)
    }

    #[test]
    fn refresh_state_preserves_owner_source_until_finish() {
        let state = RefreshState::new();

        assert_eq!(state.try_start(RefreshSource::PeriodicPrefetch), Ok(()));
        assert_eq!(
            state.try_start(RefreshSource::Demand),
            Err(RefreshSource::PeriodicPrefetch)
        );
        assert_eq!(state.active_source(), Some(RefreshSource::PeriodicPrefetch));

        state.finish();
        assert_eq!(state.active_source(), None);
        assert_eq!(state.try_start(RefreshSource::Demand), Ok(()));
    }

    #[test]
    fn refresh_source_log_labels_are_stable() {
        assert_eq!(RefreshSource::Demand.as_str(), "demand");
        assert_eq!(
            RefreshSource::CacheHitPrefetch.as_str(),
            "cache-hit-prefetch"
        );
        assert_eq!(
            RefreshSource::PeriodicPrefetch.as_str(),
            "periodic-prefetch"
        );
        assert_eq!(RefreshSource::StaleRefill.as_str(), "stale-refill");
    }

    #[test]
    fn clamp_respects_short_positive_ttl() {
        assert_eq!(clamp_ttl(5), 5);
        assert_eq!(clamp_ttl(1), 1);
        assert_eq!(clamp_ttl(0), 0);
    }
    #[test]
    fn clamp_above_max() {
        assert_eq!(clamp_ttl(u32::MAX), MAX_TTL_SECS);
    }
    #[test]
    fn clamp_within() {
        assert_eq!(clamp_ttl(3600), 3600);
    }

    #[test]
    fn neg_clamp_below_min() {
        assert_eq!(clamp_neg_ttl(0), NEG_MIN_TTL_SECS);
    }
    #[test]
    fn neg_clamp_above_max() {
        assert_eq!(clamp_neg_ttl(u32::MAX), NEG_MAX_TTL_SECS);
    }
    #[test]
    fn neg_clamp_respects_short_upstream_ttl() {
        assert_eq!(clamp_neg_ttl(3), 3);
    }

    #[tokio::test]
    async fn stale_positive_insert_is_rejected_after_clear() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("example.com", RecordType::A);
        let epoch = cache.capture_epoch();

        cache.clear().await;

        let entry = CachedEntry::scaffold(Message::query(), "test".into());
        assert!(cache
            .insert_if_epoch(epoch, key.clone(), entry, 60)
            .await
            .is_none());
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn clear_cannot_finish_between_epoch_check_and_positive_insert() {
        let cache = Arc::new(DnsCache::new(1_048_576));
        let key = CacheKey::from("racing.example", RecordType::A);
        let epoch = cache.capture_epoch();
        let stripe_guard = cache.stripe_for(&key).lock().await;

        let insert_cache = cache.clone();
        let insert_key = key.clone();
        let insert = tokio::spawn(async move {
            insert_cache
                .insert_if_epoch(
                    epoch,
                    insert_key,
                    CachedEntry::scaffold(Message::query(), "test".into()),
                    60,
                )
                .await
        });
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }

        let clear_cache = cache.clone();
        let clear = tokio::spawn(async move {
            clear_cache.clear().await;
        });
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }

        drop(stripe_guard);
        assert!(insert.await.unwrap().is_some());
        clear.await.unwrap();

        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn stale_negative_insert_is_rejected_after_clear() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("missing.example", RecordType::A);
        let epoch = cache.capture_epoch();

        cache.clear().await;

        let entry = CachedEntry::scaffold(Message::query(), "test".into());
        assert!(
            !cache
                .insert_neg_if_epoch(epoch, key.clone(), entry, 60)
                .await
        );
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn stale_nxdomain_apex_is_rejected_after_clear() {
        let cache = DnsCache::new(1_048_576);
        let epoch = cache.capture_epoch();

        cache.clear().await;

        assert!(
            !cache
                .insert_nxdomain_apex_if_epoch(
                    epoch,
                    "example.com",
                    60,
                    &soa_proof("example.com.", 60)
                )
                .await
        );
        assert!(!cache.nxdomain_apex_covers("child.example.com").await);
    }

    #[tokio::test]
    async fn fresh_epoch_insert_succeeds_after_clear() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("example.com", RecordType::A);

        cache.clear().await;

        let epoch = cache.capture_epoch();
        let entry = CachedEntry::scaffold(Message::query(), "test".into());
        assert!(cache
            .insert_if_epoch(epoch, key.clone(), entry, 60)
            .await
            .is_some());
        assert!(cache.get(&key).await.is_some());
    }

    #[tokio::test]
    async fn neg_entry_visible_within_neg_ttl() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("missing.example", RecordType::A);
        let entry = CachedEntry::scaffold(Message::query(), "test".into());
        cache.insert_neg(key.clone(), entry, 60).await;
        assert!(cache.get(&key).await.is_some());
    }

    #[tokio::test]
    async fn entry_expires_after_ttl() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("example.com", RecordType::A);
        let entry = CachedEntry::scaffold(Message::query(), "test".into());
        // `scaffold` leaves `expires_at` at the current instant, and the direct
        // insert bypasses the TTL bookkeeping so the entry lands expired.
        cache.inner.insert(key.clone(), entry).await;
        assert!(
            cache.get(&key).await.is_none(),
            "expired entry must not be returned"
        );
    }

    #[tokio::test]
    async fn insert_preserves_short_positive_ttl() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("short.example", RecordType::A);
        let entry = CachedEntry::scaffold(Message::query(), "test".into());

        assert!(cache.insert(key.clone(), entry, 5).await);

        let hit = cache.get(&key).await.expect("5s entry must be cached");
        assert_eq!(hit.original_ttl_secs, 5);
        assert_eq!(
            hit.expires_at.saturating_duration_since(hit.inserted_at),
            Duration::from_secs(5),
            "a 5s authoritative TTL must not be extended to a local minimum",
        );
    }

    #[tokio::test]
    async fn short_positive_ttl_entry_expires_on_its_own_ttl() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("failover.example", RecordType::A);
        let entry = CachedEntry::scaffold(Message::query(), "test".into());

        assert!(cache.insert(key.clone(), entry, 1).await);
        tokio::time::sleep(Duration::from_millis(1100)).await;

        assert!(
            cache.get(&key).await.is_none(),
            "a 1s TTL must expire after 1s, not after a local minimum",
        );
    }

    #[tokio::test]
    async fn zero_positive_ttl_is_never_cached() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("nocache.example", RecordType::A);
        let epoch = cache.capture_epoch();
        let entry = CachedEntry::scaffold(Message::query(), "test".into());

        assert!(cache
            .insert_if_epoch(epoch, key.clone(), entry, 0)
            .await
            .is_none());

        assert!(cache.get(&key).await.is_none());
        assert!(
            cache.get_allow_expired(&key).await.is_none(),
            "a TTL 0 answer must not become a serve-expired candidate",
        );
    }

    #[tokio::test]
    async fn zero_ttl_prefetch_refill_leaves_existing_entry_alone() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("refill.example", RecordType::A);
        cache
            .insert(
                key.clone(),
                CachedEntry::scaffold(Message::query(), "old".into()),
                60,
            )
            .await;
        let old = cache.inner.get(&key).await.unwrap();

        assert!(
            !cache
                .insert_prefetch_if_current(
                    key.clone(),
                    CachedEntry::scaffold(Message::query(), "refill".into()),
                    0,
                    &old.refresh_state,
                )
                .await
        );

        assert_eq!(cache.get(&key).await.unwrap().provider, "old");
    }

    #[tokio::test]
    async fn entry_visible_within_ttl() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("example.com", RecordType::A);
        let entry = CachedEntry::scaffold(Message::query(), "test".into());
        cache.insert(key.clone(), entry, 60).await;
        assert!(cache.get(&key).await.is_some());
    }

    #[tokio::test]
    async fn insert_restored_applies_current_max_ttl_ceiling() {
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record};
        use std::str::FromStr;

        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("example.com", RecordType::A);
        let mut msg = Message::query();
        msg.add_answer(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            u32::MAX,
            RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
        ));
        let entry = CachedEntry::scaffold(msg, "restore".into());
        let ceiling = clamp_ttl(u32::MAX);

        cache
            .insert_restored(key.clone(), entry, ceiling.saturating_add(1))
            .await;

        let hit = cache.get(&key).await.expect("restored entry must exist");
        assert_eq!(hit.original_ttl_secs, ceiling);
        assert_eq!(hit.message.answers[0].ttl, ceiling);
    }

    #[tokio::test]
    async fn get_allow_expired_returns_stale_within_grace() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("expired.example", RecordType::A);
        let mut entry = CachedEntry::scaffold(Message::query(), "test".into());
        entry.expires_at = Instant::now() - Duration::from_secs(10);
        cache.inner_insert_raw(key.clone(), entry).await;
        assert!(
            cache.get(&key).await.is_none(),
            "strict get must miss stale"
        );
        assert!(
            cache.get_allow_expired(&key).await.is_some(),
            "serve-expired must surface stale entry inside grace",
        );
    }

    #[tokio::test]
    async fn get_allow_expired_drops_beyond_grace() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("ancient.example", RecordType::A);
        let mut entry = CachedEntry::scaffold(Message::query(), "test".into());
        entry.expires_at = Instant::now() - Duration::from_secs(SERVE_EXPIRED_TTL_SECS + 60);
        cache.inner_insert_raw(key.clone(), entry).await;
        assert!(
            cache.get_allow_expired(&key).await.is_none(),
            "entries beyond grace must not be served",
        );
    }

    #[tokio::test]
    async fn insert_sets_original_ttl_and_fresh_refresh_state() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("example.com", RecordType::A);
        let entry = CachedEntry::scaffold(Message::query(), "test".into());
        cache.insert(key.clone(), entry, 600).await;
        let hit = cache.get(&key).await.unwrap();
        assert_eq!(hit.original_ttl_secs, 600);
        assert_eq!(hit.refresh_state.active_source(), None);
    }

    #[tokio::test]
    async fn get_updates_last_used_without_extending_expiry() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("used.example", RecordType::A);
        let entry = CachedEntry::scaffold(Message::query(), "test".into());
        cache.insert(key.clone(), entry, 600).await;

        let stored = cache.inner.get(&key).await.unwrap();
        let expires_at = stored.expires_at;
        stored
            .last_used_secs
            .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);

        assert!(cache.get(&key).await.is_some());
        let stored = cache.inner.get(&key).await.unwrap();
        assert_eq!(stored.expires_at, expires_at);
        assert_ne!(
            stored
                .last_used_secs
                .load(std::sync::atomic::Ordering::Relaxed),
            u64::MAX,
        );
    }

    fn a_answer(name: &str, ttl: u32, last: u8) -> Message {
        let mut message = Message::query();
        message.add_answer(Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            ttl,
            RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                192, 0, 2, last,
            ))),
        ));
        message
    }

    /// Providers hand out whatever remains of their own cached copy, so a
    /// refined winner can carry a far shorter TTL than the first answer.
    /// Keeping the first answer's expiry would serve the refined records with
    /// TTL 0 for the rest of that window.
    #[tokio::test]
    async fn refined_winner_with_a_shorter_ttl_shortens_the_entry() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("refine-short.example", RecordType::A);
        assert!(
            cache
                .insert(
                    key.clone(),
                    CachedEntry::scaffold(
                        a_answer("refine-short.example.", 300, 1),
                        "first".into()
                    ),
                    300,
                )
                .await
        );
        let epoch = cache.capture_epoch();

        let refresh_state = cache.get(&key).await.unwrap().refresh_state;

        assert!(
            cache
                .replace_refined_if_epoch(
                    epoch,
                    &key,
                    a_answer("refine-short.example.", 5, 2),
                    "refined".into(),
                    5,
                    &refresh_state,
                )
                .await
        );

        let entry = cache.get(&key).await.unwrap();
        assert!(
            entry.expires_at <= Instant::now() + Duration::from_secs(5),
            "the entry must not outlive the refined answer's TTL"
        );
        assert_eq!(entry.original_ttl_secs, 5);
        assert!(entry.message.answers.iter().all(|rec| rec.ttl <= 5));
    }

    /// A refinement improves the entry its own lookup populated. If that
    /// entry expired and a later lookup stored a different answer, the
    /// refinement is stale evidence and must leave the newer answer alone.
    #[tokio::test]
    async fn late_refinement_cannot_overwrite_a_newer_entry() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("refine-stale.example", RecordType::A);
        let first_state = cache
            .insert_returning_state(
                key.clone(),
                CachedEntry::scaffold(a_answer("refine-stale.example.", 60, 1), "first".into()),
                60,
            )
            .await
            .unwrap();
        assert!(
            cache
                .insert(
                    key.clone(),
                    CachedEntry::scaffold(a_answer("refine-stale.example.", 60, 2), "newer".into()),
                    60,
                )
                .await
        );
        let epoch = cache.capture_epoch();

        assert!(
            !cache
                .replace_refined_if_epoch(
                    epoch,
                    &key,
                    a_answer("refine-stale.example.", 60, 3),
                    "stale-refinement".into(),
                    60,
                    &first_state,
                )
                .await
        );

        let entry = cache.get(&key).await.unwrap();
        assert_eq!(entry.provider, "newer");
    }

    #[tokio::test]
    async fn invalidate_if_current_only_drops_the_identified_entry() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("withdraw.example", RecordType::A);
        let first_state = cache
            .insert_returning_state(
                key.clone(),
                CachedEntry::scaffold(a_answer("withdraw.example.", 60, 1), "first".into()),
                60,
            )
            .await
            .unwrap();
        let newer_state = cache
            .insert_returning_state(
                key.clone(),
                CachedEntry::scaffold(a_answer("withdraw.example.", 60, 2), "newer".into()),
                60,
            )
            .await
            .unwrap();

        assert!(!cache.invalidate_if_current(&key, &first_state).await);
        assert_eq!(cache.get(&key).await.unwrap().provider, "newer");

        assert!(cache.invalidate_if_current(&key, &newer_state).await);
        assert!(cache.get_allow_expired(&key).await.is_none());
    }

    #[tokio::test]
    async fn insert_prefetch_if_current_preserves_last_used_and_resets_refresh_state() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("prefetch.example", RecordType::A);
        let entry = CachedEntry::scaffold(Message::query(), "old".into());
        cache.insert(key.clone(), entry, 600).await;

        let old = cache.inner.get(&key).await.unwrap();
        let expected_refresh_state = old.refresh_state.clone();
        old.last_used_secs
            .store(123, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            old.refresh_state.try_start(RefreshSource::CacheHitPrefetch),
            Ok(())
        );

        let fresh = CachedEntry::scaffold(Message::query(), "new".into());
        assert!(
            cache
                .insert_prefetch_if_current(key.clone(), fresh, 300, &expected_refresh_state)
                .await
        );

        let hit = cache.inner.get(&key).await.unwrap();
        assert_eq!(
            hit.last_used_secs
                .load(std::sync::atomic::Ordering::Relaxed),
            123,
        );
        assert_eq!(hit.refresh_state.active_source(), None);
    }

    #[tokio::test]
    async fn clear_is_ordered_after_prefetch_commit_already_in_progress() {
        let cache = Arc::new(DnsCache::new(1_048_576));
        let key = CacheKey::from("prefetch-clear.example", RecordType::A);
        cache
            .insert(
                key.clone(),
                CachedEntry::scaffold(Message::query(), "old".into()),
                600,
            )
            .await;
        let old = cache.inner.get(&key).await.unwrap();
        let expected_refresh_state = old.refresh_state.clone();
        let stripe_guard = cache.stripe_for(&key).lock().await;

        let prefetch_cache = cache.clone();
        let prefetch_key = key.clone();
        let expected_state = expected_refresh_state.clone();
        let prefetch = tokio::spawn(async move {
            prefetch_cache
                .insert_prefetch_if_current(
                    prefetch_key,
                    CachedEntry::scaffold(Message::query(), "prefetch".into()),
                    300,
                    &expected_state,
                )
                .await
        });
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }

        let clear_cache = cache.clone();
        let clear = tokio::spawn(async move {
            clear_cache.clear().await;
        });
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }

        drop(stripe_guard);
        assert!(prefetch.await.unwrap());
        clear.await.unwrap();
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn insert_prefetch_if_current_skips_replaced_entry() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("race.example", RecordType::A);
        let entry = CachedEntry::scaffold(Message::query(), "old".into());
        cache.insert(key.clone(), entry, 600).await;

        let old = cache.inner.get(&key).await.unwrap();
        let expected_refresh_state = old.refresh_state.clone();

        let replacement = CachedEntry::scaffold(Message::query(), "replacement".into());
        cache.insert(key.clone(), replacement, 600).await;

        let stale_prefetch = CachedEntry::scaffold(Message::query(), "prefetch".into());
        assert!(
            !cache
                .insert_prefetch_if_current(
                    key.clone(),
                    stale_prefetch,
                    300,
                    &expected_refresh_state,
                )
                .await
        );
        assert_eq!(cache.inner.get(&key).await.unwrap().provider, "replacement");
    }

    /// Every entry-replacing insert path must install a fresh
    /// `refresh_state` cell, because that pointer identity is the only
    /// thing standing between a late prefetch refill and the fresher entry
    /// it would otherwise overwrite.
    #[tokio::test]
    async fn insert_neg_and_insert_restored_also_defeat_a_late_prefetch() {
        for replace_with_negative in [true, false] {
            let cache = DnsCache::new(1_048_576);
            let key = CacheKey::from("late.example", RecordType::A);
            cache
                .insert(
                    key.clone(),
                    CachedEntry::scaffold(Message::query(), "old".into()),
                    600,
                )
                .await;
            let expected_refresh_state = cache.inner.get(&key).await.unwrap().refresh_state.clone();

            let replacement = CachedEntry::scaffold(Message::query(), "replacement".into());
            if replace_with_negative {
                cache.insert_neg(key.clone(), replacement, 5).await;
            } else {
                cache.insert_restored(key.clone(), replacement, 600).await;
            }

            assert!(
                !cache
                    .insert_prefetch_if_current(
                        key.clone(),
                        CachedEntry::scaffold(Message::query(), "prefetch".into()),
                        300,
                        &expected_refresh_state,
                    )
                    .await,
                "late prefetch must lose to a replacement (negative={})",
                replace_with_negative,
            );
            assert_eq!(cache.inner.get(&key).await.unwrap().provider, "replacement");
        }
    }

    #[tokio::test]
    async fn nxdomain_apex_covers_subname() {
        let cache = DnsCache::new(1_048_576);
        cache.insert_nxdomain_apex("gone.example.").await;
        assert!(cache.nxdomain_apex_covers("foo.gone.example.").await);
        assert!(cache.nxdomain_apex_covers("a.b.gone.example.").await);
        assert!(!cache.nxdomain_apex_covers("other.example.").await);
        assert!(!cache.nxdomain_apex_covers("gone.example.other.").await);
    }

    #[tokio::test]
    async fn nxdomain_apex_expires() {
        let cache = DnsCache::new(1_048_576);
        cache
            .insert_nxdomain_apex_with_ttl(
                "fleeting.example.",
                1,
                &soa_proof("fleeting.example.", 1),
            )
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert!(!cache.nxdomain_apex_covers("x.fleeting.example.").await);
    }

    #[tokio::test]
    async fn nxdomain_apex_coverage_decreases_over_time() {
        let cache = DnsCache::new(1_048_576);
        cache
            .insert_nxdomain_apex_with_ttl(
                "gone.example.",
                NEG_MAX_TTL_SECS,
                &soa_proof("gone.example.", NEG_MAX_TTL_SECS),
            )
            .await;

        let coverage = cache
            .nxdomain_apex_coverage("x.gone.example.")
            .await
            .expect("remaining TTL must be reported for a covered name");
        assert_eq!(coverage.authorities.len(), 1);
        assert!(
            (NEG_MAX_TTL_SECS - 1..=NEG_MAX_TTL_SECS).contains(&coverage.remaining_ttl_secs),
            "got {}",
            coverage.remaining_ttl_secs
        );

        // Names not covered by any apex must report nothing.
        assert!(cache.nxdomain_apex_coverage("x.other.").await.is_none());
    }

    #[tokio::test]
    async fn nxdomain_apex_coverage_floors_live_subsecond_to_one() {
        let cache = DnsCache::new(1_048_576);
        cache
            .insert_nxdomain_apex_with_ttl("brief.example.", 1, &soa_proof("brief.example.", 1))
            .await;

        let coverage = cache
            .nxdomain_apex_coverage("x.brief.example.")
            .await
            .expect("brief apex should still be live immediately after insert");

        assert_eq!(coverage.remaining_ttl_secs, 1);
    }

    /// RFC 2308 §5: a negative answer whose TTL reached zero must not be
    /// reused. Clamping it up to the negative floor would keep a dynamic name
    /// negative after the authority refused to grant any reuse at all.
    #[tokio::test]
    async fn zero_negative_ttl_is_never_cached() {
        let cache = DnsCache::new(1_048_576);
        let key = CacheKey::from("dynamic.example", RecordType::A);
        let entry = CachedEntry::scaffold(Message::query(), "test".into());

        assert!(!cache.insert_neg(key.clone(), entry, 0).await);

        assert!(cache.get(&key).await.is_none());
        assert!(
            cache.get_allow_expired(&key).await.is_none(),
            "a TTL 0 negative answer must not become a serve-expired candidate",
        );
    }

    #[tokio::test]
    async fn zero_ttl_nxdomain_apex_cut_is_never_installed() {
        let cache = DnsCache::new(1_048_576);

        assert!(
            !cache
                .insert_nxdomain_apex_with_ttl("gone.example.", 0, &soa_proof("gone.example.", 0))
                .await
        );

        assert!(!cache.nxdomain_apex_covers("x.gone.example.").await);
    }

    /// An RFC 8020 cut denies every descendant of a name without asking
    /// upstream, so it may only exist while the proof that justified it does.
    #[tokio::test]
    async fn nxdomain_apex_cut_without_denial_proof_is_refused() {
        let cache = DnsCache::new(1_048_576);

        assert!(
            !cache
                .insert_nxdomain_apex_with_ttl("gone.example.", NEG_MAX_TTL_SECS, &[])
                .await
        );

        assert!(!cache.nxdomain_apex_covers("x.gone.example.").await);
    }

    /// The retained proof is what a DO=1 client needs to verify a synthesized
    /// denial, and it is also the only unbounded part of an apex entry.
    #[tokio::test]
    async fn nxdomain_apex_retains_denial_proof_and_drops_referral_records() {
        use hickory_proto::rr::rdata::NS;

        let cache = DnsCache::new(1_048_576);
        let zone = Name::from_ascii("gone.example.").unwrap();
        let mut authorities = soa_proof("gone.example.", NEG_MAX_TTL_SECS);
        authorities.push(Record::update0(
            zone.clone(),
            NEG_MAX_TTL_SECS,
            RecordType::RRSIG,
        ));
        authorities.push(Record::from_rdata(
            zone.clone(),
            NEG_MAX_TTL_SECS,
            RData::NS(NS(Name::from_ascii("ns.invalid.").unwrap())),
        ));
        for _ in 0..NXDOMAIN_APEX_MAX_PROOF_RECORDS {
            authorities.push(Record::update0(
                zone.clone(),
                NEG_MAX_TTL_SECS,
                RecordType::RRSIG,
            ));
        }

        assert!(
            cache
                .insert_nxdomain_apex_with_ttl("gone.example.", NEG_MAX_TTL_SECS, &authorities)
                .await
        );

        let coverage = cache
            .nxdomain_apex_coverage("x.gone.example.")
            .await
            .expect("apex must cover the descendant");
        assert!(
            coverage.authorities.len() <= NXDOMAIN_APEX_MAX_PROOF_RECORDS,
            "retained proof must stay capped",
        );
        assert!(
            coverage
                .authorities
                .iter()
                .any(|r| matches!(&r.data, RData::SOA(_))),
            "the SOA bounding the denial must be retained",
        );
        assert!(
            coverage
                .authorities
                .iter()
                .all(|r| r.record_type() != RecordType::NS),
            "referral records describe delegation, not denial",
        );
    }

    /// A zone is free to put its NSEC/NSEC3 proof ahead of the SOA. Retaining
    /// the first qualifying records would drop the one record RFC 2308 §2.1
    /// requires in a negative authority section. The section here fills the budget exactly, so the
    /// SOA is only retained if its placement is irrelevant.
    #[tokio::test]
    async fn nxdomain_apex_proof_keeps_the_soa_behind_a_long_dnssec_prefix() {
        let cache = DnsCache::new(1_048_576);
        let mut authorities: Vec<Record> = (0..NXDOMAIN_APEX_MAX_PROOF_RECORDS - 1)
            .map(|i| {
                Record::update0(
                    Name::from_ascii(format!("h{i}.gone.example.")).unwrap(),
                    NEG_MAX_TTL_SECS,
                    RecordType::NSEC3,
                )
            })
            .collect();
        authorities.extend(soa_proof("gone.example.", NEG_MAX_TTL_SECS));

        assert!(
            cache
                .insert_nxdomain_apex_with_ttl("gone.example.", NEG_MAX_TTL_SECS, &authorities)
                .await
        );

        let coverage = cache
            .nxdomain_apex_coverage("x.gone.example.")
            .await
            .expect("apex must cover the descendant");
        assert!(
            coverage
                .authorities
                .iter()
                .any(|r| matches!(&r.data, RData::SOA(_))),
            "the SOA must survive the cap wherever the authority placed it",
        );
        assert_eq!(
            coverage.authorities.len(),
            NXDOMAIN_APEX_MAX_PROOF_RECORDS,
            "a section that fills the budget exactly must be retained whole",
        );
    }

    /// A signed denial is only checkable as a whole set. An NSEC3 without its
    /// signature, or a signature whose record was cut away, proves nothing.
    #[tokio::test]
    async fn nxdomain_apex_proof_never_splits_a_signed_set() {
        let cache = DnsCache::new(1_048_576);
        let owners: Vec<Name> = (0..5)
            .map(|i| Name::from_ascii(format!("h{i}.gone.example.")).unwrap())
            .collect();
        let mut authorities = soa_proof("gone.example.", NEG_MAX_TTL_SECS);
        for owner in &owners {
            authorities.push(Record::update0(
                owner.clone(),
                NEG_MAX_TTL_SECS,
                RecordType::NSEC3,
            ));
            authorities.push(Record::update0(
                owner.clone(),
                NEG_MAX_TTL_SECS,
                RecordType::RRSIG,
            ));
        }

        assert!(
            cache
                .insert_nxdomain_apex_with_ttl("gone.example.", NEG_MAX_TTL_SECS, &authorities)
                .await
        );

        let coverage = cache
            .nxdomain_apex_coverage("x.gone.example.")
            .await
            .expect("apex must cover the descendant");
        assert!(coverage.authorities.len() <= NXDOMAIN_APEX_MAX_PROOF_RECORDS);
        for owner in &owners {
            let kept = coverage
                .authorities
                .iter()
                .filter(|r| &r.name == owner)
                .count();
            assert!(
                kept == 0 || kept == 2,
                "{owner} was retained without its full signed set",
            );
        }
    }

    /// A rollover zone signs every RRset twice, so its canonical NXDOMAIN
    /// denial is an SOA RRset plus three signed NSEC3 RRsets (closest
    /// encloser, next closer and wildcard). All of it must be retained: the SOA
    /// with both signatures covering it, and every one of the three NSEC3
    /// RRsets.
    #[tokio::test]
    async fn nxdomain_apex_proof_keeps_the_soa_signature_under_budget_pressure() {
        let cache = DnsCache::new(1_048_576);
        let zone = Name::from_ascii("gone.example.").unwrap();
        let mut authorities: Vec<Record> = Vec::new();
        for i in 0..3u16 {
            let owner = Name::from_ascii(format!("h{i}.gone.example.")).unwrap();
            authorities.push(Record::update0(
                owner.clone(),
                NEG_MAX_TTL_SECS,
                RecordType::NSEC3,
            ));
            authorities.push(rrsig_over(&owner, RecordType::NSEC3, i));
        }
        authorities.extend(soa_proof("gone.example.", NEG_MAX_TTL_SECS));
        // A zone mid-ZSK-rollover signs its SOA with both keys.
        authorities.push(rrsig_over(&zone, RecordType::SOA, 100));
        authorities.push(rrsig_over(&zone, RecordType::SOA, 101));

        assert!(
            cache
                .insert_nxdomain_apex_with_ttl("gone.example.", NEG_MAX_TTL_SECS, &authorities)
                .await
        );

        let coverage = cache
            .nxdomain_apex_coverage("x.gone.example.")
            .await
            .expect("apex must cover the descendant");
        assert!(
            coverage.authorities.len() <= NXDOMAIN_APEX_MAX_PROOF_RECORDS,
            "retained proof must stay capped",
        );
        assert!(
            coverage
                .authorities
                .iter()
                .any(|r| matches!(&r.data, RData::SOA(_))),
            "the SOA bounding the denial must be retained",
        );
        assert_eq!(
            coverage
                .authorities
                .iter()
                .filter(|r| covers_soa(r))
                .count(),
            2,
            "the SOA must never be separated from the signatures covering it",
        );
        for i in 0..3u16 {
            let owner = Name::from_ascii(format!("h{i}.gone.example.")).unwrap();
            assert_eq!(
                coverage
                    .authorities
                    .iter()
                    .filter(|r| r.name == owner)
                    .count(),
                2,
                "{owner} and its signature are one of the three components an \
                 NSEC3 denial needs - a cut may not be installed without it",
            );
        }
    }

    /// The same rollover-signed proof one RRset past the budget. Two thirds of
    /// an NSEC3 denial is not a denial, so nothing may be stored. The
    /// descendant query goes upstream, which is the correct answer.
    #[tokio::test]
    async fn nxdomain_apex_cut_is_refused_when_part_of_the_nsec3_proof_does_not_fit() {
        let cache = DnsCache::new(1_048_576);
        let zone = Name::from_ascii("gone.example.").unwrap();
        let mut authorities = soa_proof("gone.example.", NEG_MAX_TTL_SECS);
        authorities.push(rrsig_over(&zone, RecordType::SOA, 100));
        authorities.push(rrsig_over(&zone, RecordType::SOA, 101));
        // One signed NSEC3 RRset per budget record, so the proof cannot fit whole
        // whatever the budget is.
        for i in 0..NXDOMAIN_APEX_MAX_PROOF_RECORDS as u16 {
            let owner = Name::from_ascii(format!("h{i}.gone.example.")).unwrap();
            authorities.push(Record::update0(
                owner.clone(),
                NEG_MAX_TTL_SECS,
                RecordType::NSEC3,
            ));
            authorities.push(rrsig_over(&owner, RecordType::NSEC3, i));
        }

        assert!(
            !cache
                .insert_nxdomain_apex_with_ttl("gone.example.", NEG_MAX_TTL_SECS, &authorities)
                .await,
            "a partially retained NSEC3 denial must not become a cut",
        );

        assert!(!cache.nxdomain_apex_covers("x.gone.example.").await);
    }

    /// A cut denies every descendant of a name without asking upstream. If the
    /// response proved the denial with NSEC3 and the record budget kept none of
    /// it, replaying the cut would deny names it cannot prove.
    #[tokio::test]
    async fn nxdomain_apex_cut_is_refused_when_no_denial_proof_survives_the_cap() {
        let cache = DnsCache::new(1_048_576);
        let zone = Name::from_ascii("gone.example.").unwrap();
        let denied = Name::from_ascii("h0.gone.example.").unwrap();
        let mut authorities = soa_proof("gone.example.", NEG_MAX_TTL_SECS);
        authorities.push(rrsig_over(&zone, RecordType::SOA, 100));
        authorities.push(Record::update0(
            denied.clone(),
            NEG_MAX_TTL_SECS,
            RecordType::NSEC3,
        ));
        for tag in 0..NXDOMAIN_APEX_MAX_PROOF_RECORDS as u16 {
            authorities.push(rrsig_over(&denied, RecordType::NSEC3, tag));
        }

        assert!(
            !cache
                .insert_nxdomain_apex_with_ttl("gone.example.", NEG_MAX_TTL_SECS, &authorities)
                .await,
            "a signed denial whose proof does not fit the budget must not become a cut",
        );

        assert!(!cache.nxdomain_apex_covers("x.gone.example.").await);
    }

    /// An unsigned zone denies with the SOA alone. The DNSSEC refusal must not
    /// bleed into that case, where there is no denial proof to lose.
    #[tokio::test]
    async fn nxdomain_apex_cut_from_an_unsigned_zone_is_still_installed() {
        use hickory_proto::rr::rdata::NS;

        let cache = DnsCache::new(1_048_576);
        let zone = Name::from_ascii("gone.example.").unwrap();
        let mut authorities = soa_proof("gone.example.", NEG_MAX_TTL_SECS);
        authorities.push(Record::from_rdata(
            zone,
            NEG_MAX_TTL_SECS,
            RData::NS(NS(Name::from_ascii("ns.invalid.").unwrap())),
        ));

        assert!(
            cache
                .insert_nxdomain_apex_with_ttl("gone.example.", NEG_MAX_TTL_SECS, &authorities)
                .await
        );

        let coverage = cache
            .nxdomain_apex_coverage("x.gone.example.")
            .await
            .expect("apex must cover the descendant");
        assert_eq!(coverage.authorities.len(), 1);
        assert!(matches!(&coverage.authorities[0].data, RData::SOA(_)));
    }

    /// The record budget is what keeps the tracker bounded well past its entry
    /// count. An authority padding a denial with dozens of signed NSEC3 RRsets
    /// exceeds it, and a signed denial cannot be stored in part, so the flood
    /// costs the tracker nothing at all.
    #[tokio::test]
    async fn nxdomain_apex_oversized_signed_section_is_refused_not_truncated() {
        let cache = DnsCache::new(1_048_576);
        let zone = Name::from_ascii("gone.example.").unwrap();
        let mut authorities = soa_proof("gone.example.", NEG_MAX_TTL_SECS);
        authorities.push(rrsig_over(&zone, RecordType::SOA, 100));
        for i in 0..32u16 {
            let owner = Name::from_ascii(format!("h{i}.gone.example.")).unwrap();
            authorities.push(Record::update0(
                owner.clone(),
                NEG_MAX_TTL_SECS,
                RecordType::NSEC3,
            ));
            authorities.push(rrsig_over(&owner, RecordType::NSEC3, i));
        }

        assert!(
            !cache
                .insert_nxdomain_apex_with_ttl("gone.example.", NEG_MAX_TTL_SECS, &authorities)
                .await
        );

        assert!(!cache.nxdomain_apex_covers("x.gone.example.").await);
    }

    /// The budget still truncates on the path that does install a cut. A
    /// signature whose covered RRset is not part of the denial proves nothing
    /// by itself, so dropping a flood of them keeps the entry bounded without
    /// weakening the retained proof.
    #[tokio::test]
    async fn nxdomain_apex_proof_stays_capped_when_padding_signatures_are_dropped() {
        let cache = DnsCache::new(1_048_576);
        let zone = Name::from_ascii("gone.example.").unwrap();
        let mut authorities = soa_proof("gone.example.", NEG_MAX_TTL_SECS);
        authorities.push(rrsig_over(&zone, RecordType::SOA, 100));
        for tag in 0..NXDOMAIN_APEX_MAX_PROOF_RECORDS as u16 {
            authorities.push(rrsig_over(&zone, RecordType::DNSKEY, tag));
        }

        assert!(
            cache
                .insert_nxdomain_apex_with_ttl("gone.example.", NEG_MAX_TTL_SECS, &authorities)
                .await
        );

        let coverage = cache
            .nxdomain_apex_coverage("x.gone.example.")
            .await
            .expect("apex must cover the descendant");
        assert_eq!(
            coverage.authorities.len(),
            2,
            "only the SOA and the signature covering it are worth retaining",
        );
        assert_eq!(
            coverage
                .authorities
                .iter()
                .filter(|r| covers_soa(r))
                .count(),
            1,
            "the SOA signature is retained before anything competes for the budget",
        );
    }

    /// RFC 2308 §2.1: the SOA is what bounds how long a denial may be reused.
    /// A proof carrying none cannot be replayed as a negative answer.
    #[tokio::test]
    async fn nxdomain_apex_cut_without_soa_is_refused() {
        let cache = DnsCache::new(1_048_576);
        let owner = Name::from_ascii("gone.example.").unwrap();
        let authorities = vec![
            Record::update0(owner.clone(), NEG_MAX_TTL_SECS, RecordType::NSEC),
            Record::update0(owner, NEG_MAX_TTL_SECS, RecordType::RRSIG),
        ];

        assert!(
            !cache
                .insert_nxdomain_apex_with_ttl("gone.example.", NEG_MAX_TTL_SECS, &authorities)
                .await
        );

        assert!(!cache.nxdomain_apex_covers("x.gone.example.").await);
    }

    /// `clear` is the only zone-wide invalidation the resolver has. The
    /// DNSSEC toggle, a network change and `dns_flush_cache` all route
    /// through it. It must drop positive answers, negative answers and RFC
    /// 8020 apex coverage together, and must leave no residual state that
    /// makes the next insert read back as a miss.
    #[tokio::test]
    async fn clear_invalidates_every_cache_surface_and_leaves_none_poisoned() {
        let cache = DnsCache::new(1_048_576);
        let positive = CacheKey::from("a.company.internal", RecordType::A);
        let negative = CacheKey::from("missing.company.internal", RecordType::A);
        let e = |p: &str| CachedEntry::scaffold(Message::query(), p.into());

        cache.insert(positive.clone(), e("up"), 300).await;
        cache.insert_neg(negative.clone(), e("up"), 5).await;
        cache.insert_nxdomain_apex("gone.company.internal.").await;
        assert!(cache.get(&positive).await.is_some());
        assert!(cache.get(&negative).await.is_some());
        assert!(cache.nxdomain_apex_covers("x.gone.company.internal.").await);

        cache.clear().await;

        assert!(cache.get(&positive).await.is_none());
        assert!(cache.get(&negative).await.is_none());
        assert!(
            !cache.nxdomain_apex_covers("x.gone.company.internal.").await,
            "clear must drop RFC 8020 synthetic NXDOMAIN coverage too"
        );
        assert!(
            cache.get_allow_expired(&positive).await.is_none(),
            "a cleared entry must not resurface through serve-expired"
        );

        cache.insert(positive.clone(), e("down"), 300).await;
        assert_eq!(
            cache.get(&positive).await.map(|hit| hit.provider),
            Some("down".to_string()),
            "a fresh insert after clear must be visible"
        );
        cache.insert_nxdomain_apex("gone.company.internal.").await;
        assert!(cache.nxdomain_apex_covers("x.gone.company.internal.").await);
    }

    fn big_txt_entry(name: &str, approx_bytes: usize) -> CachedEntry {
        use hickory_proto::rr::{rdata::TXT, Name, Record};
        use std::str::FromStr;
        let mut msg = Message::query();
        let mut q = hickory_proto::op::Query::new();
        q.set_name(Name::from_str(name).unwrap())
            .set_query_type(RecordType::TXT);
        msg.add_query(q);
        // DNS TXT character-strings are individually capped at 255 bytes, so
        // this packs multiple 250-byte chunks into a single record to approach
        // `approx_bytes` on the wire.
        let mut remaining = approx_bytes;
        let mut chunks: Vec<String> = Vec::new();
        while remaining > 0 {
            let take = remaining.min(250);
            chunks.push("x".repeat(take));
            remaining -= take;
        }
        let rec = Record::from_rdata(
            Name::from_str(name).unwrap(),
            30,
            hickory_proto::rr::RData::TXT(TXT::new(chunks)),
        );
        msg.add_answer(rec);
        CachedEntry::scaffold(msg, "test".into())
    }

    #[tokio::test]
    async fn cache_weighs_entries_by_byte_cost() {
        let cache = DnsCache::new(1024);
        let key_a = CacheKey::from("a.example.", RecordType::A);
        let key_b = CacheKey::from("b.example.", RecordType::A);

        let big = big_txt_entry("a.example.", 800);
        let big2 = big_txt_entry("b.example.", 800);

        cache.insert(key_a.clone(), big, 300).await;
        cache.insert(key_b.clone(), big2, 300).await;

        cache.inner.run_pending_tasks().await;
        let present_a = cache.get(&key_a).await.is_some();
        let present_b = cache.get(&key_b).await.is_some();
        // Two 800-byte entries cannot both fit under a 1024-byte cap.
        assert!(!(present_a && present_b), "cache must evict under byte cap");
    }
}
