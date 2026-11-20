// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use crate::lmdb::{
    AllowlistDb, BlockAction, BlockMatch, BlocklistConfig, BlocklistDb, DomainName, MultiCategoryDb,
};
use arc_swap::ArcSwap;
use hickory_proto::rr::RecordType;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Per-path cache of `Arc<BlocklistDb>`. `heed::Env` (LMDB) refuses to reopen
/// a path while a previous `Env` for it is still alive in this process, and
/// `BlocklistDb::open` fails with "environment already open in this program"
/// until the old `Arc` drops. Reusing one canonical `Arc` per path across
/// rebuilds avoids that second open.
///
/// Runtime metadata (`tag`/`action`) lives in each `MultiCategoryDb`
/// snapshot, not in this cache, so settings reloads apply immediately even
/// when the LMDB handle itself is reused.
struct CachedDb {
    db: Arc<BlocklistDb>,
    /// Inode of the LMDB data directory at `open()` time. The scheduler
    /// publishes content-versioned DB paths, so this guards manual or legacy
    /// in-place swaps. An on-disk inode that differs from the cached value
    /// drops the stale entry before the next snapshot.
    inode: u64,
}

static DB_CACHE: OnceLock<Mutex<HashMap<PathBuf, CachedDb>>> = OnceLock::new();

fn db_cache() -> &'static Mutex<HashMap<PathBuf, CachedDb>> {
    DB_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// macOS / Linux: heed stores LMDB env as a directory with
/// `data.mdb` + `lock.mdb` inside. The directory's own inode
/// uniquely identifies the env on this filesystem.
fn dir_inode(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.ino())
}

#[derive(Debug, Clone, Copy)]
pub enum BlockDecision {
    Allow,
    AddressA(Ipv4Addr),
    AddressAAAA(Ipv6Addr),
    Nxdomain,
    Nodata,
}

static BLOCKLIST: OnceLock<ArcSwap<MultiCategoryDb>> = OnceLock::new();
static ALLOWLIST: OnceLock<ArcSwap<Option<Arc<AllowlistDb>>>> = OnceLock::new();
static ALLOWLIST_INIT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
/// Path set by the host (`dns_allowlist_set_path`) so the allowlist opens
/// lazily on the first add/remove/list call. That must work while the
/// resolver is stopped, because the Preferences allowlist UI works before
/// start.
static ALLOWLIST_PATH: OnceLock<std::sync::Mutex<Option<PathBuf>>> = OnceLock::new();

fn allowlist_slot() -> &'static ArcSwap<Option<Arc<AllowlistDb>>> {
    ALLOWLIST.get_or_init(|| ArcSwap::from_pointee(None))
}

fn allowlist_path_slot() -> &'static std::sync::Mutex<Option<PathBuf>> {
    ALLOWLIST_PATH.get_or_init(|| std::sync::Mutex::new(None))
}

fn allowlist_init_lock() -> &'static Mutex<()> {
    ALLOWLIST_INIT_LOCK.get_or_init(|| Mutex::new(()))
}

/// Times a filtering database was unusable and the resolver answered anyway.
/// No FFI accessor exports it yet. It is the single accounting point, so an
/// export needs one line.
static FILTERING_DEGRADED: AtomicU64 = AtomicU64::new(0);
/// Rate-limit anchor for degraded logging, so a broken database on the query
/// hot path cannot fill the log.
static DEGRADED_LOG_ANCHOR: Mutex<Option<Instant>> = Mutex::new(None);
const DEGRADED_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Records one fail-open event on the filtering plane: an allowlist that
/// cannot be opened or read, or a blocklist category whose lookup failed.
/// Filtering degrades and DNS keeps answering.
pub(crate) fn note_filtering_degraded(source: &str, err: &str) {
    FILTERING_DEGRADED.fetch_add(1, Ordering::Relaxed);
    let mut anchor = DEGRADED_LOG_ANCHOR
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let due = anchor.is_none_or(|at| at.elapsed() >= DEGRADED_LOG_INTERVAL);
    if !due {
        return;
    }
    *anchor = Some(Instant::now());
    drop(anchor);
    log::warn!(
        "filtering degraded ({} total): {} unusable, failing open: {}",
        FILTERING_DEGRADED.load(Ordering::Relaxed),
        source,
        err
    );
}

/// Total fail-open events on the filtering plane since process start.
pub fn filtering_degraded_count() -> u64 {
    FILTERING_DEGRADED.load(Ordering::Relaxed)
}

/// `AllowlistDb::open` sets up a write transaction, so retrying it on every
/// query turns one broken database into a per-query cost. Failed opens back
/// off exponentially from `ALLOWLIST_BACKOFF_BASE` to `ALLOWLIST_BACKOFF_MAX`
/// and are cleared by a successful open or a path change.
const ALLOWLIST_BACKOFF_BASE: Duration = Duration::from_secs(5);
const ALLOWLIST_BACKOFF_MAX: Duration = Duration::from_secs(60);

struct AllowlistOpenFailure {
    at: Instant,
    consecutive: u32,
}

static ALLOWLIST_OPEN_FAILURE: Mutex<Option<AllowlistOpenFailure>> = Mutex::new(None);

fn allowlist_failure_slot() -> std::sync::MutexGuard<'static, Option<AllowlistOpenFailure>> {
    ALLOWLIST_OPEN_FAILURE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn allowlist_backoff_window(consecutive: u32) -> Duration {
    ALLOWLIST_BACKOFF_BASE
        .saturating_mul(1u32 << consecutive.saturating_sub(1).min(5))
        .min(ALLOWLIST_BACKOFF_MAX)
}

fn allowlist_backoff_active() -> bool {
    match allowlist_failure_slot().as_ref() {
        Some(f) => f.at.elapsed() < allowlist_backoff_window(f.consecutive),
        None => false,
    }
}

fn record_allowlist_open_failure() {
    let mut slot = allowlist_failure_slot();
    let consecutive = slot.as_ref().map_or(0, |f| f.consecutive).saturating_add(1);
    *slot = Some(AllowlistOpenFailure {
        at: Instant::now(),
        consecutive,
    });
}

fn clear_allowlist_open_failure() {
    *allowlist_failure_slot() = None;
}

/// Does not open the LMDB env. It opens lazily on first use, so the host can
/// call this before `dns_configure_blocklist`.
pub fn set_allowlist_path(path: &Path) {
    let _init = allowlist_init_lock()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let new_path = path.to_path_buf();
    let mut guard = allowlist_path_slot()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let changed = guard.as_ref() != Some(&new_path);
    *guard = Some(new_path);
    drop(guard);
    if changed {
        allowlist_slot().store(Arc::new(None));
        clear_allowlist_open_failure();
    }
}

/// Return a live `Arc<AllowlistDb>`, opening it lazily from the path set
/// via `set_allowlist_path` when the env is not yet populated. Returns
/// `None` when no path was ever registered.
///
/// Management intent (Preferences add/remove/list): always attempts the open
/// so a user-driven action surfaces the real error and a repaired database is
/// picked up immediately. The DNS hot path must use `allowlist_for_query`,
/// which honours the failure backoff and never returns an error.
pub fn get_or_open_allowlist() -> Result<Option<Arc<AllowlistDb>>, String> {
    let slot = allowlist_slot();
    if let Some(existing) = slot.load().as_ref().clone() {
        return Ok(Some(existing));
    }
    let _init = allowlist_init_lock()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(existing) = slot.load().as_ref().clone() {
        return Ok(Some(existing));
    }
    let path = {
        let guard = allowlist_path_slot()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.clone()
    };
    let Some(path) = path else {
        return Ok(None);
    };
    let db = match open_allowlist_env(&path) {
        Ok(db) => db,
        Err(e) => {
            record_allowlist_open_failure();
            return Err(e.to_string());
        }
    };
    clear_allowlist_open_failure();
    let arc = Arc::new(db);
    slot.store(Arc::new(Some(arc.clone())));
    log::info!("allowlist lazy-opened at {}", path.display());
    Ok(Some(arc))
}

/// Query-path allowlist accessor. An allowlist that cannot be opened is
/// treated as empty and only retried after the backoff window, so a broken
/// database costs one `mdb_env_open` per window instead of one per query and
/// never fails the DNS answer.
fn allowlist_for_query() -> Option<Arc<AllowlistDb>> {
    if let Some(existing) = allowlist_slot().load().as_ref().clone() {
        return Some(existing);
    }
    if allowlist_backoff_active() {
        return None;
    }
    match get_or_open_allowlist() {
        Ok(db) => db,
        Err(e) => {
            note_filtering_degraded("allowlist", &e);
            None
        }
    }
}

/// Single funnel for `mdb_env_open` on the allowlist, so the backoff logic
/// and the tests share one accounting point.
fn open_allowlist_env(path: &Path) -> crate::lmdb::Result<AllowlistDb> {
    #[cfg(test)]
    ALLOWLIST_OPEN_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    AllowlistDb::open(path)
}

#[cfg(test)]
static ALLOWLIST_OPEN_ATTEMPTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn take_allowlist_open_attempts() -> usize {
    ALLOWLIST_OPEN_ATTEMPTS.swap(0, std::sync::atomic::Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ReloadOutcome {
    Applied,
    /// Selected categories whose database has not been downloaded yet. The
    /// previous snapshot stays live, but the settings themselves are valid and
    /// a refresh will publish the databases, so the host must keep them.
    PendingMissing {
        missing: usize,
    },
    /// A selected database exists but is corrupt or unopenable. This is a
    /// hard failure the host must surface.
    KeptPrevious {
        open_failed: usize,
    },
}

impl ReloadOutcome {
    /// Whether the host may keep the persisted settings.
    pub fn accepted(self) -> bool {
        matches!(self, Self::Applied | Self::PendingMissing { .. })
    }
}

/// Called by the scheduler on configure and refresh, and by the reload FFI.
/// Each caller logs the outcome, because only the caller knows what follows.
pub fn reload_from_config(cfg: &BlocklistConfig, source: &str) -> ReloadOutcome {
    let slot = BLOCKLIST.get_or_init(|| ArcSwap::from_pointee(MultiCategoryDb::new()));
    let had_live_snapshot = slot.load().database_count() > 0;
    let stale_dropped = drop_stale_cached_dbs(cfg, source);
    if stale_dropped > 0 {
        std::thread::yield_now();
    }

    let mut result = build_db_from_config_with_stats(cfg, source);
    if stale_dropped > 0 && result.open_failed > 0 {
        for delay_ms in [10, 50, 100] {
            std::thread::sleep(Duration::from_millis(delay_ms));
            result = build_db_from_config_with_stats(cfg, source);
            if result.open_failed == 0 {
                break;
            }
        }
    }

    if result.open_failed > 0 && had_live_snapshot {
        drop(result.db);
        prune_unused_cached_dbs();
        return ReloadOutcome::KeptPrevious {
            open_failed: result.open_failed,
        };
    }

    if result.missing > 0 && had_live_snapshot {
        drop(result.db);
        prune_unused_cached_dbs();
        return ReloadOutcome::PendingMissing {
            missing: result.missing,
        };
    }

    slot.store(Arc::new(result.db));
    prune_unused_cached_dbs();
    ReloadOutcome::Applied
}

/// Whether the live snapshot filters with every database `cfg` selects.
/// `ReloadOutcome::Applied` does not say that: a load with nothing live before
/// it publishes whatever opened and skips the rest.
pub fn live_snapshot_covers(cfg: &BlocklistConfig) -> bool {
    let live = BLOCKLIST.get().map(|slot| slot.load_full());
    cfg.blocklists.iter().all(|entry| {
        live.as_ref()
            .is_some_and(|db| db.holds_database(&entry.db_path))
    })
}

fn prune_unused_cached_dbs() {
    db_cache()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .retain(|_, cached| Arc::strong_count(&cached.db) > 1);
}

fn drop_stale_cached_dbs(cfg: &BlocklistConfig, source: &str) -> usize {
    if !cfg.enabled {
        return 0;
    }

    let mut cache = db_cache().lock().unwrap_or_else(|p| p.into_inner());
    let stale_paths: Vec<PathBuf> = cfg
        .blocklists
        .iter()
        .filter_map(|entry| {
            let live_inode = dir_inode(&entry.db_path)?;
            let cached = cache.get(&entry.db_path)?;
            (cached.inode != live_inode).then(|| entry.db_path.clone())
        })
        .collect();

    for path in &stale_paths {
        log::info!(
            "blocklist {}: db_path {} inode changed, dropping cached env before reload",
            source,
            path.display(),
        );
        cache.remove(path);
    }

    stale_paths.len()
}

struct BuildDbResult {
    db: MultiCategoryDb,
    /// Databases present on disk that could not be opened (corrupt).
    open_failed: usize,
    /// Databases the config selects that are not downloaded yet.
    missing: usize,
}

#[cfg(test)]
fn build_db_from_config(cfg: &BlocklistConfig, source: &str) -> MultiCategoryDb {
    build_db_from_config_with_stats(cfg, source).db
}

fn build_db_from_config_with_stats(cfg: &BlocklistConfig, source: &str) -> BuildDbResult {
    if !cfg.enabled {
        log::info!("blocklist {}: disabled (cfg.enabled=false)", source);
        // Publication decides which cached handles are still needed.
        return BuildDbResult {
            db: MultiCategoryDb::new(),
            open_failed: 0,
            missing: 0,
        };
    }
    let mut dbs = Vec::new();
    let mut skipped_missing = 0usize;
    let mut skipped_open = 0usize;
    let mut reused = 0usize;
    let mut opened = 0usize;

    // Track paths seen in this config so we can drop the rest from the cache.
    let mut active_paths: std::collections::HashSet<PathBuf> =
        std::collections::HashSet::with_capacity(cfg.blocklists.len());

    // Poison recovery. A panic in a previous holder might leave a partially
    // inserted entry but cannot corrupt the LMDB env handles themselves, so
    // reclaiming the guard is safer than aborting the agent on the next
    // reload.
    let mut cache = db_cache().lock().unwrap_or_else(|p| p.into_inner());
    for entry in &cfg.blocklists {
        let metadata = match std::fs::symlink_metadata(&entry.db_path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                skipped_missing += 1;
                log::warn!(
                    "blocklist {}: skip {} — db_path missing: {}",
                    source,
                    entry.tag,
                    entry.db_path.display()
                );
                continue;
            }
            Err(_) => None,
        };
        if metadata.is_some_and(|metadata| metadata.file_type().is_dir()) {
            match std::fs::symlink_metadata(entry.db_path.join("data.mdb")) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    skipped_missing += 1;
                    log::warn!(
                        "blocklist {}: skip {} — db_path has no data.mdb yet: {}",
                        source,
                        entry.tag,
                        entry.db_path.display()
                    );
                    continue;
                }
                Err(_) => {}
            }
        }
        active_paths.insert(entry.db_path.clone());

        let live_inode = dir_inode(&entry.db_path);
        let cached_match = cache
            .get(&entry.db_path)
            .filter(|c| live_inode.is_some_and(|live| c.inode == live))
            .map(|c| c.db.clone());

        if let Some(db) = cached_match {
            dbs.push((db, entry.clone()));
            reused += 1;
            continue;
        }

        if cache.contains_key(&entry.db_path) {
            // The cached Arc stays alive inside the active MultiCategoryDb
            // snapshot until the next BLOCKLIST.store() swap drains in-flight
            // `decide()` calls. Leaving it out of the next snapshot is enough
            // to make the new env (with the new inode) the source of truth for
            // queries that arrive after the swap.
            log::info!(
                "blocklist {}: db_path {} inode changed, reopening",
                source,
                entry.db_path.display(),
            );
            cache.remove(&entry.db_path);
        }

        match BlocklistDb::open(&entry.db_path) {
            Ok(db) => {
                let arc = Arc::new(db);
                // Inode 0 is reserved on POSIX (never returned by stat). If
                // metadata() failed here, storing 0 guarantees the next
                // reload's inode comparison will mismatch and force a
                // reopen, the safe direction.
                let inode = live_inode.unwrap_or(0);
                cache.insert(
                    entry.db_path.clone(),
                    CachedDb {
                        db: arc.clone(),
                        inode,
                    },
                );
                dbs.push((arc, entry.clone()));
                opened += 1;
            }
            Err(e) => {
                skipped_open += 1;
                log::warn!(
                    "blocklist {}: skip {} — open failed: {}",
                    source,
                    entry.tag,
                    e
                );
            }
        }
    }

    // Published and in-flight snapshots must retain reusable LMDB handles
    // until the reload has decided whether to publish the candidate.
    let removed: Vec<PathBuf> = cache
        .keys()
        .filter(|p| !active_paths.contains(*p) && Arc::strong_count(&cache[*p].db) == 1)
        .cloned()
        .collect();
    for p in &removed {
        cache.remove(p);
    }
    drop(cache);

    log::info!(
        "blocklist {}: loaded={} requested={} missing={} open_failed={} reused={} opened={} dropped={}",
        source,
        dbs.len(),
        cfg.blocklists.len(),
        skipped_missing,
        skipped_open,
        reused,
        opened,
        removed.len(),
    );
    BuildDbResult {
        db: MultiCategoryDb::from_databases(dbs),
        open_failed: skipped_open,
        missing: skipped_missing,
    }
}

/// Callback strings are valid only for the call duration. Host code must copy
/// them before returning, and callbacks must not unwind across FFI.
pub type BlockedCallback = extern "C" fn(
    domain: *const std::os::raw::c_char,
    rule: *const std::os::raw::c_char,
    category: *const std::os::raw::c_char,
);

static CALLBACK: OnceLock<ArcSwap<Option<BlockedCallback>>> = OnceLock::new();

fn callback_slot() -> &'static ArcSwap<Option<BlockedCallback>> {
    CALLBACK.get_or_init(|| ArcSwap::from_pointee(None))
}

pub fn set_blocked_callback(cb: BlockedCallback) {
    callback_slot().store(Arc::new(Some(cb)));
}

struct BlockedEvent {
    domain: String,
    rule: String,
    category: String,
}

/// The blocklist matches by parent, so unique blocked names are trivial to
/// generate. Telemetry therefore has to be bounded: `decide()` only hands the
/// observation over, and every `CString`, the FFI call, and whatever the host
/// does with it happen on the consumer thread instead of the query path.
const BLOCKED_QUEUE_CAPACITY: usize = 1024;

static BLOCKED_QUEUE: OnceLock<SyncSender<BlockedEvent>> = OnceLock::new();
/// Observations discarded because the queue was full. Losing telemetry under
/// saturation is the deliberate trade; losing it silently is not.
static BLOCKED_DROPPED: AtomicU64 = AtomicU64::new(0);
static BLOCKED_DROP_LOG_ANCHOR: Mutex<Option<Instant>> = Mutex::new(None);
const BLOCKED_DROP_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Observations dropped by a full telemetry queue since process start.
pub fn blocked_events_dropped() -> u64 {
    BLOCKED_DROPPED.load(Ordering::Relaxed)
}

/// Lazily creates the bounded queue and its single long-lived consumer. A
/// consumer that cannot be started leaves the receiver dropped, which turns
/// every send into a counted drop instead of a stall.
fn blocked_queue() -> &'static SyncSender<BlockedEvent> {
    BLOCKED_QUEUE.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel(BLOCKED_QUEUE_CAPACITY);
        if let Err(e) = std::thread::Builder::new()
            .name("macdns-blocked-telemetry".to_owned())
            .spawn(move || consume_blocked_events(&rx))
        {
            log::error!(
                "blocked telemetry consumer failed to start: {}; observations will be dropped",
                e
            );
        }
        tx
    })
}

/// Query-path hand-off. Never blocks: back-pressuring DNS resolution on
/// telemetry would be the worse failure.
fn publish_blocked_event(domain: &str, rule: &str, category: &str) {
    let event = BlockedEvent {
        domain: domain.to_owned(),
        rule: rule.to_owned(),
        category: category.to_owned(),
    };
    try_publish_blocked(blocked_queue(), event);
}

fn try_publish_blocked(tx: &SyncSender<BlockedEvent>, event: BlockedEvent) -> bool {
    if tx.try_send(event).is_ok() {
        return true;
    }
    let total = BLOCKED_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
    let mut anchor = BLOCKED_DROP_LOG_ANCHOR
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if anchor.is_none_or(|at| at.elapsed() >= BLOCKED_DROP_LOG_INTERVAL) {
        *anchor = Some(Instant::now());
        drop(anchor);
        log::warn!(
            "blocked telemetry saturated: {} observation(s) dropped since start",
            total
        );
    }
    false
}

/// The single consumer. Runs for the process lifetime, like the callback slot
/// it reads, and delivers each observation exactly once.
fn consume_blocked_events(rx: &Receiver<BlockedEvent>) {
    let mut deliver = |event: &BlockedEvent| {
        let cb_guard = callback_slot().load();
        if let Some(cb) = **cb_guard {
            invoke_blocked_callback(cb, event);
        }
    };
    while drain_blocked_batch(rx, &mut deliver) {}
}

/// Waits for one observation, then delivers everything already queued behind
/// it, so a burst costs one wake-up instead of one per observation. Returns
/// `false` once every sender is gone.
fn drain_blocked_batch(
    rx: &Receiver<BlockedEvent>,
    deliver: &mut impl FnMut(&BlockedEvent),
) -> bool {
    let Ok(first) = rx.recv() else {
        return false;
    };
    deliver(&first);
    while let Ok(event) = rx.try_recv() {
        deliver(&event);
    }
    true
}

fn invoke_blocked_callback(cb: BlockedCallback, event: &BlockedEvent) {
    if let (Ok(domain), Ok(rule), Ok(category)) = (
        std::ffi::CString::new(event.domain.as_str()),
        std::ffi::CString::new(event.rule.as_str()),
        std::ffi::CString::new(event.category.as_str()),
    ) {
        cb(domain.as_ptr(), rule.as_ptr(), category.as_ptr());
    }
}

/// Filtering decision for one query. Infallible by design: an unusable
/// allowlist or blocklist database degrades filtering (`note_filtering_degraded`)
/// and the query keeps flowing, because a filtering database is user policy,
/// not an authorization boundary. Licensing and proxy-control are the opposite
/// (they fail closed) and must not be modelled on this.
pub fn decide(domain: &str, qtype: RecordType) -> BlockDecision {
    decide_with_match(domain, qtype).0
}

/// `decide`, plus the blocklist entry that matched. The match is `Some`
/// exactly when the decision blocks.
pub fn decide_with_match(domain: &str, qtype: RecordType) -> (BlockDecision, Option<BlockMatch>) {
    let Ok(name) = DomainName::new(domain) else {
        return (BlockDecision::Allow, None);
    };

    if let Some(list) = allowlist_for_query() {
        match list.check_with_parents(&name) {
            Ok(Some(_)) => return (BlockDecision::Allow, None),
            Ok(None) => {}
            Err(e) => note_filtering_degraded("allowlist lookup", &e.to_string()),
        }
    }

    let block_match = BLOCKLIST.get().and_then(|s| s.load().check_domain(&name));

    let Some(m) = block_match else {
        return (BlockDecision::Allow, None);
    };

    if callback_slot().load().is_some() {
        publish_blocked_event(domain, m.matched_rule.as_str(), m.tag.as_str());
    }

    (decision_for_action(m.action, qtype), Some(m))
}

fn decision_for_action(action: BlockAction, qtype: RecordType) -> BlockDecision {
    match action {
        BlockAction::Null => match qtype {
            RecordType::A => BlockDecision::AddressA(Ipv4Addr::UNSPECIFIED),
            RecordType::AAAA => BlockDecision::AddressAAAA(Ipv6Addr::UNSPECIFIED),
            _ => BlockDecision::Nodata,
        },
        BlockAction::Nxdomain => BlockDecision::Nxdomain,
        BlockAction::Localhost => match qtype {
            RecordType::A => BlockDecision::AddressA(Ipv4Addr::LOCALHOST),
            RecordType::AAAA => BlockDecision::AddressAAAA(Ipv6Addr::LOCALHOST),
            _ => BlockDecision::Nodata,
        },
        BlockAction::CustomIp(ip) => match (ip, qtype) {
            (std::net::IpAddr::V4(v4), RecordType::A) => BlockDecision::AddressA(v4),
            (std::net::IpAddr::V6(v6), RecordType::AAAA) => BlockDecision::AddressAAAA(v6),
            _ => BlockDecision::Nodata,
        },
    }
}

/// Serializes tests that touch the process-wide `BLOCKLIST` / `ALLOWLIST`
/// slots and the LMDB env cache. Shared with the scheduler tests, which drive
/// `reload_from_config` through `configure`.
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Publishes an arbitrary snapshot so tests can install fault-injected
/// categories that no on-disk config could produce.
#[cfg(test)]
pub(crate) fn install_snapshot_for_tests(db: MultiCategoryDb) {
    BLOCKLIST
        .get_or_init(|| ArcSwap::from_pointee(MultiCategoryDb::new()))
        .store(Arc::new(db));
}

#[cfg(test)]
pub(crate) fn live_database_count() -> usize {
    BLOCKLIST
        .get()
        .map(|slot| slot.load().database_count())
        .unwrap_or(0)
}

/// Drops the published snapshot and the cached LMDB envs for `paths`, so the
/// next test can reopen the same directories.
#[cfg(test)]
pub(crate) fn reset_for_tests(paths: &[&Path]) {
    if let Some(slot) = BLOCKLIST.get() {
        slot.store(Arc::new(MultiCategoryDb::new()));
    }
    let mut cache = db_cache().lock().unwrap_or_else(|p| p.into_inner());
    for path in paths {
        cache.remove(*path);
    }
}

#[cfg(test)]
mod tests {
    use super::test_lock as lock;
    use super::*;
    use hickory_proto::rr::RecordType;

    #[test]
    fn decision_without_init_is_allow() {
        let _guard = lock();
        assert!(matches!(
            decide("ads.example.com", RecordType::A),
            BlockDecision::Allow
        ));
    }

    #[test]
    fn decision_for_action_honors_configured_policy() {
        assert!(matches!(
            decision_for_action(BlockAction::Nxdomain, RecordType::A),
            BlockDecision::Nxdomain
        ));
        assert!(matches!(
            decision_for_action(BlockAction::Localhost, RecordType::A),
            BlockDecision::AddressA(ip) if ip == std::net::Ipv4Addr::LOCALHOST
        ));
        assert!(matches!(
            decision_for_action(BlockAction::Localhost, RecordType::MX),
            BlockDecision::Nodata
        ));
    }

    fn blocked_event(domain: &str) -> BlockedEvent {
        BlockedEvent {
            domain: domain.to_owned(),
            rule: "doubleclick.net".to_owned(),
            category: "ads_tracking".to_owned(),
        }
    }

    /// A flood of blocked queries must cost a bounded queue, not an unbounded
    /// backlog, and every observation the queue refuses must be counted.
    #[test]
    fn blocked_queue_saturation_counts_every_drop() {
        let _guard = lock();
        let (tx, rx) = std::sync::mpsc::sync_channel(2);
        let before = blocked_events_dropped();

        let mut accepted = 0;
        for i in 0..5 {
            if try_publish_blocked(&tx, blocked_event(&format!("x{i}.doubleclick.net"))) {
                accepted += 1;
            }
        }

        assert_eq!(accepted, 2, "the queue must stop at capacity");
        assert_eq!(
            blocked_events_dropped() - before,
            3,
            "every discarded observation must be counted"
        );
        drop(rx);
    }

    /// One wake-up must drain everything queued behind it, and a closed queue
    /// must end the consumer instead of spinning.
    #[test]
    fn blocked_batch_drain_delivers_every_queued_event() {
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        for i in 0..4 {
            let sent = tx.try_send(blocked_event(&format!("x{i}.doubleclick.net")));
            assert!(sent.is_ok(), "the batch must fit before the drain runs");
        }

        let mut delivered: Vec<String> = Vec::new();
        {
            let mut collect = |event: &BlockedEvent| delivered.push(event.domain.clone());
            assert!(drain_blocked_batch(&rx, &mut collect));
            drop(tx);
            assert!(
                !drain_blocked_batch(&rx, &mut collect),
                "a closed queue must end the consumer"
            );
        }

        assert_eq!(
            delivered.len(),
            4,
            "one wake-up must drain the whole batch, without losing an observation"
        );
    }

    /// Single combined test for the lazy-open / shared-slot contract.
    /// Per-test isolation would require resetting the module statics, but
    /// LMDB forbids reopening the same env while any previous handle is
    /// still alive, and the `ALLOWLIST` slot is a process-lifetime
    /// singleton. Driving both assertions in one sequence keeps the heed
    /// refusal out of the way.
    #[test]
    fn lazy_open_contract() {
        let _guard = lock();
        // No path registered → None. A prior test may have populated the
        // slots, so reset both first. That is safe because the old Arc drops
        // before a new env opens.
        *allowlist_path_slot().lock().unwrap() = None;
        allowlist_slot().store(Arc::new(None));
        let out = get_or_open_allowlist().expect("no error on missing path");
        assert!(out.is_none(), "expected None when no path registered");

        // Register a path, lazy-open and write. The slot `decide()` reads
        // must hold the same handle.
        let tmp = tempfile::TempDir::new().unwrap();
        set_allowlist_path(tmp.path());
        let db = get_or_open_allowlist()
            .expect("lazy open ok")
            .expect("returned handle");
        let name = crate::lmdb::DomainName::new("example.com").unwrap();
        db.add_domain(&name).unwrap();

        let slot_view = allowlist_slot().load();
        let handle = slot_view
            .as_ref()
            .as_ref()
            .expect("allowlist slot populated");
        assert!(handle.contains(&name).unwrap());

        // Startup path: Swift registered the path, but no UI allowlist call
        // opened the env before DNS queries arrived.
        drop(slot_view);
        drop(db);
        allowlist_slot().store(Arc::new(None));
        let block_dir = tmp.path().join("blocked.db");
        let blocked = BlocklistDb::open_for_write(&block_dir).unwrap();
        blocked.insert(&name).unwrap();
        drop(blocked);
        let cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![crate::lmdb::BlocklistEntry {
                name: "Test".into(),
                tag: "test".into(),
                db_path: block_dir.clone(),
                action: serde_json::from_str("\"null\"").unwrap(),
            }],
        };
        assert_eq!(
            reload_from_config(&cfg, "test-allowlist-lazy-query"),
            ReloadOutcome::Applied
        );
        for qtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::HTTPS,
            RecordType::SVCB,
        ] {
            assert!(matches!(decide("example.com", qtype), BlockDecision::Allow));
        }

        allowlist_slot().store(Arc::new(None));
        BLOCKLIST
            .get()
            .unwrap()
            .store(Arc::new(MultiCategoryDb::new()));
        db_cache().lock().unwrap().remove(&block_dir);
    }

    /// Builds a blocklist snapshot containing `domain` and an allowlist path
    /// that can never be opened, then returns the blocklist directory so the
    /// caller can evict it from the env cache.
    #[cfg(test)]
    fn seed_unopenable_allowlist_with_blocklist(temp: &Path, domain: &str) -> PathBuf {
        let corrupt = temp.join("allowlist.db");
        std::fs::write(&corrupt, b"not an lmdb env directory").unwrap();
        set_allowlist_path(&corrupt);

        let block_dir = temp.join("blocked.db");
        let db = BlocklistDb::open_for_write(&block_dir).unwrap();
        db.insert(&DomainName::new(domain).unwrap()).unwrap();
        drop(db);
        let cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![crate::lmdb::BlocklistEntry {
                name: "Test".into(),
                tag: "test".into(),
                db_path: block_dir.clone(),
                action: crate::lmdb::BlockAction::Nxdomain,
            }],
        };
        assert_eq!(
            reload_from_config(&cfg, "test-degraded-allowlist"),
            ReloadOutcome::Applied
        );
        block_dir
    }

    #[cfg(test)]
    fn clear_filtering_state(block_dir: &Path) {
        allowlist_slot().store(Arc::new(None));
        *allowlist_path_slot()
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
        if let Some(slot) = BLOCKLIST.get() {
            slot.store(Arc::new(MultiCategoryDb::new()));
        }
        db_cache()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(block_dir);
    }

    /// A filtering database is not a security boundary: when the allowlist
    /// cannot be read the resolver must keep answering, using the blocklist
    /// alone, instead of failing the query.
    #[test]
    fn decision_with_unopenable_allowlist_degrades_to_blocklist() {
        let _guard = lock();
        let tmp = tempfile::TempDir::new().unwrap();
        let block_dir = seed_unopenable_allowlist_with_blocklist(tmp.path(), "ads.example");

        assert!(
            matches!(
                decide("ads.example", RecordType::A),
                BlockDecision::Nxdomain
            ),
            "an unreadable allowlist must not stop the blocklist from filtering"
        );
        assert!(
            matches!(decide("safe.example", RecordType::A), BlockDecision::Allow),
            "an unreadable allowlist must behave as an empty allowlist"
        );

        clear_filtering_state(&block_dir);
    }

    /// `AllowlistDb::open` sets up a write transaction, so retrying it on
    /// every query turns a broken allowlist into a per-query cost. Inside the
    /// cooldown the query path must not touch `mdb_env_open` at all.
    #[test]
    fn failed_allowlist_open_is_backed_off() {
        let _guard = lock();
        let tmp = tempfile::TempDir::new().unwrap();
        let block_dir = seed_unopenable_allowlist_with_blocklist(tmp.path(), "ads.example");
        take_allowlist_open_attempts();

        for _ in 0..5 {
            let _ = decide("safe.example", RecordType::A);
        }
        assert_eq!(
            take_allowlist_open_attempts(),
            1,
            "queries inside the backoff window must not retry mdb_env_open"
        );

        // A management call is user-driven and must still surface the error,
        // which means it always attempts the open.
        assert!(get_or_open_allowlist().is_err());
        assert_eq!(
            take_allowlist_open_attempts(),
            1,
            "a management call must attempt the open even during cooldown"
        );

        clear_filtering_state(&block_dir);
    }

    #[test]
    fn cached_db_dropped_when_path_inode_changes() {
        let _guard = lock();
        use crate::lmdb::{BlockAction, BlocklistEntry};
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let db_dir = temp.path().join("category.db");
        drop(BlocklistDb::open_for_write(&db_dir).unwrap());

        let entry = BlocklistEntry {
            name: "Test".into(),
            tag: "test".into(),
            db_path: db_dir.clone(),
            action: BlockAction::Nxdomain,
        };
        let cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![entry.clone()],
        };
        build_db_from_config(&cfg, "test-load1");
        let inode1 = {
            let cache = db_cache().lock().unwrap();
            cache
                .get(&db_dir)
                .map(|c| c.inode)
                .expect("first load cached")
        };

        // In-place swap: rename the directory away and put a new env at the
        // same path.
        let old = temp.path().join("category.db.old");
        std::fs::rename(&db_dir, &old).unwrap();
        let replacement = temp.path().join("category.db.new");
        drop(BlocklistDb::open_for_write(&replacement).unwrap());
        std::fs::rename(&replacement, &db_dir).unwrap();

        // The inode changed, so the cache must not reuse the env.
        build_db_from_config(&cfg, "test-load2");
        let inode2 = {
            let cache = db_cache().lock().unwrap();
            cache
                .get(&db_dir)
                .map(|c| c.inode)
                .expect("second load cached")
        };
        assert_ne!(
            inode1, inode2,
            "post-rename reload must drop stale cached env and reopen"
        );

        // The tempdir drops at the end of the test, so remove its cache entry
        // or later tests calling `build_db_from_config` inherit a stale path.
        db_cache().lock().unwrap().remove(&db_dir);
    }

    #[test]
    fn cached_db_reuse_applies_current_metadata() {
        let _guard = lock();
        use crate::lmdb::{BlockAction, BlocklistEntry};
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let db_dir = temp.path().join("category.db");
        let entry = BlocklistEntry {
            name: "Test".into(),
            tag: "old-tag".into(),
            db_path: db_dir.clone(),
            action: BlockAction::Nxdomain,
        };
        let db = BlocklistDb::open_for_write(&db_dir).unwrap();
        db.insert(&DomainName::new("ads.example").unwrap()).unwrap();
        drop(db);

        let first_cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![entry],
        };
        let first = build_db_from_config(&first_cfg, "test-metadata1");
        let first_match = first
            .check_domain(&DomainName::new("ads.example").unwrap())
            .expect("first load should match");
        assert_eq!(first_match.tag, "old-tag");
        assert_eq!(first_match.action, BlockAction::Nxdomain);

        let second_cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![BlocklistEntry {
                name: "Test".into(),
                tag: "new-tag".into(),
                db_path: db_dir.clone(),
                action: BlockAction::Localhost,
            }],
        };
        let second = build_db_from_config(&second_cfg, "test-metadata2");
        let second_match = second
            .check_domain(&DomainName::new("ads.example").unwrap())
            .expect("second load should match");
        assert_eq!(second_match.tag, "new-tag");
        assert_eq!(second_match.action, BlockAction::Localhost);

        db_cache().lock().unwrap().remove(&db_dir);
    }

    #[test]
    fn reload_applies_new_versioned_db_while_previous_snapshot_is_live() {
        let _guard = lock();
        use crate::lmdb::{BlockAction, BlocklistEntry};
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let first_dir = temp.path().join("category.111.db");
        let second_dir = temp.path().join("category.222.db");

        let create_db = |path: &Path, domain: &str| {
            let db = BlocklistDb::open_for_write(path).unwrap();
            db.insert(&DomainName::new(domain).unwrap()).unwrap();
        };
        let cfg = |path: &Path| crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![BlocklistEntry {
                name: "Test".into(),
                tag: "test".into(),
                db_path: path.to_path_buf(),
                action: BlockAction::Nxdomain,
            }],
        };

        create_db(&first_dir, "old.example");
        let first_cfg = cfg(&first_dir);
        assert_eq!(
            reload_from_config(&first_cfg, "test-reload1"),
            ReloadOutcome::Applied
        );
        assert!(matches!(
            decide("old.example", RecordType::A),
            BlockDecision::Nxdomain
        ));

        create_db(&second_dir, "new.example");
        let second_cfg = cfg(&second_dir);
        assert_eq!(
            reload_from_config(&second_cfg, "test-reload2"),
            ReloadOutcome::Applied,
            "versioned path reload must not be blocked by the previous live env"
        );
        assert!(matches!(
            decide("old.example", RecordType::A),
            BlockDecision::Allow
        ));
        assert!(matches!(
            decide("new.example", RecordType::A),
            BlockDecision::Nxdomain
        ));

        BLOCKLIST
            .get()
            .unwrap()
            .store(Arc::new(MultiCategoryDb::new()));
        let mut cache = db_cache().lock().unwrap();
        cache.remove(&first_dir);
        cache.remove(&second_dir);
    }

    #[test]
    fn reload_keeps_previous_snapshot_when_open_fails() {
        let _guard = lock();
        use crate::lmdb::{BlockAction, BlocklistEntry};
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let good_dir = temp.path().join("good.db");
        drop(BlocklistDb::open_for_write(&good_dir).unwrap());

        let good_cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![BlocklistEntry {
                name: "Good".into(),
                tag: "good".into(),
                db_path: good_dir.clone(),
                action: BlockAction::Nxdomain,
            }],
        };
        assert_eq!(
            reload_from_config(&good_cfg, "test-good"),
            ReloadOutcome::Applied
        );
        assert_eq!(BLOCKLIST.get().unwrap().load().database_count(), 1);

        let bad_path = temp.path().join("bad.db");
        std::fs::write(&bad_path, b"not a directory").unwrap();
        let bad_cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![BlocklistEntry {
                name: "Bad".into(),
                tag: "bad".into(),
                db_path: bad_path,
                action: BlockAction::Nxdomain,
            }],
        };
        assert_eq!(
            reload_from_config(&bad_cfg, "test-bad"),
            ReloadOutcome::KeptPrevious { open_failed: 1 }
        );
        assert_eq!(
            BLOCKLIST.get().unwrap().load().database_count(),
            1,
            "failed reload must keep the previous live snapshot"
        );

        assert_eq!(
            reload_from_config(&good_cfg, "test-reapply"),
            ReloadOutcome::Applied
        );
        for index in 0..3 {
            let candidate_dir = temp.path().join(format!("candidate-{index}.db"));
            drop(BlocklistDb::open_for_write(&candidate_dir).unwrap());
            let mut candidate = bad_cfg.clone();
            let mut entry = good_cfg.blocklists[0].clone();
            entry.db_path = candidate_dir.clone();
            candidate.blocklists.push(entry);
            assert_eq!(
                reload_from_config(&candidate, "test-rejected-candidate"),
                ReloadOutcome::KeptPrevious { open_failed: 1 }
            );
            assert!(
                !db_cache().lock().unwrap().contains_key(&candidate_dir),
                "rejected candidate handles must not accumulate"
            );
            assert_eq!(
                reload_from_config(&good_cfg, "test-reapply-after-candidate"),
                ReloadOutcome::Applied
            );
        }

        BLOCKLIST
            .get()
            .unwrap()
            .store(Arc::new(MultiCategoryDb::new()));
        db_cache().lock().unwrap().remove(&good_dir);
    }

    #[test]
    fn reload_keeps_previous_snapshot_when_db_path_is_missing() {
        let _guard = lock();
        use crate::lmdb::{BlockAction, BlocklistEntry};
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let good_dir = temp.path().join("good.db");
        drop(BlocklistDb::open_for_write(&good_dir).unwrap());

        let good_cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![BlocklistEntry {
                name: "Good".into(),
                tag: "good".into(),
                db_path: good_dir.clone(),
                action: BlockAction::Nxdomain,
            }],
        };
        assert_eq!(
            reload_from_config(&good_cfg, "test-missing-good"),
            ReloadOutcome::Applied
        );

        let missing_cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![BlocklistEntry {
                name: "Missing".into(),
                tag: "missing".into(),
                db_path: temp.path().join("missing.db"),
                action: BlockAction::Nxdomain,
            }],
        };
        let outcome = reload_from_config(&missing_cfg, "test-missing-bad");
        assert_eq!(outcome, ReloadOutcome::PendingMissing { missing: 1 });
        assert!(
            outcome.accepted(),
            "a not-yet-downloaded DB must not be reported as a hard failure"
        );
        assert_eq!(
            BLOCKLIST.get().unwrap().load().database_count(),
            1,
            "missing DB path must not publish an empty snapshot"
        );

        assert_eq!(
            reload_from_config(&good_cfg, "test-reapply-after-missing"),
            ReloadOutcome::Applied
        );

        BLOCKLIST
            .get()
            .unwrap()
            .store(Arc::new(MultiCategoryDb::new()));
        db_cache().lock().unwrap().remove(&good_dir);
    }

    #[test]
    fn reload_treats_empty_selected_directory_as_pending_with_live_snapshot() {
        let _guard = lock();
        use crate::lmdb::{BlockAction, BlocklistEntry};
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let good_dir = temp.path().join("good.db");
        let pending_dir = temp.path().join("pending.db");
        drop(BlocklistDb::open_for_write(&good_dir).unwrap());
        std::fs::create_dir_all(&pending_dir).unwrap();

        let entry = |name: &str, path: PathBuf| BlocklistEntry {
            name: name.into(),
            tag: name.into(),
            db_path: path,
            action: BlockAction::Nxdomain,
        };
        let cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![
                entry("good", good_dir.clone()),
                entry("pending", pending_dir),
            ],
        };

        reset_for_tests(&[&good_dir]);
        assert_eq!(
            reload_from_config(&cfg, "test-empty-dir-first"),
            ReloadOutcome::Applied
        );
        assert_eq!(BLOCKLIST.get().unwrap().load().database_count(), 1);

        let second = reload_from_config(&cfg, "test-empty-dir-second");
        assert_eq!(second, ReloadOutcome::PendingMissing { missing: 1 });
        assert!(second.accepted());
        assert_eq!(
            BLOCKLIST.get().unwrap().load().database_count(),
            1,
            "the previous snapshot must stay live while the database download is pending"
        );

        reset_for_tests(&[&good_dir]);
    }

    #[test]
    fn reload_reports_corrupt_ahead_of_missing() {
        let _guard = lock();
        use crate::lmdb::{BlockAction, BlocklistEntry};
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let good_dir = temp.path().join("good.db");
        drop(BlocklistDb::open_for_write(&good_dir).unwrap());

        let entry = |name: &str, path: PathBuf| BlocklistEntry {
            name: name.into(),
            tag: name.into(),
            db_path: path,
            action: BlockAction::Nxdomain,
        };

        let good_cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![entry("good", good_dir.clone())],
        };
        assert_eq!(
            reload_from_config(&good_cfg, "test-mixed-good"),
            ReloadOutcome::Applied
        );

        let corrupt_path = temp.path().join("corrupt.db");
        std::fs::write(&corrupt_path, b"not a directory").unwrap();
        let mixed_cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![
                entry("corrupt", corrupt_path),
                entry("missing", temp.path().join("missing.db")),
            ],
        };
        let outcome = reload_from_config(&mixed_cfg, "test-mixed-bad");
        assert_eq!(outcome, ReloadOutcome::KeptPrevious { open_failed: 1 });
        assert!(
            !outcome.accepted(),
            "a corrupt DB stays a hard failure even alongside a missing one"
        );

        BLOCKLIST
            .get()
            .unwrap()
            .store(Arc::new(MultiCategoryDb::new()));
        db_cache().lock().unwrap().remove(&good_dir);
    }

    #[test]
    fn reload_keeps_previous_snapshot_when_stale_reopen_fails() {
        let _guard = lock();
        use crate::lmdb::{BlockAction, BlocklistEntry};
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let db_dir = temp.path().join("stale.db");
        drop(BlocklistDb::open_for_write(&db_dir).unwrap());

        let cfg = crate::lmdb::BlocklistConfig {
            enabled: true,
            blocklists: vec![BlocklistEntry {
                name: "Stale".into(),
                tag: "stale".into(),
                db_path: db_dir.clone(),
                action: BlockAction::Nxdomain,
            }],
        };
        assert_eq!(
            reload_from_config(&cfg, "test-stale-good"),
            ReloadOutcome::Applied
        );
        assert_eq!(BLOCKLIST.get().unwrap().load().database_count(), 1);

        let old = temp.path().join("stale.db.old");
        std::fs::rename(&db_dir, &old).unwrap();
        std::fs::write(&db_dir, b"not an lmdb directory").unwrap();

        assert_eq!(
            reload_from_config(&cfg, "test-stale-bad"),
            ReloadOutcome::KeptPrevious { open_failed: 1 }
        );
        assert_eq!(
            BLOCKLIST.get().unwrap().load().database_count(),
            1,
            "stale reopen failure must not publish an empty snapshot"
        );

        BLOCKLIST
            .get()
            .unwrap()
            .store(Arc::new(MultiCategoryDb::new()));
        db_cache().lock().unwrap().remove(&db_dir);
    }
}
