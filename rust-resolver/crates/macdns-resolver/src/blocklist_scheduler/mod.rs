// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! In-process blocklist scheduler. It runs in two phases so the boot HTTP
//! refresh does not race NetworkExtension activation:
//!
//! 1. `configure` loads LMDB synchronously and stores the paths in the slot.
//! 2. `start` spawns the refresh loop. The host calls it after `NetworkReadySignal`.
//!
//! Swift drives them through `dns_configure_blocklist` and
//! `dns_start_blocklist_scheduler`.

use crate::lmdb::BlocklistError;
use log::{info, warn};
use rand::{rng, RngExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::task::JoinHandle;

pub mod categories;
pub mod downloader;
pub mod paths;
pub mod settings;
pub mod sources;

/// Refresh cadence. Must match `MaintenanceManager.updateInterval` in
/// Sources/MacDNSAgent/Services/MaintenanceManager.swift. Changing it is a
/// behavior change, not cleanup.
const TICK_INTERVAL: Duration = Duration::from_secs(60 * 60);

struct SchedulerState {
    settings_path: PathBuf,
    blocklists_dir: PathBuf,
    handle: Option<JoinHandle<()>>,
}

static SCHEDULER: OnceLock<Mutex<Option<SchedulerState>>> = OnceLock::new();
/// The generation every refresh started since the last `stop()` belongs to.
static LIVE_GENERATION: Mutex<Option<Generation>> = Mutex::new(None);
// Periodic refresh and "Update Now" share temp and current paths, so the
// whole download/build/publish/reload sequence is serialized, not only the
// final swap.
static REFRESH_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static REFRESH_CALLBACK: OnceLock<Mutex<Option<RefreshCallback>>> = OnceLock::new();

/// What a forced refresh left the selected lists in. A selected list that is
/// not loaded at all is an error instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForcedRefresh {
    /// Every selected list was refreshed. `changed` says whether any file was
    /// published.
    Refreshed { changed: bool },
    /// Every selected list is loaded, but at least one could not be refreshed
    /// and keeps filtering with the database it already had.
    LoadedStale,
}

/// Callback invoked after a periodic blocklist refresh publishes changed files
/// without download or reload errors. The host owns user settings and
/// persists `last_updated`. Rust only reports the event.
pub type RefreshCallback = extern "C" fn();

/// One scheduler lifetime. `stop()` retires the live generation, and every
/// refresh operation carries the generation that started it: aborting the
/// scheduler task cannot cancel a `spawn_blocking` closure that already
/// started, so the closure re-checks its generation under the publication guard
/// before writing `.current` or `.info`.
#[derive(Clone, Debug)]
struct Generation {
    id: u64,
    live: Arc<AtomicBool>,
}

impl Generation {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            live: Arc::new(AtomicBool::new(true)),
        }
    }

    fn is_current(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }

    fn retire(&self) {
        self.live.store(false, Ordering::SeqCst);
    }
}

impl std::fmt::Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// The generation new refresh work joins, created on first use after a stop.
fn current_generation() -> Generation {
    let mut guard = LIVE_GENERATION.lock().unwrap_or_else(|p| p.into_inner());
    guard.get_or_insert_with(Generation::new).clone()
}

fn slot() -> &'static Mutex<Option<SchedulerState>> {
    SCHEDULER.get_or_init(|| Mutex::new(None))
}

fn refresh_lock() -> &'static tokio::sync::Mutex<()> {
    REFRESH_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Random 0–5min offset added to every tick so installs that booted at the
/// same wall-clock moment (fleet OS update, synchronized logins) don't hit
/// the Hagezi CDN at the same second every hour.
fn refresh_jitter() -> Duration {
    Duration::from_secs(rng().random_range(0..=300))
}

fn callback_slot() -> &'static Mutex<Option<RefreshCallback>> {
    REFRESH_CALLBACK.get_or_init(|| Mutex::new(None))
}

pub fn set_refresh_callback(cb: RefreshCallback) {
    let mut guard = callback_slot().lock().unwrap_or_else(|p| p.into_inner());
    *guard = Some(cb);
}

fn emit_refresh_completed() {
    let cb = *callback_slot().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(cb) = cb {
        cb();
    }
}

/// Loads LMDB from the current settings file and stores the paths in the
/// scheduler slot. Does not spawn the refresh task. Call `start()` after the
/// host's `NetworkReadySignal` releases so the boot HTTP refresh does not race
/// NetworkExtension activation. Idempotent: when the slot is already populated
/// the LMDB reload still applies and any existing task is left alone.
pub fn configure(settings_path: &Path) -> Result<(), BlocklistError> {
    configure_in(settings_path, PathBuf::from(paths::blocklists_path()))
}

fn configure_in(settings_path: &Path, blocklists_dir: PathBuf) -> Result<(), BlocklistError> {
    // Applied right away so the running resolver uses the current list before
    // the refresh loop fires.
    let cfg = settings::load_config(settings_path, &blocklists_dir)?;
    match crate::blocklist::reload_from_config(&cfg, "scheduler-configure") {
        crate::blocklist::ReloadOutcome::Applied => {}
        crate::blocklist::ReloadOutcome::PendingMissing { missing } => {
            // The selection is valid but its databases are not downloaded
            // yet. Accepting it keeps the host from rolling the user's
            // category choice back. The refresh loop publishes them.
            info!(
                "blocklist configure: {missing} selected database(s) not downloaded yet; previous snapshot stays live until the next refresh"
            );
        }
        crate::blocklist::ReloadOutcome::KeptPrevious { open_failed } => {
            return Err(BlocklistError::Config(format!(
                "blocklist reload kept previous snapshot because {open_failed} database(s) failed to open"
            )));
        }
    }

    let mut guard = slot().lock().unwrap_or_else(|p| p.into_inner());
    if guard.is_none() {
        *guard = Some(SchedulerState {
            settings_path: settings_path.to_path_buf(),
            blocklists_dir,
            handle: None,
        });
    }
    // An already populated slot stays as it is, and a running task keeps its
    // captured paths. The settings file path does not change in practice, only
    // its content does.

    Ok(())
}

/// Spawn the refresh loop on the resolver's Tokio runtime. Must be called
/// after `configure`. Runs one boot refresh immediately, then ticks every
/// hour. Idempotent: a second call is a no-op once the task is running.
/// The host defers this call until `NetworkReadySignal` releases so the
/// boot refresh does not race Content-Filter activation (which kills
/// in-flight reqwest connections and forces a 60s timeout).
pub fn start() -> Result<(), BlocklistError> {
    let mut guard = slot().lock().unwrap_or_else(|p| p.into_inner());

    let state = match guard.as_mut() {
        Some(s) => s,
        None => {
            return Err(BlocklistError::Config(
                "blocklist scheduler not configured — call configure() first".into(),
            ))
        }
    };

    if state.handle.as_ref().is_some_and(|h| h.is_finished()) {
        state.handle = None;
    }

    if state.handle.is_some() {
        return Ok(());
    }

    let settings_path_owned = state.settings_path.clone();
    let blocklists_dir_clone = state.blocklists_dir.clone();
    let generation = current_generation();
    // Must spawn on the resolver's dedicated runtime. `tokio::spawn` would
    // panic here because this FFI is called synchronously outside any reactor
    // context.
    let handle = crate::runtime::spawn(async move {
        // One refresh on boot so a first-run install populates LMDBs without
        // waiting an hour. Failures are logged and the periodic refresh
        // retries.
        refresh_tick(&settings_path_owned, &blocklists_dir_clone, &generation).await;
        loop {
            tokio::time::sleep(TICK_INTERVAL + refresh_jitter()).await;
            refresh_tick(&settings_path_owned, &blocklists_dir_clone, &generation).await;
        }
    })
    .map_err(BlocklistError::Config)?;

    state.handle = Some(handle);

    Ok(())
}

/// Trigger an immediate refresh and block until it completes. Used by the
/// FFI `dns_force_blocklist_update_status` for "Update Now", first enable and
/// category changes. "Force" means "now", not "unconditional": every file
/// still revalidates with its stored ETag, so a run with nothing new upstream
/// normally costs one 304 per file instead of re-downloading every list. The
/// primary and backup CDNs share one `.info` but issue different validators,
/// so a failover can still cost one full download per file.
/// Errors when the scheduler was never configured or a selected list is not
/// loaded afterwards.
pub fn force_update() -> Result<ForcedRefresh, BlocklistError> {
    let (settings_path, blocklists_dir) = {
        let guard = slot().lock().unwrap_or_else(|p| p.into_inner());
        match guard.as_ref() {
            Some(s) => (s.settings_path.clone(), s.blocklists_dir.clone()),
            None => {
                return Err(BlocklistError::Config(
                    "blocklist scheduler not configured".into(),
                ))
            }
        }
    };

    let generation = current_generation();
    // Run the refresh on the resolver's runtime so the caller blocks until
    // every category finished downloading, not just until we handed the task
    // off.
    let result = crate::runtime::block_on(async move {
        force_refresh_inline(&settings_path, &blocklists_dir, &generation).await
    })
    .map_err(BlocklistError::Config)?;

    result
}

async fn force_refresh_inline(
    settings_path: &Path,
    blocklists_dir: &Path,
    generation: &Generation,
) -> Result<ForcedRefresh, BlocklistError> {
    let _refresh_guard = refresh_lock().lock().await;
    let reports = downloader::refresh_all(blocklists_dir, generation).await;
    conclude_forced_refresh(settings_path, blocklists_dir, &reports, generation).await
}

async fn conclude_forced_refresh(
    settings_path: &Path,
    blocklists_dir: &Path,
    reports: &[downloader::UpdateReport],
    generation: &Generation,
) -> Result<ForcedRefresh, BlocklistError> {
    let changed = reports.iter().any(|r| r.changed);
    let errors = reports.iter().filter(|r| r.error.is_some()).count();
    let translated = settings::load_config_with_generation(settings_path, blocklists_dir)?;
    reload_after_refresh(&translated, changed, errors, "scheduler-force", generation).await?;

    // Every list the UI can show is refreshed, selected or not. Only the
    // selected ones decide the result. The others were logged per file.
    let selected_errors: Vec<String> = reports
        .iter()
        .filter(|r| {
            r.db_path
                .as_ref()
                .is_none_or(|path| translated.selected_base_paths.contains(path))
        })
        .filter_map(|r| r.error.as_ref().map(|e| format!("[{}] {}", r.filename, e)))
        .collect();

    let full_tif_absent = translated.full_tif_generation == settings::FullTifGeneration::FakeOnly;
    if full_tif_absent || !crate::blocklist::live_snapshot_covers(&translated.config) {
        return Err(BlocklistError::Config(format!(
            "selected blocklist database(s) are not loaded after the refresh: {}",
            selected_errors.join("; ")
        )));
    }

    if errors > selected_errors.len() {
        info!(
            "blocklist scheduler-force: {} list(s) outside the selection failed to refresh",
            errors - selected_errors.len()
        );
    }
    if selected_errors.is_empty() {
        Ok(ForcedRefresh::Refreshed { changed })
    } else {
        warn!(
            "blocklist scheduler-force: selected list(s) keep their previous database: {}",
            selected_errors.join("; ")
        );
        Ok(ForcedRefresh::LoadedStale)
    }
}

/// Stop the scheduler. Idempotent.
pub fn stop() {
    // Retire before dropping the handle: `abort()` leaves any already-started
    // `spawn_blocking` closure running, and that closure must already see its
    // generation as retired when it reaches its publication guard.
    retire_generation();
    let mut guard = slot().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(prev) = guard.take() {
        if let Some(h) = prev.handle {
            h.abort();
            info!("blocklist scheduler stopped");
        }
    }
}

/// Retires under the publication guard so the retirement is atomic with respect
/// to the commit and live-reload paths: a closure that already passed its
/// generation check finishes its writes first, and one that has not reached the
/// check yet finds the generation gone. Lock order is the commit guard, then
/// `LIVE_GENERATION`. No path holds `LIVE_GENERATION` while taking the commit
/// guard.
fn retire_generation() {
    let _commit = downloader::commit_guard();
    let mut guard = LIVE_GENERATION.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(generation) = guard.take() {
        generation.retire();
    }
}

/// One periodic refresh driven by the scheduler loop. Errors are logged and
/// never escape, because the loop must keep running across transient failures.
async fn refresh_tick(settings_path: &Path, blocklists_dir: &Path, generation: &Generation) {
    let _refresh_guard = refresh_lock().lock().await;
    let reports = downloader::refresh_all(blocklists_dir, generation).await;
    let changed = reports.iter().any(|r| r.changed);
    let errors = reports.iter().filter(|r| r.error.is_some()).count();
    info!(
        "blocklist scheduler: refresh complete total={} changed={} errors={}",
        reports.len(),
        reports.iter().filter(|r| r.changed).count(),
        errors
    );
    let reload_ok = match apply_post_refresh(
        settings_path,
        blocklists_dir,
        changed,
        errors,
        "scheduler-tick",
        generation,
    )
    .await
    {
        Ok(()) => true,
        Err(error) => {
            warn!("blocklist scheduler: post-refresh apply failed: {}", error);
            false
        }
    };

    if should_emit_refresh_completed(changed, errors, reload_ok) {
        emit_refresh_completed();
    }
}

async fn apply_post_refresh(
    settings_path: &Path,
    blocklists_dir: &Path,
    changed: bool,
    source_errors: usize,
    reload_source: &'static str,
    scheduler_generation: &Generation,
) -> Result<(), BlocklistError> {
    let translated = settings::load_config_with_generation(settings_path, blocklists_dir)?;
    reload_after_refresh(
        &translated,
        changed,
        source_errors,
        reload_source,
        scheduler_generation,
    )
    .await
}

async fn reload_after_refresh(
    translated: &settings::TranslatedConfig,
    changed: bool,
    source_errors: usize,
    reload_source: &'static str,
    scheduler_generation: &Generation,
) -> Result<(), BlocklistError> {
    let generation = translated.full_tif_generation;
    if !should_reload_after_refresh(changed, generation) {
        return Ok(());
    }

    let config = translated.config.clone();
    let reload_generation = scheduler_generation.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        // Same guard the commit path uses: without it the retirement can land
        // between this check and the swap, and a stale generation hot-reloads
        // its snapshot over the one the live generation published.
        let _commit = downloader::commit_guard();
        reload_generation.is_current().then(|| {
            let outcome = crate::blocklist::reload_from_config(&config, reload_source);
            (outcome, crate::blocklist::live_snapshot_covers(&config))
        })
    })
    .await
    .map_err(|error| BlocklistError::Config(format!("blocklist reload task failed: {error}")))?;

    let Some((outcome, selection_loaded)) = outcome else {
        info!(
            "blocklist {reload_source}: reload skipped; generation {scheduler_generation} retired"
        );
        return Ok(());
    };

    match outcome {
        // With nothing live before it, a reload publishes whatever opened.
        crate::blocklist::ReloadOutcome::Applied if !selection_loaded => {
            return Err(BlocklistError::Config(
                "blocklist reload published a snapshot without every selected database".into(),
            ));
        }
        crate::blocklist::ReloadOutcome::Applied => {}
        crate::blocklist::ReloadOutcome::PendingMissing { missing } => {
            return Err(BlocklistError::Config(format!(
                "blocklist reload kept previous snapshot because {missing} database(s) are still not downloaded after a refresh"
            )));
        }
        crate::blocklist::ReloadOutcome::KeptPrevious { open_failed } => {
            return Err(BlocklistError::Config(format!(
                "blocklist reload kept previous snapshot because {open_failed} database(s) failed to open"
            )));
        }
    }

    if let Some(retired) = retired_full_tif_cleanup_path(
        source_errors,
        generation,
        outcome,
        translated.retired_full_tif_path.as_deref(),
    ) {
        if let Err(error) = crate::lmdb::paths::remove_stable_db_and_current_version(retired) {
            warn!(
                "blocklist {}: failed to remove retired Full TIF database {}: {}",
                reload_source,
                retired.display(),
                error
            );
        }
    }

    Ok(())
}

fn should_reload_after_refresh(changed: bool, generation: settings::FullTifGeneration) -> bool {
    changed || generation.migration_pending()
}

fn retired_full_tif_cleanup_path(
    source_errors: usize,
    generation: settings::FullTifGeneration,
    outcome: crate::blocklist::ReloadOutcome,
    retired_full_tif_path: Option<&Path>,
) -> Option<&Path> {
    if source_errors == 0
        && generation.migration_pending()
        && outcome == crate::blocklist::ReloadOutcome::Applied
    {
        retired_full_tif_path
    } else {
        None
    }
}

fn should_emit_refresh_completed(changed: bool, errors: usize, reload_ok: bool) -> bool {
    changed && errors == 0 && reload_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    static TEST_REFRESH_CALLBACK_COUNT: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn count_refresh_callback() {
        TEST_REFRESH_CALLBACK_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn refresh_callback_emits_registered_host_signal() {
        TEST_REFRESH_CALLBACK_COUNT.store(0, Ordering::SeqCst);
        set_refresh_callback(count_refresh_callback);

        emit_refresh_completed();

        assert_eq!(TEST_REFRESH_CALLBACK_COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn refresh_callback_requires_changed_files_and_clean_reload() {
        assert!(should_emit_refresh_completed(true, 0, true));
        assert!(!should_emit_refresh_completed(false, 0, true));
        assert!(!should_emit_refresh_completed(true, 1, true));
        assert!(!should_emit_refresh_completed(true, 0, false));
    }

    #[test]
    fn post_refresh_reload_includes_pending_migration() {
        use settings::FullTifGeneration::*;

        assert!(should_reload_after_refresh(true, NotSelected));
        assert!(should_reload_after_refresh(
            false,
            Split {
                retired_stable_present: true
            }
        ));
        assert!(!should_reload_after_refresh(
            false,
            Split {
                retired_stable_present: false
            }
        ));
        assert!(!should_reload_after_refresh(false, Legacy));
        assert!(!should_reload_after_refresh(false, FakeOnly));
    }

    #[test]
    fn retired_tif_cleanup_path_requires_clean_refresh_and_applied_split() {
        let pending = settings::FullTifGeneration::Split {
            retired_stable_present: true,
        };
        let retired = Path::new("/blocklists/malware_security_tif.db");

        assert_eq!(
            retired_full_tif_cleanup_path(
                0,
                pending,
                crate::blocklist::ReloadOutcome::Applied,
                Some(retired)
            ),
            Some(retired)
        );
        assert_eq!(
            retired_full_tif_cleanup_path(
                1,
                pending,
                crate::blocklist::ReloadOutcome::Applied,
                Some(retired)
            ),
            None
        );
        assert_eq!(
            retired_full_tif_cleanup_path(
                0,
                pending,
                crate::blocklist::ReloadOutcome::KeptPrevious { open_failed: 1 },
                Some(retired)
            ),
            None
        );
        assert_eq!(
            retired_full_tif_cleanup_path(
                0,
                pending,
                crate::blocklist::ReloadOutcome::Applied,
                None
            ),
            None
        );
        for generation in [
            settings::FullTifGeneration::NotSelected,
            settings::FullTifGeneration::FakeOnly,
            settings::FullTifGeneration::Legacy,
            settings::FullTifGeneration::Split {
                retired_stable_present: false,
            },
        ] {
            assert_eq!(
                retired_full_tif_cleanup_path(
                    0,
                    generation,
                    crate::blocklist::ReloadOutcome::Applied,
                    Some(retired)
                ),
                None
            );
        }
    }

    fn publish_test_db(base_path: &Path, digest: &str) -> PathBuf {
        let versioned_path = crate::lmdb::paths::versioned_db_path(base_path, digest);
        drop(crate::lmdb::BlocklistDb::open_for_write(&versioned_path).unwrap());
        crate::lmdb::paths::publish_current_db_path(base_path, &versioned_path).unwrap();
        versioned_path
    }

    #[test]
    fn retired_cleanup_path_uses_configured_subdirectory() {
        let temp = TempDir::new().unwrap();
        let effective_dir = temp.path().join("configured");
        std::fs::create_dir_all(&effective_dir).unwrap();

        let retired = effective_dir.join("malware_security_tif.db");
        publish_test_db(&retired, "123456789abcdef0123456789abcdef0");
        publish_test_db(
            &effective_dir.join("malware_security_tif-1.db"),
            "23456789abcdef0123456789abcdef01",
        );
        publish_test_db(
            &effective_dir.join("malware_security_tif-2.db"),
            "3456789abcdef0123456789abcdef012",
        );

        let root_sentinel = temp.path().join("malware_security_tif.db");
        publish_test_db(&root_sentinel, "456789abcdef0123456789abcdef0123");
        let settings_path = temp.path().join("blocklist_settings.json");
        std::fs::write(
            &settings_path,
            serde_json::json!({
                "version": 1,
                "enabled": true,
                "db_base_path": effective_dir,
                "categories": [{
                    "name": "Malware & Security Ultimate",
                    "identifier": "malware_security",
                    "level": "tif",
                    "action": "nxdomain",
                    "enabled": true
                }]
            })
            .to_string(),
        )
        .unwrap();

        let translated =
            settings::load_config_with_generation(&settings_path, temp.path()).unwrap();
        let cleanup_path = retired_full_tif_cleanup_path(
            0,
            translated.full_tif_generation,
            crate::blocklist::ReloadOutcome::Applied,
            translated.retired_full_tif_path.as_deref(),
        );

        assert_eq!(cleanup_path, Some(retired.as_path()));
        assert_ne!(cleanup_path, Some(root_sentinel.as_path()));
    }

    fn write_settings(path: &Path, db_base_path: &Path, identifier: &str, level: &str) {
        std::fs::write(
            path,
            serde_json::json!({
                "version": 1,
                "enabled": true,
                "db_base_path": db_base_path,
                "categories": [{
                    "name": identifier,
                    "identifier": identifier,
                    "level": level,
                    "action": "nxdomain",
                    "enabled": true
                }]
            })
            .to_string(),
        )
        .unwrap();
    }

    #[test]
    fn configure_accepts_missing_selected_db_as_pending() {
        let _guard = crate::blocklist::test_lock();
        stop();

        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_path_buf();
        let published = publish_test_db(
            &dir.join("ads_trackers_normal.db"),
            "0123456789abcdef0123456789abcdef",
        );

        let settings_path = dir.join("blocklist_settings.json");
        write_settings(&settings_path, &dir, "ads_trackers", "normal");
        configure_in(&settings_path, dir.clone()).expect("published category must configure");
        assert_eq!(crate::blocklist::live_database_count(), 1);

        // A category whose database was never downloaded.
        let pending_path = dir.join("blocklist_settings_pending.json");
        write_settings(&pending_path, &dir, "gambling", "normal");
        configure_in(&pending_path, dir.clone())
            .expect("a not-yet-downloaded category must not fail configure");
        assert_eq!(
            crate::blocklist::live_database_count(),
            1,
            "the previous snapshot must stay live while the download is pending"
        );

        stop();
        crate::blocklist::reset_for_tests(&[&published]);
    }

    #[test]
    fn configure_without_settings_file_errors() {
        // `load_config` errors must surface instead of spawning a refresh
        // loop against an unreadable file, which would leave the agent
        // "configured" with an empty blocklist and no feedback to the host.
        let missing = std::path::PathBuf::from("/nonexistent/does/not/exist/settings.json");
        let res = configure(&missing);
        assert!(res.is_err(), "configure should fail on missing path");
    }

    #[test]
    fn force_update_without_configure_errors() {
        // When the scheduler was never configured (first run before
        // dns_configure_blocklist), dns_force_blocklist_update_status must report an
        // error rather than block forever on a refresh nobody scheduled.
        stop(); // ensure clean slot
        let res = force_update();
        assert!(res.is_err(), "force_update without configure must error");
    }

    #[test]
    fn stop_retires_the_generation_in_flight_work_carries() {
        // `abort()` cannot cancel a `spawn_blocking` closure that already
        // started, so the closure's own generation has to read as retired the
        // moment `stop()` returns. That is what keeps it from publishing.
        let generation = current_generation();

        stop();

        assert!(!generation.is_current());
    }

    /// Retiring outside the publication guard leaves an interleaving open: an
    /// old closure passes `is_current()`, the retirement lands, and the closure
    /// publishes anyway. The retirement has to wait for the guard.
    #[test]
    fn retiring_a_generation_waits_for_the_publication_guard() {
        // Guard first: with it held nothing can retire, so the generation read
        // next is guaranteed to still be live when the assertions run.
        let commit = downloader::commit_guard();
        let generation = current_generation();
        let (done, retired) = std::sync::mpsc::channel();

        let retire = std::thread::spawn(move || {
            retire_generation();
            let _ = done.send(());
        });

        assert!(
            retired.recv_timeout(Duration::from_millis(200)).is_err(),
            "a retirement must not land while a publication holds the guard"
        );
        assert!(generation.is_current());

        drop(commit);

        retired
            .recv_timeout(Duration::from_secs(5))
            .expect("the retirement must land once the publication releases the guard");
        retire.join().unwrap();
        assert!(!generation.is_current());
    }

    /// The live reload shares the same split: checking the generation and then
    /// swapping the snapshot without the publication guard lets a retired
    /// generation hot-reload over the snapshot the live one published.
    #[test]
    fn live_reload_waits_for_the_publication_guard() {
        let _guard = crate::blocklist::test_lock();
        stop();

        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_path_buf();
        let ads = publish_test_db(
            &dir.join("ads_trackers_normal.db"),
            "0123456789abcdef0123456789abcdef",
        );
        let gambling = publish_test_db(
            &dir.join("gambling_normal.db"),
            "fedcba9876543210fedcba9876543210",
        );

        let one_category = dir.join("blocklist_settings.json");
        write_settings(&one_category, &dir, "ads_trackers", "normal");
        configure_in(&one_category, dir.clone()).expect("published category must configure");
        assert_eq!(crate::blocklist::live_database_count(), 1);

        let two_categories = dir.join("blocklist_settings_two.json");
        std::fs::write(
            &two_categories,
            serde_json::json!({
                "version": 1,
                "enabled": true,
                "db_base_path": dir,
                "categories": [
                    {
                        "name": "ads_trackers",
                        "identifier": "ads_trackers",
                        "level": "normal",
                        "action": "nxdomain",
                        "enabled": true
                    },
                    {
                        "name": "gambling",
                        "identifier": "gambling",
                        "level": "normal",
                        "action": "nxdomain",
                        "enabled": true
                    }
                ]
            })
            .to_string(),
        )
        .unwrap();

        let retired = Generation::new();
        retired.retire();
        run_post_refresh(&two_categories, &dir, &retired).expect("a retired reload must not fail");
        assert_eq!(
            crate::blocklist::live_database_count(),
            1,
            "a retired generation must not swap the live snapshot"
        );

        // Stands in for a publication that already passed its generation check.
        let commit = downloader::commit_guard();
        let live = Generation::new();
        let settings_for_thread = two_categories.clone();
        let dir_for_thread = dir.clone();
        let (done, reloaded) = std::sync::mpsc::channel();
        let reload = std::thread::spawn(move || {
            run_post_refresh(&settings_for_thread, &dir_for_thread, &live)
                .expect("the live reload must succeed");
            let _ = done.send(());
        });

        assert!(
            reloaded.recv_timeout(Duration::from_millis(200)).is_err(),
            "a live reload must not swap the snapshot while a publication holds the guard"
        );
        assert_eq!(crate::blocklist::live_database_count(), 1);

        drop(commit);

        reloaded
            .recv_timeout(Duration::from_secs(10))
            .expect("the live reload must proceed once the guard is released");
        reload.join().unwrap();
        assert_eq!(crate::blocklist::live_database_count(), 2);

        stop();
        crate::blocklist::reset_for_tests(&[&ads, &gambling]);
    }

    /// Drives `apply_post_refresh` on a private runtime so the caller can hold a
    /// synchronous guard while it runs.
    fn run_post_refresh(
        settings_path: &Path,
        blocklists_dir: &Path,
        generation: &Generation,
    ) -> Result<(), BlocklistError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(apply_post_refresh(
                settings_path,
                blocklists_dir,
                /* changed */ true,
                0,
                "test-reload",
                generation,
            ))
    }

    /// With nothing live before it, a reload publishes whatever opened and
    /// reports `Applied`. A refresh that leaves a selected list without a
    /// database must still fail.
    #[test]
    fn post_refresh_reload_fails_when_nothing_was_live_and_a_selected_list_is_missing() {
        let _guard = crate::blocklist::test_lock();
        stop();
        crate::blocklist::reset_for_tests(&[]);

        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_path_buf();
        let settings_path = dir.join("blocklist_settings.json");
        write_settings(&settings_path, &dir, "ads_tracking", "multi");

        let outcome = run_post_refresh(&settings_path, &dir, &Generation::new());

        assert!(
            outcome.is_err(),
            "a selected list with no database must fail the refresh: {outcome:?}"
        );

        stop();
        crate::blocklist::reset_for_tests(&[]);
    }

    fn report(db_path: &Path, error: Option<&str>) -> downloader::UpdateReport {
        downloader::UpdateReport {
            filename: db_path.display().to_string(),
            db_path: Some(db_path.to_path_buf()),
            changed: false,
            error: error.map(str::to_string),
        }
    }

    /// Drives the part of a forced refresh that runs after the downloads, with
    /// the download reports a test chooses.
    fn conclude_forced(
        settings_path: &Path,
        blocklists_dir: &Path,
        reports: &[downloader::UpdateReport],
    ) -> Result<ForcedRefresh, BlocklistError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(conclude_forced_refresh(
                settings_path,
                blocklists_dir,
                reports,
                &Generation::new(),
            ))
    }

    /// The refresh downloads every list the UI can show. One of those failing
    /// must not fail a save or an "Update Now" for the lists the user selected.
    #[test]
    fn forced_refresh_ignores_a_failure_in_a_list_that_is_not_selected() {
        let _guard = crate::blocklist::test_lock();
        stop();
        crate::blocklist::reset_for_tests(&[]);

        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_path_buf();
        let selected = dir.join("ads_tracking_multi.db");
        let published = publish_test_db(&selected, "0123456789abcdef0123456789abcdef");
        let settings_path = dir.join("blocklist_settings.json");
        write_settings(&settings_path, &dir, "ads_tracking", "multi");
        configure_in(&settings_path, dir.clone()).expect("published category must configure");

        let outcome = conclude_forced(
            &settings_path,
            &dir,
            &[
                report(&selected, None),
                report(&dir.join("gambling_gambling.db"), Some("timeout")),
            ],
        );

        assert_eq!(
            outcome.expect("a list nobody selected must not fail the refresh"),
            ForcedRefresh::Refreshed { changed: false }
        );
        assert_eq!(crate::blocklist::live_database_count(), 1);

        stop();
        crate::blocklist::reset_for_tests(&[&published]);
    }

    /// A selected list that could not be refreshed keeps filtering with the
    /// database it already had. The caller decides what stale means for it.
    #[test]
    fn forced_refresh_reports_a_selected_list_that_failed_but_is_loaded_as_stale() {
        let _guard = crate::blocklist::test_lock();
        stop();
        crate::blocklist::reset_for_tests(&[]);

        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_path_buf();
        let selected = dir.join("ads_tracking_multi.db");
        let published = publish_test_db(&selected, "0123456789abcdef0123456789abcdef");
        let settings_path = dir.join("blocklist_settings.json");
        write_settings(&settings_path, &dir, "ads_tracking", "multi");
        configure_in(&settings_path, dir.clone()).expect("published category must configure");

        let outcome = conclude_forced(&settings_path, &dir, &[report(&selected, Some("timeout"))]);

        assert_eq!(
            outcome.expect("a loaded list must not fail the refresh"),
            ForcedRefresh::LoadedStale
        );
        assert_eq!(crate::blocklist::live_database_count(), 1);

        stop();
        crate::blocklist::reset_for_tests(&[&published]);
    }

    /// A failure that names no list (the output directory, a panicked worker)
    /// may have hit a selected one, so it cannot count as refreshed.
    #[test]
    fn forced_refresh_treats_an_unattributed_failure_as_a_selected_one() {
        let _guard = crate::blocklist::test_lock();
        stop();
        crate::blocklist::reset_for_tests(&[]);

        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_path_buf();
        let published = publish_test_db(
            &dir.join("ads_tracking_multi.db"),
            "0123456789abcdef0123456789abcdef",
        );
        let settings_path = dir.join("blocklist_settings.json");
        write_settings(&settings_path, &dir, "ads_tracking", "multi");
        configure_in(&settings_path, dir.clone()).expect("published category must configure");

        let unattributed = downloader::UpdateReport {
            filename: "<panicked>".into(),
            db_path: None,
            changed: false,
            error: Some("task panicked".into()),
        };
        let outcome = conclude_forced(&settings_path, &dir, &[unattributed]);

        assert_eq!(outcome.unwrap(), ForcedRefresh::LoadedStale);

        stop();
        crate::blocklist::reset_for_tests(&[&published]);
    }

    /// First enable: nothing is live yet, so the reload publishes whatever
    /// opened and reports `Applied` even though the selected list is absent.
    #[test]
    fn forced_refresh_fails_when_a_selected_list_was_never_downloaded() {
        let _guard = crate::blocklist::test_lock();
        stop();
        crate::blocklist::reset_for_tests(&[]);

        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_path_buf();
        let selected = dir.join("ads_tracking_multi.db");
        let settings_path = dir.join("blocklist_settings.json");
        write_settings(&settings_path, &dir, "ads_tracking", "multi");
        configure_in(&settings_path, dir.clone()).expect("a pending category must configure");

        let outcome = conclude_forced(&settings_path, &dir, &[report(&selected, Some("timeout"))]);

        assert!(
            outcome.is_err(),
            "a selected list with no database must fail: {outcome:?}"
        );
        assert_eq!(crate::blocklist::live_database_count(), 0);

        stop();
        crate::blocklist::reset_for_tests(&[]);
    }

    /// Level change: the previous selection stays live while the new one has
    /// no database, so the new selection is not what filters.
    #[test]
    fn forced_refresh_fails_when_the_new_selection_is_not_what_is_loaded() {
        let _guard = crate::blocklist::test_lock();
        stop();
        crate::blocklist::reset_for_tests(&[]);

        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_path_buf();
        let published = publish_test_db(
            &dir.join("ads_tracking_multi.db"),
            "0123456789abcdef0123456789abcdef",
        );
        let settings_path = dir.join("blocklist_settings.json");
        write_settings(&settings_path, &dir, "ads_tracking", "multi");
        configure_in(&settings_path, dir.clone()).expect("published category must configure");

        let next_level = dir.join("ads_tracking_pro.db");
        write_settings(&settings_path, &dir, "ads_tracking", "pro");
        configure_in(&settings_path, dir.clone()).expect("a pending level must configure");

        let outcome = conclude_forced(
            &settings_path,
            &dir,
            &[report(&next_level, Some("timeout"))],
        );

        assert!(
            outcome.is_err(),
            "a selection that is not loaded must fail: {outcome:?}"
        );
        assert_eq!(
            crate::blocklist::live_database_count(),
            1,
            "the previous selection keeps filtering"
        );

        stop();
        crate::blocklist::reset_for_tests(&[&published]);
    }

    /// Ultimate is the fake list plus the split TIF parts. With the parts
    /// absent the reload still applies the fake list alone, which is not the
    /// list the user selected.
    #[test]
    fn forced_refresh_fails_when_full_tif_has_only_its_fake_list() {
        let _guard = crate::blocklist::test_lock();
        stop();
        crate::blocklist::reset_for_tests(&[]);

        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_path_buf();
        let fake = publish_test_db(
            &dir.join("malware_security_fake.db"),
            "0123456789abcdef0123456789abcdef",
        );
        let settings_path = dir.join("blocklist_settings.json");
        write_settings(&settings_path, &dir, "malware_security", "tif");
        configure_in(&settings_path, dir.clone()).expect("the fake list must configure");
        assert_eq!(crate::blocklist::live_database_count(), 1);

        let outcome = conclude_forced(
            &settings_path,
            &dir,
            &[report(
                &dir.join("malware_security_tif-1.db"),
                Some("timeout"),
            )],
        );

        assert!(
            outcome.is_err(),
            "Ultimate without its TIF parts must fail: {outcome:?}"
        );

        stop();
        crate::blocklist::reset_for_tests(&[&fake]);
    }

    #[test]
    fn start_without_configure_errors() {
        // `start` must refuse to spawn before `configure` has stored paths.
        // An empty slot means there is no settings file to drive the loop.
        stop(); // ensure clean slot
        let res = start();
        assert!(res.is_err(), "start without configure must error");
    }
}
