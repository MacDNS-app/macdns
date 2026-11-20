// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! Async blocklist download driver. It runs on the resolver's existing Tokio
//! runtime, with no rayon pool and no blocking reqwest.
//!
//! Responsibilities, per-URL:
//!   1. `download_with_cache` (primary URL, falls back to backup on failure).
//!   2. On 304 Not Modified: keep current DB only when the published LMDB is
//!      already valid.
//!   3. On 2xx: write downloaded bytes to a temp file, SHA-256 it, skip LMDB
//!      rebuild when the digest matches the previous run, otherwise rebuild the
//!      LMDB under a content-versioned path (`name.<sha256>.db`) and publish
//!      that path through the stable `name.db/.current` pointer.
//!   4. Always update `.info` with the freshest ETag + SHA-256.
//!
//! Parallelism: up to `MAX_CONCURRENT` downloads in flight, driven by a
//! `futures::stream::FuturesUnordered` of per-URL futures. LMDB writes run
//! inside `tokio::task::spawn_blocking` because heed issues synchronous
//! file I/O.

use super::sources::{hagezi_urls, BlocklistUrl};
use super::Generation;
use crate::lmdb::paths::{
    current_db_matches, publish_current_db_path, sync_dir, versioned_db_path,
};
use crate::lmdb::{
    BlocklistDb, BlocklistError, DomainListParser, DownloadResult, FileMetadata, HttpDownloader,
    Result,
};
use futures::stream::{FuturesUnordered, StreamExt};
use log::{debug, error, info, warn};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Full (category × level) product the scheduler refreshes. It lists every
/// level the UI can show, including unselected ones, so a user switching to a
/// new level does not wait for the next refresh tick.
const CATEGORIES: &[(&str, &[&str])] = &[
    (
        "ads_tracking",
        &["light", "normal", "pro", "proplus", "ultimate"],
    ),
    ("malware_security", &["light", "normal", "pro", "ultimate"]),
    ("adult", &["light"]),
    ("gambling", &["light", "normal", "pro"]),
    ("social", &["light"]),
    ("misc", &["light", "normal", "pro"]),
];

/// Upper bound on concurrent in-flight downloads. Tuned to preserve refresh
/// wall-clock time without swamping hagezi's CDN.
const MAX_CONCURRENT: usize = 10;
const STALE_VERSIONED_DB_RETENTION: Duration = Duration::from_secs(48 * 60 * 60);
const SUSPICIOUS_COUNT_BASELINE: usize = 1_000;
const SUSPICIOUS_COUNT_FACTOR: usize = 10;

#[derive(Debug)]
pub(super) struct UpdateReport {
    pub filename: String,
    /// Stable path of the database this report is about. `None` when the
    /// failure cannot be tied to one list.
    pub db_path: Option<PathBuf>,
    pub changed: bool,
    pub error: Option<String>,
}

struct DownloadTask {
    filename: String,
    url_info: BlocklistUrl,
    db_path: PathBuf,
}

/// Base filename of a URL: `https://.../pro.txt` gives `pro`, and
/// `https://.../tif.medium.txt` gives `tif.medium`.
fn extract_filename(url: &str) -> String {
    url.split('/')
        .next_back()
        .unwrap_or("unknown")
        .replace(".txt", "")
}

/// Refresh every category × level in the static `CATEGORIES` table. Writes
/// each LMDB atomically. Returns one `UpdateReport` per URL attempted.
///
/// `generation` is the scheduler generation that started this refresh. Work
/// that outlives it publishes nothing.
pub(super) async fn refresh_all(output_dir: &Path, generation: &Generation) -> Vec<UpdateReport> {
    if let Err(e) = std::fs::create_dir_all(output_dir) {
        error!("blocklist scheduler: create {:?} failed: {}", output_dir, e);
        return vec![UpdateReport {
            filename: "<scheduler>".into(),
            db_path: None,
            changed: false,
            error: Some(format!("create {} failed: {}", output_dir.display(), e)),
        }];
    }

    // Removes .tmp/.old leftovers a previous crash may have left behind.
    cleanup_leftovers(output_dir);

    let mut tasks: Vec<DownloadTask> = Vec::new();
    let mut seen_urls: HashSet<String> = HashSet::new();
    for (category, levels) in CATEGORIES {
        for level in *levels {
            let urls = hagezi_urls(category, level);
            if urls.is_empty() {
                warn!("No URLs for {}/{}", category, level);
                continue;
            }
            for url_info in urls {
                if !seen_urls.insert(url_info.primary.clone()) {
                    continue;
                }
                let filename = extract_filename(&url_info.primary);
                let db_path = output_dir.join(format!("{}_{}.db", category, filename));
                tasks.push(DownloadTask {
                    filename,
                    url_info,
                    db_path,
                });
            }
        }
    }

    info!(
        "blocklist scheduler: {} unique files to download/verify",
        tasks.len()
    );

    let downloader = match HttpDownloader::new() {
        Ok(d) => Arc::new(d),
        Err(e) => {
            error!("blocklist scheduler: HttpDownloader::new failed: {}", e);
            return tasks
                .into_iter()
                .map(|t| UpdateReport {
                    filename: t.filename,
                    db_path: Some(t.db_path),
                    changed: false,
                    error: Some(e.to_string()),
                })
                .collect();
        }
    };

    let mut in_flight = FuturesUnordered::new();
    let mut task_iter = tasks.into_iter();
    let mut reports: Vec<UpdateReport> = Vec::new();

    for _ in 0..MAX_CONCURRENT {
        if let Some(t) = task_iter.next() {
            let dl = downloader.clone();
            let task_generation = generation.clone();
            in_flight.push(tokio::spawn(async move {
                process_task(dl, t, task_generation).await
            }));
        }
    }

    while let Some(joined) = in_flight.next().await {
        match joined {
            Ok(report) => reports.push(report),
            Err(e) => {
                error!("blocklist scheduler: task panicked/cancelled: {}", e);
                // The per-filename context is lost here. A panicking worker
                // is rare, and the generic report is enough to surface it.
                reports.push(UpdateReport {
                    filename: "<panicked>".into(),
                    db_path: None,
                    changed: false,
                    error: Some(e.to_string()),
                });
            }
        }
        if let Some(t) = task_iter.next() {
            let dl = downloader.clone();
            let task_generation = generation.clone();
            in_flight.push(tokio::spawn(async move {
                process_task(dl, t, task_generation).await
            }));
        }
    }

    reports
}

/// One-shot wrapper around `HttpDownloader::download_with_cache` that
/// normalises the three possible outcomes into a `Result`:
///
/// * Network or IO failure: `Err`
/// * `Ok(DownloadResult::Error(...))` (HTTP 4xx/5xx): `Err`
/// * `Ok(DownloadResult::NotModified | Success { .. })`: `Ok(_)`
///
/// Without this, the backup fallback in `process_task` would treat a 500 from
/// the primary CDN as a successful download (reqwest returned `Ok`) and never
/// try the backup URL.
async fn try_one_url(
    downloader: &HttpDownloader,
    url: &str,
    db_path: &Path,
    temp_file: &Path,
    unconditional: bool,
) -> std::result::Result<DownloadResult, String> {
    match downloader
        .download_with_cache(url, db_path, temp_file, unconditional)
        .await
    {
        Ok(DownloadResult::Error(e)) => Err(e),
        Ok(other) => Ok(other),
        Err(e) => Err(e.to_string()),
    }
}

async fn process_task(
    downloader: Arc<HttpDownloader>,
    task: DownloadTask,
    generation: Generation,
) -> UpdateReport {
    let mut report = UpdateReport {
        filename: task.filename.clone(),
        db_path: Some(task.db_path.clone()),
        changed: false,
        error: None,
    };

    // One temp path for both the primary and backup attempts. The streamer
    // writes to `.partial` and renames, so a failed primary leaves nothing at
    // `temp_file`, and the backup attempt writes a complete file before the
    // rename.
    let temp_file = attempt_download_path(&task.db_path, &generation);

    // Download unconditionally whenever the cached LMDB is missing, stale or
    // corrupted. A 304 is only honest when the resolver has a valid local copy
    // to keep. Otherwise the upstream "your cache is current" answer points at
    // nothing and the category silently disappears until the next refresh.
    // Checking `current_db_matches` up front lets the 304 branch below trust
    // the local state without re-checking.
    let cached_metadata = downloader.load_metadata(&task.db_path).ok().flatten();
    let existing_valid = cached_metadata
        .as_ref()
        .and_then(|m| m.content_hash())
        .map(|digest| current_db_matches(&task.db_path, digest))
        .unwrap_or(false);
    let unconditional = !existing_valid;

    let result = match try_one_url(
        &downloader,
        &task.url_info.primary,
        &task.db_path,
        &temp_file,
        unconditional,
    )
    .await
    {
        Ok(r) => Ok(r),
        Err(primary_err) => {
            warn!(
                "[{}] Primary download failed: {}",
                task.filename, primary_err
            );
            try_one_url(
                &downloader,
                &task.url_info.backup,
                &task.db_path,
                &temp_file,
                unconditional,
            )
            .await
            .map_err(|backup_err| {
                format!(
                    "Both primary and backup failed. Primary: {}. Backup: {}",
                    primary_err, backup_err
                )
            })
        }
    };

    let result = match result {
        Ok(r) => r,
        Err(e) => {
            error!("[{}] {}", task.filename, e);
            report.error = Some(e);
            return report;
        }
    };

    match result {
        DownloadResult::NotModified => {
            if !existing_valid {
                let msg = invalid_not_modified_error(&task.filename);
                warn!("{}", msg);
                report.error = Some(msg);
                return report;
            }
            // The stored ETag is the published version's, so a 304 means
            // upstream is back on it. A held suspicious candidate is no longer
            // consecutive and must not confirm when it reappears later.
            if let Some(mut metadata) = cached_metadata
                .filter(|m| m.pending_sha256.is_some() || m.pending_domain_count.is_some())
            {
                metadata.pending_sha256 = None;
                metadata.pending_domain_count = None;
                commit_metadata(&generation, &downloader, &task.db_path, &metadata);
            }
        }
        DownloadResult::Success {
            etag,
            sha256: new_digest,
        } => {
            let old_domain_count = cached_metadata.as_ref().and_then(|m| m.domain_count);

            let changed = !current_db_matches(&task.db_path, &new_digest);

            if changed {
                match publish_or_build_changed_database(
                    &downloader,
                    &task,
                    &temp_file,
                    cached_metadata.as_ref(),
                    &new_digest,
                    etag.clone(),
                    &generation,
                )
                .await
                {
                    Ok(()) => report.changed = true,
                    Err(e) => report.error = Some(e),
                }
            } else {
                // Content unchanged. Only the ETag is refreshed, so the next
                // request can still use If-None-Match. Any held candidate is
                // stale now that upstream matches the published version.
                let metadata = FileMetadata {
                    etag: etag.clone(),
                    sha256: Some(new_digest),
                    md5: None,
                    domain_count: old_domain_count,
                    pending_sha256: None,
                    pending_domain_count: None,
                };
                commit_metadata(&generation, &downloader, &task.db_path, &metadata);
            }

            let _ = std::fs::remove_file(&temp_file);
        }
        DownloadResult::Error(_) => {
            unreachable!("HTTP error collapsed by try_one_url");
        }
    }

    report
}

async fn publish_or_build_changed_database(
    downloader: &Arc<HttpDownloader>,
    task: &DownloadTask,
    temp_file: &Path,
    cached_metadata: Option<&FileMetadata>,
    new_digest: &str,
    etag: Option<String>,
    generation: &Generation,
) -> std::result::Result<(), String> {
    let old_digest = cached_metadata.and_then(|m| m.content_hash());
    let old_domain_count = cached_metadata.and_then(|m| m.domain_count);

    let versioned_path = versioned_db_path(&task.db_path, new_digest);
    if versioned_path.exists() {
        match reusable_versioned_db(&versioned_path) {
            Ok(()) => {
                let metadata = FileMetadata {
                    etag,
                    sha256: Some(new_digest.to_string()),
                    md5: None,
                    domain_count: old_domain_count,
                    pending_sha256: None,
                    pending_domain_count: None,
                };
                return match commit_publication(
                    generation,
                    downloader,
                    &task.db_path,
                    None,
                    &versioned_path,
                    &metadata,
                ) {
                    Ok(CommitOutcome::Committed) => {
                        info!(
                            "[{}] Re-published existing DB version (SHA-256: {})",
                            task.filename, new_digest
                        );
                        Ok(())
                    }
                    Ok(CommitOutcome::StaleGeneration) => {
                        let message = stale_generation_error(&task.filename, generation);
                        warn!("{}", message);
                        Err(message)
                    }
                    Err(e) => {
                        error!(
                            "[{}] Failed to publish database pointer: {}",
                            task.filename, e
                        );
                        Err(e.to_string())
                    }
                };
            }
            Err(e) => {
                warn!(
                    "[{}] Existing DB version {} is invalid; rebuilding: {}",
                    task.filename,
                    versioned_path.display(),
                    e
                );
            }
        }
    }

    // LMDB writes are synchronous, so they run on the blocking pool instead of
    // stalling the reactor.
    let request = BuildRequest {
        src: temp_file.to_path_buf(),
        db_path: task.db_path.clone(),
        digest: new_digest.to_string(),
        source: task.filename.clone(),
        cached_metadata: cached_metadata.cloned(),
        etag,
        generation: generation.clone(),
    };
    let downloader_for_build = downloader.clone();
    let build_result = tokio::task::spawn_blocking(move || {
        build_database_from_file_with_guard(&request, &downloader_for_build)
    })
    .await;

    match build_result {
        Ok(Ok(BuildOutcome::Published(domain_count))) => {
            let reason = match old_digest {
                None => "new file",
                Some(old) if old != new_digest => "content changed",
                Some(_) => "missing published DB",
            };
            info!(
                "[{}] Downloaded ({}, SHA-256: {}, domains: {})",
                task.filename, reason, new_digest, domain_count
            );
            Ok(())
        }
        Ok(Ok(BuildOutcome::SuspiciousHeld(candidate_count))) => {
            let message = format!(
                "[{}] suspicious blocklist size change: old={} new={}; holding candidate for a second identical refresh",
                task.filename,
                old_domain_count.unwrap_or_default(),
                candidate_count
            );
            warn!("{}", message);
            Err(message)
        }
        Ok(Ok(BuildOutcome::StaleGeneration)) => {
            let message = stale_generation_error(&task.filename, generation);
            warn!("{}", message);
            Err(message)
        }
        Ok(Err(e)) => {
            error!("[{}] Failed to create database: {}", task.filename, e);
            Err(e.to_string())
        }
        Err(e) => {
            error!("[{}] spawn_blocking join failed: {}", task.filename, e);
            Err(e.to_string())
        }
    }
}

/// Serializes the scheduler-generation check with the `.current` and `.info`
/// writes it authorizes. A refresh started by a generation that is already gone
/// finds the lock, fails the check, and publishes nothing. A live one writes
/// both files inside the same critical section, so the pointer and its metadata
/// always describe the same version.
static COMMIT_LOCK: Mutex<()> = Mutex::new(());

/// Acquires the publication guard.
///
/// Shared with the scheduler: retiring a generation and reloading the live
/// snapshot take this same lock, so a retirement can never land between a
/// publication's generation check and the writes that check authorized. Only
/// checks, renames and pointer writes belong inside it. Downloads and LMDB
/// builds stay outside.
pub(super) fn commit_guard() -> std::sync::MutexGuard<'static, ()> {
    COMMIT_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Debug)]
enum CommitOutcome {
    Committed,
    StaleGeneration,
}

/// Publish `versioned_path` through `db_path/.current` and write the matching
/// metadata. `built_path`, when present, is renamed into `versioned_path`
/// first, inside the guard, so a stale generation never removes or replaces a
/// version a newer one already published.
fn commit_publication(
    generation: &Generation,
    downloader: &HttpDownloader,
    db_path: &Path,
    built_path: Option<&Path>,
    versioned_path: &Path,
    metadata: &FileMetadata,
) -> Result<CommitOutcome> {
    let _guard = commit_guard();
    if !generation.is_current() {
        return Ok(CommitOutcome::StaleGeneration);
    }

    if let Some(built_path) = built_path {
        if versioned_path.exists() {
            std::fs::remove_dir_all(versioned_path)?;
        }
        std::fs::rename(built_path, versioned_path)?;
        if let Some(parent) = versioned_path.parent() {
            sync_dir(parent)?;
        }
    }
    publish_current_db_path(db_path, versioned_path)?;
    save_metadata_reporting(downloader, db_path, metadata, log_metadata_failure);
    Ok(CommitOutcome::Committed)
}

fn log_metadata_failure(db_path: &Path, error: &BlocklistError) {
    error!(
        "blocklist metadata persistence failed for {}: {}",
        db_path.display(),
        error
    );
}

fn save_metadata_reporting(
    downloader: &HttpDownloader,
    db_path: &Path,
    metadata: &FileMetadata,
    report: impl FnOnce(&Path, &BlocklistError),
) {
    if let Err(error) = downloader.save_metadata(db_path, metadata) {
        report(db_path, &error);
    }
}

fn commit_metadata(
    generation: &Generation,
    downloader: &HttpDownloader,
    db_path: &Path,
    metadata: &FileMetadata,
) -> CommitOutcome {
    let _guard = commit_guard();
    if !generation.is_current() {
        return CommitOutcome::StaleGeneration;
    }
    save_metadata_reporting(downloader, db_path, metadata, log_metadata_failure);
    CommitOutcome::Committed
}

fn stale_generation_error(filename: &str, generation: &Generation) -> String {
    format!(
        "[{}] scheduler generation {} was replaced before publication; refresh discarded",
        filename, generation
    )
}

/// Download scratch path, scoped to the scheduler generation so a closure the
/// previous generation handed to the blocking pool cannot write into the bytes
/// a live attempt is hashing.
fn attempt_download_path(db_path: &Path, generation: &Generation) -> PathBuf {
    db_path.with_extension(format!("txt.{generation}.tmp"))
}

/// Build scratch path for one attempt. Generation-scoped for the same reason as
/// `attempt_download_path`: two generations can be building the same digest.
fn attempt_build_path(versioned_path: &Path, generation: &Generation) -> PathBuf {
    versioned_path.with_extension(format!("{generation}.db.tmp"))
}

fn reusable_versioned_db(path: &Path) -> std::result::Result<(), String> {
    if !BlocklistDb::existing_env_path(path) {
        return Err("missing LMDB data file".to_string());
    }

    match BlocklistDb::validate_existing(path) {
        Ok(()) => Ok(()),
        Err(BlocklistError::Database(heed::Error::EnvAlreadyOpened)) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

fn invalid_not_modified_error(filename: &str) -> String {
    format!(
        "[{}] Got 304 but local DB is missing or invalid; refusing NotModified",
        filename
    )
}

fn cleanup_leftovers(output_dir: &Path) {
    let live_versioned_paths = live_versioned_db_paths(output_dir);
    if let Ok(entries) = std::fs::read_dir(output_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if stale_versioned_db_path(&path, &live_versioned_paths) {
                if let Err(e) = std::fs::remove_dir_all(&path) {
                    debug!(
                        "failed to remove stale blocklist DB {}: {}",
                        path.display(),
                        e
                    );
                }
                continue;
            }
            if let Some(ext) = path.extension() {
                if ext == "old" {
                    if let Some(live_path) = strip_suffix(&path, ".old") {
                        if !live_path.exists() {
                            let _ = std::fs::rename(&path, &live_path);
                            continue;
                        }
                    }
                }
                // `.partial` is the in-flight file of the streaming download
                // in `lmdb/http::download_with_cache`. A crash mid-stream
                // leaves it behind, and nothing else removes it.
                if ext == "tmp" || ext == "old" || ext == "partial" {
                    if path.is_dir() {
                        let _ = std::fs::remove_dir_all(&path);
                    } else {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
    }
}

fn live_versioned_db_paths(output_dir: &Path) -> HashSet<PathBuf> {
    let mut live = HashSet::new();
    let Ok(entries) = std::fs::read_dir(output_dir) else {
        return live;
    };
    for entry in entries.flatten() {
        let stable_path = entry.path();
        let Ok(pointer) = std::fs::read_to_string(stable_path.join(".current")) else {
            continue;
        };
        let pointer = pointer.trim();
        if pointer.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(pointer);
        let resolved = if candidate.is_absolute() {
            candidate
        } else if let Some(parent) = stable_path.parent() {
            parent.join(candidate)
        } else {
            candidate
        };
        live.insert(resolved);
    }
    live
}

fn stale_versioned_db_path(path: &Path, live_versioned_paths: &HashSet<PathBuf>) -> bool {
    if live_versioned_paths.contains(path) || !path.is_dir() {
        return false;
    }
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if !is_versioned_db_dir_name(name) {
        return false;
    }
    let Ok(modified) = path.metadata().and_then(|m| m.modified()) else {
        return false;
    };
    modified
        .elapsed()
        .is_ok_and(|age| age > STALE_VERSIONED_DB_RETENTION)
}

fn is_versioned_db_dir_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".db") else {
        return false;
    };
    let Some((_base, digest)) = stem.rsplit_once('.') else {
        return false;
    };
    valid_content_digest(digest)
}

fn valid_content_digest(digest: &str) -> bool {
    matches!(digest.len(), 32 | 64) && digest.chars().all(|c| c.is_ascii_hexdigit())
}

fn strip_suffix(path: &Path, suffix: &str) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let base = name.strip_suffix(suffix)?;
    Some(path.with_file_name(base))
}

#[derive(Debug)]
enum BuildOutcome {
    /// LMDB built and published through `db_path/.current`.
    Published(usize),
    /// Domain count is outside the accepted range and the candidate has not
    /// been seen before. Nothing was published. The previous version stays
    /// live until an identical second candidate confirms this one.
    SuspiciousHeld(usize),
    /// The scheduler generation that started this refresh is gone. Nothing was
    /// published and no metadata was written.
    StaleGeneration,
}

/// Everything one build attempt needs. Owned so the whole request can move into
/// `spawn_blocking`, which also has to run the commit. A closure that already
/// started cannot be cancelled, so the generation check and the writes it
/// authorizes must sit together at the end of the same closure.
struct BuildRequest {
    src: PathBuf,
    db_path: PathBuf,
    digest: String,
    source: String,
    cached_metadata: Option<FileMetadata>,
    etag: Option<String>,
    generation: Generation,
}

/// Build a fresh LMDB at a content-versioned path and publish that version via
/// `db_path/.current`. The stable `db_path` directory is deliberately not the
/// live LMDB env path: heed/LMDB refuses to reopen the same env path
/// while the previous snapshot is still mmap'ed, so versioned paths let a new
/// snapshot open before the old one drops.
fn build_database_from_file_with_guard(
    request: &BuildRequest,
    downloader: &HttpDownloader,
) -> Result<BuildOutcome> {
    let BuildRequest {
        src,
        db_path,
        digest,
        source,
        cached_metadata,
        etag,
        generation,
    } = request;
    let old_domain_count = cached_metadata.as_ref().and_then(|m| m.domain_count);
    let confirm_suspicious = cached_metadata
        .as_ref()
        .is_some_and(|m| m.confirms_pending(digest));
    let parser = DomainListParser::new();

    let versioned_path = versioned_db_path(db_path, digest);
    let temp_path = attempt_build_path(&versioned_path, generation);
    if temp_path.exists() {
        std::fs::remove_dir_all(&temp_path)?;
    }

    let db = BlocklistDb::open_for_write(&temp_path)?;

    const BATCH_SIZE: usize = 10_000;
    let file = std::fs::File::open(src)?;
    let domain_count = parser.parse_reader_in_batches(
        std::io::BufReader::new(file),
        source,
        BATCH_SIZE,
        |chunk| {
            db.insert_batch(chunk)?;
            Ok(())
        },
    )?;
    drop(db);

    // The LMDB commits already synced the data pages, but the temp directory's
    // own entries for `data.mdb`/`lock.mdb` are not durable until the
    // directory itself is fsynced. Without this a crash right after the
    // `.current` pointer is published can leave a durable pointer to a version
    // whose child entries never reached disk, a broken pointer that blocks
    // startup. Must happen before the rename, not only on the parent after it.
    sync_temp_env_dir(&temp_path)?;

    if domain_count == 0 {
        let _ = std::fs::remove_dir_all(&temp_path);
        return Err(BlocklistError::Validation(format!(
            "[{}] blocklist contains zero accepted RPZ records; refusing publish",
            source
        )));
    }

    if !confirm_suspicious && suspicious_domain_count_change(old_domain_count, domain_count) {
        let _ = std::fs::remove_dir_all(&temp_path);
        // Record the candidate only. The accepted ETag, digest and count stay
        // untouched so the published list keeps filtering and the next
        // conditional request still revalidates against it. That lets an
        // identical second candidate confirm and publish instead of being
        // rejected forever.
        let mut metadata = cached_metadata.clone().unwrap_or_default();
        metadata.pending_sha256 = Some(digest.clone());
        metadata.pending_domain_count = Some(domain_count);
        return Ok(
            match commit_metadata(generation, downloader, db_path, &metadata) {
                CommitOutcome::Committed => BuildOutcome::SuspiciousHeld(domain_count),
                CommitOutcome::StaleGeneration => BuildOutcome::StaleGeneration,
            },
        );
    }

    let metadata = FileMetadata {
        etag: etag.clone(),
        sha256: Some(digest.clone()),
        md5: None,
        domain_count: Some(domain_count),
        pending_sha256: None,
        pending_domain_count: None,
    };
    match commit_publication(
        generation,
        downloader,
        db_path,
        Some(temp_path.as_path()),
        &versioned_path,
        &metadata,
    )? {
        CommitOutcome::Committed => Ok(BuildOutcome::Published(domain_count)),
        CommitOutcome::StaleGeneration => {
            let _ = std::fs::remove_dir_all(&temp_path);
            Ok(BuildOutcome::StaleGeneration)
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Fault-injection switch for `sync_temp_env_dir`, scoped to the calling
    /// test thread.
    static FAIL_TEMP_ENV_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn sync_temp_env_dir(temp_path: &Path) -> Result<()> {
    #[cfg(test)]
    if FAIL_TEMP_ENV_SYNC.with(std::cell::Cell::get) {
        return Err(BlocklistError::from(std::io::Error::other(
            "injected temp env fsync failure",
        )));
    }
    sync_dir(temp_path)?;
    Ok(())
}

fn suspicious_domain_count_change(
    old_domain_count: Option<usize>,
    new_domain_count: usize,
) -> bool {
    let Some(old) = old_domain_count else {
        return false;
    };
    if old < SUSPICIOUS_COUNT_BASELINE {
        return false;
    }
    new_domain_count < old / SUSPICIOUS_COUNT_FACTOR
        || new_domain_count > old.saturating_mul(SUSPICIOUS_COUNT_FACTOR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lmdb::DomainName;
    use tempfile::TempDir;

    #[test]
    fn metadata_failure_is_reported_without_reverting_publication() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("base.db");
        std::fs::create_dir_all(base.join(".info.tmp")).unwrap();
        let downloader = test_downloader();
        let metadata = FileMetadata::default();
        let mut reported = false;
        save_metadata_reporting(&downloader, &base, &metadata, |path, error| {
            assert_eq!(path, base);
            assert!(!error.to_string().is_empty());
            reported = true;
        });
        assert!(reported, "metadata persistence failure must be observable");
        let versioned = versioned_db_path(&base, &"a".repeat(64));
        drop(BlocklistDb::open_for_write(&versioned).unwrap());
        let generation = Generation::new();
        assert!(matches!(
            commit_publication(&generation, &downloader, &base, None, &versioned, &metadata)
                .unwrap(),
            CommitOutcome::Committed
        ));
        assert_eq!(
            crate::lmdb::paths::resolve_current_db_path(&base).unwrap(),
            versioned
        );
        assert!(matches!(
            commit_metadata(&generation, &downloader, &base, &metadata),
            CommitOutcome::Committed
        ));
    }

    fn test_downloader() -> Arc<HttpDownloader> {
        Arc::new(HttpDownloader::new().unwrap())
    }

    /// Tests own their generation instead of reading the scheduler's live one:
    /// unrelated tests call `dns_shutdown`, which retires whatever generation is
    /// live and would otherwise make an unrelated publication fail.
    fn build_request(
        src: &Path,
        db_path: &Path,
        digest: &str,
        source: &str,
        old_domain_count: Option<usize>,
    ) -> BuildRequest {
        BuildRequest {
            src: src.to_path_buf(),
            db_path: db_path.to_path_buf(),
            digest: digest.to_string(),
            source: source.to_string(),
            cached_metadata: old_domain_count.map(|count| FileMetadata {
                domain_count: Some(count),
                ..FileMetadata::default()
            }),
            etag: None,
            generation: Generation::new(),
        }
    }

    fn build_and_publish(
        src: &Path,
        db_path: &Path,
        digest: &str,
        source: &str,
        old_domain_count: Option<usize>,
    ) -> usize {
        let request = build_request(src, db_path, digest, source, old_domain_count);
        match build_database_from_file_with_guard(&request, &test_downloader()).unwrap() {
            BuildOutcome::Published(count) => count,
            other => panic!("expected a published build, got {other:?}"),
        }
    }

    fn write_rpz_file(path: &Path, domains: usize) {
        let mut content = String::new();
        for i in 0..domains {
            content.push_str(&format!("d{}.example CNAME .\n", i));
        }
        std::fs::write(path, content).unwrap();
    }

    fn download_task(base: &Path) -> DownloadTask {
        DownloadTask {
            filename: "multi".into(),
            url_info: BlocklistUrl {
                primary: "https://example.invalid/a.txt".into(),
                backup: "https://example.invalid/b.txt".into(),
            },
            db_path: base.to_path_buf(),
        }
    }

    #[test]
    fn build_database_from_file_publishes_versioned_db() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("domains.txt");
        let base = temp.path().join("ads_tracking_multi.db");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        std::fs::write(&source, "example.com CNAME .\nads.example.org CNAME .\n").unwrap();

        let domain_count = build_and_publish(&source, &base, digest, "test", None);

        let versioned = versioned_db_path(&base, digest);
        assert!(versioned.exists());
        assert!(current_db_matches(&base, digest));
        assert_eq!(domain_count, 2);

        let db = BlocklistDb::open(&versioned).unwrap();
        assert!(db
            .contains(&DomainName::new("example.com").unwrap())
            .unwrap());
    }

    #[test]
    fn build_database_rejects_zero_rpz_records_without_previous_count() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("tif.txt");
        let base = temp.path().join("malware_security_tif.db");
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        std::fs::write(
            &source,
            "This list was split into tif-1.txt and tif-2.txt\n",
        )
        .unwrap();

        let request = build_request(&source, &base, digest, "tif", None);
        let error = build_database_from_file_with_guard(&request, &test_downloader()).unwrap_err();

        let message = error.to_string();
        assert!(message.contains("tif"));
        assert!(message.contains("zero"));
        assert!(message.contains("RPZ"));
        assert!(!base.join(".current").exists());
        let versioned = versioned_db_path(&base, digest);
        assert!(!versioned.exists());
        assert!(!attempt_build_path(&versioned, &request.generation).exists());
    }

    #[test]
    fn build_database_rejects_zero_rpz_records_and_preserves_previous_database() {
        let temp = TempDir::new().unwrap();
        let previous_source = temp.path().join("previous-tif.txt");
        let zero_source = temp.path().join("tif.txt");
        let base = temp.path().join("malware_security_tif.db");
        let old_digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let new_digest = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        std::fs::write(
            &previous_source,
            "example.com CNAME .\nexample.org CNAME .\n",
        )
        .unwrap();
        std::fs::write(
            &zero_source,
            "This list was split into tif-1.txt and tif-2.txt\n",
        )
        .unwrap();

        let previous_count = build_and_publish(&previous_source, &base, old_digest, "tif", None);
        let request = build_request(&zero_source, &base, new_digest, "tif", Some(previous_count));
        let error = build_database_from_file_with_guard(&request, &test_downloader()).unwrap_err();

        assert!(error.to_string().contains("zero"));
        assert_eq!(previous_count, 2);
        assert!(current_db_matches(&base, old_digest));
        assert!(versioned_db_path(&base, old_digest).exists());
        let versioned = versioned_db_path(&base, new_digest);
        assert!(!versioned.exists());
        assert!(!attempt_build_path(&versioned, &request.generation).exists());
    }

    #[tokio::test]
    async fn identical_suspicious_candidate_is_accepted_on_second_refresh() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        let old_digest = "1111111111111111111111111111111111111111111111111111111111111111";
        let new_digest = "2222222222222222222222222222222222222222222222222222222222222222";

        let previous_source = temp.path().join("previous.txt");
        write_rpz_file(&previous_source, 2_000);
        let accepted_count = build_and_publish(&previous_source, &base, old_digest, "test", None);

        let downloader = test_downloader();
        let accepted_metadata = FileMetadata {
            etag: Some("accepted-etag".into()),
            sha256: Some(old_digest.into()),
            md5: None,
            domain_count: Some(accepted_count),
            pending_sha256: None,
            pending_domain_count: None,
        };
        downloader.save_metadata(&base, &accepted_metadata).unwrap();

        let candidate_source = base.with_extension("txt.tmp");
        write_rpz_file(&candidate_source, 30);
        let task = download_task(&base);
        let generation = Generation::new();

        let first = publish_or_build_changed_database(
            &downloader,
            &task,
            &candidate_source,
            Some(&accepted_metadata),
            new_digest,
            Some("candidate-etag".into()),
            &generation,
        )
        .await;

        assert!(first.is_err(), "first suspicious candidate must be held");
        assert!(current_db_matches(&base, old_digest));
        let after_first = downloader.load_metadata(&base).unwrap().unwrap();
        assert_eq!(after_first.etag.as_deref(), Some("accepted-etag"));
        assert_eq!(after_first.sha256.as_deref(), Some(old_digest));
        assert_eq!(after_first.domain_count, Some(accepted_count));
        assert_eq!(after_first.pending_sha256.as_deref(), Some(new_digest));
        assert_eq!(after_first.pending_domain_count, Some(30));

        let second = publish_or_build_changed_database(
            &downloader,
            &task,
            &candidate_source,
            Some(&after_first),
            new_digest,
            Some("candidate-etag".into()),
            &generation,
        )
        .await;

        assert!(
            second.is_ok(),
            "identical second candidate must publish: {second:?}"
        );
        assert!(current_db_matches(&base, new_digest));
        let after_second = downloader.load_metadata(&base).unwrap().unwrap();
        assert_eq!(after_second.etag.as_deref(), Some("candidate-etag"));
        assert_eq!(after_second.sha256.as_deref(), Some(new_digest));
        assert_eq!(after_second.domain_count, Some(30));
        assert_eq!(after_second.pending_sha256, None);
        assert_eq!(after_second.pending_domain_count, None);
    }

    #[test]
    fn build_syncs_temp_env_before_publication() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        let old_digest = "1111111111111111111111111111111111111111111111111111111111111111";
        let new_digest = "2222222222222222222222222222222222222222222222222222222222222222";
        let previous_source = temp.path().join("previous.txt");
        let next_source = temp.path().join("next.txt");
        write_rpz_file(&previous_source, 4);
        write_rpz_file(&next_source, 6);

        build_and_publish(&previous_source, &base, old_digest, "test", None);

        let request = build_request(&next_source, &base, new_digest, "test", Some(4));
        FAIL_TEMP_ENV_SYNC.with(|flag| flag.set(true));
        let error = build_database_from_file_with_guard(&request, &test_downloader()).unwrap_err();
        FAIL_TEMP_ENV_SYNC.with(|flag| flag.set(false));

        assert!(error.to_string().contains("injected temp env fsync"));
        assert!(
            current_db_matches(&base, old_digest),
            "a failed temp fsync must leave the published pointer untouched"
        );
        assert!(
            !versioned_db_path(&base, new_digest).exists(),
            "the temp directory must be fsynced before it is renamed into place"
        );
    }

    /// `JoinHandle::abort` cannot cancel a `spawn_blocking` closure that has
    /// already started, so a closure from the generation before a restart can
    /// finish long after the new generation published newer data. It must not
    /// move `.current` back, and it must not leave its own digest in `.info`
    /// either. A newer digest paired with the older pointer would let the next
    /// refresh accept the regressed pointer as up to date.
    #[tokio::test]
    async fn stale_generation_closure_cannot_publish_after_restart() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        let stale_digest = "1111111111111111111111111111111111111111111111111111111111111111";
        let live_digest = "2222222222222222222222222222222222222222222222222222222222222222";
        let stale_source = temp.path().join("stale.txt");
        let live_source = temp.path().join("live.txt");
        write_rpz_file(&stale_source, 4);
        write_rpz_file(&live_source, 6);

        let downloader = test_downloader();
        let task = download_task(&base);

        // The refresh the previous scheduler generation started. `stop()`
        // retires that generation exactly like this.
        let stale_generation = Generation::new();
        stale_generation.retire();
        let live_generation = Generation::new();

        publish_or_build_changed_database(
            &downloader,
            &task,
            &live_source,
            None,
            live_digest,
            Some("live-etag".into()),
            &live_generation,
        )
        .await
        .expect("the live generation must publish");
        assert!(current_db_matches(&base, live_digest));

        let stale = publish_or_build_changed_database(
            &downloader,
            &task,
            &stale_source,
            None,
            stale_digest,
            Some("stale-etag".into()),
            &stale_generation,
        )
        .await;

        assert!(stale.is_err(), "a stale generation must not report success");
        assert!(
            current_db_matches(&base, live_digest),
            "a stale generation must not move the published pointer"
        );
        assert!(!versioned_db_path(&base, stale_digest).exists());
        let metadata = downloader.load_metadata(&base).unwrap().unwrap();
        assert_eq!(metadata.sha256.as_deref(), Some(live_digest));
        assert_eq!(metadata.etag.as_deref(), Some("live-etag"));
        assert_eq!(metadata.domain_count, Some(6));
    }

    /// The same guard has to cover the branch that re-publishes an already
    /// built version: it writes `.current` and `.info` without rebuilding.
    #[tokio::test]
    async fn stale_generation_cannot_republish_existing_version() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        let stale_digest = "3333333333333333333333333333333333333333333333333333333333333333";
        let live_digest = "4444444444444444444444444444444444444444444444444444444444444444";
        let stale_source = temp.path().join("stale.txt");
        let live_source = temp.path().join("live.txt");
        write_rpz_file(&stale_source, 4);
        write_rpz_file(&live_source, 6);

        // Both versions already exist on disk. The stale refresh only has to
        // repoint `.current` at its own.
        build_and_publish(&stale_source, &base, stale_digest, "test", None);
        build_and_publish(&live_source, &base, live_digest, "test", None);

        let downloader = test_downloader();
        let task = download_task(&base);
        let stale_generation = Generation::new();
        stale_generation.retire();

        let stale = publish_or_build_changed_database(
            &downloader,
            &task,
            &stale_source,
            None,
            stale_digest,
            Some("stale-etag".into()),
            &stale_generation,
        )
        .await;

        assert!(stale.is_err(), "a stale generation must not report success");
        assert!(
            current_db_matches(&base, live_digest),
            "a stale generation must not repoint an existing version"
        );
        let metadata = downloader.load_metadata(&base).unwrap().unwrap();
        assert_eq!(metadata.sha256.as_deref(), Some(live_digest));
    }

    #[test]
    fn versioned_db_name_requires_digest_sibling_shape() {
        assert!(is_versioned_db_dir_name(
            "ads_tracking_multi.d41d8cd98f00b204e9800998ecf8427e.db"
        ));
        assert!(is_versioned_db_dir_name(
            "ads_tracking_multi.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.db"
        ));
        assert!(!is_versioned_db_dir_name("ads_tracking_multi.db"));
        assert!(!is_versioned_db_dir_name(
            "ads_tracking_multi.not-digest.db"
        ));
        assert!(!is_versioned_db_dir_name(
            "ads_tracking_multi.d41d8cd98f00b204e9800998ecf8427e.txt"
        ));
    }

    #[test]
    fn suspicious_domain_count_change_rejects_extreme_delta() {
        assert!(suspicious_domain_count_change(Some(10_000), 0));
        assert!(suspicious_domain_count_change(Some(10_000), 999));
        assert!(suspicious_domain_count_change(Some(10_000), 100_001));
        assert!(!suspicious_domain_count_change(Some(10_000), 1_000));
        assert!(!suspicious_domain_count_change(Some(10_000), 100_000));
        assert!(!suspicious_domain_count_change(None, 0));
        assert!(!suspicious_domain_count_change(Some(999), 0));
    }

    #[test]
    fn invalid_not_modified_error_is_operator_actionable() {
        let err = invalid_not_modified_error("ads");

        assert!(err.contains("ads"));
        assert!(err.contains("304"));
        assert!(err.contains("local DB"));
        assert!(err.contains("refusing"));
    }

    /// One-shot HTTP/1.1 origin: answers the first request with `response`.
    /// Awaiting the handle yields the lowercased request head it received.
    async fn serve_once(response: Vec<u8>) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/multi.txt", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0, "client closed before sending the request head");
                head.extend_from_slice(&buf[..n]);
            }
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
            String::from_utf8(head).unwrap().to_ascii_lowercase()
        });
        (url, server)
    }

    async fn request_head(server: tokio::task::JoinHandle<String>) -> String {
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("origin never received a request")
            .unwrap()
    }

    /// Runs one refresh of `base` against a one-shot origin answering with
    /// `response`, returning the report and the request head.
    async fn refresh_against(base: &Path, response: Vec<u8>) -> (UpdateReport, String) {
        let (url, server) = serve_once(response).await;
        // A port that was just released, so a failing primary surfaces as an
        // error instead of reaching an unrelated local listener.
        let backup = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}/multi.txt", listener.local_addr().unwrap())
        };
        let task = DownloadTask {
            filename: "multi".into(),
            url_info: BlocklistUrl {
                primary: url,
                backup,
            },
            db_path: base.to_path_buf(),
        };
        let report = process_task(test_downloader(), task, Generation::new()).await;
        (report, request_head(server).await)
    }

    fn not_modified_response(etag: &str) -> Vec<u8> {
        format!("HTTP/1.1 304 Not Modified\r\nETag: {etag}\r\nConnection: close\r\n\r\n")
            .into_bytes()
    }

    fn gzip_response(body: &[u8], etag: &str) -> Vec<u8> {
        use std::io::Write;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(body).unwrap();
        let gzipped = encoder.finish().unwrap();
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nETag: {etag}\r\nConnection: close\r\n\r\n",
            gzipped.len()
        )
        .into_bytes();
        response.extend_from_slice(&gzipped);
        response
    }

    fn rpz_body(domains: usize) -> Vec<u8> {
        (0..domains)
            .map(|i| format!("d{i}.example CNAME .\n"))
            .collect::<String>()
            .into_bytes()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        ring::digest::digest(&ring::digest::SHA256, bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Publishes `body` as the live version of `base` with `etag` recorded.
    fn publish_with_etag(temp: &TempDir, base: &Path, body: &[u8], etag: &str) -> String {
        let source = temp.path().join("published.txt");
        std::fs::write(&source, body).unwrap();
        let digest = sha256_hex(body);
        let domain_count = build_and_publish(&source, base, &digest, "multi", None);
        test_downloader()
            .save_metadata(
                base,
                &FileMetadata {
                    etag: Some(etag.into()),
                    sha256: Some(digest.clone()),
                    domain_count: Some(domain_count),
                    ..FileMetadata::default()
                },
            )
            .unwrap();
        digest
    }

    fn if_none_match(head: &str) -> Option<&str> {
        head.lines()
            .find_map(|line| line.strip_prefix("if-none-match: "))
    }

    /// "Update Now", first enable and category changes all go through the
    /// same refresh. A valid local database must be revalidated, not
    /// re-downloaded: every category toggle used to fetch all 18 lists.
    #[tokio::test]
    async fn refresh_revalidates_valid_local_db_with_stored_etag() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        let digest = publish_with_etag(&temp, &base, &rpz_body(2), "W/\"v1\"");

        let (report, head) = refresh_against(&base, not_modified_response("W/\"v1\"")).await;

        assert_eq!(if_none_match(&head), Some("w/\"v1\""), "{head}");
        assert_eq!(report.error, None);
        assert!(!report.changed);
        assert!(current_db_matches(&base, &digest));
    }

    /// A stale `.info` without its database must not send its validator: a
    /// 304 would point at nothing.
    #[tokio::test]
    async fn refresh_downloads_gzip_body_unconditionally_when_local_db_missing() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        test_downloader()
            .save_metadata(
                &base,
                &FileMetadata {
                    etag: Some("W/\"stale\"".into()),
                    sha256: Some(sha256_hex(b"gone")),
                    domain_count: Some(2),
                    ..FileMetadata::default()
                },
            )
            .unwrap();
        let body = rpz_body(2);

        let (report, head) = refresh_against(&base, gzip_response(&body, "W/\"v2\"")).await;

        assert_eq!(if_none_match(&head), None, "{head}");
        assert!(
            head.lines()
                .any(|line| line.starts_with("accept-encoding:") && line.contains("gzip")),
            "{head}"
        );
        assert_eq!(report.error, None);
        assert!(report.changed);
        assert!(current_db_matches(&base, &sha256_hex(&body)));
        let metadata = test_downloader().load_metadata(&base).unwrap().unwrap();
        assert_eq!(metadata.etag.as_deref(), Some("W/\"v2\""));
        assert_eq!(metadata.domain_count, Some(2));
    }

    /// The first gzip request after upgrading carries the identity ETag, which
    /// the CDN does not match. The digest covers the decoded body, so the
    /// unchanged list is not rebuilt and only the validator moves.
    #[tokio::test]
    async fn gzip_upgrade_with_unchanged_content_only_refreshes_the_etag() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        let body = rpz_body(2);
        let digest = publish_with_etag(&temp, &base, &body, "\"identity\"");

        let (report, head) = refresh_against(&base, gzip_response(&body, "W/\"gzip\"")).await;

        assert_eq!(if_none_match(&head), Some("\"identity\""), "{head}");
        assert_eq!(report.error, None);
        assert!(!report.changed);
        assert!(current_db_matches(&base, &digest));
        let metadata = test_downloader().load_metadata(&base).unwrap().unwrap();
        assert_eq!(metadata.etag.as_deref(), Some("W/\"gzip\""));
        assert_eq!(metadata.domain_count, Some(2));
    }

    /// Two-strike acceptance needs two consecutive identical candidates. A 304
    /// in between means upstream went back to the published list, so the held
    /// candidate must start over when it reappears.
    #[tokio::test]
    async fn not_modified_between_suspicious_candidates_resets_the_hold() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().join("ads_tracking_multi.db");
        let published = publish_with_etag(
            &temp,
            &base,
            &rpz_body(SUSPICIOUS_COUNT_BASELINE),
            "W/\"a\"",
        );
        let candidate = rpz_body(SUSPICIOUS_COUNT_BASELINE / SUSPICIOUS_COUNT_FACTOR - 1);

        let (held, _) = refresh_against(&base, gzip_response(&candidate, "W/\"b\"")).await;
        assert!(held.error.as_deref().unwrap().contains("suspicious"));
        let metadata = test_downloader().load_metadata(&base).unwrap().unwrap();
        assert_eq!(metadata.pending_sha256, Some(sha256_hex(&candidate)));

        let (reverted, head) = refresh_against(&base, not_modified_response("W/\"a\"")).await;
        assert_eq!(if_none_match(&head), Some("w/\"a\""), "{head}");
        assert_eq!(reverted.error, None);
        let metadata = test_downloader().load_metadata(&base).unwrap().unwrap();
        assert_eq!(metadata.pending_sha256, None);
        assert_eq!(metadata.pending_domain_count, None);
        assert_eq!(metadata.etag.as_deref(), Some("W/\"a\""));

        let (held_again, _) = refresh_against(&base, gzip_response(&candidate, "W/\"b\"")).await;
        assert!(held_again.error.as_deref().unwrap().contains("suspicious"));
        assert!(!held_again.changed);
        assert!(current_db_matches(&base, &published));
    }

    #[tokio::test]
    async fn refresh_all_reports_output_dir_create_failure() {
        let temp = TempDir::new().unwrap();
        let blocker = temp.path().join("not-a-dir");
        std::fs::write(&blocker, "file blocks create_dir_all").unwrap();

        let reports = refresh_all(&blocker.join("child"), &Generation::new()).await;

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].filename, "<scheduler>");
        assert!(reports[0].error.as_deref().unwrap().contains("create"));
    }
}
