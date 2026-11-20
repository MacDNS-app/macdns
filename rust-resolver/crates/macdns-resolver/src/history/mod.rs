// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! Local lookup history (`query-history.sqlite`), owned by the resolver.
//!
//! The query path only builds a `LookupEvent` and hands it to `record`, which
//! never blocks: a full queue drops the event and counts it. One writer thread
//! owns the read-write connection for the process lifetime. Every read opens
//! its own read-only connection, so the UI never waits on the writer. A
//! missing, corrupt or unwritable database degrades to "unavailable" and the
//! resolver keeps resolving. History is not configuration and never goes into
//! `state.json`.

mod query;
mod store;
mod writer;

use crate::cache::CacheKey;
use arc_swap::ArcSwap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use writer::{Control, Inbound, Writer};

pub(crate) const RETENTION_DAYS_CHOICES: [u32; 4] = [7, 14, 30, 90];
pub(crate) const POPULAR_COUNT_CHOICES: [u32; 6] = [0, 100, 250, 500, 1000, 2000];
pub(crate) const POPULAR_DAYS_CHOICES: [u32; 4] = [1, 7, 14, 30];

const EVENT_QUEUE_CAPACITY: usize = 8192;
const CLEAR_TIMEOUT: Duration = Duration::from_secs(5);
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// How a client lookup was answered. The strings are persisted in the
/// database and returned to the App, so they never change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Route {
    Cache,
    Provider,
    Stale,
    Blocked,
    Override,
    Forward,
    Captive,
    Local,
    Failed,
    Invalid,
}

impl Route {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Route::Cache => "cache",
            Route::Provider => "provider",
            Route::Stale => "stale",
            Route::Blocked => "blocked",
            Route::Override => "override",
            Route::Forward => "forward",
            Route::Captive => "captive",
            Route::Local => "local",
            Route::Failed => "failed",
            Route::Invalid => "invalid",
        }
    }
}

/// One client lookup as it left `handle_wire`. `name` may carry any case and a
/// trailing dot. The writer normalizes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LookupEvent {
    pub(crate) ts: i64,
    pub(crate) name: String,
    pub(crate) qtype: u16,
    pub(crate) rcode: u16,
    pub(crate) answers: u16,
    pub(crate) route: Route,
    pub(crate) provider: String,
    pub(crate) latency_us: u32,
    pub(crate) block_rule: String,
    pub(crate) block_category: String,
}

/// Live cache figures for the Kept Fresh card. Only the resolver's cache
/// knows them, so the caller of `query` supplies them.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct LiveCacheStats {
    /// Prefetch is on. Without it nothing keeps the popular set fresh, so the
    /// card is not shown.
    pub(crate) prefetching: bool,
    /// Popular keys with a fresh entry in the cache now.
    pub(crate) in_cache: u64,
    /// Sum of `1 / original TTL` over those entries.
    pub(crate) refreshes_per_second: f64,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error("history retention of {0} days is not one of 7, 14, 30 or 90")]
    RetentionDays(u32),
    #[error("popular host count {0} is not one of 0, 100, 250, 500, 1000 or 2000")]
    PopularCount(u32),
    #[error("popular look-back of {0} days is not one of 1, 7, 14 or 30")]
    PopularDays(u32),
    #[error("popular look-back of {days} days is longer than the {retention} day retention")]
    PopularDaysExceedRetention { days: u32, retention: u32 },
    #[error("the history writer did not apply the settings, the previous settings stay")]
    NotApplied,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Settings {
    path: Option<PathBuf>,
    enabled: bool,
    retention_days: u32,
    popular_count: u32,
    popular_days: u32,
}

fn validate(retention_days: u32, popular_count: u32, popular_days: u32) -> Result<(), ConfigError> {
    if !RETENTION_DAYS_CHOICES.contains(&retention_days) {
        return Err(ConfigError::RetentionDays(retention_days));
    }
    if !POPULAR_COUNT_CHOICES.contains(&popular_count) {
        return Err(ConfigError::PopularCount(popular_count));
    }
    if !POPULAR_DAYS_CHOICES.contains(&popular_days) {
        return Err(ConfigError::PopularDays(popular_days));
    }
    if popular_days > retention_days {
        return Err(ConfigError::PopularDaysExceedRetention {
            days: popular_days,
            retention: retention_days,
        });
    }
    Ok(())
}

/// State shared by the API callers and the writer thread.
struct Shared {
    settings: Mutex<Settings>,
    /// Checked on the query path before anything is queued.
    recording: AtomicBool,
    /// Why the store cannot be used, set by the writer.
    unavailable: Mutex<Option<String>>,
    popular: ArcSwap<HashSet<CacheKey>>,
    /// Events lost since start. The writer reports it, never the query path.
    dropped: AtomicU64,
}

impl Shared {
    fn new() -> Self {
        Self {
            settings: Mutex::new(Settings {
                path: None,
                enabled: false,
                retention_days: 30,
                popular_count: 0,
                popular_days: 7,
            }),
            recording: AtomicBool::new(false),
            unavailable: Mutex::new(None),
            popular: ArcSwap::from_pointee(HashSet::new()),
            dropped: AtomicU64::new(0),
        }
    }

    fn settings(&self) -> Settings {
        lock(&self.settings).clone()
    }

    fn set_unavailable(&self, reason: Option<String>) {
        *lock(&self.unavailable) = reason;
    }

    fn publish_popular(&self, set: HashSet<CacheKey>) {
        self.popular.store(Arc::new(set));
    }

    /// Counts lost events. Lock-free and silent: it runs on the query path.
    fn note_dropped(&self, events: u64) {
        self.dropped.fetch_add(events, Ordering::Relaxed);
    }
}

enum WriterState {
    NotStarted(Receiver<Inbound>, Receiver<Control>),
    Running,
    Failed,
}

/// One history store: its queue, its writer and the state they share. The
/// process uses a single instance (`instance()`). Tests build their own.
struct History {
    events: SyncSender<Inbound>,
    controls: Sender<Control>,
    shared: Arc<Shared>,
    writer: Mutex<WriterState>,
}

impl History {
    fn new() -> Self {
        Self::with_capacity(EVENT_QUEUE_CAPACITY)
    }

    fn with_capacity(capacity: usize) -> Self {
        let (events, event_rx) = std::sync::mpsc::sync_channel(capacity);
        let (controls, control_rx) = std::sync::mpsc::channel();
        Self {
            events,
            controls,
            shared: Arc::new(Shared::new()),
            writer: Mutex::new(WriterState::NotStarted(event_rx, control_rx)),
        }
    }

    fn record(&self, event: LookupEvent) {
        if self.shared.recording.load(Ordering::Relaxed) {
            enqueue(&self.events, event, &self.shared);
        }
    }

    fn configure(
        &self,
        path: Option<PathBuf>,
        enabled: bool,
        retention_days: u32,
        popular_count: u32,
        popular_days: u32,
    ) -> Result<(), ConfigError> {
        validate(retention_days, popular_count, popular_days)?;
        let previous = self.shared.settings();
        let previous_recording = self.shared.recording.load(Ordering::Relaxed);
        let previous_popular = self.popular();
        let settings = Settings {
            path: path.or_else(|| previous.path.clone()),
            enabled,
            retention_days,
            popular_count,
            popular_days,
        };
        *lock(&self.shared.settings) = settings.clone();
        self.shared.recording.store(
            settings.enabled && settings.path.is_some(),
            Ordering::Relaxed,
        );
        if !settings.enabled {
            self.shared.publish_popular(HashSet::new());
        }
        if settings.path.is_none() || !self.ensure_writer() {
            return Ok(());
        }
        // The writer cannot refuse settings: turning history off keeps the
        // files, and a store that cannot open is retried by a later lookup.
        // So nothing waits for it.
        if self.send(Control::Apply(settings)) {
            return Ok(());
        }
        self.restore(previous, previous_recording, previous_popular);
        Err(ConfigError::NotApplied)
    }

    /// Puts back the settings a rejected `configure` replaced. Only a writer
    /// that is gone rejects them, so there is no writer to tell.
    fn restore(&self, previous: Settings, recording: bool, popular: Arc<HashSet<CacheKey>>) {
        *lock(&self.shared.settings) = previous;
        self.shared.recording.store(recording, Ordering::Relaxed);
        self.shared.popular.store(popular);
    }

    /// Without a running writer no store was configured, so nothing could be
    /// deleted and the answer is `false`.
    fn clear(&self) -> bool {
        if !self.writer_running() {
            return false;
        }
        self.request(Control::Clear, CLEAR_TIMEOUT).unwrap_or(false)
    }

    fn flush(&self) -> bool {
        if !self.writer_running() {
            return true;
        }
        let flushed = self.request(Control::Flush, FLUSH_TIMEOUT).unwrap_or(false);
        if !flushed {
            log::warn!(
                "lookup history: pending events not flushed within {:?}",
                FLUSH_TIMEOUT
            );
        }
        flushed
    }

    fn popular(&self) -> Arc<HashSet<CacheKey>> {
        self.shared.popular.load_full()
    }

    fn query_at(&self, request_json: &str, live: LiveCacheStats, now: i64) -> String {
        let settings = self.shared.settings();
        let view = query::View {
            enabled: settings.enabled,
            path: settings.path,
            unavailable: lock(&self.shared.unavailable).clone(),
            retention_days: settings.retention_days,
            popular_count: settings.popular_count,
            popular: self.popular(),
            dropped: self.shared.dropped.load(Ordering::Relaxed),
        };
        query::run(request_json, &view, live, now)
    }

    /// Starts the writer on first use. A thread that cannot be spawned leaves
    /// the store unavailable and recording off for the session.
    fn ensure_writer(&self) -> bool {
        let mut state = lock(&self.writer);
        let (events, controls) = match std::mem::replace(&mut *state, WriterState::Failed) {
            WriterState::NotStarted(events, controls) => (events, controls),
            WriterState::Running => {
                *state = WriterState::Running;
                return true;
            }
            WriterState::Failed => return false,
        };
        let writer = Writer::new(Arc::clone(&self.shared), events, controls);
        match std::thread::Builder::new()
            .name("macdns-history-writer".to_owned())
            .spawn(move || writer.run())
        {
            Ok(_) => {
                *state = WriterState::Running;
                true
            }
            Err(e) => {
                log::error!("lookup history: writer failed to start: {}", e);
                self.shared.recording.store(false, Ordering::Relaxed);
                self.shared
                    .set_unavailable(Some(format!("history writer failed to start: {e}")));
                false
            }
        }
    }

    fn writer_running(&self) -> bool {
        matches!(*lock(&self.writer), WriterState::Running)
    }

    /// Sends a control to the writer and waits for its answer. Controls travel
    /// on their own unbounded channel so a full event queue can neither delay
    /// nor drop them. The wake-up on the event queue only shortens the wait.
    fn request(
        &self,
        control: impl FnOnce(SyncSender<bool>) -> Control,
        timeout: Duration,
    ) -> Option<bool> {
        let (reply, answer) = std::sync::mpsc::sync_channel(1);
        if !self.send(control(reply)) {
            return None;
        }
        answer.recv_timeout(timeout).ok()
    }

    /// Hands a control to the writer. `false` means the writer is gone.
    fn send(&self, control: Control) -> bool {
        if self.controls.send(control).is_err() {
            return false;
        }
        let _ = self.events.try_send(Inbound::Wake);
        true
    }
}

/// Query-path hand-off. Never blocks.
fn enqueue(tx: &SyncSender<Inbound>, event: LookupEvent, shared: &Shared) -> bool {
    if tx.try_send(Inbound::Event(event)).is_ok() {
        return true;
    }
    shared.note_dropped(1);
    false
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

static HISTORY: OnceLock<History> = OnceLock::new();

fn instance() -> &'static History {
    HISTORY.get_or_init(History::new)
}

/// Records one client lookup. Never blocks. Drops the event when history is
/// off or the queue is full.
pub(crate) fn record(event: LookupEvent) {
    #[cfg(test)]
    let Some(event) = capture::offer(event) else {
        return;
    };
    if let Some(history) = HISTORY.get() {
        history.record(event);
    }
}

/// Applies the history settings. `path` replaces the database location when
/// given and keeps the current one when `None`. Values outside the allowed
/// choices are rejected, never adjusted. Settings that keep history on return
/// at once and the writer opens the database on its own thread. Disabling
/// stops recording at once, empties the popular set and waits until the
/// database files are deleted.
pub(crate) fn configure(
    path: Option<PathBuf>,
    enabled: bool,
    retention_days: u32,
    popular_count: u32,
    popular_days: u32,
) -> Result<(), ConfigError> {
    instance().configure(path, enabled, retention_days, popular_count, popular_days)
}

/// Answers one `dns_history_query` request with a JSON document.
pub(crate) fn query(request_json: &str, live: LiveCacheStats) -> String {
    instance().query_at(request_json, live, unix_now())
}

/// Deletes the database files and, while history is on, recreates an empty
/// database. Works while history is off too. Pending events are discarded.
/// Returns `false` when no store is configured or the writer could not
/// confirm it within the bounded wait.
pub(crate) fn clear() -> bool {
    instance().clear()
}

/// Commits every event recorded before this call, waiting a bounded time.
pub(crate) fn flush() -> bool {
    HISTORY.get().is_none_or(History::flush)
}

/// The `(name, qtype)` keys prefetch keeps fresh regardless of idle time.
pub(crate) fn popular() -> Arc<HashSet<CacheKey>> {
    HISTORY
        .get()
        .map_or_else(|| Arc::new(HashSet::new()), History::popular)
}

/// Test seam: while a `Capture` is alive, `record` hands every event to it
/// instead of the store. Captures are exclusive, so tests that hold one never
/// see each other's events. Other tests may still record, so assert on names
/// the test itself looked up.
#[cfg(test)]
pub(crate) mod capture {
    use super::{lock, LookupEvent};
    use std::sync::{Mutex, MutexGuard};

    static SINK: Mutex<Option<Vec<LookupEvent>>> = Mutex::new(None);
    static EXCLUSIVE: Mutex<()> = Mutex::new(());

    pub(crate) struct Capture {
        _exclusive: MutexGuard<'static, ()>,
    }

    pub(crate) fn start() -> Capture {
        let exclusive = lock(&EXCLUSIVE);
        *lock(&SINK) = Some(Vec::new());
        Capture {
            _exclusive: exclusive,
        }
    }

    /// Keeps every capture off while held, so `record` reaches the store.
    pub(crate) fn suspend() -> MutexGuard<'static, ()> {
        lock(&EXCLUSIVE)
    }

    impl Capture {
        pub(crate) fn events(&self) -> Vec<LookupEvent> {
            lock(&SINK).clone().unwrap_or_default()
        }

        /// Events whose name matches `name`, ignoring case and a trailing dot.
        pub(crate) fn events_for(&self, name: &str) -> Vec<LookupEvent> {
            let wanted = name.trim_end_matches('.');
            self.events()
                .into_iter()
                .filter(|e| e.name.trim_end_matches('.').eq_ignore_ascii_case(wanted))
                .collect()
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            *lock(&SINK) = None;
        }
    }

    /// Takes the event when a capture is active, else gives it back.
    pub(super) fn offer(event: LookupEvent) -> Option<LookupEvent> {
        match lock(&SINK).as_mut() {
            Some(events) => {
                events.push(event);
                None
            }
            None => Some(event),
        }
    }
}

#[cfg(test)]
mod tests;
