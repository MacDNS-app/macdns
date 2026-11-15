// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! The single writer thread. It owns the read-write connection for the
//! process lifetime and is the only code that changes the database files.

use super::store::{self, Store};
use super::{unix_now, LookupEvent, Settings, Shared};
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BATCH_MAX_EVENTS: usize = 2000;
const BATCH_MAX_AGE: Duration = Duration::from_secs(1);
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(3600);
const WRITE_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);
const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(60);
const OPEN_RETRY_INTERVAL: Duration = Duration::from_secs(60);

pub(super) enum Inbound {
    Event(LookupEvent),
    /// Nudges a writer blocked on the event queue to read its controls.
    Wake,
}

/// Requests from the API. Clear and Flush carry a reply channel, where `true`
/// means done. Apply cannot fail, so nothing waits for it.
pub(super) enum Control {
    Apply(Settings),
    Clear(SyncSender<bool>),
    Flush(SyncSender<bool>),
}

pub(super) struct Writer {
    shared: Arc<Shared>,
    events: Receiver<Inbound>,
    controls: Receiver<Control>,
    settings: Option<Settings>,
    store: Option<Store>,
    batch: Vec<LookupEvent>,
    batch_started: Option<Instant>,
    next_maintenance: Instant,
    last_write_error_log: Option<Instant>,
    reported_drops: u64,
    last_drop_report: Option<Instant>,
    last_open_attempt: Option<Instant>,
    /// How long a store that failed to open waits before a lookup retries it.
    pub(super) open_retry_interval: Duration,
}

impl Writer {
    pub(super) fn new(
        shared: Arc<Shared>,
        events: Receiver<Inbound>,
        controls: Receiver<Control>,
    ) -> Self {
        Self {
            shared,
            events,
            controls,
            settings: None,
            store: None,
            batch: Vec::new(),
            batch_started: None,
            next_maintenance: Instant::now() + MAINTENANCE_INTERVAL,
            last_write_error_log: None,
            reported_drops: 0,
            last_drop_report: None,
            last_open_attempt: None,
            open_retry_interval: OPEN_RETRY_INTERVAL,
        }
    }

    /// Runs until every sender is gone, which for the process-wide store is
    /// never.
    pub(super) fn run(mut self) {
        loop {
            match self.events.recv_timeout(self.next_wake()) {
                Ok(Inbound::Event(event)) => self.push(event),
                Ok(Inbound::Wake) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    self.commit();
                    return;
                }
            }
            while let Ok(control) = self.controls.try_recv() {
                self.handle(control);
            }
            if self.batch_due() {
                self.commit();
            }
            if Instant::now() >= self.next_maintenance {
                self.maintain();
            }
            self.report_drops();
        }
    }

    /// Warns about events lost since the last report, with the running total,
    /// at most once a minute.
    pub(super) fn report_drops(&mut self) {
        let total = self.shared.dropped.load(Ordering::Relaxed);
        if total == self.reported_drops || !self.drop_report_due() {
            return;
        }
        self.reported_drops = total;
        self.last_drop_report = Some(Instant::now());
        log::warn!("lookup history: {} event(s) dropped since start", total);
    }

    fn drop_report_due(&self) -> bool {
        self.last_drop_report
            .is_none_or(|at| at.elapsed() >= DROP_REPORT_INTERVAL)
    }

    fn next_wake(&self) -> Duration {
        let mut wake = self
            .next_maintenance
            .saturating_duration_since(Instant::now());
        if self.shared.dropped.load(Ordering::Relaxed) != self.reported_drops {
            let until_report = self.last_drop_report.map_or(Duration::ZERO, |at| {
                DROP_REPORT_INTERVAL.saturating_sub(at.elapsed())
            });
            wake = wake.min(until_report);
        }
        match self.batch_started {
            Some(started) => BATCH_MAX_AGE.saturating_sub(started.elapsed()).min(wake),
            None => wake,
        }
    }

    fn push(&mut self, event: LookupEvent) {
        if self.store.is_none() && !self.retry_open() {
            if self.settings.as_ref().is_some_and(|s| s.enabled) {
                self.shared.note_dropped(1);
            }
            return;
        }
        self.batch_started.get_or_insert_with(Instant::now);
        self.batch.push(event);
    }

    fn batch_due(&self) -> bool {
        self.batch.len() >= BATCH_MAX_EVENTS
            || self
                .batch_started
                .is_some_and(|started| started.elapsed() >= BATCH_MAX_AGE)
    }

    fn handle(&mut self, control: Control) {
        let (done, reply) = match control {
            Control::Apply(settings) => {
                self.apply(settings);
                return;
            }
            Control::Clear(reply) => (self.clear(), reply),
            Control::Flush(reply) => (self.flush(), reply),
        };
        let _ = reply.try_send(done);
    }

    /// Turning history off closes the store and keeps its files: Clear
    /// History is what deletes them. A store that cannot open is reported
    /// through `unavailable` and retried by a later lookup.
    fn apply(&mut self, settings: Settings) {
        let previous = self.settings.replace(settings.clone());
        let Some(path) = settings.path.clone() else {
            return;
        };
        if !settings.enabled {
            self.discard_pending();
            self.store = None;
            self.shared.publish_popular(HashSet::new());
            self.shared.set_unavailable(None);
            self.set_recording(false);
            return;
        }
        let reopened = self.store.as_ref().is_none_or(|s| s.path() != path);
        if reopened {
            self.commit();
            self.store = None;
            self.open(&path);
        }
        let ranking_changed = previous.as_ref().is_none_or(|p| {
            !p.enabled
                || p.popular_count != settings.popular_count
                || p.popular_days != settings.popular_days
        });
        let retention_changed = previous
            .as_ref()
            .is_none_or(|p| p.retention_days != settings.retention_days);
        if reopened || retention_changed {
            self.purge();
        }
        if reopened || ranking_changed {
            self.recompute_popular();
        }
    }

    fn open(&mut self, path: &std::path::Path) {
        self.last_open_attempt = Some(Instant::now());
        match Store::open(path) {
            Ok(store) => {
                self.store = Some(store);
                self.shared.set_unavailable(None);
            }
            Err(reason) => {
                log::error!(
                    "lookup history: unavailable until a later lookup opens it: {}",
                    reason
                );
                self.shared.set_unavailable(Some(reason));
            }
        }
        // Lookups keep coming while the store is unavailable, so a later one
        // can retry it.
        self.set_recording(true);
    }

    /// Opens an unavailable store again for a lookup, at most once per
    /// `open_retry_interval`, so a store that keeps failing neither floods
    /// the log nor slows the writer.
    fn retry_open(&mut self) -> bool {
        let Some(path) = self
            .settings
            .as_ref()
            .filter(|s| s.enabled)
            .and_then(|s| s.path.clone())
        else {
            return false;
        };
        if self
            .last_open_attempt
            .is_some_and(|at| at.elapsed() < self.open_retry_interval)
        {
            return false;
        }
        self.open(&path);
        if self.store.is_none() {
            return false;
        }
        self.purge();
        self.recompute_popular();
        true
    }

    /// Removes the files instead of deleting rows: deleted rows stay readable
    /// in free pages until a vacuum.
    fn clear(&mut self) -> bool {
        self.discard_pending();
        self.shared.publish_popular(HashSet::new());
        let Some(settings) = self.settings.clone() else {
            return true;
        };
        let Some(path) = settings.path else {
            return true;
        };
        self.store = None;
        let deleted = delete_or_log(&path);
        if settings.enabled {
            self.open(&path);
            return deleted && self.store.is_some();
        }
        deleted
    }

    /// Commits everything queued before the flush request was sent.
    fn flush(&mut self) -> bool {
        while let Ok(inbound) = self.events.try_recv() {
            if let Inbound::Event(event) = inbound {
                self.push(event);
            }
        }
        self.commit()
    }

    fn discard_pending(&mut self) {
        while self.events.try_recv().is_ok() {}
        self.batch.clear();
        self.batch_started = None;
    }

    fn commit(&mut self) -> bool {
        self.batch_started = None;
        if self.batch.is_empty() {
            return true;
        }
        let batch = std::mem::take(&mut self.batch);
        let Some(store) = self.store.as_mut() else {
            return false;
        };
        match store.insert_batch(&batch) {
            Ok(()) => true,
            Err(e) => {
                self.shared.note_dropped(batch.len() as u64);
                self.on_write_error(&e);
                false
            }
        }
    }

    fn maintain(&mut self) {
        self.next_maintenance = Instant::now() + MAINTENANCE_INTERVAL;
        self.purge();
        self.recompute_popular();
    }

    fn purge(&mut self) {
        let (Some(store), Some(settings)) = (&self.store, &self.settings) else {
            return;
        };
        if let Err(e) = store.purge(unix_now(), settings.retention_days) {
            self.on_write_error(&e);
        }
    }

    fn recompute_popular(&mut self) {
        let (Some(store), Some(settings)) = (&self.store, &self.settings) else {
            self.shared.publish_popular(HashSet::new());
            return;
        };
        let ranked = store.popular(unix_now(), settings.popular_count, settings.popular_days);
        match ranked {
            Ok(popular) => self.shared.publish_popular(popular),
            Err(e) => self.on_write_error(&e),
        }
    }

    /// A damaged file is deleted and recreated. Anything else (a full disk, a
    /// permission change) is logged at most once a minute and retried with the
    /// next batch.
    fn on_write_error(&mut self, error: &rusqlite::Error) {
        if store::is_corruption(error) {
            if let Some(path) = self.store.take().map(|s| s.path().to_path_buf()) {
                log::error!("lookup history: database damaged while in use: {}", error);
                self.open(&path);
            }
            return;
        }
        if self
            .last_write_error_log
            .is_none_or(|at| at.elapsed() >= WRITE_ERROR_LOG_INTERVAL)
        {
            self.last_write_error_log = Some(Instant::now());
            log::error!("lookup history: write failed: {}", error);
        }
    }

    fn set_recording(&self, on: bool) {
        let enabled = self.settings.as_ref().is_some_and(|s| s.enabled);
        self.shared
            .recording
            .store(on && enabled, Ordering::Relaxed);
    }
}

fn delete_or_log(path: &std::path::Path) -> bool {
    match store::delete_files(path) {
        Ok(()) => true,
        Err(e) => {
            log::error!("lookup history: cannot delete {}: {}", path.display(), e);
            false
        }
    }
}
