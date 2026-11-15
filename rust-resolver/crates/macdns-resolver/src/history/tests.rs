// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use super::store::{self, Store};
use super::*;
use rusqlite::Connection;
use serde_json::Value;
use std::path::Path;
use tempfile::TempDir;

/// 2025-11-07 00:00:00 UTC.
const DAY0: i64 = 1_762_473_600;
/// 12:17:05 UTC on `DAY0`.
const NOW: i64 = DAY0 + 12 * 3600 + 17 * 60 + 5;

fn event(ts: i64, name: &str, route: Route, rcode: u16) -> LookupEvent {
    LookupEvent {
        ts,
        name: name.to_owned(),
        qtype: 1,
        rcode,
        answers: u16::from(rcode == 0),
        route,
        provider: String::new(),
        latency_us: 1000,
        block_rule: String::new(),
        block_category: String::new(),
    }
}

fn provider_event(ts: i64, name: &str, provider: &str, latency_us: u32) -> LookupEvent {
    LookupEvent {
        provider: provider.to_owned(),
        latency_us,
        ..event(ts, name, Route::Provider, 0)
    }
}

fn blocked_event(ts: i64, name: &str, rule: &str, category: &str) -> LookupEvent {
    LookupEvent {
        block_rule: rule.to_owned(),
        block_category: category.to_owned(),
        latency_us: 200,
        ..event(ts, name, Route::Blocked, 3)
    }
}

fn db_path(dir: &TempDir) -> PathBuf {
    dir.path().join("MacDNS").join("query-history.sqlite")
}

fn seeded(dir: &TempDir, events: &[LookupEvent]) -> PathBuf {
    let path = db_path(dir);
    let mut store = Store::open(&path).expect("open store");
    store.insert_batch(events).expect("insert batch");
    path
}

fn count(path: &Path, sql: &str) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row(sql, [], |r| r.get(0))
        .unwrap()
}

fn view(path: &Path) -> query::View {
    query::View {
        enabled: true,
        path: Some(path.to_path_buf()),
        unavailable: None,
        retention_days: 30,
        popular_count: 0,
        popular: Arc::new(HashSet::new()),
        dropped: 0,
    }
}

fn ask(view: &query::View, request: &str) -> Value {
    let raw = query::run(request, view, LiveCacheStats::default(), NOW);
    serde_json::from_str(&raw).expect("response is JSON")
}

fn ok(view: &query::View, request: &str) -> Value {
    let response = ask(view, request);
    assert_eq!(response["status"], "ok", "{response}");
    response
}

fn series_counts(response: &Value, field: &str) -> Vec<i64> {
    response["series"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b[field].as_i64().unwrap())
        .collect()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", path.display()))
}

fn bytes_contain(path: &Path, needle: &str) -> bool {
    std::fs::read(path)
        .map(|bytes| bytes.windows(needle.len()).any(|w| w == needle.as_bytes()))
        .unwrap_or(false)
}

fn any_file_contains(path: &Path, needle: &str) -> bool {
    [
        path.to_path_buf(),
        sidecar(path, "-wal"),
        sidecar(path, "-shm"),
    ]
    .iter()
    .any(|p| bytes_contain(p, needle))
}

// MARK: - Store

#[test]
fn history_route_strings_match_the_spec() {
    let routes = [
        (Route::Cache, "cache"),
        (Route::Provider, "provider"),
        (Route::Stale, "stale"),
        (Route::Blocked, "blocked"),
        (Route::Override, "override"),
        (Route::Forward, "forward"),
        (Route::Captive, "captive"),
        (Route::Local, "local"),
        (Route::Failed, "failed"),
        (Route::Invalid, "invalid"),
    ];
    for (route, text) in routes {
        assert_eq!(route.as_str(), text);
    }
}

#[test]
fn history_open_creates_schema_version_1_with_owner_only_files() {
    let dir = TempDir::new().unwrap();
    let path = seeded(&dir, &[event(NOW, "a.example", Route::Cache, 0)]);

    let conn = Connection::open(&path).unwrap();
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, store::SCHEMA_VERSION);
    let journal: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(journal, "wal");
    for table in ["lookups", "hourly", "names"] {
        let found: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(found, 1, "table {table}");
    }
    #[cfg(unix)]
    for file in [path.clone(), sidecar(&path, "-wal"), sidecar(&path, "-shm")] {
        assert_eq!(mode(&file), 0o600, "{}", file.display());
    }
}

#[test]
fn history_batch_coalesces_hourly_counts_and_names() {
    let dir = TempDir::new().unwrap();
    let hour = DAY0 + 10 * 3600;
    let path = seeded(
        &dir,
        &[
            event(hour + 1, "WWW.Example.COM.", Route::Cache, 0),
            event(hour + 50, "www.example.com", Route::Cache, 0),
            event(hour + 3599, "www.example.com", Route::Cache, 0),
            event(hour + 3600, "www.example.com", Route::Cache, 0),
            provider_event(hour + 10, "www.example.com", "Cloudflare", 5000),
        ],
    );

    assert_eq!(count(&path, "SELECT COUNT(*) FROM lookups"), 5);
    assert_eq!(
        count(
            &path,
            "SELECT COUNT(*) FROM lookups WHERE name = 'www.example.com'"
        ),
        5
    );
    let first_hour_cache = format!(
        "SELECT count FROM hourly WHERE hour = {} AND route = 'cache'",
        hour / 3600
    );
    assert_eq!(count(&path, &first_hour_cache), 3);
    assert_eq!(count(&path, "SELECT COUNT(*) FROM hourly"), 3);
    assert_eq!(
        count(
            &path,
            "SELECT latency_sum_us FROM hourly WHERE route = 'provider'"
        ),
        5000
    );
    assert_eq!(count(&path, "SELECT first_seen FROM names"), hour + 1);
    assert_eq!(count(&path, "SELECT last_seen FROM names"), hour + 3600);

    let mut store = Store::open(&path).unwrap();
    store
        .insert_batch(&[event(hour + 7, "www.example.com", Route::Cache, 0)])
        .unwrap();
    assert_eq!(count(&path, &first_hour_cache), 4);
}

fn names_in(path: &Path, table: &str) -> Vec<String> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare(&format!("SELECT DISTINCT name FROM {table} ORDER BY name"))
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Raw rows feed the Log and the 1h/24h ranges for a fixed week. The
/// aggregates follow the user's retention.
#[test]
fn history_purge_keeps_raw_rows_for_7_days_and_aggregates_for_the_retention() {
    let dir = TempDir::new().unwrap();
    let path = seeded(
        &dir,
        &[
            event(NOW - 49 * 3600, "two-days.example", Route::Cache, 0),
            event(NOW - 6 * 86_400, "six-days.example", Route::Cache, 0),
            event(NOW - 8 * 86_400, "eight-days.example", Route::Cache, 0),
            event(NOW - 20 * 86_400, "twenty-days.example", Route::Cache, 0),
            event(NOW - 31 * 86_400, "month-old.example", Route::Cache, 0),
        ],
    );
    let store = Store::open(&path).unwrap();

    store.purge(NOW, 30).unwrap();
    assert_eq!(
        names_in(&path, "lookups"),
        ["six-days.example", "two-days.example"]
    );
    let within_30_days = [
        "eight-days.example",
        "six-days.example",
        "twenty-days.example",
        "two-days.example",
    ];
    assert_eq!(names_in(&path, "hourly"), within_30_days);
    assert_eq!(names_in(&path, "names"), within_30_days);

    store.purge(NOW, 7).unwrap();
    assert_eq!(
        names_in(&path, "lookups"),
        ["six-days.example", "two-days.example"]
    );
    let within_7_days = ["six-days.example", "two-days.example"];
    assert_eq!(names_in(&path, "hourly"), within_7_days);
    assert_eq!(names_in(&path, "names"), within_7_days);
}

#[test]
fn history_purge_removes_more_rows_than_one_batch() {
    let dir = TempDir::new().unwrap();
    let mut events: Vec<_> = (0..25_000)
        .map(|i| {
            event(
                NOW - 8 * 86_400 + i,
                &format!("h{i}.example"),
                Route::Cache,
                0,
            )
        })
        .collect();
    events.push(event(NOW - 6 * 86_400, "kept.example", Route::Cache, 0));
    let path = seeded(&dir, &events);
    Store::open(&path).unwrap().purge(NOW, 7).unwrap();
    assert_eq!(names_in(&path, "lookups"), ["kept.example"]);
    assert_eq!(names_in(&path, "hourly"), ["kept.example"]);
}

#[test]
fn history_popular_ranks_answered_lookups_and_skips_the_rest() {
    let dir = TempDir::new().unwrap();
    let mut events = Vec::new();
    let mut add = |n: usize, e: LookupEvent| events.extend(std::iter::repeat_n(e, n));
    add(5, event(NOW - 60, "top.example", Route::Cache, 0));
    add(2, event(NOW - 60, "top.example", Route::Provider, 0));
    add(4, event(NOW - 60, "stale.example", Route::Stale, 0));
    add(3, event(NOW - 60, "second.example", Route::Provider, 0));
    add(
        50,
        blocked_event(NOW - 60, "ads.example", "ads.example", "ads"),
    );
    add(50, event(NOW - 60, "printer.local", Route::Forward, 0));
    add(50, event(NOW - 60, "broken.example", Route::Failed, 2));
    add(50, event(NOW - 60, "missing.example", Route::Provider, 3));
    add(
        50,
        LookupEvent {
            qtype: 255,
            ..event(NOW - 60, "any.example", Route::Provider, 0)
        },
    );
    add(50, event(NOW - 3 * 86_400, "old.example", Route::Cache, 0));
    let path = seeded(&dir, &events);
    let store = Store::open(&path).unwrap();

    let key = |name: &str| CacheKey {
        name: name.to_owned(),
        qtype: 1,
    };
    let all = store.popular(NOW, 100, 1).unwrap();
    let expected: HashSet<_> = ["top.example", "stale.example", "second.example"]
        .into_iter()
        .map(key)
        .collect();
    assert!(all == expected, "popular set differs");

    let top_two = store.popular(NOW, 2, 1).unwrap();
    let expected_two: HashSet<_> = [key("top.example"), key("stale.example")].into();
    assert!(top_two == expected_two, "top two differ");
    assert!(store
        .popular(NOW, 100, 7)
        .unwrap()
        .contains(&key("old.example")));
    assert!(store.popular(NOW, 0, 7).unwrap().is_empty());
}

/// Names of the files left next to the database: what a deletion must leave behind.
fn files_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn columns(path: &Path, table: &str) -> Vec<String> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info(?1)")
        .unwrap();
    stmt.query_map([table], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn history_corrupt_file_is_deleted_and_replaced() {
    let dir = TempDir::new().unwrap();
    let path = db_path(&dir);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"this is not a sqlite database, not even close").unwrap();

    let mut store = Store::open(&path).expect("recovers");
    store
        .insert_batch(&[event(NOW, "a.example", Route::Cache, 0)])
        .unwrap();

    assert!(!any_file_contains(&path, "not a sqlite database"));
    assert_eq!(
        files_in(path.parent().unwrap()),
        [
            "query-history.sqlite",
            "query-history.sqlite-shm",
            "query-history.sqlite-wal"
        ],
        "no copy of the damaged file is kept"
    );
    assert_eq!(count(&path, "SELECT COUNT(*) FROM lookups"), 1);
}

#[test]
fn history_newer_schema_version_is_deleted_and_replaced() {
    let dir = TempDir::new().unwrap();
    let path = db_path(&dir);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE future (x); PRAGMA user_version = 2;")
        .unwrap();

    Store::open(&path).expect("recovers");

    assert_eq!(count(&path, "PRAGMA user_version"), store::SCHEMA_VERSION);
    assert_eq!(
        count(
            &path,
            "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'future'"
        ),
        0
    );
}

#[test]
fn history_missing_table_is_recreated_instead_of_failing_every_write() {
    let dir = TempDir::new().unwrap();
    let path = seeded(&dir, &[event(NOW - 60, "a.example", Route::Cache, 0)]);
    Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE names;")
        .unwrap();

    let mut store = Store::open(&path).expect("recovers");

    store
        .insert_batch(&[event(NOW, "b.example", Route::Cache, 0)])
        .expect("writes work again");
    assert_eq!(count(&path, "SELECT COUNT(*) FROM names"), 1);
}

#[test]
fn history_changed_columns_are_recreated() {
    let dir = TempDir::new().unwrap();
    let path = seeded(&dir, &[event(NOW - 60, "a.example", Route::Cache, 0)]);
    let expected = columns(&path, "lookups");
    Connection::open(&path)
        .unwrap()
        .execute_batch("ALTER TABLE lookups DROP COLUMN block_category;")
        .unwrap();

    Store::open(&path).expect("recovers");

    assert_eq!(columns(&path, "lookups"), expected);
}

#[test]
fn history_unversioned_file_with_a_foreign_table_of_the_same_name_is_recreated() {
    let dir = TempDir::new().unwrap();
    let path = db_path(&dir);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE lookups (x TEXT);")
        .unwrap();

    let mut store = Store::open(&path).expect("recovers");

    store
        .insert_batch(&[event(NOW, "a.example", Route::Cache, 0)])
        .expect("writes work");
}

#[test]
fn history_matching_schema_keeps_its_rows() {
    let dir = TempDir::new().unwrap();
    let path = seeded(&dir, &[event(NOW - 60, "a.example", Route::Cache, 0)]);

    Store::open(&path).expect("opens");

    assert_eq!(count(&path, "SELECT COUNT(*) FROM lookups"), 1);
}

#[test]
fn history_unusable_location_reports_the_reason() {
    let dir = TempDir::new().unwrap();
    let blocker = dir.path().join("MacDNS");
    std::fs::write(&blocker, b"a file where the directory should be").unwrap();
    let reason = Store::open(&blocker.join("query-history.sqlite"))
        .err()
        .expect("cannot open under a file");
    assert!(reason.contains("cannot create directory"), "{reason}");
}

// MARK: - Recording and the writer

fn running(dir: &TempDir) -> (History, PathBuf) {
    let history = History::new();
    let path = db_path(dir);
    history
        .configure(Some(path.clone()), true, 30, 0, 7)
        .expect("valid settings");
    assert!(history.flush(), "the writer applied the settings");
    (history, path)
}

fn ask_history(history: &History, request: &str) -> Value {
    serde_json::from_str(&history.query_at(request, LiveCacheStats::default(), unix_now())).unwrap()
}

/// A history whose writer has not started yet. The returned receivers are
/// what the writer reads once it runs.
fn with_busy_writer() -> (History, Receiver<Inbound>, Receiver<Control>) {
    let history = History::new();
    let started = std::mem::replace(&mut *lock(&history.writer), WriterState::Running);
    let WriterState::NotStarted(events, controls) = started else {
        panic!("the writer already started");
    };
    (history, events, controls)
}

/// On a cold boot the writer took more than 5 s to open the database. It
/// cannot refuse settings that keep history on, so nothing waits for it and
/// it applies them when it gets there. 2.5.0 waited, took the timeout for a
/// rejection and reported history as off, recording nothing, until the next
/// agent start.
#[test]
fn history_enable_never_waits_for_the_writer_and_stays_on() {
    let dir = TempDir::new().unwrap();
    let (history, events, controls) = with_busy_writer();

    let started = std::time::Instant::now();
    let result = history.configure(Some(db_path(&dir)), true, 30, 100, 7);

    assert_eq!(result, Ok(()));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    let writer = Writer::new(Arc::clone(&history.shared), events, controls);
    std::thread::spawn(move || writer.run());
    history.record(event(unix_now(), "late.example", Route::Cache, 0));
    assert!(history.flush());
    let status = ask_history(&history, r#"{"kind":"status"}"#);
    assert_eq!(status["status"], "ok", "{status}");
    assert_eq!(status["enabled"], true);
    let log = ask_history(
        &history,
        r#"{"kind":"log","result":"all","query":"","limit":10,"beforeId":null}"#,
    );
    assert_eq!(log["entries"][0]["name"], "late.example", "{log}");
}

/// A writer that is gone never applies anything, so history stays off.
#[test]
fn history_enable_without_a_writer_is_rejected_and_stays_off() {
    let dir = TempDir::new().unwrap();
    let (history, events, controls) = with_busy_writer();
    drop((events, controls));

    let result = history.configure(Some(db_path(&dir)), true, 30, 100, 7);

    assert_eq!(result, Err(ConfigError::NotApplied));
    assert!(!history.shared.recording.load(Ordering::Relaxed));
    assert_eq!(
        ask_history(&history, r#"{"kind":"status"}"#)["status"],
        "disabled"
    );
}

/// A store that cannot open is opened again by a later lookup instead of
/// staying unavailable until the agent restarts.
#[cfg(unix)]
#[test]
fn history_store_that_cannot_open_is_retried_by_a_later_lookup() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let path = db_path(&dir);
    let parent = path.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();
    let (history, events, controls) = with_busy_writer();
    let mut writer = Writer::new(Arc::clone(&history.shared), events, controls);
    writer.open_retry_interval = Duration::ZERO;
    std::thread::spawn(move || writer.run());

    history
        .configure(Some(path.clone()), true, 30, 0, 7)
        .unwrap();
    assert!(history.flush());
    let unavailable = ask_history(&history, r#"{"kind":"status"}"#);
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(unavailable["status"], "unavailable", "{unavailable}");

    history.record(event(unix_now(), "retried.example", Route::Cache, 0));
    assert!(history.flush());

    let status = ask_history(&history, r#"{"kind":"status"}"#);
    assert_eq!(status["status"], "ok", "{status}");
    let log = ask_history(
        &history,
        r#"{"kind":"log","result":"all","query":"","limit":10,"beforeId":null}"#,
    );
    assert_eq!(log["entries"][0]["name"], "retried.example", "{log}");
}

#[test]
fn history_full_queue_drops_and_counts_without_blocking() {
    let history = History::with_capacity(1);
    history.shared.recording.store(true, Ordering::Relaxed);
    for _ in 0..3 {
        history.record(event(NOW, "a.example", Route::Cache, 0));
    }
    assert_eq!(history.shared.dropped.load(Ordering::Relaxed), 2);
}

/// The lookup thread only counts a drop. Logging it there blocked one lookup
/// for 255 ms behind a slow logger.
#[test]
fn history_full_queue_never_logs_on_the_lookup_path() {
    let history = History::with_capacity(1);
    history.shared.recording.store(true, Ordering::Relaxed);
    let lines = crate::log_hooks::capture_logs(|| {
        for _ in 0..3 {
            history.record(event(NOW, "a.example", Route::Cache, 0));
        }
    });
    assert!(lines.is_empty(), "{lines:?}");
    assert_eq!(history.shared.dropped.load(Ordering::Relaxed), 2);
}

#[test]
fn history_writer_reports_drops_with_the_total_at_most_once_a_minute() {
    let shared = Arc::new(Shared::new());
    let (_events, event_rx) = std::sync::mpsc::sync_channel(1);
    let (_controls, control_rx) = std::sync::mpsc::channel();
    let mut writer = Writer::new(Arc::clone(&shared), event_rx, control_rx);
    let lines = crate::log_hooks::capture_logs(|| {
        writer.report_drops();
        shared.note_dropped(2);
        writer.report_drops();
        shared.note_dropped(3);
        writer.report_drops();
    });
    let messages: Vec<_> = lines.iter().map(|(_, m)| m.as_str()).collect();
    assert_eq!(messages, ["lookup history: 2 event(s) dropped since start"]);
}

#[test]
fn history_nothing_is_queued_while_not_recording() {
    let history = History::with_capacity(1);
    for _ in 0..3 {
        history.record(event(NOW, "a.example", Route::Cache, 0));
    }
    assert_eq!(history.shared.dropped.load(Ordering::Relaxed), 0);
}

#[test]
fn history_recorded_events_reach_the_log_after_flush() {
    let dir = TempDir::new().unwrap();
    let (history, _) = running(&dir);
    history.record(event(unix_now(), "Recorded.Example.", Route::Cache, 0));
    assert!(history.flush());

    let log = ask_history(
        &history,
        r#"{"kind":"log","result":"all","query":"","limit":10,"beforeId":null}"#,
    );
    assert_eq!(log["status"], "ok", "{log}");
    assert_eq!(log["entries"][0]["name"], "recorded.example");
    assert_eq!(log["entries"][0]["route"], "cache");

    let status = ask_history(&history, r#"{"kind":"status"}"#);
    assert_eq!(status["status"], "ok");
    assert_eq!(status["enabled"], true);
    assert_eq!(status["retentionDays"], 30);
    assert_eq!(status["droppedEvents"], 0);
    assert!(status["sizeBytes"].as_u64().unwrap() > 0);
}

/// Turning history off stops recording and keeps what is stored. Clear
/// History is what deletes it.
#[test]
fn history_disable_keeps_the_files_and_stops_recording() {
    let dir = TempDir::new().unwrap();
    let (history, path) = running(&dir);
    history.record(event(unix_now(), "kept.example", Route::Cache, 0));
    assert!(history.flush());

    history.configure(None, false, 30, 0, 7).unwrap();
    assert!(history.flush());

    assert!(path.exists());
    assert!(any_file_contains(&path, "kept.example"));
    assert!(!history.shared.recording.load(Ordering::Relaxed));
    assert!(history.popular().is_empty());
    assert_eq!(
        ask_history(&history, r#"{"kind":"status"}"#)["status"],
        "disabled"
    );

    history.configure(None, true, 30, 0, 7).unwrap();
    assert!(history.flush());
    let log = ask_history(
        &history,
        r#"{"kind":"log","result":"all","query":"","limit":10,"beforeId":null}"#,
    );
    assert_eq!(log["entries"][0]["name"], "kept.example", "{log}");
}

/// Turning history off cannot fail in the writer, so nothing waits for it.
/// 2.5.0 waited 5 s for the deletion and, on a timeout, sent the previous
/// settings after the queued disable, which deleted the database and turned
/// history back on empty while the save reported a failure.
#[test]
fn history_disable_never_waits_for_the_writer() {
    let dir = TempDir::new().unwrap();
    let (history, events, controls) = with_busy_writer();
    history
        .configure(Some(db_path(&dir)), true, 30, 0, 7)
        .unwrap();

    let started = std::time::Instant::now();
    let result = history.configure(None, false, 30, 0, 7);

    assert_eq!(result, Ok(()));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert!(!history.shared.recording.load(Ordering::Relaxed));
    drop((events, controls));
}

#[test]
fn history_clear_while_off_deletes_the_files() {
    let dir = TempDir::new().unwrap();
    let (history, path) = running(&dir);
    history.record(event(unix_now(), "secret-host.example", Route::Cache, 0));
    assert!(history.flush());
    history.configure(None, false, 30, 0, 7).unwrap();
    assert!(history.flush());
    assert!(path.exists());

    assert!(history.clear());

    for file in [path.clone(), sidecar(&path, "-wal"), sidecar(&path, "-shm")] {
        assert!(!file.exists(), "{} still exists", file.display());
    }
    assert!(!history.shared.recording.load(Ordering::Relaxed));
    assert_eq!(
        ask_history(&history, r#"{"kind":"status"}"#)["status"],
        "disabled"
    );
}

/// A lookup that history is on for but no store can take is lost, and the
/// drop counter and its warning say so.
#[cfg(unix)]
#[test]
fn history_lookups_lost_while_the_store_cannot_open_are_counted() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let path = db_path(&dir);
    let parent = path.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();
    let history = History::new();
    history
        .configure(Some(path.clone()), true, 30, 0, 7)
        .unwrap();
    assert!(history.flush());

    for _ in 0..3 {
        history.record(event(unix_now(), "lost.example", Route::Cache, 0));
    }
    assert!(history.flush());
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(history.shared.dropped.load(Ordering::Relaxed), 3);
}

#[test]
fn history_clear_removes_old_lookups_from_the_files_and_keeps_recording() {
    let dir = TempDir::new().unwrap();
    let (history, path) = running(&dir);
    history.record(event(unix_now(), "secret-host.example", Route::Cache, 0));
    assert!(history.flush());
    assert!(any_file_contains(&path, "secret-host.example"));

    assert!(history.clear());

    assert!(!any_file_contains(&path, "secret-host.example"));
    let log_request = r#"{"kind":"log","result":"all","query":"","limit":10,"beforeId":null}"#;
    assert_eq!(
        ask_history(&history, log_request)["entries"],
        serde_json::json!([])
    );
    assert!(history.popular().is_empty());

    history.record(event(unix_now(), "after-clear.example", Route::Cache, 0));
    assert!(history.flush());
    assert_eq!(
        ask_history(&history, log_request)["entries"][0]["name"],
        "after-clear.example"
    );
}

/// Without a configured store nothing was deleted, so the agent must not
/// tell the user their history is gone.
#[test]
fn history_clear_without_a_configured_store_reports_failure() {
    let history = History::new();
    assert!(!history.clear());

    history.configure(None, false, 30, 0, 7).unwrap();
    assert!(!history.clear());
}

#[test]
fn history_popular_set_is_published_when_configured() {
    let dir = TempDir::new().unwrap();
    let path = db_path(&dir);
    let now = unix_now();
    {
        let mut store = Store::open(&path).unwrap();
        store
            .insert_batch(&[
                event(now - 60, "popular.example.", Route::Cache, 0),
                event(now - 60, "popular.example", Route::Cache, 0),
            ])
            .unwrap();
    }
    let history = History::new();
    history
        .configure(Some(path.clone()), true, 30, 0, 7)
        .unwrap();
    assert!(history.flush());
    assert!(history.popular().is_empty(), "count 0 publishes nothing");

    history.configure(None, true, 30, 100, 7).unwrap();
    assert!(history.flush());
    assert!(history.popular().contains(&CacheKey {
        name: "popular.example".to_owned(),
        qtype: 1,
    }));
}

/// A shorter retention takes effect when it is applied, not at the next
/// hourly maintenance.
#[test]
fn history_shorter_retention_purges_when_applied() {
    let dir = TempDir::new().unwrap();
    let path = db_path(&dir);
    let now = unix_now();
    Store::open(&path)
        .unwrap()
        .insert_batch(&[
            event(now - 3 * 86_400, "three-days.example", Route::Cache, 0),
            event(now - 10 * 86_400, "ten-days.example", Route::Cache, 0),
            event(now - 20 * 86_400, "twenty-days.example", Route::Cache, 0),
        ])
        .unwrap();
    let history = History::new();

    history
        .configure(Some(path.clone()), true, 30, 0, 7)
        .unwrap();
    assert!(history.flush());
    assert_eq!(
        names_in(&path, "hourly"),
        [
            "ten-days.example",
            "three-days.example",
            "twenty-days.example"
        ]
    );

    history.configure(None, true, 14, 0, 7).unwrap();
    assert!(history.flush());
    assert_eq!(
        names_in(&path, "hourly"),
        ["ten-days.example", "three-days.example"]
    );

    history.configure(None, true, 7, 0, 7).unwrap();
    assert!(history.flush());
    assert_eq!(names_in(&path, "hourly"), ["three-days.example"]);
    assert_eq!(names_in(&path, "names"), ["three-days.example"]);
    assert_eq!(names_in(&path, "lookups"), ["three-days.example"]);
}

#[test]
fn history_configure_rejects_values_outside_the_allowed_choices() {
    let history = History::new();
    assert_eq!(
        history.configure(None, true, 8, 0, 7),
        Err(ConfigError::RetentionDays(8))
    );
    assert_eq!(
        history.configure(None, true, 30, 150, 7),
        Err(ConfigError::PopularCount(150))
    );
    assert_eq!(
        history.configure(None, true, 30, 100, 3),
        Err(ConfigError::PopularDays(3))
    );
    assert_eq!(
        history.configure(None, true, 7, 100, 14),
        Err(ConfigError::PopularDaysExceedRetention {
            days: 14,
            retention: 7
        })
    );
    for retention in RETENTION_DAYS_CHOICES {
        for count in POPULAR_COUNT_CHOICES {
            for days in POPULAR_DAYS_CHOICES.into_iter().filter(|d| *d <= retention) {
                assert_eq!(
                    history.configure(None, false, retention, count, days),
                    Ok(())
                );
            }
        }
    }
}

#[test]
fn history_unavailable_store_answers_unavailable_and_keeps_going() {
    let dir = TempDir::new().unwrap();
    let blocker = dir.path().join("MacDNS");
    std::fs::write(&blocker, b"a file where the directory should be").unwrap();
    let history = History::new();
    history
        .configure(Some(blocker.join("query-history.sqlite")), true, 30, 0, 7)
        .unwrap();
    assert!(history.flush());

    // Lookups still reach the writer, so a later one can open the store.
    history.record(event(NOW, "a.example", Route::Cache, 0));
    assert!(history.shared.recording.load(Ordering::Relaxed));
    let status = ask_history(&history, r#"{"kind":"status"}"#);
    assert_eq!(status["status"], "unavailable");
    assert!(status["reason"]
        .as_str()
        .unwrap()
        .contains("cannot create directory"));
}

#[test]
fn history_capture_sink_takes_recorded_events() {
    let capture = capture::start();
    record(event(NOW, "Captured.Example.", Route::Blocked, 3));
    let events = capture.events_for("captured.example");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].route, Route::Blocked);
}

// MARK: - Queries

#[test]
fn history_summary_counts_routes_providers_answers_and_previous_period() {
    let dir = TempDir::new().unwrap();
    let path = seeded(
        &dir,
        &[
            event(NOW - 10, "a.example", Route::Cache, 0),
            event(NOW - 20, "a.example", Route::Cache, 0),
            provider_event(NOW - 30, "b.example", "Cloudflare", 10_000),
            provider_event(NOW - 40, "c.example", "Cloudflare", 20_000),
            provider_event(NOW - 50, "d.example", "Quad9", 30_000),
            blocked_event(NOW - 60, "ads.example", "ads.example", "ads"),
            event(NOW - 70, "gone.example", Route::Provider, 3),
            event(NOW - 80, "printer.local", Route::Forward, 2),
            event(NOW - 90, "bad.example", Route::Invalid, 4),
            event(NOW - 26 * 3600, "yesterday.example", Route::Cache, 0),
        ],
    );
    let response = ok(
        &view(&path),
        r#"{"kind":"summary","range":"24h","utcOffsetSecs":-10800}"#,
    );

    assert_eq!(response["total"], 9);
    assert_eq!(response["previousTotal"], 1);
    assert_eq!(response["cache"], 2);
    assert_eq!(response["provider"], 4);
    assert_eq!(response["blocked"], 1);
    assert_eq!(response["avgProviderLatencyMs"], 15.25);
    assert_eq!(
        response["answers"],
        serde_json::json!({"answered": 5, "blocked": 1, "notFound": 1, "failed": 2})
    );
    assert_eq!(
        response["providers"],
        serde_json::json!([
            {"name": "Cloudflare", "answers": 2, "avgLatencyMs": 15.0},
            {"name": "Quad9", "answers": 1, "avgLatencyMs": 30.0},
        ])
    );
    let series = response["series"].as_array().unwrap();
    assert_eq!(series.len(), 24);
    let last = &series[23];
    assert_eq!(last["cache"], 2);
    assert_eq!(last["provider"], 4);
    assert_eq!(last["blocked"], 1);
    assert_eq!(last["other"], 2);
    assert!(response["keptFresh"].is_null());

    let first_seen: Vec<_> = response["firstSeen"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(first_seen.len(), 8);
    assert!(!first_seen.contains(&"yesterday.example"));
    let ads = response["firstSeen"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["name"] == "ads.example")
        .unwrap();
    assert_eq!(ads["blocked"], true);
    assert_eq!(ads["count"], 1);
}

/// One lookup a day for 60 days with a 30-day retention: the month before
/// the 30d range is mostly purged, so comparing against it would report a
/// huge growth that never happened.
#[test]
fn history_previous_total_is_null_when_the_previous_period_predates_retention() {
    let dir = TempDir::new().unwrap();
    let events: Vec<_> = (0..60)
        .map(|day| {
            event(
                NOW - day * 86_400 - 60,
                &format!("d{day}.example"),
                Route::Cache,
                0,
            )
        })
        .collect();
    let path = seeded(&dir, &events);
    Store::open(&path).unwrap().purge(NOW, 30).unwrap();
    let v = view(&path);

    let month = ok(&v, r#"{"kind":"summary","range":"30d","utcOffsetSecs":0}"#);
    assert_eq!(month["total"], 30);
    assert!(month["previousTotal"].is_null(), "{month}");

    let week = ok(&v, r#"{"kind":"summary","range":"7d","utcOffsetSecs":0}"#);
    assert_eq!(week["total"], 7);
    assert_eq!(week["previousTotal"], 7);

    let mut short = view(&path);
    short.retention_days = 7;
    let week_short = ok(
        &short,
        r#"{"kind":"summary","range":"7d","utcOffsetSecs":0}"#,
    );
    assert!(week_short["previousTotal"].is_null(), "{week_short}");

    assert_eq!(count(&path, "SELECT COUNT(*) FROM lookups"), 7);
    for retention in [&v, &short] {
        let day = ok(
            retention,
            r#"{"kind":"summary","range":"24h","utcOffsetSecs":0}"#,
        );
        assert_eq!(day["total"], 1);
        assert_eq!(day["previousTotal"], 1, "{day}");
        let hour = ok(
            retention,
            r#"{"kind":"summary","range":"1h","utcOffsetSecs":0}"#,
        );
        assert_eq!(hour["previousTotal"], 0, "{hour}");
    }
}

/// A writer commit between two statements of one request must not show up
/// in some figures and not in others.
#[test]
fn history_summary_reads_one_snapshot_while_the_writer_commits() {
    let dir = TempDir::new().unwrap();
    let path = seeded(&dir, &[event(NOW - 10, "a.example", Route::Cache, 0)]);
    let writer_path = path.clone();
    query::BETWEEN_READS.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            Store::open(&writer_path)
                .unwrap()
                .insert_batch(&[event(NOW - 5, "b.example", Route::Cache, 0)])
                .unwrap();
        }));
    });

    let response = ok(
        &view(&path),
        r#"{"kind":"summary","range":"24h","utcOffsetSecs":0}"#,
    );

    assert!(
        query::BETWEEN_READS.with(|hook| hook.borrow().is_none()),
        "the write ran"
    );
    assert_eq!(count(&path, "SELECT COUNT(*) FROM lookups"), 2);
    assert_eq!(response["total"], 1);
    assert_eq!(series_counts(&response, "cache").iter().sum::<i64>(), 1);
    assert_eq!(response["answers"]["answered"], 1);
    assert_eq!(response["firstSeen"].as_array().unwrap().len(), 1);
}

#[test]
fn history_extreme_utc_offsets_are_caller_errors() {
    let dir = TempDir::new().unwrap();
    let path = seeded(&dir, &[]);
    let v = view(&path);
    for offset in [i64::MIN, i64::MAX] {
        let request = format!(r#"{{"kind":"summary","range":"24h","utcOffsetSecs":{offset}}}"#);
        let response = ask(&v, &request);
        assert_eq!(response["status"], "error", "{request} -> {response}");
    }
}

#[test]
fn history_first_seen_excludes_names_known_before_the_range() {
    let dir = TempDir::new().unwrap();
    let path = seeded(
        &dir,
        &[
            event(NOW - 10 * 86_400, "known.example", Route::Cache, 0),
            event(NOW - 10, "known.example", Route::Cache, 0),
            event(NOW - 10, "new.example", Route::Cache, 0),
        ],
    );
    let response = ok(
        &view(&path),
        r#"{"kind":"summary","range":"1h","utcOffsetSecs":0}"#,
    );
    assert_eq!(
        response["firstSeen"],
        serde_json::json!([{"name": "new.example", "firstSeen": NOW - 10, "count": 1, "blocked": false}])
    );
}

#[test]
fn history_kept_fresh_counts_cache_answers_of_popular_keys() {
    let dir = TempDir::new().unwrap();
    let path = seeded(
        &dir,
        &[
            event(NOW - 10, "hot.example", Route::Cache, 0),
            event(NOW - 20, "hot.example", Route::Cache, 0),
            event(NOW - 30, "hot.example", Route::Provider, 0),
            event(NOW - 40, "cold.example", Route::Cache, 0),
        ],
    );
    let mut popular_view = view(&path);
    popular_view.popular_count = 100;
    popular_view.popular = Arc::new(
        [CacheKey {
            name: "hot.example".to_owned(),
            qtype: 1,
        }]
        .into_iter()
        .collect(),
    );
    let live = LiveCacheStats {
        prefetching: true,
        in_cache: 1,
        refreshes_per_second: 0.5,
    };
    let raw = query::run(
        r#"{"kind":"summary","range":"24h","utcOffsetSecs":0}"#,
        &popular_view,
        live,
        NOW,
    );
    let response: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        response["keptFresh"],
        serde_json::json!({"popularCount": 1, "inCache": 1, "cacheAnswers": 2, "refreshesPerSecond": 0.5})
    );

    let prefetch_off = LiveCacheStats {
        prefetching: false,
        ..live
    };
    let raw = query::run(
        r#"{"kind":"summary","range":"24h","utcOffsetSecs":0}"#,
        &popular_view,
        prefetch_off,
        NOW,
    );
    let response: Value = serde_json::from_str(&raw).unwrap();
    assert!(response["keptFresh"].is_null());
}

#[test]
fn history_hour_range_uses_five_minute_buckets() {
    let dir = TempDir::new().unwrap();
    let window_start = DAY0 + 11 * 3600 + 20 * 60;
    let path = seeded(
        &dir,
        &[
            event(window_start - 1, "between.example", Route::Cache, 0),
            event(window_start - 3600, "previous.example", Route::Cache, 0),
            event(window_start, "first.example", Route::Cache, 0),
            event(NOW, "now.example", Route::Cache, 0),
        ],
    );
    let response = ok(
        &view(&path),
        r#"{"kind":"summary","range":"1h","utcOffsetSecs":-10800}"#,
    );
    let series = response["series"].as_array().unwrap();
    assert_eq!(series.len(), 12);
    assert_eq!(series[0]["start"], window_start);
    assert_eq!(series[11]["start"], DAY0 + 12 * 3600 + 15 * 60);
    let cache = series_counts(&response, "cache");
    assert_eq!(cache[0], 1);
    assert_eq!(cache[11], 1);
    assert_eq!(response["total"], 2);
    assert_eq!(response["previousTotal"], 1);
}

#[test]
fn history_day_range_buckets_follow_a_half_hour_offset() {
    let dir = TempDir::new().unwrap();
    // UTC+5:30: local hours start at :30 UTC.
    let last_bucket = DAY0 + 11 * 3600 + 30 * 60;
    let path = seeded(
        &dir,
        &[
            event(last_bucket - 1, "a.example", Route::Cache, 0),
            event(last_bucket, "a.example", Route::Cache, 0),
            event(last_bucket + 1, "a.example", Route::Cache, 0),
        ],
    );
    let response = ok(
        &view(&path),
        r#"{"kind":"summary","range":"24h","utcOffsetSecs":19800}"#,
    );
    let series = response["series"].as_array().unwrap();
    assert_eq!(series[0]["start"], last_bucket - 23 * 3600);
    assert_eq!(series[23]["start"], last_bucket);
    let cache = series_counts(&response, "cache");
    assert_eq!(cache[22], 1);
    assert_eq!(cache[23], 2);
}

#[test]
fn history_week_range_buckets_by_local_day() {
    let dir = TempDir::new().unwrap();
    // UTC-3: the local day starts at 03:00 UTC.
    let today = DAY0 + 3 * 3600;
    let path = seeded(
        &dir,
        &[
            event(today - 1, "late.example", Route::Cache, 0),
            event(today, "early.example", Route::Cache, 0),
            event(today + 1, "early.example", Route::Cache, 0),
            event(
                today - 7 * 86_400 + 3600,
                "last-week.example",
                Route::Cache,
                0,
            ),
        ],
    );
    let response = ok(
        &view(&path),
        r#"{"kind":"summary","range":"7d","utcOffsetSecs":-10800}"#,
    );
    let series = response["series"].as_array().unwrap();
    assert_eq!(series.len(), 7);
    assert_eq!(series[0]["start"], today - 6 * 86_400);
    let cache = series_counts(&response, "cache");
    assert_eq!(cache[5], 1);
    assert_eq!(cache[6], 2);
    assert_eq!(response["total"], 3);
    assert_eq!(response["previousTotal"], 1);
}

// MARK: - Zoom

fn zoomed(span: &str, start: i64) -> String {
    format!(r#"{{"span":"{span}","start":{start}}}"#)
}

/// A zoomed hour has 12 five-minute buckets from `start`, and every kind
/// reads only that hour.
#[test]
fn history_zoomed_hour_reads_only_that_hour_in_five_minute_buckets() {
    let dir = TempDir::new().unwrap();
    // UTC-3: 06:00 local is 09:00 UTC.
    let start = DAY0 + 9 * 3600;
    let path = seeded(
        &dir,
        &[
            event(start - 1, "before.example", Route::Cache, 0),
            event(start, "first.example", Route::Cache, 0),
            event(start + 5 * 60 + 1, "second.example", Route::Cache, 0),
            blocked_event(start + 3599, "ads.example", "example", "ads"),
            blocked_event(start + 3600, "after.example", "example", "ads"),
        ],
    );
    let v = view(&path);
    let range = zoomed("1h", start);

    let summary = ok(
        &v,
        &format!(r#"{{"kind":"summary","range":{range},"utcOffsetSecs":-10800}}"#),
    );
    let series = summary["series"].as_array().unwrap();
    assert_eq!(series.len(), 12);
    assert_eq!(series[0]["start"], start);
    assert_eq!(series[11]["start"], start + 55 * 60);
    assert_eq!(series_counts(&summary, "cache")[..2], [1, 1]);
    assert_eq!(series_counts(&summary, "blocked")[11], 1);
    assert_eq!(summary["total"], 3);
    assert_eq!(summary["previousTotal"], 1);

    let hosts = ok(
        &v,
        &format!(
            r#"{{"kind":"topHosts","range":{range},"result":"all","query":"","limit":10,"utcOffsetSecs":-10800}}"#
        ),
    );
    assert_eq!(hosts["totalHosts"], 3);

    let detail = ok(
        &v,
        &format!(
            r#"{{"kind":"hostDetail","range":{range},"name":"first.example","utcOffsetSecs":-10800}}"#
        ),
    );
    let mut expected = vec![0; 12];
    expected[0] = 1;
    assert_eq!(series_counts(&detail, "count"), expected);

    let blocked = ok(
        &v,
        &format!(
            r#"{{"kind":"topBlocked","range":{range},"category":null,"limit":100,"utcOffsetSecs":-10800}}"#
        ),
    );
    let domains: Vec<_> = blocked["domains"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["domain"].as_str().unwrap())
        .collect();
    assert_eq!(domains, ["ads.example"]);

    let log = ok(
        &v,
        &format!(
            r#"{{"kind":"log","result":"all","query":"","limit":200,"beforeId":null,"range":{range},"utcOffsetSecs":-10800}}"#
        ),
    );
    let names: Vec<_> = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["ads.example", "second.example", "first.example"]);
}

/// A day older than the raw lookups still has hourly buckets, read from the
/// aggregates. Its Log has nothing, since single lookups are gone.
#[test]
fn history_zoomed_day_past_the_raw_lookups_reads_hourly_aggregates() {
    let dir = TempDir::new().unwrap();
    let start = DAY0 - 10 * 86_400;
    let path = seeded(
        &dir,
        &[
            event(start - 3600, "previous.example", Route::Cache, 0),
            event(start, "a.example", Route::Cache, 0),
            event(start + 30 * 60, "a.example", Route::Cache, 0),
            event(start + 23 * 3600 + 59 * 60, "b.example", Route::Cache, 0),
            event(start + 86_400, "next.example", Route::Cache, 0),
        ],
    );
    Store::open(&path).unwrap().purge(NOW, 30).unwrap();
    assert_eq!(count(&path, "SELECT COUNT(*) FROM lookups"), 0);
    let v = view(&path);
    let range = zoomed("24h", start);

    let summary = ok(
        &v,
        &format!(r#"{{"kind":"summary","range":{range},"utcOffsetSecs":0}}"#),
    );
    let series = summary["series"].as_array().unwrap();
    assert_eq!(series.len(), 24);
    assert_eq!(series[0]["start"], start);
    assert_eq!(series[23]["start"], start + 23 * 3600);
    let cache = series_counts(&summary, "cache");
    assert_eq!(cache[0], 2);
    assert_eq!(cache[23], 1);
    assert_eq!(summary["total"], 3);
    assert_eq!(summary["previousTotal"], 1);

    let hosts = ok(
        &v,
        &format!(
            r#"{{"kind":"topHosts","range":{range},"result":"all","query":"","limit":10,"utcOffsetSecs":0}}"#
        ),
    );
    assert_eq!(hosts["totalHosts"], 2);

    let log = ok(
        &v,
        &format!(
            r#"{{"kind":"log","result":"all","query":"","limit":200,"beforeId":null,"range":{range},"utcOffsetSecs":0}}"#
        ),
    );
    assert_eq!(log["entries"], serde_json::json!([]));
}

#[test]
fn history_zoomed_day_that_holds_now_ends_at_now() {
    let dir = TempDir::new().unwrap();
    let path = seeded(
        &dir,
        &[
            event(DAY0, "a.example", Route::Cache, 0),
            event(NOW, "b.example", Route::Cache, 0),
            event(NOW + 60, "later.example", Route::Cache, 0),
        ],
    );
    let summary = ok(
        &view(&path),
        &format!(
            r#"{{"kind":"summary","range":{},"utcOffsetSecs":0}}"#,
            zoomed("24h", DAY0)
        ),
    );
    let cache = series_counts(&summary, "cache");
    assert_eq!(cache.len(), 24);
    assert_eq!(cache[0], 1);
    assert_eq!(cache[12], 1);
    assert!(cache[13..].iter().all(|&c| c == 0), "{cache:?}");
    assert_eq!(summary["total"], 2);
}

#[test]
fn history_invalid_zooms_are_caller_errors() {
    let dir = TempDir::new().unwrap();
    let v = view(&seeded(&dir, &[]));
    let summary =
        |range: String| format!(r#"{{"kind":"summary","range":{range},"utcOffsetSecs":0}}"#);
    let bad = [
        summary(zoomed("7d", DAY0)),
        // Not a local midnight, not a local hour.
        summary(zoomed("24h", DAY0 + 3600)),
        summary(zoomed("1h", DAY0 + 60)),
        summary(zoomed("24h", DAY0 + 86_400)),
        // Five-minute buckets need the raw lookups, kept for 7 days.
        summary(zoomed("1h", DAY0 - 8 * 86_400)),
        summary(r#"{"span":"1h"}"#.to_owned()),
        format!(
            r#"{{"kind":"log","result":"all","query":"","limit":10,"beforeId":null,"range":{}}}"#,
            zoomed("1h", DAY0)
        ),
    ];
    for request in bad {
        let response = ask(&v, &request);
        assert_eq!(response["status"], "error", "{request} -> {response}");
        assert!(response["reason"].as_str().is_some_and(|r| !r.is_empty()));
    }
}

#[test]
fn history_top_hosts_filters_by_result_and_name() {
    let dir = TempDir::new().unwrap();
    let mut events = vec![
        event(NOW - 10, "www.google.com", Route::Cache, 0),
        event(NOW - 20, "www.google.com", Route::Cache, 0),
        provider_event(NOW - 30, "www.google.com", "Cloudflare", 1000),
        event(NOW - 40, "nope.google.com", Route::Provider, 3),
        blocked_event(NOW - 50, "ads.example", "example", "ads"),
        blocked_event(NOW - 55, "ads.example", "example", "ads"),
    ];
    events.push(event(NOW - 60, "api.example", Route::Failed, 2));
    let path = seeded(&dir, &events);
    let v = view(&path);

    let all = ok(
        &v,
        r#"{"kind":"topHosts","range":"24h","result":"all","query":"","limit":2,"utcOffsetSecs":0}"#,
    );
    assert_eq!(all["totalHosts"], 4);
    let hosts = all["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts[0]["name"], "www.google.com");
    assert_eq!(hosts[0]["count"], 3);
    assert_eq!(hosts[0]["cache"], 2);
    assert_eq!(hosts[0]["provider"], 1);
    assert_eq!(hosts[0]["lastSeen"], NOW - 10);
    assert_eq!(hosts[1]["name"], "ads.example");
    assert_eq!(hosts[1]["blocked"], 2);
    assert_eq!(hosts[1]["blockRule"], "example");
    assert_eq!(hosts[1]["blockCategory"], "ads");

    let google = ok(
        &v,
        r#"{"kind":"topHosts","range":"24h","result":"all","query":"GOOGLE","limit":10,"utcOffsetSecs":0}"#,
    );
    assert_eq!(google["totalHosts"], 2);

    let not_found = ok(
        &v,
        r#"{"kind":"topHosts","range":"24h","result":"notFound","query":"","limit":10,"utcOffsetSecs":0}"#,
    );
    assert_eq!(not_found["totalHosts"], 1);
    assert_eq!(not_found["hosts"][0]["name"], "nope.google.com");
    assert_eq!(not_found["hosts"][0]["notFound"], 1);

    let failed = ok(
        &v,
        r#"{"kind":"topHosts","range":"24h","result":"failed","query":"","limit":10,"utcOffsetSecs":0}"#,
    );
    assert_eq!(failed["hosts"][0]["name"], "api.example");
    assert_eq!(failed["hosts"][0]["failed"], 1);
}

#[test]
fn history_host_detail_breaks_down_one_name() {
    let dir = TempDir::new().unwrap();
    let path = seeded(
        &dir,
        &[
            event(NOW - 2 * 86_400, "www.google.com", Route::Cache, 0),
            event(NOW - 10, "www.google.com", Route::Cache, 0),
            provider_event(NOW - 3700, "www.google.com", "Cloudflare", 1000),
            LookupEvent {
                qtype: 28,
                ..provider_event(NOW - 20, "www.google.com", "Quad9", 1000)
            },
            event(NOW - 20, "other.example", Route::Cache, 0),
        ],
    );
    let response = ok(
        &view(&path),
        r#"{"kind":"hostDetail","range":"24h","name":"WWW.Google.com.","utcOffsetSecs":0}"#,
    );
    assert_eq!(response["name"], "www.google.com");
    assert_eq!(response["firstSeen"], NOW - 2 * 86_400);
    assert_eq!(response["lastSeen"], NOW - 10);
    assert_eq!(
        response["routes"],
        serde_json::json!({"cache": 1, "provider": 2})
    );
    assert_eq!(
        response["qtypes"],
        serde_json::json!([{"qtype": 1, "count": 2}, {"qtype": 28, "count": 1}])
    );
    assert_eq!(
        response["providers"],
        serde_json::json!([{"name": "Cloudflare", "count": 1}, {"name": "Quad9", "count": 1}])
    );
    let counts = series_counts(&response, "count");
    assert_eq!(counts[23], 2);
    assert_eq!(counts[22], 1);
    assert_eq!(response["blockRule"], "");
}

#[test]
fn history_log_lists_newest_first_with_filters_and_paging() {
    let dir = TempDir::new().unwrap();
    let path = seeded(
        &dir,
        &[
            event(NOW - 30, "a.example", Route::Cache, 0),
            blocked_event(
                NOW - 20,
                "app-measurement.com",
                "app-measurement.com",
                "trackers",
            ),
            event(NOW - 10, "b.example", Route::Cache, 0),
        ],
    );
    let v = view(&path);
    let all = ok(
        &v,
        r#"{"kind":"log","result":"all","query":"","limit":200,"beforeId":null}"#,
    );
    let names: Vec<_> = all["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["b.example", "app-measurement.com", "a.example"]);

    let blocked = ok(
        &v,
        r#"{"kind":"log","result":"blocked","query":"","limit":200,"beforeId":null}"#,
    );
    assert_eq!(
        blocked["entries"],
        serde_json::json!([{"id": 2, "ts": NOW - 20, "name": "app-measurement.com", "qtype": 1,
            "rcode": 3, "route": "blocked", "provider": "", "latencyMs": 0.2,
            "blockRule": "app-measurement.com", "blockCategory": "trackers"}])
    );

    let first = ok(
        &v,
        r#"{"kind":"log","result":"all","query":"example","limit":1,"beforeId":null}"#,
    );
    assert_eq!(first["entries"][0]["name"], "b.example");
    let page = ok(
        &v,
        &format!(
            r#"{{"kind":"log","result":"all","query":"example","limit":1,"beforeId":{}}}"#,
            first["entries"][0]["id"]
        ),
    );
    assert_eq!(page["entries"][0]["name"], "a.example");
}

/// A whole-second cursor would skip the rest of a second split across two
/// pages. Paging by row id returns every row exactly once.
#[test]
fn history_log_pages_through_rows_that_share_one_second() {
    let dir = TempDir::new().unwrap();
    let events: Vec<_> = [event(NOW - 20, "earlier.example", Route::Cache, 0)]
        .into_iter()
        .chain((0..5).map(|i| {
            event(
                NOW - 10,
                &format!("same-second-{i}.example"),
                Route::Cache,
                0,
            )
        }))
        .collect();
    let path = seeded(&dir, &events);
    let v = view(&path);

    let mut seen = Vec::new();
    let mut before_id = serde_json::Value::Null;
    for _ in 0..events.len() {
        let page = ok(
            &v,
            &format!(
                r#"{{"kind":"log","result":"all","query":"","limit":2,"beforeId":{before_id}}}"#
            ),
        );
        let entries = page["entries"].as_array().unwrap();
        let Some(last) = entries.last() else {
            break;
        };
        before_id = last["id"].clone();
        seen.extend(
            entries
                .iter()
                .map(|e| e["name"].as_str().unwrap().to_owned()),
        );
    }

    assert_eq!(
        seen,
        [
            "same-second-4.example",
            "same-second-3.example",
            "same-second-2.example",
            "same-second-1.example",
            "same-second-0.example",
            "earlier.example",
        ]
    );
}

#[test]
fn history_top_blocked_groups_by_domain_and_filters_by_category() {
    let dir = TempDir::new().unwrap();
    let path = seeded(
        &dir,
        &[
            blocked_event(
                NOW - 10,
                "stats.g.doubleclick.net",
                "doubleclick.net",
                "ads",
            ),
            blocked_event(
                NOW - 20,
                "stats.g.doubleclick.net",
                "doubleclick.net",
                "ads",
            ),
            blocked_event(
                NOW - 30,
                "app-measurement.com",
                "app-measurement.com",
                "trackers",
            ),
            event(NOW - 40, "www.google.com", Route::Cache, 0),
        ],
    );
    let v = view(&path);
    let all = ok(
        &v,
        r#"{"kind":"topBlocked","range":"24h","category":null,"limit":100,"utcOffsetSecs":0}"#,
    );
    assert_eq!(
        all["domains"],
        serde_json::json!([
            {"domain": "stats.g.doubleclick.net", "matchedRule": "doubleclick.net", "category": "ads", "blockCount": 2},
            {"domain": "app-measurement.com", "matchedRule": "app-measurement.com", "category": "trackers", "blockCount": 1},
        ])
    );
    let trackers = ok(
        &v,
        r#"{"kind":"topBlocked","range":"24h","category":"trackers","limit":100,"utcOffsetSecs":0}"#,
    );
    assert_eq!(trackers["domains"].as_array().unwrap().len(), 1);
}

#[test]
fn history_malformed_requests_are_caller_errors() {
    let dir = TempDir::new().unwrap();
    let path = seeded(&dir, &[]);
    let v = view(&path);
    let bad = [
        "not json",
        r#"{"kind":"nope"}"#,
        r#"{"range":"24h"}"#,
        r#"{"kind":"summary","range":"2h","utcOffsetSecs":0}"#,
        r#"{"kind":"summary","range":"24h"}"#,
        r#"{"kind":"summary","range":"24h","utcOffsetSecs":90000}"#,
        r#"{"kind":"topHosts","range":"24h","result":"all","query":"","limit":0,"utcOffsetSecs":0}"#,
        r#"{"kind":"topHosts","range":"24h","result":"all","query":"","limit":5000,"utcOffsetSecs":0}"#,
        r#"{"kind":"topHosts","range":"24h","result":"maybe","query":"","limit":10,"utcOffsetSecs":0}"#,
        r#"{"kind":"hostDetail","range":"24h","name":"","utcOffsetSecs":0}"#,
        r#"{"kind":"log","result":"all","query":"","limit":-1,"beforeId":null}"#,
        r#"{"kind":"log","result":"all","query":"","limit":10,"beforeId":"x"}"#,
    ];
    for request in bad {
        let response = ask(&v, request);
        assert_eq!(response["status"], "error", "{request} -> {response}");
        assert!(response["reason"].as_str().is_some_and(|r| !r.is_empty()));
    }
}

#[test]
fn history_disabled_and_unavailable_states_win_over_queries() {
    let dir = TempDir::new().unwrap();
    let path = seeded(&dir, &[]);
    let summary = r#"{"kind":"summary","range":"24h","utcOffsetSecs":0}"#;

    let mut disabled = view(&path);
    disabled.enabled = false;
    assert_eq!(
        ask(&disabled, summary),
        serde_json::json!({"status": "disabled"})
    );

    let mut broken = view(&path);
    broken.unavailable = Some("disk is gone".to_owned());
    assert_eq!(
        ask(&broken, summary),
        serde_json::json!({"status": "unavailable", "reason": "disk is gone"})
    );

    let missing = view(&dir.path().join("missing").join("query-history.sqlite"));
    assert_eq!(ask(&missing, summary)["status"], "unavailable");
}
