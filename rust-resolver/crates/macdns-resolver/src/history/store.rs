// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! The on-disk store: schema, open with recovery, batch writes, purge and
//! popularity. Only the writer thread holds a `Store`.

use super::LookupEvent;
use crate::cache::CacheKey;
use hickory_proto::rr::RecordType;
use rusqlite::{named_params, params, Connection, ErrorCode, OpenFlags};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(super) const SCHEMA_VERSION: i64 = 1;
/// Raw rows feed the Log and the 1h/24h ranges. They are kept for a fixed
/// week, never longer than the aggregates.
const RAW_RETENTION_DAYS: u32 = 7;
const PURGE_BATCH_ROWS: i64 = 10_000;
const WRITER_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const READER_BUSY_TIMEOUT: Duration = Duration::from_secs(2);

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS lookups (
  ts INTEGER NOT NULL,
  name TEXT NOT NULL,
  qtype INTEGER NOT NULL,
  rcode INTEGER NOT NULL,
  answers INTEGER NOT NULL,
  route TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT '',
  latency_us INTEGER NOT NULL,
  block_rule TEXT NOT NULL DEFAULT '',
  block_category TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS lookups_ts ON lookups(ts);
CREATE TABLE IF NOT EXISTS hourly (
  hour INTEGER NOT NULL,
  name TEXT NOT NULL,
  qtype INTEGER NOT NULL,
  route TEXT NOT NULL,
  rcode INTEGER NOT NULL,
  provider TEXT NOT NULL,
  block_rule TEXT NOT NULL,
  block_category TEXT NOT NULL,
  count INTEGER NOT NULL,
  latency_sum_us INTEGER NOT NULL,
  PRIMARY KEY (hour, name, qtype, route, rcode, provider, block_rule, block_category)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS names (
  name TEXT PRIMARY KEY,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL
) WITHOUT ROWID;
PRAGMA user_version = 1;
";

pub(super) struct Store {
    conn: Connection,
    path: PathBuf,
}

impl Store {
    /// Opens the database, deleting an unreadable, newer-version or reshaped
    /// file once and starting over. History is data, not configuration, so
    /// nothing is kept and the log line records why. Returns the reason when
    /// the new file fails too.
    pub(super) fn open(path: &Path) -> Result<Self, String> {
        let first = match Self::open_checked(path) {
            Ok(store) => return Ok(store),
            Err(reason) => reason,
        };
        log::error!(
            "lookup history: {} is unusable ({}); deleting it and starting over",
            path.display(),
            first
        );
        delete_files(path).map_err(|e| format!("{first}; deleting it failed: {e}"))?;
        Self::open_checked(path)
            .map_err(|second| format!("{first}; a new database failed: {second}"))
    }

    fn open_checked(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("cannot create directory: {e}"))?;
        }
        create_owner_only(path).map_err(|e| format!("cannot create file: {e}"))?;
        let conn = Connection::open(path).map_err(|e| format!("cannot open: {e}"))?;
        prepare_connection(&conn).map_err(|e| format!("not a usable database: {e}"))?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|e| format!("cannot read schema version: {e}"))?;
        if version > SCHEMA_VERSION {
            return Err(format!(
                "schema version {version} is newer than the supported {SCHEMA_VERSION}"
            ));
        }
        let check: String = conn
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(|e| format!("integrity check failed: {e}"))?;
        if check != "ok" {
            return Err(format!("integrity check failed: {check}"));
        }
        if version < SCHEMA_VERSION {
            conn.execute_batch(&format!("BEGIN; {SCHEMA} COMMIT;"))
                .map_err(|e| format!("cannot create schema: {e}"))?;
        }
        if !has_expected_schema(&conn).map_err(|e| format!("cannot read schema: {e}"))? {
            return Err(format!(
                "tables do not match schema version {SCHEMA_VERSION}"
            ));
        }
        restrict_sidecars(path);
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Writes one batch in a single transaction: raw rows, hourly counts
    /// coalesced in memory first, and first/last seen per name.
    pub(super) fn insert_batch(&mut self, events: &[LookupEvent]) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut insert = tx.prepare_cached(
                "INSERT INTO lookups (ts, name, qtype, rcode, answers, route, provider, \
                 latency_us, block_rule, block_category) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for e in events {
                insert.execute(params![
                    e.ts,
                    stored_name(&e.name),
                    e.qtype,
                    e.rcode,
                    e.answers,
                    e.route.as_str(),
                    e.provider,
                    e.latency_us,
                    e.block_rule,
                    e.block_category,
                ])?;
            }
            upsert_hourly(&tx, events)?;
            upsert_names(&tx, events)?;
        }
        tx.commit()
    }

    /// Deletes raw rows older than the raw retention and aggregates older
    /// than the retention, a bounded number of rows per statement so the
    /// write lock is never held for long.
    pub(super) fn purge(&self, now: i64, retention_days: u32) -> rusqlite::Result<()> {
        let retention_cutoff = cutoff(now, retention_days);
        self.delete_in_batches(
            "DELETE FROM lookups WHERE rowid IN \
             (SELECT rowid FROM lookups WHERE ts < :cutoff LIMIT :limit)",
            raw_cutoff(now, retention_days),
        )?;
        self.delete_in_batches(
            "DELETE FROM hourly WHERE (hour, name, qtype, route, rcode, provider, block_rule, \
             block_category) IN (SELECT hour, name, qtype, route, rcode, provider, block_rule, \
             block_category FROM hourly WHERE hour < :cutoff / 3600 LIMIT :limit)",
            retention_cutoff,
        )?;
        self.delete_in_batches(
            "DELETE FROM names WHERE name IN \
             (SELECT name FROM names WHERE last_seen < :cutoff LIMIT :limit)",
            retention_cutoff,
        )
    }

    fn delete_in_batches(&self, sql: &str, cutoff: i64) -> rusqlite::Result<()> {
        let mut stmt = self.conn.prepare(sql)?;
        loop {
            let deleted =
                stmt.execute(named_params! { ":cutoff": cutoff, ":limit": PURGE_BATCH_ROWS })?;
            if (deleted as i64) < PURGE_BATCH_ROWS {
                return Ok(());
            }
        }
    }

    /// The top `count` `(name, qtype)` pairs answered with NOERROR from the
    /// cache, a provider or stale data over the last `days`. Blocked, private
    /// and failed lookups never qualify, and neither do qtypes prefetch would
    /// not refresh.
    pub(super) fn popular(
        &self,
        now: i64,
        count: u32,
        days: u32,
    ) -> rusqlite::Result<HashSet<CacheKey>> {
        let mut popular = HashSet::new();
        if count == 0 {
            return Ok(popular);
        }
        let since_hour = (now - i64::from(days) * 86_400).div_euclid(3600);
        let mut stmt = self.conn.prepare(
            "SELECT name, qtype FROM hourly \
             WHERE hour >= ?1 AND route IN ('cache', 'provider', 'stale') AND rcode = 0 \
             GROUP BY name, qtype ORDER BY SUM(count) DESC, name, qtype",
        )?;
        let mut rows = stmt.query([since_hour])?;
        while let Some(row) = rows.next()? {
            let qtype: u16 = row.get(1)?;
            if !crate::query::prefetch_qtype_allowed(RecordType::from(qtype)) {
                continue;
            }
            popular.insert(cache_key(&row.get::<_, String>(0)?, qtype));
            if popular.len() >= count as usize {
                break;
            }
        }
        Ok(popular)
    }
}

/// The oldest time kept for `retention_days`.
pub(super) fn cutoff(now: i64, retention_days: u32) -> i64 {
    now - i64::from(retention_days) * 86_400
}

/// The oldest time `lookups` keeps.
pub(super) fn raw_cutoff(now: i64, retention_days: u32) -> i64 {
    cutoff(now, RAW_RETENTION_DAYS.min(retention_days))
}

pub(super) fn open_read_only(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(READER_BUSY_TIMEOUT)?;
    Ok(conn)
}

fn prepare_connection(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(WRITER_BUSY_TIMEOUT)?;
    let mode: String =
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(rusqlite::Error::InvalidQuery);
    }
    // Losing the last second of history on power loss is accepted.
    conn.pragma_update(None, "synchronous", "NORMAL")
}

/// Whether every table and column matches what `SCHEMA` creates, compared
/// with an in-memory copy so the check cannot drift from the schema text. A
/// file with the right version but a dropped table or column would otherwise
/// open and then fail every write with an error that is not corruption.
fn has_expected_schema(conn: &Connection) -> rusqlite::Result<bool> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA)?;
    Ok(schema_shape(conn)? == schema_shape(&reference)?)
}

type ColumnShape = (String, String, bool, i64);

fn schema_shape(conn: &Connection) -> rusqlite::Result<Vec<(String, Vec<ColumnShape>)>> {
    let tables: Vec<String> = conn
        .prepare(
            "SELECT name FROM sqlite_schema \
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut columns =
        conn.prepare("SELECT name, type, \"notnull\", pk FROM pragma_table_info(?1) ORDER BY cid")?;
    tables
        .into_iter()
        .map(|table| {
            let shape = columns
                .query_map([&table], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok((table, shape))
        })
        .collect()
}

/// Errors that mean the file itself is damaged, as opposed to a full disk or
/// a permission problem that recreating the file would not fix.
pub(super) fn is_corruption(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase)
    )
}

#[derive(Hash, PartialEq, Eq)]
struct HourlyKey<'a> {
    hour: i64,
    name: String,
    qtype: u16,
    route: &'static str,
    rcode: u16,
    provider: &'a str,
    block_rule: &'a str,
    block_category: &'a str,
}

fn upsert_hourly(conn: &Connection, events: &[LookupEvent]) -> rusqlite::Result<()> {
    let mut totals: HashMap<HourlyKey<'_>, (i64, i64)> = HashMap::new();
    for e in events {
        let key = HourlyKey {
            hour: e.ts.div_euclid(3600),
            name: stored_name(&e.name),
            qtype: e.qtype,
            route: e.route.as_str(),
            rcode: e.rcode,
            provider: &e.provider,
            block_rule: &e.block_rule,
            block_category: &e.block_category,
        };
        let entry = totals.entry(key).or_default();
        entry.0 += 1;
        entry.1 += i64::from(e.latency_us);
    }
    let mut upsert = conn.prepare_cached(
        "INSERT INTO hourly (hour, name, qtype, route, rcode, provider, block_rule, \
         block_category, count, latency_sum_us) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
         ON CONFLICT DO UPDATE SET count = count + excluded.count, \
         latency_sum_us = latency_sum_us + excluded.latency_sum_us",
    )?;
    for (k, (count, latency_sum)) in &totals {
        upsert.execute(params![
            k.hour,
            k.name,
            k.qtype,
            k.route,
            k.rcode,
            k.provider,
            k.block_rule,
            k.block_category,
            count,
            latency_sum,
        ])?;
    }
    Ok(())
}

fn upsert_names(conn: &Connection, events: &[LookupEvent]) -> rusqlite::Result<()> {
    let mut seen: HashMap<String, (i64, i64)> = HashMap::new();
    for e in events {
        seen.entry(stored_name(&e.name))
            .and_modify(|(first, last)| {
                *first = (*first).min(e.ts);
                *last = (*last).max(e.ts);
            })
            .or_insert((e.ts, e.ts));
    }
    let mut upsert = conn.prepare_cached(
        "INSERT INTO names (name, first_seen, last_seen) VALUES (?1, ?2, ?3) \
         ON CONFLICT (name) DO UPDATE SET first_seen = min(first_seen, excluded.first_seen), \
         last_seen = max(last_seen, excluded.last_seen)",
    )?;
    for (name, (first, last)) in &seen {
        upsert.execute(params![name, first, last])?;
    }
    Ok(())
}

/// Lowercase without the trailing dot. The root stays visible as ".".
pub(super) fn stored_name(name: &str) -> String {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        ".".to_owned()
    } else {
        trimmed.to_lowercase()
    }
}

/// The cache key a stored name and qtype refer to (`CacheKey::from` spells
/// the root as an empty name).
pub(super) fn cache_key(stored: &str, qtype: u16) -> CacheKey {
    CacheKey {
        name: stored.trim_end_matches('.').to_owned(),
        qtype,
    }
}

const SIDECAR_SUFFIXES: [&str; 2] = ["-wal", "-shm"];

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(suffix);
    PathBuf::from(os)
}

/// Deletes the database and its sidecars together, so no lookup history is
/// left on disk and a leftover WAL is never replayed into a new file. The
/// connection must be closed first.
pub(super) fn delete_files(path: &Path) -> std::io::Result<()> {
    remove_if_exists(path)?;
    for suffix in SIDECAR_SUFFIXES {
        remove_if_exists(&with_suffix(path, suffix))?;
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Database, WAL and shared-memory size in bytes.
pub(super) fn size_on_disk(path: &Path) -> u64 {
    std::iter::once(path.to_path_buf())
        .chain(SIDECAR_SUFFIXES.iter().map(|s| with_suffix(path, s)))
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum()
}

/// Creates the file 0600 before SQLite opens it. SQLite gives the `-wal` and
/// `-shm` files it creates later the same mode as the database file.
#[cfg(unix)]
fn create_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn create_owner_only(path: &Path) -> std::io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map(drop)
}

/// Sidecars left by an older build may predate the 0600 database file.
fn restrict_sidecars(path: &Path) {
    #[cfg(unix)]
    for suffix in SIDECAR_SUFFIXES {
        use std::os::unix::fs::PermissionsExt;

        let sidecar = with_suffix(path, suffix);
        if sidecar.exists() {
            if let Err(e) =
                std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600))
            {
                log::warn!(
                    "lookup history: cannot restrict {}: {}",
                    sidecar.display(),
                    e
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}
