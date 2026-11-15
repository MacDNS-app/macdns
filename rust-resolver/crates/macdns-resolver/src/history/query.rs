// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

//! `dns_history_query`: parses a request, runs it on a fresh read-only
//! connection and renders the JSON the App decodes with the types in
//! `Sources/Shared/QueryHistory.swift`. `QueryHistoryContractTests` pins the
//! shapes, so a change here changes both sides.
//!
//! Ranges up to 24 hours read the raw `lookups` rows, which are exact and
//! allow 5-minute buckets. Longer ranges read the `hourly` aggregates, whose
//! rows start on UTC hours, so in a time zone with a half-hour offset a row
//! near a day boundary counts toward the day its hour starts in.

use super::store::{self, cache_key, stored_name};
use super::LiveCacheStats;
use crate::cache::CacheKey;
use rusqlite::{named_params, Connection, Row};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

const MAX_LIMIT: u32 = 1000;
const MAX_UTC_OFFSET_SECS: i64 = 18 * 3600;
const MAX_NAME_LEN: usize = 255;
const FIRST_SEEN_LIMIT: u32 = 20;

/// What the API knows about the store when a request arrives.
pub(super) struct View {
    pub(super) enabled: bool,
    pub(super) path: Option<PathBuf>,
    pub(super) unavailable: Option<String>,
    pub(super) retention_days: u32,
    pub(super) popular_count: u32,
    pub(super) popular: Arc<HashSet<CacheKey>>,
    pub(super) dropped: u64,
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum Request {
    Summary {
        range: Period,
        utc_offset_secs: i64,
    },
    TopHosts {
        range: Period,
        result: Outcome,
        query: String,
        limit: u32,
        utc_offset_secs: i64,
    },
    HostDetail {
        range: Period,
        name: String,
        utc_offset_secs: i64,
    },
    Log {
        result: Outcome,
        query: String,
        limit: u32,
        before_id: Option<i64>,
        /// Only lookups in this period. Every lookup the log keeps when absent.
        range: Option<Period>,
        /// Required with `range`.
        utc_offset_secs: Option<i64>,
    },
    TopBlocked {
        range: Period,
        category: Option<String>,
        limit: u32,
        utc_offset_secs: i64,
    },
    Status {},
}

/// `range` of a request: the last `Range` up to now, or one bucket of a
/// chart zoomed in, a day as 24 hourly buckets or an hour as 12 five-minute
/// buckets from `start`, which is a local midnight or a local hour.
#[derive(Clone, Copy, Deserialize)]
#[serde(untagged)]
enum Period {
    Last(Range),
    Zoomed { span: Range, start: i64 },
}

#[derive(Clone, Copy, Deserialize)]
enum Range {
    #[serde(rename = "1h")]
    Hour,
    #[serde(rename = "24h")]
    Day,
    #[serde(rename = "7d")]
    Week,
    #[serde(rename = "30d")]
    Month,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Outcome {
    All,
    Answered,
    Blocked,
    NotFound,
    Failed,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::All => "all",
            Outcome::Answered => "answered",
            Outcome::Blocked => "blocked",
            Outcome::NotFound => "notFound",
            Outcome::Failed => "failed",
        }
    }
}

/// The answer class of a row. One class per row, checked in this order, so
/// a blocked NXDOMAIN counts as blocked and a forwarded SERVFAIL as failed.
const OUTCOME_SQL: &str = "CASE \
     WHEN route = 'blocked' THEN 'blocked' \
     WHEN route IN ('failed', 'invalid') OR rcode IN (2, 5) THEN 'failed' \
     WHEN rcode = 3 THEN 'notFound' \
     WHEN rcode = 0 THEN 'answered' \
     ELSE 'other' END";

fn result_filter_sql() -> String {
    format!("(:result = 'all' OR ({OUTCOME_SQL}) = :result)")
}

const NAME_FILTER_SQL: &str = "(:query = '' OR instr(name, :query) > 0)";

/// The time-bounded rows a range reads, as columns `t` (start time) and `n`
/// (lookup count) plus the outcome columns.
#[derive(Clone, Copy)]
enum Source {
    Raw,
    Hourly,
}

impl Source {
    fn facts_cte(self) -> &'static str {
        match self {
            Source::Raw => {
                "WITH facts AS (SELECT ts AS t, name, qtype, route, rcode, provider, block_rule, \
                 block_category, 1 AS n, latency_us AS lat FROM lookups \
                 WHERE ts >= :start AND ts < :end)"
            }
            Source::Hourly => {
                "WITH facts AS (SELECT hour * 3600 AS t, name, qtype, route, rcode, provider, \
                 block_rule, block_category, count AS n, latency_sum_us AS lat FROM hourly \
                 WHERE hour >= (:start + 3599) / 3600 AND hour < (:end + 3599) / 3600)"
            }
        }
    }
}

/// A period resolved against the clock: `buckets` buckets of `bucket` seconds
/// aligned to local time. The last one holds `now` unless the period is a
/// zoomed one that ended before it.
#[derive(Clone, Copy)]
struct Window {
    start: i64,
    end: i64,
    bucket: i64,
    buckets: i64,
    source: Source,
}

impl Window {
    fn new(
        period: Period,
        now: i64,
        utc_offset_secs: i64,
        retention_days: u32,
    ) -> Result<Self, Failure> {
        match period {
            Period::Last(range) => Ok(Self::last(range, now, utc_offset_secs)),
            Period::Zoomed { span, start } => {
                Self::zoomed(span, start, now, utc_offset_secs, retention_days)
            }
        }
    }

    fn last(range: Range, now: i64, utc_offset_secs: i64) -> Self {
        let (bucket, buckets, source) = match range {
            Range::Hour => (300, 12, Source::Raw),
            Range::Day => (3600, 24, Source::Raw),
            Range::Week => (86_400, 7, Source::Hourly),
            Range::Month => (86_400, 30, Source::Hourly),
        };
        let local = now + utc_offset_secs;
        let current_bucket = local - local.rem_euclid(bucket) - utc_offset_secs;
        Self {
            start: current_bucket - (buckets - 1) * bucket,
            end: now + 1,
            bucket,
            buckets,
            source,
        }
    }

    /// A zoomed day reads the raw lookups while they still hold all of it and
    /// the hourly aggregates after that. A zoomed hour needs the raw lookups.
    fn zoomed(
        span: Range,
        start: i64,
        now: i64,
        utc_offset_secs: i64,
        retention_days: u32,
    ) -> Result<Self, Failure> {
        let (bucket, buckets) = match span {
            Range::Hour => (300, 12),
            Range::Day => (3600, 24),
            Range::Week | Range::Month => {
                return Err(Failure::Caller("a zoomed range spans 1h or 24h".to_owned()))
            }
        };
        let length = bucket * buckets;
        if (start + utc_offset_secs).rem_euclid(length) != 0 {
            return Err(Failure::Caller(format!(
                "a zoomed range starts on a local {}",
                if length == 3600 { "hour" } else { "midnight" }
            )));
        }
        if start > now {
            return Err(Failure::Caller(
                "a zoomed range starts in the future".to_owned(),
            ));
        }
        let source = if start >= store::raw_cutoff(now, retention_days) {
            Source::Raw
        } else if matches!(span, Range::Day) {
            Source::Hourly
        } else {
            return Err(Failure::Caller(
                "five-minute detail is kept only as long as single lookups".to_owned(),
            ));
        };
        Ok(Self {
            start,
            end: (start + length).min(now + 1),
            bucket,
            buckets,
            source,
        })
    }

    /// The oldest time this window's source still holds in full.
    fn kept_since(self, now: i64, retention_days: u32) -> i64 {
        match self.source {
            Source::Raw => store::raw_cutoff(now, retention_days),
            Source::Hourly => store::cutoff(now, retention_days),
        }
    }

    /// The same span, one range earlier.
    fn previous(self) -> Self {
        let span = self.bucket * self.buckets;
        Self {
            start: self.start - span,
            end: self.end - span,
            ..self
        }
    }

    fn sql(self, body: &str) -> String {
        format!("{} {}", self.source.facts_cte(), body)
    }

    fn bucket_starts(self) -> impl Iterator<Item = i64> {
        (0..self.buckets).map(move |i| self.start + i * self.bucket)
    }

    fn bucket_index(self, raw: i64) -> Option<usize> {
        usize::try_from(raw)
            .ok()
            .filter(|&i| (i as i64) < self.buckets)
    }
}

/// Request failures. `Caller` is a bug in the request. `Unavailable` is the
/// store's fault and may clear up.
enum Failure {
    Caller(String),
    Unavailable(String),
}

impl From<rusqlite::Error> for Failure {
    fn from(e: rusqlite::Error) -> Self {
        Failure::Unavailable(format!("history database read failed: {e}"))
    }
}

pub(super) fn run(request_json: &str, view: &View, live: LiveCacheStats, now: i64) -> String {
    let response = match respond(request_json, view, live, now) {
        Ok(payload) => payload,
        Err(Failure::Caller(reason)) => json!({ "status": "error", "reason": reason }),
        Err(Failure::Unavailable(reason)) => {
            json!({ "status": "unavailable", "reason": reason })
        }
    };
    response.to_string()
}

fn respond(
    request_json: &str,
    view: &View,
    live: LiveCacheStats,
    now: i64,
) -> Result<Value, Failure> {
    let request: Request = serde_json::from_str(request_json)
        .map_err(|e| Failure::Caller(format!("malformed request: {e}")))?;
    validate(&request)?;
    if !view.enabled {
        return Ok(json!({ "status": "disabled" }));
    }
    if let Some(reason) = &view.unavailable {
        return Err(Failure::Unavailable(reason.clone()));
    }
    let Some(path) = &view.path else {
        return Err(Failure::Unavailable("history path is not set".to_owned()));
    };
    if let Request::Status {} = request {
        return Ok(json!({
            "status": "ok",
            "enabled": true,
            "sizeBytes": store::size_on_disk(path),
            "droppedEvents": view.dropped,
            "retentionDays": view.retention_days,
        }));
    }
    let mut conn = store::open_read_only(path)
        .map_err(|e| Failure::Unavailable(format!("cannot open history database: {e}")))?;
    // One WAL snapshot for every statement, so a writer commit between two
    // of them never makes one response disagree with itself.
    let conn = conn.transaction()?;
    let window =
        |period, utc_offset_secs| Window::new(period, now, utc_offset_secs, view.retention_days);
    let mut payload = match request {
        Request::Summary {
            range,
            utc_offset_secs,
        } => summary(&conn, window(range, utc_offset_secs)?, view, live, now)?,
        Request::TopHosts {
            range,
            result,
            query,
            limit,
            utc_offset_secs,
        } => top_hosts(
            &conn,
            window(range, utc_offset_secs)?,
            result,
            &query.to_lowercase(),
            limit,
        )?,
        Request::HostDetail {
            range,
            name,
            utc_offset_secs,
        } => host_detail(&conn, window(range, utc_offset_secs)?, &stored_name(&name))?,
        Request::Log {
            result,
            query,
            limit,
            before_id,
            range,
            utc_offset_secs,
        } => {
            let span = match (range, utc_offset_secs) {
                (Some(range), Some(offset)) => Some(window(range, offset)?),
                _ => None,
            };
            log(&conn, result, &query.to_lowercase(), limit, before_id, span)?
        }
        Request::TopBlocked {
            range,
            category,
            limit,
            utc_offset_secs,
        } => top_blocked(
            &conn,
            window(range, utc_offset_secs)?,
            category.as_deref(),
            limit,
        )?,
        Request::Status {} => unreachable!("answered above"),
    };
    payload.insert("status".to_owned(), json!("ok"));
    Ok(Value::Object(payload))
}

fn validate(request: &Request) -> Result<(), Failure> {
    let (offset, limit, text) = match request {
        Request::Summary {
            utc_offset_secs, ..
        } => (Some(*utc_offset_secs), None, None),
        Request::TopHosts {
            utc_offset_secs,
            limit,
            query,
            ..
        } => (Some(*utc_offset_secs), Some(*limit), Some(query)),
        Request::HostDetail {
            utc_offset_secs,
            name,
            ..
        } => {
            if name.trim_end_matches('.').is_empty() {
                return Err(Failure::Caller("name is empty".to_owned()));
            }
            (Some(*utc_offset_secs), None, Some(name))
        }
        Request::Log {
            limit,
            query,
            range,
            utc_offset_secs,
            ..
        } => {
            if range.is_some() && utc_offset_secs.is_none() {
                return Err(Failure::Caller(
                    "a log range needs utcOffsetSecs".to_owned(),
                ));
            }
            (*utc_offset_secs, Some(*limit), Some(query))
        }
        Request::TopBlocked {
            utc_offset_secs,
            limit,
            category,
            ..
        } => (Some(*utc_offset_secs), Some(*limit), category.as_ref()),
        Request::Status {} => (None, None, None),
    };
    if offset.is_some_and(|o| !(-MAX_UTC_OFFSET_SECS..=MAX_UTC_OFFSET_SECS).contains(&o)) {
        return Err(Failure::Caller(format!(
            "utcOffsetSecs must be within ±{MAX_UTC_OFFSET_SECS}"
        )));
    }
    if limit.is_some_and(|l| l == 0 || l > MAX_LIMIT) {
        return Err(Failure::Caller(format!(
            "limit must be between 1 and {MAX_LIMIT}"
        )));
    }
    if text.is_some_and(|t| t.len() > MAX_NAME_LEN) {
        return Err(Failure::Caller(format!(
            "text filters are limited to {MAX_NAME_LEN} bytes"
        )));
    }
    Ok(())
}

type Payload = Map<String, Value>;

/// `previousTotal` is null when the previous window reaches back past what
/// the source still keeps, since its count would be partial.
fn summary(
    conn: &Connection,
    window: Window,
    view: &View,
    live: LiveCacheStats,
    now: i64,
) -> Result<Payload, Failure> {
    let totals_sql = window.sql(
        "SELECT COALESCE(SUM(n), 0), \
         COALESCE(SUM(CASE WHEN route = 'blocked' THEN n END), 0), \
         COALESCE(SUM(CASE WHEN route = 'cache' THEN n END), 0), \
         COALESCE(SUM(CASE WHEN route = 'provider' THEN n END), 0), \
         COALESCE(SUM(lat), 0), \
         COALESCE(SUM(CASE WHEN route = 'provider' THEN lat END), 0) FROM facts",
    );
    let totals = |w: Window| {
        conn.query_row(
            &totals_sql,
            named_params! { ":start": w.start, ":end": w.end },
            |r| {
                Ok([
                    r.get::<_, i64>(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ])
            },
        )
    };
    let [total, blocked, cache, provider, latency, provider_latency] = totals(window)?;
    let previous = window.previous();
    let previous_total = if previous.start < window.kept_since(now, view.retention_days) {
        None
    } else {
        let [previous_total, ..] = totals(previous)?;
        Some(previous_total)
    };
    between_reads();

    let mut payload = Payload::new();
    payload.insert("total".into(), json!(total));
    payload.insert("previousTotal".into(), json!(previous_total));
    payload.insert("blocked".into(), json!(blocked));
    payload.insert("cache".into(), json!(cache));
    payload.insert("provider".into(), json!(provider));
    payload.insert("avgLatencyMs".into(), json!(average_ms(latency, total)));
    payload.insert(
        "avgProviderLatencyMs".into(),
        json!(average_ms(provider_latency, provider)),
    );
    payload.insert("series".into(), summary_series(conn, window)?);
    payload.insert("providers".into(), providers(conn, window)?);
    payload.insert("answers".into(), answers(conn, window)?);
    payload.insert("firstSeen".into(), first_seen(conn, window)?);
    payload.insert("keptFresh".into(), kept_fresh(conn, window, view, live)?);
    Ok(payload)
}

fn summary_series(conn: &Connection, window: Window) -> Result<Value, Failure> {
    let mut buckets = vec![[0i64; 4]; window.buckets as usize];
    let sql = window.sql(
        "SELECT (t - :start) / :bucket, \
         SUM(CASE WHEN route = 'cache' THEN n ELSE 0 END), \
         SUM(CASE WHEN route = 'provider' THEN n ELSE 0 END), \
         SUM(CASE WHEN route = 'blocked' THEN n ELSE 0 END), \
         SUM(CASE WHEN route NOT IN ('cache', 'provider', 'blocked') THEN n ELSE 0 END) \
         FROM facts GROUP BY 1",
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(
        named_params! { ":start": window.start, ":end": window.end, ":bucket": window.bucket },
    )?;
    while let Some(r) = rows.next()? {
        if let Some(i) = window.bucket_index(r.get(0)?) {
            buckets[i] = [r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?];
        }
    }
    let series = window
        .bucket_starts()
        .zip(buckets)
        .map(|(start, [cache, provider, blocked, other])| {
            json!({ "start": start, "cache": cache, "provider": provider,
                    "blocked": blocked, "other": other })
        })
        .collect();
    Ok(Value::Array(series))
}

fn providers(conn: &Connection, window: Window) -> Result<Value, Failure> {
    let sql = window.sql(
        "SELECT provider, SUM(n), SUM(lat) FROM facts \
         WHERE route = 'provider' AND provider != '' \
         GROUP BY provider ORDER BY SUM(n) DESC, provider",
    );
    collect(
        conn,
        &sql,
        named_params! { ":start": window.start, ":end": window.end },
        |r| {
            let answers: i64 = r.get(1)?;
            Ok(json!({ "name": r.get::<_, String>(0)?, "answers": answers,
                       "avgLatencyMs": average_ms(r.get(2)?, answers) }))
        },
    )
}

fn answers(conn: &Connection, window: Window) -> Result<Value, Failure> {
    let mut counts = Map::new();
    for outcome in ["answered", "blocked", "notFound", "failed"] {
        counts.insert(outcome.into(), json!(0));
    }
    let sql = window.sql(&format!(
        "SELECT {OUTCOME_SQL}, SUM(n) FROM facts GROUP BY 1"
    ));
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(named_params! { ":start": window.start, ":end": window.end })?;
    while let Some(r) = rows.next()? {
        let outcome: String = r.get(0)?;
        if counts.contains_key(&outcome) {
            counts.insert(outcome, json!(r.get::<_, i64>(1)?));
        }
    }
    Ok(Value::Object(counts))
}

/// Names whose first lookup ever (within the retention) falls in the range.
fn first_seen(conn: &Connection, window: Window) -> Result<Value, Failure> {
    let sql = window.sql(
        "SELECT nm.name, nm.first_seen, SUM(f.n), \
         SUM(CASE WHEN f.route = 'blocked' THEN f.n ELSE 0 END) \
         FROM names nm JOIN facts f ON f.name = nm.name \
         WHERE nm.first_seen >= :start AND nm.first_seen < :end \
         GROUP BY nm.name ORDER BY nm.first_seen DESC, nm.name LIMIT :limit",
    );
    collect(
        conn,
        &sql,
        named_params! { ":start": window.start, ":end": window.end, ":limit": FIRST_SEEN_LIMIT },
        |r| {
            Ok(
                json!({ "name": r.get::<_, String>(0)?, "firstSeen": r.get::<_, i64>(1)?,
                       "count": r.get::<_, i64>(2)?, "blocked": r.get::<_, i64>(3)? > 0 }),
            )
        },
    )
}

/// `null` when popular prefetch is off. `cacheAnswers` counts cache hits of
/// the keys in the current popular set.
fn kept_fresh(
    conn: &Connection,
    window: Window,
    view: &View,
    live: LiveCacheStats,
) -> Result<Value, Failure> {
    if view.popular_count == 0 || !live.prefetching {
        return Ok(Value::Null);
    }
    let sql = window
        .sql("SELECT name, qtype, SUM(n) FROM facts WHERE route = 'cache' GROUP BY name, qtype");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(named_params! { ":start": window.start, ":end": window.end })?;
    let mut cache_answers = 0i64;
    while let Some(r) = rows.next()? {
        if view
            .popular
            .contains(&cache_key(&r.get::<_, String>(0)?, r.get(1)?))
        {
            cache_answers += r.get::<_, i64>(2)?;
        }
    }
    Ok(json!({
        "popularCount": view.popular.len(),
        "inCache": live.in_cache,
        "cacheAnswers": cache_answers,
        "refreshesPerSecond": live.refreshes_per_second,
    }))
}

fn top_hosts(
    conn: &Connection,
    window: Window,
    result: Outcome,
    query: &str,
    limit: u32,
) -> Result<Payload, Failure> {
    let matched = format!(
        "matched AS (SELECT * FROM facts WHERE {} AND {NAME_FILTER_SQL})",
        result_filter_sql()
    );
    let total_sql = window.sql(&format!(
        ", {matched} SELECT COUNT(DISTINCT name) FROM matched"
    ));
    let total_hosts: i64 = conn.query_row(
        &total_sql,
        named_params! { ":start": window.start, ":end": window.end,
        ":result": result.as_str(), ":query": query },
        |r| r.get(0),
    )?;
    let hosts_sql = window.sql(&format!(
        ", {matched}, ranked AS (SELECT name, SUM(n) AS total, \
         SUM(CASE WHEN route = 'cache' THEN n ELSE 0 END) AS cache, \
         SUM(CASE WHEN route = 'provider' THEN n ELSE 0 END) AS provider, \
         SUM(CASE WHEN route = 'blocked' THEN n ELSE 0 END) AS blocked, \
         SUM(CASE WHEN {OUTCOME_SQL} = 'notFound' THEN n ELSE 0 END) AS not_found, \
         SUM(CASE WHEN {OUTCOME_SQL} = 'failed' THEN n ELSE 0 END) AS failed, \
         MAX(t) AS last_t, \
         COALESCE(MAX(CASE WHEN route = 'blocked' THEN block_rule END), '') AS rule, \
         COALESCE(MAX(CASE WHEN route = 'blocked' THEN block_category END), '') AS category \
         FROM matched GROUP BY name ORDER BY total DESC, name LIMIT :limit) \
         SELECT ranked.name, total, cache, provider, blocked, not_found, failed, \
         COALESCE(nm.last_seen, last_t), rule, category \
         FROM ranked LEFT JOIN names nm ON nm.name = ranked.name ORDER BY total DESC, ranked.name"
    ));
    let hosts = collect(
        conn,
        &hosts_sql,
        named_params! { ":start": window.start, ":end": window.end,
        ":result": result.as_str(), ":query": query, ":limit": limit },
        |r| {
            Ok(json!({
                "name": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?,
                "cache": r.get::<_, i64>(2)?, "provider": r.get::<_, i64>(3)?,
                "blocked": r.get::<_, i64>(4)?, "notFound": r.get::<_, i64>(5)?,
                "failed": r.get::<_, i64>(6)?, "lastSeen": r.get::<_, i64>(7)?,
                "blockRule": r.get::<_, String>(8)?, "blockCategory": r.get::<_, String>(9)?,
            }))
        },
    )?;
    let mut payload = Payload::new();
    payload.insert("totalHosts".into(), json!(total_hosts));
    payload.insert("hosts".into(), hosts);
    Ok(payload)
}

fn host_detail(conn: &Connection, window: Window, name: &str) -> Result<Payload, Failure> {
    let span = named_params! { ":start": window.start, ":end": window.end, ":name": name };
    let seen: Option<(i64, i64)> = conn
        .query_row(
            "SELECT first_seen, last_seen FROM names WHERE name = ?1",
            [name],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })?;

    let mut counts = vec![0i64; window.buckets as usize];
    let series_sql = window
        .sql("SELECT (t - :start) / :bucket, SUM(n) FROM facts WHERE name = :name GROUP BY 1");
    let mut stmt = conn.prepare(&series_sql)?;
    let mut rows = stmt.query(named_params! { ":start": window.start, ":end": window.end,
    ":name": name, ":bucket": window.bucket })?;
    while let Some(r) = rows.next()? {
        if let Some(i) = window.bucket_index(r.get(0)?) {
            counts[i] = r.get(1)?;
        }
    }
    let series: Vec<Value> = window
        .bucket_starts()
        .zip(counts)
        .map(|(start, count)| json!({ "start": start, "count": count }))
        .collect();

    let mut routes = Map::new();
    let routes_sql = window
        .sql("SELECT route, SUM(n) FROM facts WHERE name = :name GROUP BY route ORDER BY route");
    let mut stmt = conn.prepare(&routes_sql)?;
    let mut rows = stmt.query(span)?;
    while let Some(r) = rows.next()? {
        routes.insert(r.get(0)?, json!(r.get::<_, i64>(1)?));
    }

    let providers = collect(
        conn,
        &window.sql(
            "SELECT provider, SUM(n) FROM facts \
             WHERE name = :name AND route = 'provider' AND provider != '' \
             GROUP BY provider ORDER BY SUM(n) DESC, provider",
        ),
        span,
        |r| Ok(json!({ "name": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)? })),
    )?;
    let qtypes = collect(
        conn,
        &window.sql(
            "SELECT qtype, SUM(n) FROM facts WHERE name = :name \
             GROUP BY qtype ORDER BY SUM(n) DESC, qtype",
        ),
        span,
        |r| Ok(json!({ "qtype": r.get::<_, i64>(0)?, "count": r.get::<_, i64>(1)? })),
    )?;
    let (rule, category): (String, String) = conn.query_row(
        &window.sql(
            "SELECT COALESCE(MAX(block_rule), ''), COALESCE(MAX(block_category), '') \
             FROM facts WHERE name = :name AND route = 'blocked'",
        ),
        span,
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;

    let mut payload = Payload::new();
    payload.insert("name".into(), json!(name));
    payload.insert("firstSeen".into(), json!(seen.map(|s| s.0)));
    payload.insert("lastSeen".into(), json!(seen.map(|s| s.1)));
    payload.insert("series".into(), Value::Array(series));
    payload.insert("routes".into(), Value::Object(routes));
    payload.insert("providers".into(), providers);
    payload.insert("qtypes".into(), qtypes);
    payload.insert("blockRule".into(), json!(rule));
    payload.insert("blockCategory".into(), json!(category));
    Ok(payload)
}

/// Raw lookups, newest first by row id, within `window` when there is one.
/// The next page passes the last entry's `id` as `beforeId`, so rows that
/// share a second are never skipped.
fn log(
    conn: &Connection,
    result: Outcome,
    query: &str,
    limit: u32,
    before_id: Option<i64>,
    window: Option<Window>,
) -> Result<Payload, Failure> {
    let sql = format!(
        "SELECT rowid, ts, name, qtype, rcode, route, provider, latency_us, block_rule, \
         block_category FROM lookups WHERE rowid < :before_id AND ts >= :start AND ts < :end \
         AND {} AND {NAME_FILTER_SQL} ORDER BY rowid DESC LIMIT :limit",
        result_filter_sql()
    );
    let entries = collect(
        conn,
        &sql,
        named_params! { ":before_id": before_id.unwrap_or(i64::MAX),
        ":start": window.map_or(i64::MIN, |w| w.start),
        ":end": window.map_or(i64::MAX, |w| w.end),
        ":result": result.as_str(), ":query": query, ":limit": limit },
        |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "ts": r.get::<_, i64>(1)?,
                "name": r.get::<_, String>(2)?, "qtype": r.get::<_, i64>(3)?,
                "rcode": r.get::<_, i64>(4)?, "route": r.get::<_, String>(5)?,
                "provider": r.get::<_, String>(6)?,
                "latencyMs": r.get::<_, i64>(7)? as f64 / 1000.0,
                "blockRule": r.get::<_, String>(8)?, "blockCategory": r.get::<_, String>(9)?,
            }))
        },
    )?;
    let mut payload = Payload::new();
    payload.insert("entries".into(), entries);
    Ok(payload)
}

fn top_blocked(
    conn: &Connection,
    window: Window,
    category: Option<&str>,
    limit: u32,
) -> Result<Payload, Failure> {
    let sql = window.sql(
        "SELECT name, MAX(block_rule), MAX(block_category), SUM(n) FROM facts \
         WHERE route = 'blocked' AND (:category IS NULL OR block_category = :category) \
         GROUP BY name ORDER BY SUM(n) DESC, name LIMIT :limit",
    );
    let domains = collect(
        conn,
        &sql,
        named_params! { ":start": window.start, ":end": window.end,
        ":category": category, ":limit": limit },
        |r| {
            Ok(json!({
                "domain": r.get::<_, String>(0)?, "matchedRule": r.get::<_, String>(1)?,
                "category": r.get::<_, String>(2)?, "blockCount": r.get::<_, i64>(3)?,
            }))
        },
    )?;
    let mut payload = Payload::new();
    payload.insert("domains".into(), domains);
    Ok(payload)
}

fn collect(
    conn: &Connection,
    sql: &str,
    params: &[(&str, &dyn rusqlite::ToSql)],
    mut map: impl FnMut(&Row<'_>) -> rusqlite::Result<Value>,
) -> Result<Value, Failure> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(params)?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(map(r)?);
    }
    Ok(Value::Array(out))
}

#[cfg(test)]
thread_local! {
    /// Runs once between two reads of a summary, so a test can commit a
    /// write in the middle of one response.
    pub(super) static BETWEEN_READS: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

fn between_reads() {
    #[cfg(test)]
    if let Some(hook) = BETWEEN_READS.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
}

fn average_ms(sum_us: i64, count: i64) -> f64 {
    if count == 0 {
        0.0
    } else {
        sum_us as f64 / count as f64 / 1000.0
    }
}
