// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use crate::cache::{cap_message_ttls, CacheKey, CachedEntry, DnsCache};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, Name};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_SNAPSHOT_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SNAPSHOT_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

/// Format version for the on-disk cache dump. Bump it when the wire layout
/// changes incompatibly (a new field, a renamed `SerializedEntry` variant) so
/// `restore_from_path` refuses stale snapshots instead of deserializing
/// garbage. A mismatch is logged and the dump deleted, so the cache starts
/// empty as on a first boot.
///
/// Version 2 marks a content contract change rather than a layout one:
/// entries written while the DNSSEC toggle was off had their DNSSEC records
/// stripped before being stored, so restoring them would serve answers without
/// RRSIG until they expired. `needs_cache_flush` does not cover this because
/// it fires on a toggle change, not on an upgrade.
///
/// Version 3 adds capture time. Untimed dumps cannot preserve cache age.
const SNAPSHOT_VERSION: u16 = 3;

/// Wire-ready cache entry with lifetime remaining at the snapshot capture time.
#[derive(Serialize, Deserialize)]
struct SerializedEntry {
    name: String,
    qtype: u16,
    remaining_ttl_secs: u32,
    provider: String,
    message_wire: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u16,
    captured_at_unix_secs: u64,
    entries: Vec<SerializedEntry>,
}

/// Serializes the live cache to `path`. Iterates the moka cache, skips
/// already-expired entries (nothing to restore from them), and writes the
/// postcard payload to a temp file before `rename`-ing over `path` so a
/// crash mid-write never leaves a truncated dump. Returns the number of
/// entries written, which callers log to show whether the snapshot preserves
/// data between restarts.
pub async fn snapshot_to_path(cache: &DnsCache, path: &Path) -> std::io::Result<usize> {
    cache.flush_pending().await;
    snapshot_to_path_sync(cache, path)
}

pub(crate) fn snapshot_to_path_sync(cache: &DnsCache, path: &Path) -> std::io::Result<usize> {
    snapshot_to_path_sync_guarded(cache, path, "dump.tmp", |tmp, target| {
        std::fs::rename(tmp, target)?;
        Ok(true)
    })
    .map(|n| n.unwrap_or(0))
}

/// Serializes the cache into a unique temp file and hands publication to the
/// caller.
///
/// All expensive work (iteration, encoding, compression, write, fsync) runs
/// before `publish` is invoked, so the caller's publication lock only has to
/// cover the epoch check and the atomic rename. `publish` returns `false` to
/// reject a stale attempt, in which case the temp file is removed.
pub(crate) fn snapshot_to_path_sync_guarded(
    cache: &DnsCache,
    path: &Path,
    tmp_extension: &str,
    publish: impl FnOnce(&Path, &Path) -> std::io::Result<bool>,
) -> std::io::Result<Option<usize>> {
    let captured_at_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(Error::other)?
        .as_secs();
    let now = Instant::now();
    let mut entries: Vec<SerializedEntry> = Vec::new();
    for (key_arc, entry) in cache.iter() {
        let remaining = entry.expires_at.saturating_duration_since(now).as_secs();
        if remaining == 0 {
            continue;
        }
        let remaining_ttl_secs = remaining.min(u64::from(u32::MAX)) as u32;
        let mut message = entry.message.clone();
        cap_message_ttls(&mut message, remaining_ttl_secs);
        let wire = match message.to_bytes() {
            Ok(b) => b,
            Err(_) => continue,
        };
        entries.push(SerializedEntry {
            name: key_arc.name.clone(),
            qtype: key_arc.qtype,
            remaining_ttl_secs,
            provider: entry.provider.clone(),
            message_wire: wire,
        });
    }
    let payload = Snapshot {
        version: SNAPSHOT_VERSION,
        captured_at_unix_secs,
        entries,
    };
    let count = payload.entries.len();
    // postcard, not bincode (RUSTSEC-2025-0141).
    let raw = postcard::to_allocvec(&payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // Default gzip level (6). Higher levels gain little ratio on DNS wire
    // bytes for noticeably more CPU at every shutdown, which is not worth it
    // for a snapshot written at most a few times per day.
    let mut gz = GzEncoder::new(Vec::with_capacity(raw.len() / 4), Compression::default());
    gz.write_all(&raw)?;
    let bytes = gz.finish()?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(tmp_extension);
    {
        let mut file = create_owner_only_file(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    match publish(&tmp, path) {
        Ok(true) => {}
        Ok(false) => {
            let _ = std::fs::remove_file(&tmp);
            return Ok(None);
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::File::open(parent).and_then(|dir| dir.sync_all());
    }
    Ok(Some(count))
}

/// Reads a dump produced by `snapshot_to_path` and populates `cache`. Silent
/// no-op when the file is missing (first boot, user ran `dns_flush_cache`
/// which deletes the dump). Corrupt payloads and mismatched versions are
/// treated as "no data" rather than hard errors, because the agent must always
/// start. Losing the warm cache is acceptable. Crashing the agent over a stale
/// file on disk is not. Returns how many entries were reinstated.
pub async fn restore_from_path(cache: &DnsCache, path: &Path) -> std::io::Result<usize> {
    let owned_path = path.to_path_buf();
    let snapshot = tokio::task::spawn_blocking(move || load_snapshot(&owned_path))
        .await
        .map_err(std::io::Error::other)??;
    let Some(snapshot) = snapshot else {
        return Ok(0);
    };

    restore_snapshot(cache, snapshot, SystemTime::now()).await
}

async fn restore_snapshot(
    cache: &DnsCache,
    snapshot: Snapshot,
    now: SystemTime,
) -> std::io::Result<usize> {
    let started = Instant::now();
    restore_snapshot_with_clock(cache, snapshot, now, || started.elapsed()).await
}

async fn restore_snapshot_with_clock(
    cache: &DnsCache,
    snapshot: Snapshot,
    now: SystemTime,
    elapsed: impl Fn() -> Duration,
) -> std::io::Result<usize> {
    let captured = UNIX_EPOCH.checked_add(Duration::from_secs(snapshot.captured_at_unix_secs));
    let Some(downtime_at_start) = captured.and_then(|captured| now.duration_since(captured).ok())
    else {
        // Unknown time or clock rollback cannot safely preserve cache age.
        return Ok(0);
    };
    let mut restored = 0usize;
    for e in snapshot.entries {
        let observed_at = Instant::now();
        let age = downtime_at_start.saturating_add(elapsed());
        let downtime = age
            .as_secs()
            .saturating_add(u64::from(age.subsec_nanos() > 0));
        // The dump is user-writable: a structurally valid snapshot can
        // still carry entries the pipeline would never produce. Reject
        // qtypes that are never cached (0 = reserved, 255 = ANY) and any
        // key that disagrees with the message's own question. Otherwise a
        // crafted entry could be served under an unrelated cache key.
        if e.qtype == 0 || e.qtype == 255 {
            continue;
        }
        let Ok(mut msg) = Message::from_bytes(&e.message_wire) else {
            continue;
        };
        if !question_binds_key(&msg, &e) {
            continue;
        }
        // The backdated insertion timestamp carries the elapsed age. Keep
        // captured wire TTLs so the response path subtracts that age once.
        cap_message_ttls(&mut msg, e.remaining_ttl_secs);
        if !filter_rebinding_for_restore(&mut msg, crate::config::BLOCK_REBINDING) {
            continue;
        }
        let key = CacheKey {
            name: e.name,
            qtype: e.qtype,
        };
        let entry = CachedEntry::scaffold(msg, e.provider);
        if cache
            .insert_restored_aged(key, entry, e.remaining_ttl_secs, downtime, observed_at)
            .await
        {
            restored += 1;
        }
    }
    Ok(restored)
}

/// Blocking half of the restore: open, capped read, decompress and
/// deserialize. Every step is synchronous file I/O or CPU work, so it runs on
/// the blocking pool and leaves the async cache insertion to
/// `restore_from_path`. `Ok(None)` means "no usable data". A missing,
/// oversized, corrupt or version-mismatched dump is never a startup failure.
fn load_snapshot(path: &Path) -> std::io::Result<Option<Snapshot>> {
    // One open and a capped read from the same handle. A separate
    // exists/metadata/read sequence would let the file be swapped between
    // the size check and the read.
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.take(MAX_SNAPSHOT_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SNAPSHOT_FILE_BYTES {
        log::warn!(
            "cache restore: dump exceeds {} bytes; ignoring dump",
            MAX_SNAPSHOT_FILE_BYTES
        );
        let _ = std::fs::remove_file(path);
        return Ok(None);
    }
    let raw = match decode_gzip_limited(&bytes, MAX_SNAPSHOT_DECOMPRESSED_BYTES) {
        Ok(raw) => raw,
        Err(e) => {
            log::warn!("cache restore: decode failed ({}); ignoring dump", e);
            let _ = std::fs::remove_file(path);
            return Ok(None);
        }
    };
    let snapshot: Snapshot = match postcard::from_bytes(&raw) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("cache restore: deserialize failed ({}); ignoring dump", e);
            let _ = std::fs::remove_file(path);
            return Ok(None);
        }
    };
    if snapshot.version != SNAPSHOT_VERSION {
        log::warn!(
            "cache restore: version {} does not match current {}, ignoring dump",
            snapshot.version,
            SNAPSHOT_VERSION
        );
        let _ = std::fs::remove_file(path);
        return Ok(None);
    }
    Ok(Some(snapshot))
}

/// The snapshot key is only trustworthy when the message carries exactly one
/// `IN` question that matches it. Zero questions leave the key unbound to the
/// payload and several questions leave it ambiguous. Either way a same-user
/// process could bind crafted answers to any permitted name and qtype, since
/// mode `0600` keeps other users out but not other processes of this user.
fn question_binds_key(msg: &Message, entry: &SerializedEntry) -> bool {
    let [question] = msg.queries.as_slice() else {
        return false;
    };
    if question.query_class() != DNSClass::IN || u16::from(question.query_type()) != entry.qtype {
        return false;
    }
    // Parsing the stored key punycodes an IDN display form, so both sides
    // compare as canonical ASCII wire labels whichever presentation the
    // snapshot captured. `eq_ignore_root` absorbs the trailing-dot difference
    // between the wire question and the cache key.
    Name::from_str_relaxed(&entry.name)
        .is_ok_and(|key_name| key_name.eq_ignore_root(question.name()))
}

fn filter_rebinding_for_restore(msg: &mut Message, block_rebinding: bool) -> bool {
    if !block_rebinding {
        return true;
    }
    !crate::rebinding::filter_rebindable_records(msg).all_useful_answers_stripped()
}

fn decode_gzip_limited(bytes: &[u8], max_output_bytes: u64) -> std::io::Result<Vec<u8>> {
    let mut limited = GzDecoder::new(bytes).take(max_output_bytes.saturating_add(1));
    let mut out = Vec::new();
    limited.read_to_end(&mut out)?;
    if out.len() as u64 > max_output_bytes {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "gzip payload exceeds cache snapshot limit",
        ));
    }
    Ok(out)
}

fn create_owner_only_file(path: &Path) -> std::io::Result<File> {
    let file = open_owner_only(path)?;
    set_owner_only_permissions(path)?;
    Ok(file)
}

#[cfg(unix)]
fn open_owner_only(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.write(true).mode(0o600);
    options.create(true).truncate(true);
    options.open(path)
}

#[cfg(not(unix))]
fn open_owner_only(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true);
    options.create(true).truncate(true);
    options.open(path)
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Best-effort delete of the dump file. Called from `dns_flush_cache` so a
/// user-initiated flush survives a restart. Otherwise the next `dns_init`
/// would restore the flushed entries from disk.
pub fn remove_dump(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::path::Path;
    use std::str::FromStr;
    use tempfile::TempDir;

    fn make_positive_entry(ip_tail: u8) -> (CacheKey, CachedEntry) {
        let name = Name::from_str("example.com.").unwrap();
        let mut msg = Message::query();
        msg.add_query(hickory_proto::op::Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                93, 184, 216, ip_tail,
            ))),
        ));
        let key = CacheKey::from("example.com", RecordType::A);
        let entry = CachedEntry::scaffold(msg, "Cloudflare".into());
        (key, entry)
    }

    fn read_gzip_snapshot(path: &Path) -> Snapshot {
        let bytes = std::fs::read(path).unwrap();
        let mut decoder = GzDecoder::new(&bytes[..]);
        let mut raw = Vec::new();
        decoder.read_to_end(&mut raw).unwrap();
        postcard::from_bytes(&raw).unwrap()
    }

    #[tokio::test]
    async fn untimed_version_2_dump_cannot_restore_fresh_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let (key, entry) = make_positive_entry(34);
        #[derive(Serialize)]
        struct LegacySnapshot {
            version: u16,
            entries: Vec<SerializedEntry>,
        }
        let payload = LegacySnapshot {
            version: 2,
            entries: vec![SerializedEntry {
                name: key.name,
                qtype: key.qtype,
                remaining_ttl_secs: 120,
                provider: entry.provider,
                message_wire: entry.message.to_bytes().unwrap(),
            }],
        };
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&postcard::to_allocvec(&payload).unwrap())
            .unwrap();
        std::fs::write(&path, gz.finish().unwrap()).unwrap();
        assert_eq!(
            restore_from_path(&DnsCache::new(1_048_576), &path)
                .await
                .unwrap(),
            0
        );
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn restore_accounts_for_downtime_and_stale_age() {
        for (downtime, fresh, stale) in [
            (10, true, true),
            (130, false, true),
            (120 + crate::cache::SERVE_EXPIRED_TTL_SECS + 2, false, false),
        ] {
            let (key, entry) = make_positive_entry(34);
            let payload = Snapshot {
                version: SNAPSHOT_VERSION,
                captured_at_unix_secs: 1_000_000,
                entries: vec![SerializedEntry {
                    name: key.name.clone(),
                    qtype: key.qtype,
                    remaining_ttl_secs: 120,
                    provider: entry.provider,
                    message_wire: entry.message.to_bytes().unwrap(),
                }],
            };
            let dst = DnsCache::new(1_048_576);
            restore_snapshot_with_clock(
                &dst,
                payload,
                UNIX_EPOCH + Duration::from_secs(1_000_000 + downtime),
                || Duration::ZERO,
            )
            .await
            .unwrap();
            assert_eq!(dst.get(&key).await.is_some(), fresh, "downtime={downtime}");
            let hit = dst.get_allow_expired(&key).await;
            assert_eq!(hit.is_some(), stale, "downtime={downtime}");
            if downtime == 10 {
                assert_eq!(hit.unwrap().message.answers[0].ttl, 120);
            } else if downtime == 130 {
                assert!(
                    Instant::now()
                        .duration_since(hit.unwrap().expires_at)
                        .as_secs()
                        >= 10
                );
                let dir = TempDir::new().unwrap();
                assert_eq!(
                    snapshot_to_path(&dst, &dir.path().join("cache.dump"))
                        .await
                        .unwrap(),
                    0,
                    "stale data must not acquire a new retention lifetime after another restart"
                );
            }
        }
    }

    #[tokio::test]
    async fn restore_preserves_captured_ttl_and_single_aging_origin() {
        for downtime in [0, 10, 110, 120, 200] {
            let (key, entry) = make_positive_entry(34);
            let payload = Snapshot {
                version: SNAPSHOT_VERSION,
                captured_at_unix_secs: 1_000_000,
                entries: vec![SerializedEntry {
                    name: key.name.clone(),
                    qtype: key.qtype,
                    remaining_ttl_secs: 120,
                    provider: entry.provider,
                    message_wire: entry.message.to_bytes().unwrap(),
                }],
            };
            let dst = DnsCache::new(1_048_576);
            restore_snapshot_with_clock(
                &dst,
                payload,
                UNIX_EPOCH + Duration::from_secs(1_000_000 + downtime),
                || Duration::ZERO,
            )
            .await
            .unwrap();
            let restored = dst.get_allow_expired(&key).await.unwrap();
            assert_eq!(restored.original_ttl_secs, 120, "downtime={downtime}");
            assert_eq!(
                restored.message.answers[0].ttl, 120,
                "store the captured TTL, then age once"
            );
            assert_eq!(
                restored.inserted_at + Duration::from_secs(120),
                restored.expires_at,
                "refinement must preserve the original age/expiry relationship",
            );
            assert_eq!(dst.get(&key).await.is_some(), downtime < 120);
        }
    }

    #[tokio::test]
    async fn clock_rollback_and_fractional_downtime_are_conservative() {
        for (restore_time, expected) in [(999_999_000, None), (1_000_000_001, Some(120))] {
            let (key, entry) = make_positive_entry(34);
            let payload = Snapshot {
                version: SNAPSHOT_VERSION,
                captured_at_unix_secs: 1_000_000,
                entries: vec![SerializedEntry {
                    name: key.name.clone(),
                    qtype: key.qtype,
                    remaining_ttl_secs: 120,
                    provider: entry.provider,
                    message_wire: entry.message.to_bytes().unwrap(),
                }],
            };
            let dst = DnsCache::new(1_048_576);
            restore_snapshot_with_clock(
                &dst,
                payload,
                UNIX_EPOCH + Duration::from_millis(restore_time),
                || Duration::ZERO,
            )
            .await
            .unwrap();
            assert_eq!(
                dst.get(&key).await.map(|hit| hit.original_ttl_secs),
                expected
            );
            if let Some(hit) = dst.get(&key).await {
                let remaining = hit.expires_at.saturating_duration_since(Instant::now());
                assert!(remaining <= Duration::from_secs(119));
                assert!(remaining > Duration::from_secs(118));
            }
        }
    }

    #[tokio::test]
    async fn snapshot_then_restore_preserves_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let src = DnsCache::new(1_048_576);
        let (k, e) = make_positive_entry(34);
        src.insert(k.clone(), e, 120).await;

        let n = snapshot_to_path(&src, &path).await.unwrap();
        assert_eq!(n, 1, "snapshot must serialize the one live entry");
        assert!(path.exists());

        let dst = DnsCache::new(1_048_576);
        let n2 = restore_from_path(&dst, &path).await.unwrap();
        assert_eq!(n2, 1, "restore must bring the entry back");
        let hit = dst.get(&k).await.expect("restored entry must be visible");
        assert_eq!(hit.provider, "Cloudflare");
    }

    #[tokio::test]
    async fn guarded_snapshot_drops_temp_without_publish() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let src = DnsCache::new(1_048_576);
        let (k, e) = make_positive_entry(35);
        src.insert(k, e, 120).await;

        let out =
            snapshot_to_path_sync_guarded(&src, &path, "dump.stale.tmp", |_, _| Ok(false)).unwrap();

        assert!(out.is_none());
        assert!(!path.exists());
        assert!(!path.with_extension("dump.stale.tmp").exists());
    }

    #[tokio::test]
    async fn guarded_snapshot_prepares_payload_before_publishing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let src = DnsCache::new(1_048_576);
        let (k, e) = make_positive_entry(35);
        src.insert(k, e, 120).await;

        // The temp file must already be complete when publication is decided,
        // proving serialization happens outside the publication critical
        // section.
        let out = snapshot_to_path_sync_guarded(&src, &path, "dump.late.tmp", |tmp, target| {
            assert!(tmp.exists());
            assert!(std::fs::metadata(tmp).unwrap().len() > 0);
            std::fs::rename(tmp, target)?;
            Ok(true)
        })
        .unwrap();

        assert_eq!(out, Some(1));
        assert!(path.exists());
        assert!(!path.with_extension("dump.late.tmp").exists());
    }

    #[tokio::test]
    async fn snapshot_caps_wire_ttl_to_remaining_lifetime() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let src = DnsCache::new(1_048_576);
        let (k, e) = make_positive_entry(34);
        src.insert(k, e, 120).await;

        snapshot_to_path(&src, &path).await.unwrap();
        let snapshot = read_gzip_snapshot(&path);
        assert_eq!(snapshot.entries.len(), 1);
        let saved = &snapshot.entries[0];
        let msg = Message::from_bytes(&saved.message_wire).unwrap();

        assert!(saved.remaining_ttl_secs <= 120);
        assert_eq!(msg.answers[0].ttl, saved.remaining_ttl_secs);
    }

    #[tokio::test]
    async fn restore_caps_wire_ttl_to_remaining_lifetime() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let (key, entry) = make_positive_entry(55);
        let payload = Snapshot {
            version: SNAPSHOT_VERSION,
            captured_at_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            entries: vec![SerializedEntry {
                name: key.name.clone(),
                qtype: key.qtype,
                remaining_ttl_secs: 42,
                provider: entry.provider,
                message_wire: entry.message.to_bytes().unwrap(),
            }],
        };
        let raw = postcard::to_allocvec(&payload).unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&raw).unwrap();
        std::fs::write(&path, gz.finish().unwrap()).unwrap();

        let dst = DnsCache::new(1_048_576);
        let n = restore_from_path(&dst, &path).await.unwrap();
        assert_eq!(n, 1);
        let hit = dst.get(&key).await.expect("restored entry must be visible");

        assert!(hit.message.answers[0].ttl <= 42 && hit.message.answers[0].ttl > 0);
    }

    #[tokio::test]
    async fn restore_rejects_key_question_mismatch_and_uncacheable_qtypes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let qname = Name::from_str("attacker.example.").unwrap();
        let mut msg = Message::query();
        msg.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        msg.add_answer(Record::from_rdata(
            qname,
            300,
            RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                93, 184, 216, 34,
            ))),
        ));
        let wire = msg.to_bytes().unwrap();
        let payload = Snapshot {
            version: SNAPSHOT_VERSION,
            captured_at_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            entries: vec![
                // Key claims a different name than the message's question. A
                // crafted dump must not serve attacker data under an
                // unrelated cache key.
                SerializedEntry {
                    name: "victim.example".into(),
                    qtype: u16::from(RecordType::A),
                    remaining_ttl_secs: 42,
                    provider: "Cloudflare".into(),
                    message_wire: wire.clone(),
                },
                // ANY (255) is never produced by the cache pipeline.
                SerializedEntry {
                    name: "attacker.example".into(),
                    qtype: 255,
                    remaining_ttl_secs: 42,
                    provider: "Cloudflare".into(),
                    message_wire: wire,
                },
            ],
        };
        let raw = postcard::to_allocvec(&payload).unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&raw).unwrap();
        std::fs::write(&path, gz.finish().unwrap()).unwrap();

        let dst = DnsCache::new(1_048_576);
        let n = restore_from_path(&dst, &path).await.unwrap();
        assert_eq!(n, 0, "tampered entries must be dropped on restore");
    }

    #[tokio::test]
    async fn restore_rejects_empty_question_section() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let attacker = Name::from_str("attacker.example.").unwrap();
        let answer = Record::from_rdata(
            attacker.clone(),
            300,
            RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                93, 184, 216, 34,
            ))),
        );
        let victim = Name::from_str("victim.example.").unwrap();

        // No question at all: nothing binds the key to the payload.
        let mut no_question = Message::query();
        no_question.add_answer(answer.clone());

        // Two questions: the first one matches the key, but a second question
        // leaves the binding ambiguous.
        let mut two_questions = Message::query();
        two_questions.add_query(hickory_proto::op::Query::query(
            victim.clone(),
            RecordType::A,
        ));
        two_questions.add_query(hickory_proto::op::Query::query(attacker, RecordType::A));
        two_questions.add_answer(answer.clone());

        // Right name and type, wrong class. The cache only ever holds IN.
        let mut wrong_class = Message::query();
        let mut chaos_query = hickory_proto::op::Query::query(victim, RecordType::A);
        chaos_query.set_query_class(DNSClass::CH);
        wrong_class.add_query(chaos_query);
        wrong_class.add_answer(answer);

        let entries = [no_question, two_questions, wrong_class]
            .iter()
            .map(|msg| SerializedEntry {
                name: "victim.example".into(),
                qtype: u16::from(RecordType::A),
                remaining_ttl_secs: 42,
                provider: "Cloudflare".into(),
                message_wire: msg.to_bytes().unwrap(),
            })
            .collect();
        let payload = Snapshot {
            version: SNAPSHOT_VERSION,
            captured_at_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            entries,
        };
        let raw = postcard::to_allocvec(&payload).unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&raw).unwrap();
        std::fs::write(&path, gz.finish().unwrap()).unwrap();

        let dst = DnsCache::new(1_048_576);
        let n = restore_from_path(&dst, &path).await.unwrap();

        assert_eq!(n, 0, "an unbound question section must never be restored");
        assert!(dst
            .get(&CacheKey::from("victim.example", RecordType::A))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn idn_entries_survive_snapshot_restore_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let idn = Name::from_str("café.example.").unwrap();
        let wire_name = idn.to_ascii();
        assert!(
            wire_name.contains("xn--"),
            "fixture must be a punycode wire name"
        );

        let mut msg = Message::query();
        msg.add_query(hickory_proto::op::Query::query(idn.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            idn,
            300,
            RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                93, 184, 216, 34,
            ))),
        ));

        // Both key presentations of the same wire name must round-trip: the
        // punycode form the resolver derives today and the Unicode display
        // form a snapshot can carry.
        let ascii_key = CacheKey::from(&wire_name, RecordType::A);
        let unicode_key = CacheKey::from("café.example.", RecordType::A);
        let src = DnsCache::new(1_048_576);
        src.insert(
            ascii_key.clone(),
            CachedEntry::scaffold(msg.clone(), "Cloudflare".into()),
            120,
        )
        .await;
        src.insert(
            unicode_key.clone(),
            CachedEntry::scaffold(msg, "Cloudflare".into()),
            120,
        )
        .await;

        assert_eq!(snapshot_to_path(&src, &path).await.unwrap(), 2);

        let dst = DnsCache::new(1_048_576);
        let n = restore_from_path(&dst, &path).await.unwrap();

        assert_eq!(n, 2, "IDN entries must not be dropped on restore");
        assert!(dst.get(&ascii_key).await.is_some());
        assert!(dst.get(&unicode_key).await.is_some());
    }

    #[tokio::test]
    async fn restore_keeps_short_remaining_lifetime_without_min_ttl_clamp() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let (key, entry) = make_positive_entry(56);
        let payload = Snapshot {
            version: SNAPSHOT_VERSION,
            captured_at_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            entries: vec![SerializedEntry {
                name: key.name.clone(),
                qtype: key.qtype,
                remaining_ttl_secs: 5,
                provider: entry.provider,
                message_wire: entry.message.to_bytes().unwrap(),
            }],
        };
        let raw = postcard::to_allocvec(&payload).unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&raw).unwrap();
        std::fs::write(&path, gz.finish().unwrap()).unwrap();

        let dst = DnsCache::new(1_048_576);
        let n = restore_from_path(&dst, &path).await.unwrap();
        assert_eq!(n, 1);
        let hit = dst.get(&key).await.expect("restored entry must be visible");

        assert!(hit.original_ttl_secs <= 5 && hit.original_ttl_secs > 0);
        assert!(
            hit.expires_at
                .saturating_duration_since(Instant::now())
                .as_secs()
                <= 5
        );
        assert!(hit.message.answers[0].ttl <= 5 && hit.message.answers[0].ttl > 0);
    }

    #[tokio::test]
    async fn missing_dump_is_silent_noop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let dst = DnsCache::new(1_048_576);
        let n = restore_from_path(&dst, &path).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn corrupt_dump_is_ignored_and_removed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        std::fs::write(&path, b"not a bincode payload").unwrap();
        let dst = DnsCache::new(1_048_576);
        let n = restore_from_path(&dst, &path).await.unwrap();
        assert_eq!(n, 0);
        assert!(!path.exists(), "corrupt dump must be removed");
    }

    #[tokio::test]
    async fn snapshot_payload_is_gzip_compressed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let src = DnsCache::new(1_048_576);
        let (k, e) = make_positive_entry(34);
        src.insert(k, e, 120).await;
        snapshot_to_path(&src, &path).await.unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() >= 2);
        assert_eq!(
            &bytes[..2],
            &[0x1f, 0x8b],
            "snapshot must start with gzip magic bytes"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn snapshot_file_is_owner_read_write_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let src = DnsCache::new(1_048_576);
        let (k, e) = make_positive_entry(34);
        src.insert(k, e, 120).await;

        snapshot_to_path(&src, &path).await.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn gzip_decoder_rejects_payload_over_limit() {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&[0u8; 32]).unwrap();
        let bytes = gz.finish().unwrap();

        let err = decode_gzip_limited(&bytes, 8).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn uncompressed_dump_is_ignored_and_removed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let (k, e) = make_positive_entry(99);
        let payload = Snapshot {
            version: SNAPSHOT_VERSION,
            captured_at_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            entries: vec![SerializedEntry {
                name: k.name.clone(),
                qtype: k.qtype,
                remaining_ttl_secs: 120,
                provider: e.provider,
                message_wire: e.message.to_bytes().unwrap(),
            }],
        };
        std::fs::write(&path, postcard::to_allocvec(&payload).unwrap()).unwrap();

        let dst = DnsCache::new(1_048_576);
        let n = restore_from_path(&dst, &path).await.unwrap();

        assert_eq!(n, 0, "an uncompressed dump must restore nothing");
        assert!(dst.get(&k).await.is_none());
        assert!(!path.exists(), "an uncompressed dump must be removed");
    }

    /// Guards the `SNAPSHOT_VERSION` bump to 2. Version 1 entries were written
    /// while the DNSSEC toggle stripped records before storing them, so
    /// restoring one serves answers without RRSIG until it expires. The bump
    /// exists to prevent exactly that.
    ///
    /// The version literal here is deliberately `1` and not `SNAPSHOT_VERSION -
    /// 1`, so reverting the bump makes this test fail.
    #[tokio::test]
    async fn version_1_dump_is_rejected_and_deleted() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let src = DnsCache::new(1_048_576);
        let (k, e) = make_positive_entry(77);
        src.insert(k.clone(), e, 120).await;

        let mut entries: Vec<SerializedEntry> = Vec::new();
        for (key_arc, entry) in src.iter() {
            let remaining = entry
                .expires_at
                .saturating_duration_since(Instant::now())
                .as_secs() as u32;
            entries.push(SerializedEntry {
                name: key_arc.name.clone(),
                qtype: key_arc.qtype,
                remaining_ttl_secs: remaining,
                provider: entry.provider.clone(),
                message_wire: entry.message.to_bytes().unwrap(),
            });
        }
        let raw = postcard::to_allocvec(&Snapshot {
            version: 1,
            captured_at_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            entries,
        })
        .unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&raw).unwrap();
        std::fs::write(&path, gz.finish().unwrap()).unwrap();

        let dst = DnsCache::new(1_048_576);
        let n = restore_from_path(&dst, &path).await.unwrap();

        assert_eq!(n, 0, "a version-1 dump must restore nothing");
        assert!(
            dst.get(&k).await.is_none(),
            "no entry from a version-1 dump may reach the cache"
        );
        assert!(
            !path.exists(),
            "the rejected dump must be deleted so it is not re-read every boot"
        );
    }

    #[tokio::test]
    async fn expired_entries_are_dropped_on_snapshot() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let src = DnsCache::new(1_048_576);
        let (k, mut e) = make_positive_entry(34);
        e.expires_at = Instant::now() - std::time::Duration::from_secs(10);
        // Bypass `insert` so we can keep the stale `expires_at`.
        src.inner_insert_raw(k, e).await;
        let n = snapshot_to_path(&src, &path).await.unwrap();
        assert_eq!(n, 0, "expired entry must be skipped by snapshot");
    }

    /// A snapshot taken after `clear` must carry nothing forward: the dump is
    /// the one path that can outlive the invalidation, so an entry that
    /// survived into the file would come back on the next start.
    #[tokio::test]
    async fn cleared_entries_are_dropped_on_snapshot_and_do_not_restore() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache.dump");
        let src = DnsCache::new(1_048_576);
        let (k, e) = make_positive_entry(34);
        src.insert(k.clone(), e, 120).await;
        assert_eq!(snapshot_to_path(&src, &path).await.unwrap(), 1);

        src.clear().await;
        let n = snapshot_to_path(&src, &path).await.unwrap();

        assert_eq!(n, 0, "cleared entry must not survive restart snapshot");
        let dst = DnsCache::new(1_048_576);
        assert_eq!(restore_from_path(&dst, &path).await.unwrap(), 0);
        assert!(dst.get(&k).await.is_none());
    }

    #[test]
    fn restore_filter_drops_all_private_answers_when_rebinding_enabled() {
        let name = Name::from_str("private.example.").unwrap();
        let mut msg = Message::query();
        msg.add_answer(Record::from_rdata(
            name,
            300,
            RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                10, 0, 0, 1,
            ))),
        ));

        assert!(!filter_rebinding_for_restore(&mut msg, true));
        assert!(msg.answers.is_empty());
    }
}
