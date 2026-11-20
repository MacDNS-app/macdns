// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(panic = "unwind"))]
compile_error!("macdns-resolver requires panic=unwind: every extern \"C\" export relies on catch_unwind to return a sentinel");

pub mod blocklist;
pub mod blocklist_scheduler;
pub mod cache;
pub mod cache_persist;
pub mod config;
pub mod consensus;
pub mod dns64;
#[cfg(test)]
mod doh_repro;
#[cfg(test)]
mod doh_test_server;
mod domain_name;
pub mod forward;
pub mod hedge;
#[cfg(test)]
#[path = "../../../vendor/tests/transport.rs"]
mod hickory_transport_tests;
mod history;
pub mod listener;
pub mod lmdb;
pub mod local_zones;
pub mod log_hooks;
pub mod network_profile;
pub mod overrides;
pub mod policy;
pub mod probe;
mod provider_transport;
mod provider_transport_trace;
pub mod providers;
mod proxy_control;
pub mod query;
pub mod rebinding;
pub mod runtime;
pub mod state;
pub mod stats;
#[cfg(test)]
pub(crate) mod test_dns_server;
pub mod zones;

use crate::cache::DnsCache;
use crate::forward::ForwardResolver;
use crate::lmdb::DomainName;
use crate::local_zones::LocalZones;
use crate::overrides::OverrideStore;
use crate::providers::ProviderPool;
use crate::runtime::{block_on, cancel_token, spawn, start_runtime, stop_runtime};
use crate::state::{get_state, init_state, ModuleState};
use crate::zones::ForwardZones;
use arc_swap::ArcSwap;
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, TXT};
use hickory_proto::rr::{RData, RecordType};
use std::ffi::{CStr, CString};
use std::net::IpAddr;
use std::os::raw::{c_char, c_int, c_ushort};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const SHUTDOWN_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(3);

/// Deadline for the hourly `dns_snapshot_cache` call. Longer than the shutdown
/// budget because nothing waits on it, but bounded so a wedged runtime or a
/// slow disk cannot pin the caller thread for the rest of the hour.
const PERIODIC_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(10);

/// Return code for a snapshot the deadline abandoned. Distinct from the generic
/// `-1` so the host can tell "the write is too slow" from "persistence is
/// disabled".
const SNAPSHOT_TIMED_OUT: c_int = -2;

/// Return code for a snapshot refused because a previous writer still owns the
/// single flight. Distinct from `-1` so the host does not report an expected
/// coalesced tick as a failure.
const SNAPSHOT_BUSY: c_int = -3;

/// Outcome of one snapshot attempt: the join result of the blocking writer
/// wrapping the writer's own I/O result, where `None` means a newer cache
/// generation superseded the dump before publication.
type SnapshotAttempt = Result<std::io::Result<Option<usize>>, tokio::task::JoinError>;

/// Serialises `dns_init` and `dns_shutdown`. The runtime and state slots have
/// independent locks (`OnceLock<Mutex>` and `ArcSwap`), so without an outer
/// guard a `dns_init` racing a `dns_shutdown` could see `state == None` and a
/// stopped runtime, pass both early-exit guards, and start a second runtime on
/// top of orphan listener Arcs from the first session. The Swift host
/// serialises these calls, but the FFI must stay safe if a caller does not.
static LIFECYCLE_LOCK: Mutex<()> = Mutex::new(());

fn lifecycle_lock() -> std::sync::MutexGuard<'static, ()> {
    match LIFECYCLE_LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Advanced by every `dns_init` that starts a new session and by every
/// `dns_shutdown` that ends one. `dns_flush_cache` and
/// `dns_notify_network_change` block on the runtime, so they can still be
/// running after a restart. They capture this generation next to the state
/// `Arc` and revalidate it before touching an artefact they no longer own.
/// Advancing on shutdown too covers the stop-to-init window, where the session
/// that admitted the work is gone and no new one exists yet.
static SESSION_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Captures the live session: its generation and the module state it published
/// (`None` while the resolver is stopped). Taken under the lifecycle lock so the
/// pair can never mix one session's generation with another session's state.
fn capture_session() -> (u64, Option<Arc<ModuleState>>) {
    let _lifecycle = lifecycle_lock();
    (SESSION_GENERATION.load(Ordering::Acquire), get_state())
}

fn session_is_current(generation: u64) -> bool {
    SESSION_GENERATION.load(Ordering::Acquire) == generation
}

/// Optional on-disk path for cache snapshots, set by `dns_set_cache_path`
/// before `dns_init`. Without a path the cache is in-memory only. It lives for
/// the whole process so `dns_shutdown` dumps to the same location `dns_init`
/// loaded from.
static CACHE_PATH: OnceLock<arc_swap::ArcSwapOption<PathBuf>> = OnceLock::new();
static CACHE_SNAPSHOT_EPOCH: AtomicU64 = AtomicU64::new(1);
static CACHE_SNAPSHOT_ATTEMPT: AtomicU64 = AtomicU64::new(0);
static CACHE_DUMP_LOCK: Mutex<()> = Mutex::new(());
#[cfg(test)]
static SHUTDOWN_SNAPSHOT_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static SNAPSHOT_TMP_NAMES: Mutex<Vec<String>> = Mutex::new(Vec::new());
static PROXY_BYPASS_REQUESTED: AtomicBool = AtomicBool::new(true);
/// Location of `query-history.sqlite`, set by `dns_set_history_path` and
/// handed to the history store on every `dns_configure_history`.
static HISTORY_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

pub(crate) fn proxy_interception_ready() -> bool {
    !PROXY_BYPASS_REQUESTED.load(Ordering::Acquire)
}

fn set_proxy_bypass_requested(requested: bool) {
    PROXY_BYPASS_REQUESTED.store(requested, Ordering::Release);
}

#[cfg(test)]
fn set_proxy_bypass_requested_for_test(requested: bool) {
    set_proxy_bypass_requested(requested);
}

fn cache_path_slot() -> &'static arc_swap::ArcSwapOption<PathBuf> {
    CACHE_PATH.get_or_init(arc_swap::ArcSwapOption::empty)
}

fn current_cache_path() -> Option<Arc<PathBuf>> {
    cache_path_slot().load_full()
}

fn cache_dump_lock() -> std::sync::MutexGuard<'static, ()> {
    CACHE_DUMP_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Single-flight ownership of the cache writer.
///
/// The FFI deadline only abandons the *wait*. The `spawn_blocking` closure keeps
/// running and still publishes through the epoch check. Releasing ownership when
/// the FFI call returns would let the next tick start a second writer of the
/// same epoch, and the two would race on the final rename, where the older one
/// can win and publish the staler dump. The guard is therefore moved into the
/// blocking closure and drops only when that closure finishes.
static SNAPSHOT_WRITER_ACTIVE: AtomicBool = AtomicBool::new(false);

struct SnapshotWriterGuard;

impl SnapshotWriterGuard {
    fn try_acquire() -> Option<Self> {
        if SNAPSHOT_WRITER_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            Some(Self)
        } else {
            None
        }
    }
}

impl Drop for SnapshotWriterGuard {
    fn drop(&mut self) {
        SNAPSHOT_WRITER_ACTIVE.store(false, Ordering::Release);
    }
}

/// Builds the temp-file name for one snapshot attempt.
///
/// The epoch alone is not unique: it advances only on `dns_init` and cache
/// invalidation, and the temp file is opened with `create(true).truncate(true)`,
/// so two snapshots in the same epoch would truncate the same inode and one
/// could publish a partial dump. The per-attempt counter gives every write a
/// private file. The publication lock still decides which finished file wins
/// the rename.
fn next_snapshot_tmp_name(tmp_extension: &str, epoch: u64) -> String {
    let attempt = CACHE_SNAPSHOT_ATTEMPT.fetch_add(1, Ordering::Relaxed);
    let name = format!("{tmp_extension}.{epoch}.{attempt}");
    #[cfg(test)]
    SNAPSHOT_TMP_NAMES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(name.clone());
    name
}

/// Writes a cache snapshot without holding the publication lock across the
/// expensive work.
///
/// Serialization, compression, and fsync run lock-free so a snapshot that
/// shutdown abandoned after its timeout can never block the next `dns_init`.
/// The publication lock covers only the epoch check and the atomic rename, and
/// a snapshot from a superseded epoch is discarded instead of published.
fn snapshot_cache_blocking(
    cache: Arc<DnsCache>,
    path: PathBuf,
    tmp_extension: String,
    epoch: u64,
) -> std::io::Result<Option<usize>> {
    let unique_tmp = next_snapshot_tmp_name(&tmp_extension, epoch);
    crate::cache_persist::snapshot_to_path_sync_guarded(
        &cache,
        &path,
        &unique_tmp,
        |tmp, target| {
            let _dump = cache_dump_lock();
            if CACHE_SNAPSHOT_EPOCH.load(Ordering::Acquire) != epoch {
                return Ok(false);
            }
            std::fs::rename(tmp, target)?;
            Ok(true)
        },
    )
}

/// Reads a C string into an owned `String`. Returns `None` when the pointer is
/// null or the bytes are not valid UTF-8, which callers report as invalid input
/// so a buggy host cannot cause UB at the deref site.
///
/// # Safety
/// `ptr` must either be null or a valid, NUL-terminated UTF-8 C
/// string for the call duration.
unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller contract guarantees non-null + NUL-terminated.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// Panic guard for `c_int` entrypoints whose failure sentinel is `0`.
///
/// `name` is logged on the panic path. Without it the agent sees an ordinary
/// failure return, indistinguishable from a rejected argument, and the panic
/// leaves no trace.
fn catch_ffi_panic(name: &'static str, operation: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or_else(|_| {
        log::error!("{}: panic", name);
        0
    })
}

#[no_mangle]
pub extern "C" fn dns_init(port: c_ushort) -> c_int {
    catch_ffi_panic("dns_init", || dns_init_guarded(port))
}

fn dns_init_guarded(port: c_ushort) -> c_int {
    install_ffi_logger();
    // Panic hook must land right after the logger so a panic during the
    // rest of `dns_init` still routes through `emit_log`. `RUST_BACKTRACE`
    // is seeded by the Swift host (`AgentMain.main`) before this dylib is
    // loaded, so the hook's first `Backtrace::force_capture()` sees a
    // populated frame list without any `set_var` from Rust.
    log_hooks::install_panic_hook();

    // The lifecycle lock is held outside the inner `catch_unwind`, so the init
    // attempt and its cleanup run under one acquisition. The guard lives in
    // this frame and survives the unwind, which keeps a parallel
    // `dns_init`/`dns_shutdown` from observing the half-state mid-teardown and
    // avoids a re-acquire that could deadlock the non-reentrant mutex.
    let _lifecycle = lifecycle_lock();
    catch_unwind(AssertUnwindSafe(|| dns_init_inner(port))).unwrap_or_else(|_| {
        log::error!("dns_init: panic; cleaning up partial init");
        // A panic between `start_runtime()` and `init_state()` (for example the
        // `expect` in `ProviderPool::new`) leaves the runtime alive with no
        // module state. The next `dns_init` would then hit the early-exit guard
        // and refuse to start, so tear both halves down here.
        crate::state::clear_state();
        runtime::stop_runtime(Duration::from_secs(2));
        0
    })
}

/// Caller must hold `LIFECYCLE_LOCK`. `dns_init` acquires it around both this
/// call and its panic cleanup.
fn dns_init_inner(port: c_ushort) -> c_int {
    if get_state().is_some() {
        log::info!("resolver already initialized; dns_init is idempotent");
        return 1;
    }
    if runtime::is_running() {
        log::warn!("resolver runtime is running without state; refusing duplicate dns_init");
        return 0;
    }
    set_proxy_bypass_requested(true);
    proxy_control::clear();
    CACHE_SNAPSHOT_EPOCH.fetch_add(1, Ordering::AcqRel);
    // Advance before anything else in this session becomes reachable, so an
    // operation still running from the previous session already reads as stale.
    SESSION_GENERATION.fetch_add(1, Ordering::AcqRel);

    if start_runtime().is_err() {
        return 0;
    }

    let v4_bind = format!("127.0.0.1:{}", port);
    let v6_bind = format!("[::1]:{}", port);
    // Bind both 127.0.0.1 and [::1]: Apple's resolver and some CLI tools try
    // ::1 first on dual-stack hosts. The v4 bind is mandatory. The v6 bind is
    // best effort so hosts with IPv6 disabled still start.
    //
    // Everything touching Tokio runtime internals (socket binds, hickory
    // resolver builders, surge-ping `Client::new`) must run inside the runtime
    // context, or it panics.
    let bound = block_on(async move {
        let udp4 = tokio::net::UdpSocket::bind(&v4_bind).await.map_err(|e| {
            log::error!("UDP bind {} failed: {}", v4_bind, e);
            e
        })?;
        let tcp4 = tokio::net::TcpListener::bind(&v4_bind).await.map_err(|e| {
            log::error!("TCP bind {} failed: {}", v4_bind, e);
            e
        })?;
        let udp6 = match tokio::net::UdpSocket::bind(&v6_bind).await {
            Ok(s) => Some(s),
            Err(e) => {
                log::warn!(
                    "UDP bind {} failed (v6 UDP listener disabled): {}",
                    v6_bind,
                    e
                );
                None
            }
        };
        let tcp6 = match tokio::net::TcpListener::bind(&v6_bind).await {
            Ok(l) => Some(l),
            Err(e) => {
                log::warn!("TCP bind {} failed (v6 listener disabled): {}", v6_bind, e);
                None
            }
        };
        Ok::<_, std::io::Error>((udp4, tcp4, udp6, tcp6))
    });
    let (udp_sock, tcp_lst, udp_sock_v6, tcp_lst_v6) = match bound {
        Ok(Ok(pair)) => pair,
        _ => {
            stop_runtime(Duration::from_secs(2));
            return 0;
        }
    };

    let v4_addr = udp_sock
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let listener_addrs = match (udp_sock_v6.as_ref(), tcp_lst_v6.as_ref()) {
        (Some(u6), Some(_)) => {
            let v6_addr = u6
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "?".into());
            format!("{}, {}", v4_addr, v6_addr)
        }
        _ => v4_addr,
    };
    log::info!("resolver listening on {} (UDP+TCP)", listener_addrs);

    let pool = Arc::new(ProviderPool::new());
    // 200 MB byte cap. Moka stores whole encoded `Message` blobs, so an A
    // record shared by N answers costs N times the bytes. The headroom keeps a
    // useful entry count at steady state instead of evicting hot entries under
    // duplicate-RRset pressure.
    let cache = Arc::new(DnsCache::new(209_715_200));
    let overrides = Arc::new(OverrideStore::new());
    let zones = Arc::new(ForwardZones::new());
    let local_zones = Arc::new(LocalZones::new());
    let forward: ArcSwap<Option<Arc<ForwardResolver>>> = ArcSwap::from_pointee(None);

    // Restore runs inside the runtime because `cache.insert` awaits moka.
    // Failure is non-fatal: a warm cache is a latency optimization, not a
    // correctness requirement.
    if let Some(path) = current_cache_path() {
        let cache_for_restore = cache.clone();
        let path_clone = path.as_ref().clone();
        let display = path_clone.display().to_string();
        // No publication lock here: the snapshot epoch was already advanced
        // above, so an abandoned worker can no longer publish, and rename is
        // atomic. Holding the lock across decompression would let a timed-out
        // shutdown snapshot block startup.
        match block_on(async move {
            crate::cache_persist::restore_from_path(&cache_for_restore, &path_clone).await
        }) {
            Ok(Ok(n)) => log::info!("resolver cache restored {} entries from {}", n, display),
            Ok(Err(e)) => log::warn!("resolver cache restore failed: {}", e),
            Err(e) => log::warn!("resolver cache restore block_on failed: {}", e),
        }
    } else {
        log::warn!("resolver cache path not configured — restore skipped (persistence disabled)");
    }

    let state = init_state(ModuleState {
        pool,
        cache,
        policy: arc_swap::ArcSwap::from_pointee(crate::policy::RuntimePolicySnapshot {
            overrides,
            zones,
        }),
        ephemeral_zones: arc_swap::ArcSwap::from_pointee(std::sync::Arc::new(
            crate::zones::ForwardZones::new(),
        )),
        local_zones,
        forward,
        forward_generation: AtomicU64::new(0),
        network: Arc::new(crate::network_profile::NetworkProfileStore::new()),
    });

    let Some(token) = cancel_token() else {
        stop_runtime(Duration::from_secs(2));
        return 0;
    };
    let t_udp = token.clone();
    let t_tcp = token.clone();
    let _ = spawn(async move {
        listener::run_udp(udp_sock, t_udp).await;
    });
    let _ = spawn(async move {
        listener::run_tcp(tcp_lst, t_tcp).await;
    });
    if let Some(udp6) = udp_sock_v6 {
        let t = token.clone();
        let _ = spawn(async move {
            listener::run_udp(udp6, t).await;
        });
    }
    if let Some(tcp6) = tcp_lst_v6 {
        let t = token.clone();
        let _ = spawn(async move {
            listener::run_tcp(tcp6, t).await;
        });
    }
    state.pool.spawn_keepalive(token.clone());
    let prefetch_state = state.clone();
    let prefetch_cancel = token.clone();
    let _ = spawn(async move {
        query::run_prefetch_loop(prefetch_state, prefetch_cancel).await;
    });

    1
}

#[no_mangle]
pub extern "C" fn dns_shutdown(skip_snapshot: c_int) -> c_int {
    catch_ffi_panic("dns_shutdown", || dns_shutdown_inner(skip_snapshot != 0))
}

fn dns_shutdown_inner(skip_snapshot: bool) -> c_int {
    let _lifecycle = lifecycle_lock();
    // Retire before the snapshot below writes. The snapshot is gated by
    // `CACHE_SNAPSHOT_EPOCH`, not by this generation, so retiring first cannot
    // invalidate it. Retiring afterwards would leave the snapshot window open
    // for a previous-session flush to delete the dump it just wrote.
    SESSION_GENERATION.fetch_add(1, Ordering::AcqRel);
    set_proxy_bypass_requested(true);
    // The agent's fail-safe stop path calls `ResolverModule.stop()` without
    // disconnecting the control XPC link first, so the session has to be
    // dropped here too. Idempotent: the normal Swift clear stays safe.
    proxy_control::clear();
    log::debug!("resolver shutdown requested");
    if skip_snapshot {
        log::info!("resolver cache snapshot skipped for forced shutdown");
    } else {
        // Snapshot before stopping the runtime. The blocking serializer runs
        // behind a short deadline so shutdown cannot sit inside the lifecycle
        // lock indefinitely.
        match (
            current_cache_path(),
            get_state(),
            SnapshotWriterGuard::try_acquire(),
        ) {
            (Some(path), Some(state), Some(writer)) => {
                #[cfg(test)]
                SHUTDOWN_SNAPSHOT_ATTEMPTS.fetch_add(1, Ordering::AcqRel);
                let cache = state.cache.clone();
                let path_buf = path.as_ref().clone();
                let display = path_buf.display().to_string();
                let epoch = CACHE_SNAPSHOT_EPOCH.load(Ordering::Acquire);
                let tmp_extension = format!("dump.shutdown-{epoch}.tmp");
                match block_on(async move {
                    tokio::time::timeout(SHUTDOWN_SNAPSHOT_TIMEOUT, async move {
                        // Drain moka's write queue first so the snapshot
                        // iterator sees the logical cache state.
                        cache.flush_pending().await;
                        tokio::task::spawn_blocking(move || {
                            // Ownership is released only when the write really
                            // ends, not when the deadline above gives up on it.
                            let _writer = writer;
                            snapshot_cache_blocking(cache, path_buf, tmp_extension, epoch)
                        })
                        .await
                    })
                    .await
                }) {
                    Ok(Ok(Ok(Ok(Some(n))))) => {
                        log::info!("resolver cache snapshot wrote {} entries to {}", n, display)
                    }
                    Ok(Ok(Ok(Ok(None)))) => log::info!(
                        "resolver cache snapshot skipped because a newer cache generation exists"
                    ),
                    Ok(Ok(Ok(Err(e)))) => log::warn!("resolver cache snapshot failed: {}", e),
                    Ok(Ok(Err(e))) => log::warn!("resolver cache snapshot task failed: {}", e),
                    Ok(Err(_)) => log::warn!(
                        "resolver cache snapshot timed out after {:?}; shutdown continuing",
                        SHUTDOWN_SNAPSHOT_TIMEOUT
                    ),
                    Err(e) => log::warn!("resolver cache snapshot block_on failed: {}", e),
                }
            }
            (None, ..) => {
                log::warn!("resolver cache path not configured — shutdown snapshot skipped")
            }
            (_, None, _) => {
                log::warn!("resolver state already cleared — shutdown snapshot skipped")
            }
            (.., None) => log::warn!(
                "resolver cache snapshot still running from a previous call — shutdown snapshot skipped"
            ),
        }
    }
    blocklist_scheduler::stop();
    // Probe clients hold a receiver task on this runtime. Drop them before it
    // goes away, or the next session inherits sockets nothing reads.
    probe::reset_clients();
    stop_runtime(Duration::from_secs(5));
    // Drop the module state so the next dns_init rebuilds cache, provider
    // pool, overrides, zones, and forward resolver from scratch.
    crate::state::clear_state();
    // The listeners are gone, so every lookup of this session is queued. The
    // writer itself lives for the process, like the blocked telemetry thread.
    history::flush();
    log::info!("resolver shutdown complete");
    1
}

/// Clears the cache of the state the caller captured. Takes the state rather
/// than re-reading the global slot: a caller that started before a restart must
/// clear the cache it was admitted against, never the one the new session
/// published.
fn clear_live_cache_sync(state: &ModuleState, reason: &str) {
    let cache = state.cache.clone();
    match block_on(async move {
        cache.clear().await;
    }) {
        Ok(()) => log::info!("resolver cache cleared ({})", reason),
        Err(e) => log::warn!("resolver cache clear failed ({}): {}", reason, e),
    }
}

/// Deletes the on-disk dump on behalf of `generation`.
///
/// The session check runs under the publication lock, so an operation admitted
/// before a restart cannot delete the dump the new session owns. The epoch bump
/// that stops in-flight writers happens only when the removal goes ahead.
fn remove_cache_dump_for_session(generation: u64, reason: &str) {
    let _dump = cache_dump_lock();
    if !session_is_current(generation) {
        log::info!(
            "resolver cache dump kept ({}): the session that requested the removal has restarted",
            reason
        );
        return;
    }
    CACHE_SNAPSHOT_EPOCH.fetch_add(1, Ordering::AcqRel);
    if let Some(path) = current_cache_path() {
        crate::cache_persist::remove_dump(path.as_ref());
        log::info!("resolver cache dump removed ({})", reason);
    }
}

#[no_mangle]
pub extern "C" fn dns_is_ready() -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if runtime::is_running() && get_state().is_some() {
            1
        } else {
            0
        }
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_is_ready: panic");
        0
    })
}

/// Copies the process-wide resolver counters into `out`.
///
/// Read-only and allocation-free: the caller owns the destination struct, so
/// there is no matching `dns_*_free_*`. The counters are process statics, not
/// session state, so this answers whether or not `dns_init` has run. A stopped
/// resolver reports the totals accumulated by the previous session.
///
/// Returns 1 on success, 0 on a NULL pointer or panic.
///
/// # Safety
/// `out` must point to a writable `stats::StatsSnapshot` for the call duration.
#[no_mangle]
pub unsafe extern "C" fn dns_stats_snapshot(out: *mut stats::StatsSnapshot) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            log::warn!("dns_stats_snapshot: null out pointer");
            return 0;
        }
        // SAFETY: caller contract guarantees `out` is writable and correctly
        // sized. `StatsSnapshot` is `Copy`, so nothing is dropped in place.
        unsafe { std::ptr::write(out, stats::snapshot()) };
        1
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_stats_snapshot: panic");
        0
    })
}

#[no_mangle]
pub extern "C" fn dns_set_proxy_bypass_requested(enabled: c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        set_proxy_bypass_requested(enabled != 0);
        1
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_set_proxy_bypass_requested: panic");
        0
    })
}

/// Installs the control-plane HMAC session. `session_len` must be 16 and
/// `key_len` must be 32. Returns 1 on success, 0 on any failure/panic.
///
/// # Safety
/// `session_ptr`/`key_ptr` must reference at least the stated lengths for the
/// call duration, or be null (rejected as failure).
#[no_mangle]
pub unsafe extern "C" fn dns_configure_proxy_control(
    session_ptr: *const u8,
    session_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> c_int {
    catch_ffi_panic("dns_configure_proxy_control", || {
        if session_ptr.is_null() || key_ptr.is_null() || session_len != 16 || key_len != 32 {
            return 0;
        }
        let mut id = [0u8; 16];
        // Zeroizing so the staged key does not survive this frame. `configure`
        // scrubs the copy it receives once the session owns the material.
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        // SAFETY: pointers are non-null and lengths were validated above.
        unsafe {
            std::ptr::copy_nonoverlapping(session_ptr, id.as_mut_ptr(), 16);
            std::ptr::copy_nonoverlapping(key_ptr, key.as_mut_ptr(), 32);
        }
        proxy_control::configure(id, *key);
        1
    })
}

/// Clears any installed control-plane session. Returns 1 on success.
#[no_mangle]
pub extern "C" fn dns_clear_proxy_control() -> c_int {
    catch_ffi_panic("dns_clear_proxy_control", || {
        proxy_control::clear();
        1
    })
}

/// Returns true when the delta between `prev` and `next` changes anything the
/// live upstreams were built with. Today that is only the DNSSEC toggle: it sets
/// the upstream's default CD bit, frozen into the slot's `InnerState` when the
/// connection is built, so the upstreams must be rebuilt for a toggle to take
/// effect. DO is unconditional and plays no part. The App-side transaction also
/// bounces the whole backend for this knob (`saveFullConfigWithBounce`), which
/// rebuilds the pool from scratch.
///
/// Keep this function exhaustive and in sync with
/// `InnerState::built_for_dnssec`: the selection gate refuses to route any slot
/// whose snapshot disagrees with the configured policy, so a knob added here
/// without a matching field there would gate slots out with no rebuild able to
/// clear them.
pub(crate) fn needs_provider_rebuild(
    prev: &crate::config::ResolverOptions,
    next: &crate::config::ResolverOptions,
) -> bool {
    prev.dnssec != next.dnssec
}

/// Returns true when the delta changes client-visible cache policy. The DNSSEC
/// toggle flips the upstream CD bit, so answers cached under the other mode must
/// go, because those cached with CD set were never validated. The DO bit is
/// unconditional and plays no part. Log and serve-expired toggles do not
/// invalidate existing entries.
pub(crate) fn needs_cache_flush(
    prev: &crate::config::ResolverOptions,
    next: &crate::config::ResolverOptions,
) -> bool {
    prev.dnssec != next.dnssec
}

fn apply_resolver_options_checked(next: crate::config::ResolverOptions) -> bool {
    let _lifecycle = lifecycle_lock();
    let prev = crate::config::current();
    // The lifecycle lock is held for the whole call, so the generation read here
    // stays valid for the cache invalidation below.
    let session_generation = SESSION_GENERATION.load(Ordering::Acquire);
    let state = get_state();
    if let Some(ref state) = state {
        let current_ids = state.pool.provider_ids_canonical_order();
        let next_ids = crate::config::canonicalize_provider_ids(&next.doh_providers);
        if current_ids != next_ids {
            log::error!("resolver options rejected: provider list cannot change live");
            return false;
        }
    }

    crate::config::set(next);
    let new_opts = crate::config::current();
    if needs_provider_rebuild(&prev, &new_opts) {
        if let Some(ref state) = state {
            let gated_out = state
                .pool
                .rebuild_all_conns(&format!("dnssec toggled to {}", new_opts.dnssec));
            if gated_out > 0 {
                // Fail-closed: those slots hold a CD bit for the previous
                // setting, so routing skips them until a rebuild succeeds. The
                // maintenance tick retries them. Still return `true`:
                // `crate::config::set` already ran, and reporting a rejected
                // transaction would desync the Swift side from a change that
                // did take effect.
                log::error!(
                    "dnssec toggled to {}: {} provider conn(s) failed to rebuild and are gated out of routing until a later maintenance tick",
                    new_opts.dnssec,
                    gated_out
                );
            }
        }
    }
    if needs_cache_flush(&prev, &new_opts) {
        if let Some(ref state) = state {
            clear_live_cache_sync(state, "dnssec toggled");
        }
        remove_cache_dump_for_session(session_generation, "dnssec toggled");
    }
    true
}

/// Sets resolver options sourced from UI-owned `state.json` toggles. Must be
/// called before `dns_init` for the initial values to influence `ProviderPool`
/// construction. Runtime calls update the global store. DNSSEC changes also
/// rebuild providers and flush the cache.
///
/// Returns 0 for invalid provider strings, invalid dispatch mode, null/invalid
/// UTF-8 pointers, or live provider-list changes.
///
/// # Safety
/// `provider_ids` must be null or a valid, NUL-terminated UTF-8 C string for
/// the call duration. Null is rejected before dereference.
#[no_mangle]
pub unsafe extern "C" fn dns_set_resolver_options(
    dnssec: c_int,
    _case_randomization: c_int,
    log_queries: c_int,
    log_replies: c_int,
    prefetch: c_int,
    serve_expired: c_int,
    _log_servfail: c_int,
    provider_ids: *const c_char,
    dispatch_mode: c_int,
    answer_refinement: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(raw_provider_ids) = (unsafe { cstr_to_string(provider_ids) }) else {
            log::error!("resolver options rejected: provider list pointer invalid");
            return 0;
        };
        let parsed_ids: Option<Vec<_>> = raw_provider_ids
            .split(',')
            .map(str::trim)
            .map(crate::config::DoHProviderId::parse_raw)
            .collect();
        let Some(parsed_ids) = parsed_ids else {
            log::error!("resolver options rejected: unknown provider id");
            return 0;
        };
        if parsed_ids.is_empty() {
            log::error!("resolver options rejected: empty provider list");
            return 0;
        }
        let provider_ids = crate::config::canonicalize_provider_ids(&parsed_ids);
        let Some(dispatch_mode) = crate::config::DispatchMode::from_ffi(dispatch_mode) else {
            log::error!(
                "resolver options rejected: invalid dispatch mode {}",
                dispatch_mode
            );
            return 0;
        };

        let opts = crate::config::ResolverOptions {
            dnssec: dnssec != 0,
            log_queries: log_queries != 0,
            log_replies: log_replies != 0,
            prefetch: prefetch != 0,
            serve_expired: serve_expired != 0,
            doh_providers: provider_ids,
            dispatch_mode,
            answer_refinement: answer_refinement != 0,
        };

        if apply_resolver_options_checked(opts) {
            1
        } else {
            0
        }
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_set_resolver_options: panic");
        0
    })
}

/// Rebuilds the in-memory blocklist `MultiCategoryDb` from
/// `blocklist_settings.json`. Reuses the scheduler's settings loader so the
/// on-disk format stays in lockstep with the refresh loop. Idempotent, so any
/// Swift path that needs an immediate re-apply (zone regeneration, UI-driven
/// settings saves) can call it.
///
/// # Safety
/// `settings_path` must be a valid, NUL-terminated UTF-8 C string for the
/// call duration.
#[no_mangle]
pub unsafe extern "C" fn dns_reload_blocklist(settings_path: *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if settings_path.is_null() {
            return 0;
        }
        let s = match unsafe { CStr::from_ptr(settings_path) }.to_str() {
            Ok(v) => v,
            Err(_) => return 0,
        };
        let blocklists_dir =
            std::path::PathBuf::from(blocklist_scheduler::paths::blocklists_path());
        match blocklist_scheduler::settings::load_config(std::path::Path::new(s), &blocklists_dir) {
            Ok(cfg) => match blocklist::reload_from_config(&cfg, "ffi-reload") {
                blocklist::ReloadOutcome::Applied => 1,
                blocklist::ReloadOutcome::PendingMissing { missing } => {
                    log::info!(
                        "blocklist reload: {missing} selected database(s) not downloaded yet; previous snapshot stays live until the next refresh"
                    );
                    1
                }
                blocklist::ReloadOutcome::KeptPrevious { open_failed } => {
                    log::error!(
                        "blocklist reload kept previous snapshot because {open_failed} database(s) failed to open"
                    );
                    0
                }
            },
            Err(e) => {
                log::error!("blocklist reload: {}", e);
                0
            }
        }
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_reload_blocklist: panic");
        0
    })
}

/// # Safety
/// `settings_path` must be a valid, NUL-terminated UTF-8 C string for the
/// call duration. Loads `blocklist_settings.json`, applies the current
/// category selection to the live `MultiCategoryDb`, and stores the path
/// in the scheduler slot. Does NOT spawn the refresh task: call
/// `dns_start_blocklist_scheduler` after the host's NetworkReadySignal
/// releases. Idempotent. Returns 1 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn dns_configure_blocklist(settings_path: *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if settings_path.is_null() {
            return -1;
        }
        let s = match unsafe { CStr::from_ptr(settings_path) }.to_str() {
            Ok(v) => v,
            Err(e) => {
                log::error!("dns_configure_blocklist: invalid settings path: {}", e);
                return -1;
            }
        };
        match blocklist_scheduler::configure(std::path::Path::new(s)) {
            Ok(()) => 1,
            Err(e) => {
                log::error!("blocklist scheduler configure: {}", e);
                -1
            }
        }
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_configure_blocklist: panic");
        -1
    })
}

/// Spawns the blocklist refresh task on the resolver's Tokio runtime. Must
/// be called after `dns_configure_blocklist`. Runs one boot refresh
/// immediately, then ticks every hour. Idempotent: a second call is a no-op
/// once the task runs. The Swift agent defers this call until
/// `NetworkReadySignal` releases so the boot refresh doesn't race
/// Content-Filter activation, which kills in-flight reqwest connections and
/// forces a 60s timeout. Returns 1 on success, -1 on error.
#[no_mangle]
pub extern "C" fn dns_start_blocklist_scheduler() -> c_int {
    catch_unwind(AssertUnwindSafe(|| match blocklist_scheduler::start() {
        Ok(()) => 1,
        Err(e) => {
            log::error!(
                "blocklist scheduler not started, periodic refresh is off: {}",
                e
            );
            -1
        }
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_start_blocklist_scheduler: panic");
        -1
    })
}

/// Registers a host callback invoked after a periodic blocklist refresh
/// completes successfully. Manual force updates are acknowledged through
/// the synchronous FFI return path. This callback lets Swift persist
/// `last_updated` after a background refresh without Rust rewriting
/// `blocklist_settings.json`.
#[no_mangle]
pub extern "C" fn dns_set_blocklist_refresh_callback(cb: blocklist_scheduler::RefreshCallback) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        blocklist_scheduler::set_refresh_callback(cb)
    }))
    .map_err(|_| log::error!("dns_set_blocklist_refresh_callback: panic"));
}

/// Runs an immediate blocklist refresh and blocks the caller until every
/// category finished. The result is about the lists the user selected. A
/// failure in any other list is only logged. Returns 1 when they were all
/// refreshed and at least one file changed and was published, 0 when they were
/// all refreshed and nothing changed, 2 when they are all loaded but at least
/// one could not be refreshed and keeps its previous database, and -1 when one
/// of them is not loaded or on error (scheduler unconfigured, panic).
#[no_mangle]
pub extern "C" fn dns_force_blocklist_update_status() -> c_int {
    catch_unwind(AssertUnwindSafe(
        || match blocklist_scheduler::force_update() {
            Ok(blocklist_scheduler::ForcedRefresh::Refreshed { changed: true }) => 1,
            Ok(blocklist_scheduler::ForcedRefresh::Refreshed { changed: false }) => 0,
            Ok(blocklist_scheduler::ForcedRefresh::LoadedStale) => 2,
            Err(e) => {
                log::error!("blocklist scheduler force_update: {}", e);
                -1
            }
        },
    ))
    .unwrap_or_else(|_| {
        log::error!("dns_force_blocklist_update_status: panic");
        -1
    })
}

/// # Safety
/// `path` must be a valid, NUL-terminated UTF-8 C string for the call
/// duration. Stashes the allowlist LMDB path so later list/add/remove FFI
/// calls can open it lazily. Does NOT open the env, because the resolver may
/// still be stopped when the UI reads or writes the allowlist.
#[no_mangle]
pub unsafe extern "C" fn dns_allowlist_set_path(path: *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if path.is_null() {
            return -1;
        }
        let s = match unsafe { CStr::from_ptr(path) }.to_str() {
            Ok(v) => v,
            Err(e) => {
                log::error!("dns_allowlist_set_path: invalid path: {}", e);
                return -1;
            }
        };
        blocklist::set_allowlist_path(std::path::Path::new(s));
        1
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_allowlist_set_path: panic");
        -1
    })
}

/// Returns a heap-allocated NUL-terminated JSON array of allowlisted
/// domains (`["a.com","b.com"]`). The caller owns the pointer and must
/// release it through `dns_allowlist_free_json`. Returns NULL on any error,
/// which the caller treats as an empty list.
#[no_mangle]
pub extern "C" fn dns_allowlist_list() -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| -> Option<CString> {
        let db = match blocklist::get_or_open_allowlist() {
            Ok(Some(db)) => db,
            Ok(None) => {
                log::warn!("dns_allowlist_list: path not configured");
                return None;
            }
            Err(e) => {
                log::error!("dns_allowlist_list: {}", e);
                return None;
            }
        };
        let domains = match db.list_domains() {
            Ok(v) => v,
            Err(e) => {
                log::error!("dns_allowlist_list: {}", e);
                return None;
            }
        };
        let json = match serde_json::to_string(&domains) {
            Ok(s) => s,
            Err(e) => {
                log::error!("dns_allowlist_list: json {}", e);
                return None;
            }
        };
        CString::new(json).ok()
    }));
    match result {
        Ok(Some(cs)) => cs.into_raw(),
        Ok(None) => std::ptr::null_mut(),
        Err(_) => {
            log::error!("dns_allowlist_list: panic");
            std::ptr::null_mut()
        }
    }
}

/// Copies `message` into a caller-owned buffer as a NUL-terminated C string,
/// truncated on a character boundary when it does not fit.
///
/// # Safety
/// `buf` must be either NULL or point to `len` writable bytes.
unsafe fn write_caller_buffer(buf: *mut c_char, len: usize, message: &str) {
    if buf.is_null() || len == 0 {
        return;
    }
    let mut end = message.len().min(len - 1);
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    // SAFETY: caller contract guarantees `len` writable bytes and `end < len`.
    unsafe {
        std::ptr::copy_nonoverlapping(message.as_ptr(), buf.cast::<u8>(), end);
        *buf.add(end) = 0;
    }
}

/// # Safety
/// `json` must satisfy the `dns_apply_policy_snapshot` contract. `error_buf`
/// must be either NULL or point to `error_len` writable bytes. On rejection it
/// receives a NUL-terminated message naming the offending entry, truncated to
/// fit. Nothing is allocated on the Rust side for the caller, so there is no
/// matching free function.
///
/// Same atomic whole-snapshot semantics as `dns_apply_policy_snapshot`: the
/// candidate policy is built and validated before anything live changes, and a
/// rejected entry leaves the previous policy fully active. Returns 1 on
/// success, 0 on invalid input, build failure, missing runtime state, or panic.
#[no_mangle]
pub unsafe extern "C" fn dns_apply_policy_snapshot(
    json: *const c_char,
    error_buf: *mut c_char,
    error_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        // The message reaches the host through `error_buf`, which logs it
        // with the consequence.
        let report = |message: String| {
            // SAFETY: caller contract guarantees `error_len` writable bytes.
            unsafe { write_caller_buffer(error_buf, error_len, &message) };
            0
        };

        let Some(raw) = (unsafe { cstr_to_string(json) }) else {
            return report("invalid input".into());
        };
        let dto: crate::policy::PolicySnapshotDto = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => return report(format!("invalid json: {e}")),
        };
        // The build error already identifies the offending entry, and it leads
        // the message so a truncated buffer still names it.
        let candidate = match crate::policy::build_snapshot(&dto) {
            Ok(v) => v,
            Err(e) => return report(e),
        };
        let _lifecycle = lifecycle_lock();
        let Some(state) = get_state() else {
            return report("resolver not initialized".into());
        };
        state.policy.store(std::sync::Arc::new(candidate));
        1
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_apply_policy_snapshot: panic");
        0
    })
}

/// # Safety
/// `json` must be a valid, NUL-terminated UTF-8 C string holding a JSON array
/// of `{"domain":..,"forwardIP":..}` records for the call duration.
///
/// Replaces the routes discovered from the attached network's DHCP search
/// domains as one table. An empty array clears them. These routes are
/// runtime-derived and never persisted to `state.json`. Records outside the
/// private-use suffixes are dropped by the resolver, so a hostile search-domain
/// list cannot capture a public namespace. Returns 1 on success, 0 on invalid
/// input, missing runtime state, or panic.
#[no_mangle]
pub unsafe extern "C" fn dns_apply_ephemeral_routes(json: *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(raw) = (unsafe { cstr_to_string(json) }) else {
            log::error!("dns_apply_ephemeral_routes: invalid input");
            return 0;
        };
        let records: Vec<crate::policy::EphemeralRouteRecord> = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                log::error!("dns_apply_ephemeral_routes: invalid json: {}", e);
                return 0;
            }
        };
        let candidate = crate::policy::build_ephemeral_routes(&records);
        let _lifecycle = lifecycle_lock();
        let Some(state) = get_state() else {
            log::error!("dns_apply_ephemeral_routes: resolver not initialized");
            return 0;
        };
        state
            .ephemeral_zones
            .store(std::sync::Arc::new(std::sync::Arc::new(candidate)));
        1
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_apply_ephemeral_routes: panic");
        0
    })
}

/// # Safety
/// `json` must be a valid, NUL-terminated UTF-8 C string valid for the call
/// duration, holding the attached network's facts:
/// `{"ipv4":bool,"ipv6":bool,"interface":"en0","interfaceIndex":11,
/// "resolvers":["172.20.10.1","fe80::1"]}`. `resolvers` are the primary
/// service's own DNS servers, never a VPN or system-wide override.
///
/// Starts a new network generation: NAT64 synthesis stops at once and resumes
/// only after RFC 7050 discovery against these resolvers finds a prefix. The
/// host calls this on service start, on every network configuration change,
/// and on wake. A rejected snapshot still ends the current generation, so the
/// previous network's prefix never outlives it. Returns 1 on success, 0 on
/// invalid input, missing runtime state, or panic.
#[no_mangle]
pub unsafe extern "C" fn dns_apply_network_snapshot(json: *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = {
            let _lifecycle = lifecycle_lock();
            get_state()
        };
        let Some(state) = state else {
            log::error!("dns_apply_network_snapshot: resolver not initialized");
            return 0;
        };
        // A refused snapshot still means the host moved on, so the previous
        // network's prefix must not survive it.
        let parsed = match unsafe { cstr_to_string(json) } {
            Some(raw) => crate::network_profile::NetworkSnapshot::from_json(&raw),
            None => Err("invalid input".to_string()),
        };
        let snapshot = match parsed {
            Ok(snapshot) => snapshot,
            Err(e) => {
                state.network.invalidate();
                log::error!(
                    "dns_apply_network_snapshot: {}; NAT64 synthesis off until the next valid snapshot",
                    e
                );
                return 0;
            }
        };
        match crate::network_profile::apply_snapshot(&state.network, snapshot) {
            Ok(()) => 1,
            Err(e) => {
                log::error!("dns_apply_network_snapshot: discovery not started: {}", e);
                0
            }
        }
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_apply_network_snapshot: panic");
        0
    })
}

/// # Safety
/// `domains_json` must be a valid, NUL-terminated UTF-8 C string holding a
/// JSON array of domain strings, valid for the call duration. Every domain is
/// validated before any write begins, and the replacement commits in a single
/// LMDB transaction, so the allowlist is never partially applied. Returns 1
/// on success, -1 on any error (path not set, invalid JSON, invalid domain,
/// LMDB failure, panic).
#[no_mangle]
pub unsafe extern "C" fn dns_allowlist_replace_json(domains_json: *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if domains_json.is_null() {
            return -1;
        }
        let s = match unsafe { CStr::from_ptr(domains_json) }.to_str() {
            Ok(v) => v,
            Err(e) => {
                log::error!("dns_allowlist_replace_json: {}", e);
                return -1;
            }
        };
        let raw: Vec<String> = match serde_json::from_str(s) {
            Ok(v) => v,
            Err(e) => {
                log::error!("dns_allowlist_replace_json: invalid json: {}", e);
                return -1;
            }
        };

        // Validate the complete set before opening a write transaction so a
        // malformed entry can never leave a partially replaced allowlist.
        let mut names = Vec::with_capacity(raw.len());
        for domain in &raw {
            match DomainName::new(domain) {
                Ok(n) => names.push(n),
                Err(e) => {
                    log::warn!(
                        "dns_allowlist_replace_json: invalid domain {:?}: {}",
                        domain,
                        e
                    );
                    return -1;
                }
            }
        }

        let db = match blocklist::get_or_open_allowlist() {
            Ok(Some(db)) => db,
            Ok(None) => {
                log::error!("dns_allowlist_replace_json: path not configured");
                return -1;
            }
            Err(e) => {
                log::error!("dns_allowlist_replace_json: {}", e);
                return -1;
            }
        };

        match db.replace_domains(&names) {
            Ok(()) => 1,
            Err(e) => {
                log::error!("dns_allowlist_replace_json: {}", e);
                -1
            }
        }
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_allowlist_replace_json: panic");
        -1
    })
}

/// # Safety
/// `domain` must be a valid, NUL-terminated UTF-8 C string for the call
/// duration. Adds a single domain to the allowlist LMDB. Returns 1 on
/// success, -1 on any error (path not set, invalid domain, LMDB failure,
/// panic).
#[no_mangle]
pub unsafe extern "C" fn dns_allowlist_add(domain: *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if domain.is_null() {
            return -1;
        }
        let s = match unsafe { CStr::from_ptr(domain) }.to_str() {
            Ok(v) => v,
            Err(e) => {
                log::error!("dns_allowlist_add: {}", e);
                return -1;
            }
        };
        let db = match blocklist::get_or_open_allowlist() {
            Ok(Some(db)) => db,
            Ok(None) => {
                log::error!("dns_allowlist_add: path not configured");
                return -1;
            }
            Err(e) => {
                log::error!("dns_allowlist_add: {}", e);
                return -1;
            }
        };
        let name = match DomainName::new(s) {
            Ok(n) => n,
            Err(e) => {
                log::warn!("dns_allowlist_add: invalid domain {:?}: {}", s, e);
                return -1;
            }
        };
        match db.add_domain(&name) {
            Ok(()) => 1,
            Err(e) => {
                log::error!("dns_allowlist_add: {}", e);
                -1
            }
        }
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_allowlist_add: panic");
        -1
    })
}

/// # Safety
/// `domain` must be a valid, NUL-terminated UTF-8 C string for the call
/// duration. Removes a single domain from the allowlist LMDB. Returns 1 when
/// the domain was removed or the env is empty (remove is idempotent for the
/// caller), -1 on error.
#[no_mangle]
pub unsafe extern "C" fn dns_allowlist_remove(domain: *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if domain.is_null() {
            return -1;
        }
        let s = match unsafe { CStr::from_ptr(domain) }.to_str() {
            Ok(v) => v,
            Err(_) => return -1,
        };
        let db = match blocklist::get_or_open_allowlist() {
            Ok(Some(db)) => db,
            Ok(None) => {
                log::error!("dns_allowlist_remove: path not configured");
                return -1;
            }
            Err(_) => return -1,
        };
        let name = match DomainName::new(s) {
            Ok(n) => n,
            Err(e) => {
                log::warn!("dns_allowlist_remove: invalid domain {:?}: {}", s, e);
                return -1;
            }
        };
        match db.remove_domain(&name) {
            Ok(_) => 1,
            Err(e) => {
                log::error!("dns_allowlist_remove: {}", e);
                -1
            }
        }
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_allowlist_remove: panic");
        -1
    })
}

/// # Safety
/// `ptr` must be either NULL or a pointer previously returned by
/// `dns_allowlist_list`. Passing any other value is undefined behaviour.
/// Reclaims the CString heap buffer handed to the Swift side.
#[no_mangle]
pub unsafe extern "C" fn dns_allowlist_free_json(ptr: *mut c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() {
            return;
        }
        // SAFETY: caller contract guarantees ptr came from `CString::into_raw`.
        let _ = unsafe { CString::from_raw(ptr) };
    }))
    .map_err(|_| log::error!("dns_allowlist_free_json: panic"));
}

/// Register a callback invoked on every blocked query.
#[no_mangle]
pub extern "C" fn dns_set_blocked_callback(cb: blocklist::BlockedCallback) {
    let _ = catch_unwind(AssertUnwindSafe(|| blocklist::set_blocked_callback(cb)))
        .map_err(|_| log::error!("dns_set_blocked_callback: panic"));
}

/// Routes Rust `log::{error,warn,info}!` lines into the hosting process.
/// Without this the dylib's stderr is discarded by launchd (no
/// `StandardErrorPath` in the LaunchAgent plist), making hickory and our own
/// warn/error output invisible and leaving SERVFAIL investigations blind.
/// It installs the logger and the panic hook too, so calls made before
/// `dns_init`, such as the lookup history set up at agent launch, log as well.
/// Returns 1 on success, 0 on panic. The host logs the failure so a silent
/// downgrade to stderr-only output does not go unnoticed.
#[no_mangle]
pub extern "C" fn dns_set_log_callback(cb: log_hooks::LogCallback) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        log_hooks::set_log_callback(cb);
        install_ffi_logger();
        log_hooks::install_panic_hook();
    }))
    .map(|_| 1)
    .unwrap_or_else(|_| {
        log::error!("dns_set_log_callback: panic");
        0
    })
}

struct FfiLogger;

impl log::Log for FfiLogger {
    /// Foreign Debug/Trace is too noisy for os.log. The transport tracing
    /// subscriber forwards only selected h2 lifecycle evidence at Info.
    fn enabled(&self, m: &log::Metadata) -> bool {
        if matches!(
            m.level(),
            log::Level::Error | log::Level::Warn | log::Level::Info
        ) {
            return true;
        }
        let t = m.target();
        t.starts_with("macdns_resolver") || t.starts_with("macdns")
    }

    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let msg = format!("{}", r.args());
        log_hooks::emit_log(r.level(), r.target(), &msg);
    }

    fn flush(&self) {}
}

static FFI_LOGGER: FfiLogger = FfiLogger;

fn install_ffi_logger() {
    // `set_logger` succeeds only once per process. Later `dns_init` calls are
    // no-ops.
    if log::set_logger(&FFI_LOGGER).is_ok() {
        log::set_max_level(log::LevelFilter::Debug);
    }
    provider_transport_trace::install();
}

/// Registers a callback invoked on every accepted query when
/// `log_queries` is enabled. The callback runs on the listener task
/// thread, so it must be cheap and non-blocking.
#[no_mangle]
pub extern "C" fn dns_set_query_callback(cb: log_hooks::QueryCallback) {
    let _ = catch_unwind(AssertUnwindSafe(|| log_hooks::set_query_callback(cb)))
        .map_err(|_| log::error!("dns_set_query_callback: panic"));
}

/// Registers a callback invoked on every outbound reply when
/// `log_replies` is enabled. Same latency contract as the query callback.
#[no_mangle]
pub extern "C" fn dns_set_reply_callback(cb: log_hooks::ReplyCallback) {
    let _ = catch_unwind(AssertUnwindSafe(|| log_hooks::set_reply_callback(cb)))
        .map_err(|_| log::error!("dns_set_reply_callback: panic"));
}

/// Registers a callback invoked on every SERVFAIL emitted by the proxy. The
/// host routes these to a dedicated os.log subsystem so operators can page on
/// real upstream outages without drowning in benign noise.
#[no_mangle]
pub extern "C" fn dns_set_servfail_callback(cb: log_hooks::ServfailCallback) {
    let _ = catch_unwind(AssertUnwindSafe(|| log_hooks::set_servfail_callback(cb)))
        .map_err(|_| log::error!("dns_set_servfail_callback: panic"));
}

pub(crate) fn parse_override(qtype: &str, value: &str) -> Result<(RecordType, RData), String> {
    match qtype {
        "A" => {
            let ip: IpAddr = value
                .parse()
                .map_err(|e: std::net::AddrParseError| e.to_string())?;
            if let IpAddr::V4(v4) = ip {
                Ok((RecordType::A, RData::A(A(v4))))
            } else {
                Err("not v4".into())
            }
        }
        "AAAA" => {
            let ip: IpAddr = value
                .parse()
                .map_err(|e: std::net::AddrParseError| e.to_string())?;
            if let IpAddr::V6(v6) = ip {
                Ok((RecordType::AAAA, RData::AAAA(AAAA(v6))))
            } else {
                Err("not v6".into())
            }
        }
        "CNAME" => {
            let name = hickory_proto::rr::Name::from_str(value).map_err(|e| e.to_string())?;
            Ok((RecordType::CNAME, RData::CNAME(CNAME(name))))
        }
        "PTR" => {
            let name = hickory_proto::rr::Name::from_str(value).map_err(|e| e.to_string())?;
            Ok((RecordType::PTR, RData::PTR(PTR(name))))
        }
        "NS" => {
            let name = hickory_proto::rr::Name::from_str(value).map_err(|e| e.to_string())?;
            Ok((RecordType::NS, RData::NS(NS(name))))
        }
        "MX" => {
            let parts: Vec<&str> = value.split_whitespace().collect();
            let (pref, host) = match parts.as_slice() {
                [host] => (10, *host),
                [pref, host] => (
                    pref.parse()
                        .map_err(|e: std::num::ParseIntError| e.to_string())?,
                    *host,
                ),
                _ => return Err("MX: [priority] hostname".into()),
            };
            let name = hickory_proto::rr::Name::from_str(host).map_err(|e| e.to_string())?;
            Ok((RecordType::MX, RData::MX(MX::new(pref, name))))
        }
        "TXT" => {
            if value.len() > 255 {
                return Err("TXT value exceeds 255 UTF-8 bytes".into());
            }
            Ok((
                RecordType::TXT,
                RData::TXT(TXT::new(vec![value.to_string()])),
            ))
        }
        // SRV owner names require underscore labels (`_sip._tcp.example.com`),
        // which `domain_name::canonicalize` and the App both reject, so an SRV
        // override can never be addressed. Rejected explicitly to keep the
        // generic fallback below from re-enabling an unusable record type.
        "SRV" => Err("SRV overrides are not supported".into()),
        "CAA" => {
            // Presentation format "<flags> <tag> <value>", with a tag such as
            // issue, issuewild or iodef. Parsed through hickory's zonefile path
            // because CAA is `#[non_exhaustive]` with no generic public ctor.
            let parts: Vec<&str> = value.splitn(3, ' ').collect();
            if parts.len() != 3 {
                return Err("CAA: flags tag value".into());
            }
            let _flags: u8 = parts[0]
                .parse()
                .map_err(|e: std::num::ParseIntError| e.to_string())?;
            let rdata = RData::try_from_str(RecordType::CAA, value).map_err(|e| e.to_string())?;
            Ok((RecordType::CAA, rdata))
        }
        other => {
            // Every other type hickory knows (HTTPS, SVCB, TLSA, SSHFP, NAPTR,
            // LOC, DS, DNSKEY, NSEC, NSEC3, RRSIG, DNAME, HINFO and more) goes
            // through its zonefile presentation parser instead of a hand-rolled
            // format.
            let rtype = RecordType::from_str(other)
                .map_err(|e| format!("unsupported qtype {:?}: {}", other, e))?;
            let rdata = RData::try_from_str(rtype, value)
                .map_err(|e| format!("parse {} value {:?}: {}", other, value, e))?;
            Ok((rtype, rdata))
        }
    }
}

/// Publishes a forwarding transition. The value lands before the counter, which
/// rules out the one unsafe pairing: a new generation next to the previous
/// forward. The opposite skew stays reachable: a reader that samples the value
/// before this writer and the counter after it sees the new forward with the old
/// generation. That is safe because `PolicyGeneration` pins the forward `Arc`
/// itself and rejects on identity, not on the counter alone. Headroom is checked
/// before anything is published, so a forward the exhausted counter refuses is
/// never installed.
///
/// The load/store pair replaces a `fetch_update` because it must bracket the
/// value write. That is sound only because every mutation of
/// `forward_generation` happens under the lifecycle lock, which every caller
/// already holds.
fn publish_forward_transition(state: &ModuleState, forward: Option<Arc<ForwardResolver>>) -> bool {
    let Some(next_generation) = state
        .forward_generation
        .load(Ordering::Acquire)
        .checked_add(1)
    else {
        return false;
    };
    state.forward.store(Arc::new(forward));
    state
        .forward_generation
        .store(next_generation, Ordering::Release);
    true
}

fn publish_forward_rebuild_if_current(
    state: &ModuleState,
    expected_generation: u64,
    rebuilt: ForwardResolver,
) -> bool {
    let _lifecycle = lifecycle_lock();
    if state.forward_generation.load(Ordering::Acquire) != expected_generation {
        return false;
    }
    state.forward.store(Arc::new(Some(Arc::new(rebuilt))));
    true
}

#[no_mangle]
pub extern "C" fn dns_probe_recursive_resolution() -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(state) = get_state() else { return 0 };
        match block_on(
            async move { crate::query::probe_recursive_resolution(state.as_ref()).await },
        ) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(error) => {
                log::warn!("recursive resolution probe failed: {}", error);
                0
            }
        }
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_probe_recursive_resolution: panic");
        0
    })
}

/// Defense-in-depth ceiling on the array size the forwarding FFI will
/// dereference. The Swift host sends a handful of resolvers, but a buggy or
/// hostile caller passing `i32::MAX` with a smaller array would otherwise tip
/// `slice::from_raw_parts` into UB.
const MAX_FORWARDING_SERVERS: usize = 64;

/// Reads the C server array shared by the forwarding entrypoints. Rejects
/// rather than truncates an out-of-range count: truncating would still read
/// `MAX_FORWARDING_SERVERS` entries from an array that may be far smaller.
///
/// # Safety
/// `servers` must point to a valid array of `count` null-terminated UTF-8 C strings.
unsafe fn read_forwarding_servers(
    entrypoint: &str,
    servers: *const *const c_char,
    count: c_int,
) -> Option<Vec<String>> {
    if count <= 0 {
        log::warn!("{entrypoint}: empty server list");
        return None;
    }
    if servers.is_null() {
        log::warn!("{entrypoint}: null servers pointer");
        return None;
    }
    let Ok(count) = usize::try_from(count) else {
        log::warn!("{entrypoint}: invalid server count");
        return None;
    };
    if count > MAX_FORWARDING_SERVERS {
        log::error!(
            "{entrypoint}: count {count} exceeds cap {MAX_FORWARDING_SERVERS}; rejecting (caller must trim array)"
        );
        return None;
    }
    let server_ptrs = unsafe { std::slice::from_raw_parts(servers, count) };
    let mut parsed = Vec::with_capacity(count);
    for &ptr in server_ptrs {
        if ptr.is_null() {
            continue;
        }
        if let Ok(server) = unsafe { CStr::from_ptr(ptr) }.to_str() {
            parsed.push(server.to_string());
        }
    }
    Some(parsed)
}

/// Returns 1 only when one of `servers` answers a fresh query, 0 otherwise.
/// Captive detection calls it before moving public DNS onto the network's
/// resolvers, so an outage that also takes those resolvers down keeps the
/// public path. It never changes live forwarding state.
///
/// # Safety
/// `servers` must point to a valid array of `count` null-terminated UTF-8 C strings.
#[no_mangle]
pub unsafe extern "C" fn dns_probe_network_dns(
    servers: *const *const c_char,
    count: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(servers) =
            (unsafe { read_forwarding_servers("dns_probe_network_dns", servers, count) })
        else {
            return 0;
        };
        if get_state().is_none() {
            return 0;
        }
        let started = std::time::Instant::now();
        let probed = servers.clone();
        match block_on(async move { crate::forward::probe_network_dns(&probed).await }) {
            Ok(Ok(())) => 1,
            Ok(Err(failure)) => {
                log::warn!(
                    "health-probe kind=network-dns servers={} failure={} duration_ms={}",
                    servers.join(","),
                    failure,
                    started.elapsed().as_millis()
                );
                0
            }
            Err(error) => {
                log::warn!("network DNS probe failed: {}", error);
                0
            }
        }
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_probe_network_dns: panic");
        0
    })
}

/// # Safety
/// `servers` must point to a valid array of `count` null-terminated UTF-8 C strings.
#[no_mangle]
pub unsafe extern "C" fn dns_enable_forwarding(
    servers: *const *const c_char,
    count: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let _lifecycle = lifecycle_lock();
        let Some(v) = (unsafe { read_forwarding_servers("dns_enable_forwarding", servers, count) })
        else {
            return 0;
        };
        let Some(state) = get_state() else {
            return 0;
        };
        match ForwardResolver::new(&v) {
            Ok(r) => {
                if !publish_forward_transition(state.as_ref(), Some(Arc::new(r))) {
                    log::error!("forwarding generation exhausted; enable rejected");
                    return 0;
                }
                log::debug!("forwarding enabled: {:?}", v);
                1
            }
            Err(e) => {
                log::error!("forwarding: {}", e);
                0
            }
        }
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_enable_forwarding: panic");
        0
    })
}

#[no_mangle]
pub extern "C" fn dns_disable_forwarding() -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let _lifecycle = lifecycle_lock();
        let Some(state) = get_state() else { return 0 };
        if !publish_forward_transition(state.as_ref(), None) {
            log::error!("forwarding generation exhausted; disable rejected");
            return 0;
        }
        log::debug!("forwarding disabled");
        1
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_disable_forwarding: panic");
        0
    })
}

#[no_mangle]
pub extern "C" fn dns_flush_cache() {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // Clear synchronously so callers see an empty cache when this returns.
        // An async clear would race the `dns_snapshot_cache` that
        // MaintenanceManager calls right after a flush, and the snapshot could
        // write mid-clear entries back to disk.
        //
        // The blocking clear can outlive its session, so the session is
        // captured up front: the flush touches only the state it was admitted
        // against, and the dump removal revalidates the generation.
        let (session_generation, state) = capture_session();
        if let Some(s) = state {
            clear_live_cache_sync(&s, "cache flush");
        }
        // Flush is sticky across restarts. Without removing the dump, the next
        // `dns_init` would restore the entries the user just evicted.
        remove_cache_dump_for_session(session_generation, "cache flush");
    }))
    .map_err(|_| log::error!("dns_flush_cache: panic"));
}

/// # Safety
/// `path` must be a valid, NUL-terminated UTF-8 C string for the call duration.
///
/// Configures the on-disk path for cache snapshots. Must be called BEFORE
/// `dns_init` for the initial restore to fire, and kept set through
/// `dns_shutdown` so the snapshot lands in the same location. Passing a
/// NULL pointer clears the path (disables persistence entirely).
#[no_mangle]
pub unsafe extern "C" fn dns_set_cache_path(path: *const c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if path.is_null() {
            cache_path_slot().store(None);
            return;
        }
        let Ok(s) = unsafe { CStr::from_ptr(path) }.to_str() else {
            return;
        };
        let buf = PathBuf::from(s);
        cache_path_slot().store(Some(Arc::new(buf)));
    }))
    .map_err(|_| log::error!("dns_set_cache_path: panic"));
}

/// # Safety
/// `path` must be NULL or a valid, NUL-terminated C string for the call
/// duration.
///
/// Sets the location of the lookup history database. Called before
/// `dns_init`, like `dns_set_cache_path`. The store picks it up on the next
/// `dns_configure_history`. A NULL or non-UTF-8 path is rejected and logged,
/// and the previous path stays.
#[no_mangle]
pub unsafe extern "C" fn dns_set_history_path(path: *const c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(path) = (unsafe { cstr_to_string(path) }) else {
            log::error!("dns_set_history_path: path is NULL or not UTF-8");
            return;
        };
        *HISTORY_PATH.lock().unwrap_or_else(|p| p.into_inner()) = Some(PathBuf::from(path));
    }))
    .map_err(|_| log::error!("dns_set_history_path: panic"));
}

/// Applies the lookup history settings live. `retention_days` is one of 7,
/// 14, 30 or 90, `popular_count` one of 0, 100, 250, 500, 1000 or 2000, and
/// `popular_days` one of 1, 7, 14 or 30, never longer than the retention.
/// Turning history off stops recording and keeps the database.
/// `dns_history_clear` is what deletes it.
///
/// Returns 1 as soon as the writer has the settings, without waiting for it.
/// Returns 0 when a value is outside its allowed set, when the writer is
/// gone, or on panic. Except after a panic, a 0 leaves the previous settings
/// in effect.
#[no_mangle]
pub extern "C" fn dns_configure_history(
    enabled: c_int,
    retention_days: c_int,
    popular_count: c_int,
    popular_days: c_int,
) -> c_int {
    catch_ffi_panic("dns_configure_history", || {
        let (Ok(retention_days), Ok(popular_count), Ok(popular_days)) = (
            u32::try_from(retention_days),
            u32::try_from(popular_count),
            u32::try_from(popular_days),
        ) else {
            log::error!(
                "lookup history settings rejected: negative value (retention {}, popular {} over {} days)",
                retention_days,
                popular_count,
                popular_days
            );
            return 0;
        };
        let path = HISTORY_PATH
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        match history::configure(
            path,
            enabled != 0,
            retention_days,
            popular_count,
            popular_days,
        ) {
            Ok(()) => 1,
            Err(e) => {
                log::error!("lookup history settings rejected: {}", e);
                0
            }
        }
    })
}

/// Answers one lookup history request (the JSON contract decoded by
/// `Sources/Shared/QueryHistory.swift`). The caller owns the returned string
/// and must release it through `dns_history_free_json`. A NULL or non-UTF-8 request gets a
/// `{"status":"error"}` answer. NULL is returned only on panic.
///
/// # Safety
/// `request` must be NULL or a valid, NUL-terminated C string for the call
/// duration.
#[no_mangle]
pub unsafe extern "C" fn dns_history_query(request: *const c_char) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| -> Option<CString> {
        let answer = match unsafe { cstr_to_string(request) } {
            Some(request) => history::query(&request, live_cache_stats_for(&request)),
            None => serde_json::json!({
                "status": "error",
                "reason": "request is NULL or not UTF-8",
            })
            .to_string(),
        };
        CString::new(answer).ok()
    }));
    match result {
        Ok(Some(answer)) => answer.into_raw(),
        Ok(None) => {
            log::error!("dns_history_query: answer contains a NUL byte");
            std::ptr::null_mut()
        }
        Err(_) => {
            log::error!("dns_history_query: panic");
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// `ptr` must be either NULL or a pointer previously returned by
/// `dns_history_query`. Passing any other value is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn dns_history_free_json(ptr: *mut c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() {
            return;
        }
        // SAFETY: caller contract guarantees ptr came from `CString::into_raw`.
        let _ = unsafe { CString::from_raw(ptr) };
    }))
    .map_err(|_| log::error!("dns_history_free_json: panic"));
}

/// Deletes every stored lookup: pending events, the database file and its
/// `-wal`/`-shm` sidecars, then, while history is on, recreates an empty
/// database. Works while history is off too. Waits up to 5 s
/// for the writer. Returns 1 when done, 0 when no store is configured yet
/// (`dns_configure_history` never ran with a path), it failed, timed out or
/// panicked.
#[no_mangle]
pub extern "C" fn dns_history_clear() -> c_int {
    catch_ffi_panic("dns_history_clear", || c_int::from(history::clear()))
}

/// The live cache figures a `summary` needs. Other kinds never read them, and
/// a stopped resolver has no cache, so both answer zeros with prefetch off.
fn live_cache_stats_for(request: &str) -> history::LiveCacheStats {
    #[derive(serde::Deserialize)]
    struct Kind {
        kind: String,
    }
    let is_summary = serde_json::from_str::<Kind>(request).is_ok_and(|r| r.kind == "summary");
    match get_state() {
        Some(state) if is_summary => history::LiveCacheStats {
            prefetching: config::current().prefetch,
            ..live_cache_stats(&state.cache, &history::popular(), std::time::Instant::now())
        },
        _ => history::LiveCacheStats::default(),
    }
}

/// Counts the popular keys with a fresh cache entry and sums one refresh per
/// original TTL over them. Iterates the cache without `get`, so reading the
/// figures never marks an entry used.
fn live_cache_stats(
    cache: &DnsCache,
    popular: &std::collections::HashSet<cache::CacheKey>,
    now: std::time::Instant,
) -> history::LiveCacheStats {
    let mut stats = history::LiveCacheStats::default();
    if popular.is_empty() {
        return stats;
    }
    for (key, entry) in cache.iter() {
        if entry.expires_at <= now || !popular.contains(key.as_ref()) {
            continue;
        }
        stats.in_cache += 1;
        if entry.original_ttl_secs > 0 {
            stats.refreshes_per_second += 1.0 / f64::from(entry.original_ttl_secs);
        }
    }
    stats
}

/// Writes the live cache to the configured dump path without tearing the
/// runtime down. Called hourly so a SIGKILL, panic or kernel OOM loses at most
/// one hour of warm-cache work instead of the whole session.
///
/// Returns the number of entries written, saturated at `c_int::MAX`. Returns
/// -1 when persistence is disabled (no path configured), state is not
/// initialized, a newer cache generation superseded the dump, or the snapshot
/// failed (already logged). Returns -2 when the write outlived
/// `PERIODIC_SNAPSHOT_TIMEOUT`, and -3 when a previous writer is still running
/// and this call was coalesced into it. Safe to call on any thread: it bridges
/// onto the Tokio runtime through `block_on`, like the `dns_shutdown` snapshot.
#[no_mangle]
pub extern "C" fn dns_snapshot_cache() -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(path) = current_cache_path() else {
            return -1;
        };
        let Some(state) = get_state() else {
            return -1;
        };
        // Single-flight: the host's own guard releases when this call returns,
        // which after a timeout is long before the abandoned write finishes.
        let Some(writer) = SnapshotWriterGuard::try_acquire() else {
            log::info!("resolver cache snapshot already running; this call was coalesced into it");
            return SNAPSHOT_BUSY;
        };
        let cache = state.cache.clone();
        let path_buf = path.as_ref().clone();
        let epoch = CACHE_SNAPSHOT_EPOCH.load(Ordering::Acquire);
        snapshot_with_deadline(PERIODIC_SNAPSHOT_TIMEOUT, async move {
            // Drain moka's write queue first so the snapshot iterator sees
            // the logical cache state.
            cache.flush_pending().await;
            tokio::task::spawn_blocking(move || {
                // Ownership is released only when the write really ends, not
                // when the deadline above gives up on it.
                let _writer = writer;
                snapshot_cache_blocking(cache, path_buf, "dump.tmp".into(), epoch)
            })
            .await
        })
    }))
    .unwrap_or_else(|_| {
        log::error!("dns_snapshot_cache: panic");
        -1
    })
}

/// Runs one periodic snapshot attempt under `deadline` and maps it onto the
/// FFI return code.
///
/// The deadline bounds only the *wait*: an abandoned write keeps running on the
/// blocking pool and still publishes through the epoch check in
/// `snapshot_cache_blocking`, exactly like the shutdown path. Without it the
/// caller thread stays pinned for as long as iteration, serialization, gzip and
/// fsync of a 200 MB cache take.
fn snapshot_with_deadline<F>(deadline: Duration, work: F) -> c_int
where
    F: std::future::Future<Output = SnapshotAttempt> + Send + 'static,
{
    match block_on(async move { tokio::time::timeout(deadline, work).await }) {
        Ok(Ok(Ok(Ok(Some(n))))) => {
            log::info!("resolver cache snapshot wrote {} entries (periodic)", n);
            snapshot_count_to_c_int(n)
        }
        Ok(Ok(Ok(Ok(None)))) => {
            log::info!("resolver cache snapshot skipped because cache generation changed");
            -1
        }
        Ok(Ok(Ok(Err(e)))) => {
            log::warn!("resolver cache snapshot failed (periodic): {}", e);
            -1
        }
        Ok(Ok(Err(e))) => {
            log::warn!("resolver cache snapshot task failed (periodic): {}", e);
            -1
        }
        Ok(Err(_)) => {
            log::warn!(
                "resolver cache snapshot timed out after {:?} (periodic); write continues in background",
                deadline
            );
            SNAPSHOT_TIMED_OUT
        }
        Err(e) => {
            log::warn!("resolver cache snapshot block_on failed (periodic): {}", e);
            -1
        }
    }
}

fn snapshot_count_to_c_int(n: usize) -> c_int {
    c_int::try_from(n).unwrap_or(c_int::MAX)
}

/// Flushes infrastructure state across caches and upstream connections. After
/// a network transition the upstream state negotiated on the previous network
/// (H2 connections, RTT estimates, EDNS probe results, forward/stub UDP
/// sockets) is stale, and keeping it makes the first query after a roam pay the
/// full failure and rebuild path. This call:
///   1. Drops every cached answer so validation re-runs on the new network
///      (critical after roaming into a captive portal or a network that
///      rewrites DNS).
///   2. Rebuilds every `ProviderPool` connection so DoH H2 streams
///      re-handshake with fresh RTT/EDNS state.
///   3. Rebuilds every forward/stub-zone resolver so their UDP sockets bind to
///      the new default route.
///   4. Rebuilds the global forwarding resolver, when forwarding is on, for
///      the same reason.
///
/// The App's manual flush takes this path too, to force fresh upstream
/// handshakes.
///
/// A failed forwarding rebuild is non-fatal: the old resolver is kept so
/// forwarding does not silently disappear.
#[no_mangle]
pub extern "C" fn dns_notify_network_change() {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        log::debug!("flushing caches and rebuilding resolvers");
        // Every step below blocks on the runtime and can outlive its session.
        // Capture both halves once so nothing here reaches into a session that
        // started while this call was running.
        let (session_generation, state) = capture_session();
        let Some(s) = state else { return };

        clear_live_cache_sync(&s, "network change");
        remove_cache_dump_for_session(session_generation, "network change");

        s.pool.close_family_gates_for_network_change();
        s.pool.rebuild_all_conns("network change");
        // Re-close after every slot generation has advanced so stale
        // in-flight events from the previous network cannot seed a
        // fresh family-gate window between the first close and rebuild.
        s.pool.close_family_gates_for_network_change();

        let zones_rebuilt = {
            let _lifecycle = lifecycle_lock();
            let current = s.policy.load_full();
            let (zones, rebuilt) = current.zones.rebuilt_copy();
            s.policy
                .store(Arc::new(crate::policy::RuntimePolicySnapshot {
                    overrides: current.overrides.clone(),
                    zones: Arc::new(zones),
                }));
            rebuilt
        };
        if zones_rebuilt > 0 {
            log::info!(
                "zones: {} resolvers rebuilt (network change)",
                zones_rebuilt
            );
        }

        let forward_rebuild = {
            let _lifecycle = lifecycle_lock();
            let generation = s.forward_generation.load(Ordering::Acquire);
            let snapshot = s.forward.load_full();
            snapshot
                .as_ref()
                .as_ref()
                .map(|existing| (generation, existing.servers.clone()))
        };
        if let Some((generation, servers)) = forward_rebuild {
            match ForwardResolver::new(&servers) {
                Ok(new) => {
                    if publish_forward_rebuild_if_current(s.as_ref(), generation, new) {
                        log::info!("forwarding resolver rebuilt (network change)");
                    } else {
                        log::debug!("discarded stale forwarding rebuild (network change)");
                    }
                }
                Err(e) => log::warn!(
                    "forwarding rebuild failed, keeping previous resolver: {}",
                    e
                ),
            }
        }
    }))
    .map_err(|_| log::error!("dns_notify_network_change: panic"));
}

#[cfg(test)]
mod ffi_tests {
    use super::*;

    // Lifecycle tests share the process-wide module state slot. Without
    // serialization `cargo test`'s parallel runner can interleave a
    // `full_init_then_shutdown` test with one that asserts pre-init state
    // and observe the half-initialized world. The lock is the state slot's
    // own, so query tests that install a state are serialized with these.
    fn ffi_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::state::test_lock()
    }

    /// Ensures `dns_shutdown` runs even if a later assert in the test panics,
    /// otherwise the leaked tokio runtime and bound port contaminate the next
    /// FFI test that takes `ffi_lock()`.
    struct InitGuard;
    impl Drop for InitGuard {
        fn drop(&mut self) {
            dns_shutdown(0);
        }
    }

    #[test]
    fn rejected_policy_snapshot_keeps_previous_policy_active() {
        let _guard = ffi_lock();
        let port = pick_test_port();
        assert_eq!(dns_init(port), 1);
        let _init = InitGuard;

        let good = CString::new(
            r#"{"overrides":[{"domain":"a.example","qtype":"A","value":"10.0.0.1"}],
                "forwardZones":[{"domain":"corp.local","forwardIP":"10.0.0.53"}]}"#,
        )
        .unwrap();
        assert_eq!(
            unsafe { dns_apply_policy_snapshot(good.as_ptr(), std::ptr::null_mut(), 0) },
            1
        );

        let state = get_state().expect("state after init");
        assert!(state
            .policy
            .load()
            .overrides
            .get_exact("a.example", hickory_proto::rr::RecordType::A)
            .is_some());

        // A snapshot whose second record is invalid must be refused whole.
        let bad = CString::new(
            r#"{"overrides":[{"domain":"b.example","qtype":"A","value":"10.0.0.2"},
                             {"domain":"c.example","qtype":"A","value":"not-an-ip"}],
                "forwardZones":[]}"#,
        )
        .unwrap();
        assert_eq!(
            unsafe { dns_apply_policy_snapshot(bad.as_ptr(), std::ptr::null_mut(), 0) },
            0
        );

        let policy = state.policy.load();
        assert!(policy
            .overrides
            .get_exact("a.example", hickory_proto::rr::RecordType::A)
            .is_some());
        assert!(policy
            .overrides
            .get_exact("b.example", hickory_proto::rr::RecordType::A)
            .is_none());
        assert!(policy.zones.entry_for("host.corp.local").is_some());
    }

    #[test]
    fn policy_snapshot_reports_the_offending_entry_to_the_caller() {
        let bad = CString::new(
            r#"{"overrides":[{"domain":"good.example","qtype":"A","value":"10.0.0.1"},
                             {"domain":"bad.example","qtype":"A","value":"not-an-ip"}],
                "forwardZones":[]}"#,
        )
        .unwrap();

        let mut buffer = [0 as c_char; 256];
        let applied =
            unsafe { dns_apply_policy_snapshot(bad.as_ptr(), buffer.as_mut_ptr(), buffer.len()) };
        assert_eq!(applied, 0);

        let reported = unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        assert!(
            reported.contains("bad.example"),
            "rejection {reported:?} must name the offending entry"
        );
        assert!(
            !reported.contains("good.example"),
            "rejection {reported:?} must not blame the valid entry"
        );
    }

    #[test]
    fn policy_snapshot_truncates_a_rejection_that_does_not_fit() {
        let bad = CString::new(
            r#"{"overrides":[{"domain":"averylongdomainnamethatdoesnotfit.example",
                              "qtype":"A","value":"not-an-ip"}],
                "forwardZones":[]}"#,
        )
        .unwrap();

        let mut buffer = [0x7f as c_char; 16];
        let applied =
            unsafe { dns_apply_policy_snapshot(bad.as_ptr(), buffer.as_mut_ptr(), buffer.len()) };
        assert_eq!(applied, 0);

        let reported = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        assert!(reported.to_bytes().len() < buffer.len());
        assert!(reported.to_string_lossy().starts_with("override "));
    }

    /// A query holds the snapshot `Arc` it loaded for the whole request.
    /// Publishing a new policy must leave that pinned copy untouched, or an
    /// in-flight query would see half of the next configuration.
    #[test]
    fn policy_snapshot_publication_does_not_mutate_a_pinned_snapshot() {
        let _guard = ffi_lock();
        let port = pick_test_port();
        assert_eq!(dns_init(port), 1);
        let _init = InitGuard;
        let state = get_state().expect("state after init");
        let pinned = state.policy.load_full();

        let policy = CString::new(
            r#"{"overrides":[{"domain":"pinned.example","qtype":"A","value":"192.0.2.1"}],
                "forwardZones":[{"domain":"pinned.local","forwardIP":"10.0.0.53"}]}"#,
        )
        .unwrap();
        assert_eq!(
            unsafe { dns_apply_policy_snapshot(policy.as_ptr(), std::ptr::null_mut(), 0) },
            1
        );

        assert!(pinned
            .overrides
            .get_exact("pinned.example", RecordType::A)
            .is_none());
        assert!(pinned.zones.entry_for("host.pinned.local").is_none());
        let published = state.policy.load();
        assert!(published
            .overrides
            .get_exact("pinned.example", RecordType::A)
            .is_some());
        assert!(published.zones.entry_for("host.pinned.local").is_some());
    }

    /// Owner-name and CNAME-conflict rejection at the FFI boundary: the whole
    /// snapshot is refused and nothing from it reaches the live policy.
    #[test]
    fn policy_snapshot_rejects_invalid_owner_and_cname_conflict() {
        let _guard = ffi_lock();
        let port = pick_test_port();
        assert_eq!(dns_init(port), 1);
        let _init = InitGuard;
        let state = get_state().expect("state after init");

        for json in [
            r#"{"overrides":[{"domain":"alias.example","qtype":"CNAME","value":"target.example"},
                             {"domain":"alias.example","qtype":"A","value":"192.0.2.1"}],
                "forwardZones":[]}"#,
            r#"{"overrides":[{"domain":"bad_domain.example","qtype":"A","value":"192.0.2.1"}],
                "forwardZones":[]}"#,
        ] {
            let policy = CString::new(json).unwrap();
            assert_eq!(
                unsafe { dns_apply_policy_snapshot(policy.as_ptr(), std::ptr::null_mut(), 0) },
                0,
                "{json} must be refused whole"
            );
        }

        let policy = state.policy.load();
        assert!(policy
            .overrides
            .get_exact("alias.example", RecordType::CNAME)
            .is_none());
        assert!(policy
            .overrides
            .get_exact("bad_domain.example", RecordType::A)
            .is_none());
    }

    #[test]
    fn policy_snapshot_rejects_invalid_input_without_state() {
        let _guard = ffi_lock();
        assert_eq!(
            unsafe { dns_apply_policy_snapshot(std::ptr::null(), std::ptr::null_mut(), 0) },
            0
        );
    }

    /// Reserves a loopback port that is currently free for both UDP and TCP,
    /// so tests do not flake on a hardcoded port already in use. The kernel
    /// picks the UDP number without looking at TCP, and tests outside
    /// `ffi_lock()` open TCP sockets in parallel, so a number taken on TCP is
    /// skipped rather than treated as a failure.
    fn pick_test_port() -> u16 {
        use std::net::{Ipv4Addr, TcpListener, UdpSocket};
        for _ in 0..64 {
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve udp port");
            let port = udp.local_addr().expect("udp local_addr").port();
            if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
                return port;
            }
        }
        panic!("no loopback port is free for both UDP and TCP");
    }

    fn enable_test_forwarding(server: &str) -> c_int {
        let server = CString::new(server).unwrap();
        let pointers = [server.as_ptr()];
        unsafe { dns_enable_forwarding(pointers.as_ptr(), 1) }
    }

    /// Sends a real DNS query to the listener started by `dns_init` and
    /// returns the response wire.
    fn query_listener(port: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
        use std::net::{Ipv4Addr, UdpSocket};

        let mut wire = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.trim_end_matches('.').split('.') {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        wire.extend_from_slice(&qtype.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .ok()?;
        socket.send_to(&wire, (Ipv4Addr::LOCALHOST, port)).ok()?;

        let mut buf = [0u8; 4096];
        let (len, _) = socket.recv_from(&mut buf).ok()?;
        Some(buf[..len].to_vec())
    }

    fn response_code(wire: &[u8]) -> u8 {
        wire[3] & 0x0F
    }

    fn first_a_record(wire: &[u8]) -> Option<std::net::Ipv4Addr> {
        let msg = hickory_proto::op::Message::from_vec(wire).ok()?;
        msg.answers.iter().find_map(|r| match &r.data {
            hickory_proto::rr::RData::A(a) => Some(a.0),
            _ => None,
        })
    }

    /// An override must win over the built-in special-use table covering the
    /// same name: `.test` is an RFC 6761 name the resolver never sends
    /// upstream, and an operator override still has to answer it.
    #[test]
    fn override_wins_over_builtin_special_use_on_the_wire() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let port = pick_test_port();
        assert_eq!(dns_init(port), 1);
        let _shutdown = InitGuard;

        let policy = CString::new(
            r#"{"overrides":[{"domain":"host.corp.test","qtype":"A","value":"10.9.9.9"}],
                "forwardZones":[]}"#,
        )
        .unwrap();
        assert_eq!(
            unsafe { dns_apply_policy_snapshot(policy.as_ptr(), std::ptr::null_mut(), 0) },
            1
        );

        let wire = query_listener(port, "host.corp.test", 1).expect("response");
        assert_eq!(response_code(&wire), 0, "override must answer NOERROR");
        assert_eq!(
            first_a_record(&wire),
            Some(std::net::Ipv4Addr::new(10, 9, 9, 9))
        );
    }

    /// The rebinding filter must never touch an operator-configured answer.
    /// An override is the documented remediation for a name that legitimately
    /// resolves into private space (`docs/DNS_REBINDING_DEFENSE.md`), so it has
    /// to reach the client verbatim.
    #[test]
    fn override_private_address_survives_rebinding_filter_on_the_wire() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let port = pick_test_port();
        assert_eq!(dns_init(port), 1);
        let _shutdown = InitGuard;

        let policy = CString::new(
            r#"{"overrides":[{"domain":"nas.rebind.test","qtype":"A","value":"192.168.1.10"}],
                "forwardZones":[]}"#,
        )
        .unwrap();
        assert_eq!(
            unsafe { dns_apply_policy_snapshot(policy.as_ptr(), std::ptr::null_mut(), 0) },
            1
        );

        let wire = query_listener(port, "nas.rebind.test", 1).expect("response");
        assert_eq!(response_code(&wire), 0, "override must answer NOERROR");
        assert_eq!(
            first_a_record(&wire),
            Some(std::net::Ipv4Addr::new(192, 168, 1, 10)),
            "an operator-configured private address must not be stripped"
        );
    }

    /// Built-in special-use handling must apply without any user route.
    #[test]
    fn builtin_special_use_zone_answers_on_the_wire() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let port = pick_test_port();
        assert_eq!(dns_init(port), 1);
        let _shutdown = InitGuard;

        let wire = query_listener(port, "printer.invalid", 1).expect("response");
        // RFC 6761: `.invalid` is always NXDOMAIN, never sent upstream.
        assert_eq!(response_code(&wire), 3);
    }

    /// Sends one `dns_history_query` request and frees the answer through
    /// `dns_history_free_json`, as the agent does.
    fn history_query(request: &str) -> serde_json::Value {
        let request = CString::new(request).unwrap();
        let raw = unsafe { dns_history_query(request.as_ptr()) };
        assert!(!raw.is_null(), "a request always gets a JSON answer");
        let json = unsafe { CStr::from_ptr(raw) }.to_str().unwrap().to_owned();
        unsafe { dns_history_free_json(raw) };
        serde_json::from_str(&json).unwrap()
    }

    fn history_log_names() -> Vec<String> {
        let log = history_query(
            r#"{"kind":"log","result":"all","query":"history-ffi","limit":50,"beforeId":null}"#,
        );
        assert_eq!(log["status"], "ok", "{log}");
        log["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap().to_owned())
            .collect()
    }

    /// Owns the process-wide history for one test: captures stay off so
    /// lookups reach the store, and the drop turns history off again so later
    /// tests never write into a deleted directory.
    struct HistoryGuard {
        _no_capture: std::sync::MutexGuard<'static, ()>,
        dir: tempfile::TempDir,
    }

    impl HistoryGuard {
        fn enable() -> Self {
            let guard = Self {
                _no_capture: crate::history::capture::suspend(),
                dir: tempfile::TempDir::new().unwrap(),
            };
            let path = CString::new(
                guard
                    .dir
                    .path()
                    .join("query-history.sqlite")
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
            unsafe { dns_set_history_path(path.as_ptr()) };
            assert_eq!(dns_configure_history(1, 30, 0, 7), 1);
            guard
        }
    }

    impl Drop for HistoryGuard {
        fn drop(&mut self) {
            dns_configure_history(0, 30, 0, 7);
        }
    }

    #[test]
    fn history_records_listener_lookups_and_answers_through_the_ffi() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let history = HistoryGuard::enable();
        let port = pick_test_port();
        assert_eq!(dns_init(port), 1);
        let _shutdown = InitGuard;

        let wire = query_listener(port, "history-ffi.localhost", 1).expect("response");
        assert_eq!(response_code(&wire), 0, "test setup must answer locally");
        assert!(crate::history::flush());

        assert_eq!(history_log_names(), ["history-ffi.localhost"]);
        let status = history_query(r#"{"kind":"status"}"#);
        assert_eq!(status["status"], "ok", "{status}");
        assert_eq!(status["enabled"], true);
        assert!(history.dir.path().join("query-history.sqlite").exists());

        assert_eq!(dns_history_clear(), 1);
        assert!(history_log_names().is_empty());
    }

    /// The agent configures history at launch, before and without `dns_init`,
    /// so the Queries tab and Clear History work while protection is off.
    #[test]
    fn history_works_while_the_resolver_is_stopped() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let history = HistoryGuard::enable();
        let path = history.dir.path().join("query-history.sqlite");
        let stored = |needle: &str| {
            ["", "-wal", "-shm"].iter().any(|suffix| {
                std::fs::read(format!("{}{suffix}", path.display()))
                    .is_ok_and(|bytes| bytes.windows(needle.len()).any(|w| w == needle.as_bytes()))
            })
        };
        crate::history::record(crate::history::LookupEvent {
            ts: crate::history::unix_now(),
            name: "history-ffi-stopped.example".to_owned(),
            qtype: 1,
            rcode: 0,
            answers: 1,
            route: crate::history::Route::Cache,
            provider: String::new(),
            latency_us: 1000,
            block_rule: String::new(),
            block_category: String::new(),
        });
        assert!(crate::history::flush());
        assert_eq!(history_log_names(), ["history-ffi-stopped.example"]);
        assert!(stored("history-ffi-stopped.example"));

        assert_eq!(dns_history_clear(), 1);
        assert!(!stored("history-ffi-stopped.example"));
        assert!(history_log_names().is_empty());

        assert_eq!(dns_configure_history(0, 30, 0, 7), 1);
        assert!(crate::history::flush());
        assert!(path.exists(), "turning history off keeps the database");
        assert_eq!(history_query(r#"{"kind":"status"}"#)["status"], "disabled");

        assert_eq!(dns_history_clear(), 1);
        for suffix in ["", "-wal", "-shm"] {
            let file = format!("{}{suffix}", path.display());
            assert!(!std::path::Path::new(&file).exists(), "{file} still exists");
        }
        assert_eq!(history_query(r#"{"kind":"status"}"#)["status"], "disabled");
    }

    #[test]
    fn history_shutdown_commits_the_lookups_it_saw() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let _history = HistoryGuard::enable();
        let port = pick_test_port();
        assert_eq!(dns_init(port), 1);
        let _shutdown = InitGuard;

        query_listener(port, "history-ffi-shutdown.localhost", 1).expect("response");
        assert_eq!(dns_shutdown(1), 1);

        assert_eq!(history_log_names(), ["history-ffi-shutdown.localhost"]);
    }

    #[test]
    fn history_configure_rejects_values_outside_the_allowed_choices() {
        for (retention, count, days) in [
            (8, 0, 7),
            (-30, 0, 7),
            (30, 50, 7),
            (30, -100, 7),
            (30, 0, 3),
            (7, 100, 14),
        ] {
            assert_eq!(
                dns_configure_history(1, retention, count, days),
                0,
                "retention {retention}, count {count}, days {days}"
            );
        }
    }

    #[test]
    fn history_query_reports_caller_errors_as_json() {
        let raw = unsafe { dns_history_query(std::ptr::null()) };
        assert!(!raw.is_null());
        let answer: serde_json::Value =
            serde_json::from_str(unsafe { CStr::from_ptr(raw) }.to_str().unwrap()).unwrap();
        unsafe { dns_history_free_json(raw) };
        assert_eq!(answer["status"], "error", "{answer}");
        assert_eq!(history_query(r#"{"kind":"nope"}"#)["status"], "error");
    }

    #[test]
    fn resolver_discovery_does_not_replay_cached_upstream_advertisements_on_the_wire() {
        use hickory_proto::op::{Message, Query, ResponseCode};
        use hickory_proto::rr::{rdata::SVCB, Name, Record};

        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let port = pick_test_port();
        assert_eq!(dns_init(port), 1);
        let _shutdown = InitGuard;
        let domain = "_dns.resolver.arpa";
        let name = Name::from_str(domain).unwrap();
        let mut cached = Message::query();
        cached.add_query(Query::query(name.clone(), RecordType::SVCB));
        cached.add_answer(Record::from_rdata(
            name,
            300,
            RData::SVCB(SVCB::new(
                1,
                Name::from_str("dns.quad9.net.").unwrap(),
                vec![],
            )),
        ));
        let cache = get_state().unwrap().cache.clone();
        block_on(async move {
            assert!(
                cache
                    .insert(
                        crate::cache::CacheKey::from(domain, RecordType::SVCB),
                        crate::cache::CachedEntry::scaffold(cached, "Quad9".into()),
                        300,
                    )
                    .await
            );
        })
        .unwrap();

        let wire = query_listener(port, domain, 64).expect("local DDR response");
        let response = Message::from_vec(&wire).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(
            response.answers.is_empty(),
            "cached upstream DDR must not reach the client"
        );
        assert_eq!(response.authorities.len(), 1);
        assert_eq!(response.authorities[0].record_type(), RecordType::SOA);
        assert_eq!(
            response.authorities[0].name,
            Name::from_str("resolver.arpa.").unwrap()
        );
    }

    /// A user forward zone must take precedence over built-in handling for the
    /// same suffix, so split DNS keeps working.
    #[test]
    fn forward_zone_takes_precedence_over_builtin_on_the_wire() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let port = pick_test_port();
        assert_eq!(dns_init(port), 1);
        let _shutdown = InitGuard;

        let state = get_state().expect("state");
        assert!(state
            .policy
            .load()
            .zones
            .entry_for("host.corp.local")
            .is_none());

        let policy = CString::new(
            r#"{"overrides":[],
                "forwardZones":[{"domain":"corp.local","forwardIP":"127.0.0.2"}]}"#,
        )
        .unwrap();
        assert_eq!(
            unsafe { dns_apply_policy_snapshot(policy.as_ptr(), std::ptr::null_mut(), 0) },
            1
        );

        // The route is installed ahead of the built-in `.local` handling.
        assert!(state
            .policy
            .load()
            .zones
            .entry_for("host.corp.local")
            .is_some());
    }

    #[test]
    fn outer_ffi_guard_converts_setup_panic_to_sentinel() {
        assert_eq!(catch_ffi_panic("test_guard", || panic!("setup panic")), 0);
    }

    #[test]
    fn ready_is_zero_before_init() {
        let _g = ffi_lock();
        // Clear state a previous lifecycle test may have left, so the
        // assertion holds in any test order.
        crate::state::clear_state();
        assert_eq!(dns_is_ready(), 0);
    }

    #[test]
    fn recursive_resolution_probe_is_zero_before_init() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);

        assert_eq!(dns_probe_recursive_resolution(), 0);
    }

    #[test]
    fn network_dns_probe_is_zero_before_init() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let server = CString::new("192.168.1.1").unwrap();
        let pointers = [server.as_ptr()];

        assert_eq!(unsafe { dns_probe_network_dns(pointers.as_ptr(), 1) }, 0);
    }

    #[test]
    fn network_dns_probe_rejects_an_invalid_server_array() {
        let _g = ffi_lock();
        let server = CString::new("192.168.1.1").unwrap();
        let pointers = [server.as_ptr()];

        assert_eq!(unsafe { dns_probe_network_dns(std::ptr::null(), 1) }, 0);
        assert_eq!(unsafe { dns_probe_network_dns(pointers.as_ptr(), 0) }, 0);
        assert_eq!(unsafe { dns_probe_network_dns(pointers.as_ptr(), 65) }, 0);
    }

    #[test]
    fn proxy_probe_is_refused_only_when_bypass_is_not_requested() {
        let _g = ffi_lock();
        set_proxy_bypass_requested_for_test(true);
        assert!(!proxy_interception_ready());

        set_proxy_bypass_requested_for_test(false);
        assert!(proxy_interception_ready());

        set_proxy_bypass_requested_for_test(true);
    }

    #[test]
    fn dns_set_proxy_bypass_requested_round_trips() {
        let _g = ffi_lock();
        assert_eq!(dns_set_proxy_bypass_requested(1), 1);
        assert!(!proxy_interception_ready());
        assert_eq!(dns_set_proxy_bypass_requested(0), 1);
        assert!(proxy_interception_ready());

        assert_eq!(dns_set_proxy_bypass_requested(1), 1);
    }

    #[test]
    fn disable_forwarding_fails_without_state() {
        let _g = ffi_lock();
        crate::state::clear_state();
        assert_eq!(dns_disable_forwarding(), 0);
    }

    #[test]
    fn stale_forward_rebuild_after_disable_is_discarded() {
        let _g = ffi_lock();
        assert_eq!(dns_init(pick_test_port()), 1);
        let _shutdown = InitGuard;
        assert_eq!(enable_test_forwarding("127.0.0.1"), 1);
        let state = get_state().unwrap();
        let captured_generation = state.forward_generation.load(Ordering::Acquire);

        assert_eq!(dns_disable_forwarding(), 1);
        let rebuilt = ForwardResolver::new(&["127.0.0.1".into()]).unwrap();

        assert!(!publish_forward_rebuild_if_current(
            state.as_ref(),
            captured_generation,
            rebuilt
        ));
        assert!(state.forward.load().as_ref().is_none());
    }

    #[test]
    fn stale_forward_rebuild_after_replacement_is_discarded() {
        let _g = ffi_lock();
        assert_eq!(dns_init(pick_test_port()), 1);
        let _shutdown = InitGuard;
        assert_eq!(enable_test_forwarding("127.0.0.1"), 1);
        let state = get_state().unwrap();
        let captured_generation = state.forward_generation.load(Ordering::Acquire);

        assert_eq!(enable_test_forwarding("127.0.0.2"), 1);
        let rebuilt = ForwardResolver::new(&["127.0.0.1".into()]).unwrap();

        assert!(!publish_forward_rebuild_if_current(
            state.as_ref(),
            captured_generation,
            rebuilt
        ));
        assert_eq!(
            state.forward.load().as_ref().as_ref().unwrap().servers,
            vec!["127.0.0.2"]
        );
    }

    #[test]
    fn full_init_then_shutdown_does_not_panic() {
        let _g = ffi_lock();
        std::env::set_var("RUST_BACKTRACE", "1");
        let rc = dns_init(pick_test_port());
        assert_eq!(rc, 1, "dns_init returned 0 — check stderr");
        let _shutdown = InitGuard;
        assert_eq!(dns_is_ready(), 1);
    }

    /// Init, install session policy, shut down, reinit. Session-owned state
    /// must be rebuilt from scratch: a leak across sessions would let a stale
    /// override or zone survive a service bounce the user asked for.
    #[test]
    fn reinit_rebuilds_session_state_without_leaking_policy() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);

        assert_eq!(dns_init(pick_test_port()), 1);
        let policy = CString::new(
            r#"{"overrides":[{"domain":"leak.example","qtype":"A","value":"10.0.0.9"}],
                "forwardZones":[{"domain":"leak.local","forwardIP":"10.0.0.53"}]}"#,
        )
        .unwrap();
        assert_eq!(
            unsafe { dns_apply_policy_snapshot(policy.as_ptr(), std::ptr::null_mut(), 0) },
            1
        );

        let first_state = get_state().expect("state after first init");
        assert!(first_state
            .policy
            .load()
            .overrides
            .get_exact("leak.example", hickory_proto::rr::RecordType::A)
            .is_some());

        assert_eq!(dns_shutdown(1), 1);
        assert_eq!(dns_is_ready(), 0);
        assert!(get_state().is_none());

        assert_eq!(dns_init(pick_test_port()), 1);
        let _shutdown = InitGuard;
        let second_state = get_state().expect("state after reinit");

        assert!(!std::sync::Arc::ptr_eq(&first_state, &second_state));

        let policy = second_state.policy.load();
        assert!(policy
            .overrides
            .get_exact("leak.example", hickory_proto::rr::RecordType::A)
            .is_none());
        assert!(policy.zones.entry_for("host.leak.local").is_none());
    }

    #[test]
    fn double_init_while_running_keeps_the_existing_session() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);

        assert_eq!(dns_init(pick_test_port()), 1);
        let _shutdown = InitGuard;
        let state = get_state().expect("state after init");

        // A duplicate init must not replace live state under running queries.
        assert_eq!(dns_init(pick_test_port()), 1);
        let after = get_state().expect("state after duplicate init");

        assert!(std::sync::Arc::ptr_eq(&state, &after));
    }

    #[test]
    fn repeated_shutdown_is_safe() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);

        assert_eq!(dns_init(pick_test_port()), 1);
        assert_eq!(dns_shutdown(1), 1);
        assert_eq!(dns_shutdown(1), 1);
        assert_eq!(dns_is_ready(), 0);
    }

    /// The agent's fail-safe stop path calls `ResolverModule.stop()` directly,
    /// without disconnecting the control XPC link first. Shutdown must therefore
    /// drop the HMAC session itself, otherwise the key stays resident until the
    /// next `dns_init`.
    #[test]
    fn shutdown_clears_the_proxy_control_session() {
        let _g = ffi_lock();
        let _session = crate::proxy_control::test_lock();
        let _ = dns_shutdown(1);

        let id = [0x11u8; 16];
        let key = [0x22u8; 32];
        assert_eq!(
            unsafe { dns_configure_proxy_control(id.as_ptr(), 16, key.as_ptr(), 32) },
            1
        );
        assert!(crate::proxy_control::build_response(&[0u8; 32], b'u', true, b"q").is_some());

        assert_eq!(dns_shutdown(1), 1);

        assert!(
            crate::proxy_control::build_response(&[0u8; 32], b'u', true, b"q").is_none(),
            "shutdown must clear the control session"
        );
    }

    #[test]
    fn forced_shutdown_skips_cache_snapshot() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let temp = tempfile::TempDir::new().unwrap();
        let cache_path = temp.path().join("cache.json");
        let cache_path_c = CString::new(cache_path.to_string_lossy().as_bytes()).unwrap();
        unsafe { dns_set_cache_path(cache_path_c.as_ptr()) };
        assert_eq!(dns_init(pick_test_port()), 1);
        let attempts_before = SHUTDOWN_SNAPSHOT_ATTEMPTS.load(Ordering::Acquire);

        assert_eq!(dns_shutdown(1), 1);

        assert_eq!(
            SHUTDOWN_SNAPSHOT_ATTEMPTS.load(Ordering::Acquire),
            attempts_before
        );
        assert!(!cache_path.exists());
    }

    /// The periodic snapshot must never pin its caller indefinitely: a write
    /// that outlives the deadline is abandoned with a distinct return code
    /// instead of blocking until iteration, gzip and fsync finish.
    #[test]
    fn periodic_snapshot_abandons_the_wait_after_the_deadline() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        assert_eq!(dns_init(pick_test_port()), 1);
        let _init = InitGuard;

        let rc = snapshot_with_deadline(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            SnapshotAttempt::Ok(Ok(Some(1)))
        });

        assert_eq!(rc, SNAPSHOT_TIMED_OUT);
    }

    #[test]
    fn periodic_snapshot_within_the_deadline_reports_the_entry_count() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        assert_eq!(dns_init(pick_test_port()), 1);
        let _init = InitGuard;

        let rc = snapshot_with_deadline(Duration::from_secs(30), async {
            SnapshotAttempt::Ok(Ok(Some(7)))
        });

        assert_eq!(rc, 7);
    }

    /// Points the process-wide dump path at `path`. `dns_set_cache_path` copies
    /// the bytes out, so the `CString` only has to survive the call itself.
    fn use_test_cache_path(path: &std::path::Path) {
        let c = CString::new(path.to_string_lossy().as_bytes()).unwrap();
        unsafe { dns_set_cache_path(c.as_ptr()) };
    }

    fn positive_entry(name: &str) -> (crate::cache::CacheKey, crate::cache::CachedEntry) {
        let owner = hickory_proto::rr::Name::from_str(&format!("{name}.")).unwrap();
        let mut msg = hickory_proto::op::Message::query();
        msg.add_query(hickory_proto::op::Query::query(
            owner.clone(),
            RecordType::A,
        ));
        msg.add_answer(hickory_proto::rr::Record::from_rdata(
            owner,
            300,
            RData::A(A(std::net::Ipv4Addr::new(93, 184, 216, 34))),
        ));
        (
            crate::cache::CacheKey::from(name, RecordType::A),
            crate::cache::CachedEntry::scaffold(msg, "Cloudflare".into()),
        )
    }

    /// `dns_flush_cache` and `dns_notify_network_change` block on the runtime,
    /// so they can still be running after a shutdown/init pair. The work they
    /// finish afterwards belongs to the session that admitted it. Clearing the
    /// new cache or deleting the new dump would cost the user a warm cache for
    /// reasons that ended with the previous session.
    #[test]
    fn stale_session_work_leaves_the_new_cache_and_dump_alone() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let temp = tempfile::TempDir::new().unwrap();
        let dump = temp.path().join("cache.dump");
        use_test_cache_path(&dump);

        assert_eq!(dns_init(pick_test_port()), 1);
        // Exactly what a long-running flush or network change captured before
        // the restart below.
        let (stale_generation, stale_state) = capture_session();
        let stale_state = stale_state.expect("state after the first init");

        assert_eq!(dns_shutdown(1), 1);
        assert_eq!(dns_init(pick_test_port()), 1);
        let _shutdown = InitGuard;
        let live = get_state().expect("state after the restart");

        let (key, entry) = positive_entry("survivor.example");
        let cache = live.cache.clone();
        let insert_key = key.clone();
        block_on(async move {
            cache.insert(insert_key, entry, 120).await;
            cache.flush_pending().await;
        })
        .expect("warm the new session's cache");
        std::fs::write(&dump, b"new session dump").unwrap();

        // The previous session's operation completes here.
        clear_live_cache_sync(&stale_state, "stale session");
        remove_cache_dump_for_session(stale_generation, "stale session");

        assert!(
            dump.exists(),
            "a stale session must not delete the dump the new session owns"
        );
        let cache = live.cache.clone();
        assert!(
            block_on(async move { cache.get(&key).await })
                .expect("cache lookup")
                .is_some(),
            "a stale session must not clear the new session's cache"
        );

        unsafe { dns_set_cache_path(std::ptr::null()) };
    }

    /// The stop-to-init window. Work goes stale without a restart, because the
    /// session that admitted it ended at `dns_shutdown`. A flush completing
    /// before the next `dns_init` must not delete the dump the shutdown snapshot
    /// just wrote, or the restart loses the warm cache.
    #[test]
    fn stale_session_work_cannot_delete_the_shutdown_dump() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let temp = tempfile::TempDir::new().unwrap();
        let dump = temp.path().join("cache.dump");
        use_test_cache_path(&dump);

        assert_eq!(dns_init(pick_test_port()), 1);
        // Exactly what a long-running flush captured before the shutdown below.
        let (stale_generation, stale_state) = capture_session();
        let stale_state = stale_state.expect("state after the init");

        let (key, entry) = positive_entry("survivor.example");
        let cache = stale_state.cache.clone();
        block_on(async move {
            cache.insert(key, entry, 120).await;
            cache.flush_pending().await;
        })
        .expect("warm the cache the shutdown snapshot has to persist");

        assert_eq!(dns_shutdown(0), 1);
        assert!(
            dump.exists(),
            "the shutdown snapshot must have written a dump"
        );

        // The previous session's operation completes here, before any new init.
        remove_cache_dump_for_session(stale_generation, "stale session");

        assert!(
            dump.exists(),
            "work admitted before the shutdown must not delete the dump that shutdown wrote"
        );

        unsafe { dns_set_cache_path(std::ptr::null()) };
    }

    /// The generation check must not degrade into a permanent veto: a flush
    /// issued by the live session still has to make the dump disappear, or the
    /// next `dns_init` restores the entries the user just evicted.
    #[test]
    fn live_session_flush_still_removes_the_dump() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let temp = tempfile::TempDir::new().unwrap();
        let dump = temp.path().join("cache.dump");
        use_test_cache_path(&dump);
        assert_eq!(dns_init(pick_test_port()), 1);
        let _shutdown = InitGuard;
        std::fs::write(&dump, b"live session dump").unwrap();

        dns_flush_cache();

        assert!(
            !dump.exists(),
            "an explicit flush must stay sticky across restarts"
        );
        unsafe { dns_set_cache_path(std::ptr::null()) };
    }

    /// The host releases its own in-flight guard when the FFI call returns,
    /// which after a timeout is long before the abandoned write ends. A later
    /// tick must be refused instead of starting a second writer that races the
    /// first on the final rename.
    #[test]
    fn periodic_snapshot_reports_busy_while_a_writer_owns_the_flight() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let temp = tempfile::TempDir::new().unwrap();
        let dump = temp.path().join("cache.dump");
        use_test_cache_path(&dump);
        assert_eq!(dns_init(pick_test_port()), 1);
        let _shutdown = InitGuard;

        let writer = SnapshotWriterGuard::try_acquire().expect("no writer may be active");

        assert_eq!(dns_snapshot_cache(), SNAPSHOT_BUSY);
        assert!(!dump.exists(), "the refused tick must not write a dump");
        assert_eq!(dns_snapshot_cache(), SNAPSHOT_BUSY);
        assert_eq!(dns_snapshot_cache(), SNAPSHOT_BUSY);

        drop(writer);

        assert!(
            dns_snapshot_cache() >= 0,
            "the next tick must run once ownership is released"
        );
        assert!(dump.exists());

        unsafe { dns_set_cache_path(std::ptr::null()) };
    }

    /// Ownership has to survive the deadline. The timeout only ends the wait,
    /// and releasing ownership on return would let a second writer start.
    #[test]
    fn snapshot_ownership_outlives_an_abandoned_deadline() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        assert_eq!(dns_init(pick_test_port()), 1);
        let _init = InitGuard;

        let writer = SnapshotWriterGuard::try_acquire().expect("no writer may be active");
        let (release, parked) = std::sync::mpsc::channel::<()>();

        let rc = snapshot_with_deadline(Duration::from_millis(10), async move {
            tokio::task::spawn_blocking(move || {
                let _writer = writer;
                let _ = parked.recv();
                Ok::<Option<usize>, std::io::Error>(Some(1))
            })
            .await
        });

        assert_eq!(rc, SNAPSHOT_TIMED_OUT);
        assert!(
            SnapshotWriterGuard::try_acquire().is_none(),
            "an abandoned writer must keep the single flight"
        );

        release.send(()).expect("the writer must still be parked");
        let mut regained = None;
        for _ in 0..200 {
            regained = SnapshotWriterGuard::try_acquire();
            if regained.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            regained.is_some(),
            "ownership must return once the blocking write finishes"
        );
    }

    /// Shutdown shares the single flight with the periodic tick: starting its
    /// own writer while one is still running would recreate the same-epoch
    /// rename race the flight exists to prevent.
    #[test]
    fn shutdown_snapshot_skips_while_a_writer_owns_the_flight() {
        let _g = ffi_lock();
        let _ = dns_shutdown(1);
        let temp = tempfile::TempDir::new().unwrap();
        let dump = temp.path().join("cache.dump");
        use_test_cache_path(&dump);
        assert_eq!(dns_init(pick_test_port()), 1);

        let writer = SnapshotWriterGuard::try_acquire().expect("no writer may be active");
        let attempts_before = SHUTDOWN_SNAPSHOT_ATTEMPTS.load(Ordering::Acquire);

        assert_eq!(dns_shutdown(0), 1);

        assert_eq!(
            SHUTDOWN_SNAPSHOT_ATTEMPTS.load(Ordering::Acquire),
            attempts_before,
            "shutdown must not start a writer next to the running one"
        );
        assert!(!dump.exists());

        drop(writer);
        unsafe { dns_set_cache_path(std::ptr::null()) };
    }

    /// Two snapshots inside the same epoch must not share a temp file: the
    /// temp is opened truncating, so a shared name lets one attempt overwrite
    /// the bytes the other is about to publish.
    #[tokio::test]
    async fn concurrent_same_epoch_snapshots_use_distinct_temp_paths() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("cache.dump");
        let cache = Arc::new(DnsCache::new(1_048_576));
        let name = hickory_proto::rr::Name::from_str("example.com.").unwrap();
        let mut msg = hickory_proto::op::Message::query();
        msg.add_query(hickory_proto::op::Query::query(name.clone(), RecordType::A));
        msg.add_answer(hickory_proto::rr::Record::from_rdata(
            name,
            300,
            RData::A(A(std::net::Ipv4Addr::new(93, 184, 216, 34))),
        ));
        cache
            .insert(
                crate::cache::CacheKey::from("example.com", RecordType::A),
                crate::cache::CachedEntry::scaffold(msg, "Cloudflare".into()),
                120,
            )
            .await;
        cache.flush_pending().await;

        let tmp_extension = "dump.race.tmp";
        SNAPSHOT_TMP_NAMES
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();

        let results = {
            // The epoch must not move mid-test: a concurrent init, shutdown or
            // flush would legitimately reject both attempts as stale.
            let _guard = ffi_lock();
            let epoch = CACHE_SNAPSHOT_EPOCH.load(Ordering::Acquire);
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let cache = cache.clone();
                    let path = path.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        snapshot_cache_blocking(cache, path, tmp_extension.into(), epoch)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("snapshot thread"))
                .collect::<Vec<_>>()
        };

        for result in &results {
            assert!(
                matches!(result, Ok(Some(1))),
                "both same-epoch attempts must publish one entry"
            );
        }

        let names: Vec<String> = SNAPSHOT_TMP_NAMES
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|recorded| recorded.starts_with(tmp_extension))
            .cloned()
            .collect();
        assert_eq!(names.len(), 2, "both attempts must derive a temp name");
        assert_ne!(
            names[0], names[1],
            "same-epoch attempts must not share a temp path"
        );
        for name in &names {
            assert!(
                !path.with_extension(name).exists(),
                "temp file {} left behind",
                name
            );
        }

        let restored = DnsCache::new(1_048_576);
        assert_eq!(
            crate::cache_persist::restore_from_path(&restored, &path)
                .await
                .unwrap(),
            1,
            "the published dump must still be readable"
        );
    }

    #[test]
    fn dns_flush_cache_invalidates_snapshot_epoch() {
        let _g = ffi_lock();
        crate::state::clear_state();
        let before = CACHE_SNAPSHOT_EPOCH.load(Ordering::Acquire);

        dns_flush_cache();

        assert!(CACHE_SNAPSHOT_EPOCH.load(Ordering::Acquire) > before);
    }

    #[test]
    fn dns_notify_network_change_rebuilds_provider_conns() {
        let _g = ffi_lock();
        crate::state::clear_state();
        let rc = dns_init(pick_test_port());
        assert_eq!(rc, 1, "dns_init returned 0 — check stderr");
        let _shutdown = InitGuard;

        let before: Vec<u64> = crate::state::get_state()
            .expect("state initialized")
            .pool
            .all()
            .iter()
            .flat_map(|p| p.conns.iter().map(|c| c.generation()))
            .collect();
        assert!(!before.is_empty(), "provider pool should have connections");

        dns_notify_network_change();

        let after: Vec<u64> = crate::state::get_state()
            .expect("state still initialized")
            .pool
            .all()
            .iter()
            .flat_map(|p| p.conns.iter().map(|c| c.generation()))
            .collect();
        assert_eq!(after.len(), before.len());
        assert!(
            after
                .iter()
                .zip(before.iter())
                .all(|(after, before)| after > before),
            "network change must rebuild every provider connection"
        );
    }

    #[test]
    fn dns_force_blocklist_update_status_errors_without_configure() {
        let _g = ffi_lock();
        blocklist_scheduler::stop();

        assert_eq!(dns_force_blocklist_update_status(), -1);
    }

    #[test]
    fn dns_set_resolver_options_accepts_valid_provider_list() {
        let _g = ffi_lock();
        crate::state::clear_state();
        crate::config::set(crate::config::ResolverOptions::default());
        let providers = CString::new("cloudflare,google,quad9").unwrap();

        let rc = unsafe { dns_set_resolver_options(1, 0, 0, 0, 1, 1, 1, providers.as_ptr(), 1, 1) };

        assert_eq!(rc, 1);
        assert_eq!(
            crate::config::current().doh_providers,
            crate::config::default_provider_ids()
        );
    }

    #[test]
    fn dns_set_resolver_options_rejects_null_provider_pointer() {
        let _g = ffi_lock();
        let rc = unsafe { dns_set_resolver_options(1, 0, 0, 0, 1, 1, 1, std::ptr::null(), 1, 1) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn dns_set_resolver_options_rejects_empty_provider_string() {
        let _g = ffi_lock();
        let providers = CString::new("").unwrap();
        let rc = unsafe { dns_set_resolver_options(1, 0, 0, 0, 1, 1, 1, providers.as_ptr(), 1, 1) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn dns_set_resolver_options_rejects_unknown_provider_without_mutation() {
        let _g = ffi_lock();
        crate::state::clear_state();
        let before = crate::config::ResolverOptions {
            log_queries: true,
            ..Default::default()
        };
        crate::config::set(before.clone());
        let providers = CString::new("cloudflare,unknown").unwrap();

        let rc = unsafe { dns_set_resolver_options(1, 0, 0, 0, 1, 1, 1, providers.as_ptr(), 1, 1) };

        assert_eq!(rc, 0);
        assert_eq!(crate::config::current().log_queries, before.log_queries);
        assert_eq!(crate::config::current().doh_providers, before.doh_providers);
    }

    #[test]
    fn dns_set_resolver_options_rejects_invalid_dispatch_mode() {
        let _g = ffi_lock();
        let providers = CString::new("cloudflare").unwrap();
        let rc =
            unsafe { dns_set_resolver_options(1, 0, 0, 0, 1, 1, 1, providers.as_ptr(), 99, 1) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn dns_set_resolver_options_rejects_provider_list_change_while_initialized() {
        let _g = ffi_lock();
        crate::state::clear_state();
        crate::config::set(crate::config::ResolverOptions::default());

        assert_eq!(
            dns_init(pick_test_port()),
            1,
            "dns_init returned 0 — check stderr"
        );
        let _shutdown = InitGuard;
        let before_ids = crate::config::current().doh_providers.clone();

        let providers = CString::new("cloudflare").unwrap();
        let rc = unsafe { dns_set_resolver_options(1, 0, 0, 0, 1, 1, 1, providers.as_ptr(), 1, 1) };

        assert_eq!(rc, 0);
        assert_eq!(crate::config::current().doh_providers, before_ids);
    }

    #[test]
    fn dns_set_resolver_options_dnssec_toggle_signals_rebuild_and_flush() {
        let _g = ffi_lock();
        crate::state::clear_state();
        let prev = crate::config::ResolverOptions {
            dnssec: true,
            ..Default::default()
        };
        crate::config::set(prev.clone());
        let providers = CString::new("cloudflare,google,quad9").unwrap();

        let rc = unsafe { dns_set_resolver_options(0, 0, 0, 0, 1, 1, 1, providers.as_ptr(), 1, 1) };

        assert_eq!(rc, 1);
        let new = crate::config::current();
        assert!(!new.dnssec);
        assert!(needs_provider_rebuild(&prev, &new));
        assert!(needs_cache_flush(&prev, &new));
    }

    #[test]
    fn dns_stats_snapshot_returns_zero_on_null_out() {
        let rc = unsafe { dns_stats_snapshot(std::ptr::null_mut()) };
        assert_eq!(rc, 0, "null out pointer must yield 0, not a write");
    }

    #[test]
    fn dns_stats_snapshot_reports_counter_movement_without_init() {
        // The counters are process statics, so the export answers with the
        // resolver stopped. That is what lets `getRuntimeState` report totals
        // after a service stop.
        let mut before = crate::stats::StatsSnapshot::default();
        assert_eq!(unsafe { dns_stats_snapshot(&mut before) }, 1);
        crate::stats::add(&crate::stats::counters().blocked, 3);
        let mut after = crate::stats::StatsSnapshot::default();
        assert_eq!(unsafe { dns_stats_snapshot(&mut after) }, 1);

        assert_eq!(after.blocked - before.blocked, 3);
    }

    #[test]
    fn parse_override_caa_round_trip() {
        let (rt, rd) = parse_override("CAA", "0 issue letsencrypt.org").unwrap();
        assert_eq!(rt, RecordType::CAA);
        if let RData::CAA(_) = rd {
            // Fields are platform-specific, so only the variant is asserted.
        } else {
            panic!("expected CAA rdata");
        }
    }

    #[test]
    fn parse_override_rejects_srv_qtype() {
        // Owner labels reject `_`, so SRV is unreachable by design. The
        // generic zonefile fallback must not resurrect it.
        assert!(parse_override("SRV", "10 60 5060 sip.example.com.").is_err());
        assert!(parse_override("SRV", "10 60 sip.example").is_err());
    }

    #[test]
    fn parse_override_caa_rejects_malformed() {
        assert!(parse_override("CAA", "issue").is_err());
        assert!(parse_override("CAA", "256 issue example.com").is_err());
    }

    #[test]
    fn parse_override_https_round_trip() {
        let (rt, rd) = parse_override("HTTPS", "1 . alpn=h2,h3").unwrap();
        assert_eq!(rt, RecordType::HTTPS);
        assert!(matches!(rd, RData::HTTPS(_)));
    }

    #[test]
    fn parse_override_svcb_round_trip() {
        let (rt, rd) = parse_override("SVCB", "1 svc.example.com. alpn=h2").unwrap();
        assert_eq!(rt, RecordType::SVCB);
        assert!(matches!(rd, RData::SVCB(_)));
    }

    #[test]
    fn parse_override_tlsa_round_trip() {
        // 3 1 1 <hex sha256>: DANE-EE, SPKI, SHA-256.
        let (rt, rd) = parse_override(
            "TLSA",
            "3 1 1 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        )
        .unwrap();
        assert_eq!(rt, RecordType::TLSA);
        assert!(matches!(rd, RData::TLSA(_)));
    }

    #[test]
    fn parse_override_naptr_round_trip() {
        let (rt, rd) = parse_override(
            "NAPTR",
            r#"100 50 "s" "z3950+I2L+I2C" "" _z3950._tcp.gatech.edu."#,
        )
        .unwrap();
        assert_eq!(rt, RecordType::NAPTR);
        assert!(matches!(rd, RData::NAPTR(_)));
    }

    #[test]
    fn parse_override_unknown_qtype_returns_err() {
        assert!(parse_override("NOTAREALTYPE", "anything").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Kept Fresh counts only popular keys whose entry is fresh now, and its
    /// traffic estimate is one refresh per TTL for each of them.
    #[test]
    fn live_cache_stats_counts_fresh_popular_entries() {
        use crate::cache::{CacheKey, CachedEntry};
        use hickory_proto::op::Message;
        use std::collections::HashSet;
        use std::time::Instant;

        let cache = DnsCache::new(1 << 20);
        let entry = |ttl: u32, fresh: bool| {
            let mut entry = CachedEntry::scaffold(Message::query(), "Test".into());
            entry.original_ttl_secs = ttl;
            entry.expires_at = if fresh {
                Instant::now() + Duration::from_secs(u64::from(ttl))
            } else {
                Instant::now() - Duration::from_secs(1)
            };
            entry
        };
        let fresh_a = CacheKey::from("fresh.example", RecordType::A);
        let fresh_aaaa = CacheKey::from("fresh.example", RecordType::AAAA);
        let expired = CacheKey::from("expired.example", RecordType::A);
        let not_popular = CacheKey::from("other.example", RecordType::A);
        let missing = CacheKey::from("missing.example", RecordType::A);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            cache
                .inner_insert_raw(fresh_a.clone(), entry(300, true))
                .await;
            cache
                .inner_insert_raw(fresh_aaaa.clone(), entry(60, true))
                .await;
            cache
                .inner_insert_raw(expired.clone(), entry(300, false))
                .await;
            cache.inner_insert_raw(not_popular, entry(10, true)).await;
            cache.flush_pending().await;
        });
        let popular: HashSet<_> = [fresh_a, fresh_aaaa, expired, missing].into();

        let stats = live_cache_stats(&cache, &popular, Instant::now());

        assert_eq!(stats.in_cache, 2);
        assert!((stats.refreshes_per_second - (1.0 / 300.0 + 1.0 / 60.0)).abs() < 1e-9);
        assert_eq!(
            live_cache_stats(&cache, &HashSet::new(), Instant::now()),
            crate::history::LiveCacheStats::default()
        );
    }

    #[test]
    fn log_only_toggle_does_not_require_rebuild() {
        let prev = crate::config::ResolverOptions::default();
        let mut next = prev.clone();
        next.log_queries = !prev.log_queries;
        assert!(!needs_provider_rebuild(&prev, &next));
        assert!(!needs_cache_flush(&prev, &next));
    }

    #[test]
    fn dnssec_toggle_requires_rebuild_and_flush() {
        let prev = crate::config::ResolverOptions::default();
        let mut next = prev.clone();
        next.dnssec = !prev.dnssec;
        assert!(needs_provider_rebuild(&prev, &next));
        assert!(needs_cache_flush(&prev, &next));
    }

    #[test]
    fn snapshot_count_to_c_int_saturates_on_overflow() {
        assert_eq!(snapshot_count_to_c_int(42), 42);
        assert_eq!(snapshot_count_to_c_int(c_int::MAX as usize + 1), c_int::MAX);
    }

    /// The user local-zone FFI mutated `local_zones` live, outside the
    /// `ArcSwap` policy snapshot, and was removed. If the product needs user
    /// local zones, they travel through `PolicySnapshotDto` so overrides,
    /// forward zones and local zones publish as one validated snapshot.
    #[test]
    fn user_local_zone_ffi_stays_deleted() {
        let exports = exported_names();
        for deleted in [
            "dns_upsert_local_zone",
            "dns_remove_local_zone",
            "dns_clear_local_zones",
        ] {
            assert!(
                !exports.contains(&deleted.to_string()),
                "{deleted} publishes local zones outside the ArcSwap policy snapshot"
            );
        }
    }

    /// The incremental override and forward-zone FFI applied user policy entry
    /// by entry, so a rejected entry left a half-applied policy live, and was
    /// removed. `dns_apply_policy_snapshot` is the only way user policy reaches
    /// the resolver, and it validates the whole candidate before one `ArcSwap`
    /// publication. Re-exporting any of these names restores the second update
    /// model.
    #[test]
    fn incremental_policy_ffi_stays_deleted() {
        let exports = exported_names();
        for deleted in [
            "dns_set_override",
            "dns_remove_override",
            "dns_clear_overrides",
            "dns_upsert_forward_zone",
            "dns_upsert_stub_zone",
            "dns_remove_forward_zone",
            "dns_clear_forward_zones",
        ] {
            assert!(
                !exports.contains(&deleted.to_string()),
                "{deleted} mutates policy incrementally instead of publishing one validated snapshot"
            );
        }
        assert!(
            exports.contains(&"dns_apply_policy_snapshot".to_string()),
            "the snapshot export that replaced the incremental FFI is missing"
        );
    }

    /// Names of every `extern "C"` export in this file. Collects the names
    /// rather than searching the whole source so a name spelled out in a
    /// caller's assertion cannot match itself.
    fn exported_names() -> Vec<String> {
        let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
            .expect("lib.rs must be readable from the crate manifest dir");
        let exports: Vec<String> = source
            .lines()
            .filter_map(|line| line.split_once("extern \"C\" fn "))
            .filter_map(|(_, rest)| rest.split('(').next())
            .map(|name| name.trim().to_string())
            .collect();
        assert!(
            !exports.is_empty(),
            "the export scanner no longer matches the crate"
        );
        exports
    }
}
