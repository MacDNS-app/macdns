// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

// ## In-process dylib contract
//
// - `ResolverModule.shared` is the sole owner of the dylib handle. `dlopen`
//   runs at most once per agent lifetime (idempotent `load()`) and the handle
//   is never `dlclose`d, so resolved symbol pointers stay valid for the whole
//   process. `RTLD_NODELETE` is unnecessary for the same reason.
// - Every read and write of `startTime` goes through `stateLock`. `start()` and
//   `stop()` write it on the agent setup queue, and `isWarmingUp()` reads it on
//   the CaptivePortalDetector queue.
// - Every `@convention(c)` closure handed to the dylib is non-capturing and
//   reaches only global singletons. Rust invokes them from its own threads,
//   and a capture would need a heap trampoline the Rust side cannot free.
// - rust-resolver builds with the Cargo default `panic = unwind`, and every
//   `#[no_mangle] extern "C"` entry wraps its body in
//   `catch_unwind(AssertUnwindSafe(...))`, returning a sentinel (`0` / `-1` /
//   `NULL`) on panic instead of aborting the agent.
// - The shipped dylib must be signed with the agent's Developer ID identity
//   and `--options runtime` (hardened runtime) so it can load into the
//   notarized agent binary.

import Darwin
import Foundation
import Shared

private typealias DnsInitFn = @convention(c) (UInt16) -> Int32
private typealias DnsShutdownFn = @convention(c) (Int32) -> Int32
private typealias DnsIsReadyFn = @convention(c) () -> Int32
private typealias DnsSetProxyBypassRequestedFn = @convention(c) (Int32) -> Int32
private typealias DnsConfigureProxyControlFn =
    @convention(c) (UnsafePointer<UInt8>, Int, UnsafePointer<UInt8>, Int) -> Int32
private typealias DnsClearProxyControlFn = @convention(c) () -> Int32
private typealias DnsReloadBlFn = @convention(c) (UnsafePointer<CChar>) -> Int32
private typealias DnsStatsSnapshotFn = @convention(c) (UnsafeMutableRawPointer) -> Int32
private typealias DnsEnableFwdFn = @convention(c) (UnsafePointer<UnsafePointer<CChar>?>, Int32) -> Int32
private typealias DnsDisableFwdFn = @convention(c) () -> Int32
private typealias DnsProbeRecursiveResolutionFn = @convention(c) () -> Int32
private typealias DnsProbeNetworkDNSFn = @convention(c) (UnsafePointer<UnsafePointer<CChar>?>, Int32) -> Int32
private typealias DnsFlushCacheFn = @convention(c) () -> Void
private typealias DnsNetworkChgFn = @convention(c) () -> Void
private typealias DnsSnapshotCacheFn = @convention(c) () -> Int32
private typealias DnsSetCachePathFn = @convention(c) (UnsafePointer<CChar>) -> Void
private typealias BlockedCCallback =
    @convention(c) (
        UnsafePointer<CChar>, UnsafePointer<CChar>, UnsafePointer<CChar>
    ) -> Void
private typealias DnsSetBlockedCbFn = @convention(c) (BlockedCCallback) -> Void
private typealias QueryCCallback =
    @convention(c) (UnsafePointer<CChar>, UnsafePointer<CChar>) -> Void
private typealias ReplyCCallback =
    @convention(c) (
        UnsafePointer<CChar>, UnsafePointer<CChar>, UnsafePointer<CChar>, UInt32,
        UnsafePointer<CChar>, UnsafePointer<CChar>
    ) -> Void
private typealias ServfailCCallback =
    @convention(c) (
        UnsafePointer<CChar>, UnsafePointer<CChar>, UnsafePointer<CChar>
    ) -> Void
private typealias DnsSetQueryCbFn = @convention(c) (QueryCCallback) -> Void
private typealias DnsSetReplyCbFn = @convention(c) (ReplyCCallback) -> Void
private typealias DnsSetServfailCbFn = @convention(c) (ServfailCCallback) -> Void
private typealias DnsSetResolverOptsFn =
    @convention(c) (
        Int32, Int32, Int32, Int32, Int32, Int32, Int32,
        UnsafePointer<CChar>, Int32, Int32
    ) -> Int32
private typealias LogCCallback =
    @convention(c) (Int32, UnsafePointer<CChar>, UnsafePointer<CChar>) -> Void
private typealias DnsSetLogCbFn = @convention(c) (LogCCallback) -> Int32

// Blocklist scheduler and allowlist FFI. Allowlist calls return 1 on success
// and -1 on error. The list call returns a heap-allocated JSON C-string that
// the caller frees with `dns_allowlist_free_json`, or NULL.
private typealias DnsConfigureBlocklistFn = @convention(c) (UnsafePointer<CChar>) -> Int32
private typealias DnsForceBlocklistUpdateStatusFn = @convention(c) () -> Int32
private typealias DnsStartBlocklistSchedulerFn = @convention(c) () -> Int32
private typealias BlocklistRefreshCCallback = @convention(c) () -> Void
private typealias DnsSetBlocklistRefreshCbFn = @convention(c) (BlocklistRefreshCCallback) -> Void
private typealias DnsAllowlistSetPathFn = @convention(c) (UnsafePointer<CChar>) -> Int32
private typealias DnsAllowlistListFn = @convention(c) () -> UnsafeMutablePointer<CChar>?
private typealias DnsApplyPolicySnapshotFn =
    @convention(c) (UnsafePointer<CChar>, UnsafeMutablePointer<CChar>?, Int) -> Int32
private typealias DnsApplyEphemeralRoutesFn = @convention(c) (UnsafePointer<CChar>) -> Int32
private typealias DnsApplyNetworkSnapshotFn = @convention(c) (UnsafePointer<CChar>) -> Int32
private typealias DnsAllowlistReplaceJsonFn = @convention(c) (UnsafePointer<CChar>) -> Int32
private typealias DnsAllowlistFreeJsonFn = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void

// Lookup history. The query returns a heap-allocated JSON C-string the caller
// frees via `dns_history_free_json`, or NULL on panic.
private typealias DnsSetHistoryPathFn = @convention(c) (UnsafePointer<CChar>) -> Void
private typealias DnsConfigureHistoryFn = @convention(c) (Int32, Int32, Int32, Int32) -> Int32
private typealias DnsHistoryQueryFn = @convention(c) (UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
private typealias DnsHistoryFreeJsonFn = @convention(c) (UnsafeMutablePointer<CChar>?) -> Void
private typealias DnsHistoryClearFn = @convention(c) () -> Int32

/// Layout mirror of `StatsSnapshot` in
/// `rust-resolver/crates/macdns-resolver/src/stats.rs`: eleven `UInt64` fields
/// in the same declaration order, which `dns_stats_snapshot` writes through a
/// pointer to this struct. Adding, removing or reordering a field here is an
/// ABI change and must land with the Rust struct.
/// `ResolverModule.statsSnapshot()` refuses to read a mirror whose size
/// stopped matching.
struct RawResolverStats {
    var queriesTotal: UInt64 = 0
    var cacheHits: UInt64 = 0
    var cacheMisses: UInt64 = 0
    var blocked: UInt64 = 0
    var servfail: UInt64 = 0
    var prefetchRefills: UInt64 = 0
    var staleServed: UInt64 = 0
    var rebindingFiltered: UInt64 = 0
    var belowNXDomainHits: UInt64 = 0
    var udpOverloadDrops: UInt64 = 0
    var tcpOverloadDrops: UInt64 = 0
}

extension ResolverStatsSnapshot {
    init(_ raw: RawResolverStats) {
        self.init(
            queriesTotal: raw.queriesTotal,
            cacheHits: raw.cacheHits,
            cacheMisses: raw.cacheMisses,
            blocked: raw.blocked,
            servfail: raw.servfail,
            prefetchRefills: raw.prefetchRefills,
            staleServed: raw.staleServed,
            rebindingFiltered: raw.rebindingFiltered,
            belowNXDomainHits: raw.belowNXDomainHits,
            udpOverloadDrops: raw.udpOverloadDrops,
            tcpOverloadDrops: raw.tcpOverloadDrops
        )
    }
}

/// Outcome of an atomic policy-snapshot publication.
///
/// The rejection carries the resolver's own description of the offending entry
/// so a failed start says which override or forward zone has to be fixed
/// instead of only that "something" was rejected.
enum PolicySnapshotApplyResult: Equatable {
    case applied
    case rejected(String)

    var isApplied: Bool {
        self == .applied
    }

    var rejection: String? {
        guard case .rejected(let reason) = self else { return nil }
        return reason
    }
}

final class ResolverModule {
    static let shared = ResolverModule()

    /// Size `RawResolverStats` must have to be layout-compatible with the
    /// `#[repr(C)]` Rust struct. Pinned on the Rust side by
    /// `struct_layout_is_eleven_u64_fields` in stats.rs.
    static let resolverStatsByteCount = 11 * MemoryLayout<UInt64>.size

    private var handle: UnsafeMutableRawPointer?
    private var fnInit: DnsInitFn?
    private var fnShutdown: DnsShutdownFn?
    private var fnIsReady: DnsIsReadyFn?
    private var fnSetProxyBypassRequested: DnsSetProxyBypassRequestedFn?
    private var fnConfigureProxyControl: DnsConfigureProxyControlFn?
    private var fnClearProxyControl: DnsClearProxyControlFn?
    private var fnReloadBl: DnsReloadBlFn?
    private var fnStatsSnapshot: DnsStatsSnapshotFn?
    private var fnEnableFwd: DnsEnableFwdFn?
    private var fnDisableFwd: DnsDisableFwdFn?
    private var fnProbeRecursiveResolution: DnsProbeRecursiveResolutionFn?
    private var fnProbeNetworkDNS: DnsProbeNetworkDNSFn?
    private var fnFlushCache: DnsFlushCacheFn?
    private var fnNetworkChg: DnsNetworkChgFn?
    private var fnSnapshotCache: DnsSnapshotCacheFn?
    private var fnSetCachePath: DnsSetCachePathFn?
    private var fnSetBlockedCallback: DnsSetBlockedCbFn?
    private var fnSetQueryCallback: DnsSetQueryCbFn?
    private var fnSetReplyCallback: DnsSetReplyCbFn?
    private var fnSetServfailCallback: DnsSetServfailCbFn?
    private var fnSetResolverOpts: DnsSetResolverOptsFn?
    private var fnSetLogCallback: DnsSetLogCbFn?
    private var fnConfigureBlocklist: DnsConfigureBlocklistFn?
    private var fnForceBlocklistUpdateStatus: DnsForceBlocklistUpdateStatusFn?
    private var fnStartBlocklistScheduler: DnsStartBlocklistSchedulerFn?
    private var fnSetBlocklistRefreshCallback: DnsSetBlocklistRefreshCbFn?
    private var fnAllowlistSetPath: DnsAllowlistSetPathFn?
    private var fnAllowlistList: DnsAllowlistListFn?
    private var fnApplyPolicySnapshot: DnsApplyPolicySnapshotFn?
    private var fnApplyEphemeralRoutes: DnsApplyEphemeralRoutesFn?
    private var fnApplyNetworkSnapshot: DnsApplyNetworkSnapshotFn?
    private var fnAllowlistReplaceJson: DnsAllowlistReplaceJsonFn?
    private var fnAllowlistFreeJson: DnsAllowlistFreeJsonFn?
    private var fnSetHistoryPath: DnsSetHistoryPathFn?
    private var fnConfigureHistory: DnsConfigureHistoryFn?
    private var fnHistoryQuery: DnsHistoryQueryFn?
    private var fnHistoryFreeJson: DnsHistoryFreeJsonFn?
    private var fnHistoryClear: DnsHistoryClearFn?

    /// Guards `startTime`, which `start()`/`stop()` write on the agent setup
    /// queue and `isWarmingUp()` reads on the CaptivePortalDetector queue.
    private let stateLock = NSLock()

    /// Last successful start. `isWarmingUp` uses it so the captive portal
    /// detector avoids selecting compatibility mode while hickory finishes the
    /// DoH TLS handshakes.
    private var startTime: Date?
    private let warmupWindow: TimeInterval = 15

    private init() {}

    // MARK: - Lifecycle

    /// Idempotent. The handle is cached on `self`. `RTLD_LAZY` defers symbol
    /// resolution to first use. `RTLD_LOCAL` keeps symbols out of the global
    /// namespace so the agent cannot pick up a resolver symbol through a
    /// future third-party dylib. `RTLD_NODELETE` is omitted because the handle
    /// is never `dlclose`d.
    private func load() -> Bool {
        guard handle == nil else {
            return fnInit != nil && fnShutdown != nil && fnIsReady != nil
        }
        let path = PathResolver.resolverDylib
        guard let h = dlopen(path, RTLD_LAZY | RTLD_LOCAL) else {
            let errMsg = dlerror().map { String(cString: $0) } ?? "unknown"
            AgentLogger.shared.error("dlopen failed: \(errMsg)")
            return false
        }
        handle = h
        func sym<T>(_ name: String) -> T? {
            guard let p = dlsym(h, name) else { return nil }
            return unsafeBitCast(p, to: T.self)
        }
        fnInit = sym("dns_init")
        fnShutdown = sym("dns_shutdown")
        fnIsReady = sym("dns_is_ready")
        fnSetProxyBypassRequested = sym("dns_set_proxy_bypass_requested")
        fnConfigureProxyControl = sym("dns_configure_proxy_control")
        fnClearProxyControl = sym("dns_clear_proxy_control")
        fnReloadBl = sym("dns_reload_blocklist")
        fnStatsSnapshot = sym("dns_stats_snapshot")
        fnEnableFwd = sym("dns_enable_forwarding")
        fnDisableFwd = sym("dns_disable_forwarding")
        fnProbeRecursiveResolution = sym("dns_probe_recursive_resolution")
        fnProbeNetworkDNS = sym("dns_probe_network_dns")
        fnFlushCache = sym("dns_flush_cache")
        fnNetworkChg = sym("dns_notify_network_change")
        fnSnapshotCache = sym("dns_snapshot_cache")
        fnSetCachePath = sym("dns_set_cache_path")
        fnSetBlockedCallback = sym("dns_set_blocked_callback")
        fnSetQueryCallback = sym("dns_set_query_callback")
        fnSetReplyCallback = sym("dns_set_reply_callback")
        fnSetServfailCallback = sym("dns_set_servfail_callback")
        fnSetResolverOpts = sym("dns_set_resolver_options")
        fnSetLogCallback = sym("dns_set_log_callback")
        fnConfigureBlocklist = sym("dns_configure_blocklist")
        fnForceBlocklistUpdateStatus = sym("dns_force_blocklist_update_status")
        fnStartBlocklistScheduler = sym("dns_start_blocklist_scheduler")
        fnSetBlocklistRefreshCallback = sym("dns_set_blocklist_refresh_callback")
        fnAllowlistSetPath = sym("dns_allowlist_set_path")
        fnAllowlistList = sym("dns_allowlist_list")
        fnApplyPolicySnapshot = sym("dns_apply_policy_snapshot")
        fnApplyEphemeralRoutes = sym("dns_apply_ephemeral_routes")
        fnApplyNetworkSnapshot = sym("dns_apply_network_snapshot")
        fnAllowlistReplaceJson = sym("dns_allowlist_replace_json")
        fnAllowlistFreeJson = sym("dns_allowlist_free_json")
        fnSetHistoryPath = sym("dns_set_history_path")
        fnConfigureHistory = sym("dns_configure_history")
        fnHistoryQuery = sym("dns_history_query")
        fnHistoryFreeJson = sym("dns_history_free_json")
        fnHistoryClear = sym("dns_history_clear")

        guard fnInit != nil, fnShutdown != nil, fnIsReady != nil else {
            AgentLogger.shared.error("resolver: missing required symbols; keeping dylib loaded until agent restart")
            return false
        }
        registerLogCallback()
        AgentLogger.shared.info("resolver dylib loaded from \(path)")
        return true
    }

    /// Boots the in-process resolver. Fail-closed: if the dylib cannot load
    /// or `dns_init` refuses the port, start() throws. Blocklist
    /// initialization runs separately via `configureBlocklist(settingsPath:)`.
    func start(port: UInt16 = 5335, options: ResolverOptions = .default) throws {
        guard load() else {
            throw NSError(
                domain: "ResolverModule", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "failed to load dylib"]
            )
        }

        guard applyResolverOptions(options) else {
            throw NSError(
                domain: "ResolverModule", code: 3,
                userInfo: [NSLocalizedDescriptionKey: "resolver options rejected"]
            )
        }
        registerBlockedCallback()
        registerQueryReplyCallbacks()
        registerServfailCallback()
        registerBlocklistRefreshCallback()
        applyCachePath()

        guard fnInit?(port) == 1 else {
            throw NSError(
                domain: "ResolverModule", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "dns_init returned 0"]
            )
        }
        stateLock.withLock { startTime = Date() }
        // `dns_init` already logs "resolver listening on <addrs>" through the
        // FFI logger.
    }

    /// Resolver knobs sourced from UI-owned state.json toggles. Internal
    /// safety/cache policy stays in Rust constants, not user-editable state.
    struct ResolverOptions {
        let dnssec: Bool
        let logQueries: Bool
        let logReplies: Bool
        let prefetch: Bool
        let serveExpired: Bool
        let dohProviders: [DoHProviderID]
        let dohDispatchMode: DoHDispatchMode
        let dnsAnswerRefinementEnabled: Bool

        static let `default` = ResolverOptions(
            dnssec: true,
            logQueries: false,
            logReplies: false,
            prefetch: true,
            serveExpired: true,
            dohProviders: DoHProviderID.defaultProviders,
            dohDispatchMode: .defaultMode,
            dnsAnswerRefinementEnabled: true
        )
    }

    /// `nil` means the symbol is absent, which must fail closed. Acknowledging
    /// an apply that never reached Rust would commit a rejected transaction.
    static func confirmedResolverOptionsApplySucceeded(_ result: Int32?) -> Bool {
        result.map { $0 == 1 } ?? false
    }

    func canApplyResolverOptions(_: ResolverOptions) -> Bool {
        guard load() else { return false }
        return fnSetResolverOpts != nil
    }

    private func applyResolverOptions(_ o: ResolverOptions) -> Bool {
        guard let setResolverOpts = fnSetResolverOpts else {
            AgentLogger.shared.error(
                "resolver: dns_set_resolver_options symbol missing — resolver options apply refused"
            )
            return false
        }

        let providers = o.dohProviders.map(\.rawValue).joined(separator: ",")
        let result = providers.withCString { cProviders in
            setResolverOpts(
                o.dnssec ? 1 : 0,
                0,
                o.logQueries ? 1 : 0,
                o.logReplies ? 1 : 0,
                o.prefetch ? 1 : 0,
                o.serveExpired ? 1 : 0,
                1,
                cProviders,
                o.dohDispatchMode.ffiValue,
                o.dnsAnswerRefinementEnabled ? 1 : 0
            )
        }
        return Self.confirmedResolverOptionsApplySucceeded(result)
    }

    /// Live-updates runtime knobs. Only `logQueries`, `logReplies`,
    /// `prefetch`, and `serveExpired` take effect without a restart.
    /// `dnssec` is captured by providers at build time, so it requires the
    /// backend restart handled by `saveFullConfig`.
    func updateResolverOptions(_ options: ResolverOptions) -> Bool {
        applyResolverOptions(options)
    }

    /// Points the Rust cache at an on-disk dump file so warm entries survive
    /// agent restarts. Must run before `fnInit`, because the Rust side reads
    /// the path during init to restore entries into the fresh cache. A dylib
    /// without `dns_set_cache_path` skips persistence and the in-memory cache
    /// keeps working.
    private func applyCachePath() {
        guard let setPath = fnSetCachePath else {
            AgentLogger.shared.warning(
                "resolver: dns_set_cache_path symbol missing — cache persistence disabled")
            return
        }
        // Dedicated file for the Rust snapshot format (gzip + postcard). The
        // Rust "cache restored N entries from <path>" line during dns_init
        // already logs the path.
        let path = PathResolver.resolverCacheFile.path
        path.withCString { p in setPath(p) }
    }

    private func registerServfailCallback() {
        let cb: ServfailCCallback = { dPtr, tPtr, rPtr in
            let d = String(cString: dPtr)
            let t = String(cString: tPtr)
            let r = String(cString: rPtr)
            AgentLogger.shared.dnsServfail(domain: d, qtype: t, reason: r)
        }
        fnSetServfailCallback?(cb)
    }

    private func registerBlocklistRefreshCallback() {
        let cb: BlocklistRefreshCCallback = {
            DispatchQueue.main.async {
                BlocklistManager.shared.markRefreshCompleted()
            }
        }
        fnSetBlocklistRefreshCallback?(cb)
    }

    private func registerQueryReplyCallbacks() {
        let qcb: QueryCCallback = { dPtr, tPtr in
            let d = String(cString: dPtr)
            let t = String(cString: tPtr)
            AgentLogger.shared.dnsQuery(domain: d, qtype: t)
        }
        fnSetQueryCallback?(qcb)

        let rcb: ReplyCCallback = { dPtr, tPtr, rPtr, answers, provPtr, dataPtr in
            let d = String(cString: dPtr)
            let t = String(cString: tPtr)
            let r = String(cString: rPtr)
            let provider = String(cString: provPtr)
            let data = String(cString: dataPtr)
            AgentLogger.shared.dnsReply(
                domain: d,
                qtype: t,
                rcode: r,
                answers: answers,
                provider: provider,
                data: data
            )
        }
        fnSetReplyCallback?(rcb)
    }

    /// Routes Rust `log::{error,warn,info,debug,trace}!` output into os.log.
    /// Without this the dylib's stderr is discarded (LaunchAgent plist has no
    /// StandardErrorPath), leaving hickory/provider failures invisible.
    /// Level mapping mirrors `log_hooks::LogCallback`: 0=Error, 1=Warn,
    /// 2=Info, 3=Debug, 4=Trace. Trace collapses to debug because
    /// `os.Logger` has no trace tier.
    private func registerLogCallback() {
        let cb: LogCCallback = { level, tPtr, mPtr in
            let target = String(cString: tPtr)
            let msg = String(cString: mPtr)
            let line = "[\(target)] \(msg)"
            switch level {
            case 0: AgentLogger.shared.error(line)
            case 1: AgentLogger.shared.warning(line)
            case 2: AgentLogger.shared.info(line)
            case 3, 4: AgentLogger.shared.debug(line)
            default: AgentLogger.shared.info(line)
            }
        }
        guard let fn = fnSetLogCallback else {
            AgentLogger.shared.warning(
                "resolver: dns_set_log_callback symbol missing — Rust log lines will stay in dylib stderr")
            return
        }
        if fn(cb) != 1 {
            AgentLogger.shared.error(
                "resolver: dns_set_log_callback reported failure — Rust log pipeline is inactive")
        }
    }

    /// The callback runs on the resolver's own telemetry thread, behind a
    /// bounded queue, never on the query path. It only feeds the sampled
    /// BLOCKED log line: blocked counts live in the lookup history.
    private func registerBlockedCallback() {
        let cb: BlockedCCallback = { dPtr, rPtr, cPtr in
            BlockedQueryLog.shared.record(
                domain: String(cString: dPtr),
                rule: String(cString: rPtr),
                category: String(cString: cPtr)
            )
        }
        fnSetBlockedCallback?(cb)
    }

    /// Stops the resolver runtime.
    ///
    /// Returns `true` only when the resolver actually stopped: either the
    /// shutdown call reported success, or the module no longer reports ready.
    /// Callers must not report a successful stop to the UI without this.
    @discardableResult
    func stop(force: Bool = false) -> Bool {
        guard let fnShutdown else {
            AgentLogger.shared.error("resolver: dns_shutdown symbol missing")
            return !isRunning()
        }
        var stopped = fnShutdown(force ? 1 : 0) == 1

        // A reported failure is still a real stop if the module went down.
        if !stopped && !isRunning() {
            stopped = true
        }

        guard stopped else {
            AgentLogger.shared.error(
                "resolver module still running after shutdown request"
            )
            return false
        }

        stateLock.withLock { startTime = nil }
        return true
    }

    func isRunning() -> Bool { (fnIsReady?() ?? 0) == 1 }

    func setProxyBypassRequested(_ requested: Bool) -> Bool {
        guard load(), let fnSetProxyBypassRequested else { return false }
        return fnSetProxyBypassRequested(requested ? 1 : 0) == 1
    }

    func configureProxyControl(sessionID: Data, key: Data) -> Bool {
        guard load(), let fnConfigureProxyControl,
            sessionID.count == 16, key.count == 32
        else { return false }
        return sessionID.withUnsafeBytes { sidBuf in
            key.withUnsafeBytes { keyBuf in
                fnConfigureProxyControl(
                    sidBuf.bindMemory(to: UInt8.self).baseAddress!, 16,
                    keyBuf.bindMemory(to: UInt8.self).baseAddress!, 32) == 1
            }
        }
    }

    func clearProxyControl() -> Bool {
        guard load(), let fnClearProxyControl else { return false }
        return fnClearProxyControl() == 1
    }

    /// Returns true during the first `warmupWindow` seconds after `start()`.
    /// The captive portal detector uses this to avoid false positives while
    /// hickory completes the initial DoH TLS handshakes. Probes issued in
    /// that window can fail before provider connections are ready.
    func isWarmingUp() -> Bool {
        stateLock.withLock {
            guard let t = startTime else { return false }
            return Date().timeIntervalSince(t) < warmupWindow
        }
    }

    // MARK: - Resolver Counters

    /// Pulls the resolver's monotonic counters for the agent's runtime-state
    /// report. `dns_stats_snapshot` copies process statics into the caller's
    /// struct and allocates nothing, so there is no matching free call, and it
    /// answers with the resolver stopped. Returns nil when the dylib is not
    /// loaded, the symbol is missing, or the mirror layout no longer matches
    /// the Rust struct. An absent reading must never be reported as all-zero
    /// counters.
    func statsSnapshot() -> ResolverStatsSnapshot? {
        guard let fn = fnStatsSnapshot else { return nil }
        guard MemoryLayout<RawResolverStats>.size == Self.resolverStatsByteCount else {
            AgentLogger.shared.error(
                "resolver: stats mirror is \(MemoryLayout<RawResolverStats>.size) bytes, "
                    + "expected \(Self.resolverStatsByteCount); skipping counters"
            )
            return nil
        }
        var raw = RawResolverStats()
        let read = withUnsafeMutablePointer(to: &raw) {
            fn(UnsafeMutableRawPointer($0)) == 1
        }
        guard read else { return nil }
        return ResolverStatsSnapshot(raw)
    }

    // MARK: - Forwarding Mode

    static func forwardingCallSucceeded(_ result: Int32) -> Bool {
        result == 1
    }

    static func confirmedForwardingDisableSucceeded(
        _ v2Result: Int32?
    ) -> Bool {
        v2Result.map(forwardingCallSucceeded) ?? false
    }

    func enableForwarding(servers: [String]) -> Bool {
        guard !servers.isEmpty else {
            AgentLogger.shared.warning("enableForwarding called with empty server list")
            return false
        }
        guard load(), let fnEnableFwd else { return false }
        return Self.withServerArray(servers) { baseAddress, count in
            Self.forwardingCallSucceeded(fnEnableFwd(baseAddress, count))
        }
    }

    /// Blocks for up to the resolver's network-DNS probe bound (about 5 s).
    /// Call off the detector state queue only.
    func probeNetworkDNS(servers: [String]) -> Bool {
        guard !servers.isEmpty, load(), let fnProbeNetworkDNS else { return false }
        return Self.withServerArray(servers) { baseAddress, count in
            Self.forwardingCallSucceeded(fnProbeNetworkDNS(baseAddress, count))
        }
    }

    private static func withServerArray(
        _ servers: [String],
        _ body: (UnsafePointer<UnsafePointer<CChar>?>, Int32) -> Bool
    ) -> Bool {
        let cStrings = servers.map { strdup($0) }
        defer { cStrings.forEach { free($0) } }
        guard cStrings.allSatisfy({ $0 != nil }) else { return false }
        let pointers: [UnsafePointer<CChar>?] = cStrings.map {
            UnsafePointer($0!)
        }
        return pointers.withUnsafeBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else { return false }
            return body(baseAddress, Int32(servers.count))
        }
    }

    func disableForwarding() -> Bool {
        guard load(), let fnDisableFwd else {
            AgentLogger.shared.error(
                "resolver: dns_disable_forwarding symbol missing"
            )
            return false
        }
        return Self.confirmedForwardingDisableSucceeded(
            fnDisableFwd()
        )
    }

    func probeRecursiveResolution() -> Bool {
        guard load(), let fnProbeRecursiveResolution else { return false }
        return Self.forwardingCallSucceeded(fnProbeRecursiveResolution())
    }

    // MARK: - Cache + Network

    func flushCache() { fnFlushCache?() }
    func notifyNetworkChange() { fnNetworkChg?() }

    enum CacheSnapshotResult: Equatable {
        case wrote(entries: Int32)
        /// The Rust side abandoned the wait on its own deadline. The write
        /// itself continues on the blocking pool and still publishes under
        /// the epoch check, so this is a slowness signal, not data loss.
        case timedOut
        /// A previous writer still owns the resolver's single-flight slot, so
        /// this call was coalesced into it instead of starting a second writer
        /// that would race the first on the final rename. Expected state.
        case busy
        case failed
    }

    /// Maps `dns_snapshot_cache`'s return code. Negative values are sentinels.
    /// `-2` is the periodic deadline, `-3` means a writer is still running, and
    /// anything else negative is a plain failure such as no configured path or
    /// a runtime error, logged on the Rust side.
    static func cacheSnapshotResult(_ raw: Int32) -> CacheSnapshotResult {
        switch raw {
        case 0...: return .wrote(entries: raw)
        case -2: return .timedOut
        case -3: return .busy
        default: return .failed
        }
    }

    /// Writes the live cache to the configured dump path without shutting
    /// the module down. Called hourly from MaintenanceManager so a
    /// crash/SIGKILL leaves at most one hour of warm-cache work behind
    /// instead of the whole session. Blocks the caller for the duration of
    /// the write, so call it from a background queue only.
    func snapshotCache() -> CacheSnapshotResult {
        guard let snap = fnSnapshotCache else { return .failed }
        return Self.cacheSnapshotResult(snap())
    }

    /// Rebuilds the in-memory `MultiCategoryDb` from the current
    /// `blocklist_settings.json` without touching the scheduler loop. Used
    /// after zone regeneration and UI-driven settings saves so changes take
    /// effect without waiting for the hourly refresh tick.
    func reloadBlocklist() -> Bool {
        guard load(), let fn = fnReloadBl else {
            AgentLogger.shared.warning("resolver: dns_reload_blocklist symbol missing")
            return false
        }
        return PathResolver.blocklistSettings.path.withCString { fn($0) == 1 }
    }

    // MARK: - Blocklist scheduler

    /// Loads the settings JSON and applies the current category selection
    /// to the live `MultiCategoryDb`. Does NOT spawn the refresh loop. Call
    /// `startBlocklistScheduler` separately after `NetworkReadySignal`
    /// releases. Idempotent.
    /// - Parameter settingsPath: absolute filesystem path to
    ///   `blocklist_settings.json`.
    /// - Returns: `true` when the Rust side accepted the path, `false` on
    ///   error or missing symbol. Callers must check it, because silently
    ///   dropping the LMDB reload leaves the agent running with a stale
    ///   category selection.
    func configureBlocklist(settingsPath: String) -> Bool {
        guard load(), let fn = fnConfigureBlocklist else {
            AgentLogger.shared.warning(
                "resolver: dns_configure_blocklist symbol missing — scheduler disabled")
            return false
        }
        return settingsPath.withCString { p in fn(p) == 1 }
    }

    /// Outcome of a forced refresh for the lists the user selected. A failure
    /// in a list nobody selected never shows up here.
    enum BlocklistUpdateResult {
        case changed
        case unchanged
        /// Every selected list is loaded, but at least one could not be
        /// refreshed and keeps filtering with the database it already had.
        case loadedStale
        /// A selected list is not loaded, or the refresh could not run.
        case failed

        /// What a settings save needs: the selection is what filters.
        var selectionLoaded: Bool { self != .failed }
        /// What "Update Now" reports: every selected list is fresh.
        var refreshed: Bool { self == .changed || self == .unchanged }
        var changedFiles: Bool { self == .changed }
    }

    /// Maps `dns_force_blocklist_update_status`'s return code. Anything it
    /// does not know is a failure.
    static func blocklistUpdateResult(_ raw: Int32) -> BlocklistUpdateResult {
        switch raw {
        case 1: return .changed
        case 0: return .unchanged
        case 2: return .loadedStale
        default: return .failed
        }
    }

    /// Synchronously drives an immediate blocklist refresh and returns when
    /// every category has finished or failed. Blocks the caller thread, so
    /// call it from a background queue only. Reports changed vs. unchanged so
    /// `lastUpdated` only moves when files were published.
    func forceBlocklistUpdateResult() -> BlocklistUpdateResult {
        guard load(), let fn = fnForceBlocklistUpdateStatus else {
            AgentLogger.shared.warning("resolver: dns_force_blocklist_update_status symbol missing")
            return .failed
        }
        return Self.blocklistUpdateResult(fn())
    }

    /// Spawns the in-process blocklist refresh task on the resolver's Tokio
    /// runtime. Must be called after `configureBlocklist`. Runs one boot
    /// refresh immediately and then ticks every hour. Idempotent. The host
    /// defers this until `NetworkReadySignal` releases so the boot refresh
    /// does not race Content Filter activation, which kills reqwest
    /// connections mid-flight and leaves them stalled for the 60 s default
    /// timeout. Returns `false` on a missing symbol or an FFI error.
    func startBlocklistScheduler() -> Bool {
        guard load(), let fn = fnStartBlocklistScheduler else {
            AgentLogger.shared.warning(
                "resolver: dns_start_blocklist_scheduler symbol missing — periodic refresh disabled")
            return false
        }
        return fn() == 1
    }

    // MARK: - Allowlist

    /// Registers the allowlist LMDB path with the resolver so subsequent
    /// list/add/remove FFI calls can lazy-open the env. Must work while the
    /// resolver is stopped, because the Preferences UI reads and writes the
    /// allowlist long before `start()`. Callers must log on failure so a
    /// missing symbol or unreadable path cannot silently disable the
    /// allowlist.
    func setAllowlistPath(_ path: URL) -> Bool {
        guard load(), let fn = fnAllowlistSetPath else {
            AgentLogger.shared.warning(
                "resolver: dns_allowlist_set_path symbol missing — allowlist disabled")
            return false
        }
        return path.path.withCString { p in fn(p) == 1 }
    }

    enum AllowlistListError: Error {
        case symbolsMissing
        case ffiFailure
        case invalidEncoding
        case decodingFailed
    }

    func listAllowedDomains() -> Result<[String], AllowlistListError> {
        guard load(), let list = fnAllowlistList, let freeJson = fnAllowlistFreeJson else {
            AgentLogger.shared.warning("resolver: allowlist list symbols missing")
            return .failure(.symbolsMissing)
        }
        guard let ptr = list() else { return .failure(.ffiFailure) }
        defer { freeJson(ptr) }
        let json = String(cString: ptr)
        guard let data = json.data(using: .utf8) else {
            AgentLogger.shared.warning("resolver: dns_allowlist_list returned non-UTF8 JSON")
            return .failure(.invalidEncoding)
        }
        do {
            return .success(
                try JSONDecoder().decode([String].self, from: data)
            )
        } catch {
            AgentLogger.shared.warning("resolver: failed to decode allowlist JSON: \(error)")
            return .failure(.decodingFailed)
        }
    }

    // MARK: - Lookup History

    /// Applies the lookup-history settings. Independent of `start()`: the
    /// store records only while the resolver runs, but queries and Clear
    /// History work while protection is off. Turning history off stops
    /// recording and keeps the database, which only Clear History deletes.
    /// `false` means Rust rejected the values (nothing changed) or the library
    /// is unavailable.
    func configureHistory(_ settings: QueryHistorySettings) -> Bool {
        guard load(), let setPath = fnSetHistoryPath, let configure = fnConfigureHistory else {
            AgentLogger.shared.error("resolver: lookup history symbols missing — history stays off")
            return false
        }
        guard
            let retentionDays = Int32(exactly: settings.retentionDays),
            let popularCount = Int32(exactly: settings.popularCount),
            let popularDays = Int32(exactly: settings.popularDays)
        else { return false }
        // Rust reads the path only on configure.
        PathResolver.queryHistoryDB.path.withCString { setPath($0) }
        return configure(settings.enabled ? 1 : 0, retentionDays, popularCount, popularDays) == 1
    }

    /// Answers one `dns_history_query` request. Never nil: a request that is
    /// not a plain UTF-8 string is a caller `error`, and a resolver that cannot
    /// answer is `unavailable`, both in the JSON contract's shape.
    func queryHistory(_ request: Data) -> Data {
        guard let text = String(data: request, encoding: .utf8), !text.contains("\0") else {
            return Self.historyAnswer(status: "error", reason: "request is not a UTF-8 string without NUL bytes")
        }
        guard load(), let query = fnHistoryQuery, let freeJson = fnHistoryFreeJson else {
            AgentLogger.shared.warning("resolver: lookup history symbols missing")
            return Self.historyAnswer(status: "unavailable", reason: "the resolver cannot read lookup history")
        }
        return text.withCString { cRequest in
            guard let answer = query(cRequest) else {
                AgentLogger.shared.error("resolver: dns_history_query returned nil")
                return Self.historyAnswer(status: "unavailable", reason: "the resolver failed to read lookup history")
            }
            defer { freeJson(answer) }
            return Data(bytes: answer, count: strlen(answer))
        }
    }

    /// Deletes every stored lookup. Waits up to 5 s for the history writer, so
    /// call it off the XPC thread. `false` when nothing was deleted, including
    /// when `configureHistory` never succeeded.
    func clearHistory() -> Bool {
        guard load(), let clear = fnHistoryClear else {
            AgentLogger.shared.warning("resolver: dns_history_clear symbol missing")
            return false
        }
        return clear() == 1
    }

    private static func historyAnswer(status: String, reason: String) -> Data {
        (try? JSONSerialization.data(withJSONObject: ["status": status, "reason": reason]))
            ?? Data(#"{"status":"unavailable","reason":"internal error"}"#.utf8)
    }

    /// Publishes overrides and forward zones as one atomic policy snapshot.
    ///
    /// A rejected record leaves the previous policy fully active, so a failed
    /// apply can never expose a partially configured resolver. Rejections carry
    /// the offending entry when the resolver can report it, because a
    /// whole-snapshot rejection the user cannot attribute to an entry is not
    /// actionable. Fails closed when no apply symbol is available instead of
    /// falling back to per-entry mutation.
    func applyPolicySnapshot(
        overrides: [[String: String]],
        forwardZones: [[String: String]]
    ) -> PolicySnapshotApplyResult {
        guard load() else {
            return .rejected("resolver module unavailable")
        }
        let payload: [String: Any] = [
            "overrides": overrides,
            "forwardZones": forwardZones,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
            let json = String(data: data, encoding: .utf8)
        else {
            return .rejected("failed to encode policy snapshot")
        }

        guard let fn = fnApplyPolicySnapshot else {
            return .rejected(
                "dns_apply_policy_snapshot symbol missing — policy apply refused"
            )
        }
        var reason = [CChar](repeating: 0, count: 512)
        let applied = json.withCString { p in
            reason.withUnsafeMutableBufferPointer { buffer in
                fn(p, buffer.baseAddress, buffer.count) == 1
            }
        }
        guard !applied else { return .applied }
        let reported = String(cString: reason)
        return .rejected(reported.isEmpty ? "policy snapshot rejected" : reported)
    }

    /// Publishes the routes discovered from the attached network's search
    /// domains as one table. An empty array clears them.
    ///
    /// These routes are runtime-derived and never persisted to `state.json`.
    /// The resolver drops any domain outside the private-use suffixes, so an
    /// unauthenticated search-domain list cannot capture a public namespace.
    @discardableResult
    func applyEphemeralRoutes(_ routes: [EphemeralSearchDomainRoutes.Route]) -> Bool {
        guard load(), let fn = fnApplyEphemeralRoutes else {
            AgentLogger.shared.warning(
                "resolver: dns_apply_ephemeral_routes symbol missing — discovered routes not published"
            )
            return false
        }
        let payload = routes.map { ["domain": $0.domain, "forwardIP": $0.forwardIP] }
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
            let json = String(data: data, encoding: .utf8)
        else {
            AgentLogger.shared.error("resolver: failed to encode discovered routes")
            return false
        }
        return json.withCString { p in fn(p) == 1 }
    }

    /// Publishes the attached network's facts. The resolver starts a new
    /// network generation, stops NAT64 synthesis at once, and resumes it only
    /// if discovery against these resolvers finds a NAT64 prefix.
    @discardableResult
    func applyNetworkSnapshot(_ snapshot: NetworkProfileSnapshot) -> Bool {
        guard load(), let fn = fnApplyNetworkSnapshot else {
            AgentLogger.shared.warning(
                "resolver: dns_apply_network_snapshot symbol missing — network profile not published"
            )
            return false
        }
        guard let data = try? JSONSerialization.data(withJSONObject: snapshot.payload),
            let json = String(data: data, encoding: .utf8)
        else {
            AgentLogger.shared.error("resolver: failed to encode network snapshot")
            return false
        }
        return json.withCString { p in fn(p) == 1 }
    }

    /// Replaces the entire allowlist LMDB contents in one transaction.
    ///
    /// Every domain is validated before any write begins, so a rejected entry
    /// leaves the previous allowlist intact. Returns `false` when the symbol
    /// is unavailable so callers can fail closed instead of silently applying
    /// a partial list through per-domain calls.
    @discardableResult
    func replaceAllowedDomains(_ domains: [String]) -> Bool {
        guard load(), let fn = fnAllowlistReplaceJson else {
            AgentLogger.shared.error(
                "resolver: dns_allowlist_replace_json symbol missing — allowlist sync refused"
            )
            return false
        }
        guard let data = try? JSONSerialization.data(withJSONObject: domains),
            let json = String(data: data, encoding: .utf8)
        else {
            AgentLogger.shared.error("resolver: failed to encode allowlist domains")
            return false
        }
        return json.withCString { p in fn(p) == 1 }
    }
}
